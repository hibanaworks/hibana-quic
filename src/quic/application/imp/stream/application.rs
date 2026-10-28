//! Bounded stream application operations; no protocol ordering.
use super::*;

impl<'book, const RX: usize, const CHUNK: usize> App<'book, '_, '_, RX, CHUNK> {
    /// Open a locally initiated bidirectional stream using authenticated peer credit.
    pub fn open_local(&mut self) -> Result<StreamHandle, Error> {
        let mut n = self
            .core
            .numbers
            .try_borrow_mut()
            .map_err(|_| Error::Borrowed)?;
        let stream = n.table.open_local(true)?;
        n.register(stream)?;
        Ok(stream)
    }

    /// Open a local unidirectional stream with authenticated peer stream credit.
    /// A send-only stream has no receive-half release receipt.
    pub fn open_local_uni(&mut self) -> Result<StreamHandle, Error> {
        let mut n = self
            .core
            .numbers
            .try_borrow_mut()
            .map_err(|_| Error::Borrowed)?;
        let stream = n.table.open_local(false)?;
        n.register(stream)?;
        Ok(stream)
    }

    /// Resolve stream identity within this connection. Permission to submit
    /// data is carried by the projected production endpoint.
    pub(crate) fn origin(&self, id: u64) -> Result<Origin<'book>, Error> {
        let numbers = self
            .core
            .numbers
            .try_borrow()
            .map_err(|_| Error::Borrowed)?;
        if !numbers.table.can_send(id) {
            return Err(streams::Error::StreamState.into());
        }
        let stream = numbers.table.lookup(id)?;
        numbers.state(stream)?;
        Ok(Origin {
            identity: &self.core.identity,
            stream,
        })
    }

    pub(in crate::quic) fn release_input(
        &mut self,
        id: u64,
    ) -> Result<Option<InputReleased<'book>>, Error> {
        let mut n = self
            .core
            .numbers
            .try_borrow_mut()
            .map_err(|_| Error::Borrowed)?;
        let stream = match n.table.lookup(id) {
            Ok(stream) => stream,
            Err(streams::Error::Retired) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let read = n.table.receive(stream)?;
        if !read.first.is_empty() || !read.second.is_empty() || (!read.fin && read.reset.is_none())
        {
            return Err(Error::Binding);
        }
        let Some(stream) = n.state_mut(stream)?.input_release.take() else {
            return Ok(None);
        };
        Ok(Some(InputReleased {
            origin: Origin {
                identity: &self.core.identity,
                stream,
            },
        }))
    }

    pub(in crate::quic) fn input_released(&self, id: u64) -> Result<bool, Error> {
        let numbers = self
            .core
            .numbers
            .try_borrow()
            .map_err(|_| Error::Borrowed)?;
        let stream = match numbers.table.lookup(id) {
            Ok(stream) => stream,
            Err(streams::Error::Retired) => return Ok(true),
            Err(error) => return Err(error.into()),
        };
        if !numbers.table.can_receive(id) {
            return Err(Error::Binding);
        }
        Ok(numbers.state(stream)?.input_release.is_none())
    }
    fn production_stream(&self, origin: Origin<'_>) -> Result<StreamHandle, Error> {
        if !core::ptr::eq(origin.identity, &self.core.identity) {
            return Err(Error::Binding);
        }
        Ok(origin.stream)
    }

    /// Admit at most one chunk and the available peer credit. FIN is attached
    /// only when the complete supplied suffix fits.
    pub(crate) fn enqueue_prefix(
        &mut self,
        origin: Origin<'_>,
        bytes: &[u8],
        fin: bool,
    ) -> Result<usize, Error> {
        let stream = self.production_stream(origin)?;
        let mut n = self
            .core
            .numbers
            .try_borrow_mut()
            .map_err(|_| Error::Borrowed)?;
        let credit = n.table.send_credit(stream)?;
        let len = bytes.len().min(CHUNK).min(
            usize::try_from(credit.connection_available.min(credit.stream_available))
                .unwrap_or(usize::MAX),
        );
        if len == 0 && !bytes.is_empty() {
            return Err(streams::Error::FlowControl.into());
        }
        let Numbers { table, queue, .. } = &mut *n;
        queue.enqueue(table, stream, &bytes[..len], fin && len == bytes.len())?;
        Ok(len)
    }

    pub(in crate::quic) fn receive_offset(&self, stream: StreamHandle) -> Result<u64, Error> {
        let numbers = self
            .core
            .numbers
            .try_borrow()
            .map_err(|_| Error::Borrowed)?;
        numbers.state(stream)?;
        Ok(numbers.table.receive_offset(stream)?)
    }

    /// Copy and consume a contiguous prefix without exposing a borrowed view.
    /// Freed storage schedules reliable MAX_DATA/MAX_STREAM_DATA updates.
    pub fn read(&mut self, stream: StreamHandle, output: &mut [u8]) -> Result<Read, Error> {
        self.consume(stream, |view| {
            let len = (view.first.len() + view.second.len()).min(output.len());
            let first = len.min(view.first.len());
            output[..first].copy_from_slice(&view.first[..first]);
            output[first..len].copy_from_slice(&view.second[..len - first]);
            Ok(len)
        })
    }

    /// Inspect the actual receive storage without copying it, then consume the
    /// prefix returned by `consume`. The two slices cover ring-buffer wrapping.
    /// The synchronous callback cannot retain the view across an await. Returning
    /// an error or a count beyond the view leaves bytes and receive credit intact.
    /// Successful consumption schedules reliable receive-credit updates.
    pub fn consume(
        &mut self,
        stream: StreamHandle,
        consume: impl FnOnce(streams::ReadView<'_>) -> Result<usize, Error>,
    ) -> Result<Read, Error> {
        let mut n = self
            .core
            .numbers
            .try_borrow_mut()
            .map_err(|_| Error::Borrowed)?;
        n.state(stream)?;
        let (len, fin, reset) = {
            let view = n.table.receive(stream)?;
            let ready = view.first.len() + view.second.len();
            let fin = view.fin;
            let reset = view.reset;
            let len = consume(view)?;
            if len > ready {
                return Err(Error::Capacity);
            }
            (len, fin && len == ready, reset)
        };
        n.table.consume(stream, len)?;
        if len != 0 || reset.is_some() {
            n.replenish_credit(stream)?;
        }
        Ok(Read { len, fin, reset })
    }

    /// Owned handles only: no table/view borrow crosses the caller's await.
    /// A consumed FIN/reset remains observable until the application retires it.
    pub fn ready_streams(&self) -> Result<[Option<StreamHandle>; MAX_LIVE_STREAMS], Error> {
        let n = self
            .core
            .numbers
            .try_borrow()
            .map_err(|_| Error::Borrowed)?;
        let mut ready = [None; MAX_LIVE_STREAMS];
        let mut count = 0;
        for stream in n.table.live_handles() {
            if !n.table.can_receive(stream.id()) || n.state(stream)?.input_release.is_none() {
                continue;
            }
            let view = n.table.receive(stream)?;
            if !view.first.is_empty() || !view.second.is_empty() || view.fin || view.reset.is_some()
            {
                ready[count] = Some(stream);
                count += 1;
            }
        }
        Ok(ready)
    }

    /// Find one eligible stream without copying a capacity-sized handle array.
    /// The table borrow ends before the returned handle reaches a localside.
    pub fn find_readable_stream(
        &self,
        mut accept: impl FnMut(StreamHandle) -> bool,
    ) -> Result<Option<StreamHandle>, Error> {
        let n = self
            .core
            .numbers
            .try_borrow()
            .map_err(|_| Error::Borrowed)?;
        for stream in n.table.live_handles() {
            if !n.table.can_receive(stream.id())
                || n.state(stream)?.input_release.is_none()
                || !accept(stream)
            {
                continue;
            }
            let view = n.table.receive(stream)?;
            if !view.first.is_empty() || !view.second.is_empty() || view.fin || view.reset.is_some()
            {
                return Ok(Some(stream));
            }
        }
        Ok(None)
    }
    pub fn readable_stream(&self) -> Result<Option<StreamHandle>, Error> {
        self.find_readable_stream(|_| true)
    }

    pub fn delivery(&self, stream: StreamHandle) -> Result<Option<DeliveryRecord>, Error> {
        let n = self
            .core
            .numbers
            .try_borrow()
            .map_err(|_| Error::Borrowed)?;
        Ok(n.state(stream)?.delivered)
    }
    pub fn send_complete(&self, stream: StreamHandle) -> Result<bool, Error> {
        let n = self
            .core
            .numbers
            .try_borrow()
            .map_err(|_| Error::Borrowed)?;
        Ok(n.state(stream)?.delivered.is_some())
    }

    pub fn receive_complete(&self, stream: StreamHandle) -> Result<bool, Error> {
        let n = self
            .core
            .numbers
            .try_borrow()
            .map_err(|_| Error::Borrowed)?;
        let view = n.table.receive(stream)?;
        Ok(view.reset.is_some() || (view.fin && view.first.is_empty() && view.second.is_empty()))
    }

    pub fn queued_chunks(&self) -> Result<usize, Error> {
        let n = self
            .core
            .numbers
            .try_borrow()
            .map_err(|_| Error::Borrowed)?;
        Ok(n.queue.queued_chunks())
    }
}
