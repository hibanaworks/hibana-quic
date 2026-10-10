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
    /// Its production lease has no fictitious receive-half release capability.
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

    pub(crate) fn take_production(
        &mut self,
        stream: StreamHandle,
    ) -> Result<Production<'book>, Error> {
        let mut numbers = self
            .core
            .numbers
            .try_borrow_mut()
            .map_err(|_| Error::Borrowed)?;
        let issued = numbers
            .state_mut(stream)?
            .production
            .take()
            .ok_or(Error::Binding)?;
        Ok(Production {
            identity: &self.core.identity,
            stream: issued,
        })
    }

    pub(in crate::quic) fn take_unissued_production(
        &mut self,
        stream: StreamHandle,
    ) -> Result<Option<Production<'book>>, Error> {
        let mut numbers = self
            .core
            .numbers
            .try_borrow_mut()
            .map_err(|_| Error::Borrowed)?;
        Ok(numbers
            .state_mut(stream)?
            .production
            .take()
            .map(|issued| Production {
                identity: &self.core.identity,
                stream: issued,
            }))
    }

    pub(in crate::quic) fn release_production(
        &mut self,
        production: Production<'book>,
    ) -> Result<ProductionReleased<'book>, Error> {
        let stream = self.production_stream(&production)?;
        self.core
            .numbers
            .try_borrow()
            .map_err(|_| Error::Borrowed)?
            .state(stream)?;
        Ok(ProductionReleased {
            origin: Origin {
                identity: &self.core.identity,
                stream,
            },
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
    fn production_stream(&self, production: &Production<'_>) -> Result<StreamHandle, Error> {
        if !core::ptr::eq(production.identity, &self.core.identity) {
            return Err(Error::Binding);
        }
        Ok(production.stream)
    }

    /// Admit at most one chunk and the available peer credit. FIN is attached
    /// only when the complete supplied suffix fits.
    pub(crate) fn enqueue_prefix(
        &mut self,
        production: &mut Production<'_>,
        bytes: &[u8],
        fin: bool,
    ) -> Result<usize, Error> {
        let stream = self.production_stream(production)?;
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

    pub fn readable_stream(&self) -> Result<Option<StreamHandle>, Error> {
        Ok(self.ready_streams()?.into_iter().flatten().next())
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
