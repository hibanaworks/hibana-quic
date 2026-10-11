//! Bounded stream receive operations; no protocol ordering.
use super::*;

impl<'book, const RX: usize, const CHUNK: usize> Rx<'book, '_, '_, RX, CHUNK> {
    pub(in crate::quic) fn stop_intent(
        &mut self,
        id: u64,
        error_code: u64,
    ) -> Result<StopIntent<'book>, Error> {
        if error_code > streams::MAX_OFFSET {
            return Err(streams::Error::InvalidId.into());
        }
        let mut n = self
            .core
            .numbers
            .try_borrow_mut()
            .map_err(|_| Error::Borrowed)?;
        if !n.table.can_send(id) {
            return Err(streams::Error::StreamState.into());
        }
        let stream = n.accept_stream(id)?;
        Ok(StopIntent {
            identity: &self.core.identity,
            stream,
            error_code,
        })
    }

    /// The caller is the authenticated connection receive continuation, after
    /// whole-packet AEAD/frame/recovery validation. An arbitrary public caller
    /// cannot feed frames directly into this producer boundary.
    pub(in crate::quic) fn apply(&mut self, frame: &Frame<'_>) -> Result<(), Error> {
        let mut n = self
            .core
            .numbers
            .try_borrow_mut()
            .map_err(|_| Error::Borrowed)?;
        match *frame {
            Frame::Stream {
                id,
                offset,
                fin,
                data,
            } => {
                if !n.table.can_receive(id) {
                    return Err(streams::Error::StreamState.into());
                }
                let stream = match n.accept_stream(id) {
                    Ok(stream) => stream,
                    Err(Error::Streams(streams::Error::Retired)) => return Ok(()),
                    Err(error) => return Err(error),
                };
                n.table.on_stream(stream, offset, data, fin)?;
            }
            Frame::ResetStream {
                id,
                error_code,
                final_size,
            } => {
                if !n.table.can_receive(id) {
                    return Err(streams::Error::StreamState.into());
                }
                let stream = match n.accept_stream(id) {
                    Ok(stream) => stream,
                    Err(Error::Streams(streams::Error::Retired)) => return Ok(()),
                    Err(error) => return Err(error),
                };
                n.table.on_reset(stream, error_code, final_size)?;
            }
            Frame::MaxData { maximum } => n.table.on_max_data(maximum)?,
            Frame::MaxStreamData { id, maximum } => {
                if !n.table.can_send(id) {
                    return Err(streams::Error::StreamState.into());
                }
                let stream = match n.accept_stream(id) {
                    Ok(stream) => stream,
                    Err(Error::Streams(streams::Error::Retired)) => return Ok(()),
                    Err(error) => return Err(error),
                };
                n.table.on_max_stream_data(stream, maximum)?;
            }
            Frame::MaxStreams {
                bidirectional,
                maximum,
            } => {
                n.table.on_max_streams(bidirectional, maximum)?;
            }
            Frame::StreamDataBlocked { id, .. } => {
                if !n.table.can_receive(id) {
                    return Err(streams::Error::StreamState.into());
                }
                match n.accept_stream(id) {
                    Ok(_) | Err(Error::Streams(streams::Error::Retired)) => {}
                    Err(error) => return Err(error),
                }
            }
            Frame::DataBlocked { .. } | Frame::StreamsBlocked { .. } => {}
            _ => return Err(Error::UnsupportedFrame),
        }
        Ok(())
    }
}
