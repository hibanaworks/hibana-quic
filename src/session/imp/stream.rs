//! Raw QUIC application-carrier effects. No native OS types or HTTP envelopes.
use crate::quic::application::{BodyReader, ClientRequests, Error, ServerHandler, StreamSink};
use crate::session::StreamPeer;
use crate::session::{
    Protocol,
    imp::wire::{self, Bytes, CAPACITY, Decoder},
};
use core::future::poll_fn;
pub struct Output<'a, 's> {
    peer: &'a StreamPeer<'s>,
    pending: Option<Bytes>,
}
impl<'a, 's> Output<'a, 's> {
    fn new(peer: &'a StreamPeer<'s>, pending: Option<Bytes>) -> Self {
        Self { peer, pending }
    }
}
impl BodyReader for Output<'_, '_> {
    async fn read(&mut self, out: &mut [u8]) -> Result<usize, ()> {
        if out.is_empty() {
            return Err(());
        }
        if self.pending.is_none() {
            let Some(frame) = poll_fn(|cx| self.peer.poll_outgoing(cx))
                .await
                .map_err(|_| ())?
            else {
                return Ok(0);
            };
            self.pending = Some(wire::message(frame)?);
        }
        let pending = self.pending.as_mut().ok_or(())?;
        let n = pending.read(out);
        if pending.offset == pending.len {
            self.pending = None;
        }
        Ok(n)
    }
}
pub struct Requests<'a, 's, Start> {
    start: Option<Start>,
    prefix: Option<Bytes>,
    body: Output<'a, 's>,
}
impl<'a, 's, Start> Requests<'a, 's, Start> {
    pub fn new(peer: &'a StreamPeer<'s>, start: Start) -> Self {
        Self {
            start: Some(start),
            prefix: Some(wire::prefix()),
            body: Output::new(peer, None),
        }
    }
}
impl<Start: AsyncFnOnce(Protocol) -> Result<(), Error>> ClientRequests for Requests<'_, '_, Start> {
    async fn connected(&mut self, protocol: Protocol) -> Result<(), Error> {
        if !matches!(protocol, Protocol::Raw(_)) {
            return Err(Error::Binding);
        }
        self.start.take().ok_or(Error::Binding)?(protocol).await
    }
    async fn next(&mut self, out: &mut [u8]) -> Result<Option<usize>, ()> {
        let Some(prefix) = self.prefix.as_ref() else {
            return Ok(None);
        };
        out.get_mut(..prefix.len)
            .ok_or(())?
            .copy_from_slice(&prefix.bytes[..prefix.len]);
        Ok(Some(prefix.len))
    }
    async fn body(&mut self, stream: u64, out: &mut [u8]) -> Result<usize, ()> {
        if stream != 0 {
            return Err(());
        }
        self.body.read(out).await
    }
    fn started(&mut self, stream: u64) -> Result<(), ()> {
        if stream != 0 {
            return Err(());
        }
        self.prefix.take().map(|_| ()).ok_or(())
    }
}
pub struct Input<'a, 's> {
    peer: &'a StreamPeer<'s>,
    decoder: Decoder,
}
impl<'a, 's> Input<'a, 's> {
    pub fn new(peer: &'a StreamPeer<'s>) -> Self {
        Self {
            peer,
            decoder: Decoder::new(),
        }
    }
}
impl StreamSink for Input<'_, '_> {
    fn poll_write(
        &mut self,
        stream: u64,
        input: &[u8],
        _: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<usize, ()>> {
        core::task::Poll::Ready((|| {
            if stream != 0 {
                return Err(());
            }
            let n = input.len().min(CAPACITY - self.decoder.len);
            if n == 0 {
                return Err(());
            }
            self.decoder.bytes[self.decoder.len..self.decoder.len + n].copy_from_slice(&input[..n]);
            self.decoder.len += n;
            Ok(n)
        })())
    }
    async fn flush(&mut self, stream: u64) -> Result<(), ()> {
        if stream != 0 {
            return Err(());
        }
        if !self.decoder.prefix()? {
            return Ok(());
        }
        while let Some(frame) = self.decoder.next()? {
            poll_fn(|cx| self.peer.poll_incoming(frame.header, frame.payload, cx))
                .await
                .map_err(|_| ())?;
            self.decoder.consume(frame.consumed)?;
        }
        Ok(())
    }
    async fn finish(&mut self, stream: u64) -> Result<(), ()> {
        if stream != 0 {
            return Err(());
        }
        self.decoder.finish()
    }
}
pub struct Service<'a, 's, Start> {
    pub start: Option<Start>,
    pub peer: &'a StreamPeer<'s>,
}
impl<'a, 's, Start: AsyncFnOnce(Protocol) -> Result<(), Error>> ServerHandler
    for Service<'a, 's, Start>
{
    async fn connected(&mut self, protocol: Protocol) -> Result<(), Error> {
        if !matches!(protocol, Protocol::Raw(_)) {
            return Err(Error::Binding);
        }
        self.start.take().ok_or(Error::Binding)?(protocol).await
    }

    type Body = Output<'a, 's>;
    fn request_limit(&self) -> Option<core::num::NonZeroUsize> {
        core::num::NonZeroUsize::new(1)
    }
    async fn open(&mut self, stream: u64, prefix: &[u8]) -> Result<Self::Body, ()> {
        if stream != 0 || !prefix.is_empty() {
            return Err(());
        }
        Ok(Output::new(self.peer, Some(wire::prefix())))
    }
}
