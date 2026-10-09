//! Stream effects for the application connection graph. No native OS types.
use super::super::{
    Protocol,
    imp::wire::{self, Bytes, CAPACITY, Decoder},
};
use super::StreamPeer;
use crate::quic::application::{BodyReader, ClientRequests, Error, ServerHandler, StreamSink};
use core::future::poll_fn;
pub struct Output<'a, 's> {
    peer: &'a StreamPeer<'s>,
    protocol: Protocol,
    pending: Option<Bytes>,
}
impl<'a, 's> Output<'a, 's> {
    fn new(peer: &'a StreamPeer<'s>, protocol: Protocol, pending: Option<Bytes>) -> Self {
        Self {
            peer,
            protocol,
            pending,
        }
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
            self.pending = Some(wire::message(self.protocol, frame)?);
        }
        let pending = self.pending.as_mut().ok_or(())?;
        let n = pending.read(out);
        if pending.offset == pending.len {
            self.pending = None;
        }
        Ok(n)
    }
}
pub struct Requests<'a, 's> {
    prefix: Option<Bytes>,
    body: Output<'a, 's>,
}
impl<'a, 's> Requests<'a, 's> {
    pub fn new(
        peer: &'a StreamPeer<'s>,
        protocol: Protocol,
        authority: &str,
    ) -> Result<Self, Error> {
        Ok(Self {
            prefix: Some(wire::prefix(protocol, Some(authority)).map_err(|_| Error::Application)?),
            body: Output::new(peer, protocol, None),
        })
    }
}
impl ClientRequests for Requests<'_, '_> {
    fn peer_settings(&mut self, settings: crate::http3::Settings) -> Result<(), Error> {
        if settings.max_field_section_size < 512 {
            Err(Error::Application)
        } else {
            Ok(())
        }
    }
    async fn next(&mut self, out: &mut [u8]) -> Result<Option<usize>, ()> {
        let Some(prefix) = self.prefix.take() else {
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
        if stream == 0 { Ok(()) } else { Err(()) }
    }
}
pub struct Input<'a, 's> {
    peer: &'a StreamPeer<'s>,
    decoder: Decoder,
}
impl<'a, 's> Input<'a, 's> {
    pub fn new(peer: &'a StreamPeer<'s>, protocol: Protocol, request: bool) -> Self {
        Self {
            peer,
            decoder: Decoder::new(protocol, request),
        }
    }
}
impl StreamSink for Input<'_, '_> {
    async fn write(&mut self, stream: u64, mut input: &[u8]) -> Result<(), ()> {
        if stream != 0 {
            return Err(());
        }
        while !input.is_empty() {
            let n = input.len().min(CAPACITY - self.decoder.len);
            if n == 0 {
                return Err(());
            }
            self.decoder.bytes[self.decoder.len..self.decoder.len + n].copy_from_slice(&input[..n]);
            self.decoder.len += n;
            input = &input[n..];
            if !self.decoder.prefix()? {
                continue;
            }
            while let Some(frame) = self.decoder.next()? {
                poll_fn(|cx| self.peer.poll_incoming(frame.header, frame.payload, cx))
                    .await
                    .map_err(|_| ())?;
                self.decoder.consume(frame.consumed)?;
            }
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
pub struct Service<'a, 's> {
    pub peer: &'a StreamPeer<'s>,
    pub protocol: Protocol,
}
impl<'a, 's> ServerHandler for Service<'a, 's> {
    type Body = Output<'a, 's>;
    fn peer_settings(&mut self, settings: crate::http3::Settings) -> Result<(), Error> {
        if settings.max_field_section_size < 512 {
            Err(Error::Application)
        } else {
            Ok(())
        }
    }
    fn request_limit(&self) -> Option<core::num::NonZeroUsize> {
        core::num::NonZeroUsize::new(1)
    }
    async fn open(&mut self, stream: u64, prefix: &[u8]) -> Result<Self::Body, ()> {
        if stream != 0 || !prefix.is_empty() {
            return Err(());
        }
        Ok(Output::new(
            self.peer,
            self.protocol,
            Some(wire::prefix(self.protocol, None)?),
        ))
    }
}
