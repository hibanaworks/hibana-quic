//! HTTP/3 message decoding using one Hibana global and direct localsides.
//!
//! [`decode_response`] consumes FIN-complete random-access storage in place. It is not
//! a streaming client or a connection factory. The caller owns publication of
//! the resulting body; an error must leave that storage unpublished.
//! [`decode_request`] validates the bounded GET profile used by `hq`.
pub mod global;
mod imp;
pub mod local;
use crate::io::RandomAccess;
use crate::{
    http3::{self, Fields},
    runtime::carrier::CarrierStorage,
};
use core::cell::RefCell;
use global::*;
use hibana::runtime::{
    SessionKitStorage,
    ids::SessionId,
    program::{RoleProgram, project},
};
use imp::wire::unknown;
use local::Exchange;
pub type Result<T> = core::result::Result<T, Error>;

/// Decode only FIN-complete random-access storage. No destination is published here;
/// the caller keeps its existing atomic download-finish ownership contract.
pub async fn decode_response(file: &impl RandomAccess, slab: &mut [u8]) -> Result<u64> {
    let total = file.len().map_err(Error::from)?;
    let global = choreography();
    let reader: RoleProgram<READER> = project(&global);
    let writer: RoleProgram<WRITER> = project(&global);
    let carrier = CarrierStorage::<1, 16, 128>::new();
    let mut kit = SessionKitStorage::uninit();
    let sid = SessionId::new(1);
    let rendezvous = kit
        .init()
        .rendezvous(slab, carrier.bind(sid).map_err(Error::from)?)
        .map_err(Error::from)?;
    let mut reader = rendezvous.enter(sid, &reader).map_err(Error::from)?;
    let mut writer = rendezvous.enter(sid, &writer).map_err(Error::from)?;
    let exchange = Exchange {
        fields: RefCell::new(None),
        bytes: RefCell::new([0; 4096]),
    };
    let written = RefCell::new(0);
    crate::runtime::join2(
        local::read(&mut reader, file, total, &exchange),
        local::write(&mut writer, file, &exchange, &written),
    )
    .await?;
    Ok(written.into_inner())
}

/// A FIN-complete bounded GET request: HEADERS first, then an empty body.
/// Unknown extensions are skipped by their actual lengths. This file-service
/// profile does not accept pushed responses, CONNECT, or nonempty GET bodies.
pub fn decode_request(input: &[u8]) -> Result<Fields> {
    let mut offset = 0usize;
    let decoded = loop {
        let frame = http3::decode_frame_header(input.get(offset..).ok_or("request framing")?)
            .map_err(Error::from)?;
        offset = offset
            .checked_add(frame.encoded_len)
            .ok_or("request offset overflow")?;
        let end = offset
            .checked_add(usize::try_from(frame.length).map_err(Error::from)?)
            .ok_or("request length overflow")?;
        let bytes = input.get(offset..end).ok_or("truncated request frame")?;
        offset = end;
        if frame.kind == 1 {
            break http3::decode_fields(bytes).map_err(Error::from)?;
        }
        unknown(frame.kind)?;
    };
    if decoded.status.is_some()
        || decoded.method != Some(http3::Method::Get)
        || decoded.https != Some(true)
        || decoded.path_len == 0
        || decoded.authority_len == 0
        || decoded.content_length.is_some_and(|n| n != 0)
    {
        return Err("request is not a bounded HTTPS GET".into());
    }
    while offset < input.len() {
        let frame = http3::decode_frame_header(&input[offset..]).map_err(Error::from)?;
        offset += frame.encoded_len;
        let end = offset
            .checked_add(usize::try_from(frame.length).map_err(Error::from)?)
            .ok_or("request length overflow")?;
        input.get(offset..end).ok_or("truncated request body")?;
        if frame.kind != 0 || frame.length != 0 {
            unknown(frame.kind)?;
        }
        offset = end;
    }
    Ok(decoded)
}

/// Failure evidence for bounded message decoding and projected role progress.
#[derive(Debug)]
pub enum Error {
    Invalid(&'static str),
    Io(crate::io::IoError),
    Wire(crate::quic::imp::kernel::packet::Error),
    Fields(super::Error),
    Endpoint(hibana::EndpointError),
    Attach(hibana::runtime::AttachError),
    Transport(hibana::runtime::transport::TransportError),
    Length(core::num::TryFromIntError),
}
impl From<&'static str> for Error {
    fn from(value: &'static str) -> Self {
        Self::Invalid(value)
    }
}
impl From<crate::io::IoError> for Error {
    fn from(value: crate::io::IoError) -> Self {
        Self::Io(value)
    }
}
impl From<crate::quic::imp::kernel::packet::Error> for Error {
    fn from(value: crate::quic::imp::kernel::packet::Error) -> Self {
        Self::Wire(value)
    }
}
impl From<super::Error> for Error {
    fn from(value: super::Error) -> Self {
        Self::Fields(value)
    }
}
impl From<hibana::EndpointError> for Error {
    fn from(value: hibana::EndpointError) -> Self {
        Self::Endpoint(value)
    }
}
impl From<hibana::runtime::AttachError> for Error {
    fn from(value: hibana::runtime::AttachError) -> Self {
        Self::Attach(value)
    }
}
impl From<hibana::runtime::transport::TransportError> for Error {
    fn from(value: hibana::runtime::transport::TransportError) -> Self {
        Self::Transport(value)
    }
}
impl From<core::num::TryFromIntError> for Error {
    fn from(value: core::num::TryFromIntError) -> Self {
        Self::Length(value)
    }
}
