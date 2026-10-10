//! HTTP/3 message decoding using one Hibana global and direct localsides.
//!
//! [`crate::http3::message::decode_response`] consumes FIN-complete random-access storage in place. It is not
//! a streaming client or a connection factory. The caller owns publication of
//! the resulting body; an error must leave that storage unpublished.
//! [`crate::http3::message::decode_request`] validates the bounded GET profile used by `hq`.
pub mod global;
mod imp;
pub mod localside;
pub use imp::request::decode_request;
pub use localside::run::decode_response;
pub type Result<T> = core::result::Result<T, Error>;

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

pub use imp::buffer::Exchange;
