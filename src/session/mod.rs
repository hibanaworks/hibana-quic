//! OS-independent attachment of an application localside to an ordered stream.
//! Application progress remains in its projected Hibana program.

use crate::runtime::carrier::CarrierStorage;
mod imp;
pub mod local;
#[derive(Clone, Copy)]
pub enum Protocol {
    Quic,
    Http3,
}
impl Protocol {
    pub fn negotiated(self) -> hibana_tls::Protocol {
        match self {
            Self::Quic => hibana_tls::Protocol::Raw(
                hibana_tls::RawProtocol::new(b"hibana/1").expect("static ALPN"),
            ),
            Self::Http3 => hibana_tls::Protocol::Http3,
        }
    }
}
/// Caller-owned runtime storage; no heap or native executor is required.
pub struct Storage {
    carrier: CarrierStorage<4, 256, 8>,
}
impl Storage {
    pub const fn new() -> Self {
        Self {
            carrier: CarrierStorage::new(),
        }
    }
}
impl Default for Storage {
    fn default() -> Self {
        Self::new()
    }
}
#[derive(Debug)]
pub enum Error<E> {
    Transport(hibana::runtime::transport::TransportError),
    Attach(hibana::runtime::AttachError),
    Local(E),
    Network(E),
}
