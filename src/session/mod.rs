//! OS-independent attachment of an application localside to an ordered stream.
//! Application progress remains in its projected Hibana program.

use crate::runtime::carrier::CarrierStorage;
mod imp;
/// Stream adapters for caller-owned connection storage.
pub use imp::stream;
pub mod localside;
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
/// Borrowed stream-facing half of the application carrier.
pub type StreamPeer<'a> = crate::runtime::carrier::Peer<'a, 4, 256, 8>;

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

pub const DATAGRAM: usize = crate::quic::application::imp::owned::DATAGRAM;
pub const PARAMETERS: usize = 2048;

/// Finite request/response connection settings. These values do not track progress.
pub struct Client<'a> {
    pub address: crate::io::Address,
    pub now: hibana_tls::certificate::UnixTime,
    pub server_name: &'a str,
    pub trust_anchors: &'a [hibana_tls::certificate::TrustAnchor<'a>],
    pub protocol: Protocol,
    pub idle_timeout_ms: u64,
    pub stream_capacity: usize,
}
pub struct Server<'a> {
    pub protocol: Protocol,
    pub certificate_chain: &'a [&'a [u8]],
    pub signing_key: &'a hibana_tls::handshake::SigningKey,
    pub idle_timeout_ms: u64,
    pub stream_capacity: usize,
}
