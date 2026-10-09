//! Common authenticated connection startup with injected physical capabilities.
mod client;
mod server;
pub use client::connect;
pub use server::accept;
pub const DATAGRAM: usize = crate::quic::application::imp::owned::DATAGRAM;
pub const PARAMETERS: usize = 2048;

/// Bounded setup calculations shared by native endpoints.
mod imp;

/// Finite request/response connection settings. These values do not track progress.
pub struct Client<'a> {
    pub address: crate::quic::path::Address,
    pub now: hibana_tls::certificate::UnixTime,
    pub server_name: &'a str,
    pub trust_anchors: &'a [hibana_tls::certificate::TrustAnchor<'a>],
    pub protocol: hibana_tls::Protocol,
    pub idle_timeout_ms: u64,
    pub stream_capacity: usize,
}
pub struct Server<'a> {
    pub protocol: hibana_tls::Protocol,
    pub certificate_chain: &'a [&'a [u8]],
    pub signing_key: &'a hibana_tls::handshake::SigningKey,
    pub idle_timeout_ms: u64,
    pub stream_capacity: usize,
}
