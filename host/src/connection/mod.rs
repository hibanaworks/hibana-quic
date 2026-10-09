//! Host-owned allocation and attachment for the canonical Hibana QUIC prefix.
//! This is the authenticated handshake entry, not a complete HTTP/3 client SDK.
pub use hibana_quic::quic::global;
pub mod local;
pub use local::handshake;
pub const DATAGRAM: usize = crate::io::DATAGRAM;
pub const PARAMETERS: usize = 2048;

/// Bounded setup calculations shared by native endpoints.
pub mod imp;

/// Finite request/response connection settings. These values do not track progress.
pub struct Client<'a> {
    pub remote: std::net::SocketAddr,
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
