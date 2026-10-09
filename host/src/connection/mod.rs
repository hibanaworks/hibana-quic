//! Host-owned allocation and attachment for the canonical Hibana QUIC prefix.
//! This is the authenticated handshake entry, not a complete HTTP/3 client SDK.
pub use hibana_quic::quic::global;
pub mod local;
pub use local::handshake;
pub const DATAGRAM: usize = crate::io::DATAGRAM;
pub const PARAMETERS: usize = 2048;
