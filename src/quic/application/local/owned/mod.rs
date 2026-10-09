//! Allocator-backed execution for the canonical QUIC application graph.
//! Applications supply their own request, body and sink effects; no CLI file types.
use crate::http3::Protocol;
mod client;
mod server;
pub use client::client;
pub use server::server;
/// Resource limits and caller-supplied parameters, never protocol progress.
pub struct ClientProfile {
    pub generation: u64,
    pub protocol: Protocol,
    pub stream_capacity: usize,
    pub early_request_capacity: usize,
    pub key_update_target: u64,
    pub idle_timeout_ms: u64,
}
/// Resource limits and caller-supplied parameters, never protocol progress.
pub struct ServerProfile<'a> {
    pub generation: u64,
    pub protocol: Protocol,
    pub stream_capacity: usize,
    pub server_token: Option<&'a [u8]>,
    pub idle_timeout_ms: u64,
}

pub const DATAGRAM: usize = crate::quic::application::imp::owned::DATAGRAM;
pub const PARAMETERS: usize = 2048;
