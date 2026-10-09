//! Host-owned resources for the canonical QUIC application graph.
//! Applications supply their own request, body and sink effects; no CLI file types.
pub use hibana_quic::quic::application::global;
pub use hibana_quic::quic::application::{BodyReader, ClientRequests, ServerHandler, StreamSink};
pub mod local;
use hibana_quic::http3::Protocol;
pub use local::{client, server};
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
