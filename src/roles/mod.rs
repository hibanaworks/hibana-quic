//! Readable role-local implementations over one projected choreography.
//!
//! These roles own real resources. The enclosing session retains endpoint
//! values until every role finishes; no actor recreates or synchronously polls
//! another actor's endpoint. Numerical buffer/descriptor checks remain local.
pub mod packet_protection;
pub mod protocol;

pub mod client;
pub mod protocol_tls;
pub mod protocol_tls_phases;
pub mod tls_owner;

pub mod packet_authority;
pub mod protocol_recovery;
pub mod recovery_owner;

pub mod protocol_path;

pub mod path_owner;

pub mod connection_authority;

pub mod protocol_stream;
pub mod stream_owner;

pub mod sealed_packet;

pub mod datagram;

pub mod protocol_early;
pub mod early_owner;
