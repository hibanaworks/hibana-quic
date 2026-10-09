//! The canonical QUIC-specific TLS API, implemented by `hibana-tls`.
//!
//! These are direct module re-exports, with no forwarding functions, extra key
//! owners or protocol controller. Only QUIC CRYPTO reassembly lives here.
pub use hibana_tls::endpoint::*;
pub use hibana_tls::signature::rsa;
pub use hibana_tls::{certificate, handshake, key_exchange, schedule, ticket, wire};

pub mod buffer;
