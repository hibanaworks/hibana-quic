//! Packet storage, framing and numerical calculations used by the QUIC locals.
use super::*;
pub mod application_wire;
pub mod early_wire;
pub(crate) mod idle;
pub mod kernel;
pub mod parameters;
pub mod publication_gate;
pub mod recovery;
pub mod tls;
pub(crate) mod wire;

pub mod crypto_buffer;
