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

/// Bounded routing of actual received datagrams to owned connections.
pub mod receive_routes;

pub(crate) mod initial;
pub(crate) mod sealing;
pub(crate) mod transcript;

pub mod early_requests;

pub mod datagram;

pub(crate) mod handshake_wire;
