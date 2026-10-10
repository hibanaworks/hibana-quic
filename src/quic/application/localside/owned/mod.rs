//! Caller-storage execution for the canonical QUIC application graph.
//! Applications supply their own request, body and sink effects; no CLI file types.
mod client;
mod server;
use crate::quic::application::imp::profile::{DATAGRAM, PARAMETERS};
use crate::quic::application::{ClientProfile, ServerProfile};
pub use client::client;
pub use server::server;
