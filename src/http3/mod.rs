//! HTTP/3: explicit global control choreography and bounded wire codecs.
//! Direct IO roles remain with their privately owned QUIC application resources.
pub mod global;
mod tables;
pub mod wire;
pub use wire::*;
