//! Optional HTTP/0.9 interop profile (`hq` Cargo feature, disabled by default).
//! Uses the same authenticated connection global and stream localsides as QUIC
//! and HTTP/3. GET encoding and bounded request/body effects live here; filesystem policy stays with
//! the caller. Run bounded request/sink effects with [`crate::session::Client::transfer`]
//! or [`crate::session::Server::serve`]. These operations need no OS or allocator.
mod imp;
pub use imp::codec::{Error, decode_request, encode_request};
/// Explicit selection of the optional profile; never the default ALPN.
pub const PROTOCOL: crate::session::Protocol = crate::session::Protocol::Hq;
pub use imp::effects::{Requests, Response, Service};
