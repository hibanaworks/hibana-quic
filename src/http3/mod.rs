//! HTTP/3 control order, its endpoint-owning localside, and bounded byte codecs.
pub mod global;
pub(crate) mod imp;
pub mod localside;
pub use imp::wire::*;

/// Bounded request validation and projected response consumption.
pub mod message;

/// Caller-owned buffers for one native HTTP exchange.
pub use imp::storage::Storage;
