//! HTTP/3 control order, its endpoint-owning localside, and bounded byte codecs.
pub mod global;
pub mod imp;
pub mod local;
pub use imp::wire::*;

/// Bounded request validation and projected response consumption.
pub mod message;
