//! Bounded HTTP/3 byte decoding, immutable tables and control-stream storage.
pub(crate) mod control;
mod tables;
pub mod wire;

pub(crate) mod stream;

pub(crate) mod storage;
