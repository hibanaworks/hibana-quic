//! Physical environment implementations for hibana-quic.
//! The same no_std capability contracts apply with or without an OS.
#![no_std]
#![deny(unsafe_code)]
#[cfg(any(target_os = "linux", target_os = "macos"))]
extern crate alloc;
#[cfg(test)]
#[macro_use]
extern crate std;
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(unsafe_code)]
mod sys;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod unix;

pub use hibana_quic::entropy::Entropy;
/// Platform implementations satisfy these executor-neutral, no_std capabilities.
pub use hibana_quic::io::{Clock, DatagramSocket, RandomAccess};
