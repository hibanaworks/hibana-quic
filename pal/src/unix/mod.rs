//! Linux and macOS capabilities. Uses core/alloc and a confined native ABI.
pub mod clock;
pub mod entropy;
pub mod error;
pub mod paths;
pub mod reactor;
pub mod udp;
pub use crate::sys::os::{AsRawFd, Instant, OwnedFd, UdpSocket, UnixStream};

#[allow(unsafe_code)]
pub mod files;
