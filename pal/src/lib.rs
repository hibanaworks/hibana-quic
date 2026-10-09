//! Native environment access: UDP, readiness, clocks, entropy and files.
//! Protocol globals, localsides and calculations live in hibana-quic.
#![deny(unsafe_code)]

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod udp;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod path_socket;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod async_io;

/// Concrete reactor-backed UDP and clock effects.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod io;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod entropy;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(unsafe_code)]
mod sys;

/// Native file storage.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod fs;

/// PEM decoding for caller-owned certificate and key files.
pub mod pem;

/// Native launch: bind sockets, read credentials and drive the common connection.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod launch;
