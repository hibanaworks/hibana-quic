//! Linux host-only adapters. This crate is outside the no_std/no_alloc core.
#![deny(unsafe_code)]

#[cfg(target_os = "linux")]
pub mod udp;

#[cfg(target_os = "linux")]
pub mod path_socket;

#[cfg(target_os = "linux")]
pub mod async_io;

pub mod receive_routes;

/// Concrete reactor-backed UDP and clock effects.
#[cfg(target_os = "linux")]
pub mod io;
/// Caller-selected bounded connection buffers and limits.
pub mod storage;

#[cfg(target_os = "linux")]
pub mod entropy;

#[cfg(any(target_os="linux",target_os="macos"))]
#[allow(unsafe_code)]
mod os;

/// FIN-complete HTTP/3 file-service framing and response decoding.
#[cfg(target_os = "linux")]
pub mod http3;
