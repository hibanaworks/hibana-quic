//! Linux host-only adapters. This crate is outside the no_std/no_alloc core.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
pub mod udp;

#[cfg(target_os = "linux")]
pub mod path_socket;

#[cfg(target_os = "linux")]
pub mod async_io;
