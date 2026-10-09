#![no_std]
#![allow(long_running_const_eval)]
#![forbid(unsafe_code)]
// Failure must return actual affine reservations/keys inline. Boxing would add
// allocation and change ownership; their bounded sizes are deliberate.
#![allow(clippy::result_large_err)]
//! QUIC and HTTP/3 with communication authority expressed by Hibana choreography.
//! Start with each protocol's global and direct locals; numerical mechanisms
//! live with their owning domain. Storage is bounded and caller-owned.

#[cfg(test)]
extern crate self as hibana_quic;
#[cfg(test)]
extern crate std;

pub mod crypto;
pub mod http3;
pub mod io;
pub mod quic;
pub mod runtime;

/// Caller-owned cryptographic entropy input.
pub use hibana_tls::entropy;

#[cfg(test)]
#[path = "../tests/support/async_tls_fixture.rs"]
pub(crate) mod scoped_tls_fixture;

#[cfg(test)]
#[allow(dead_code)]
#[path = "../tests/support/tls_actor_fixture.rs"]
pub(crate) mod tls_fixture;

/// OS-independent application session attachment and stream framing.
pub mod session;
