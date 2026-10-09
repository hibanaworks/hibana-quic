//! Stream buffers, accounting and frame encoding owned by application locals.
pub mod stream;

/// Allocator-backed resource owner; entropy is supplied by the environment.
#[cfg(feature = "alloc")]
pub mod owned;
