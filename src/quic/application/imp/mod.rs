//! Stream buffers, accounting and frame encoding owned by application locals.
pub mod stream;

pub(crate) mod acknowledgments;
pub(crate) mod io;
pub(crate) mod keys;
/// Allocator-backed resource owner; entropy is supplied by the environment.
#[cfg(feature = "alloc")]
pub mod owned;
pub(crate) mod publication;
pub(crate) mod reset;

pub(crate) mod reclaim;

#[cfg(feature = "alloc")]
pub(crate) mod profile;

pub(super) mod frame;
