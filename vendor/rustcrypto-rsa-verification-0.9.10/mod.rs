//! Private verification-only extraction; see README.md and provenance.json.
#![allow(
    clippy::manual_div_ceil,
    clippy::needless_borrows_for_generic_args,
    clippy::legacy_numeric_constants
)]
#[derive(Debug)]
pub(crate) enum Error {
    Verification,
}
pub(crate) type Result<T> = core::result::Result<T, Error>;
pub(crate) mod mgf;
pub(crate) mod pkcs1v15;
pub(crate) mod pss;
