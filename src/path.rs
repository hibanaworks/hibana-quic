//! Fixed-path address data used by the current UDP adapters.
//!
//! The unconnected legacy path-validation/migration controller was removed.
//! Future migration and challenge lifetimes must be projected Hibana contracts;
//! this module does not implement or qualify those features.
use core::net::SocketAddr;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Address {
    pub local: SocketAddr,
    pub remote: SocketAddr,
}
