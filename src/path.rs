//! Physical path addresses, scoped CID receipts, and projected path validation.
//! Address changes are admitted by authenticated packet observations and a
//! matching physical challenge response; available storage is not path proof.
use core::net::SocketAddr;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Address {
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

pub mod ids;
pub(crate) mod responses;

pub mod global;
pub(crate) mod validation;

pub mod preferred;

pub mod peer_ids;
