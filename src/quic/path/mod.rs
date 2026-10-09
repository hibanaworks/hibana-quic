//! Physical path addresses, scoped CID receipts, and projected path validation.
//! Address changes are admitted by authenticated packet observations and a
//! matching physical challenge response; available storage is not path proof.
use core::net::SocketAddr;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Address {
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

pub mod global;
pub mod imp;
pub mod local;
