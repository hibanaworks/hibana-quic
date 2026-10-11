//! Physical path addresses, scoped CID receipts, and projected path validation.
//! Address changes are admitted by authenticated packet observations and a
//! matching physical challenge response; available storage is not path proof.
pub mod global;
pub(crate) mod imp;
pub use imp::preferred::Preferred;
pub use imp::{ids, peer_ids, preferred};
pub mod localside;
