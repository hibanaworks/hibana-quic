//! early data choreography, direct role locals and numerical implementation.
pub mod global;
pub(crate) mod imp;
pub use hibana_tls::early::*;
pub use imp::QuarantineSlot;
pub mod localside;
pub use imp::exchange::{
    Admission, AuthenticatedInput, ControlBlock, Exchange, Range, StoredPacket,
};

#[derive(Debug)]
pub enum Failure {
    Endpoint(hibana::EndpointError),
    Bytes(imp::Error),
    Binding,
}
impl From<hibana::EndpointError> for Failure {
    fn from(e: hibana::EndpointError) -> Self {
        Self::Endpoint(e)
    }
}
impl From<imp::Error> for Failure {
    fn from(e: imp::Error) -> Self {
        Self::Bytes(e)
    }
}
