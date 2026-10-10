//! One pending ECN marking request.
use crate::quic::imp::{kernel::accounting::PacketNumber, tls::Inbox};
#[derive(Clone, Copy)]
pub(in crate::quic) struct Requested {
    pub(in crate::quic) packet: PacketNumber,
    pub(in crate::quic) ack_eliciting: bool,
}
pub(crate) struct Exchange {
    pub(in crate::quic) requested: Inbox<Option<Requested>>,
}
impl Exchange {
    pub(crate) const fn new() -> Self {
        Self {
            requested: Inbox::new(),
        }
    }
}
