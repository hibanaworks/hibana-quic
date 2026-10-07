//! Validated ACK evidence is retained without blocking handshake confirmation.
//! Only the projected adapter continuation consumes it to apply stream effects.
use super::{Control, Error};
use crate::quic::{recovery::FrameAcknowledgments, tls::Inbox};
pub(super) struct Exchange<'scope> {
    pub(super) pending: Inbox<FrameAcknowledgments<'scope>>,
    pub(super) loss: Inbox<crate::quic::recovery::ApplicationLoss<'scope>>,
}
impl<'scope> Exchange<'scope> {
    pub(super) fn new() -> Self {
        Self {
            pending: Inbox::new(),
            loss: Inbox::new(),
        }
    }
    pub(super) fn deliver(
        &self,
        grant: FrameAcknowledgments<'scope>,
        control: &Control<'_, 'scope>,
    ) -> Result<(), Error> {
        let grant = if self.pending.is_empty() {
            grant
        } else {
            let mut previous = self.pending.take().map_err(|_| Error::Binding)?;
            previous.merge(grant)?;
            previous
        };
        self.pending.put(grant).map_err(|_| Error::Binding)?;
        control.changed()
    }
    pub(super) fn settled(&self, control: &Control<'_, 'scope>) -> Result<(), Error> {
        control.changed()
    }
}
