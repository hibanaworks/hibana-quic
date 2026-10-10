//! Validated ACK evidence is retained without blocking handshake confirmation.
//! Only the projected adapter continuation consumes it to apply stream effects.
use crate::quic::application::{Control, Error};
use crate::quic::imp::recovery::FrameAcknowledgments;
use crate::quic::imp::tls::Inbox;
pub(in crate::quic::application) struct Exchange<'scope> {
    pub(in crate::quic::application) pending: Inbox<FrameAcknowledgments<'scope>>,
    pub(in crate::quic::application) loss:
        Inbox<crate::quic::imp::recovery::ApplicationLoss<'scope>>,
}
impl<'scope> Exchange<'scope> {
    pub(in crate::quic::application) fn new() -> Self {
        Self {
            pending: Inbox::new(),
            loss: Inbox::new(),
        }
    }
    pub(in crate::quic::application) fn deliver(
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
    pub(in crate::quic::application) fn settled(
        &self,
        control: &Control<'_, 'scope>,
    ) -> Result<(), Error> {
        control.changed()
    }
}
