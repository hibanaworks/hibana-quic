//! Distinct early-data authority. No EarlyReceiveTicket can authorize an ACK
//! mutation or ordinary delivery. Release follows the actual typed Finished
//! receipt and a checked quarantine revision; cryptography belongs to the TLS
//! actor and the affine replay claim belongs to the quarantine.
use super::*;
use crate::early_data::{Quarantine, ReleaseTicket as QuarantineTicket};
use crate::protocol::*;
use crate::roles::tls_owner::{EarlyOpenReceipt, FinishedReceipt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EarlyReceiveTicket(Descriptor);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EarlyBufferTicket {
    descriptor: Descriptor,
    receive: EarlyReceiveTicket,
    stream_id: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EarlyReleaseTicket {
    descriptor: Descriptor,
    quarantine: QuarantineTicket,
    stream_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EarlyPeerCloseTicket {
    descriptor: Descriptor,
    receive: EarlyReceiveTicket,
    error_code: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EarlyControlBufferTicket {
    descriptor: Descriptor,
    receive: EarlyReceiveTicket,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EarlyControlReleaseTicket {
    descriptor: Descriptor,
    control: crate::early_control::ControlTicket,
}
impl EarlyControlReleaseTicket {
    pub(crate) const fn descriptor_id(self) -> u32 {
        self.descriptor.id
    }
    pub(crate) const fn generation(self) -> u64 {
        self.descriptor.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EarlyIntentTicket {
    descriptor: Descriptor,
    import: crate::early_send::ImportTicket,
}
pub(super) struct State {
    receive: Option<EarlyReceiveTicket>,
    buffer: Option<EarlyBufferTicket>,
    control_buffer: Option<EarlyControlBufferTicket>,
    peer_close: Option<EarlyPeerCloseTicket>,
    control_release: Option<EarlyControlReleaseTicket>,
    next_control_revision: Option<u64>,
    finished: Option<FinishedReceipt>,
    release: Option<EarlyReleaseTicket>,
    intent: Option<EarlyIntentTicket>,
    next_intent_stream: u64,
    next_revision: Option<u64>,
}
impl State {
    pub(super) const fn new() -> Self {
        Self {
            receive: None,
            buffer: None,
            control_buffer: None,
            peer_close: None,
            control_release: None,
            next_control_revision: Some(0),
            finished: None,
            release: None,
            intent: None,
            next_intent_stream: 0,
            next_revision: Some(0),
        }
    }
    pub(super) fn retired() -> Self {
        Self {
            next_revision: None,
            next_control_revision: None,
            ..Self::new()
        }
    }
    pub(super) fn receiving(&self) -> bool {
        self.receive.is_some()
    }
}
impl Driver<'_> {
    /// Consume one successful Open from the TLS owner, together with the
    /// quarantine that consumed this connection's committed replay claim.
    /// Neither a key snapshot nor an asserted authentication flag can create
    /// this authority. Packet-number replay and whole-packet preflight remain
    /// numerical obligations of the connection owner.
    pub fn begin_early_receive<const BYTES: usize>(
        &mut self,
        opened: EarlyOpenReceipt,
        quarantine: &Quarantine<'_, BYTES>,
    ) -> Result<EarlyReceiveTicket, DriverError> {
        self.ensure_live()?;
        if opened.generation() != self.generation
            || !quarantine.accepts_authenticated_generation(opened.generation())
        {
            return Err(DriverError::InvalidTicket);
        }
        if self.receive.is_some() || self.early.receive.is_some() {
            return Err(DriverError::ReceiveBusy);
        }
        let descriptor = self.issue_descriptor()?;
        self.execute(|roles| {
            poll_ready(roles.ingress.send::<EarlyAuthenticated>(&descriptor.id))?;
            match_id(
                poll_ready(roles.packet.recv::<EarlyAuthenticated>())?,
                descriptor.id,
            )
        })?;
        let ticket = EarlyReceiveTicket(descriptor);
        self.early.receive = Some(ticket);
        Ok(ticket)
    }
    fn validate_early_receive(&self, ticket: EarlyReceiveTicket) -> Result<(), DriverError> {
        self.ensure_live()?;
        if ticket.0.generation != self.generation || self.early.receive != Some(ticket) {
            return Err(DriverError::InvalidTicket);
        }
        Ok(())
    }
    pub fn finish_early_receive(&mut self, ticket: EarlyReceiveTicket) -> Result<(), DriverError> {
        self.validate_early_receive(ticket)?;
        if self.early.buffer.is_some()
            || self.early.control_buffer.is_some()
            || self.early.peer_close.is_some()
        {
            return Err(DriverError::ReceiveEffectBusy);
        }
        self.execute(|roles| {
            poll_ready(roles.packet.send::<EarlyReceived>(&ticket.0.id))?;
            match_id(
                poll_ready(roles.ingress.recv::<EarlyReceived>())?,
                ticket.0.id,
            )
        })?;
        self.early.receive = None;
        Ok(())
    }
    pub fn begin_early_buffer(
        &mut self,
        receive: EarlyReceiveTicket,
        stream_id: u64,
    ) -> Result<EarlyBufferTicket, DriverError> {
        self.validate_early_receive(receive)?;
        if self.early.buffer.is_some()
            || self.early.control_buffer.is_some()
            || self.early.peer_close.is_some()
        {
            return Err(DriverError::ReceiveEffectBusy);
        }
        if stream_id > crate::packet::MAX_VARINT {
            return Err(DriverError::InvalidStreamId);
        }
        let ticket = EarlyBufferTicket {
            descriptor: self.issue_descriptor()?,
            receive,
            stream_id,
        };
        let wire = buffer_wire(ticket);
        self.execute(|roles| {
            poll_ready(roles.packet.send::<EarlyBufferRequest>(&wire))?;
            match_bytes(
                poll_ready(roles.application.recv::<EarlyBufferRequest>())?,
                wire,
            )
        })?;
        self.early.buffer = Some(ticket);
        Ok(ticket)
    }
    pub fn finish_early_buffer(&mut self, ticket: EarlyBufferTicket) -> Result<(), DriverError> {
        self.validate_early_receive(ticket.receive)?;
        if self.early.buffer != Some(ticket) {
            return Err(DriverError::InvalidTicket);
        }
        let wire = buffer_wire(ticket);
        self.execute(|roles| {
            poll_ready(roles.application.send::<EarlyBufferCompleted>(&wire))?;
            match_bytes(
                poll_ready(roles.packet.recv::<EarlyBufferCompleted>())?,
                wire,
            )
        })?;
        self.early.buffer = None;
        Ok(())
    }
    /// A valid CONNECTION_CLOSE in an accepted/authenticated early packet is
    /// terminal immediately. It does not grant application delivery or ACKs.
    pub fn begin_early_peer_close(
        &mut self,
        receive: EarlyReceiveTicket,
        error_code: u64,
    ) -> Result<EarlyPeerCloseTicket, DriverError> {
        self.validate_early_receive(receive)?;
        if error_code > crate::packet::MAX_VARINT {
            return Err(DriverError::InvalidTicket);
        }
        if self.early.buffer.is_some()
            || self.early.control_buffer.is_some()
            || self.early.peer_close.is_some()
        {
            return Err(DriverError::ReceiveEffectBusy);
        }
        let ticket = EarlyPeerCloseTicket {
            descriptor: self.issue_descriptor()?,
            receive,
            error_code,
        };
        let wire = peer_close_wire(ticket);
        self.execute(|roles| {
            poll_ready(roles.packet.send::<EarlyPeerCloseRequest>(&wire))?;
            match_bytes(
                poll_ready(roles.application.recv::<EarlyPeerCloseRequest>())?,
                wire,
            )
        })?;
        self.early.peer_close = Some(ticket);
        Ok(ticket)
    }
    pub fn finish_early_peer_close(
        &mut self,
        ticket: EarlyPeerCloseTicket,
    ) -> Result<(), DriverError> {
        self.validate_early_receive(ticket.receive)?;
        if self.early.peer_close != Some(ticket) {
            return Err(DriverError::InvalidTicket);
        }
        let wire = peer_close_wire(ticket);
        self.execute(|roles| {
            poll_ready(roles.application.send::<EarlyPeerCloseCompleted>(&wire))?;
            match_bytes(
                poll_ready(roles.packet.recv::<EarlyPeerCloseCompleted>())?,
                wire,
            )
        })?;
        self.early.peer_close = None;
        Ok(())
    }
    /// Hold this distinct authority while committing a fully preflighted
    /// deferred-control packet. It grants storage, never an application effect.
    pub fn begin_early_control_buffer(
        &mut self,
        receive: EarlyReceiveTicket,
    ) -> Result<EarlyControlBufferTicket, DriverError> {
        self.validate_early_receive(receive)?;
        if self.early.buffer.is_some()
            || self.early.control_buffer.is_some()
            || self.early.peer_close.is_some()
        {
            return Err(DriverError::ReceiveEffectBusy);
        }
        let ticket = EarlyControlBufferTicket {
            descriptor: self.issue_descriptor()?,
            receive,
        };
        let wire = control_buffer_wire(ticket);
        self.execute(|roles| {
            poll_ready(roles.packet.send::<EarlyControlBufferRequest>(&wire))?;
            match_bytes(
                poll_ready(roles.application.recv::<EarlyControlBufferRequest>())?,
                wire,
            )
        })?;
        self.early.control_buffer = Some(ticket);
        Ok(ticket)
    }
    pub fn finish_early_control_buffer(
        &mut self,
        ticket: EarlyControlBufferTicket,
    ) -> Result<(), DriverError> {
        self.validate_early_receive(ticket.receive)?;
        if self.early.control_buffer != Some(ticket) {
            return Err(DriverError::InvalidTicket);
        }
        let wire = control_buffer_wire(ticket);
        self.execute(|roles| {
            poll_ready(roles.application.send::<EarlyControlBufferCompleted>(&wire))?;
            match_bytes(
                poll_ready(roles.packet.recv::<EarlyControlBufferCompleted>())?,
                wire,
            )
        })?;
        self.early.control_buffer = None;
        Ok(())
    }
    pub fn begin_early_control_release(
        &mut self,
        control: crate::early_control::ControlTicket,
    ) -> Result<EarlyControlReleaseTicket, DriverError> {
        self.ensure_live()?;
        if self.early.finished.is_none()
            || control.generation() != self.generation
            || self.early.next_control_revision != Some(control.revision())
        {
            return Err(DriverError::InvalidTicket);
        }
        if self.early.release.is_some()
            || self.early.intent.is_some()
            || self.early.control_release.is_some()
            || self.receive_effect.is_some()
        {
            return Err(DriverError::ReceiveEffectBusy);
        }
        let ticket = EarlyControlReleaseTicket {
            descriptor: self.issue_descriptor()?,
            control,
        };
        let wire = control_release_wire(ticket);
        self.execute(|roles| {
            poll_ready(roles.packet.send::<EarlyControlReleaseRequest>(&wire))?;
            match_bytes(
                poll_ready(roles.application.recv::<EarlyControlReleaseRequest>())?,
                wire,
            )
        })?;
        self.early.control_release = Some(ticket);
        Ok(ticket)
    }
    pub(super) fn validate_early_control_release(
        &self,
        ticket: EarlyControlReleaseTicket,
    ) -> Result<(), DriverError> {
        self.ensure_live()?;
        if self.early.finished.is_none()
            || ticket.generation() != self.generation
            || self.early.control_release != Some(ticket)
        {
            return Err(DriverError::InvalidTicket);
        }
        Ok(())
    }
    pub fn finish_early_control_release(
        &mut self,
        ticket: EarlyControlReleaseTicket,
    ) -> Result<(), DriverError> {
        self.validate_early_control_release(ticket)?;
        if self.receive_effect.is_some() {
            return Err(DriverError::ReceiveEffectBusy);
        }
        let wire = control_release_wire(ticket);
        self.execute(|roles| {
            poll_ready(
                roles
                    .application
                    .send::<EarlyControlReleaseCompleted>(&wire),
            )?;
            match_bytes(
                poll_ready(roles.packet.recv::<EarlyControlReleaseCompleted>())?,
                wire,
            )
        })?;
        self.early.next_control_revision = ticket.control.revision().checked_add(1);
        self.early.control_release = None;
        Ok(())
    }
    /// Consume the TLS owner's unique verified-Finished transition. A copied
    /// snapshot or endpoint assertion cannot establish the release boundary.
    /// ```compile_fail
    /// use hibana_quic::driver::Driver;
    /// fn assert_finished(driver: &mut Driver<'_>) {
    ///     driver.handshake_finished().unwrap();
    /// }
    /// ```
    pub fn handshake_finished(&mut self, finished: FinishedReceipt) -> Result<(), DriverError> {
        self.ensure_live()?;
        if finished.generation() != self.generation || self.early.finished.is_some() {
            return Err(DriverError::InvalidTicket);
        }
        if self.early.receive.is_some() {
            return Err(DriverError::ReceiveBusy);
        }
        let id = self.issue_descriptor()?.id;
        self.execute(|roles| {
            poll_ready(roles.packet.send::<VerifiedFinished>(&id))?;
            match_id(
                poll_ready(roles.application.recv::<VerifiedFinished>())?,
                id,
            )?;
            poll_ready(roles.application.send::<VerifiedFinishedAccepted>(&id))?;
            match_id(
                poll_ready(roles.packet.recv::<VerifiedFinishedAccepted>())?,
                id,
            )
        })?;
        self.early.finished = Some(finished);
        Ok(())
    }
    pub fn begin_early_intent_import(
        &mut self,
        import: crate::early_send::ImportTicket,
    ) -> Result<EarlyIntentTicket, DriverError> {
        self.ensure_live()?;
        if self.early.finished.is_none()
            || import.generation() != self.generation
            || import.stream_id() != self.early.next_intent_stream
        {
            return Err(DriverError::InvalidTicket);
        }
        if self.early.release.is_some()
            || self.early.intent.is_some()
            || self.early.control_release.is_some()
        {
            return Err(DriverError::ReceiveEffectBusy);
        }
        let ticket = EarlyIntentTicket {
            descriptor: self.issue_descriptor()?,
            import,
        };
        let wire = intent_wire(ticket);
        self.execute(|roles| {
            poll_ready(roles.packet.send::<EarlyIntentRequest>(&wire))?;
            match_bytes(
                poll_ready(roles.application.recv::<EarlyIntentRequest>())?,
                wire,
            )
        })?;
        self.early.intent = Some(ticket);
        Ok(ticket)
    }
    pub fn finish_early_intent_import(
        &mut self,
        ticket: EarlyIntentTicket,
        transferred: bool,
    ) -> Result<(), DriverError> {
        self.ensure_live()?;
        if self.early.intent != Some(ticket) || ticket.descriptor.generation != self.generation {
            return Err(DriverError::InvalidTicket);
        }
        let mut wire = [0; 13];
        wire[..12].copy_from_slice(&intent_wire(ticket));
        wire[12] = u8::from(transferred);
        self.execute(|roles| {
            poll_ready(roles.application.send::<EarlyIntentCompleted>(&wire))?;
            match_bytes(
                poll_ready(roles.packet.recv::<EarlyIntentCompleted>())?,
                wire,
            )
        })?;
        if transferred {
            self.early.next_intent_stream = self
                .early
                .next_intent_stream
                .checked_add(4)
                .ok_or(DriverError::DescriptorIdsExhausted)?;
        }
        self.early.intent = None;
        Ok(())
    }

    /// The caller must also validate the current quarantine view, then hold
    /// both tickets around StreamTable admission. Neither ticket substitutes
    /// for the other's checked ledger. Revisions never wrap or get replayed.
    pub fn begin_early_release(
        &mut self,
        stream_id: u64,
        quarantine: QuarantineTicket,
    ) -> Result<EarlyReleaseTicket, DriverError> {
        self.ensure_live()?;
        if self.early.finished.is_none()
            || quarantine.generation() != self.generation
            || self.early.next_revision != Some(quarantine.revision())
        {
            return Err(DriverError::InvalidTicket);
        }
        if self.early.release.is_some()
            || self.early.intent.is_some()
            || self.early.control_release.is_some()
        {
            return Err(DriverError::ReceiveEffectBusy);
        }
        if stream_id > crate::packet::MAX_VARINT {
            return Err(DriverError::InvalidStreamId);
        }
        let ticket = EarlyReleaseTicket {
            descriptor: self.issue_descriptor()?,
            quarantine,
            stream_id,
        };
        let wire = release_wire(ticket);
        self.execute(|roles| {
            poll_ready(roles.packet.send::<EarlyReleaseRequest>(&wire))?;
            match_bytes(
                poll_ready(roles.application.recv::<EarlyReleaseRequest>())?,
                wire,
            )
        })?;
        self.early.release = Some(ticket);
        Ok(ticket)
    }
    pub fn finish_early_release(&mut self, ticket: EarlyReleaseTicket) -> Result<(), DriverError> {
        self.ensure_live()?;
        if self.early.release != Some(ticket) || ticket.descriptor.generation != self.generation {
            return Err(DriverError::InvalidTicket);
        }
        let wire = release_wire(ticket);
        self.execute(|roles| {
            poll_ready(roles.application.send::<EarlyReleaseCompleted>(&wire))?;
            match_bytes(
                poll_ready(roles.packet.recv::<EarlyReleaseCompleted>())?,
                wire,
            )
        })?;
        self.early.next_revision = ticket.quarantine.revision().checked_add(1);
        self.early.release = None;
        Ok(())
    }
}
fn peer_close_wire(t: EarlyPeerCloseTicket) -> [u8; 16] {
    let mut wire = [0; 16];
    wire[..4].copy_from_slice(&t.receive.0.id.to_be_bytes());
    wire[4..8].copy_from_slice(&t.descriptor.id.to_be_bytes());
    wire[8..].copy_from_slice(&t.error_code.to_be_bytes());
    wire
}
fn control_buffer_wire(t: EarlyControlBufferTicket) -> [u8; 8] {
    let mut wire = [0; 8];
    wire[..4].copy_from_slice(&t.receive.0.id.to_be_bytes());
    wire[4..].copy_from_slice(&t.descriptor.id.to_be_bytes());
    wire
}
fn control_release_wire(t: EarlyControlReleaseTicket) -> [u8; 12] {
    let mut wire = [0; 12];
    wire[..4].copy_from_slice(&t.descriptor.id.to_be_bytes());
    wire[4..].copy_from_slice(&t.control.revision().to_be_bytes());
    wire
}
fn intent_wire(t: EarlyIntentTicket) -> [u8; 12] {
    let mut b = [0; 12];
    b[..4].copy_from_slice(&t.descriptor.id.to_be_bytes());
    b[4..].copy_from_slice(&t.import.stream_id().to_be_bytes());
    b
}
fn buffer_wire(t: EarlyBufferTicket) -> [u8; 16] {
    let mut b = [0; 16];
    b[..4].copy_from_slice(&t.receive.0.id.to_be_bytes());
    b[4..8].copy_from_slice(&t.descriptor.id.to_be_bytes());
    b[8..].copy_from_slice(&t.stream_id.to_be_bytes());
    b
}
fn release_wire(t: EarlyReleaseTicket) -> [u8; 12] {
    let mut b = [0; 12];
    b[..4].copy_from_slice(&t.descriptor.id.to_be_bytes());
    b[4..].copy_from_slice(&t.stream_id.to_be_bytes());
    b
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::early_data::{
        Quarantine, QuarantineSlot, RememberedLimits, ReplayLedger, ReplayStorage, ServerPolicy,
    };
    pub(crate) fn begin(driver: &mut Driver<'_>) -> Result<EarlyReceiveTicket, DriverError> {
        with_quarantine(driver.generation(), |opened, quarantine| {
            driver.begin_early_receive(opened, quarantine)
        })
    }
    fn with_quarantine<R>(
        generation: u64,
        body: impl FnOnce(EarlyOpenReceipt, &mut Quarantine<'_, 16>) -> R,
    ) -> R {
        let (opened, claim) = super::super::test_support::early(generation);
        let limits = RememberedLimits::from_authenticated_server_parameters(&[
            0, 0, 15, 0, 4, 1, 16, 5, 1, 16, 6, 1, 16, 8, 1, 1,
        ])
        .unwrap();
        let mut slots = [QuarantineSlot::<16>::EMPTY];
        let mut quarantine = Quarantine::new(
            ServerPolicy::BufferedReplaySafeRequests {
                max_bytes: 16,
                max_streams: 1,
            },
            limits,
            claim,
            &mut slots,
        )
        .unwrap();
        body(opened, &mut quarantine)
    }
    fn ticket(generation: u64) -> QuarantineTicket {
        let issuer = [9; 16];
        let mut storage = ReplayStorage::<1>::new();
        let mut ledger = ReplayLedger::bind(issuer, &mut storage).unwrap();
        let claim = ledger
            .claim_after_authentication(issuer, [3; 12], 100, 0, generation)
            .unwrap();
        let limits = RememberedLimits::from_authenticated_server_parameters(&[
            0, 0, 15, 0, 4, 1, 16, 5, 1, 16, 6, 1, 16, 8, 1, 1,
        ])
        .unwrap();
        let mut slots = [QuarantineSlot::<16>::EMPTY];
        let mut q = Quarantine::new(
            ServerPolicy::BufferedReplaySafeRequests {
                max_bytes: 16,
                max_streams: 1,
            },
            limits,
            claim,
            &mut slots,
        )
        .unwrap();
        q.buffer_authenticated_stream(generation, 0, 0, b"GET /", true)
            .unwrap();
        q.finish_after_verified_handshake(generation).unwrap();
        q.next_release().unwrap().unwrap().ticket
    }
    #[test]
    fn early_open_and_quarantine_authority_are_distinct_and_single_consumption_checked() {
        super::super::tests::with_driver::<16, _>(400, |d, q| {
            let rx = begin(d).unwrap();
            assert!(matches!(
                d.begin_receive(super::super::test_support::initial(d.generation())),
                Err(DriverError::ReceiveBusy)
            ));
            let b = d.begin_early_buffer(rx, 0).unwrap();
            assert!(matches!(
                d.finish_early_receive(rx),
                Err(DriverError::ReceiveEffectBusy)
            ));
            d.timer(1).unwrap();
            let tx = d.reserve_transmit().unwrap();
            d.adapter_result(tx).unwrap();
            d.finish_early_buffer(b).unwrap();
            assert!(matches!(
                d.finish_early_buffer(b),
                Err(DriverError::InvalidTicket)
            ));
            d.finish_early_receive(rx).unwrap();
            assert!(matches!(
                d.finish_early_receive(rx),
                Err(DriverError::InvalidTicket)
            ));
            assert_eq!(q.queued(), 0);
        });
    }
    #[test]
    fn actual_finished_gate_and_quarantine_revision_reject_forbidden_release() {
        let valid = ticket(401);
        let foreign = ticket(402);
        super::super::tests::with_driver::<16, _>(401, |d, q| {
            assert!(matches!(
                d.begin_early_release(0, valid),
                Err(DriverError::InvalidTicket)
            ));
            assert!(matches!(
                d.handshake_finished(super::super::test_support::finished(402)),
                Err(DriverError::InvalidTicket)
            ));
            d.handshake_finished(super::super::test_support::finished(d.generation()))
                .unwrap();
            assert!(matches!(
                d.handshake_finished(super::super::test_support::finished(d.generation())),
                Err(DriverError::InvalidTicket)
            ));
            assert!(matches!(
                d.begin_early_release(0, foreign),
                Err(DriverError::InvalidTicket)
            ));
            let release = d.begin_early_release(0, valid).unwrap();
            assert!(matches!(
                d.begin_early_release(0, valid),
                Err(DriverError::ReceiveEffectBusy)
            ));
            d.finish_early_release(release).unwrap();
            assert!(matches!(
                d.finish_early_release(release),
                Err(DriverError::InvalidTicket)
            ));
            assert!(matches!(
                d.begin_early_release(0, valid),
                Err(DriverError::InvalidTicket)
            ));
            assert_eq!(q.queued(), 0);
        });
    }
    #[test]
    fn retired_early_tickets_cannot_complete_new_connection_with_same_local_ids() {
        let old = super::super::tests::with_driver::<16, _>(403, |d, _| begin(d).unwrap());
        super::super::tests::with_driver::<16, _>(404, |d, _| {
            let new = begin(d).unwrap();
            assert_eq!(old.0.id, new.0.id);
            assert!(matches!(
                d.finish_early_receive(old),
                Err(DriverError::InvalidTicket)
            ));
            d.finish_early_receive(new).unwrap();
            d.retire();
            assert!(matches!(begin(d), Err(DriverError::Retired)));
        });
    }
    #[test]
    fn actual_open_receipt_requires_matching_live_replay_claim_generation() {
        super::super::tests::with_driver::<16, _>(405, |driver, queues| {
            with_quarantine(406, |opened, quarantine| {
                assert!(matches!(
                    driver.begin_early_receive(opened, quarantine),
                    Err(DriverError::InvalidTicket)
                ));
            });
            with_quarantine(405, |opened, _| {
                with_quarantine(406, |_, foreign| {
                    assert!(matches!(
                        driver.begin_early_receive(opened, foreign),
                        Err(DriverError::InvalidTicket)
                    ));
                });
            });
            with_quarantine(405, |opened, rejected| {
                rejected.reject(405).unwrap();
                assert!(matches!(
                    driver.begin_early_receive(opened, rejected),
                    Err(DriverError::InvalidTicket)
                ));
            });
            assert!(!driver.is_retired());
            let receive = begin(driver).unwrap();
            driver.finish_early_receive(receive).unwrap();
            assert_eq!(queues.queued(), 0);
        });
    }
    #[test]
    fn client_intent_import_requires_finished_and_completion_does_not_fake_success() {
        use crate::early_send::{Decision, Journal, RequestSlot};
        let limits = RememberedLimits::from_authenticated_server_parameters(&[
            0, 0, 15, 0, 4, 1, 16, 6, 1, 16, 8, 1, 1,
        ])
        .unwrap();
        let mut slots = [RequestSlot::<16>::EMPTY];
        let mut journal = Journal::new(500, limits, &mut slots).unwrap();
        journal.enqueue(b"GET /").unwrap();
        journal.decide(Decision::Rejected).unwrap();
        let import = journal.next_import().unwrap().unwrap().ticket;
        super::super::tests::with_driver::<16, _>(500, |d, q| {
            assert!(matches!(
                d.begin_early_intent_import(import),
                Err(DriverError::InvalidTicket)
            ));
            d.handshake_finished(super::super::test_support::finished(d.generation()))
                .unwrap();
            let first = d.begin_early_intent_import(import).unwrap();
            assert!(matches!(
                d.begin_early_intent_import(import),
                Err(DriverError::ReceiveEffectBusy)
            ));
            d.finish_early_intent_import(first, false).unwrap();
            assert!(matches!(
                d.finish_early_intent_import(first, true),
                Err(DriverError::InvalidTicket)
            ));
            let retry = d.begin_early_intent_import(import).unwrap();
            d.finish_early_intent_import(retry, true).unwrap();
            assert!(matches!(
                d.begin_early_intent_import(import),
                Err(DriverError::InvalidTicket)
            ));
            assert!(!d.is_retired());
            assert_eq!(q.queued(), 0);
        });
    }
    #[test]
    fn deferred_control_authority_is_finished_gated_and_cannot_repeat_or_overlap() {
        use crate::{
            connection_id::Cid,
            early_control::{Slot, Store},
            handshake_endpoint::NetworkReceiveContext,
            path::PathIdentity,
        };
        let mut slots = [Slot::<32>::EMPTY];
        let mut store = Store::new(501, &mut slots).unwrap();
        let context = NetworkReceiveContext {
            path: PathIdentity {
                connection_generation: 501,
                path_generation: 0,
                slot: 0,
            },
            destination: Cid::new(b"original").unwrap(),
        };
        store
            .prepare(&[0x1a, 1, 2, 3, 4, 5, 6, 7, 8], context)
            .unwrap()
            .commit()
            .unwrap();
        store.finished(501).unwrap();
        let control = store.next_release().unwrap().unwrap().ticket;
        super::super::tests::with_driver::<16, _>(501, |d, q| {
            assert!(matches!(
                d.begin_early_control_release(control),
                Err(DriverError::InvalidTicket)
            ));
            let receive = begin(d).unwrap();
            let buffer = d.begin_early_control_buffer(receive).unwrap();
            assert!(matches!(
                d.begin_early_buffer(receive, 0),
                Err(DriverError::ReceiveEffectBusy)
            ));
            assert!(matches!(
                d.finish_early_receive(receive),
                Err(DriverError::ReceiveEffectBusy)
            ));
            d.finish_early_control_buffer(buffer).unwrap();
            assert!(matches!(
                d.finish_early_control_buffer(buffer),
                Err(DriverError::InvalidTicket)
            ));
            d.finish_early_receive(receive).unwrap();
            assert!(matches!(
                d.begin_early_control_buffer(receive),
                Err(DriverError::InvalidTicket)
            ));
            d.handshake_finished(super::super::test_support::finished(d.generation()))
                .unwrap();
            let release = d.begin_early_control_release(control).unwrap();
            assert!(matches!(
                d.begin_early_control_release(control),
                Err(DriverError::ReceiveEffectBusy)
            ));
            let path = d
                .begin_early_path_effect(
                    release,
                    context.path,
                    super::super::PathEffect::ChallengeReceived,
                )
                .unwrap();
            assert!(matches!(
                d.finish_early_control_release(release),
                Err(DriverError::ReceiveEffectBusy)
            ));
            d.finish_path_effect(path).unwrap();
            d.finish_early_control_release(release).unwrap();
            assert!(matches!(
                d.begin_early_path_effect(
                    release,
                    context.path,
                    super::super::PathEffect::ChallengeReceived
                ),
                Err(DriverError::InvalidTicket)
            ));
            store.complete_release(control).unwrap();
            assert!(matches!(
                d.finish_early_control_release(release),
                Err(DriverError::InvalidTicket)
            ));
            assert!(matches!(
                d.begin_early_control_release(control),
                Err(DriverError::InvalidTicket)
            ));
            d.retire();
            assert!(matches!(
                d.begin_early_control_release(control),
                Err(DriverError::Retired)
            ));
            assert_eq!(q.queued(), 0);
        });
    }
    #[test]
    fn authenticated_early_peer_close_has_terminal_authority_before_finished() {
        super::super::tests::with_driver::<16, _>(503, |d, q| {
            let receive = begin(d).unwrap();
            let close = d.begin_early_peer_close(receive, 123).unwrap();
            assert!(matches!(
                d.begin_early_control_buffer(receive),
                Err(DriverError::ReceiveEffectBusy)
            ));
            assert!(matches!(
                d.finish_early_receive(receive),
                Err(DriverError::ReceiveEffectBusy)
            ));
            assert!(d.early.finished.is_none());
            d.finish_early_peer_close(close).unwrap();
            assert!(matches!(
                d.finish_early_peer_close(close),
                Err(DriverError::InvalidTicket)
            ));
            d.finish_early_receive(receive).unwrap();
            assert!(matches!(
                d.begin_early_peer_close(receive, 0),
                Err(DriverError::InvalidTicket)
            ));
            d.retire();
            assert!(matches!(
                d.begin_early_peer_close(receive, 0),
                Err(DriverError::Retired)
            ));
            assert_eq!(q.queued(), 0);
        });
    }
}
