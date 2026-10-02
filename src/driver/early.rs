//! Distinct early-data authority. No EarlyReceiveTicket can authorize an ACK
//! mutation or ordinary delivery. Release follows the actual typed Finished
//! message and a checked quarantine revision; cryptography remains the caller's.
use super::*;
use crate::early_data::ReleaseTicket as QuarantineTicket;
use crate::protocol::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EarlyKeyUseTicket {
    descriptor: Descriptor,
    installation: u32,
}
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

pub(super) struct State {
    key: KeyState,
    key_use: Option<EarlyKeyUseTicket>,
    receive: Option<EarlyReceiveTicket>,
    buffer: Option<EarlyBufferTicket>,
    finished: bool,
    release: Option<EarlyReleaseTicket>,
    next_revision: Option<u64>,
}
impl State {
    pub(super) const fn new() -> Self {
        Self {
            key: KeyState::Uninstalled,
            key_use: None,
            receive: None,
            buffer: None,
            finished: false,
            release: None,
            next_revision: Some(0),
        }
    }
    pub(super) fn retired() -> Self {
        Self {
            key: KeyState::Retired,
            next_revision: None,
            ..Self::new()
        }
    }
    pub(super) fn receiving(&self) -> bool {
        self.receive.is_some()
    }
    pub(super) fn using_key(&self) -> bool {
        self.key_use.is_some()
    }
}
impl Driver<'_> {
    /// Call after the real early packet key was installed. A rejected early
    /// epoch is terminal and cannot be reinstalled in this connection.
    pub fn install_early_key(&mut self) -> Result<(), DriverError> {
        self.ensure_live()?;
        match self.early.key {
            KeyState::Uninstalled => {}
            KeyState::Installed(_) => return Err(DriverError::KeyAlreadyInstalled),
            KeyState::Retired => return Err(DriverError::KeyRetired),
        }
        let id = self.issue_descriptor()?.id;
        self.execute(|roles| key_grant::<EarlyKeyInstalled>(roles, id))?;
        self.early.key = KeyState::Installed(id);
        Ok(())
    }
    pub fn is_early_key_installed(&self) -> bool {
        !self.is_retired() && matches!(self.early.key, KeyState::Installed(_))
    }
    pub fn begin_early_key_use(&mut self) -> Result<EarlyKeyUseTicket, DriverError> {
        self.ensure_live()?;
        let installation = match self.early.key {
            KeyState::Uninstalled => return Err(DriverError::KeyNotInstalled),
            KeyState::Retired => return Err(DriverError::KeyRetired),
            KeyState::Installed(id) => id,
        };
        if self.key_use.is_some() || self.early.key_use.is_some() {
            return Err(DriverError::KeyUseBusy);
        }
        let descriptor = self.issue_descriptor()?;
        self.execute(|roles| key_route::<EarlyKeyUse>(roles, descriptor.id))?;
        let ticket = EarlyKeyUseTicket {
            descriptor,
            installation,
        };
        self.early.key_use = Some(ticket);
        Ok(ticket)
    }
    pub fn finish_early_key_use(&mut self, ticket: EarlyKeyUseTicket) -> Result<(), DriverError> {
        self.ensure_live()?;
        if self.early.key_use != Some(ticket)
            || ticket.descriptor.generation != self.generation
            || self.early.key != KeyState::Installed(ticket.installation)
        {
            return Err(DriverError::InvalidTicket);
        }
        self.execute(|roles| key_completion::<EarlyKeyUsed>(roles, ticket.descriptor.id))?;
        self.early.key_use = None;
        Ok(())
    }
    pub fn retire_early_key(&mut self) -> Result<(), DriverError> {
        self.ensure_live()?;
        let id = match self.early.key {
            KeyState::Installed(id) => id,
            KeyState::Uninstalled => return Err(DriverError::KeyNotInstalled),
            KeyState::Retired => return Err(DriverError::KeyRetired),
        };
        if self.early.key_use.is_some() {
            return Err(DriverError::KeyUseBusy);
        }
        self.execute(|roles| key_route::<EarlyKeyRetired>(roles, id))?;
        self.early.key = KeyState::Retired;
        Ok(())
    }
    /// Invoke only after successful early AEAD and replay-policy admission.
    /// This gives quarantine authority, never stream application delivery.
    pub fn begin_early_receive(&mut self) -> Result<EarlyReceiveTicket, DriverError> {
        self.ensure_live()?;
        if !self.is_early_key_installed() {
            return Err(DriverError::KeyNotInstalled);
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
        if self.early.buffer.is_some() {
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
        if self.early.buffer.is_some() {
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
    /// Invoke only after TLS verifies the peer Finished. The program itself
    /// places this actual message before every early-release message.
    pub fn handshake_finished(&mut self) -> Result<(), DriverError> {
        self.ensure_live()?;
        if self.early.finished {
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
        self.early.finished = true;
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
        if !self.early.finished
            || quarantine.generation() != self.generation
            || self.early.next_revision != Some(quarantine.revision())
        {
            return Err(DriverError::InvalidTicket);
        }
        if self.early.release.is_some() {
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
mod tests {
    use super::*;
    use crate::early_data::{
        Quarantine, QuarantineSlot, RememberedLimits, ReplayLedger, ReplayStorage, ServerPolicy,
    };
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
    fn early_key_and_quarantine_authority_are_distinct_and_replay_checked() {
        super::super::tests::with_driver::<16, _>(400, |d, q| {
            assert!(matches!(
                d.begin_early_key_use(),
                Err(DriverError::KeyNotInstalled)
            ));
            assert!(matches!(
                d.begin_early_receive(),
                Err(DriverError::KeyNotInstalled)
            ));
            d.install_early_key().unwrap();
            let k = d.begin_early_key_use().unwrap();
            assert!(matches!(d.retire_early_key(), Err(DriverError::KeyUseBusy)));
            d.finish_early_key_use(k).unwrap();
            assert!(matches!(
                d.finish_early_key_use(k),
                Err(DriverError::InvalidTicket)
            ));
            let rx = d.begin_early_receive().unwrap();
            assert!(matches!(d.begin_receive(), Err(DriverError::ReceiveBusy)));
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
            d.retire_early_key().unwrap();
            assert!(matches!(
                d.install_early_key(),
                Err(DriverError::KeyRetired)
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
            d.handshake_finished().unwrap();
            assert!(matches!(
                d.handshake_finished(),
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
        let old = super::super::tests::with_driver::<16, _>(403, |d, _| {
            d.install_early_key().unwrap();
            d.begin_early_key_use().unwrap()
        });
        super::super::tests::with_driver::<16, _>(404, |d, _| {
            d.install_early_key().unwrap();
            let new = d.begin_early_key_use().unwrap();
            assert_eq!(old.descriptor.id, new.descriptor.id);
            assert!(matches!(
                d.finish_early_key_use(old),
                Err(DriverError::InvalidTicket)
            ));
            d.finish_early_key_use(new).unwrap();
            d.retire();
            assert!(matches!(d.begin_early_receive(), Err(DriverError::Retired)));
        });
    }
}
