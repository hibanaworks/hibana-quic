//! Endpoint-side capabilities for the actual Recovery owner.
//!
//! The endpoint keeps mailbox capabilities and copied observations only. Sent
//! history, congestion control, RTT, ECN, flights, timers and probe permissions
//! are mutated solely by the projected Recovery role.
use super::*;
use crate::roles::{datagram, packet_authority, recovery_owner};

pub const RECOVERY_RECORDS: usize = 64;
pub const RECOVERY_FLIGHT_BYTES: usize = 900;
pub type RecoveryClient<'channel, 'storage> =
    recovery_owner::Client<'channel, 'storage, RECOVERY_RECORDS, RECOVERY_FLIGHT_BYTES, 1, 1>;
pub type RecoverySnapshot = recovery_owner::Snapshot;
pub type RecoveryOwner =
    recovery_owner::RecoveryOwner<RECOVERY_RECORDS, 16, RECOVERY_FLIGHT_BYTES, 64>;
pub type RecoveryExchange = recovery_owner::Exchange<RECOVERY_RECORDS, RECOVERY_FLIGHT_BYTES>;
pub type PacketAuthority = packet_authority::Arena<8, 128>;
pub type RecoveryOutcome = recovery_owner::Outcome<RECOVERY_RECORDS, RECOVERY_FLIGHT_BYTES>;

/// Owns one admitted packet scope through ordered frame dispatch. Cancellation
/// revokes queued grants and destroys the original affine key-owner receipt.
pub(super) struct PacketScope<'a> {
    arena: &'a PacketAuthority,
    ticket: Option<packet_authority::PacketTicket>,
}
impl<'a> PacketScope<'a> {
    pub(super) fn admit(
        arena: &'a PacketAuthority,
        receipt: packet_authority::ReceiveEvidence,
        plaintext: &[u8],
    ) -> Result<Self, Error> {
        Ok(Self {
            arena,
            ticket: Some(arena.admit(receipt, plaintext)?),
        })
    }
    pub(super) fn ticket(&self) -> packet_authority::PacketTicket {
        self.ticket.expect("live packet scope")
    }
    pub(super) fn finish(mut self) -> Result<(), Error> {
        self.arena.finish(self.ticket())?;
        self.ticket = None;
        Ok(())
    }
}
impl Drop for PacketScope<'_> {
    fn drop(&mut self) {
        if let Some(ticket) = self.ticket.take() {
            let _ = self.arena.cancel(ticket);
        }
    }
}

struct PendingRecoveryCall<'a, 'r, 's, 'tc, 'ts, K: InitialKeyProtection> {
    endpoint: &'a mut HandshakeEndpoint<'r, 's, 'tc, 'ts, K>,
    complete: bool,
}
impl<K: InitialKeyProtection> Drop for PendingRecoveryCall<'_, '_, '_, '_, '_, K> {
    fn drop(&mut self) {
        if !self.complete {
            self.endpoint.retire();
        }
    }
}

impl<'r, 's, 'tc, 'ts, K: InitialKeyProtection> HandshakeEndpoint<'r, 's, 'tc, 'ts, K> {
    pub fn recovery_snapshot(&self) -> RecoverySnapshot {
        self.recovery
            .as_ref()
            .map_or(self.recovery_last, RecoveryClient::snapshot)
    }
    pub(super) async fn recovery_request(
        &mut self,
        command: recovery_owner::Command<RECOVERY_FLIGHT_BYTES>,
    ) -> Result<RecoveryOutcome, Error> {
        let mut call = PendingRecoveryCall {
            endpoint: self,
            complete: false,
        };
        let owner = call.endpoint.recovery.as_mut().ok_or(Error::Retired)?;
        let outcome = owner.request(command).await?;
        call.endpoint.recovery_last = owner.snapshot();
        call.complete = true;
        match outcome {
            recovery_owner::Outcome::Rejected(error) => Err(Error::RecoveryRejected(error)),
            outcome => Ok(outcome),
        }
    }
    pub(super) async fn recovery_reserve(
        &mut self,
        plan: recovery_owner::SendPlan,
    ) -> Result<recovery_owner::SendTicket, Error> {
        match self
            .recovery_request(recovery_owner::Command::Reserve(plan))
            .await?
        {
            recovery_owner::Outcome::Reserved(ticket) => Ok(ticket),
            _ => Err(Error::InvalidConfig),
        }
    }
    pub(super) async fn recovery_flight(
        &mut self,
        command: recovery_owner::FlightCommand<RECOVERY_FLIGHT_BYTES>,
    ) -> Result<RecoveryOutcome, Error> {
        self.recovery_request(recovery_owner::Command::Flight(command))
            .await
    }
    pub(super) async fn recovery_complete(
        &mut self,
        completion: datagram::RecoveryCompletion,
    ) -> Result<(), Error> {
        match self
            .recovery_request(recovery_owner::Command::AdapterComplete(completion))
            .await?
        {
            recovery_owner::Outcome::AdapterAccepted(_)
            | recovery_owner::Outcome::AdapterRejected(_) => Ok(()),
            _ => Err(Error::InvalidConfig),
        }
    }
    pub(super) async fn recovery_cancel(
        &mut self,
        cancellation: datagram::RecoveryCancellation,
    ) -> Result<(), Error> {
        match self
            .recovery_request(recovery_owner::Command::Cancel(cancellation))
            .await?
        {
            recovery_owner::Outcome::AdapterRejected(_) => Ok(()),
            _ => Err(Error::InvalidConfig),
        }
    }
    pub(super) async fn recovery_ack(
        &mut self,
        grant: packet_authority::AckGrant,
        received_path: Option<PathIdentity>,
    ) -> Result<recovery_owner::AckResult<RECOVERY_RECORDS>, Error> {
        let context = recovery_owner::AckContext {
            ack_delay_exponent: self.peer_ack_exponent,
            max_ack_delay_us: self.peer_max_ack_delay,
            handshake_confirmed: self.handshake_confirmed,
            peer_address_validated: self.timer_context().peer_completed_address_validation(),
            received_path,
            local_decryption_delay_us: 0,
            app_or_flow_limited: false,
        };
        match self
            .recovery_request(recovery_owner::Command::Ack {
                grant,
                now: self.now,
                context,
            })
            .await?
        {
            recovery_owner::Outcome::Acknowledged(ack) => Ok(ack),
            _ => Err(Error::InvalidConfig),
        }
    }
    pub(super) async fn recovery_reclaim(&mut self, space: PacketNumberSpace) -> Result<(), Error> {
        match self
            .recovery_request(recovery_owner::Command::Reclaim(space))
            .await?
        {
            recovery_owner::Outcome::Reclaimed { .. } => Ok(()),
            _ => Err(Error::InvalidConfig),
        }
    }
    pub(super) async fn recovery_reject_early(
        &mut self,
        grant: crate::roles::tls_owner::EarlyRejectedGrant,
    ) -> Result<u64, Error> {
        match self
            .recovery_request(recovery_owner::Command::RejectZeroRtt(grant))
            .await?
        {
            recovery_owner::Outcome::ZeroRttRejected { bytes_removed } => Ok(bytes_removed),
            recovery_owner::Outcome::ZeroRttPending(grant) => {
                self.early_rejection = Some(grant);
                Err(Error::Busy)
            }
            _ => Err(Error::InvalidConfig),
        }
    }
    pub(super) fn abort_recovery(&mut self) {
        if let Some(mut owner) = self.recovery.take() {
            self.recovery_last = owner.snapshot();
            owner.close();
        }
    }
    pub(super) async fn retire_recovery(&mut self) -> Result<(), Error> {
        if let Some(owner) = self.recovery.take() {
            self.recovery_last = owner.retire().await?;
        }
        Ok(())
    }
}

impl<'r, 's, 'tc, 'ts, K: InitialKeyProtection> HandshakeEndpoint<'r, 's, 'tc, 'ts, K> {
    pub(super) async fn reject_early_packets_impl(&mut self) -> Result<u64, Error> {
        let grant = self
            .early_rejection
            .take()
            .or_else(|| {
                self.tls
                    .as_mut()
                    .and_then(|owner| owner.take_early_rejected())
            })
            .ok_or(Error::InvalidConfig)?;
        let removed = self.recovery_reject_early(grant).await?;
        if self.tls_snapshot().early_keys {
            self.tls_discard_early().await?;
        }
        self.recovery_reclaim(PacketNumberSpace::ApplicationData)
            .await?;
        self.refresh_timer().await?;
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const GENERATION: u64 = 0x5245;
    const PARAMETERS: &[u8] = &[15, 8, b'c', b'l', b'i', b'e', b'n', b't', b'i', b'd'];
    const ACKS: &[u8] = &[2, 0, 0, 0, 0, 2, 0, 0, 0, 0];

    fn opened() -> crate::roles::tls_owner::OpenedPacket<1536> {
        crate::roles::stream_owner::test_evidence::application_evidence(
            GENERATION, PARAMETERS, ACKS,
        )
        .1
    }
    fn grant(
        arena: &PacketAuthority,
        ticket: packet_authority::PacketTicket,
        ordinal: u32,
    ) -> packet_authority::AckGrant {
        arena
            .grant_ack(
                ticket,
                ordinal,
                packet::AckRanges::new(&[packet::AckRange {
                    smallest: 0,
                    largest: 0,
                }])
                .unwrap(),
                0,
                None,
            )
            .unwrap()
    }
    #[test]
    fn actual_packet_scope_authorizes_multiple_frames_then_rejects_late_ids() {
        let opened = opened();
        let arena = PacketAuthority::new(GENERATION);
        let scope = PacketScope::admit(
            &arena,
            packet_authority::ReceiveEvidence::Tls(opened.receipt),
            opened.packet.body(),
        )
        .unwrap();
        let ticket = scope.ticket();
        let first = grant(&arena, ticket, 0);
        let second = grant(&arena, ticket, 1);
        assert_eq!(arena.consume_ack(first).unwrap().1.ranges()[0].end, 0);
        assert_eq!(arena.consume_ack(second).unwrap().1.ranges()[0].end, 0);
        scope.finish().unwrap();
        assert_eq!(
            arena.finish(ticket),
            Err(packet_authority::Error::InvalidPacket)
        );
    }
    #[test]
    fn finishing_with_an_outstanding_effect_revokes_its_late_grant() {
        let opened = opened();
        let arena = PacketAuthority::new(GENERATION);
        let scope = PacketScope::admit(
            &arena,
            packet_authority::ReceiveEvidence::Tls(opened.receipt),
            opened.packet.body(),
        )
        .unwrap();
        let ticket = scope.ticket();
        let queued = grant(&arena, ticket, 0);
        assert!(matches!(
            scope.finish(),
            Err(Error::PacketAuthority(
                packet_authority::Error::OutstandingEffects
            ))
        ));
        assert!(matches!(
            arena.consume_ack(queued),
            Err(packet_authority::Error::InvalidGrant)
        ));
        assert_eq!(
            arena.cancel(ticket),
            Err(packet_authority::Error::InvalidPacket)
        );
    }
}
