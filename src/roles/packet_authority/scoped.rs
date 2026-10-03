//! RECONSTRUCTED AFTER EXECUTOR RESET; UNVERIFIED.
//! Producer-bound packet authority for the directional application-key path.
//!
//! A unique borrow fixes caller-owned arena storage for the lifetime of every
//! scoped ticket and effect. Scope identity comes from the actual RX producer;
//! it is never inferred from a connection-generation number. The legacy raw
//! arena remains available to the existing RPC path and does not provide this
//! cross-arena identity guarantee.

use super::{
    AckFrame, AckGrant, Arena, AuthenticatedPacket, DeliveryFrame, DeliveryGrant, Error,
    PacketTicket, ReceiveEvidence,
};
use crate::crypto::directional::{AckEligible, ApplicationKeyScope, PacketAuthorityInstallation};
use core::cell::Cell;

#[cfg(test)]
mod tests;

/// Opaque owned evidence retained by the legacy bounded packet record after
/// checking an actual directional receipt. No constructor accepts copied facts.
#[doc(hidden)]
pub struct DirectionalReceiveEvidence {
    facts: AuthenticatedPacket,
    plaintext_digest: [u8; 32],
}
impl DirectionalReceiveEvidence {
    pub(super) const fn facts(&self) -> AuthenticatedPacket { self.facts }
    pub(super) fn authenticates_plaintext(&self, plaintext: &[u8]) -> bool {
        crate::roles::sealed_packet::plaintext_digest(plaintext) == self.plaintext_digest
    }
}

/// Affine authentication from an RX producer already attached to a key scope.
/// Consumers cannot attach an arbitrary legacy receipt to their own scope.
/// ```compile_fail
/// use hibana_quic::{crypto::directional::ApplicationKeyScope,
///     roles::packet_authority::{ReceiveEvidence, ScopedReceiveEvidence}};
/// fn bind(scope: &ApplicationKeyScope, evidence: ReceiveEvidence) {
///     let _ = ScopedReceiveEvidence::from_received(scope, evidence);
/// }
/// ```
pub struct ScopedReceiveEvidence<'a> {
    scope: &'a ApplicationKeyScope,
    evidence: ReceiveEvidence,
}
impl<'a> ScopedReceiveEvidence<'a> {
    /// Called by the fixed-scope RX producer immediately after actual legacy
    /// AEAD success. This is never a consumer-side raw-grant adapter.
    pub(crate) fn from_received(
        scope: &'a ApplicationKeyScope,
        evidence: ReceiveEvidence,
    ) -> Result<Self, Error> {
        if matches!(evidence, ReceiveEvidence::Directional(_)) {
            return Err(Error::UnsupportedProtection);
        }
        if evidence.facts()?.generation() != scope.connection_generation() {
            return Err(Error::WrongGeneration);
        }
        Ok(Self { scope, evidence })
    }

    /// Consume actual producer-bound RX evidence after any write-epoch barrier.
    /// Plaintext is checked here and again when entering the arena.
    pub(crate) fn from_directional(
        receipt: AckEligible<'a>,
        operation_id: u64,
        plaintext: &[u8],
    ) -> Result<Self, Error> {
        if !receipt.authenticates_plaintext(plaintext) {
            return Err(Error::InvalidFrame);
        }
        let scope = receipt.scope();
        let facts = AuthenticatedPacket {
            generation: receipt.connection_generation(),
            operation_id,
            space: crate::accounting::PacketNumberSpace::ApplicationData,
            packet_number: receipt.packet_number(),
            key_generation: receipt.opened().generation,
        };
        Ok(Self {
            scope,
            evidence: ReceiveEvidence::Directional(DirectionalReceiveEvidence {
                facts,
                plaintext_digest: crate::roles::sealed_packet::plaintext_digest(plaintext),
            }),
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct Identity<'a> {
    // u64 remains nonzero-sized at zero capacities. The unique storage borrow
    // prevents replacement while any scoped ticket/grant remains usable.
    arena: &'a u64,
    scope: &'a ApplicationKeyScope,
}
impl Identity<'_> {
    fn matches(self, other: Self) -> bool {
        core::ptr::eq(self.arena, other.arena) && core::ptr::eq(self.scope, other.scope)
    }
}

/// Affine packet authority. Finish/cancel revokes it in the live table.
#[derive(Debug)]
pub struct ScopedPacketTicket<'a> {
    identity: Identity<'a>,
    ticket: PacketTicket,
}
impl ScopedPacketTicket<'_> {
    pub const fn generation(&self) -> u64 { self.ticket.generation() }
    pub const fn sequence(&self) -> u64 { self.ticket.sequence() }
}

/// One authenticated ACK effect from its scoped producer arena.
/// ```compile_fail
/// use hibana_quic::roles::packet_authority::ScopedAckGrant;
/// fn duplicate(grant: ScopedAckGrant<'_>) { let first = grant; let second = grant; }
/// ```
#[derive(Debug)]
pub struct ScopedAckGrant<'a> {
    identity: Identity<'a>,
    grant: AckGrant,
}
#[derive(Debug)]
pub struct ScopedDeliveryGrant<'a, const N: usize> {
    identity: Identity<'a>,
    grant: DeliveryGrant<N>,
}

/// One-shot recovery construction permission. Dropping it cannot reopen claim.
/// ```compile_fail
/// use hibana_quic::roles::packet_authority::RecoveryBinding;
/// fn duplicate(binding: RecoveryBinding<'_, '_, 1, 1>) {
///     let first = binding; let second = binding;
/// }
/// ```
pub struct RecoveryBinding<'arena, 'scope, const P: usize, const E: usize> {
    arena: &'arena ScopedArena<'scope, P, E>,
}
impl<'arena, 'scope, const P: usize, const E: usize> RecoveryBinding<'arena, 'scope, P, E> {
    pub(crate) fn into_arena(self) -> &'arena ScopedArena<'scope, P, E> { self.arena }
}

/// Shared bounded storage; no raw arena or mutable borrow can escape this API.
/// Raw legacy grants cannot enter the directional path.
/// ```compile_fail
/// use hibana_quic::roles::packet_authority::{AckGrant, ScopedArena};
/// fn raw(arena: &ScopedArena<'_, 1, 1>, grant: AckGrant) {
///     let _ = arena.consume_ack(grant);
/// }
/// ```
/// Live authority prevents replacing caller-owned storage.
/// ```compile_fail
/// use hibana_quic::{crypto::directional::ApplicationKeyScope,
///     roles::packet_authority::{Arena, ScopedArena}};
/// let mut scope = ApplicationKeyScope::new(1);
/// let mut installation = scope.claim().unwrap();
/// let mut storage = Arena::<1, 1>::new(1);
/// let token = installation.take_packet_authority().unwrap();
/// let arena = ScopedArena::new(&mut storage, token).unwrap();
/// storage = Arena::new(1);
/// let _ = arena.live_packets();
/// ```
/// A surviving ticket keeps the storage loan even when the facade drops.
/// ```compile_fail
/// use hibana_quic::{crypto::directional::PacketAuthorityInstallation,
///     roles::packet_authority::{Arena, ScopedArena, ScopedReceiveEvidence}};
/// fn replace<'a>(storage: &'a mut Arena<1, 1>, token: PacketAuthorityInstallation<'a>,
///     evidence: ScopedReceiveEvidence<'a>) {
///     let arena = ScopedArena::new(storage, token).unwrap();
///     let ticket = arena.admit(evidence, &[2, 0, 0, 0, 0]).unwrap();
///     drop(arena);
///     *storage = Arena::new(1);
///     let _ = ticket.sequence();
/// }
/// ```
/// Shared scope observations cannot mint another arena.
/// ```compile_fail
/// use hibana_quic::{crypto::directional::ApplicationKeyScope,
///     roles::packet_authority::{Arena, ScopedArena}};
/// fn duplicate(storage: &mut Arena<1, 1>, scope: &ApplicationKeyScope) {
///     let _ = ScopedArena::new(storage, scope);
/// }
/// ```
pub struct ScopedArena<'a, const P: usize, const E: usize> {
    arena: &'a Arena<P, E>,
    identity: Identity<'a>,
    recovery_claimed: Cell<bool>,
}
impl<'a, const P: usize, const E: usize> ScopedArena<'a, P, E> {
    pub fn new(
        arena: &'a mut Arena<P, E>,
        installation: PacketAuthorityInstallation<'a>,
    ) -> Result<Self, Error> {
        let scope = installation.into_scope();
        if arena.generation() != scope.connection_generation() {
            return Err(Error::WrongGeneration);
        }
        Ok(Self {
            identity: Identity { arena: &arena.generation, scope },
            arena,
            recovery_claimed: Cell::new(false),
        })
    }
    /// A downstream construction error also leaves this claim spent.
    pub fn claim_recovery(&self) -> Result<RecoveryBinding<'_, 'a, P, E>, Error> {
        if self.recovery_claimed.replace(true) { return Err(Error::InvalidGrant); }
        Ok(RecoveryBinding { arena: self })
    }
    pub const fn generation(&self) -> u64 { self.arena.generation() }
    pub const fn scope(&self) -> &'a ApplicationKeyScope { self.identity.scope }
    fn validate(&self, identity: Identity<'_>) -> Result<(), Error> {
        if self.identity.matches(identity) { Ok(()) } else { Err(Error::InvalidGrant) }
    }
    pub fn admit(
        &self,
        evidence: ScopedReceiveEvidence<'a>,
        plaintext: &[u8],
    ) -> Result<ScopedPacketTicket<'a>, Error> {
        if !core::ptr::eq(self.identity.scope, evidence.scope) {
            return Err(Error::InvalidGrant);
        }
        let ticket = self.arena.admit(evidence.evidence, plaintext)?;
        Ok(ScopedPacketTicket { identity: self.identity, ticket })
    }
    pub fn inspect(&self, ticket: &ScopedPacketTicket<'_>) -> Result<AuthenticatedPacket, Error> {
        self.validate(ticket.identity)?;
        self.arena.inspect(ticket.ticket)
    }
    pub fn grant_ack(
        &self,
        ticket: &ScopedPacketTicket<'_>,
        frame_ordinal: u32,
        ranges: crate::packet::AckRanges<'_>,
        delay: u64,
        ecn: Option<crate::packet::EcnCounts>,
    ) -> Result<ScopedAckGrant<'a>, Error> {
        self.validate(ticket.identity)?;
        let grant = self.arena.grant_ack(ticket.ticket, frame_ordinal, ranges, delay, ecn)?;
        Ok(ScopedAckGrant { identity: self.identity, grant })
    }
    pub fn consume_ack(&self, grant: ScopedAckGrant<'_>) -> Result<(AuthenticatedPacket, AckFrame), Error> {
        self.validate(grant.identity)?;
        self.arena.consume_ack(grant.grant)
    }
    pub fn grant_delivery<const N: usize>(
        &self,
        ticket: &ScopedPacketTicket<'_>,
        frame_ordinal: u32,
        frame: crate::packet::Frame<'_>,
    ) -> Result<ScopedDeliveryGrant<'a, N>, Error> {
        self.validate(ticket.identity)?;
        let grant = self.arena.grant_delivery(ticket.ticket, frame_ordinal, frame)?;
        Ok(ScopedDeliveryGrant { identity: self.identity, grant })
    }
    pub fn consume_delivery<const N: usize>(
        &self,
        grant: ScopedDeliveryGrant<'_, N>,
    ) -> Result<(AuthenticatedPacket, DeliveryFrame<N>), Error> {
        self.validate(grant.identity)?;
        self.arena.consume_delivery(grant.grant)
    }
    pub fn finish(&self, ticket: &ScopedPacketTicket<'_>) -> Result<AuthenticatedPacket, Error> {
        self.validate(ticket.identity)?;
        self.arena.finish(ticket.ticket)
    }
    pub fn cancel(&self, ticket: &ScopedPacketTicket<'_>) -> Result<(), Error> {
        self.validate(ticket.identity)?;
        self.arena.cancel(ticket.ticket)
    }
    pub fn live_packets(&self) -> usize { self.arena.live_packets() }
    pub fn live_effects(&self) -> usize { self.arena.live_effects() }
}
