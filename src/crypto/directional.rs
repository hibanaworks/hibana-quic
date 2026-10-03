//! RECONSTRUCTED after workspace loss on 2026-10-03; these bytes are UNVERIFIED.
//! Reconstructed from the original implementation and retained tool history.
//! Earlier test results do not validate this reconstruction.
//!
//! Independently owned 1-RTT receive and transmit keys. AEAD/HKDF use the existing
//! PacketKey implementation. An affine peer-update round trip gates ACK
//! eligibility until the matching write epoch is installed. Lost transition
//! receipts leave RX blocked until the connection is discarded.

use super::{ApplicationKeys, Error, HP_SAMPLE_LEN, IntegrityBudget, KeyKind, Opened, PacketKey};
use crate::roles::{path_owner::HandshakeConfirmation, recovery_owner::KeyAckGrant};
use zeroize::Zeroize;

#[cfg(test)]
#[path = "directional_tests.rs"]
mod tests;

/// Caller-owned identity claimed once. It has no keys or shared running state.
#[derive(Debug)]
pub struct ApplicationKeyScope {
    connection_generation: u64,
    claimed: bool,
}
impl ApplicationKeyScope {
    pub const fn new(connection_generation: u64) -> Self {
        Self { connection_generation, claimed: false }
    }
    pub const fn connection_generation(&self) -> u64 { self.connection_generation }
    /// Claim before application keys exist, then share immutable identity with
    /// the actual authority producers. Dropping the claim cannot reissue it.
    pub fn claim(&mut self) -> Result<ApplicationKeyInstallation<'_>, Error> {
        if self.claimed { return Err(Error::KeyUpdateNotAllowed); }
        self.claimed = true;
        Ok(ApplicationKeyInstallation { scope: self, packet_authority_claimed: false, publication_gate_claimed: false })
    }
    pub fn install(&mut self, local: PacketKey, remote: PacketKey)
        -> Result<(ApplicationReadKeys<'_>, ApplicationWriteKeys<'_>), Error>
    { self.claim()?.install(local, remote) }
}

/// One-shot installation capability. Fresh provider-owned 1-RTT keys are the
/// intended source; installation does not import old raw authorization state.
/// ```compile_fail
/// use hibana_quic::crypto::directional::ApplicationKeyInstallation;
/// fn duplicate(grant: ApplicationKeyInstallation<'_>) { let first = grant; let second = grant; }
/// ```
/// ```compile_fail
/// use hibana_quic::crypto::{ApplicationKeys, directional::ApplicationKeyInstallation};
/// fn legacy(grant: ApplicationKeyInstallation<'_>, keys: ApplicationKeys) {
///     let _ = grant.install_existing(keys);
/// }
/// ```
/// ```compile_fail
/// use hibana_quic::crypto::{ApplicationKeys, directional::ApplicationKeyScope};
/// fn legacy(keys: ApplicationKeys, scope: &mut ApplicationKeyScope) {
///     let _ = keys.into_directional(scope);
/// }
/// ```
#[must_use = "dropping installation permanently closes this scope to new keys"]
#[derive(Debug)]
pub struct ApplicationKeyInstallation<'a> {
    scope: &'a ApplicationKeyScope,
    packet_authority_claimed: bool,
    publication_gate_claimed: bool,
}
impl<'a> ApplicationKeyInstallation<'a> {
pub fn take_packet_authority(&mut self) -> Result<PacketAuthorityInstallation<'a>, Error> {
    if self.packet_authority_claimed {
        return Err(Error::KeyUpdateNotAllowed);
    }
    self.packet_authority_claimed = true;
    Ok(PacketAuthorityInstallation { scope: self.scope })
}

pub fn take_publication_gate(&mut self) -> Result<PublicationGateInstallation<'a>, Error> {
    if self.publication_gate_claimed {
        return Err(Error::KeyUpdateNotAllowed);
    }
    self.publication_gate_claimed = true;
    Ok(PublicationGateInstallation { scope: self.scope })
}
    pub const fn scope(&self) -> &'a ApplicationKeyScope { self.scope }
    pub fn install(self, local: PacketKey, remote: PacketKey)
        -> Result<(ApplicationReadKeys<'a>, ApplicationWriteKeys<'a>), Error>
    {
        if local.kind != KeyKind::OneRtt || remote.kind != KeyKind::OneRtt || local.suite != remote.suite {
            return Err(Error::KeyUpdateNotAllowed);
        }
        let local_next = local.derive_next()?;
        let remote_next = remote.derive_next()?;
        Ok((
            ApplicationReadKeys {
                scope: self.scope, current: remote, next: Some(remote_next), previous: None,
                generation: 0, installed_write_generation: 0, current_min: None,
                current_max: None, previous_max: None, previous_deadline: None,
                pending: None, last_now: 0, active: true,
            },
            ApplicationWriteKeys {
                scope: self.scope, current: local, next: Some(local_next), generation: 0,
                receive_generation: 0, first_sent: None, handshake_confirmed: false,
                current_acked: false, update_after: None, last_now: 0, active: true,
            },
        ))
    }
    /// Trusted migration only: preserves keys, accounting AND legacy authority.
    /// Public callers must install fresh keys and obtain scoped producer grants.
    pub(crate) fn install_existing(self, keys: ApplicationKeys)
        -> Result<(ApplicationReadKeys<'a>, ApplicationWriteKeys<'a>), Error>
    { split_claimed(keys, self.scope) }
}

/// One affine arena-installation capability for an actual key scope.
/// ```compile_fail
/// use hibana_quic::crypto::directional::PacketAuthorityInstallation;
/// fn duplicate(token: PacketAuthorityInstallation<'_>) {
///     let first = token; let second = token;
/// }
/// ```
#[must_use = "dropping installation permanently closes this scope to a packet arena"]
#[derive(Debug)]
pub struct PacketAuthorityInstallation<'a> {
    scope: &'a ApplicationKeyScope,
}

impl<'a> PacketAuthorityInstallation<'a> {
    pub(crate) fn into_scope(self) -> &'a ApplicationKeyScope { self.scope }
}

/// One affine publication-gate capability for an actual key scope.
/// ```compile_fail
/// use hibana_quic::crypto::directional::PublicationGateInstallation;
/// fn duplicate(token: PublicationGateInstallation<'_>) {
///     let first = token; let second = token;
/// }
/// ```
#[must_use = "dropping installation permanently closes this scope to a publication gate"]
#[derive(Debug)]
pub struct PublicationGateInstallation<'a> {
    scope: &'a ApplicationKeyScope,
}

impl<'a> PublicationGateInstallation<'a> {
    pub(crate) fn into_scope(self) -> &'a ApplicationKeyScope { self.scope }
}

/// Bind at the actual Path producer, never by wrapping a raw grant at TX.
#[derive(Debug)]
pub struct ScopedHandshakeConfirmation<'a> { scope: &'a ApplicationKeyScope }
impl<'a> ScopedHandshakeConfirmation<'a> {
    pub(crate) fn from_confirmed(scope: &'a ApplicationKeyScope, confirmation: HandshakeConfirmation)
        -> Result<Self, Error>
    {
        if confirmation.generation() != scope.connection_generation { return Err(Error::KeyUpdateNotAllowed); }
        Ok(Self { scope })
    }
}

/// Bind at the actual Recovery producer using its stored scope. A numeric
/// connection-generation field cannot substitute for this reference identity.
#[derive(Debug)]
pub struct ValidatedKeyAck<'a> {
    scope: &'a ApplicationKeyScope,
    sent_packet_number: u64,
    received_key_generation: u64,
}
impl<'a> ValidatedKeyAck<'a> {
    pub(crate) fn from_validated(scope: &'a ApplicationKeyScope, grant: KeyAckGrant) -> Result<Self, Error> {
        if grant.generation() != scope.connection_generation { return Err(Error::InvalidAcknowledgment); }
        Ok(Self { scope, sent_packet_number: grant.sent_packet_number(), received_key_generation: grant.received_key_generation() })
    }
}

/// RX owns current, prepared next and retained previous read keys exclusively.
/// ```compile_fail
/// use hibana_quic::crypto::directional::ApplicationReadKeys;
/// fn transmit(rx: &mut ApplicationReadKeys<'_>) {
///     rx.seal(0, &[0x40], &mut [0; 16], 0).unwrap();
/// }
/// ```
pub struct ApplicationReadKeys<'a> {
    scope: &'a ApplicationKeyScope,
    current: PacketKey,
    next: Option<PacketKey>,
    previous: Option<PacketKey>,
    generation: u64,
    installed_write_generation: u64,
    current_min: Option<u64>,
    current_max: Option<u64>,
    previous_max: Option<u64>,
    previous_deadline: Option<u64>,
    pending: Option<Pending>,
    last_now: u64,
    active: bool,
}
/// TX owns current/next write keys and all send-key usage exclusively.
/// ```compile_fail
/// use hibana_quic::crypto::{IntegrityBudget, directional::ApplicationWriteKeys};
/// fn receive(tx: &mut ApplicationWriteKeys<'_>, budget: &mut IntegrityBudget) {
///     tx.open(0, false, &[0x40], &mut [0; 16], budget, 0, 10).unwrap();
/// }
/// ```
pub struct ApplicationWriteKeys<'a> {
    scope: &'a ApplicationKeyScope,
    current: PacketKey,
    next: Option<PacketKey>,
    generation: u64,
    receive_generation: u64,
    first_sent: Option<u64>,
    handshake_confirmed: bool,
    current_acked: bool,
    update_after: Option<u64>,
    last_now: u64,
    active: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Pending {
    Peer { packet_number: u64, opened: Opened },
    Local { receive_generation: u64 },
}
#[derive(Debug)]
pub enum AuthenticatedRead<'a> {
    Ready(AckEligible<'a>),
    PeerUpdate(PeerUpdateAuthenticated<'a>),
}
impl AuthenticatedRead<'_> {
    pub const fn opened(&self) -> Opened {
        match self { Self::Ready(receipt) => receipt.opened, Self::PeerUpdate(receipt) => receipt.opened }
    }
}

/// Actual authentication and completed write-epoch coupling, bound to plaintext.
/// ```compile_fail
/// use hibana_quic::crypto::directional::AckEligible;
/// fn duplicate(receipt: AckEligible<'_>) { let first = receipt; let second = receipt; }
/// ```
/// ```compile_fail
/// use hibana_quic::crypto::{Opened, directional::AckEligible};
/// fn forge(snapshot: Opened) -> AckEligible<'static> { snapshot.into() }
/// ```
#[must_use = "ACK processing must consume the authenticated packet's eligibility"]
#[derive(Debug)]
pub struct AckEligible<'a> {
    scope: &'a ApplicationKeyScope,
    packet_number: u64,
    opened: Opened,
    plaintext_digest: [u8; 32],
}
impl<'a> AckEligible<'a> {
    pub const fn scope(&self) -> &'a ApplicationKeyScope { self.scope }
    pub const fn packet_number(&self) -> u64 { self.packet_number }
    pub const fn opened(&self) -> Opened { self.opened }
    pub const fn connection_generation(&self) -> u64 { self.scope.connection_generation }
    pub fn authenticates_plaintext(&self, plaintext: &[u8]) -> bool {
        self.plaintext_digest == crate::roles::sealed_packet::plaintext_digest(plaintext)
    }
}
/// Only successful next-generation AEAD mints this affine receipt.
/// ```compile_fail
/// use hibana_quic::crypto::directional::PeerUpdateAuthenticated;
/// fn duplicate(receipt: PeerUpdateAuthenticated<'_>) { let first = receipt; let second = receipt; }
/// ```
#[must_use = "dropping this transition leaves RX blocked"]
#[derive(Debug)]
pub struct PeerUpdateAuthenticated<'a> {
    scope: &'a ApplicationKeyScope,
    packet_number: u64,
    opened: Opened,
    previous_generation: u64,
    observed_at: u64,
    plaintext_digest: [u8; 32],
}
impl PeerUpdateAuthenticated<'_> {
    pub const fn opened(&self) -> Opened { self.opened }
    pub const fn packet_number(&self) -> u64 { self.packet_number }
}
/// TX installed the exact write epoch required by this authenticated packet.
/// ```compile_fail
/// use hibana_quic::crypto::directional::WriteEpochInstalled;
/// fn duplicate(receipt: WriteEpochInstalled<'_>) { let first = receipt; let second = receipt; }
/// ```
#[must_use = "RX must accept this installation before the packet is ACK eligible"]
#[derive(Debug)]
pub struct WriteEpochInstalled<'a> { authenticated: PeerUpdateAuthenticated<'a> }
impl WriteEpochInstalled<'_> {
    pub const fn generation(&self) -> u64 { self.authenticated.opened.generation }
}
/// Prepared RX next key and a parked receive owner. Lost grants fail closed.
/// ```compile_fail
/// use hibana_quic::crypto::directional::LocalUpdateReady;
/// fn duplicate(receipt: LocalUpdateReady<'_>) { let first = receipt; let second = receipt; }
/// ```
#[must_use = "TX must consume this readiness or RX must explicitly cancel it"]
#[derive(Debug)]
pub struct LocalUpdateReady<'a> {
    scope: &'a ApplicationKeyScope,
    receive_generation: u64,
    prepared_at: u64,
}
#[must_use = "RX must accept the installed local write epoch before resuming"]
#[derive(Debug)]
pub struct LocalWriteEpochInstalled<'a> {
    ready: LocalUpdateReady<'a>,
    write_generation: u64,
    installed_at: u64,
}
impl LocalWriteEpochInstalled<'_> {
    pub const fn generation(&self) -> u64 { self.write_generation }
}
#[derive(Debug)]
pub struct LocalUpdateRejected<'a> { pub error: Error, pub ready: LocalUpdateReady<'a> }

pub(super) fn split<'a>(keys: ApplicationKeys, scope: &'a mut ApplicationKeyScope)
    -> Result<(ApplicationReadKeys<'a>, ApplicationWriteKeys<'a>), Error>
{ scope.claim()?.install_existing(keys) }
fn split_claimed<'a>(keys: ApplicationKeys, scope: &'a ApplicationKeyScope)
    -> Result<(ApplicationReadKeys<'a>, ApplicationWriteKeys<'a>), Error>
{
    keys.ensure_active()?;
    let ApplicationKeys {
        local, local_next, remote, remote_next, remote_previous,
        send_generation, receive_generation, first_sent, current_min,
        current_max, previous_max, previous_deadline, handshake_confirmed,
        current_acked, update_after, last_now, active,
    } = keys;
    Ok((
        ApplicationReadKeys {
            scope, current: remote, next: remote_next, previous: remote_previous,
            generation: receive_generation, installed_write_generation: send_generation,
            current_min, current_max, previous_max, previous_deadline,
            pending: None, last_now, active,
        },
        ApplicationWriteKeys {
            scope, current: local, next: local_next, generation: send_generation,
            receive_generation, first_sent, handshake_confirmed, current_acked,
            update_after, last_now, active,
        },
    ))
}
fn time(active: bool, last_now: &mut u64, now: u64, pto: u64) -> Result<u64, Error> {
    if !active { return Err(Error::KeyDiscarded); }
    if now < *last_now || pto == 0 { return Err(Error::InvalidTime); }
    let deadline = pto.checked_mul(3).and_then(|delta| now.checked_add(delta)).ok_or(Error::InvalidTime)?;
    *last_now = now;
    Ok(deadline)
}

impl<'a> ApplicationReadKeys<'a> {
    pub const fn scope(&self) -> &'a ApplicationKeyScope { self.scope }
    pub const fn generation(&self) -> u64 { self.generation }
    pub const fn previous_key_deadline(&self) -> Option<u64> { self.previous_deadline }
    fn ensure_ready(&self) -> Result<(), Error> {
        if !self.active { return Err(Error::KeyDiscarded); }
        if self.pending.is_some() { return Err(Error::KeyUpdateNotAllowed); }
        Ok(())
    }
    pub fn maintain(&mut self, now: u64, pto: u64) -> Result<(), Error> {
        time(self.active, &mut self.last_now, now, pto)?;
        self.expire(now);
        if self.next.is_none() { self.next = Some(self.current.derive_next()?); }
        Ok(())
    }
    fn expire(&mut self, now: u64) {
        if self.previous_deadline.is_some_and(|deadline| now >= deadline) {
            self.previous = None;
            self.previous_deadline = None;
        }
    }
    pub fn header_mask(&self, sample: &[u8; HP_SAMPLE_LEN]) -> Result<[u8; 5], Error> {
        if !self.active { return Err(Error::KeyDiscarded); }
        self.current.header_mask(sample)
    }
    /// Exactly one AEAD attempt, no fallback or HKDF. Outstanding transitions
    /// block before AEAD so no later packet bypasses the write-installation gate.
    #[allow(clippy::too_many_arguments)]
    pub fn open(&mut self, pn: u64, phase: bool, header: &[u8], buffer: &mut [u8],
        budget: &mut IntegrityBudget, now: u64, pto: u64) -> Result<AuthenticatedRead<'a>, Error>
    {
        self.ensure_ready()?;
        if header.first().is_none_or(|first| (first & 4 != 0) != phase) { return Err(Error::InvalidHeader); }
        let deadline = time(self.active, &mut self.last_now, now, pto)?;
        self.expire(now);
        let different_phase = phase != (self.generation & 1 != 0);
        let previous = different_phase && self.current_min.is_some_and(|min| pn < min);
        let next = different_phase && !previous;
        let candidate = if previous { self.previous.as_ref() } else if next { self.next.as_ref() } else { Some(&self.current) };
        let selected = candidate.unwrap_or(&self.current);
        let result = selected.open(pn, header, buffer, budget);
        if candidate.is_none() {
            buffer.zeroize();
            return match result { Ok(_) => Err(budget.record_failure()), Err(error) => Err(error) };
        }
        let len = result?;
        if next {
            let Some(generation) = self.generation.checked_add(1) else {
                buffer.zeroize(); self.discard(); return Err(Error::KeyUpdateError);
            };
            if self.current_max.is_some_and(|max| pn <= max)
                || self.installed_write_generation < self.generation
                || self.installed_write_generation > generation
            {
                buffer.zeroize(); self.discard(); return Err(Error::KeyUpdateError);
            }
            let promoted = self.next.take().ok_or(Error::KeyUpdateNotAllowed)?;
            self.previous = Some(core::mem::replace(&mut self.current, promoted));
            self.previous_max = self.current_max;
            self.current_min = Some(pn);
            self.current_max = Some(pn);
            self.previous_deadline = Some(deadline);
            let previous_generation = self.generation;
            self.generation = generation;
            let opened = Opened { len, generation, key_updated: true };
            self.pending = Some(Pending::Peer { packet_number: pn, opened });
            Ok(AuthenticatedRead::PeerUpdate(PeerUpdateAuthenticated {
                scope: self.scope, packet_number: pn, opened, previous_generation,
                observed_at: now,
                plaintext_digest: crate::roles::sealed_packet::plaintext_digest(&buffer[..len]),
            }))
        } else {
            let generation = if previous {
                self.previous_max = Some(self.previous_max.map_or(pn, |max| max.max(pn)));
                self.generation - 1
            } else {
                if self.previous_max.is_some_and(|max| pn <= max) {
                    buffer.zeroize(); self.discard(); return Err(Error::KeyUpdateError);
                }
                self.current_min = Some(self.current_min.map_or(pn, |min| min.min(pn)));
                self.current_max = Some(self.current_max.map_or(pn, |max| max.max(pn)));
                self.generation
            };
            Ok(AuthenticatedRead::Ready(AckEligible {
                scope: self.scope, packet_number: pn,
                opened: Opened { len, generation, key_updated: false },
                plaintext_digest: crate::roles::sealed_packet::plaintext_digest(&buffer[..len]),
            }))
        }
    }
    pub fn accept_write_epoch(&mut self, installed: WriteEpochInstalled<'a>) -> Result<AckEligible<'a>, Error> {
        if !self.active { return Err(Error::KeyDiscarded); }
        let receipt = installed.authenticated;
        if !core::ptr::eq(self.scope, receipt.scope)
            || self.pending != Some(Pending::Peer { packet_number: receipt.packet_number, opened: receipt.opened })
        { return Err(Error::KeyUpdateError); }
        self.installed_write_generation = receipt.opened.generation;
        self.pending = None;
        Ok(AckEligible { scope: self.scope, packet_number: receipt.packet_number, opened: receipt.opened, plaintext_digest: receipt.plaintext_digest })
    }
    pub fn prepare_local_update(&mut self) -> Result<LocalUpdateReady<'a>, Error> {
        self.ensure_ready()?;
        if self.next.is_none() || self.generation != self.installed_write_generation { return Err(Error::KeyUpdateNotAllowed); }
        self.pending = Some(Pending::Local { receive_generation: self.generation });
        Ok(LocalUpdateReady { scope: self.scope, receive_generation: self.generation, prepared_at: self.last_now })
    }
    fn check_local(&self, ready: &LocalUpdateReady<'a>) -> Result<(), Error> {
        if !self.active { return Err(Error::KeyDiscarded); }
        if !core::ptr::eq(self.scope, ready.scope)
            || self.pending != Some(Pending::Local { receive_generation: ready.receive_generation })
        { return Err(Error::KeyUpdateError); }
        Ok(())
    }
    pub fn accept_local_write_epoch(&mut self, installed: LocalWriteEpochInstalled<'a>) -> Result<(), Error> {
        self.check_local(&installed.ready)?;
        if self.generation.checked_add(1) != Some(installed.write_generation) { return Err(Error::KeyUpdateError); }
        self.installed_write_generation = installed.write_generation;
        self.last_now = self.last_now.max(installed.installed_at);
        self.pending = None;
        Ok(())
    }
    pub fn cancel_local_update(&mut self, ready: LocalUpdateReady<'a>) -> Result<(), Error> {
        self.check_local(&ready)?;
        self.pending = None;
        Ok(())
    }
    pub fn discard(&mut self) {
        self.current.discard(); self.next = None; self.previous = None;
        self.previous_deadline = None; self.pending = None; self.active = false;
    }
}

impl<'a> ApplicationWriteKeys<'a> {
    pub const fn scope(&self) -> &'a ApplicationKeyScope { self.scope }
    pub const fn generation(&self) -> u64 { self.generation }
    pub const fn phase(&self) -> bool { self.generation & 1 != 0 }
    pub const fn last_sealed_packet_number(&self) -> Option<u64> { self.current.last_sealed }
    fn ensure_active(&self) -> Result<(), Error> { if self.active { Ok(()) } else { Err(Error::KeyDiscarded) } }
    /// Actual scope-bound QUIC confirmation, not merely TLS completion.
    /// ```compile_fail
    /// use hibana_quic::{crypto::directional::ApplicationWriteKeys, roles::path_owner::HandshakeConfirmation};
    /// fn unbound(tx: &mut ApplicationWriteKeys<'_>, confirmation: HandshakeConfirmation) {
    ///     tx.confirm_handshake(confirmation).unwrap();
    /// }
    /// ```
    pub fn confirm_handshake(&mut self, confirmation: ScopedHandshakeConfirmation<'a>) -> Result<(), Error> {
        self.ensure_active()?;
        if !core::ptr::eq(self.scope, confirmation.scope) { return Err(Error::KeyUpdateNotAllowed); }
        self.handshake_confirmed = true;
        Ok(())
    }
    /// Consume actual scope-bound sent-ledger ACK evidence.
    /// ```compile_fail
    /// use hibana_quic::{crypto::directional::ApplicationWriteKeys, roles::recovery_owner::KeyAckGrant};
    /// fn unbound(tx: &mut ApplicationWriteKeys<'_>, grant: KeyAckGrant) {
    ///     tx.acknowledge(grant, 0, 10).unwrap();
    /// }
    /// ```
    pub fn acknowledge(&mut self, grant: ValidatedKeyAck<'a>, now: u64, pto: u64) -> Result<(), Error> {
        if !core::ptr::eq(self.scope, grant.scope) { return Err(Error::InvalidAcknowledgment); }
        self.acknowledge_validated(grant.sent_packet_number, grant.received_key_generation, now, pto)
    }
    fn acknowledge_validated(&mut self, pn: u64, received_generation: u64, now: u64, pto: u64) -> Result<(), Error> {
        let deadline = time(self.active, &mut self.last_now, now, pto)?;
        if self.current.last_sealed.is_none_or(|last| pn > last) || received_generation > self.receive_generation {
            return Err(Error::InvalidAcknowledgment);
        }
        if self.first_sent.is_some_and(|first| pn >= first) {
            if received_generation < self.generation { self.discard(); return Err(Error::KeyUpdateError); }
            if !self.current_acked {
                self.current_acked = true;
                self.update_after = Some(if self.generation == 0 { now } else { deadline });
            }
        }
        Ok(())
    }
    pub fn maintain(&mut self, now: u64, pto: u64) -> Result<(), Error> {
        time(self.active, &mut self.last_now, now, pto)?;
        if self.next.is_none() { self.next = Some(self.current.derive_next()?); }
        Ok(())
    }
    pub fn initiate(&mut self, ready: LocalUpdateReady<'a>, now: u64, pto: u64)
        -> Result<LocalWriteEpochInstalled<'a>, LocalUpdateRejected<'a>>
    {
        let result = (|| {
            if !core::ptr::eq(self.scope, ready.scope) { return Err(Error::KeyUpdateNotAllowed); }
            time(self.active, &mut self.last_now, now, pto)?;
            if now < ready.prepared_at { return Err(Error::InvalidTime); }
            if ready.receive_generation != self.receive_generation || self.generation != self.receive_generation
                || !self.handshake_confirmed || !self.current_acked
                || self.update_after.is_none_or(|deadline| now < deadline) || self.next.is_none()
            { return Err(Error::KeyUpdateNotAllowed); }
            self.promote()
        })();
        match result {
            Ok(()) => Ok(LocalWriteEpochInstalled { ready, write_generation: self.generation, installed_at: now }),
            Err(error) => Err(LocalUpdateRejected { error, ready }),
        }
    }
    pub fn install_peer_update(&mut self, receipt: PeerUpdateAuthenticated<'a>) -> Result<WriteEpochInstalled<'a>, Error> {
        self.ensure_active()?;
        if !core::ptr::eq(self.scope, receipt.scope) { return Err(Error::KeyUpdateError); }
        if self.receive_generation != receipt.previous_generation || self.generation < receipt.previous_generation
            || self.generation > receipt.opened.generation
            || (self.generation == receipt.previous_generation && self.next.is_none())
        { self.discard(); return Err(Error::KeyUpdateError); }
        if self.generation == receipt.previous_generation { self.promote()?; }
        self.receive_generation = receipt.opened.generation;
        self.last_now = self.last_now.max(receipt.observed_at);
        Ok(WriteEpochInstalled { authenticated: receipt })
    }
    fn promote(&mut self) -> Result<(), Error> {
        let generation = self.generation.checked_add(1).ok_or(Error::KeyUpdateNotAllowed)?;
        let mut next = self.next.take().ok_or(Error::KeyUpdateNotAllowed)?;
        next.last_sealed = self.current.last_sealed;
        self.current = next; self.generation = generation;
        self.first_sent = None; self.current_acked = false; self.update_after = None;
        Ok(())
    }
    pub fn seal(&mut self, pn: u64, header: &[u8], buffer: &mut [u8], plaintext_len: usize) -> Result<usize, Error> {
        self.ensure_active()?;
        if self.current.last_sealed.is_some_and(|last| pn <= last) { return Err(Error::PacketNumberReuse); }
        if header.first().is_none_or(|first| (first & 4 != 0) != self.phase()) { return Err(Error::InvalidHeader); }
        let len = self.current.seal(pn, header, buffer, plaintext_len)?;
        if self.first_sent.is_none() { self.first_sent = Some(pn); }
        Ok(len)
    }
    pub fn header_mask(&self, sample: &[u8; HP_SAMPLE_LEN]) -> Result<[u8; 5], Error> {
        self.ensure_active()?; self.current.header_mask(sample)
    }
    pub fn discard(&mut self) { self.current.discard(); self.next = None; self.active = false; }
}
