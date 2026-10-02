//! Caller-owned connection-ID and stateless-reset ledgers for nonzero QUIC CIDs.
//!
//! This is a state kernel, not an authenticated packet processor or a migration
//! implementation. Call methods named `authenticated` only after authenticating
//! the containing packet and validating its encryption level; call methods named
//! `verified` only after authenticating and validating the transport parameters.
//! Initial and Retry packets alone do not authenticate reset tokens.
//!
//! Every distinct sequence occupies one caller-provided slot for the connection's
//! entire lifetime, including after retirement and retirement acknowledgment.
//! Keeping that bounded history makes duplicate/conflict checking exact even for
//! arbitrary reordered gaps. Slots are never evicted or reused within a table;
//! `HistoryFull` is an explicit, fail-closed lifetime limit, not an invitation to
//! forget a CID. Provision enough peer slots for active IDs and at least twice the
//! advertised active limit in pending retirements (RFC 9000 section 5.1.2).
//!
//! Addresses include both IP and UDP port. Each peer CID has bounded remote
//! history, and remains bound to its original local address. The sole exception
//! to the one-remote rule is explicitly authorized, authenticated peer rebinding
//! on that same local address. A remote is eligible for reset detection only
//! after a datagram using this CID was actually accepted for sending there.
//!
//! Sources: RFC 9000 sections [5.1], [9.5], [10.3], [19.15], and [19.16].
//! [5.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1
//! [9.5]: https://www.rfc-editor.org/rfc/rfc9000.html#section-9.5
//! [10.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-10.3
//! [19.15]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.15
//! [19.16]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.16

use core::{fmt, net::SocketAddr};
use subtle::{Choice, ConstantTimeEq};

const MAX_SEQUENCE: u64 = (1 << 62) - 1;

/// A nonzero QUIC connection ID, owning at most 20 bytes without allocation.
/// Zero-length CID connections intentionally use a separate, non-migrating path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cid {
    bytes: [u8; 20],
    len: u8,
}

impl Cid {
    pub fn new(bytes: &[u8]) -> Result<Self, CidError> {
        if bytes.is_empty() || bytes.len() > 20 {
            return Err(CidError::InvalidCidLength);
        }
        let mut result = Self {
            bytes: [0; 20],
            len: bytes.len() as u8,
        };
        result.bytes[..bytes.len()].copy_from_slice(bytes);
        Ok(result)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

/// A reset token. Debug output is redacted and equality is constant-time.
/// Construction is not proof of authentication; only authenticated/verified
/// table operations can make a received token eligible for reset detection.
#[derive(Clone, Copy)]
pub struct ResetToken([u8; 16]);

impl ResetToken {
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// For encoding an issued token. Do not log or expose tokens to third parties.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl ConstantTimeEq for ResetToken {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for ResetToken {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for ResetToken {}

impl fmt::Debug for ResetToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ResetToken([redacted])")
    }
}

/// Errors leave the table unchanged. The caller maps malformed frame fields to
/// FRAME_ENCODING_ERROR, conflicts/invalid retirement to PROTOCOL_VIOLATION,
/// and ActiveLimit to CONNECTION_ID_LIMIT_ERROR. History/address exhaustion is
/// a bounded implementation limit; do not silently drop state or ignore frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CidError {
    InvalidCidLength,
    InvalidActiveLimit,
    InvalidCapacity,
    InvalidSequence,
    InvalidRetirePriorTo,
    InitialRequired,
    InitialAlreadyIssued,
    PreferredSequenceUnavailable,
    HistoryFull,
    ActiveLimit,
    ConnectionIdReused,
    ResetTokenReused,
    ConflictingSequence,
    UnknownSequence,
    CurrentDestinationCid,
    StaleHandle,
    Retired,
    NotRetired,
    DifferentLocalAddress,
    DifferentRemoteAddress,
    UnusedConnectionId,
    AddressHistoryFull,
    GenerationExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Handle {
    table: u64,
    connection_generation: u64,
    slot: usize,
    generation: u64,
}

/// An opaque local-CID reference, checked against table and slot generations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalCidHandle(Handle);
impl LocalCidHandle {
    pub const fn connection_generation(self) -> u64 {
        self.0.connection_generation
    }
}

/// An opaque peer-CID reference, also usable for retirement acknowledgment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerCidHandle(Handle);
impl PeerCidHandle {
    pub const fn connection_generation(self) -> u64 {
        self.0.connection_generation
    }
}

/// Information needed to encode a local CID advertisement. For sequence zero,
/// the CID is carried in the handshake and its optional token in server TPs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalCid {
    pub handle: LocalCidHandle,
    pub sequence: u64,
    pub cid: Cid,
    pub token: Option<ResetToken>,
    pub retire_prior_to: u64,
}

/// Caller-owned local history storage. Initialize arrays with `EMPTY`.
#[derive(Clone, Copy)]
pub struct LocalCidSlot {
    generation: u64,
    entry: Option<LocalEntry>,
}

impl LocalCidSlot {
    pub const EMPTY: Self = Self {
        generation: 0,
        entry: None,
    };
}

#[derive(Clone, Copy)]
struct LocalEntry {
    sequence: u64,
    cid: Cid,
    token: Option<ResetToken>,
    retire_prior_to: u64,
    advertised: bool,
    retired: bool,
}

/// Issued IDs keep routing until an actual authenticated RETIRE_CONNECTION_ID.
///
/// `table` must identify this ledger within a connection. The caller must never
/// reuse `(table, connection_generation)` for different backing storage while
/// old handles can arrive. Reinitializing the same storage increments each slot
/// generation, preflighted without wrapping. Tables cannot be cloned.
pub struct LocalCidTable<'a> {
    table: u64,
    connection_generation: u64,
    slots: &'a mut [LocalCidSlot],
    peer_active_limit: u64,
    next_sequence: u64,
    highest_advertised_sequence: Option<u64>,
    retire_prior_to: u64,
}

impl<'a> LocalCidTable<'a> {
    pub fn new(
        table: u64,
        connection_generation: u64,
        slots: &'a mut [LocalCidSlot],
        peer_active_limit: u64,
    ) -> Result<Self, CidError> {
        validate_limit(peer_active_limit)?;
        if slots.is_empty() {
            return Err(CidError::InvalidCapacity);
        }
        if slots.iter().any(|slot| slot.generation == u64::MAX) {
            return Err(CidError::GenerationExhausted);
        }
        for slot in slots.iter_mut() {
            slot.generation += 1;
            slot.entry = None;
        }
        Ok(Self {
            table,
            connection_generation,
            slots,
            peer_active_limit,
            next_sequence: 0,
            highest_advertised_sequence: None,
            retire_prior_to: 0,
        })
    }

    /// Install the authenticated peer limit before generating further IDs.
    pub fn set_peer_limit_verified(&mut self, limit: u64) -> Result<(), CidError> {
        validate_limit(limit)?;
        let active = self
            .slots
            .iter()
            .filter_map(|s| s.entry.as_ref())
            .filter(|e| !e.retired && e.sequence >= self.retire_prior_to)
            .count() as u64;
        if active > limit {
            return Err(CidError::ActiveLimit);
        }
        self.peer_active_limit = limit;
        Ok(())
    }
    pub fn can_issue(&self) -> bool {
        self.available_history() > 0
            && (self
                .slots
                .iter()
                .filter_map(|s| s.entry.as_ref())
                .filter(|e| !e.retired && e.sequence >= self.retire_prior_to)
                .count() as u64)
                < self.peer_active_limit
    }
    pub fn available_history(&self) -> usize {
        self.slots.iter().filter(|s| s.entry.is_none()).count()
    }
    /// Reserve sequence zero before advertising the initial source CID.
    /// Tokens must be unpredictable and unique across connections too; this
    /// table only enforces uniqueness within the current connection lifetime.
    pub fn issue_initial(
        &mut self,
        cid: Cid,
        token: Option<ResetToken>,
    ) -> Result<LocalCid, CidError> {
        if self.next_sequence != 0 {
            return Err(CidError::InitialAlreadyIssued);
        }
        self.insert(cid, token, 0)
    }

    /// Reserve the preferred_address transport parameter's required sequence 1.
    /// Call before issuing any other post-initial CID when providing that TP.
    pub fn issue_preferred(&mut self, cid: Cid, token: ResetToken) -> Result<LocalCid, CidError> {
        if self.next_sequence != 1 {
            return Err(CidError::PreferredSequenceUnavailable);
        }
        self.insert(cid, Some(token), 0)
    }

    /// Reserve the next consecutive CID advertisement. Keep the returned data
    /// in reliable-send state and retransmit it until acknowledged. Once issued,
    /// a CID is never rolled back or forgotten, even if a send is blocked.
    /// Raising the floor asks the peer to retire IDs; it does not stop routing.
    /// Reservations route immediately, but only `mark_advertised` after carrier
    /// acceptance advances the maximum sequence that a peer can retire.
    pub fn issue(
        &mut self,
        cid: Cid,
        token: ResetToken,
        retire_prior_to: u64,
    ) -> Result<LocalCid, CidError> {
        if self.next_sequence == 0 {
            return Err(CidError::InitialRequired);
        }
        self.insert(cid, Some(token), retire_prior_to)
    }

    fn insert(
        &mut self,
        cid: Cid,
        token: Option<ResetToken>,
        retire_prior_to: u64,
    ) -> Result<LocalCid, CidError> {
        if self.next_sequence > MAX_SEQUENCE {
            return Err(CidError::InvalidSequence);
        }
        if retire_prior_to > self.next_sequence || retire_prior_to < self.retire_prior_to {
            return Err(CidError::InvalidRetirePriorTo);
        }
        for entry in self.slots.iter().filter_map(|slot| slot.entry.as_ref()) {
            if entry.cid == cid {
                return Err(CidError::ConnectionIdReused);
            }
            if token.is_some() && entry.token == token {
                return Err(CidError::ResetTokenReused);
            }
        }
        let active_after = self
            .slots
            .iter()
            .filter_map(|slot| slot.entry.as_ref())
            .filter(|entry| !entry.retired && entry.sequence >= retire_prior_to)
            .count();
        if active_after as u64 >= self.peer_active_limit {
            return Err(CidError::ActiveLimit);
        }
        let index = self
            .slots
            .iter()
            .position(|slot| slot.entry.is_none())
            .ok_or(CidError::HistoryFull)?;
        self.slots[index].entry = Some(LocalEntry {
            sequence: self.next_sequence,
            cid,
            token,
            retire_prior_to,
            advertised: false,
            retired: false,
        });
        self.next_sequence += 1;
        self.retire_prior_to = retire_prior_to;
        self.get(self.handle(index))
    }

    fn handle(&self, index: usize) -> LocalCidHandle {
        LocalCidHandle(Handle {
            table: self.table,
            connection_generation: self.connection_generation,
            slot: index,
            generation: self.slots[index].generation,
        })
    }

    pub fn get(&self, handle: LocalCidHandle) -> Result<LocalCid, CidError> {
        let slot = self.slots.get(handle.0.slot).ok_or(CidError::StaleHandle)?;
        validate_handle(
            handle.0,
            self.table,
            self.connection_generation,
            slot.generation,
        )?;
        let entry = slot.entry.ok_or(CidError::StaleHandle)?;
        if entry.retired {
            return Err(CidError::Retired);
        }
        Ok(LocalCid {
            handle,
            sequence: entry.sequence,
            cid: entry.cid,
            token: entry.token,
            retire_prior_to: entry.retire_prior_to,
        })
    }

    /// Public routing aliases ever issued in this bounded connection lifetime,
    /// including retired IDs. A host listener may retain them across draining
    /// so late packets cannot be mistaken for a fresh connection. No tokens.
    pub fn issued_ids(&self) -> impl Iterator<Item = Cid> + '_ {
        self.slots
            .iter()
            .filter_map(|slot| slot.entry.as_ref().map(|entry| entry.cid))
    }

    /// Route by actual packet DCID. A match is not packet authentication.
    pub fn route(&self, destination: &[u8]) -> Option<LocalCidHandle> {
        self.slots
            .iter()
            .position(|slot| {
                slot.entry
                    .as_ref()
                    .is_some_and(|entry| !entry.retired && entry.cid.as_bytes() == destination)
            })
            .map(|index| self.handle(index))
    }

    /// Record actual carrier acceptance of the Initial source CID, the complete
    /// preferred-address TP advertisement, or a NEW_CONNECTION_ID frame. Call
    /// only after the carrying datagram was accepted, never for a planned,
    /// rejected, or blocked send. At bootstrap, retained evidence of the same
    /// completed send is sufficient. This is send evidence, not a peer ACK.
    ///
    /// Record acceptance before processing incoming packets or mutating this
    /// ledger again. Returns true on the first accepted advertisement of this
    /// CID; duplicate/reordered send notifications never lower the maximum.
    pub fn mark_advertised(&mut self, handle: LocalCidHandle) -> Result<bool, CidError> {
        let sequence = self.get(handle)?.sequence;
        let entry = self.slots[handle.0.slot]
            .entry
            .as_mut()
            .ok_or(CidError::StaleHandle)?;
        let changed = !entry.advertised;
        entry.advertised = true;
        self.highest_advertised_sequence = Some(
            self.highest_advertised_sequence
                .map_or(sequence, |old| old.max(sequence)),
        );
        Ok(changed)
    }

    /// Process an authenticated RETIRE frame with its packet's actual DCID.
    /// Duplicate retirement is harmless, except a frame cannot retire its own
    /// packet's DCID. Returns true only for the first retirement.
    /// Reserved-but-unsent sequences above the maximum actually advertised are
    /// rejected. RFC 9000 section 19.16 checks this maximum: a known lower
    /// sequence is allowed even if its own advertisement was reordered/blocked.
    pub fn retire_authenticated(
        &mut self,
        sequence: u64,
        packet_dcid: &[u8],
    ) -> Result<bool, CidError> {
        self.check_retirement(sequence, packet_dcid)?;
        let index = self
            .slots
            .iter()
            .position(|slot| {
                slot.entry
                    .as_ref()
                    .is_some_and(|entry| entry.sequence == sequence)
            })
            .ok_or(CidError::UnknownSequence)?;
        let entry = self.slots[index]
            .entry
            .as_mut()
            .ok_or(CidError::UnknownSequence)?;
        if entry.cid.as_bytes() == packet_dcid {
            return Err(CidError::CurrentDestinationCid);
        }
        let changed = !entry.retired;
        entry.retired = true;
        Ok(changed)
    }

    /// Read-only receive-time admission. A deferred RETIRE must pass this check
    /// before it is retained: later advertisements cannot legalize the frame.
    pub fn check_retirement(&self, sequence: u64, packet_dcid: &[u8]) -> Result<(), CidError> {
        if self
            .highest_advertised_sequence
            .is_none_or(|highest| sequence > highest)
        {
            return Err(CidError::UnknownSequence);
        }
        let entry = self
            .slots
            .iter()
            .filter_map(|slot| slot.entry.as_ref())
            .find(|entry| entry.sequence == sequence)
            .ok_or(CidError::UnknownSequence)?;
        if entry.cid.as_bytes() == packet_dcid {
            return Err(CidError::CurrentDestinationCid);
        }
        Ok(())
    }

    /// IDs still accepted for routing, including IDs below the requested floor.
    pub fn routing_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.entry.as_ref().is_some_and(|entry| !entry.retired))
            .count()
    }

    pub const fn retire_prior_to(&self) -> u64 {
        self.retire_prior_to
    }

    pub const fn highest_advertised_sequence(&self) -> Option<u64> {
        self.highest_advertised_sequence
    }
}

#[derive(Clone, Copy)]
struct RemoteUse {
    address: SocketAddr,
    sent: bool,
}

#[derive(Clone, Copy)]
struct PeerEntry<const ADDRESSES: usize> {
    sequence: u64,
    cid: Cid,
    token: Option<ResetToken>,
    retired: bool,
    retirement_acked: bool,
    local: Option<SocketAddr>,
    remotes: [Option<RemoteUse>; ADDRESSES],
}

/// Caller-owned peer history. `ADDRESSES` bounds remote rebinding history per
/// CID, including both authorized and actually used remote addresses.
#[derive(Clone, Copy)]
pub struct PeerCidSlot<const ADDRESSES: usize> {
    generation: u64,
    entry: Option<PeerEntry<ADDRESSES>>,
}

impl<const ADDRESSES: usize> PeerCidSlot<ADDRESSES> {
    pub const EMPTY: Self = Self {
        generation: 0,
        entry: None,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerCid {
    pub handle: PeerCidHandle,
    pub sequence: u64,
    pub cid: Cid,
}

/// The handle may refer to a tombstone when an old NEW frame arrives below the
/// retirement floor. It is then usable for retirement bookkeeping, not sending.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerCidUpdate {
    pub handle: PeerCidHandle,
    pub duplicate: bool,
    pub retired: bool,
}

/// Authenticated peer IDs, reliable retirement state, and reset-token history.
/// Identity and backing-storage requirements are the same as `LocalCidTable`.
pub struct PeerCidTable<'a, const ADDRESSES: usize> {
    table: u64,
    connection_generation: u64,
    slots: &'a mut [PeerCidSlot<ADDRESSES>],
    active_limit: u64,
    retire_prior_to: u64,
}

impl<'a, const ADDRESSES: usize> PeerCidTable<'a, ADDRESSES> {
    /// Seed sequence zero with the peer's final initial source CID. The caller
    /// handles Retry/handshake CID negotiation before seeding this ledger. No
    /// reset token is trusted here, even if the CID came from an Initial packet.
    pub fn new(
        table: u64,
        connection_generation: u64,
        slots: &'a mut [PeerCidSlot<ADDRESSES>],
        active_limit: u64,
        initial_cid: Cid,
    ) -> Result<Self, CidError> {
        validate_limit(active_limit)?;
        if slots.is_empty() || ADDRESSES == 0 {
            return Err(CidError::InvalidCapacity);
        }
        if slots.iter().any(|slot| slot.generation == u64::MAX) {
            return Err(CidError::GenerationExhausted);
        }
        for slot in slots.iter_mut() {
            slot.generation += 1;
            slot.entry = None;
        }
        slots[0].entry = Some(PeerEntry {
            sequence: 0,
            cid: initial_cid,
            token: None,
            retired: false,
            retirement_acked: false,
            local: None,
            remotes: [None; ADDRESSES],
        });
        Ok(Self {
            table,
            connection_generation,
            slots,
            active_limit,
            retire_prior_to: 0,
        })
    }

    /// Private admission simulation in separate caller storage. Handles from
    /// this copy must never authorize a real send or reset-token decision.
    /// Replays retained early controls under the remembered (possibly smaller)
    /// active CID limit without mutating the live table.
    pub(crate) fn admission_copy<'b>(
        &self,
        slots: &'b mut [PeerCidSlot<ADDRESSES>],
        active_limit: u64,
    ) -> Result<PeerCidTable<'b, ADDRESSES>, CidError> {
        validate_limit(active_limit)?;
        if slots.len() != self.slots.len() {
            return Err(CidError::InvalidCapacity);
        }
        let limit = self.active_limit.min(active_limit);
        if self.active().count() as u64 > limit {
            return Err(CidError::ActiveLimit);
        }
        slots.copy_from_slice(self.slots);
        Ok(PeerCidTable {
            table: self.table,
            connection_generation: self.connection_generation,
            slots,
            active_limit: limit,
            retire_prior_to: self.retire_prior_to,
        })
    }

    pub fn initial(&self) -> Result<PeerCid, CidError> {
        self.get(self.handle(0))
    }

    /// Client only: install the server's stateless_reset_token parameter after
    /// TLS authentication and all TP checks (including initial_source_connection_id).
    /// The same parameter from a client is forbidden and must be rejected by the
    /// transport-parameter layer. Repeated identical installation is idempotent.
    pub fn install_initial_token_verified(&mut self, token: ResetToken) -> Result<(), CidError> {
        let entry = self.slots[0]
            .entry
            .as_ref()
            .ok_or(CidError::UnknownSequence)?;
        if entry.token.is_some_and(|old| old != token) {
            return Err(CidError::ConflictingSequence);
        }
        if self
            .slots
            .iter()
            .skip(1)
            .filter_map(|slot| slot.entry.as_ref())
            .any(|other| other.token == Some(token))
        {
            return Err(CidError::ResetTokenReused);
        }
        self.slots[0]
            .entry
            .as_mut()
            .ok_or(CidError::UnknownSequence)?
            .token = Some(token);
        Ok(())
    }

    /// Client only: accept the server's preferred_address CID and token from
    /// verified transport parameters. Its sequence number is always one.
    pub fn accept_preferred_verified(
        &mut self,
        cid: Cid,
        token: ResetToken,
    ) -> Result<PeerCidUpdate, CidError> {
        self.accept_new_authenticated(1, 0, cid, token)
    }

    /// Process a NEW_CONNECTION_ID from an authenticated packet at a permitted
    /// encryption level. Validated duplicate frames may raise the retirement
    /// floor; smaller floors never undo retirement. The entire change is
    /// preflighted, including the active limit after both retirements and add.
    pub fn accept_new_authenticated(
        &mut self,
        sequence: u64,
        retire_prior_to: u64,
        cid: Cid,
        token: ResetToken,
    ) -> Result<PeerCidUpdate, CidError> {
        if sequence > MAX_SEQUENCE {
            return Err(CidError::InvalidSequence);
        }
        if retire_prior_to > sequence {
            return Err(CidError::InvalidRetirePriorTo);
        }
        let mut existing = None;
        for (index, entry) in self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| slot.entry.as_ref().map(|entry| (index, entry)))
        {
            if entry.sequence == sequence {
                if entry.cid != cid || entry.token.is_some_and(|old| old != token) {
                    return Err(CidError::ConflictingSequence);
                }
                existing = Some(index);
            } else {
                if entry.cid == cid {
                    return Err(CidError::ConnectionIdReused);
                }
                if entry.token == Some(token) {
                    return Err(CidError::ResetTokenReused);
                }
            }
        }
        let floor = self.retire_prior_to.max(retire_prior_to);
        let active_after = self
            .slots
            .iter()
            .filter_map(|slot| slot.entry.as_ref())
            .filter(|entry| !entry.retired && entry.sequence >= floor)
            .count() as u64
            + u64::from(existing.is_none() && sequence >= floor);
        if active_after > self.active_limit {
            return Err(CidError::ActiveLimit);
        }
        let index = match existing {
            Some(index) => index,
            None => self
                .slots
                .iter()
                .position(|slot| slot.entry.is_none())
                .ok_or(CidError::HistoryFull)?,
        };

        // There are no fallible operations below this line.
        for entry in self.slots.iter_mut().filter_map(|slot| slot.entry.as_mut()) {
            if entry.sequence < floor {
                entry.retired = true;
            }
        }
        self.retire_prior_to = floor;
        if let Some(entry) = self.slots[index].entry.as_mut() {
            // Sequence zero may first acquire its token in an authenticated NEW.
            entry.token = Some(token);
        } else {
            self.slots[index].entry = Some(PeerEntry {
                sequence,
                cid,
                token: Some(token),
                retired: sequence < floor,
                retirement_acked: false,
                local: None,
                remotes: [None; ADDRESSES],
            });
        }
        Ok(PeerCidUpdate {
            handle: self.handle(index),
            duplicate: existing.is_some(),
            retired: self.slots[index]
                .entry
                .as_ref()
                .is_some_and(|entry| entry.retired),
        })
    }

    fn handle(&self, index: usize) -> PeerCidHandle {
        PeerCidHandle(Handle {
            table: self.table,
            connection_generation: self.connection_generation,
            slot: index,
            generation: self.slots[index].generation,
        })
    }

    fn entry(&self, handle: PeerCidHandle) -> Result<&PeerEntry<ADDRESSES>, CidError> {
        let slot = self.slots.get(handle.0.slot).ok_or(CidError::StaleHandle)?;
        validate_handle(
            handle.0,
            self.table,
            self.connection_generation,
            slot.generation,
        )?;
        slot.entry.as_ref().ok_or(CidError::StaleHandle)
    }

    pub fn get(&self, handle: PeerCidHandle) -> Result<PeerCid, CidError> {
        let entry = self.entry(handle)?;
        if entry.retired {
            return Err(CidError::Retired);
        }
        Ok(PeerCid {
            handle,
            sequence: entry.sequence,
            cid: entry.cid,
        })
    }

    pub fn active(&self) -> impl Iterator<Item = PeerCid> + '_ {
        self.slots.iter().enumerate().filter_map(|(index, slot)| {
            let entry = slot.entry.as_ref()?;
            (!entry.retired).then(|| PeerCid {
                handle: self.handle(index),
                sequence: entry.sequence,
                cid: entry.cid,
            })
        })
    }

    /// Preflight before submitting a datagram to the carrier. `record_sent`
    /// must follow acceptance without intervening mutations of this table.
    pub fn check_send(
        &self,
        handle: PeerCidHandle,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Result<(), CidError> {
        let entry = self.entry(handle)?;
        if entry.retired {
            return Err(CidError::Retired);
        }
        if let Some(previous) = entry.local {
            if previous != local {
                return Err(CidError::DifferentLocalAddress);
            }
            if !entry
                .remotes
                .iter()
                .flatten()
                .any(|usage| usage.address == remote)
            {
                return Err(CidError::DifferentRemoteAddress);
            }
        }
        Ok(())
    }

    /// Record an actual carrier-accepted send, never a planned or blocked send.
    /// This enables the authenticated token only for this exact remote address.
    pub fn record_sent(
        &mut self,
        handle: PeerCidHandle,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Result<(), CidError> {
        self.check_send(handle, local, remote)?;
        let entry = self.slots[handle.0.slot]
            .entry
            .as_mut()
            .ok_or(CidError::StaleHandle)?;
        if entry.local.is_none() {
            entry.local = Some(local);
            entry.remotes[0] = Some(RemoteUse {
                address: remote,
                sent: true,
            });
        } else {
            // check_send already proved the exact remote exists.
            for usage in entry.remotes.iter_mut().flatten() {
                if usage.address == remote {
                    usage.sent = true;
                }
            }
        }
        Ok(())
    }

    /// Authorize the RFC 9000 section 9.5 remote-rebinding exception only after
    /// authenticating a peer packet arriving from `remote` at the same `local`,
    /// with the same local destination CID as the previous path. The caller's
    /// path layer must establish those facts and apply migration/address-
    /// validation rules. This neither validates a path nor records a send.
    pub fn authorize_remote_rebinding_authenticated(
        &mut self,
        handle: PeerCidHandle,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Result<(), CidError> {
        let entry = self.entry(handle)?;
        if entry.retired {
            return Err(CidError::Retired);
        }
        match entry.local {
            None => return Err(CidError::UnusedConnectionId),
            Some(previous) if previous != local => return Err(CidError::DifferentLocalAddress),
            Some(_) => {}
        }
        if entry
            .remotes
            .iter()
            .flatten()
            .any(|usage| usage.address == remote)
        {
            return Ok(());
        }
        let index = entry
            .remotes
            .iter()
            .position(Option::is_none)
            .ok_or(CidError::AddressHistoryFull)?;
        self.slots[handle.0.slot]
            .entry
            .as_mut()
            .ok_or(CidError::StaleHandle)?
            .remotes[index] = Some(RemoteUse {
            address: remote,
            sent: false,
        });
        Ok(())
    }

    /// Immediately stop use and queue a reliable RETIRE frame. All copies of
    /// the handle cease to authorize sends or reset detection. Idempotent.
    pub fn retire(&mut self, handle: PeerCidHandle) -> Result<bool, CidError> {
        let changed = !self.entry(handle)?.retired;
        self.slots[handle.0.slot]
            .entry
            .as_mut()
            .ok_or(CidError::StaleHandle)?
            .retired = true;
        Ok(changed)
    }

    /// Includes retirements awaiting acknowledgment, whether or not sent yet.
    /// Retransmit using the caller's recovery layer until the frame is ACKed.
    pub fn pending_retirements(&self) -> impl Iterator<Item = PeerCidHandle> + '_ {
        self.slots.iter().enumerate().filter_map(|(index, slot)| {
            let entry = slot.entry.as_ref()?;
            (entry.retired && !entry.retirement_acked).then(|| self.handle(index))
        })
    }

    /// Obtain a pending retirement's sequence for a packet with this actual
    /// destination CID. RETIRE must never retire its own packet's DCID.
    pub fn retirement_sequence(
        &self,
        handle: PeerCidHandle,
        packet_dcid: Cid,
    ) -> Result<u64, CidError> {
        let entry = self.entry(handle)?;
        if !entry.retired {
            return Err(CidError::NotRetired);
        }
        if entry.cid == packet_dcid {
            return Err(CidError::CurrentDestinationCid);
        }
        Ok(entry.sequence)
    }

    /// Called only when an authenticated ACK acknowledges a packet that really
    /// carried this RETIRE frame. Retains the tombstone and uniqueness history.
    pub fn acknowledge_retirement(&mut self, handle: PeerCidHandle) -> Result<bool, CidError> {
        let entry = self.entry(handle)?;
        if !entry.retired {
            return Err(CidError::NotRetired);
        }
        let changed = !entry.retirement_acked;
        self.slots[handle.0.slot]
            .entry
            .as_mut()
            .ok_or(CidError::StaleHandle)?
            .retirement_acked = true;
        Ok(changed)
    }

    /// Check the *whole original UDP datagram*, including when the first packet
    /// cannot be routed/decrypted. AEAD failure alone is never reset evidence.
    /// A true result requires entering draining and sending no more packets;
    /// the connection/lifecycle owner performs that transition.
    ///
    /// No first-byte/header-bit check is allowed. All eligible token comparisons
    /// use `subtle` and accumulate without early exit. Unused/retired IDs and
    /// unsent/wrong remote addresses cannot match. Address/history eligibility
    /// is not secret; token bytes do not influence control flow until the result.
    pub fn detect_stateless_reset(&self, datagram: &[u8], remote: SocketAddr) -> bool {
        if datagram.len() < 21 {
            return false;
        }
        let tail = &datagram[datagram.len() - 16..];
        let mut matched = Choice::from(0);
        for entry in self.slots.iter().filter_map(|slot| slot.entry.as_ref()) {
            if entry.retired
                || !entry
                    .remotes
                    .iter()
                    .flatten()
                    .any(|usage| usage.sent && usage.address == remote)
            {
                continue;
            }
            if let Some(token) = entry.token {
                matched |= token.0.as_slice().ct_eq(tail);
            }
        }
        bool::from(matched)
    }

    pub const fn retire_prior_to(&self) -> u64 {
        self.retire_prior_to
    }
}

fn validate_limit(limit: u64) -> Result<(), CidError> {
    if !(2..=MAX_SEQUENCE).contains(&limit) {
        return Err(CidError::InvalidActiveLimit);
    }
    Ok(())
}

fn validate_handle(
    handle: Handle,
    table: u64,
    connection_generation: u64,
    generation: u64,
) -> Result<(), CidError> {
    if handle.table != table
        || handle.connection_generation != connection_generation
        || handle.generation != generation
    {
        return Err(CidError::StaleHandle);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::{Ipv4Addr, SocketAddrV4};

    fn cid(value: u8) -> Cid {
        Cid::new(&[value; 8]).unwrap()
    }

    fn token(value: u8) -> ResetToken {
        ResetToken::new([value; 16])
    }

    fn addr(last: u8, port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, last), port))
    }

    fn reset(value: u8) -> [u8; 21] {
        let mut result = [0; 21];
        result[5..].fill(value);
        result
    }

    #[test]
    fn deferred_retirement_cannot_be_legalized_by_a_later_advertisement() {
        let mut slots = [LocalCidSlot::EMPTY; 4];
        let mut table = LocalCidTable::new(1, 7, &mut slots, 2).unwrap();
        let initial = table.issue_initial(cid(0), None).unwrap();
        table.mark_advertised(initial.handle).unwrap();
        let next = table.issue(cid(1), token(1), 0).unwrap();
        let admission = table.check_retirement(1, cid(0).as_bytes());
        assert_eq!(admission, Err(CidError::UnknownSequence));
        assert_eq!(table.routing_count(), 2);
        table.mark_advertised(next.handle).unwrap();
        assert_eq!(table.check_retirement(1, cid(0).as_bytes()), Ok(()));
        assert_eq!(admission, Err(CidError::UnknownSequence));
        assert_eq!(
            table.check_retirement(1, cid(1).as_bytes()),
            Err(CidError::CurrentDestinationCid)
        );
    }

    #[test]
    fn early_admission_copy_enforces_remembered_cumulative_credit_without_effects() {
        let mut slots = [PeerCidSlot::<2>::EMPTY; 8];
        let mut table = PeerCidTable::new(1, 7, &mut slots, 4, cid(0)).unwrap();
        let mut scratch = [PeerCidSlot::<2>::EMPTY; 8];
        {
            let mut admission = table.admission_copy(&mut scratch, 2).unwrap();
            admission
                .accept_new_authenticated(1, 0, cid(1), token(1))
                .unwrap();
            assert_eq!(
                admission.accept_new_authenticated(2, 0, cid(2), token(2)),
                Err(CidError::ActiveLimit)
            );
            admission
                .accept_new_authenticated(2, 1, cid(2), token(2))
                .unwrap();
            assert_eq!(admission.active().count(), 2);
            assert_eq!(
                admission.accept_new_authenticated(1, 1, cid(3), token(1)),
                Err(CidError::ConflictingSequence)
            );
        }
        assert_eq!(table.active().count(), 1);
        table
            .accept_new_authenticated(1, 0, cid(1), token(1))
            .unwrap();
        table
            .accept_new_authenticated(2, 0, cid(2), token(2))
            .unwrap();
        assert!(matches!(
            table.admission_copy(&mut scratch, 2),
            Err(CidError::ActiveLimit)
        ));
    }

    #[test]
    fn cid_bounds_and_token_debug() {
        assert_eq!(Cid::new(&[]), Err(CidError::InvalidCidLength));
        assert_eq!(Cid::new(&[0; 21]), Err(CidError::InvalidCidLength));
        assert_eq!(Cid::new(&[0; 20]).unwrap().as_bytes(), &[0; 20]);
        assert_eq!(Cid::new(&[1]).unwrap().as_bytes(), &[1]);
        assert_eq!(std::format!("{:?}", token(7)), "ResetToken([redacted])");
        assert_eq!(token(7), token(7));
        assert_ne!(token(7), token(8));
    }

    #[test]
    fn local_sequence_preferred_and_routing_until_actual_retire() {
        let mut slots = [LocalCidSlot::EMPTY; 5];
        let mut table = LocalCidTable::new(1, 9, &mut slots, 2).unwrap();
        assert_eq!(
            table.issue(cid(1), token(1), 0),
            Err(CidError::InitialRequired)
        );
        let initial = table.issue_initial(cid(0), Some(token(0))).unwrap();
        let preferred = table.issue_preferred(cid(1), token(1)).unwrap();
        table.mark_advertised(initial.handle).unwrap();
        table.mark_advertised(preferred.handle).unwrap();
        assert_eq!((initial.sequence, preferred.sequence), (0, 1));
        assert_eq!(
            table.issue_initial(cid(2), None),
            Err(CidError::InitialAlreadyIssued)
        );
        assert_eq!(
            table.issue_preferred(cid(2), token(2)),
            Err(CidError::PreferredSequenceUnavailable)
        );
        assert_eq!(table.issue(cid(2), token(2), 0), Err(CidError::ActiveLimit));
        let next = table.issue(cid(2), token(2), 1).unwrap();
        assert_eq!(next.sequence, 2);
        assert_eq!(table.retire_prior_to(), 1);
        assert_eq!(table.routing_count(), 3);
        assert_eq!(table.route(cid(0).as_bytes()), Some(initial.handle));
        assert_eq!(
            table.retire_authenticated(0, cid(0).as_bytes()),
            Err(CidError::CurrentDestinationCid)
        );
        assert_eq!(table.route(cid(0).as_bytes()), Some(initial.handle));
        assert_eq!(
            table.retire_authenticated(3, cid(2).as_bytes()),
            Err(CidError::UnknownSequence)
        );
        assert_eq!(table.retire_authenticated(0, cid(2).as_bytes()), Ok(true));
        assert_eq!(table.retire_authenticated(0, cid(2).as_bytes()), Ok(false));
        assert_eq!(table.route(cid(0).as_bytes()), None);
        assert_eq!(table.get(initial.handle), Err(CidError::Retired));
        assert_eq!(table.get(preferred.handle), Ok(preferred));
        assert_eq!(table.routing_count(), 2);
    }

    #[test]
    fn local_uniqueness_survives_retirement_and_capacity_is_atomic() {
        let mut slots = [LocalCidSlot::EMPTY; 2];
        let mut table = LocalCidTable::new(1, 0, &mut slots, 2).unwrap();
        let initial = table.issue_initial(cid(0), Some(token(0))).unwrap();
        table.mark_advertised(initial.handle).unwrap();
        table.issue(cid(1), token(1), 0).unwrap();
        table.retire_authenticated(0, cid(1).as_bytes()).unwrap();
        assert_eq!(
            table.issue(cid(0), token(2), 1),
            Err(CidError::ConnectionIdReused)
        );
        assert_eq!(
            table.issue(cid(2), token(0), 1),
            Err(CidError::ResetTokenReused)
        );
        assert_eq!(table.issue(cid(2), token(2), 2), Err(CidError::HistoryFull));
        assert_eq!(table.retire_prior_to(), 0);
        assert_eq!(table.next_sequence, 2);
        assert_eq!(table.routing_count(), 1);
        assert!(table.route(cid(1).as_bytes()).is_some());
    }

    #[test]
    fn local_rejects_invalid_and_decreasing_floor_without_consuming_sequence() {
        let mut slots = [LocalCidSlot::EMPTY; 5];
        let mut table = LocalCidTable::new(1, 0, &mut slots, 2).unwrap();
        table.issue_initial(cid(0), None).unwrap();
        assert_eq!(
            table.issue(cid(1), token(1), 2),
            Err(CidError::InvalidRetirePriorTo)
        );
        assert_eq!(table.issue(cid(1), token(1), 1).unwrap().sequence, 1);
        assert_eq!(
            table.issue(cid(2), token(2), 0),
            Err(CidError::InvalidRetirePriorTo)
        );
        assert_eq!(table.issue(cid(2), token(2), 1).unwrap().sequence, 2);
    }

    #[test]
    fn local_unsent_advertisements_do_not_authorize_retirement() {
        let mut slots = [LocalCidSlot::EMPTY; 4];
        let mut table = LocalCidTable::new(1, 0, &mut slots, 4).unwrap();
        let zero = table.issue_initial(cid(0), None).unwrap();
        let one = table.issue_preferred(cid(1), token(1)).unwrap();
        let two = table.issue(cid(2), token(2), 0).unwrap();
        // Every reservation routes for send/receive race safety, even when its
        // advertisement was rejected by a carrier and has no accepted evidence.
        assert_eq!(table.routing_count(), 3);
        assert_eq!(table.highest_advertised_sequence(), None);
        for sequence in 0..=2 {
            assert_eq!(
                table.retire_authenticated(sequence, cid(3).as_bytes()),
                Err(CidError::UnknownSequence)
            );
        }
        assert_eq!(table.routing_count(), 3);
        assert_eq!(table.mark_advertised(zero.handle), Ok(true));
        assert_eq!(table.highest_advertised_sequence(), Some(0));
        assert_eq!(
            table.retire_authenticated(1, cid(0).as_bytes()),
            Err(CidError::UnknownSequence)
        );
        assert_eq!(
            table.retire_authenticated(2, cid(0).as_bytes()),
            Err(CidError::UnknownSequence)
        );
        assert_eq!(table.route(cid(1).as_bytes()), Some(one.handle));
        assert_eq!(table.route(cid(2).as_bytes()), Some(two.handle));
        assert_eq!(table.mark_advertised(one.handle), Ok(true));
        assert_eq!(table.mark_advertised(one.handle), Ok(false));
        assert_eq!(table.highest_advertised_sequence(), Some(1));
        assert_eq!(table.retire_authenticated(1, cid(0).as_bytes()), Ok(true));
        assert_eq!(table.retire_authenticated(1, cid(0).as_bytes()), Ok(false));
        assert_eq!(table.mark_advertised(one.handle), Err(CidError::Retired));
        assert_eq!(table.highest_advertised_sequence(), Some(1));
        assert_eq!(
            table.retire_authenticated(2, cid(0).as_bytes()),
            Err(CidError::UnknownSequence)
        );
    }

    #[test]
    fn local_reordered_advertisements_use_precise_highest_sent_bound() {
        let mut slots = [LocalCidSlot::EMPTY; 4];
        let mut table = LocalCidTable::new(1, 0, &mut slots, 4).unwrap();
        let zero = table.issue_initial(cid(0), None).unwrap();
        let one = table.issue(cid(1), token(1), 0).unwrap();
        let two = table.issue(cid(2), token(2), 0).unwrap();
        table.mark_advertised(two.handle).unwrap();
        assert_eq!(table.highest_advertised_sequence(), Some(2));
        assert_eq!(table.mark_advertised(zero.handle), Ok(true));
        assert_eq!(table.mark_advertised(zero.handle), Ok(false));
        assert_eq!(table.highest_advertised_sequence(), Some(2));
        // Sequence one was reserved but its send was blocked. The RFC compares
        // with the highest sequence actually sent, so this known lower ID can
        // be retired; an unallocated sequence still cannot.
        assert_eq!(table.retire_authenticated(1, cid(2).as_bytes()), Ok(true));
        assert_eq!(table.get(one.handle), Err(CidError::Retired));
        assert_eq!(
            table.retire_authenticated(3, cid(2).as_bytes()),
            Err(CidError::UnknownSequence)
        );
        assert_eq!(table.highest_advertised_sequence(), Some(2));
    }

    #[test]
    fn handles_reject_other_tables_connections_and_reinitialized_storage() {
        let mut local_slots = [LocalCidSlot::EMPTY; 2];
        let old_local = {
            let mut table = LocalCidTable::new(1, 9, &mut local_slots, 2).unwrap();
            table.issue_initial(cid(0), None).unwrap().handle
        };
        let mut table = LocalCidTable::new(1, 9, &mut local_slots, 2).unwrap();
        table.issue_initial(cid(0), None).unwrap();
        assert_eq!(table.get(old_local), Err(CidError::StaleHandle));
        assert_eq!(table.mark_advertised(old_local), Err(CidError::StaleHandle));
        assert_eq!(table.highest_advertised_sequence(), None);
        let mut other_slots = [LocalCidSlot::EMPTY; 2];
        let mut other = LocalCidTable::new(2, 9, &mut other_slots, 2).unwrap();
        other.issue_initial(cid(0), None).unwrap();
        assert_eq!(other.get(old_local), Err(CidError::StaleHandle));
        let mut generation_slots = [LocalCidSlot::EMPTY; 2];
        let mut other = LocalCidTable::new(1, 10, &mut generation_slots, 2).unwrap();
        other.issue_initial(cid(0), None).unwrap();
        assert_eq!(other.get(old_local), Err(CidError::StaleHandle));

        let mut peer_slots = [PeerCidSlot::<2>::EMPTY; 2];
        let old_peer = PeerCidTable::new(1, 9, &mut peer_slots, 2, cid(0))
            .unwrap()
            .initial()
            .unwrap()
            .handle;
        let mut peer = PeerCidTable::new(1, 9, &mut peer_slots, 2, cid(0)).unwrap();
        assert_eq!(peer.get(old_peer), Err(CidError::StaleHandle));
        assert_eq!(peer.retire(old_peer), Err(CidError::StaleHandle));
        assert_eq!(
            peer.acknowledge_retirement(old_peer),
            Err(CidError::StaleHandle)
        );
        assert_eq!(
            peer.record_sent(old_peer, addr(1, 1), addr(2, 2)),
            Err(CidError::StaleHandle)
        );
        let mut other_slots = [PeerCidSlot::<2>::EMPTY; 2];
        let other = PeerCidTable::new(2, 9, &mut other_slots, 2, cid(0)).unwrap();
        assert_eq!(other.get(old_peer), Err(CidError::StaleHandle));
        let mut generation_slots = [PeerCidSlot::<2>::EMPTY; 2];
        let other = PeerCidTable::new(1, 10, &mut generation_slots, 2, cid(0)).unwrap();
        assert_eq!(other.get(old_peer), Err(CidError::StaleHandle));
    }

    #[test]
    fn slot_generation_exhaustion_and_invalid_construction_are_atomic() {
        let mut local_slots = [LocalCidSlot::EMPTY; 2];
        local_slots[0].generation = 12;
        local_slots[1].generation = u64::MAX;
        assert!(matches!(
            LocalCidTable::new(1, 1, &mut local_slots, 2),
            Err(CidError::GenerationExhausted)
        ));
        assert_eq!(local_slots[0].generation, 12);
        assert!(matches!(
            LocalCidTable::new(1, 1, &mut local_slots, 1),
            Err(CidError::InvalidActiveLimit)
        ));
        let mut peer_slots = [PeerCidSlot::<2>::EMPTY; 2];
        peer_slots[0].generation = 12;
        peer_slots[1].generation = u64::MAX;
        assert!(matches!(
            PeerCidTable::new(1, 1, &mut peer_slots, 2, cid(0)),
            Err(CidError::GenerationExhausted)
        ));
        assert_eq!(peer_slots[0].generation, 12);
        let mut empty_addresses = [PeerCidSlot::<0>::EMPTY; 2];
        assert!(matches!(
            PeerCidTable::new(1, 1, &mut empty_addresses, 2, cid(0)),
            Err(CidError::InvalidCapacity)
        ));
    }

    #[test]
    fn peer_reordered_new_frames_floor_and_duplicate_invariants() {
        let mut slots = [PeerCidSlot::<2>::EMPTY; 8];
        let mut table = PeerCidTable::new(1, 0, &mut slots, 3, cid(0)).unwrap();
        let zero = table.initial().unwrap().handle;
        let three = table
            .accept_new_authenticated(3, 2, cid(3), token(3))
            .unwrap();
        assert!(!three.retired);
        assert!(!three.duplicate);
        assert_eq!(table.get(zero), Err(CidError::Retired));
        let one = table
            .accept_new_authenticated(1, 0, cid(1), token(1))
            .unwrap();
        assert!(one.retired);
        assert_eq!(table.retire_prior_to(), 2);
        let two = table
            .accept_new_authenticated(2, 0, cid(2), token(2))
            .unwrap();
        assert!(!two.retired);
        assert_eq!(table.active().count(), 2);
        let duplicate = table
            .accept_new_authenticated(3, 2, cid(3), token(3))
            .unwrap();
        assert!(duplicate.duplicate);
        assert_eq!(duplicate.handle, three.handle);
        assert_eq!(
            table.accept_new_authenticated(3, 3, cid(7), token(3)),
            Err(CidError::ConflictingSequence)
        );
        assert_eq!(
            table.accept_new_authenticated(3, 3, cid(3), token(7)),
            Err(CidError::ConflictingSequence)
        );
        assert_eq!(table.retire_prior_to(), 2);
        assert!(table.get(two.handle).is_ok());
        assert_eq!(
            table.accept_new_authenticated(4, 4, cid(3), token(4)),
            Err(CidError::ConnectionIdReused)
        );
        assert_eq!(
            table.accept_new_authenticated(4, 4, cid(4), token(1)),
            Err(CidError::ResetTokenReused)
        );
        assert_eq!(table.retire_prior_to(), 2);
        let raised = table
            .accept_new_authenticated(3, 3, cid(3), token(3))
            .unwrap();
        assert!(raised.duplicate);
        assert_eq!(table.get(two.handle), Err(CidError::Retired));
        assert_eq!(table.active().count(), 1);
        assert_eq!(table.pending_retirements().count(), 3);
    }

    #[test]
    fn peer_limit_is_checked_after_retirement_and_failures_are_atomic() {
        let mut slots = [PeerCidSlot::<1>::EMPTY; 4];
        let mut table = PeerCidTable::new(1, 0, &mut slots, 2, cid(0)).unwrap();
        table
            .accept_new_authenticated(1, 0, cid(1), token(1))
            .unwrap();
        assert_eq!(
            table.accept_new_authenticated(2, 0, cid(2), token(2)),
            Err(CidError::ActiveLimit)
        );
        assert_eq!(table.retire_prior_to(), 0);
        assert_eq!(table.active().count(), 2);
        let two = table
            .accept_new_authenticated(2, 1, cid(2), token(2))
            .unwrap();
        assert_eq!(table.active().count(), 2);
        assert_eq!(table.pending_retirements().count(), 1);
        table
            .accept_new_authenticated(3, 3, cid(3), token(3))
            .unwrap();
        assert_eq!(table.active().count(), 1);
        assert_eq!(table.get(two.handle), Err(CidError::Retired));
        assert_eq!(
            table.accept_new_authenticated(4, 4, cid(4), token(4)),
            Err(CidError::HistoryFull)
        );
        assert_eq!(table.retire_prior_to(), 3);
        assert_eq!(table.active().next().unwrap().sequence, 3);
        assert_eq!(
            table.accept_new_authenticated(4, 5, cid(4), token(4)),
            Err(CidError::InvalidRetirePriorTo)
        );
        assert_eq!(
            table.accept_new_authenticated(MAX_SEQUENCE + 1, 0, cid(4), token(4)),
            Err(CidError::InvalidSequence)
        );
        assert_eq!(table.active().count(), 1);
    }

    #[test]
    fn arbitrary_retirement_gaps_and_acked_duplicates_never_reopen() {
        let mut slots = [PeerCidSlot::<1>::EMPTY; 5];
        let mut table = PeerCidTable::new(1, 0, &mut slots, 5, cid(0)).unwrap();
        let zero = table.initial().unwrap().handle;
        let two = table
            .accept_new_authenticated(2, 0, cid(2), token(2))
            .unwrap()
            .handle;
        let four = table
            .accept_new_authenticated(4, 0, cid(4), token(4))
            .unwrap()
            .handle;
        assert_eq!(table.acknowledge_retirement(two), Err(CidError::NotRetired));
        assert_eq!(
            table.retirement_sequence(two, cid(4)),
            Err(CidError::NotRetired)
        );
        assert_eq!(table.retire(two), Ok(true));
        assert_eq!(table.retire(two), Ok(false));
        assert_eq!(
            table.retirement_sequence(two, cid(2)),
            Err(CidError::CurrentDestinationCid)
        );
        assert_eq!(table.retirement_sequence(two, cid(4)), Ok(2));
        assert_eq!(table.pending_retirements().count(), 1);
        assert_eq!(table.acknowledge_retirement(two), Ok(true));
        assert_eq!(table.acknowledge_retirement(two), Ok(false));
        assert_eq!(table.pending_retirements().count(), 0);
        assert!(
            table
                .accept_new_authenticated(2, 0, cid(2), token(2))
                .unwrap()
                .retired
        );
        assert_eq!(table.pending_retirements().count(), 0);
        let one = table
            .accept_new_authenticated(1, 0, cid(1), token(1))
            .unwrap();
        let three = table
            .accept_new_authenticated(3, 0, cid(3), token(3))
            .unwrap();
        assert!(!one.retired && !three.retired);
        assert!(table.get(zero).is_ok());
        assert!(table.get(four).is_ok());
        assert_eq!(table.get(two), Err(CidError::Retired));
        assert_eq!(table.retire_prior_to(), 0);
    }

    #[test]
    fn reset_requires_authenticated_token_used_cid_and_exact_remote() {
        let mut slots = [PeerCidSlot::<2>::EMPTY; 3];
        let mut table = PeerCidTable::new(1, 0, &mut slots, 3, cid(0)).unwrap();
        let local = addr(1, 4000);
        let remote = addr(2, 443);
        let initial = table.initial().unwrap().handle;
        table.record_sent(initial, local, remote).unwrap();
        assert!(!table.detect_stateless_reset(&reset(0), remote));
        table.install_initial_token_verified(token(0)).unwrap();
        assert!(table.detect_stateless_reset(&reset(0), remote));
        let one = table
            .accept_new_authenticated(1, 0, cid(1), token(1))
            .unwrap()
            .handle;
        assert!(!table.detect_stateless_reset(&reset(1), remote));
        table.check_send(one, local, remote).unwrap();
        assert!(!table.detect_stateless_reset(&reset(1), remote));
        table.record_sent(one, local, remote).unwrap();
        assert!(table.detect_stateless_reset(&reset(1), remote));
        assert!(!table.detect_stateless_reset(&reset(1), addr(3, 443)));
        assert!(!table.detect_stateless_reset(&reset(1), addr(2, 444)));
        assert!(!table.detect_stateless_reset(&reset(1)[1..], remote));
        assert!(!table.detect_stateless_reset(&reset(7), remote));
        for first in [0, 0x40, 0x80, 0xff] {
            let mut datagram = reset(1);
            datagram[0] = first;
            assert!(table.detect_stateless_reset(&datagram, remote));
        }
        for offset in 5..21 {
            let mut forged = reset(1);
            forged[offset] ^= 1;
            assert!(!table.detect_stateless_reset(&forged, remote));
        }
        let mut coalesced = [0; 70];
        coalesced[5..21].fill(1);
        coalesced[54..].fill(7);
        assert!(!table.detect_stateless_reset(&coalesced, remote));
        coalesced[54..].fill(1);
        assert!(table.detect_stateless_reset(&coalesced, remote));
        table.retire(one).unwrap();
        assert!(!table.detect_stateless_reset(&reset(1), remote));
        assert_eq!(
            table.record_sent(one, local, remote),
            Err(CidError::Retired)
        );
        assert!(table.detect_stateless_reset(&reset(0), remote));
        table
            .accept_new_authenticated(2, 2, cid(2), token(2))
            .unwrap();
        assert!(!table.detect_stateless_reset(&reset(0), remote));
    }

    #[test]
    fn authenticated_rebinding_requires_same_local_and_an_actual_send() {
        let mut slots = [PeerCidSlot::<2>::EMPTY; 3];
        let mut table = PeerCidTable::new(1, 0, &mut slots, 3, cid(0)).unwrap();
        let initial = table.initial().unwrap().handle;
        table.install_initial_token_verified(token(0)).unwrap();
        let local = addr(1, 4000);
        let first = addr(2, 443);
        let rebound = addr(2, 444);
        assert_eq!(
            table.authorize_remote_rebinding_authenticated(initial, local, first),
            Err(CidError::UnusedConnectionId)
        );
        table.record_sent(initial, local, first).unwrap();
        assert_eq!(
            table.check_send(initial, local, rebound),
            Err(CidError::DifferentRemoteAddress)
        );
        assert_eq!(
            table.record_sent(initial, local, rebound),
            Err(CidError::DifferentRemoteAddress)
        );
        assert_eq!(
            table.check_send(initial, addr(1, 4001), first),
            Err(CidError::DifferentLocalAddress)
        );
        assert_eq!(
            table.authorize_remote_rebinding_authenticated(initial, addr(1, 4001), rebound),
            Err(CidError::DifferentLocalAddress)
        );
        table
            .authorize_remote_rebinding_authenticated(initial, local, rebound)
            .unwrap();
        table
            .authorize_remote_rebinding_authenticated(initial, local, rebound)
            .unwrap();
        assert!(!table.detect_stateless_reset(&reset(0), rebound));
        table.check_send(initial, local, rebound).unwrap();
        table.record_sent(initial, local, rebound).unwrap();
        assert!(table.detect_stateless_reset(&reset(0), rebound));
        assert!(table.detect_stateless_reset(&reset(0), first));
        let third = addr(2, 445);
        assert_eq!(
            table.authorize_remote_rebinding_authenticated(initial, local, third),
            Err(CidError::AddressHistoryFull)
        );
        assert_eq!(
            table.check_send(initial, local, third),
            Err(CidError::DifferentRemoteAddress)
        );
        assert!(!table.detect_stateless_reset(&reset(0), third));
        let fresh = table
            .accept_new_authenticated(1, 0, cid(1), token(1))
            .unwrap()
            .handle;
        table.record_sent(fresh, addr(1, 4001), third).unwrap();
        assert!(table.detect_stateless_reset(&reset(1), third));
    }

    #[test]
    fn verified_transport_tokens_conflict_and_duplicate_rules() {
        let mut slots = [PeerCidSlot::<1>::EMPTY; 4];
        let mut table = PeerCidTable::new(1, 0, &mut slots, 3, cid(0)).unwrap();
        let one = table.accept_preferred_verified(cid(1), token(1)).unwrap();
        assert_eq!(table.get(one.handle).unwrap().sequence, 1);
        assert!(
            table
                .accept_preferred_verified(cid(1), token(1))
                .unwrap()
                .duplicate
        );
        assert_eq!(
            table.install_initial_token_verified(token(1)),
            Err(CidError::ResetTokenReused)
        );
        table.install_initial_token_verified(token(0)).unwrap();
        table.install_initial_token_verified(token(0)).unwrap();
        assert_eq!(
            table.install_initial_token_verified(token(2)),
            Err(CidError::ConflictingSequence)
        );
        assert_eq!(
            table.accept_new_authenticated(0, 0, cid(0), token(2)),
            Err(CidError::ConflictingSequence)
        );
        assert!(
            table
                .accept_new_authenticated(0, 0, cid(0), token(0))
                .unwrap()
                .duplicate
        );
        table
            .accept_new_authenticated(2, 2, cid(2), token(2))
            .unwrap();
        assert_eq!(table.get(one.handle), Err(CidError::Retired));
        assert_eq!(
            table.accept_new_authenticated(3, 3, cid(3), token(1)),
            Err(CidError::ResetTokenReused)
        );
        assert_eq!(table.retire_prior_to(), 2);
    }

    #[test]
    fn authenticated_new_can_supply_initial_token_but_never_reopen_initial() {
        let mut slots = [PeerCidSlot::<1>::EMPTY; 2];
        let mut table = PeerCidTable::new(1, 0, &mut slots, 2, cid(0)).unwrap();
        let initial = table.initial().unwrap().handle;
        let local = addr(1, 4000);
        let remote = addr(2, 443);
        table.record_sent(initial, local, remote).unwrap();
        table
            .accept_new_authenticated(0, 0, cid(0), token(0))
            .unwrap();
        assert!(table.detect_stateless_reset(&reset(0), remote));
        table.retire(initial).unwrap();
        table.install_initial_token_verified(token(0)).unwrap();
        let duplicate = table
            .accept_new_authenticated(0, 0, cid(0), token(0))
            .unwrap();
        assert!(duplicate.retired);
        assert!(!table.detect_stateless_reset(&reset(0), remote));
    }
}
