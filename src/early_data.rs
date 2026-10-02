//! Bounded policy and quarantine primitives for the 0-RTT integration.
//!
//! These helpers do not negotiate TLS, authenticate tickets/packets, allocate
//! packet numbers, acknowledge data, or establish Finished. Their caller must
//! supply those checked facts. No application bytes are exposed until finish.
//! Replay claims are burned before accepting early data and are not rolled back.
//! The TLS/transport/typed-driver integration is intentionally still separate.

use crate::parameters::{Parameters, Peer};
use zeroize::Zeroize;

const MAX: u64 = (1 << 62) - 1;
const MAX_STREAMS: u64 = 1 << 60;
pub const REMEMBERED_BYTES: usize = 73;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Parameters(crate::parameters::Error),
    Packet(crate::packet::Error),
    InvalidLimits,
    InvalidFreshness,
    ChangedLimits,
    Disabled,
    Capacity,
    Replay,
    Expired,
    ClockRollback,
    EpochMismatch,
    StaleGeneration,
    Exhausted,
    State,
    StreamId,
    FlowControl,
    FinalSize,
    ConflictingOverlap,
    StaleRelease,
}

/// TLS decision plus the Finished boundary. Pending acceptance never permits
/// application delivery. Rejection is terminal for this connection's early data.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum EarlyStatus {
    #[default]
    Disabled,
    Offered,
    AcceptedPendingFinished,
    Accepted,
    Rejected,
}

/// Independent0RTT freshness policy. There is deliberately no Default and no
/// conversion from the ordinary resumption age tolerance. The one-minute cap
/// is this bounded profile's administrative limit, not an RFC guarantee.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EarlyFreshness {
    max_age_skew_ms: u32,
}
impl EarlyFreshness {
    pub const MAX_SKEW_MS: u32 = 60_000;
    pub fn new(max_age_skew_ms: u32) -> Result<Self, Error> {
        if max_age_skew_ms > Self::MAX_SKEW_MS {
            Err(Error::InvalidFreshness)
        } else {
            Ok(Self { max_age_skew_ms })
        }
    }
    pub fn permits(self, actual_age_ms: u64, reported_age_ms: u64) -> bool {
        actual_age_ms.abs_diff(reported_age_ms) <= u64::from(self.max_age_skew_ms)
    }
}

/// The reusable server parameters understood by this transport profile. Never
/// restore ACK-delay settings, CIDs, reset tokens, or preferred addresses.
/// Future supported transport extensions must extend this versioned encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RememberedLimits {
    idle_timeout: u64,
    max_udp_payload: u64,
    max_data: u64,
    stream_bidi_local: u64,
    stream_bidi_remote: u64,
    stream_uni: u64,
    streams_bidi: u64,
    streams_uni: u64,
    active_cids: u64,
    disable_migration: bool,
}
impl RememberedLimits {
    /// Call only on peer parameters authenticated by the completed connection.
    /// Parsing validates syntax; it does not establish their authentication.
    pub fn from_authenticated_server_parameters(bytes: &[u8]) -> Result<Self, Error> {
        let p = Parameters::parse(bytes, Peer::Server, &mut [0; 64]).map_err(Error::Parameters)?;
        let get = |id, default| p.get_integer(id, default).map_err(Error::Parameters);
        let limits = Self {
            idle_timeout: get(1, 0)?,
            max_udp_payload: get(3, 65527)?,
            max_data: get(4, 0)?,
            stream_bidi_local: get(5, 0)?,
            stream_bidi_remote: get(6, 0)?,
            stream_uni: get(7, 0)?,
            streams_bidi: get(8, 0)?,
            streams_uni: get(9, 0)?,
            active_cids: get(14, 2)?,
            disable_migration: p.get(12).is_some(),
        };
        limits.validate()?;
        Ok(limits)
    }
    fn numbers(self) -> [u64; 9] {
        [
            self.idle_timeout,
            self.max_udp_payload,
            self.max_data,
            self.stream_bidi_local,
            self.stream_bidi_remote,
            self.stream_uni,
            self.streams_bidi,
            self.streams_uni,
            self.active_cids,
        ]
    }
    fn validate(self) -> Result<(), Error> {
        if self.numbers().iter().any(|n| *n > MAX)
            || self.max_udp_payload < 1200
            || self.active_cids < 2
            || self.streams_bidi > MAX_STREAMS
            || self.streams_uni > MAX_STREAMS
        {
            return Err(Error::InvalidLimits);
        }
        Ok(())
    }
    /// Fixed 73-byte ticket payload, covered by the ticket's AEAD. This is not
    /// the TLS/QUIC wire transport-parameter encoding.
    pub fn encode(self) -> [u8; REMEMBERED_BYTES] {
        let mut out = [0; REMEMBERED_BYTES];
        for (i, n) in self.numbers().iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&n.to_be_bytes());
        }
        out[72] = u8::from(self.disable_migration);
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != REMEMBERED_BYTES || bytes[72] > 1 {
            return Err(Error::InvalidLimits);
        }
        let mut n = [0; 9];
        for (i, value) in n.iter_mut().enumerate() {
            *value = u64::from_be_bytes(
                bytes[i * 8..i * 8 + 8]
                    .try_into()
                    .map_err(|_| Error::InvalidLimits)?,
            );
        }
        let limits = Self {
            idle_timeout: n[0],
            max_udp_payload: n[1],
            max_data: n[2],
            stream_bidi_local: n[3],
            stream_bidi_remote: n[4],
            stream_uni: n[5],
            streams_bidi: n[6],
            streams_uni: n[7],
            active_cids: n[8],
            disable_migration: bytes[72] != 0,
        };
        limits.validate()?;
        Ok(limits)
    }
    /// Conservative acceptance: credit/UDP/CID limits may grow; idle/migration
    /// policy must remain identical. Clients continue using remembered limits
    /// for 0-RTT even if new handshake values are larger.
    pub fn permits_early_from(self, remembered: Self) -> Result<(), Error> {
        if self.idle_timeout != remembered.idle_timeout
            || self.disable_migration != remembered.disable_migration
            || self.numbers()[1..]
                .iter()
                .zip(&remembered.numbers()[1..])
                .any(|(new, old)| new < old)
        {
            return Err(Error::ChangedLimits);
        }
        Ok(())
    }
    pub fn stream_limits(self) -> crate::streams::Limits {
        crate::streams::Limits {
            max_data: self.max_data,
            max_streams_bidi: self.streams_bidi,
            max_streams_uni: self.streams_uni,
            stream_data_bidi_local: self.stream_bidi_local,
            stream_data_bidi_remote: self.stream_bidi_remote,
            stream_data_uni: self.stream_uni,
        }
    }
    pub fn active_connection_id_limit(self) -> u64 {
        self.active_cids
    }
    pub fn max_data(self) -> u64 {
        self.max_data
    }
    pub fn max_streams(self) -> u64 {
        self.streams_bidi + self.streams_uni
    }
    pub fn max_udp_payload(self) -> u64 {
        self.max_udp_payload
    }
}

/// Explicit opt-in for replay-tolerant requests. This only authorizes buffering;
/// the application must still restrict operations (initially HTTP/0.9 GET).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerPolicy {
    Disabled,
    BufferedReplaySafeRequests {
        max_bytes: usize,
        max_streams: usize,
    },
}
impl ServerPolicy {
    pub fn check_capacity<const BYTES: usize>(
        self,
        limits: RememberedLimits,
        slots: usize,
    ) -> Result<(), Error> {
        let Self::BufferedReplaySafeRequests {
            max_bytes,
            max_streams,
        } = self
        else {
            return Err(Error::Disabled);
        };
        let capacity = slots.checked_mul(BYTES).ok_or(Error::Capacity)?;
        if max_bytes == 0
            || max_streams == 0
            || max_bytes > capacity
            || max_streams > slots
            || limits.max_data > max_bytes as u64
            || limits.max_streams() > max_streams as u64
            || limits.stream_bidi_remote > BYTES as u64
            || limits.stream_uni > BYTES as u64
        {
            return Err(Error::Capacity);
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct ReplayEntry {
    issuer: [u8; 16],
    nonce: [u8; 12],
    expires: u64,
    occupied: bool,
}
impl ReplayEntry {
    const EMPTY: Self = Self {
        issuer: [0; 16],
        nonce: [0; 12],
        expires: 0,
        occupied: false,
    };
}
/// Caller-owned persistent storage. Reborrowing does not reset live claims.
/// Production integration must borrow it for the ticket-key lifetime and create
/// a fresh random ticket issuer/key after process restart; there is no clear API.
pub struct ReplayStorage<const N: usize> {
    epoch: Option<[u8; 16]>,
    entries: [ReplayEntry; N],
    last_time: Option<u64>,
    last_generation: Option<u64>,
    next_claim: u64,
}
impl<const N: usize> ReplayStorage<N> {
    pub const fn new() -> Self {
        Self {
            epoch: None,
            entries: [ReplayEntry::EMPTY; N],
            last_time: None,
            last_generation: None,
            next_claim: 1,
        }
    }
}
impl<const N: usize> Default for ReplayStorage<N> {
    fn default() -> Self {
        Self::new()
    }
}
/// Used only while exclusively borrowed by one freshly generated ticket key.
/// The key constructor starts its random issuer epoch; no live owner exposes a
/// reset operation. Dropping a key destroys its secret before storage is reused.
pub trait ReplayProtection {
    fn start_fresh_key_epoch(&mut self, issuer: [u8; 16]) -> Result<(), Error>;
    fn claim_authenticated(
        &mut self,
        issuer: [u8; 16],
        nonce: [u8; 12],
        expires: u64,
        now: u64,
        generation: u64,
    ) -> Result<ReplayClaim, Error>;
}
impl<const N: usize> ReplayProtection for ReplayStorage<N> {
    fn start_fresh_key_epoch(&mut self, issuer: [u8; 16]) -> Result<(), Error> {
        if N == 0 {
            return Err(Error::Capacity);
        }
        if self.epoch != Some(issuer) {
            *self = Self::new();
            self.epoch = Some(issuer);
        }
        Ok(())
    }
    fn claim_authenticated(
        &mut self,
        issuer: [u8; 16],
        nonce: [u8; 12],
        expires: u64,
        now: u64,
        generation: u64,
    ) -> Result<ReplayClaim, Error> {
        ReplayLedger::bind(issuer, self)?
            .claim_after_authentication(issuer, nonce, expires, now, generation)
    }
}

pub struct ReplayLedger<'a, const N: usize> {
    storage: &'a mut ReplayStorage<N>,
}
/// Only proves a committed local replay claim. It is not evidence of ticket,
/// binder, packet, or peer authentication, all of which precede claim issuance.
pub struct ReplayClaim {
    issuer: [u8; 16],
    generation: u64,
    serial: u64,
}
/// Numeric identity for private owner-to-owner handoffs. Copying this value
/// cannot create a replay claim or undo its committed ledger entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReplayBinding {
    issuer: [u8; 16],
    generation: u64,
    serial: u64,
}
impl ReplayClaim {
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub(crate) fn owner_binding(&self) -> ReplayBinding {
        ReplayBinding {
            issuer: self.issuer,
            generation: self.generation,
            serial: self.serial,
        }
    }
}
impl<'a, const N: usize> ReplayLedger<'a, N> {
    pub fn bind(epoch: [u8; 16], storage: &'a mut ReplayStorage<N>) -> Result<Self, Error> {
        if N == 0 {
            return Err(Error::Capacity);
        }
        match storage.epoch {
            Some(previous) if previous != epoch => return Err(Error::EpochMismatch),
            None => storage.epoch = Some(epoch),
            _ => {}
        }
        Ok(Self { storage })
    }
    /// Caller has already verified ticket AEAD, binder, expiry, origin/trust,
    /// remembered limits and resource admission. Commit before accepting 0-RTT.
    /// Dropping the returned claim never refunds it, even if Finished fails.
    pub fn claim_after_authentication(
        &mut self,
        issuer: [u8; 16],
        nonce: [u8; 12],
        expires_ms: u64,
        now_ms: u64,
        connection_generation: u64,
    ) -> Result<ReplayClaim, Error> {
        let s = &mut self.storage;
        if s.epoch != Some(issuer) {
            return Err(Error::EpochMismatch);
        }
        if s.last_time.is_some_and(|old| now_ms < old) {
            return Err(Error::ClockRollback);
        }
        s.last_time = Some(now_ms);
        if now_ms >= expires_ms {
            return Err(Error::Expired);
        }
        if s.last_generation
            .is_some_and(|old| connection_generation <= old)
        {
            return Err(Error::StaleGeneration);
        }
        for entry in &mut s.entries {
            if entry.occupied && now_ms >= entry.expires {
                *entry = ReplayEntry::EMPTY;
            }
        }
        if s.entries
            .iter()
            .any(|e| e.occupied && e.issuer == issuer && e.nonce == nonce)
        {
            return Err(Error::Replay);
        }
        let next = s.next_claim.checked_add(1).ok_or(Error::Exhausted)?;
        let entry = s
            .entries
            .iter_mut()
            .find(|e| !e.occupied)
            .ok_or(Error::Capacity)?;
        *entry = ReplayEntry {
            issuer,
            nonce,
            expires: expires_ms,
            occupied: true,
        };
        let serial = s.next_claim;
        s.next_claim = next;
        s.last_generation = Some(connection_generation);
        Ok(ReplayClaim {
            issuer,
            generation: connection_generation,
            serial,
        })
    }
}

// RESET final size has the same high-water/final-size effect as an empty FIN
// at that offset, but no payload bytes or application FIN are released.
struct StreamEffect<'a> {
    id: u64,
    offset: u64,
    fin: bool,
    data: &'a [u8],
}
fn stream_effect(frame: crate::packet::Frame<'_>) -> Result<Option<StreamEffect<'_>>, Error> {
    use crate::packet::Frame;
    let effect = match frame {
        Frame::Stream {
            id,
            offset,
            fin,
            data,
        } => StreamEffect {
            id,
            offset,
            fin,
            data,
        },
        Frame::ResetStream { id, final_size, .. } => StreamEffect {
            id,
            offset: final_size,
            fin: true,
            data: &[],
        },
        Frame::StopSending { id, .. } | Frame::MaxStreamData { id, .. } => {
            if id & 3 != 0 {
                return Err(Error::StreamId);
            }
            StreamEffect {
                id,
                offset: 0,
                fin: false,
                data: &[],
            }
        }
        Frame::StreamDataBlocked { id, .. } => StreamEffect {
            id,
            offset: 0,
            fin: false,
            data: &[],
        },
        _ => return Ok(None),
    };
    Ok(Some(effect))
}
fn packet_admission_error(error: crate::packet::Error) -> Error {
    match error {
        crate::packet::Error::LimitExceeded(_) => Error::Capacity,
        error => Error::Packet(error),
    }
}
fn early_packet_frames(payload: &[u8]) -> Result<crate::packet::FrameIter<'_>, Error> {
    crate::packet::FrameIter::new(
        payload,
        crate::packet::EncryptionLevel::ZeroRtt,
        crate::packet::ParseLimits {
            max_frames: 128,
            ..crate::packet::ParseLimits::default()
        },
    )
    .map_err(packet_admission_error)
}

/// Caller-owned byte/coverage storage. Its complete memory cost is bounded by
/// two BYTES arrays plus metadata; there is no allocator or self-reference.
pub struct QuarantineSlot<const BYTES: usize> {
    id: Option<u64>,
    highest: u64,
    final_size: Option<u64>,
    fin_pending: bool,
    marker_pending: bool,
    opened_in_table: bool,
    released_highest: u64,
    fin_released: bool,
    reset: bool,
    bytes: [u8; BYTES],
    present: [u8; BYTES],
}
impl<const BYTES: usize> QuarantineSlot<BYTES> {
    pub const EMPTY: Self = Self {
        id: None,
        highest: 0,
        final_size: None,
        fin_pending: false,
        marker_pending: false,
        opened_in_table: false,
        released_highest: 0,
        fin_released: false,
        reset: false,
        bytes: [0; BYTES],
        present: [0; BYTES],
    };
    fn clear(&mut self) {
        self.bytes.zeroize();
        self.present.fill(0);
        self.id = None;
        self.highest = 0;
        self.final_size = None;
        self.fin_pending = false;
        self.marker_pending = false;
        self.opened_in_table = false;
        self.released_highest = 0;
        self.fin_released = false;
        self.reset = false;
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Holding,
    Finished,
    Rejected,
}
/// A checked descriptor for one contiguous buffered range. It can be completed
/// only once and only in this connection/claim/revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseTicket {
    issuer: [u8; 16],
    generation: u64,
    claim: u64,
    revision: u64,
    slot: usize,
    offset: usize,
    len: usize,
    fin: bool,
}
impl ReleaseTicket {
    pub const fn generation(self) -> u64 {
        self.generation
    }
    pub const fn revision(self) -> u64 {
        self.revision
    }
}
pub struct ReleaseView<'a> {
    pub ticket: ReleaseTicket,
    pub stream_id: u64,
    pub offset: u64,
    pub bytes: &'a [u8],
    pub fin: bool,
}
pub struct Quarantine<'a, const BYTES: usize> {
    slots: &'a mut [QuarantineSlot<BYTES>],
    limits: RememberedLimits,
    issuer: [u8; 16],
    generation: u64,
    claim: u64,
    revision: u64,
    charged: u64,
    phase: Phase,
}
impl<'a, const BYTES: usize> Quarantine<'a, BYTES> {
    /// All remembered receive credits are backed before TLS advertises early
    /// acceptance. Consume the already-committed replay claim into this owner.
    pub fn new(
        policy: ServerPolicy,
        limits: RememberedLimits,
        claim: ReplayClaim,
        slots: &'a mut [QuarantineSlot<BYTES>],
    ) -> Result<Self, Error> {
        policy.check_capacity::<BYTES>(limits, slots.len())?;
        for slot in slots.iter_mut() {
            slot.clear();
        }
        Ok(Self {
            slots,
            limits,
            issuer: claim.issuer,
            generation: claim.generation,
            claim: claim.serial,
            revision: 0,
            charged: 0,
            phase: Phase::Holding,
        })
    }
    /// The claim was consumed by `new`; this only observes its still-live
    /// generation and cannot mint a claim or revive a rejected quarantine.
    pub(crate) fn accepts_authenticated_generation(&self, generation: u64) -> bool {
        generation == self.generation && self.phase != Phase::Rejected
    }
    pub fn charged(&self) -> u64 {
        self.charged
    }
    /// Read-only whole-packet admission check. At most 128 decoded frames are
    /// examined with bounded pairwise passes; there is no storage clone. A
    /// Capacity error means valid local resource pressure: drop without ACK or
    /// mutation. StreamId/FlowControl/FinalSize/ConflictingOverlap are protocol
    /// failures, and Packet retains malformed/forbidden-frame diagnostics.
    ///
    /// Hold all other owners unchanged between this check and the sequential
    /// STREAM/RESET_STREAM commits. Also reserve deferred control capacity before any commit.
    pub fn preflight_authenticated_packet(
        &self,
        generation: u64,
        payload: &[u8],
    ) -> Result<(), Error> {
        if generation != self.generation {
            return Err(Error::StaleGeneration);
        }
        if self.phase == Phase::Rejected {
            return Err(Error::State);
        }
        // Validate even a malformed tail before considering any admission.
        for frame in early_packet_frames(payload)? {
            frame.map_err(packet_admission_error)?;
        }
        let mut unique_new = 0;
        let mut charged = self.charged;
        for (index, frame) in early_packet_frames(payload)?.enumerate() {
            let Some(StreamEffect {
                id,
                offset,
                fin,
                data,
            }) = stream_effect(frame.map_err(packet_admission_error)?)?
            else {
                continue;
            };
            if id > MAX || id & 1 != 0 {
                return Err(Error::StreamId);
            }
            let uni = id & 2 != 0;
            if id / 4 + 1
                > if uni {
                    self.limits.streams_uni
                } else {
                    self.limits.streams_bidi
                }
            {
                return Err(Error::FlowControl);
            }
            let end = offset
                .checked_add(data.len() as u64)
                .ok_or(Error::FlowControl)?;
            let limit = if uni {
                self.limits.stream_uni
            } else {
                self.limits.stream_bidi_remote
            };
            if end > limit || end > BYTES as u64 {
                return Err(Error::FlowControl);
            }
            let slot = self.slots.iter().find(|slot| slot.id == Some(id));
            let old_highest = slot.map_or(0, |slot| slot.highest);
            if slot.is_some_and(|slot| {
                slot.final_size
                    .is_some_and(|size| end > size || fin && end != size)
            }) || fin && end < old_highest
            {
                return Err(Error::FinalSize);
            }
            let start = usize::try_from(offset).map_err(|_| Error::FlowControl)?;
            if slot.is_some_and(|slot| {
                data.iter()
                    .enumerate()
                    .any(|(i, byte)| slot.present[start + i] == 1 && slot.bytes[start + i] != *byte)
            }) {
                return Err(Error::ConflictingOverlap);
            }
            let mut first = true;
            let mut highest = end.max(old_highest);
            for (other_index, other) in early_packet_frames(payload)?.enumerate() {
                let Some(StreamEffect {
                    id: other_id,
                    offset: other_offset,
                    fin: other_fin,
                    data: other_data,
                }) = stream_effect(other.map_err(packet_admission_error)?)?
                else {
                    continue;
                };
                if other_id != id || other_index == index {
                    continue;
                }
                let other_end = other_offset
                    .checked_add(other_data.len() as u64)
                    .ok_or(Error::FlowControl)?;
                first &= other_index > index;
                highest = highest.max(other_end);
                if fin && (other_end > end || other_fin && other_end != end)
                    || other_fin && end > other_end
                {
                    return Err(Error::FinalSize);
                }
                let overlap_start = offset.max(other_offset);
                let overlap_end = end.min(other_end);
                for byte_offset in overlap_start..overlap_end {
                    let released = slot
                        .is_some_and(|slot| slot.reset || slot.present[byte_offset as usize] == 2);
                    if !released
                        && data[(byte_offset - offset) as usize]
                            != other_data[(byte_offset - other_offset) as usize]
                    {
                        return Err(Error::ConflictingOverlap);
                    }
                }
            }
            if first {
                unique_new += usize::from(slot.is_none());
                charged = charged
                    .checked_add(highest - old_highest)
                    .ok_or(Error::FlowControl)?;
                if charged > self.limits.max_data {
                    return Err(Error::FlowControl);
                }
            }
        }
        if unique_new > self.slots.iter().filter(|slot| slot.id.is_none()).count() {
            return Err(Error::Capacity);
        }
        Ok(())
    }
    /// Supply only authenticated and whole-packet-validated client STREAM data.
    /// Authentication failure must never call this. Every local error is atomic.
    pub fn buffer_authenticated_stream(
        &mut self,
        generation: u64,
        stream_id: u64,
        offset: u64,
        bytes: &[u8],
        fin: bool,
    ) -> Result<(), Error> {
        if generation != self.generation {
            return Err(Error::StaleGeneration);
        }
        if self.phase == Phase::Rejected {
            return Err(Error::State);
        }
        if stream_id > MAX || stream_id & 1 != 0 {
            return Err(Error::StreamId);
        }
        let uni = stream_id & 2 != 0;
        let count = stream_id / 4 + 1;
        if count
            > if uni {
                self.limits.streams_uni
            } else {
                self.limits.streams_bidi
            }
        {
            return Err(Error::FlowControl);
        }
        let limit = if uni {
            self.limits.stream_uni
        } else {
            self.limits.stream_bidi_remote
        };
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or(Error::FlowControl)?;
        if end > limit || end > BYTES as u64 {
            return Err(Error::FlowControl);
        }
        let index = self
            .slots
            .iter()
            .position(|s| s.id == Some(stream_id))
            .or_else(|| self.slots.iter().position(|s| s.id.is_none()))
            .ok_or(Error::Capacity)?;
        let slot = &self.slots[index];
        if slot
            .final_size
            .is_some_and(|size| end > size || fin && end != size)
            || fin && end < slot.highest
        {
            return Err(Error::FinalSize);
        }
        if slot.reset {
            return Ok(());
        }
        let start = usize::try_from(offset).map_err(|_| Error::FlowControl)?;
        if bytes
            .iter()
            .enumerate()
            .any(|(i, b)| slot.present[start + i] == 1 && slot.bytes[start + i] != *b)
        {
            return Err(Error::ConflictingOverlap);
        }
        let charged = self
            .charged
            .checked_add(end.saturating_sub(slot.highest))
            .ok_or(Error::FlowControl)?;
        if charged > self.limits.max_data {
            return Err(Error::FlowControl);
        }
        let slot = &mut self.slots[index];
        slot.id = Some(stream_id);
        slot.highest = slot.highest.max(end);
        for (i, b) in bytes.iter().enumerate() {
            if slot.present[start + i] != 2 {
                slot.bytes[start + i] = *b;
                slot.present[start + i] = 1;
            }
        }
        if bytes.is_empty() && (!slot.opened_in_table || end > slot.released_highest) {
            slot.marker_pending = true;
        }
        if fin {
            slot.final_size = Some(end);
            slot.fin_pending = !slot.fin_released;
        }
        self.charged = charged;
        Ok(())
    }
    /// Admit RESET_STREAM against remembered credit before marking its early
    /// packet seen. Its final size charges the same receive high-water ledger as
    /// STREAM, while all withheld bytes are wiped. The deferred control store
    /// separately retains its actual error code for the post-Finished table
    /// transition. Later valid STREAM frames cannot revive discarded data.
    pub fn buffer_authenticated_reset(
        &mut self,
        generation: u64,
        stream_id: u64,
        final_size: u64,
    ) -> Result<(), Error> {
        self.buffer_authenticated_stream(generation, stream_id, final_size, &[], true)?;
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| slot.id == Some(stream_id))
            .ok_or(Error::State)?;
        slot.reset = true;
        slot.bytes.zeroize();
        slot.present.fill(2);
        slot.fin_pending = false;
        slot.marker_pending = false;
        Ok(())
    }
    /// Reserve remembered stream identity/credit for a deferred control before
    /// admission. Non-stream controls have no quarantine accounting effect.
    /// MAX_STREAM_DATA grants our sending credit; its numeric maximum does not
    /// consume this receive ledger. The authenticated referenced stream does.
    pub fn buffer_authenticated_control(
        &mut self,
        generation: u64,
        frame: crate::packet::Frame<'_>,
    ) -> Result<(), Error> {
        if generation != self.generation {
            return Err(Error::StaleGeneration);
        }
        if self.phase == Phase::Rejected {
            return Err(Error::State);
        }
        if matches!(frame, crate::packet::Frame::Stream { .. }) {
            return Ok(());
        }
        if let crate::packet::Frame::ResetStream { id, final_size, .. } = frame {
            return self.buffer_authenticated_reset(generation, id, final_size);
        }
        if let Some(StreamEffect {
            id,
            offset,
            fin,
            data,
        }) = stream_effect(frame)?
        {
            self.buffer_authenticated_stream(generation, id, offset, data, fin)?;
        }
        Ok(())
    }
    /// Only the real TLS owner may report its verified client Finished here.
    /// Integration must execute the distinct typed Finished/early-release gate.
    pub fn finish_after_verified_handshake(&mut self, generation: u64) -> Result<(), Error> {
        if generation != self.generation {
            return Err(Error::StaleGeneration);
        }
        if self.phase != Phase::Holding {
            return Err(Error::State);
        }
        self.phase = Phase::Finished;
        Ok(())
    }
    pub fn reject(&mut self, generation: u64) -> Result<(), Error> {
        if generation != self.generation {
            return Err(Error::StaleGeneration);
        }
        if self.phase != Phase::Holding {
            return Err(Error::State);
        }
        for slot in self.slots.iter_mut() {
            slot.clear();
        }
        self.phase = Phase::Rejected;
        Ok(())
    }
    pub fn next_release(&self) -> Result<Option<ReleaseView<'_>>, Error> {
        if self.phase != Phase::Finished {
            return Err(Error::State);
        }
        for (index, slot) in self.slots.iter().enumerate() {
            let Some(id) = slot.id else { continue };
            let range = if let Some(start) = slot.present.iter().position(|p| *p == 1) {
                let len = slot.present[start..]
                    .iter()
                    .take_while(|p| **p == 1)
                    .count();
                Some((
                    start,
                    len,
                    slot.fin_pending && slot.final_size == Some((start + len) as u64),
                ))
            } else if slot.fin_pending || slot.marker_pending {
                Some((slot.highest as usize, 0, slot.fin_pending))
            } else {
                None
            };
            if let Some((offset, len, fin)) = range {
                return Ok(Some(ReleaseView {
                    ticket: ReleaseTicket {
                        issuer: self.issuer,
                        generation: self.generation,
                        claim: self.claim,
                        revision: self.revision,
                        slot: index,
                        offset,
                        len,
                        fin,
                    },
                    stream_id: id,
                    offset: offset as u64,
                    bytes: &slot.bytes[offset..offset + len],
                    fin,
                }));
            }
        }
        Ok(None)
    }
    /// Complete only after the ordinary authenticated stream table accepts the
    /// range. Backpressure leaves bytes owned here. No ACK/loss event is implied.
    pub fn complete_release(&mut self, ticket: ReleaseTicket) -> Result<(), Error> {
        let expected = self.next_release()?.ok_or(Error::StaleRelease)?.ticket;
        if expected != ticket {
            return Err(Error::StaleRelease);
        }
        let revision = self.revision.checked_add(1).ok_or(Error::Exhausted)?;
        let slot = &mut self.slots[ticket.slot];
        slot.bytes[ticket.offset..ticket.offset + ticket.len].zeroize();
        slot.present[ticket.offset..ticket.offset + ticket.len].fill(2);
        slot.opened_in_table = true;
        slot.released_highest = slot
            .released_highest
            .max((ticket.offset + ticket.len) as u64);
        if ticket.fin {
            slot.fin_pending = false;
            slot.fin_released = true;
        }
        if (ticket.offset + ticket.len) as u64 >= slot.highest {
            slot.marker_pending = false;
        }
        self.revision = revision;
        Ok(())
    }
}
impl<const BYTES: usize> Drop for Quarantine<'_, BYTES> {
    fn drop(&mut self) {
        for slot in self.slots.iter_mut() {
            slot.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Syntactically valid server parameters, including required connection IDs.
    const PARAMS: &[u8] = &[
        0, 0, 15, 0, 4, 1, 16, 5, 1, 8, 6, 1, 8, 7, 1, 8, 8, 1, 1, 9, 1, 1,
    ];
    const POLICY: ServerPolicy = ServerPolicy::BufferedReplaySafeRequests {
        max_bytes: 16,
        max_streams: 2,
    };
    fn limits() -> RememberedLimits {
        RememberedLimits::from_authenticated_server_parameters(PARAMS).unwrap()
    }
    fn claim<const N: usize>(storage: &mut ReplayStorage<N>, generation: u64) -> ReplayClaim {
        ReplayLedger::bind([1; 16], storage)
            .unwrap()
            .claim_after_authentication([1; 16], [2; 12], 1000, 10, generation)
            .unwrap()
    }
    #[test]
    fn remembered_parameters_roundtrip_and_forbidden_fields_are_not_restored() {
        let expected = limits();
        assert_eq!(RememberedLimits::decode(&expected.encode()), Ok(expected));
        // Changed CIDs and ACK-delay settings do not become remembered values.
        let mut changed = [0; 64];
        let extra = [10, 1, 4, 11, 1, 40, 16, 1, 99];
        changed[..PARAMS.len()].copy_from_slice(PARAMS);
        changed[PARAMS.len()..PARAMS.len() + extra.len()].copy_from_slice(&extra);
        assert_eq!(
            RememberedLimits::from_authenticated_server_parameters(
                &changed[..PARAMS.len() + extra.len()]
            ),
            Ok(expected)
        );
        let mut reordered = [0; PARAMS.len()];
        let rest = PARAMS.len() - 4;
        reordered[..rest].copy_from_slice(&PARAMS[4..]);
        reordered[rest..].copy_from_slice(&PARAMS[..4]);
        assert_eq!(
            RememberedLimits::from_authenticated_server_parameters(&reordered),
            Ok(expected)
        );
        for n in 0..REMEMBERED_BYTES {
            assert_eq!(
                RememberedLimits::decode(&expected.encode()[..n]),
                Err(Error::InvalidLimits)
            );
        }
        let mut bad = expected.encode();
        bad[72] = 2;
        assert_eq!(RememberedLimits::decode(&bad), Err(Error::InvalidLimits));
    }
    #[test]
    fn all_relevant_limit_reductions_and_changed_policies_reject() {
        let old = RememberedLimits {
            idle_timeout: 50,
            max_udp_payload: 1400,
            max_data: 16,
            stream_bidi_local: 8,
            stream_bidi_remote: 8,
            stream_uni: 8,
            streams_bidi: 1,
            streams_uni: 1,
            active_cids: 4,
            disable_migration: true,
        };
        for index in 1..9 {
            let mut bytes = old.encode();
            let n = u64::from_be_bytes(bytes[index * 8..index * 8 + 8].try_into().unwrap());
            bytes[index * 8..index * 8 + 8].copy_from_slice(&(n - 1).to_be_bytes());
            let reduced = RememberedLimits::decode(&bytes).unwrap();
            assert_eq!(reduced.permits_early_from(old), Err(Error::ChangedLimits));
        }
        assert_eq!(
            RememberedLimits {
                idle_timeout: 51,
                ..old
            }
            .permits_early_from(old),
            Err(Error::ChangedLimits)
        );
        assert_eq!(
            RememberedLimits {
                disable_migration: false,
                ..old
            }
            .permits_early_from(old),
            Err(Error::ChangedLimits)
        );
        assert_eq!(
            RememberedLimits {
                max_data: 32,
                streams_bidi: 2,
                ..old
            }
            .permits_early_from(old),
            Ok(())
        );
    }
    #[test]
    fn policy_requires_explicit_opt_in_and_backed_credit() {
        assert_eq!(
            ServerPolicy::Disabled.check_capacity::<8>(limits(), 2),
            Err(Error::Disabled)
        );
        assert_eq!(POLICY.check_capacity::<8>(limits(), 2), Ok(()));
        assert_eq!(
            POLICY.check_capacity::<8>(limits(), 1),
            Err(Error::Capacity)
        );
        assert_eq!(
            POLICY.check_capacity::<4>(limits(), 2),
            Err(Error::Capacity)
        );
        assert_eq!(
            POLICY.check_capacity::<8>(
                RememberedLimits {
                    max_data: 17,
                    ..limits()
                },
                2
            ),
            Err(Error::Capacity)
        );
    }
    #[test]
    fn replay_claims_survive_reborrow_drop_and_capacity_pressure() {
        let mut storage = ReplayStorage::<1>::new();
        {
            let mut ledger = ReplayLedger::bind([1; 16], &mut storage).unwrap();
            let _burned = ledger
                .claim_after_authentication([1; 16], [2; 12], 100, 10, 1)
                .unwrap();
        }
        let mut ledger = ReplayLedger::bind([1; 16], &mut storage).unwrap();
        assert!(matches!(
            ledger.claim_after_authentication([1; 16], [2; 12], 100, 11, 2),
            Err(Error::Replay)
        ));
        assert!(matches!(
            ledger.claim_after_authentication([1; 16], [3; 12], 101, 12, 2),
            Err(Error::Capacity)
        ));
        assert!(
            ledger
                .claim_after_authentication([1; 16], [3; 12], 101, 100, 2)
                .is_ok()
        );
        assert!(matches!(
            ledger.claim_after_authentication([1; 16], [4; 12], 200, 100, 2),
            Err(Error::StaleGeneration)
        ));
        assert!(matches!(
            ReplayLedger::bind([9; 16], &mut storage),
            Err(Error::EpochMismatch)
        ));
    }
    #[test]
    fn replay_expiry_clock_and_identifier_exhaustion_fail_closed() {
        let mut storage = ReplayStorage::<2>::new();
        let mut ledger = ReplayLedger::bind([1; 16], &mut storage).unwrap();
        assert!(matches!(
            ledger.claim_after_authentication([1; 16], [2; 12], 10, 10, 1),
            Err(Error::Expired)
        ));
        assert!(matches!(
            ledger.claim_after_authentication([1; 16], [2; 12], 100, 9, 1),
            Err(Error::ClockRollback)
        ));
        assert!(matches!(
            ledger.claim_after_authentication([2; 16], [2; 12], 100, 11, 1),
            Err(Error::EpochMismatch)
        ));
        ledger.storage.next_claim = u64::MAX;
        assert!(matches!(
            ledger.claim_after_authentication([1; 16], [2; 12], 100, 11, 1),
            Err(Error::Exhausted)
        ));
        assert!(!ledger.storage.entries.iter().any(|e| e.occupied));
    }
    #[test]
    fn authenticated_bytes_are_quarantined_until_finished_then_release_once() {
        let mut replay = ReplayStorage::<1>::new();
        let mut slots = [QuarantineSlot::<8>::EMPTY, QuarantineSlot::EMPTY];
        let mut q = Quarantine::new(POLICY, limits(), claim(&mut replay, 7), &mut slots).unwrap();
        q.buffer_authenticated_stream(7, 0, 3, b"def", true)
            .unwrap();
        q.buffer_authenticated_stream(7, 0, 0, b"abc", false)
            .unwrap();
        q.buffer_authenticated_stream(7, 0, 0, b"abc", false)
            .unwrap();
        assert_eq!(q.charged(), 6);
        assert!(matches!(q.next_release(), Err(Error::State)));
        assert_eq!(
            q.finish_after_verified_handshake(8),
            Err(Error::StaleGeneration)
        );
        q.finish_after_verified_handshake(7).unwrap();
        let view = q.next_release().unwrap().unwrap();
        assert_eq!(
            (view.stream_id, view.offset, view.bytes, view.fin),
            (0, 0, &b"abcdef"[..], true)
        );
        let ticket = view.ticket;
        q.complete_release(ticket).unwrap();
        assert!(q.next_release().unwrap().is_none());
        assert_eq!(q.complete_release(ticket), Err(Error::StaleRelease));
        assert_eq!(
            q.buffer_authenticated_stream(7, 0, 6, b"x", false),
            Err(Error::FinalSize)
        );
    }
    #[test]
    fn late_early_ranges_after_finished_preserve_history_and_do_not_release_twice() {
        let mut replay = ReplayStorage::<1>::new();
        let mut slots = [QuarantineSlot::<8>::EMPTY, QuarantineSlot::EMPTY];
        let mut q = Quarantine::new(POLICY, limits(), claim(&mut replay, 1), &mut slots).unwrap();
        q.buffer_authenticated_stream(1, 0, 0, b"abc", false)
            .unwrap();
        q.finish_after_verified_handshake(1).unwrap();
        let first = q.next_release().unwrap().unwrap().ticket;
        q.complete_release(first).unwrap();
        q.buffer_authenticated_stream(1, 0, 0, b"abc", false)
            .unwrap();
        assert_eq!(q.charged(), 3);
        assert!(q.next_release().unwrap().is_none());
        q.buffer_authenticated_stream(1, 0, 3, b"def", true)
            .unwrap();
        let late = q.next_release().unwrap().unwrap();
        assert_eq!((late.offset, late.bytes, late.fin), (3, &b"def"[..], true));
        let second = late.ticket;
        q.complete_release(second).unwrap();
        q.buffer_authenticated_stream(1, 0, 0, b"abcdef", true)
            .unwrap();
        assert_eq!(q.charged(), 6);
        assert!(q.next_release().unwrap().is_none());
        assert_eq!(
            q.buffer_authenticated_stream(1, 0, 0, b"abcd", true),
            Err(Error::FinalSize)
        );
        assert_eq!(q.complete_release(first), Err(Error::StaleRelease));
        // Released payload is wiped; ordinary delivered-stream history handles
        // duplicate bytes while this quarantine preserves offsets/final size.
        q.buffer_authenticated_stream(1, 0, 0, b"xxxxxx", true)
            .unwrap();
        assert!(q.next_release().unwrap().is_none());
    }

    #[test]
    fn sparse_ranges_and_empty_offset_markers_survive_handoff() {
        let mut replay = ReplayStorage::<1>::new();
        let mut slots = [QuarantineSlot::<8>::EMPTY, QuarantineSlot::EMPTY];
        let mut q = Quarantine::new(POLICY, limits(), claim(&mut replay, 1), &mut slots).unwrap();
        q.buffer_authenticated_stream(1, 0, 2, b"cd", false)
            .unwrap();
        q.buffer_authenticated_stream(1, 0, 7, b"", false).unwrap();
        q.buffer_authenticated_stream(1, 2, 0, b"", true).unwrap();
        q.finish_after_verified_handshake(1).unwrap();
        let view = q.next_release().unwrap().unwrap();
        assert_eq!((view.offset, view.bytes, view.fin), (2, &b"cd"[..], false));
        let a = view.ticket;
        q.complete_release(a).unwrap();
        let view = q.next_release().unwrap().unwrap();
        assert_eq!((view.offset, view.bytes, view.fin), (7, &b""[..], false));
        let b = view.ticket;
        q.complete_release(b).unwrap();
        let view = q.next_release().unwrap().unwrap();
        assert_eq!(
            (view.stream_id, view.offset, view.bytes, view.fin),
            (2, 0, &b""[..], true)
        );
        let c = view.ticket;
        q.complete_release(c).unwrap();
        assert!(q.next_release().unwrap().is_none());
    }
    #[test]
    fn failed_overlap_final_size_and_flow_updates_leave_state_unchanged() {
        let mut replay = ReplayStorage::<1>::new();
        let mut slots = [QuarantineSlot::<8>::EMPTY, QuarantineSlot::EMPTY];
        let mut q = Quarantine::new(POLICY, limits(), claim(&mut replay, 1), &mut slots).unwrap();
        q.buffer_authenticated_stream(1, 0, 0, b"abc", false)
            .unwrap();
        for (id, offset, bytes, fin, error) in [
            (0, 1, &b"xy"[..], false, Error::ConflictingOverlap),
            (0, 1, &b"b"[..], true, Error::FinalSize),
            (0, 8, &b"x"[..], false, Error::FlowControl),
            (4, 0, &b"x"[..], false, Error::FlowControl),
            (1, 0, &b"x"[..], false, Error::StreamId),
        ] {
            assert_eq!(
                q.buffer_authenticated_stream(1, id, offset, bytes, fin),
                Err(error)
            );
            assert_eq!(q.charged(), 3);
        }
        q.finish_after_verified_handshake(1).unwrap();
        assert_eq!(q.next_release().unwrap().unwrap().bytes, b"abc");
    }
    #[test]
    fn rejection_and_drop_wipe_bytes_without_refunding_replay() {
        let mut replay = ReplayStorage::<1>::new();
        let mut slots = [QuarantineSlot::<8>::EMPTY, QuarantineSlot::EMPTY];
        {
            let mut q =
                Quarantine::new(POLICY, limits(), claim(&mut replay, 1), &mut slots).unwrap();
            q.buffer_authenticated_stream(1, 0, 0, b"secret", true)
                .unwrap();
            q.reject(1).unwrap();
            assert!(matches!(q.next_release(), Err(Error::State)));
            assert_eq!(q.finish_after_verified_handshake(1), Err(Error::State));
        }
        assert!(
            slots
                .iter()
                .all(|s| s.bytes == [0; 8] && s.present == [0; 8])
        );
        let mut ledger = ReplayLedger::bind([1; 16], &mut replay).unwrap();
        assert!(matches!(
            ledger.claim_after_authentication([1; 16], [2; 12], 1000, 11, 2),
            Err(Error::Replay)
        ));
    }
    #[test]
    fn restarted_key_epoch_cannot_complete_old_release_even_if_caller_reuses_generation() {
        let mut first_storage = ReplayStorage::<1>::new();
        let mut second_storage = ReplayStorage::<1>::new();
        let a_claim = claim(&mut first_storage, 7);
        let b_claim = ReplayLedger::bind([9; 16], &mut second_storage)
            .unwrap()
            .claim_after_authentication([9; 16], [2; 12], 1000, 10, 7)
            .unwrap();
        let mut a_slots = [QuarantineSlot::<8>::EMPTY, QuarantineSlot::EMPTY];
        let mut b_slots = [QuarantineSlot::<8>::EMPTY, QuarantineSlot::EMPTY];
        let mut a = Quarantine::new(POLICY, limits(), a_claim, &mut a_slots).unwrap();
        let mut b = Quarantine::new(POLICY, limits(), b_claim, &mut b_slots).unwrap();
        a.buffer_authenticated_stream(7, 0, 0, b"a", true).unwrap();
        b.buffer_authenticated_stream(7, 0, 0, b"b", true).unwrap();
        a.finish_after_verified_handshake(7).unwrap();
        b.finish_after_verified_handshake(7).unwrap();
        assert_eq!(
            b.complete_release(a.next_release().unwrap().unwrap().ticket),
            Err(Error::StaleRelease)
        );
    }

    #[test]
    fn foreign_release_descriptor_and_generation_are_rejected() {
        let mut replay = ReplayStorage::<2>::new();
        let mut a_slots = [QuarantineSlot::<8>::EMPTY, QuarantineSlot::EMPTY];
        let mut b_slots = [QuarantineSlot::<8>::EMPTY, QuarantineSlot::EMPTY];
        let a_claim = claim(&mut replay, 1);
        let b_claim = ReplayLedger::bind([1; 16], &mut replay)
            .unwrap()
            .claim_after_authentication([1; 16], [3; 12], 1000, 10, 2)
            .unwrap();
        let mut a = Quarantine::new(POLICY, limits(), a_claim, &mut a_slots).unwrap();
        let mut b = Quarantine::new(POLICY, limits(), b_claim, &mut b_slots).unwrap();
        a.buffer_authenticated_stream(1, 0, 0, b"a", true).unwrap();
        b.buffer_authenticated_stream(2, 0, 0, b"b", true).unwrap();
        a.finish_after_verified_handshake(1).unwrap();
        b.finish_after_verified_handshake(2).unwrap();
        let ticket = a.next_release().unwrap().unwrap().ticket;
        assert_eq!(b.complete_release(ticket), Err(Error::StaleRelease));
        assert_eq!(
            b.buffer_authenticated_stream(1, 0, 0, b"x", false),
            Err(Error::StaleGeneration)
        );
    }
    #[test]
    fn packet_preflight_validates_cross_frame_high_water_final_size_and_overlap_atomically() {
        use crate::packet::{self, Frame};
        let mut replay = ReplayStorage::<1>::new();
        let mut slots = [QuarantineSlot::<8>::EMPTY, QuarantineSlot::EMPTY];
        let mut q = Quarantine::new(POLICY, limits(), claim(&mut replay, 7), &mut slots).unwrap();
        let cases = [
            (
                [
                    Frame::Stream {
                        id: 0,
                        offset: 0,
                        fin: false,
                        data: b"ab",
                    },
                    Frame::Stream {
                        id: 0,
                        offset: 1,
                        fin: false,
                        data: b"X",
                    },
                ],
                Err(Error::ConflictingOverlap),
            ),
            (
                [
                    Frame::Stream {
                        id: 0,
                        offset: 0,
                        fin: true,
                        data: b"ab",
                    },
                    Frame::Stream {
                        id: 0,
                        offset: 2,
                        fin: false,
                        data: b"c",
                    },
                ],
                Err(Error::FinalSize),
            ),
            (
                [
                    Frame::Stream {
                        id: 0,
                        offset: 0,
                        fin: true,
                        data: b"ab",
                    },
                    Frame::Stream {
                        id: 0,
                        offset: 0,
                        fin: true,
                        data: b"a",
                    },
                ],
                Err(Error::FinalSize),
            ),
            (
                [
                    Frame::Stream {
                        id: 0,
                        offset: 3,
                        fin: true,
                        data: b"def",
                    },
                    Frame::Stream {
                        id: 0,
                        offset: 0,
                        fin: false,
                        data: b"abc",
                    },
                ],
                Ok(()),
            ),
        ];
        for (frames, expected) in cases {
            let mut bytes = [0; 64];
            let mut n = 0;
            for frame in frames {
                n += packet::encode_frame(&frame, &mut bytes[n..]).unwrap();
            }
            assert_eq!(q.preflight_authenticated_packet(7, &bytes[..n]), expected);
            assert_eq!(q.charged(), 0);
            assert!(q.slots.iter().all(|s| s.id.is_none()));
            if expected.is_ok() {
                for frame in frames {
                    let Frame::Stream {
                        id,
                        offset,
                        fin,
                        data,
                    } = frame
                    else {
                        unreachable!()
                    };
                    q.buffer_authenticated_stream(7, id, offset, data, fin)
                        .unwrap();
                }
            }
        }
        assert_eq!(q.charged(), 6);
        let mut bytes = [0; 64];
        let n = packet::encode_frame(
            &Frame::Stream {
                id: 0,
                offset: 0,
                fin: true,
                data: b"abcdef",
            },
            &mut bytes,
        )
        .unwrap();
        q.preflight_authenticated_packet(7, &bytes[..n]).unwrap();
        q.finish_after_verified_handshake(7).unwrap();
        let release = q.next_release().unwrap().unwrap().ticket;
        q.complete_release(release).unwrap();
        let n = packet::encode_frame(
            &Frame::Stream {
                id: 0,
                offset: 0,
                fin: true,
                data: b"xxxxxx",
            },
            &mut bytes,
        )
        .unwrap();
        q.preflight_authenticated_packet(7, &bytes[..n]).unwrap();
        assert_eq!(q.charged(), 6);
    }
    #[test]
    fn packet_preflight_bounds_frames_and_preserves_protocol_error_classification() {
        let mut replay = ReplayStorage::<1>::new();
        let mut slots = [QuarantineSlot::<8>::EMPTY, QuarantineSlot::EMPTY];
        let q = Quarantine::new(POLICY, limits(), claim(&mut replay, 7), &mut slots).unwrap();
        assert_eq!(
            q.preflight_authenticated_packet(7, &[1; 129]),
            Err(Error::Capacity)
        );
        assert!(matches!(
            q.preflight_authenticated_packet(7, &[1, 0x1e]),
            Err(Error::Packet(_))
        ));
        assert_eq!(
            q.preflight_authenticated_packet(8, &[1]),
            Err(Error::StaleGeneration)
        );
        let mut bytes = [0; 64];
        let n = crate::packet::encode_frame(
            &crate::packet::Frame::Stream {
                id: 0,
                offset: 8,
                fin: false,
                data: b"x",
            },
            &mut bytes,
        )
        .unwrap();
        assert_eq!(
            q.preflight_authenticated_packet(7, &bytes[..n]),
            Err(Error::FlowControl)
        );
        assert_eq!(q.charged(), 0);
    }
    #[test]
    fn packet_preflight_charges_each_stream_maximum_once_then_all_commits_succeed() {
        use crate::packet::{self, Frame};
        let mut replay = ReplayStorage::<1>::new();
        let mut slots = [QuarantineSlot::<8>::EMPTY, QuarantineSlot::EMPTY];
        let mut q = Quarantine::new(POLICY, limits(), claim(&mut replay, 7), &mut slots).unwrap();
        let frames = [
            Frame::Stream {
                id: 0,
                offset: 4,
                fin: true,
                data: b"efgh",
            },
            Frame::Stream {
                id: 0,
                offset: 0,
                fin: false,
                data: b"abcdef",
            },
            Frame::Stream {
                id: 2,
                offset: 0,
                fin: true,
                data: b"12345678",
            },
            Frame::Stream {
                id: 0,
                offset: 0,
                fin: true,
                data: b"abcdefgh",
            },
        ];
        let mut bytes = [0; 128];
        let mut n = 0;
        for frame in frames {
            n += packet::encode_frame(&frame, &mut bytes[n..]).unwrap();
        }
        q.preflight_authenticated_packet(7, &bytes[..n]).unwrap();
        assert_eq!(q.charged(), 0);
        for frame in frames {
            let Frame::Stream {
                id,
                offset,
                fin,
                data,
            } = frame
            else {
                unreachable!()
            };
            q.buffer_authenticated_stream(7, id, offset, data, fin)
                .unwrap();
        }
        assert_eq!(q.charged(), 16);
        q.preflight_authenticated_packet(7, &bytes[..n]).unwrap();
    }
    #[test]
    fn successful_pair_preflight_guarantees_both_sequential_stream_commits() {
        use crate::packet::{self, Frame};
        let mut admitted = 0;
        // Exhaustive bounded pairs vary both offsets/lengths/FINs, overlap
        // contents and same-versus-distinct streams. This checks the admission
        // implication against the actual mutating implementation.
        for encoded_case in 0usize..(9 * 9 * 4 * 4 * 2 * 2 * 2 * 2) {
            let mut case = encoded_case;
            let mut take = |radix| {
                let value = case % radix;
                case /= radix;
                value
            };
            let offsets = [take(9), take(9)];
            let lengths = [take(4), take(4)];
            let fins = [take(2) != 0, take(2) != 0];
            let conflict = take(2) != 0;
            let other_stream = take(2) != 0;
            let mut data = [[0; 4]; 2];
            for which in 0..2 {
                for (i, byte) in data[which].iter_mut().take(lengths[which]).enumerate() {
                    *byte = b'a' + (offsets[which] + i) as u8;
                }
            }
            if conflict {
                data[1][0] ^= 1;
            }
            let frames = [
                Frame::Stream {
                    id: 0,
                    offset: offsets[0] as u64,
                    fin: fins[0],
                    data: &data[0][..lengths[0]],
                },
                Frame::Stream {
                    id: if other_stream { 2 } else { 0 },
                    offset: offsets[1] as u64,
                    fin: fins[1],
                    data: &data[1][..lengths[1]],
                },
            ];
            let mut payload = [0; 32];
            let mut n = 0;
            for frame in frames {
                n += packet::encode_frame(&frame, &mut payload[n..]).unwrap();
            }
            let mut replay = ReplayStorage::<1>::new();
            let mut slots = [QuarantineSlot::<8>::EMPTY, QuarantineSlot::EMPTY];
            let mut q =
                Quarantine::new(POLICY, limits(), claim(&mut replay, 7), &mut slots).unwrap();
            let result = q.preflight_authenticated_packet(7, &payload[..n]);
            assert_eq!(q.charged(), 0);
            assert!(q.slots.iter().all(|slot| slot.id.is_none()));
            if result.is_ok() {
                admitted += 1;
                for frame in frames {
                    let Frame::Stream {
                        id,
                        offset,
                        fin,
                        data,
                    } = frame
                    else {
                        unreachable!()
                    };
                    q.buffer_authenticated_stream(7, id, offset, data, fin)
                        .unwrap();
                }
            }
        }
        assert!(admitted > 1000);
    }
    #[test]
    fn reset_admission_uses_remembered_credit_and_final_size_without_releasing_withheld_data() {
        use crate::packet::{self, Frame};
        let mut replay = ReplayStorage::<1>::new();
        let mut slots = [QuarantineSlot::<8>::EMPTY, QuarantineSlot::EMPTY];
        let mut q = Quarantine::new(POLICY, limits(), claim(&mut replay, 7), &mut slots).unwrap();
        let mut payload = [0; 64];
        for frame in [
            Frame::ResetStream {
                id: 0,
                error_code: 1,
                final_size: 9,
            },
            Frame::ResetStream {
                id: 4,
                error_code: 2,
                final_size: 0,
            },
        ] {
            let n = packet::encode_frame(&frame, &mut payload).unwrap();
            assert_eq!(
                q.preflight_authenticated_packet(7, &payload[..n]),
                Err(Error::FlowControl)
            );
            assert_eq!(q.charged(), 0);
        }
        q.buffer_authenticated_stream(7, 0, 0, b"secret", false)
            .unwrap();
        assert_eq!(q.buffer_authenticated_reset(7, 0, 5), Err(Error::FinalSize));
        q.buffer_authenticated_reset(7, 0, 8).unwrap();
        assert_eq!(q.charged(), 8);
        assert!(q.slots[0].bytes.iter().all(|byte| *byte == 0));
        q.buffer_authenticated_stream(7, 0, 0, b"ignored!", true)
            .unwrap();
        assert!(q.slots[0].bytes.iter().all(|byte| *byte == 0));
        assert_eq!(q.buffer_authenticated_reset(7, 0, 7), Err(Error::FinalSize));
        let n = packet::encode_frame(
            &Frame::ResetStream {
                id: 0,
                error_code: 3,
                final_size: 7,
            },
            &mut payload,
        )
        .unwrap();
        assert_eq!(
            q.preflight_authenticated_packet(7, &payload[..n]),
            Err(Error::FinalSize)
        );
        q.buffer_authenticated_reset(7, 2, 8).unwrap();
        assert_eq!(q.charged(), 16);
        q.finish_after_verified_handshake(7).unwrap();
        assert!(q.next_release().unwrap().is_none());
    }
    #[test]
    fn reset_and_stream_pair_preflight_matches_real_commits_in_both_orders() {
        use crate::packet::{self, Frame};
        let mut admitted = 0;
        for final_size in 0..10 {
            for offset in 0..10 {
                for len in 0..4 {
                    for fin in [false, true] {
                        for reset_first in [false, true] {
                            let stream = Frame::Stream {
                                id: 0,
                                offset,
                                fin,
                                data: &b"abcd"[..len],
                            };
                            let reset = Frame::ResetStream {
                                id: 0,
                                error_code: 3,
                                final_size,
                            };
                            let frames = if reset_first {
                                [reset, stream]
                            } else {
                                [stream, reset]
                            };
                            let mut payload = [0; 32];
                            let mut n = 0;
                            for frame in frames {
                                n += packet::encode_frame(&frame, &mut payload[n..]).unwrap();
                            }
                            let mut replay = ReplayStorage::<1>::new();
                            let mut slots = [QuarantineSlot::<8>::EMPTY, QuarantineSlot::EMPTY];
                            let mut q = Quarantine::new(
                                POLICY,
                                limits(),
                                claim(&mut replay, 7),
                                &mut slots,
                            )
                            .unwrap();
                            let result = q.preflight_authenticated_packet(7, &payload[..n]);
                            assert_eq!(q.charged(), 0);
                            if result.is_ok() {
                                admitted += 1;
                                for frame in frames {
                                    match frame {
                                        Frame::Stream {
                                            id,
                                            offset,
                                            fin,
                                            data,
                                        } => q
                                            .buffer_authenticated_stream(7, id, offset, data, fin)
                                            .unwrap(),
                                        Frame::ResetStream { id, final_size, .. } => {
                                            q.buffer_authenticated_reset(7, id, final_size).unwrap()
                                        }
                                        _ => unreachable!(),
                                    }
                                }
                                assert_eq!(q.charged(), final_size);
                                q.finish_after_verified_handshake(7).unwrap();
                                assert!(q.next_release().unwrap().is_none());
                            }
                        }
                    }
                }
            }
        }
        assert!(admitted > 100);
    }
    #[test]
    fn deferred_stream_controls_enforce_remembered_count_and_direction_before_finished() {
        use crate::packet::{self, Frame};
        let mut replay = ReplayStorage::<1>::new();
        let mut slots = [QuarantineSlot::<8>::EMPTY, QuarantineSlot::EMPTY];
        let mut q = Quarantine::new(POLICY, limits(), claim(&mut replay, 7), &mut slots).unwrap();
        let mut payload = [0; 64];
        for id in [1, 2, 3, 4, 6] {
            for frame in [
                Frame::StopSending { id, error_code: 1 },
                Frame::MaxStreamData { id, maximum: 900 },
            ] {
                let n = packet::encode_frame(&frame, &mut payload).unwrap();
                assert!(q.preflight_authenticated_packet(7, &payload[..n]).is_err());
                assert!(q.buffer_authenticated_control(7, frame).is_err());
                assert!(q.slots.iter().all(|slot| slot.id.is_none()));
            }
        }
        for id in [1, 3, 4, 6] {
            let frame = Frame::StreamDataBlocked { id, limit: 8 };
            let n = packet::encode_frame(&frame, &mut payload).unwrap();
            assert!(q.preflight_authenticated_packet(7, &payload[..n]).is_err());
            assert!(q.buffer_authenticated_control(7, frame).is_err());
        }
        for frame in [
            Frame::StopSending {
                id: 0,
                error_code: 1,
            },
            Frame::MaxStreamData {
                id: 0,
                maximum: 900,
            },
            Frame::StreamDataBlocked { id: 2, limit: 8 },
        ] {
            let n = packet::encode_frame(&frame, &mut payload).unwrap();
            q.preflight_authenticated_packet(7, &payload[..n]).unwrap();
            q.buffer_authenticated_control(7, frame).unwrap();
        }
        // Control references open remembered stream identities but do not
        // consume receive bytes; a MAX_STREAM_DATA maximum grants send credit.
        assert_eq!(q.charged(), 0);
        assert_eq!(q.slots.iter().filter(|slot| slot.id.is_some()).count(), 2);
        assert!(q.next_release().is_err());
        q.finish_after_verified_handshake(7).unwrap();
        for id in [0, 2] {
            let view = q.next_release().unwrap().unwrap();
            assert_eq!(view.stream_id, id);
            assert!(view.bytes.is_empty() && !view.fin);
            let ticket = view.ticket;
            q.complete_release(ticket).unwrap();
        }
    }
}
