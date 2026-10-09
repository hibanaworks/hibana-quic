//! Scoped synchronous recovery facets for direct role-local packet I/O.
//!
//! RECONSTRUCTED after the 2026-10-03 executor reset. Fresh compilation and
//! execution are required; historical test results do not validate these bytes.
//! Packet authentication and adapter acceptance are affine producer boundaries.
//! No borrow of the numerical owner escapes a synchronous method.
use super::Side;
use crate::{
    crypto::directional::RecoveryInstallation,
    crypto::{
        KeyKind,
        directional::{AckEligible, ApplicationKeyScope},
    },
    quic::kernel::accounting::{
        self, AccountingError, AckRange, PacketKind, PacketNumber, PacketNumberSpace, PathBudget,
        PathReservation, SendReservation, SentLedger,
    },
    quic::kernel::flights::{self, FlightId, FlightStore, Reference},
    quic::kernel::packet::{self, EncryptionLevel, Frame, FrameIter, ParseLimits},
    quic::kernel::recovery::{
        self as kernel, LossCandidate, LossDecision, NewReno, RecoveryTimer, RttEstimator,
        RttSample, SpaceTimer, TimeoutAction, TimerContext, TimerDeadline,
    },
    tls::Level,
    tls::handshake::key_source::{AuthenticatedLevelRead, FinishedAuthenticated},
};
use core::cell::RefCell;

pub const LEDGER_CAPACITY: usize = 64;
// Keep a bounded recovery lane inside the existing ledger: ordinary in-flight
// traffic must not consume every record required to publish fresh PTO packets.
// This profile backs eight two-packet PTO events without any peer feedback.
const PTO_RECORD_RESERVE: usize = 16;
pub(super) const ORDINARY_RECORD_CAPACITY: usize = LEDGER_CAPACITY - PTO_RECORD_RESERVE;
pub const FLIGHT_CAPACITY: usize = 16;
pub const REFERENCE_CAPACITY: usize = 64;
pub const ACK_CAPACITY: usize = 32;
const SPACES: [PacketNumberSpace; 3] = [
    PacketNumberSpace::Initial,
    PacketNumberSpace::Handshake,
    PacketNumberSpace::ApplicationData,
];
const LEVELS: [Level; 3] = [Level::Initial, Level::Handshake, Level::OneRtt];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Accounting(AccountingError),
    Recovery(kernel::RecoveryError),
    Packet(packet::Error),
    Flight(flights::Error),
    Ecn(crate::quic::ecn::Error),
    Binding,
    Capacity,
    UnsupportedLevel,
    UnsupportedFrame,
    CongestionLimited,
    StaleDeadline,
    PendingInitialPublication,
}
impl From<AccountingError> for Error {
    fn from(e: AccountingError) -> Self {
        Self::Accounting(e)
    }
}
impl From<kernel::RecoveryError> for Error {
    fn from(e: kernel::RecoveryError) -> Self {
        Self::Recovery(e)
    }
}
impl From<packet::Error> for Error {
    fn from(e: packet::Error) -> Self {
        Self::Packet(e)
    }
}
impl From<crate::quic::ecn::Error> for Error {
    fn from(error: crate::quic::ecn::Error) -> Self {
        Self::Ecn(error)
    }
}
impl From<flights::Error> for Error {
    fn from(e: flights::Error) -> Self {
        Self::Flight(e)
    }
}

struct Identity {
    _generation: u64,
}
pub struct Recovery<'scope, const B: usize> {
    identity: Identity,
    scope: &'scope ApplicationKeyScope,
    numbers: RefCell<Numbers<'scope, B>>,
}
pub struct Tx<'book, 'scope, const B: usize> {
    book: &'book Recovery<'scope, B>,
}
pub struct Rx<'book, 'scope, const B: usize> {
    book: &'book Recovery<'scope, B>,
}
pub struct Clock<'book, 'scope, const B: usize> {
    book: &'book Recovery<'scope, B>,
}
pub struct Publication<'book, 'scope, const B: usize> {
    book: &'book Recovery<'scope, B>,
}
/// Read-only view used by the terminal role. It never duplicates delivery,
/// publication, or confirmation authority and holds no borrow across an await.
pub struct CompletionObserver<'book, 'scope, const B: usize> {
    book: &'book Recovery<'scope, B>,
}
impl<const B: usize> CompletionObserver<'_, '_, B> {
    pub(crate) fn ecn_observation(&self) -> Result<EcnObservation, Error> {
        let n = self.book.numbers.borrow();
        n.ordinary()?;
        let accepted = SPACES.into_iter().try_fold(0u64, |total, space| {
            let sent = n.ledger.accepted_ecn_counts(space);
            total
                .checked_add(sent.ect0)
                .and_then(|n| n.checked_add(sent.ect1))
                .ok_or(AccountingError::Overflow)
        })?;
        Ok(EcnObservation {
            accepted,
            received: n.received_ecn.marked_packets()?,
            acknowledgments_sent: n.ecn_acknowledgments_sent,
            lost: n.lost_ecn_packets,
            validated: n.validated_ecn_packets,
            first_sent_at: n.first_ecn_sent_at,
            first_failure: n.first_ecn_failure,
            path_changes: n.path_changes,
            probe_period: n
                .rtt
                .pto_duration_us(
                    n.peer_parameters
                        .as_ref()
                        .map_or(25_000, |p| p.max_ack_delay_us),
                    0,
                )?
                .checked_mul(3)
                .ok_or(AccountingError::Overflow)?,
        })
    }

    pub fn idle_deadline(&self, local_timeout_ms: u64) -> Result<Option<u64>, Error> {
        let n = self.book.numbers.borrow();
        n.ordinary()?;
        let pto = n.rtt.pto_duration_us(
            n.peer_parameters
                .as_ref()
                .map_or(25_000, |p| p.max_ack_delay_us),
            0,
        )?;
        n.idle_activity
            .deadline(
                local_timeout_ms,
                n.peer_parameters.as_ref().map_or(0, |p| p.idle_timeout_ms),
                pto,
            )
            .transpose()
            .map_err(|()| AccountingError::Overflow.into())
    }
    /// Receive ACKs must reach actual adapter acceptance, and retained control
    /// flights must be acknowledged or retired before normal completion revokes
    /// publication. An accepted HANDSHAKE_DONE or ticket is not yet delivered.
    pub fn ordinary_settled(&self) -> Result<bool, Error> {
        let n = self.book.numbers.borrow();
        n.ordinary()?;
        Ok(n.pending.iter().all(|count| *count == 0)
            && n.flights.active_flights() == 0
            && (0..3).all(|index| n.retired_space[index] || !n.ack_pending[index]))
    }
    /// Clients confirm through authenticated HANDSHAKE_DONE or a validated
    /// acknowledgment of a physically accepted 1-RTT packet (RFC 9001 4.1.2);
    /// servers use the validated peer-Finished transition.
    pub fn handshake_confirmed(&self) -> Result<bool, Error> {
        let n = self.book.numbers.borrow();
        n.ordinary()?;
        Ok(n.handshake_confirmed)
    }
}
pub struct RetirementGuard<'book, 'scope, const B: usize> {
    book: &'book Recovery<'scope, B>,
    armed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub bytes_in_flight: u64,
    pub reserved_in_flight: u64,
    pub received_bytes: u64,
    pub accepted_bytes: u64,
    pub reserved_bytes: u64,
    pub available_bytes: u64,
    pub address_validated: bool,
    pub congestion_window: u64,
    pub active_flights: usize,
    pub retained_packets: usize,
    pub pto_count: u32,
    pub probe_credits: u8,
    pub revision: u64,
    pub next_packet_number: [Option<u64>; 3],
    pub handshake_confirmed: bool,
    pub history_floor: [u64; 3],
    pub pending_publications: [usize; 3],
}

#[derive(Clone, Copy)]
struct PlaintextBinding {
    len: usize,
    digest: [u8; 32],
}
impl PlaintextBinding {
    fn new(bytes: &[u8]) -> Self {
        Self {
            len: bytes.len(),
            digest: crate::crypto::plaintext_digest(bytes),
        }
    }
    fn matches(&self, bytes: &[u8]) -> bool {
        self.len == bytes.len() && self.digest == crate::crypto::plaintext_digest(bytes)
    }
}
#[derive(Clone, Copy)]
struct CryptoBinding {
    offset: u64,
    bytes: PlaintextBinding,
}
#[must_use = "settle actual adapter acceptance or explicitly cancel this reservation"]
pub struct Reservation<'book> {
    identity: &'book Identity,
    scope: &'book ApplicationKeyScope,
    send: SendReservation,
    path: PathReservation,
    flight: Option<Reference>,
    bytes: u64,
    prepared_at: u64,
    probe_epoch: Option<u64>,
    crypto: Option<CryptoBinding>,
    ack_eliciting: bool,
    padded: bool,
    key_generation: u64,
    kind: PacketKind,
    plaintext: Option<PlaintextBinding>,
}
impl<'book> Reservation<'book> {
    pub(super) fn ack_eliciting(&self) -> bool {
        self.ack_eliciting
    }

    pub fn packet(&self) -> PacketNumber {
        self.send.packet()
    }
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    pub fn scope(&self) -> &'book ApplicationKeyScope {
        self.scope
    }
    pub fn key_generation(&self) -> u64 {
        self.key_generation
    }
    pub fn kind(&self) -> PacketKind {
        self.kind
    }
    pub fn matches_crypto(&self, offset: u64, bytes: &[u8]) -> bool {
        self.crypto
            .is_some_and(|bound| bound.offset == offset && bound.bytes.matches(bytes))
    }
    pub fn matches_plaintext(&self, plaintext: &[u8]) -> Result<bool, Error> {
        if let Some(bound) = self.plaintext {
            return Ok(bound.matches(plaintext));
        }
        let level = match self.packet().space {
            PacketNumberSpace::Initial => EncryptionLevel::Initial,
            PacketNumberSpace::Handshake => EncryptionLevel::Handshake,
            _ => return Err(Error::Binding),
        };
        let mut ack_eliciting = false;
        let mut padded = false;
        let mut crypto_count = 0;
        for frame in frames(plaintext, level)? {
            let frame = frame?;
            ack_eliciting |= frame.ack_eliciting();
            match frame {
                Frame::Crypto { offset, data } => {
                    crypto_count += 1;
                    if !self.matches_crypto(offset, data) {
                        return Ok(false);
                    }
                }
                Frame::Padding { length } => padded |= length != 0,
                Frame::Ack { .. } | Frame::Ping => {}
                _ => return Ok(false),
            }
        }
        Ok(crypto_count == usize::from(self.crypto.is_some())
            && ack_eliciting == self.ack_eliciting
            && padded == self.padded)
    }
}
#[must_use]
pub struct Completion<'book> {
    reservation: Reservation<'book>,
    accepted_at: Option<u64>,
    ecn: crate::quic::ecn::Codepoint,
}
impl<'book> Completion<'book> {
    pub(super) fn from_adapter(
        reservation: Reservation<'book>,
        accepted_at: Option<u64>,
        ecn: crate::quic::ecn::Codepoint,
    ) -> Self {
        Self {
            reservation,
            accepted_at,
            ecn,
        }
    }
}
pub struct Flight<const B: usize> {
    level: Level,
    offset: u64,
    bytes: [u8; B],
    len: usize,
}
impl<const B: usize> Flight<B> {
    pub fn level(&self) -> Level {
        self.level
    }
    pub fn offset(&self) -> u64 {
        self.offset
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
pub struct AckSnapshot<'book> {
    identity: &'book Identity,
    index: usize,
    revision: u64,
    ranges: [packet::AckRange; ACK_CAPACITY],
    len: usize,
    ecn: Option<packet::EcnCounts>,
    largest_received_at: u64,
    delay_exponent: u8,
}
impl AckSnapshot<'_> {
    /// Intentional delay since the largest acknowledged packet was observed,
    /// including owned ciphertext key-wait. Never include unknown OS buffering.
    pub fn encoded_delay(&self, now: u64) -> Result<u64, Error> {
        let delay = now
            .checked_sub(self.largest_received_at)
            .ok_or(kernel::RecoveryError::TimeWentBackwards)?;
        let encoded = delay >> self.delay_exponent;
        if encoded > packet::MAX_VARINT {
            return Err(Error::Capacity);
        }
        Ok(encoded)
    }
    pub fn ecn(&self) -> Option<packet::EcnCounts> {
        self.ecn
    }
    pub fn level(&self) -> Level {
        LEVELS[self.index]
    }
    pub fn ranges(&self) -> &[packet::AckRange] {
        &self.ranges[..self.len]
    }
}
pub struct Deadline<'book> {
    identity: &'book Identity,
    revision: u64,
    deadline: TimerDeadline,
}
impl Deadline<'_> {
    pub fn at(&self) -> u64 {
        self.deadline.at
    }
}

/// Affine evidence minted only by validated peer Finished or actual HANDSHAKE_DONE.
#[derive(Debug)]
pub struct HandshakeConfirmed<'scope> {
    scope: &'scope ApplicationKeyScope,
    side: Side,
}
impl<'scope> HandshakeConfirmed<'scope> {
    pub fn scope(&self) -> &'scope ApplicationKeyScope {
        self.scope
    }
    pub fn side(&self) -> Side {
        self.side
    }
}
#[derive(Debug)]
pub struct KeyAcknowledged<'scope> {
    scope: &'scope ApplicationKeyScope,
    packet: PacketNumber,
    sent_key_generation: u64,
    received_key_generation: u64,
}
impl<'scope> KeyAcknowledged<'scope> {
    pub fn scope(&self) -> &'scope ApplicationKeyScope {
        self.scope
    }
    pub fn packet(&self) -> PacketNumber {
        self.packet
    }
    pub fn sent_packet_number(&self) -> u64 {
        self.packet.value
    }
    pub fn sent_key_generation(&self) -> u64 {
        self.sent_key_generation
    }
    pub fn received_key_generation(&self) -> u64 {
        self.received_key_generation
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitialRetirementEvent {
    ClientHandshakeAccepted,
    ServerHandshakeAuthenticated,
}
#[derive(Debug)]
pub struct InitialRetirement<'scope> {
    scope: &'scope ApplicationKeyScope,
    event: InitialRetirementEvent,
}
#[derive(Debug)]
pub struct InitialRetired<'scope> {
    scope: &'scope ApplicationKeyScope,
    event: InitialRetirementEvent,
}
impl<'scope> InitialRetirement<'scope> {
    pub fn scope(&self) -> &'scope ApplicationKeyScope {
        self.scope
    }
    pub fn event(&self) -> InitialRetirementEvent {
        self.event
    }
}
impl<'scope> InitialRetired<'scope> {
    pub fn scope(&self) -> &'scope ApplicationKeyScope {
        self.scope
    }
    pub fn event(&self) -> InitialRetirementEvent {
        self.event
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketOutcome {
    pub duplicate: bool,
    pub ack_eliciting: bool,
    pub newly_acknowledged: usize,
}
/// One-shot loss evidence from the installed recovery owner and actual key scope.
pub struct ApplicationLoss<'scope> {
    scope: &'scope ApplicationKeyScope,
    packet: PacketNumber,
}
impl ApplicationLoss<'_> {
    pub fn packet(&self) -> PacketNumber {
        self.packet
    }
    pub(crate) fn scope(&self) -> &ApplicationKeyScope {
        self.scope
    }
}
/// Affine evidence issued only after authenticated recovery validated these ACKs.
pub(crate) struct FrameAcknowledgments<'scope> {
    scope: &'scope ApplicationKeyScope,
    packets: [Option<PacketNumber>; LEDGER_CAPACITY],
}
impl FrameAcknowledgments<'_> {
    pub(crate) fn scope(&self) -> &ApplicationKeyScope {
        self.scope
    }
    pub(crate) fn packets(&self) -> &[Option<PacketNumber>] {
        &self.packets
    }
    pub(crate) fn merge(&mut self, other: Self) -> Result<(), Error> {
        if !core::ptr::eq(self.scope, other.scope) {
            return Err(Error::Binding);
        }
        for packet in other.packets.into_iter().flatten() {
            if self.packets.contains(&Some(packet)) {
                continue;
            }
            *self
                .packets
                .iter_mut()
                .find(|p| p.is_none())
                .ok_or(Error::Capacity)? = Some(packet);
        }
        Ok(())
    }
}
pub struct ApplicationOutcome<'scope> {
    pub(crate) frame_acks: Option<FrameAcknowledgments<'scope>>,
    pub duplicate: bool,
    pub ack_eliciting: bool,
    pub newly_acknowledged: usize,
    pub packets: [Option<PacketNumber>; LEDGER_CAPACITY],
    pub key_acks: [Option<KeyAcknowledged<'scope>>; LEDGER_CAPACITY],
    pub confirmation: Option<HandshakeConfirmed<'scope>>,
    pub history_floor: u64,
}

#[derive(Clone, Copy)]
struct Epoch {
    packet: PacketNumber,
    generation: u64,
}
/// Exact authenticated feedback discrepancy retained until connection retirement.
/// This is evidence for the projected ECN owner, never a marking-policy state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EcnFailure {
    pub space: PacketNumberSpace,
    pub largest: u64,
    pub previous: packet::EcnCounts,
    pub reported: Option<packet::EcnCounts>,
    pub newly: crate::quic::ecn::MarkedPackets,
    pub reason: crate::quic::ecn::Error,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct EcnObservation {
    pub accepted: u64,
    pub received: u64,
    pub acknowledgments_sent: u64,
    pub lost: u64,
    pub validated: u64,
    pub first_sent_at: Option<u64>,
    pub first_failure: Option<EcnFailure>,
    pub path_changes: u64,
    pub probe_period: u64,
}
struct Numbers<'scope, const B: usize> {
    side: Side,
    generation: u64,
    max_datagram_size: u64,
    local_ack_delay_exponent: u8,
    path_start: Option<u64>,
    path_changes: u64,
    ledger: SentLedger<LEDGER_CAPACITY>,
    flights: FlightStore<FLIGHT_CAPACITY, B, REFERENCE_CAPACITY>,
    path: PathBudget<LEDGER_CAPACITY>,
    rtt: RttEstimator,
    congestion: NewReno,
    timer: RecoveryTimer,
    received: [Received; 3],
    received_ecn: crate::quic::ecn::RxCounts,
    peer_ecn: [packet::EcnCounts; 3],
    ecn_acknowledgments_sent: u64,
    validated_ecn_packets: u64,
    lost_ecn_packets: u64,
    first_ecn_sent_at: Option<u64>,
    first_ecn_failure: Option<EcnFailure>,
    ack_pending: [bool; 3],
    ack_revision: [u64; 3],
    revision: u64,
    last_now: Option<u64>,
    largest_acked: [Option<u64>; 3],
    loss_time: [Option<u64>; 3],
    last_ack_eliciting: [Option<u64>; 3],
    idle_activity: super::idle::Activity,
    pending: [usize; 3],
    retired_space: [bool; 3],
    epochs: [Option<Epoch>; LEDGER_CAPACITY],
    lost: [Option<PacketNumber>; LEDGER_CAPACITY],
    floor: [u64; 3],
    probe_space: Option<PacketNumberSpace>,
    probe_credits: u8,
    probe_epoch: u64,
    probe_minimum: u16,
    handshake_confirmed: bool,
    handshake_ack_received: bool,
    peer_parameters: Option<PeerRecoveryParameters>,
    handshake_done: Option<FlightId>,
    initial_event_minted: bool,
    initial_event: Option<InitialRetirementEvent>,
    closing: Option<super::application::OrdinaryRetired<'scope>>,
    retired_next: Option<[Option<u64>; 3]>,
    retired_path: Option<(u64, u64, bool)>,
}

// Actual authenticated peer configuration, present only after scoped validation.
// The presence check cannot disagree with separate default-valued fields.
struct PeerRecoveryParameters {
    ack_delay_exponent: u8,
    max_ack_delay_us: u64,
    idle_timeout_ms: u64,
}

#[derive(Clone, Copy)]
struct Received {
    ranges: [packet::AckRange; ACK_CAPACITY],
    len: usize,
    // Packets below this monotone cutoff are never accepted again.
    floor: u64,
    largest_received_at: u64,
}
impl Received {
    const EMPTY: Self = Self {
        ranges: [packet::AckRange {
            smallest: 0,
            largest: 0,
        }; ACK_CAPACITY],
        len: 0,
        floor: 0,
        largest_received_at: 0,
    };
    /// Bound ACK memory by retiring the oldest disjoint ranges, while retaining
    /// the largest and permanently excluding discarded packet numbers.
    /// RFC 9000 section 13.2.3; no capacity increase or fabricated ACK ranges.
    fn insert(&mut self, pn: u64, received_at: u64) -> Result<bool, Error> {
        if pn > packet::MAX_VARINT {
            return Err(Error::Binding);
        }
        if pn < self.floor {
            return Ok(true);
        }
        if self.ranges[..self.len]
            .iter()
            .any(|r| r.smallest <= pn && pn <= r.largest)
        {
            return Ok(true);
        }
        let mut items = [packet::AckRange {
            smallest: 0,
            largest: 0,
        }; ACK_CAPACITY + 1];
        items[..self.len].copy_from_slice(&self.ranges[..self.len]);
        items[self.len] = packet::AckRange {
            smallest: pn,
            largest: pn,
        };
        items[..self.len + 1].sort_unstable_by_key(|b| core::cmp::Reverse(b.largest));
        let mut next = Self::EMPTY;
        next.floor = self.floor;
        next.largest_received_at = if self.len == 0 || pn > self.ranges[0].largest {
            received_at
        } else {
            self.largest_received_at
        };
        for range in &items[..self.len + 1] {
            if next.len != 0
                && range.largest.saturating_add(1) >= next.ranges[next.len - 1].smallest
            {
                next.ranges[next.len - 1].smallest =
                    next.ranges[next.len - 1].smallest.min(range.smallest);
            } else {
                if next.len == ACK_CAPACITY {
                    next.floor = next
                        .floor
                        .max(range.largest.checked_add(1).ok_or(Error::Binding)?);
                    continue;
                }
                next.ranges[next.len] = *range;
                next.len += 1;
            }
        }
        *self = next;
        Ok(pn < self.floor)
    }
}

fn level_index(level: Level) -> Result<usize, Error> {
    match level {
        Level::Initial => Ok(0),
        Level::Handshake => Ok(1),
        Level::OneRtt => Ok(2),
    }
}
pub(super) fn frames(plaintext: &[u8], level: EncryptionLevel) -> Result<FrameIter<'_>, Error> {
    Ok(FrameIter::new(
        plaintext,
        level,
        ParseLimits {
            max_bytes: plaintext.len(),
            max_frames: 256,
            max_ack_ranges: ACK_CAPACITY,
        },
    )?)
}
fn ack_ranges(ranges: packet::AckRanges<'_>) -> Result<([AckRange; ACK_CAPACITY], usize), Error> {
    if ranges.len() > ACK_CAPACITY {
        return Err(Error::Capacity);
    }
    let mut result = [AckRange { start: 0, end: 0 }; ACK_CAPACITY];
    let len = ranges.len();
    for (i, range) in ranges.iter().enumerate() {
        result[len - i - 1] = AckRange {
            start: range.smallest,
            end: range.largest,
        };
    }
    Ok((result, len))
}

impl<'scope, const B: usize> Recovery<'scope, B> {
    /// Consume the key installation's unique recovery claim; numeric generations cannot
    /// manufacture a second recovery owner for this installed key scope.
    /// `local_ack_delay_exponent` must match the local transport parameter;
    /// the RFC default is 3. It configures units, never protocol progression.
    pub fn new(
        binding: RecoveryInstallation<'scope>,
        side: Side,
        initial_rtt_us: u64,
        max_datagram_size: u64,
        local_ack_delay_exponent: u8,
    ) -> Result<Self, Error> {
        if local_ack_delay_exponent > 20 {
            return Err(kernel::RecoveryError::InvalidConfiguration.into());
        }
        let scope = binding.into_scope();
        let generation = scope.connection_generation();
        let mut path = PathBudget::new(0, generation);
        if side == Side::Client {
            path.mark_validated()?;
        }
        Ok(Self {
            identity: Identity {
                _generation: generation,
            },
            scope,
            numbers: RefCell::new(Numbers {
                side,
                generation,
                max_datagram_size,
                local_ack_delay_exponent,
                path_start: None,
                path_changes: 0,
                ledger: SentLedger::new(generation),
                flights: FlightStore::new(),
                path,
                rtt: RttEstimator::new(initial_rtt_us)?,
                congestion: NewReno::new(max_datagram_size)?,
                timer: RecoveryTimer::new(),
                received: [Received::EMPTY; 3],
                received_ecn: crate::quic::ecn::RxCounts::new(),
                peer_ecn: [packet::EcnCounts {
                    ect0: 0,
                    ect1: 0,
                    ce: 0,
                }; 3],
                ecn_acknowledgments_sent: 0,
                validated_ecn_packets: 0,
                lost_ecn_packets: 0,
                first_ecn_sent_at: None,
                first_ecn_failure: None,
                ack_pending: [false; 3],
                ack_revision: [0; 3],
                revision: 0,
                last_now: None,
                largest_acked: [None; 3],
                loss_time: [None; 3],
                last_ack_eliciting: [None; 3],
                idle_activity: super::idle::Activity::default(),
                pending: [0; 3],
                retired_space: [false; 3],
                epochs: [None; LEDGER_CAPACITY],
                lost: [None; LEDGER_CAPACITY],
                floor: [0; 3],
                probe_space: None,
                probe_credits: 0,
                probe_epoch: 0,
                probe_minimum: 0,
                handshake_confirmed: false,
                handshake_ack_received: false,
                peer_parameters: None,
                handshake_done: None,
                initial_event_minted: false,
                initial_event: None,
                closing: None,
                retired_next: None,
                retired_path: None,
            }),
        })
    }
    pub fn scope(&self) -> &'scope ApplicationKeyScope {
        self.scope
    }
    pub fn side(&self) -> Side {
        self.numbers.borrow().side
    }
    pub fn max_datagram_size(&self) -> u64 {
        self.numbers.borrow().max_datagram_size
    }
    pub fn snapshot(&self) -> Snapshot {
        self.numbers.borrow().snapshot()
    }
    #[allow(clippy::type_complexity)]
    pub fn split(
        &mut self,
    ) -> Result<
        (
            Tx<'_, 'scope, B>,
            Rx<'_, 'scope, B>,
            Clock<'_, 'scope, B>,
            Publication<'_, 'scope, B>,
            RetirementGuard<'_, 'scope, B>,
        ),
        Error,
    > {
        self.numbers.borrow().active()?;
        Ok((
            Tx { book: self },
            Rx { book: self },
            Clock { book: self },
            Publication { book: self },
            RetirementGuard {
                book: self,
                armed: true,
            },
        ))
    }
    /// A server's authenticated client Finished confirms its handshake;
    /// a client requires authenticated HANDSHAKE_DONE.
    pub fn bind_validated_peer<const P: usize>(
        &mut self,
        peer: &super::parameters::ValidatedPeer<'scope, P>,
    ) -> Result<Option<HandshakeConfirmed<'scope>>, Error> {
        bind_peer(self, peer)
    }
}
impl<const B: usize> RetirementGuard<'_, '_, B> {
    pub fn disarm(&mut self) {
        self.armed = false;
    }
    pub fn retire_all(&mut self) {
        self.book.numbers.borrow_mut().retire_all();
        self.armed = false;
    }
}
impl<const B: usize> Drop for RetirementGuard<'_, '_, B> {
    fn drop(&mut self) {
        if self.armed {
            self.book.numbers.borrow_mut().retire_all();
        }
    }
}

impl<const B: usize> Numbers<'_, B> {
    fn active(&self) -> Result<(), Error> {
        if self.retired_next.is_some() {
            Err(AccountingError::Retired.into())
        } else {
            Ok(())
        }
    }
    fn ordinary(&self) -> Result<(), Error> {
        self.active()?;
        if self.closing.is_some() {
            Err(AccountingError::Retired.into())
        } else {
            Ok(())
        }
    }
    fn check_time(&mut self, now: u64) -> Result<(), Error> {
        if self.last_now.is_some_and(|old| now < old) {
            return Err(kernel::RecoveryError::TimeWentBackwards.into());
        }
        self.last_now = Some(now);
        Ok(())
    }
    fn changed(&mut self) -> Result<(), Error> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(AccountingError::Overflow)?;
        Ok(())
    }
    fn context(&self) -> TimerContext {
        TimerContext {
            is_server: self.side == Side::Server,
            handshake_confirmed: self.handshake_confirmed,
            handshake_ack_received: self.handshake_ack_received,
            server_amplification_blocked: !self.path.is_validated()
                && self.path.available_bytes() < self.max_datagram_size,
        }
    }
    fn snapshot(&self) -> Snapshot {
        let (received, accepted, validated) = self.retired_path.unwrap_or((
            self.path.received_bytes(),
            self.path.accepted_bytes(),
            self.path.is_validated(),
        ));
        Snapshot {
            bytes_in_flight: self.ledger.bytes_in_flight(),
            reserved_in_flight: self.ledger.reserved_in_flight(),
            received_bytes: received,
            accepted_bytes: accepted,
            reserved_bytes: self.path.reserved_bytes(),
            available_bytes: if self.retired_next.is_some() {
                0
            } else {
                self.path.available_bytes()
            },
            address_validated: validated,
            congestion_window: self.congestion.congestion_window(),
            active_flights: self.flights.active_flights(),
            retained_packets: self.ledger.retained_records(),
            pto_count: self.timer.pto_count(),
            probe_credits: self.probe_credits,
            revision: self.revision,
            next_packet_number: self
                .retired_next
                .unwrap_or_else(|| SPACES.map(|s| self.ledger.next_packet_number(s))),
            handshake_confirmed: self.handshake_confirmed,
            history_floor: self.floor,
            pending_publications: self.pending,
        }
    }
    fn reclaim_application(&mut self) -> Result<(), Error> {
        let floor = self
            .ledger
            .reclaim_completed_prefix(PacketNumberSpace::ApplicationData)?;
        if floor != self.floor[2] {
            self.floor[2] = floor;
            for epoch in &mut self.epochs {
                if epoch.is_some_and(|e| e.packet.value < floor) {
                    *epoch = None;
                }
            }
            self.changed()?;
        }
        if self.ledger.remaining_capacity() == 0 {
            let compacted = self.ledger.compact_ack_history()?;
            for epoch in &mut self.epochs {
                if epoch.is_some_and(|e| compacted.iter().flatten().any(|pn| *pn == e.packet)) {
                    *epoch = None;
                }
            }
            if compacted.iter().any(Option::is_some) {
                self.changed()?;
            }
        }
        Ok(())
    }
    // Called only at the authenticated client Finished boundary below. TLS
    // rejection cancels the early epoch, not the shared application PN space.
    // The application owner retains request bytes for explicit 1-RTT replay.
    fn reject_zero_rtt(&mut self) -> Result<u64, Error> {
        self.ordinary()?;
        if self.side != Side::Client {
            return Err(Error::Binding);
        }
        if self.pending[2] != 0 {
            return Err(AccountingError::OutstandingPackets.into());
        }
        let revision = self
            .revision
            .checked_add(1)
            .ok_or(AccountingError::Overflow)?;
        let early_lost = self.lost.map(|packet| {
            packet.is_some_and(|packet| self.ledger.sent_kind(packet) == Some(PacketKind::ZeroRtt))
        });
        let removed = self.ledger.reject_zero_rtt()?;
        for (entry, early) in self.lost.iter_mut().zip(early_lost) {
            if early {
                *entry = None;
            }
        }
        if !self.ledger.outstanding_sent().any(|packet| {
            packet.packet.space == PacketNumberSpace::ApplicationData && packet.ack_eliciting
        }) {
            self.loss_time[2] = None;
            self.last_ack_eliciting[2] = None;
            if self.probe_space == Some(PacketNumberSpace::ApplicationData) {
                self.probe_space = None;
                self.probe_credits = 0;
            }
        }
        // Invalidate previously issued deadlines. No congestion event, ACK,
        // key-update grant, PN reset, or physical-path accounting is invented.
        self.revision = revision;
        Ok(removed)
    }
    fn mint_initial_event(&mut self, event: InitialRetirementEvent) {
        if !self.initial_event_minted {
            self.initial_event_minted = true;
            self.initial_event = Some(event);
        }
    }
    fn discard_space(&mut self, index: usize) -> Result<u64, Error> {
        if self.retired_space[index] {
            return Ok(0);
        }
        if self.pending[index] != 0 {
            return Err(AccountingError::OutstandingPackets.into());
        }
        // Both kernels guard pending references; no ordinary I/O may be in
        // flight when the affine retirement lane reaches this effect.
        let removed = self.ledger.discard_space(SPACES[index])?;
        self.flights.discard_space(SPACES[index])?;
        if index < 2 {
            self.timer.on_keys_discarded(SPACES[index])?;
        }
        self.retired_space[index] = true;
        self.floor[index] = self
            .ledger
            .next_packet_number(SPACES[index])
            .unwrap_or(accounting::MAX_PACKET_NUMBER + 1);
        self.received[index] = Received::EMPTY;
        self.ack_pending[index] = false;
        self.largest_acked[index] = None;
        self.loss_time[index] = None;
        self.last_ack_eliciting[index] = None;
        if self.probe_space == Some(SPACES[index]) {
            self.probe_space = None;
            self.probe_credits = 0;
        }
        self.changed()?;
        Ok(removed)
    }
    fn retire_all(&mut self) {
        if self.retired_next.is_some() {
            return;
        }
        self.retired_next = Some(SPACES.map(|space| self.ledger.next_packet_number(space)));
        self.retired_path = Some((
            self.path.received_bytes(),
            self.path.accepted_bytes(),
            self.path.is_validated(),
        ));
        // Aggregate cancellation is terminal. Replacement storage is immediately
        // closed; its fresh allocator can never grant a replacement packet.
        self.ledger = SentLedger::new(self.generation);
        self.ledger.retire();
        self.path = PathBudget::new(0, self.generation);
        self.path.retire();
        self.flights.discard();
        self.timer = RecoveryTimer::new();
        self.epochs.fill(None);
        self.lost.fill(None);
        self.pending.fill(0);
        self.ack_pending.fill(false);
        self.retired_space.fill(true);
        self.probe_space = None;
        self.probe_credits = 0;
        self.initial_event = None;
        self.revision = self.revision.saturating_add(1);
    }
    fn detect_loss(&mut self, space: PacketNumberSpace, now: u64) -> Result<(), Error> {
        let index = space as usize;
        if self.retired_space[index] {
            return Ok(());
        }
        let mut packets = [None; LEDGER_CAPACITY];
        let mut count = 0;
        for packet in self
            .ledger
            .outstanding_sent()
            .filter(|p| p.packet.space == space)
        {
            packets[count] = Some(packet);
            count += 1;
        }
        let mut decisions = [false; LEDGER_CAPACITY];
        let mut next = None;
        let mut loss_count = 0;
        for (slot, packet) in packets[..count].iter().flatten().enumerate() {
            match kernel::loss_decision(
                &self.rtt,
                LossCandidate {
                    packet_number: packet.packet.value,
                    sent_at: packet.sent_at,
                    newer_sent_packets: self.largest_acked[index].map_or(0, |largest| {
                        self.ledger.count_later_sent(packet.packet, largest)
                    }),
                },
                self.largest_acked[index],
                now,
            )? {
                LossDecision::Lost => {
                    decisions[slot] = true;
                    loss_count += 1;
                }
                LossDecision::WaitUntil(at) => next = Some(next.map_or(at, |old: u64| old.min(at))),
                LossDecision::NotEligible => {}
            }
        }
        if index == 2 && self.lost.iter().filter(|slot| slot.is_none()).count() < loss_count {
            return Err(Error::Capacity);
        }
        for (slot, packet) in packets[..count].iter().flatten().enumerate() {
            if !decisions[slot] {
                continue;
            }
            if let accounting::LossOutcome::NewlyLost {
                bytes_removed_from_flight,
            } = self.ledger.declare_lost(packet.packet)?
            {
                if matches!(
                    packet.ecn,
                    crate::quic::ecn::Codepoint::Ect0 | crate::quic::ecn::Codepoint::Ect1
                ) {
                    self.lost_ecn_packets = self
                        .lost_ecn_packets
                        .checked_add(1)
                        .ok_or(AccountingError::Overflow)?;
                }
                self.flights.mark_lost(packet.packet);
                if index == 2 {
                    let free = self
                        .lost
                        .iter_mut()
                        .find(|slot| slot.is_none())
                        .ok_or(Error::Capacity)?;
                    *free = Some(packet.packet);
                }
                if bytes_removed_from_flight != 0
                    && self.path_start.is_none_or(|first| {
                        packet.packet.space == PacketNumberSpace::ApplicationData
                            && packet.packet.value >= first
                    })
                {
                    self.congestion.on_congestion_event(now, packet.sent_at)?;
                }
            }
        }
        self.loss_time[index] = next;
        if loss_count != 0 {
            self.changed()?;
        }
        Ok(())
    }
}

fn bind_peer<'scope, const B: usize, const P: usize>(
    book: &Recovery<'scope, B>,
    peer: &super::parameters::ValidatedPeer<'scope, P>,
) -> Result<Option<HandshakeConfirmed<'scope>>, Error> {
    let receipt = peer.finished();
    let mut n = book.numbers.borrow_mut();
    n.ordinary()?;
    let expected = match n.side {
        Side::Client => crate::tls::schedule::Side::Client,
        Side::Server => crate::tls::schedule::Side::Server,
    };
    if !core::ptr::eq(book.scope, peer.scope())
        || receipt.side() != expected
        || !receipt.authenticates_peer_parameters(peer.parameters())
    {
        return Err(Error::Binding);
    }
    if n.peer_parameters.is_some() {
        return Ok(None);
    }
    if n.side == Side::Client
        && receipt.early_status() == crate::quic::early_data::EarlyStatus::Rejected
    {
        n.reject_zero_rtt()?;
    }
    n.peer_parameters = Some(PeerRecoveryParameters {
        ack_delay_exponent: peer.ack_delay_exponent(),
        max_ack_delay_us: peer.max_ack_delay_us(),
        idle_timeout_ms: peer.max_idle_timeout_ms(),
    });
    n.changed()?;
    if n.side == Side::Server && !n.handshake_confirmed {
        n.handshake_confirmed = true;
        Ok(Some(HandshakeConfirmed {
            scope: book.scope,
            side: n.side,
        }))
    } else {
        Ok(None)
    }
}
fn take_initial<'scope, const B: usize>(
    book: &Recovery<'scope, B>,
) -> Option<InitialRetirement<'scope>> {
    book.numbers
        .borrow_mut()
        .initial_event
        .take()
        .map(|event| InitialRetirement {
            scope: book.scope,
            event,
        })
}
fn retire_initial<'scope, const B: usize>(
    book: &Recovery<'scope, B>,
    token: InitialRetirement<'scope>,
) -> Result<InitialRetired<'scope>, (Error, InitialRetirement<'scope>)> {
    let result = (|| {
        let mut n = book.numbers.borrow_mut();
        n.ordinary()?;
        let expected = match n.side {
            Side::Client => InitialRetirementEvent::ClientHandshakeAccepted,
            Side::Server => InitialRetirementEvent::ServerHandshakeAuthenticated,
        };
        if !core::ptr::eq(book.scope, token.scope)
            || token.event != expected
            || !n.initial_event_minted
        {
            return Err(Error::Binding);
        }
        if n.pending[0] != 0 {
            return Err(Error::PendingInitialPublication);
        }
        n.discard_space(0)?;
        Ok(())
    })();
    match result {
        Ok(()) => Ok(InitialRetired {
            scope: token.scope,
            event: token.event,
        }),
        Err(e) => Err((e, token)),
    }
}
fn retire_handshake<const B: usize>(
    book: &Recovery<'_, B>,
    token: &HandshakeConfirmed<'_>,
) -> Result<u64, Error> {
    let mut n = book.numbers.borrow_mut();
    n.ordinary()?;
    if !core::ptr::eq(book.scope, token.scope) || n.side != token.side || !n.handshake_confirmed {
        return Err(Error::Binding);
    }
    if n.pending[0] != 0 || n.pending[1] != 0 {
        return Err(AccountingError::OutstandingPackets.into());
    }
    let initial = n.discard_space(0)?;
    let handshake = n.discard_space(1)?;
    Ok(initial + handshake)
}

/// Independent synchronous capability for the finite Initial retirement lane.
pub struct InitialRetirementOwner<'book, 'scope, const B: usize> {
    book: &'book Recovery<'scope, B>,
}
impl<'scope, const B: usize> InitialRetirementOwner<'_, 'scope, B> {
    pub fn retire_initial(
        &mut self,
        token: InitialRetirement<'scope>,
    ) -> Result<InitialRetired<'scope>, (Error, InitialRetirement<'scope>)> {
        retire_initial(self.book, token)
    }
    pub fn snapshot(&self) -> Snapshot {
        self.book.snapshot()
    }
}

impl<'book, 'scope, const B: usize> Tx<'book, 'scope, B> {
    pub(crate) fn path_datagram_limit(&self) -> usize {
        self.book.numbers.borrow().max_datagram_size as usize
    }
    pub(crate) fn validated_path(
        &mut self,
        old: crate::quic::path::Address,
        new: crate::quic::path::Address,
        now: u64,
    ) -> Result<(), Error> {
        let mut n = self.book.numbers.borrow_mut();
        n.ordinary()?;
        if n.pending.iter().any(|count| *count != 0) {
            return Err(Error::Binding);
        }
        n.check_time(now)?;
        let limit = n.max_datagram_size.min(1200);
        if old.local.ip() != new.local.ip() || old.remote.ip() != new.remote.ip() {
            let first = n
                .ledger
                .next_packet_number(PacketNumberSpace::ApplicationData)
                .ok_or(Error::Capacity)?;
            let congestion = NewReno::new(limit)?;
            let rtt = RttEstimator::new(333_000)?;
            n.path_start = Some(first);
            n.congestion = congestion;
            n.rtt = rtt;
            n.timer = RecoveryTimer::new();
            n.loss_time = [None; 3];
        }
        n.max_datagram_size = limit;
        n.path_changes = n.path_changes.checked_add(1).ok_or(Error::Capacity)?;
        n.changed()?;
        Ok(())
    }

    /// Numerical effect of the projected client Retry join. The caller must
    /// consume its one-shot Retry branch and settle every actual publication
    /// before invoking this effect. No TLS input/output or PN allocator is reset.
    pub(super) fn retry_initial(&mut self, now: u64) -> Result<(), Error> {
        let mut n = self.book.numbers.borrow_mut();
        n.ordinary()?;
        if n.side != Side::Client
            || n.received.iter().any(|received| received.len != 0)
            || n.retired_space.iter().any(|retired| *retired)
            || n.ledger.next_packet_number(PacketNumberSpace::Handshake) != Some(0)
            || n.ledger
                .next_packet_number(PacketNumberSpace::ApplicationData)
                != Some(0)
        {
            return Err(Error::Binding);
        }
        if n.pending.iter().any(|count| *count != 0) {
            return Err(Error::PendingInitialPublication);
        }
        // Validate fallible arithmetic before detaching accepted references.
        let revision = n.revision.checked_add(1).ok_or(AccountingError::Overflow)?;
        let congestion = NewReno::new(n.max_datagram_size)?;
        n.check_time(now)?;
        n.ledger.discard_space(PacketNumberSpace::Initial)?;
        n.flights.requeue_space(PacketNumberSpace::Initial)?;
        n.congestion = congestion;
        n.timer = RecoveryTimer::new();
        n.largest_acked.fill(None);
        n.loss_time.fill(None);
        n.last_ack_eliciting.fill(None);
        n.epochs.fill(None);
        n.lost.fill(None);
        n.floor[0] = n
            .ledger
            .next_packet_number(PacketNumberSpace::Initial)
            .unwrap_or(accounting::MAX_PACKET_NUMBER + 1);
        n.probe_space = None;
        n.probe_credits = 0;
        n.revision = revision;
        Ok(())
    }
    pub fn snapshot(&self) -> Snapshot {
        self.book.snapshot()
    }
    pub fn completion_observer(&self) -> CompletionObserver<'book, 'scope, B> {
        CompletionObserver { book: self.book }
    }
    pub fn initial_retirement_owner(&self) -> InitialRetirementOwner<'book, 'scope, B> {
        InitialRetirementOwner { book: self.book }
    }
    pub fn retire_initial(
        &mut self,
        token: InitialRetirement<'scope>,
    ) -> Result<InitialRetired<'scope>, (Error, InitialRetirement<'scope>)> {
        retire_initial(self.book, token)
    }
    pub fn retire_handshake(&mut self, receipt: &HandshakeConfirmed<'_>) -> Result<u64, Error> {
        retire_handshake(self.book, receipt)
    }
    pub fn pto_duration_us(&self) -> Result<u64, Error> {
        let n = self.book.numbers.borrow();
        n.active()?;
        Ok(n.rtt.pto_duration_us(
            n.peer_parameters
                .as_ref()
                .map_or(25_000, |p| p.max_ack_delay_us),
            0,
        )?)
    }
    pub fn store_crypto(
        &mut self,
        level: Level,
        offset: u64,
        bytes: &[u8],
    ) -> Result<FlightId, Error> {
        let index = level_index(level)?;
        let mut n = self.book.numbers.borrow_mut();
        n.ordinary()?;
        if n.retired_space[index] {
            return Err(AccountingError::Retired.into());
        }
        let id = n.flights.append(level, offset, bytes)?;
        n.changed()?;
        Ok(id)
    }
    pub fn store_handshake_done(
        &mut self,
        receipt: &FinishedAuthenticated<'scope>,
    ) -> Result<FlightId, Error> {
        self.store_handshake_done_token(receipt, None)
    }
    pub(super) fn store_handshake_done_token(
        &mut self,
        receipt: &FinishedAuthenticated<'scope>,
        token: Option<&[u8]>,
    ) -> Result<FlightId, Error> {
        let mut n = self.book.numbers.borrow_mut();
        n.ordinary()?;
        if !core::ptr::eq(self.book.scope, receipt.scope())
            || n.side != Side::Server
            || receipt.side() != crate::tls::schedule::Side::Server
            || !n.handshake_confirmed
            || n.peer_parameters.is_none()
        {
            return Err(Error::Binding);
        }
        if let Some(id) = n.handshake_done {
            return Ok(id);
        }
        let id = n.flights.append_handshake_done_token(token)?;
        n.handshake_done = Some(id);
        n.changed()?;
        Ok(id)
    }
    pub fn is_handshake_done(&self, id: FlightId) -> Result<bool, Error> {
        Ok(self.book.numbers.borrow().flights.is_handshake_done(id)?)
    }
    pub(crate) fn unsent_control(&self) -> Option<FlightId> {
        self.book.numbers.borrow().flights.unsent_control()
    }
    pub fn flight_data(&self, id: FlightId) -> Result<Flight<B>, Error> {
        let n = self.book.numbers.borrow();
        n.ordinary()?;
        let (level, offset, bytes) = n.flights.data(id)?;
        let mut result = Flight {
            level,
            offset,
            bytes: [0; B],
            len: bytes.len(),
        };
        result.bytes[..bytes.len()].copy_from_slice(bytes);
        Ok(result)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn reserve(
        &mut self,
        level: Level,
        bytes: u64,
        flight: Option<FlightId>,
        ack_eliciting: bool,
        padded: bool,
        pto_probe: bool,
        now: u64,
    ) -> Result<Reservation<'book>, Error> {
        let index = level_index(level)?;
        if index == 2 {
            return Err(Error::UnsupportedLevel);
        }
        let crypto = if let Some(id) = flight {
            let n = self.book.numbers.borrow();
            let (actual_level, offset, data) = n.flights.data(id)?;
            if actual_level != level || n.flights.is_handshake_done(id)? || !ack_eliciting {
                return Err(Error::Binding);
            }
            Some(CryptoBinding {
                offset,
                bytes: PlaintextBinding::new(data),
            })
        } else {
            None
        };
        reserve(
            self.book,
            index,
            bytes,
            flight,
            ack_eliciting,
            padded,
            pto_probe,
            now,
            0,
            None,
            crypto,
            false,
        )
    }
    /// A real client early key authorizes only this scoped early reservation.
    /// The ordinary application allocator is shared; a rejected send burns its PN.
    pub fn reserve_early(
        &mut self,
        key: &crate::tls::handshake::key_source::TransmitPacketKey<'_>,
        plaintext: &[u8],
        bytes: u64,
        now: u64,
    ) -> Result<Reservation<'book>, Error> {
        if key.kind() != KeyKind::ZeroRtt
            || !core::ptr::eq(key.scope(), self.book.scope)
            || self.book.numbers.borrow().side != Side::Client
        {
            return Err(Error::Binding);
        }
        let mut eliciting = false;
        let mut padded = false;
        for frame in frames(plaintext, EncryptionLevel::ZeroRtt)? {
            let frame = frame?;
            eliciting |= frame.ack_eliciting();
            if let Frame::Padding { length } = frame {
                padded |= length != 0;
            }
        }
        if plaintext.is_empty() {
            return Err(Error::Binding);
        }
        reserve_kind(
            self.book,
            PacketKind::ZeroRtt,
            bytes,
            None,
            eliciting,
            padded,
            false,
            now,
            0,
            Some(PlaintextBinding::new(plaintext)),
            None,
            false,
        )
    }
    pub fn reserve_application(
        &mut self,
        plaintext: &[u8],
        key_generation: u64,
        bytes: u64,
        pto_probe: bool,
        now: u64,
    ) -> Result<Reservation<'book>, Error> {
        let classification = classify_application(plaintext)?;
        if classification.handshake_done != 0
            || classification.close != 0
            || classification.new_token != 0
        {
            return Err(Error::UnsupportedFrame);
        }
        reserve(
            self.book,
            2,
            bytes,
            None,
            classification.ack_eliciting,
            classification.padded,
            pto_probe,
            now,
            key_generation,
            Some(PlaintextBinding::new(plaintext)),
            None,
            false,
        )
    }
    /// Retain the exact post-handshake CRYPTO flight across loss, in the same
    /// application packet-number ledger used by ordinary data.
    pub fn reserve_application_crypto(
        &mut self,
        plaintext: &[u8],
        key_generation: u64,
        bytes: u64,
        flight: FlightId,
        pto_probe: bool,
        now: u64,
    ) -> Result<Reservation<'book>, Error> {
        let binding = {
            let n = self.book.numbers.borrow();
            let (level, offset, data) = n.flights.data(flight)?;
            if level != Level::OneRtt || n.flights.is_handshake_done(flight)? {
                return Err(Error::Binding);
            }
            CryptoBinding {
                offset,
                bytes: PlaintextBinding::new(data),
            }
        };
        let mut count = 0;
        let mut padded = false;
        for frame in frames(plaintext, EncryptionLevel::OneRtt)? {
            match frame? {
                Frame::Crypto { offset, data }
                    if offset == binding.offset && binding.bytes.matches(data) =>
                {
                    count += 1
                }
                Frame::Padding { length } => padded |= length != 0,
                Frame::Ack { .. } => {}
                _ => return Err(Error::Binding),
            }
        }
        if count != 1 {
            return Err(Error::Binding);
        }
        reserve(
            self.book,
            2,
            bytes,
            Some(flight),
            true,
            padded,
            pto_probe,
            now,
            key_generation,
            Some(PlaintextBinding::new(plaintext)),
            Some(binding),
            false,
        )
    }
    pub fn reserve_application_control(
        &mut self,
        plaintext: &[u8],
        key_generation: u64,
        bytes: u64,
        flight: FlightId,
        pto_probe: bool,
        now: u64,
    ) -> Result<Reservation<'book>, Error> {
        let classification = classify_application(plaintext)?;
        if classification.handshake_done != 1
            || classification.other
            || classification.close != 0
            || classification.new_token > 1
        {
            return Err(Error::UnsupportedFrame);
        }
        if !self
            .book
            .numbers
            .borrow()
            .flights
            .is_handshake_done(flight)?
        {
            return Err(Error::Binding);
        }
        // Control bytes are retained with the actual flight. A retransmission
        // may add only ACK/PING/PADDING, never replace the issued token.
        let retained = self.flight_data(flight)?;
        let mut control = [0; B];
        let mut len = 0;
        for frame in frames(plaintext, EncryptionLevel::OneRtt)? {
            let frame = frame?;
            if matches!(frame, Frame::HandshakeDone | Frame::NewToken { .. }) {
                len += packet::encode_frame(&frame, &mut control[len..])?;
            }
        }
        if &control[..len] != retained.bytes() {
            return Err(Error::Binding);
        }
        reserve(
            self.book,
            2,
            bytes,
            Some(flight),
            classification.ack_eliciting,
            classification.padded,
            pto_probe,
            now,
            key_generation,
            Some(PlaintextBinding::new(plaintext)),
            None,
            false,
        )
    }
    /// Consume and retain the actual ordinary-role retirement join. The stored
    /// affine graph receipt closes ordinary admission without a separate phase
    /// flag; packet-number accounting is retained for the finite close flight.
    pub(super) fn discard_for_close(
        &mut self,
        retired: super::application::OrdinaryRetired<'scope>,
    ) -> Result<(), Error> {
        if !core::ptr::eq(self.book.scope, retired.scope()) {
            return Err(Error::Binding);
        }
        let mut n = self.book.numbers.borrow_mut();
        n.active()?;
        if n.pending.iter().any(|count| *count != 0) {
            return Err(AccountingError::OutstandingPackets.into());
        }
        if n.closing.is_some() {
            return Ok(());
        }
        n.discard_space(0)?;
        n.discard_space(1)?;
        n.ledger.discard_space(PacketNumberSpace::ApplicationData)?;
        n.flights
            .discard_space(PacketNumberSpace::ApplicationData)?;
        n.floor[2] = n
            .ledger
            .next_packet_number(PacketNumberSpace::ApplicationData)
            .unwrap_or(accounting::MAX_PACKET_NUMBER + 1);
        n.epochs.fill(None);
        n.lost.fill(None);
        n.ack_pending.fill(false);
        n.timer = RecoveryTimer::new();
        n.probe_credits = 0;
        n.probe_space = None;
        n.closing = Some(retired);
        n.changed()?;
        Ok(())
    }
    pub(super) fn reserve_close(
        &mut self,
        plaintext: &[u8],
        key_generation: u64,
        bytes: u64,
        now: u64,
    ) -> Result<Reservation<'book>, Error> {
        let classification = classify_application(plaintext)?;
        if classification.close != 1
            || classification.handshake_done != 0
            || classification.other
            || classification.ack_eliciting
        {
            return Err(Error::UnsupportedFrame);
        }
        for frame in frames(plaintext, EncryptionLevel::OneRtt)? {
            if !matches!(
                frame?,
                Frame::ConnectionClose { .. } | Frame::Padding { .. }
            ) {
                return Err(Error::UnsupportedFrame);
            }
        }
        reserve(
            self.book,
            2,
            bytes,
            None,
            false,
            classification.padded,
            false,
            now,
            key_generation,
            Some(PlaintextBinding::new(plaintext)),
            None,
            true,
        )
    }
    pub fn cancel(&mut self, reservation: Reservation<'book>) -> Result<(), Error> {
        settle(
            self.book,
            reservation,
            None,
            crate::quic::ecn::Codepoint::NotEct,
        )
    }
    pub fn has_outstanding_crypto(&self) -> bool {
        self.book.numbers.borrow().flights.active_flights() != 0
    }
    /// Retained ServerHello bytes may share an already-required Initial ACK.
    /// This selector supplies no PTO allowance or loss verdict. The ordinary
    /// reservation still checks congestion, amplification, and real acceptance.
    pub(super) fn initial_for_ack(&self) -> Option<FlightId> {
        let n = self.book.numbers.borrow();
        if n.side != Side::Server
            || n.retired_next.is_some()
            || n.closing.is_some()
            || n.retired_space[0]
        {
            return None;
        }
        n.flights.probe(PacketNumberSpace::Initial)
    }
    pub fn next_retransmit(&self) -> Option<(FlightId, bool)> {
        let n = self.book.numbers.borrow();
        if n.retired_next.is_some() || n.closing.is_some() {
            return None;
        }
        if n.probe_credits != 0
            && let Some(id) = n.probe_space.and_then(|space| n.flights.probe(space))
        {
            return Some((id, true));
        }
        n.flights.next_lost().map(|id| (id, false))
    }
    pub fn pending_probe(&self) -> Option<Level> {
        let n = self.book.numbers.borrow();
        if n.retired_next.is_some() || n.closing.is_some() || n.probe_credits == 0 {
            None
        } else {
            n.probe_space.map(|space| LEVELS[space as usize])
        }
    }
    pub fn pending_probe_minimum(&self) -> Option<u16> {
        let n = self.book.numbers.borrow();
        if n.retired_next.is_some() || n.closing.is_some() || n.probe_credits == 0 {
            None
        } else {
            Some(n.probe_minimum)
        }
    }
    /// Snapshot for an already-authorized outgoing packet in this space.
    pub(super) fn ack_for_packet(&self, level: Level) -> Option<AckSnapshot<'book>> {
        let index = level_index(level).ok()?;
        let n = self.book.numbers.borrow();
        if n.retired_next.is_some()
            || n.closing.is_some()
            || n.retired_space[index]
            || n.received[index].len == 0
        {
            return None;
        }
        Some(AckSnapshot {
            identity: &self.book.identity,
            index,
            revision: n.ack_revision[index],
            ranges: n.received[index].ranges,
            len: n.received[index].len,
            ecn: n.received_ecn.ack_counts(SPACES[index]),
            largest_received_at: n.received[index].largest_received_at,
            delay_exponent: n.local_ack_delay_exponent,
        })
    }
    pub fn pending_ack(&self) -> Option<AckSnapshot<'book>> {
        let n = self.book.numbers.borrow();
        if n.retired_next.is_some() || n.closing.is_some() {
            return None;
        }
        n.ack_pending
            .iter()
            .position(|pending| *pending)
            .map(|index| AckSnapshot {
                identity: &self.book.identity,
                index,
                revision: n.ack_revision[index],
                ranges: n.received[index].ranges,
                len: n.received[index].len,
                ecn: n.received_ecn.ack_counts(SPACES[index]),
                largest_received_at: n.received[index].largest_received_at,
                delay_exponent: n.local_ack_delay_exponent,
            })
    }
    pub fn acknowledgment_sent(&mut self, snapshot: AckSnapshot<'book>) -> Result<(), Error> {
        ack_sent(self.book, snapshot)
    }
    pub fn take_lost_application(&mut self) -> Option<ApplicationLoss<'scope>> {
        let mut n = self.book.numbers.borrow_mut();
        n.lost
            .iter_mut()
            .find(|slot| slot.is_some())
            .and_then(Option::take)
            .map(|packet| ApplicationLoss {
                scope: self.book.scope,
                packet,
            })
    }
    pub fn application_history_floor(&self) -> u64 {
        self.book.numbers.borrow().floor[2]
    }
}
struct Classification {
    ack_eliciting: bool,
    padded: bool,
    handshake_done: usize,
    close: usize,
    new_token: usize,
    other: bool,
}
fn classify_application(plaintext: &[u8]) -> Result<Classification, Error> {
    let mut result = Classification {
        ack_eliciting: false,
        padded: false,
        handshake_done: 0,
        close: 0,
        new_token: 0,
        other: false,
    };
    for frame in frames(plaintext, EncryptionLevel::OneRtt)? {
        let frame = frame?;
        result.ack_eliciting |= frame.ack_eliciting();
        match frame {
            Frame::Padding { length } => result.padded |= length != 0,
            Frame::HandshakeDone => result.handshake_done += 1,
            Frame::NewToken { .. } => result.new_token += 1,
            Frame::ConnectionClose { .. } => result.close += 1,
            Frame::Ack { .. } | Frame::Ping => {}
            _ => result.other = true,
        }
    }
    Ok(result)
}
#[allow(clippy::too_many_arguments)]
fn reserve<'book, const B: usize>(
    book: &'book Recovery<'_, B>,
    index: usize,
    bytes: u64,
    flight: Option<FlightId>,
    ack_eliciting: bool,
    padded: bool,
    pto_probe: bool,
    now: u64,
    key_generation: u64,
    plaintext: Option<PlaintextBinding>,
    crypto: Option<CryptoBinding>,
    closing: bool,
) -> Result<Reservation<'book>, Error> {
    reserve_kind(
        book,
        [
            PacketKind::Initial,
            PacketKind::Handshake,
            PacketKind::OneRtt,
        ][index],
        bytes,
        flight,
        ack_eliciting,
        padded,
        pto_probe,
        now,
        key_generation,
        plaintext,
        crypto,
        closing,
    )
}
#[allow(clippy::too_many_arguments)]
fn reserve_kind<'book, const B: usize>(
    book: &'book Recovery<'_, B>,
    kind: PacketKind,
    bytes: u64,
    flight: Option<FlightId>,
    ack_eliciting: bool,
    padded: bool,
    pto_probe: bool,
    now: u64,
    key_generation: u64,
    plaintext: Option<PlaintextBinding>,
    crypto: Option<CryptoBinding>,
    closing: bool,
) -> Result<Reservation<'book>, Error> {
    let index = kind.space() as usize;
    let mut n = book.numbers.borrow_mut();
    n.active()?;
    if n.closing.is_some() != closing || n.retired_space[index] {
        return Err(AccountingError::Retired.into());
    }
    if bytes == 0 || bytes > n.max_datagram_size {
        return Err(Error::Capacity);
    }
    n.check_time(now)?;
    n.reclaim_application()?;
    if !pto_probe
        && !closing
        && (ack_eliciting || padded)
        && n.ledger.remaining_capacity() <= LEDGER_CAPACITY - ORDINARY_RECORD_CAPACITY
    {
        return Err(AccountingError::Full.into());
    }
    if n.ledger.remaining_capacity() == 0 && pto_probe {
        // No fabricated loss or ACK frees an outstanding publication. Exhausting
        // this finite profile is an explicit error, not a wait for an ACK which
        // cannot be elicited because its probe can never be published.
        return Err(Error::Capacity);
    }
    if kind == PacketKind::OneRtt && n.epochs.iter().all(Option::is_some) {
        return Err(if pto_probe {
            Error::Capacity
        } else {
            AccountingError::Full.into()
        });
    }
    let probe_epoch = if pto_probe {
        if n.probe_space != Some(SPACES[index])
            || n.probe_credits == 0
            || !ack_eliciting
            || bytes < u64::from(n.probe_minimum)
        {
            return Err(Error::Binding);
        }
        Some(n.probe_epoch)
    } else {
        None
    };
    if !n.congestion.can_send(
        n.ledger
            .outstanding_sent()
            .filter(|packet| {
                packet.in_flight
                    && n.path_start.is_none_or(|first| {
                        packet.packet.space == PacketNumberSpace::ApplicationData
                            && packet.packet.value >= first
                    })
            })
            .map(|packet| packet.bytes)
            .sum(),
        n.ledger.reserved_in_flight(),
        bytes,
        ack_eliciting || padded,
        pto_probe,
    ) {
        return Err(Error::CongestionLimited);
    }
    let path = n.path.reserve(bytes)?;
    let send =
        match n
            .ledger
            .reserve_classified(kind, bytes, ack_eliciting || padded, ack_eliciting)
        {
            Ok(value) => value,
            Err(error) => {
                n.path.cancel(path)?;
                return Err(error.into());
            }
        };
    let reference = match flight
        .map(|id| n.flights.reserve(id, send.packet()))
        .transpose()
    {
        Ok(value) => value,
        Err(error) => {
            n.ledger.cancel(send)?;
            n.path.cancel(path)?;
            n.reclaim_application()?;
            return Err(error.into());
        }
    };
    if kind == PacketKind::OneRtt {
        let slot = n
            .epochs
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(AccountingError::Full)?;
        *slot = Some(Epoch {
            packet: send.packet(),
            generation: key_generation,
        });
    }
    n.pending[index] += 1;
    if pto_probe {
        n.probe_credits -= 1;
    }
    n.changed()?;
    Ok(Reservation {
        identity: &book.identity,
        scope: book.scope,
        send,
        path,
        flight: reference,
        bytes,
        prepared_at: now,
        probe_epoch,
        crypto,
        ack_eliciting,
        padded,
        key_generation,
        kind,
        plaintext,
    })
}
fn settle<const B: usize>(
    book: &Recovery<'_, B>,
    reservation: Reservation<'_>,
    accepted_at: Option<u64>,
    ecn: crate::quic::ecn::Codepoint,
) -> Result<(), Error> {
    if !core::ptr::eq(&book.identity, reservation.identity)
        || !core::ptr::eq(book.scope, reservation.scope)
    {
        return Err(Error::Binding);
    }
    let mut n = book.numbers.borrow_mut();
    n.active()?;
    let packet = reservation.packet();
    let index = packet.space as usize;
    if n.pending[index] == 0 {
        return Err(Error::Binding);
    }
    if let Some(at) = accepted_at {
        if at < reservation.prepared_at {
            return Err(kernel::RecoveryError::TimeWentBackwards.into());
        }
        // Adapter acceptance is a historical producer timestamp, not a new
        // clock reading at callback processing. RX or the timer may already
        // have observed a later instant while this submission was pending.
        // Keep its exact send time; only the aggregate observation bound takes
        // the later of two observations of the same monotonic clock.
        let observed_at = n.last_now.map_or(at, |previous| previous.max(at));
        n.ledger.adapter_accepted_ecn(reservation.send, at, ecn)?;
        if matches!(
            ecn,
            crate::quic::ecn::Codepoint::Ect0 | crate::quic::ecn::Codepoint::Ect1
        ) {
            n.first_ecn_sent_at = Some(n.first_ecn_sent_at.map_or(at, |old| old.min(at)));
        }
        n.path.adapter_accepted(reservation.path)?;
        if let Some(reference) = reservation.flight {
            n.flights.accepted(reference, at)?;
        }
        n.last_now = Some(observed_at);
        if reservation.ack_eliciting {
            n.idle_activity.accepted_ack_eliciting(at);
            let latest = &mut n.last_ack_eliciting[index];
            *latest = Some(latest.map_or(at, |previous| previous.max(at)));
        }
        if index == 1 && n.side == Side::Client {
            n.mint_initial_event(InitialRetirementEvent::ClientHandshakeAccepted);
        }
    } else {
        n.ledger.cancel(reservation.send)?;
        n.path.cancel(reservation.path)?;
        if let Some(reference) = reservation.flight {
            n.flights.cancelled(reference)?;
        }
        if index == 2 {
            for epoch in &mut n.epochs {
                if epoch.is_some_and(|e| e.packet == packet) {
                    *epoch = None;
                }
            }
        }
        if reservation.probe_epoch == Some(n.probe_epoch) && n.probe_space == Some(packet.space) {
            n.probe_credits = n
                .probe_credits
                .checked_add(1)
                .ok_or(AccountingError::Overflow)?;
        }
    }
    n.pending[index] -= 1;
    // RFC 9002 section 6.2.4: spend the second existing PTO credit in
    // another live packet-number space. The expired space's first probe must
    // have reached actual adapter acceptance; cancellation cannot advance it.
    // No extra allowance, timer, handshake confirmation or loss is invented.
    if accepted_at.is_some()
        && reservation.probe_epoch == Some(n.probe_epoch)
        && n.probe_space == Some(packet.space)
        && n.probe_credits == 1
        && n.pending.iter().all(|pending| *pending == 0)
    {
        let other = match (n.side, packet.space) {
            (Side::Server, PacketNumberSpace::Initial) => Some(PacketNumberSpace::Handshake),
            (Side::Client, PacketNumberSpace::Handshake) => {
                Some(PacketNumberSpace::ApplicationData)
            }
            _ => None,
        };
        if let Some(other) = other
            && !n.retired_space[other as usize]
            && n.ledger.outstanding_sent().any(|sent| {
                sent.ack_eliciting
                    && sent.packet.space == other
                    && (other != PacketNumberSpace::ApplicationData
                        || n.ledger.sent_kind(sent.packet) == Some(PacketKind::OneRtt))
            })
        {
            n.probe_space = Some(other);
            n.probe_minimum = 0;
        }
    }
    if accepted_at.is_some() {
        // A later-PN ACK may have arrived while this record was still Reserved.
        // Re-evaluate newly accepted history using the observation bound, with
        // the original PN and send timestamp retained for loss/RTT arithmetic.
        let observed_at = n.last_now.ok_or(Error::Binding)?;
        n.detect_loss(packet.space, observed_at)?;
    }
    n.changed()?;
    n.reclaim_application()?;
    Ok(())
}
fn ack_sent<const B: usize>(
    book: &Recovery<'_, B>,
    snapshot: AckSnapshot<'_>,
) -> Result<(), Error> {
    if !core::ptr::eq(&book.identity, snapshot.identity) {
        return Err(Error::Binding);
    }
    let mut n = book.numbers.borrow_mut();
    n.active()?;
    if snapshot
        .ecn
        .is_some_and(|counts| counts.ect0 != 0 || counts.ect1 != 0 || counts.ce != 0)
    {
        n.ecn_acknowledgments_sent = n
            .ecn_acknowledgments_sent
            .checked_add(1)
            .ok_or(AccountingError::Overflow)?;
    }
    if n.ack_revision[snapshot.index] == snapshot.revision {
        n.ack_pending[snapshot.index] = false;
        n.changed()?;
    }
    Ok(())
}
impl<'book, 'scope, const B: usize> Publication<'book, 'scope, B> {
    pub fn settle(&mut self, completion: Completion<'book>) -> Result<(), Error> {
        settle(
            self.book,
            completion.reservation,
            completion.accepted_at,
            completion.ecn,
        )
    }
    pub fn cancel(&mut self, reservation: Reservation<'book>) -> Result<(), Error> {
        settle(
            self.book,
            reservation,
            None,
            crate::quic::ecn::Codepoint::NotEct,
        )
    }
    pub fn acknowledgment_sent(&mut self, snapshot: AckSnapshot<'book>) -> Result<(), Error> {
        ack_sent(self.book, snapshot)
    }
    pub fn retire_all(&mut self) {
        self.book.numbers.borrow_mut().retire_all();
    }
    pub fn snapshot(&self) -> Snapshot {
        self.book.snapshot()
    }
    pub fn take_initial_retirement(&mut self) -> Option<InitialRetirement<'scope>> {
        take_initial(self.book)
    }
    pub fn retire_initial(
        &mut self,
        token: InitialRetirement<'scope>,
    ) -> Result<InitialRetired<'scope>, (Error, InitialRetirement<'scope>)> {
        retire_initial(self.book, token)
    }
}

impl<'scope, const B: usize> Rx<'_, 'scope, B> {
    pub fn snapshot(&self) -> Snapshot {
        self.book.snapshot()
    }
    pub fn received_datagram(&mut self, bytes: u64) -> Result<(), Error> {
        let mut n = self.book.numbers.borrow_mut();
        n.ordinary()?;
        n.path.record_received(bytes)?;
        n.changed()
    }
    pub fn bind_validated_peer<const P: usize>(
        &mut self,
        peer: &super::parameters::ValidatedPeer<'scope, P>,
    ) -> Result<Option<HandshakeConfirmed<'scope>>, Error> {
        bind_peer(self.book, peer)
    }
    pub fn pto_duration_us(&self) -> Result<u64, Error> {
        let n = self.book.numbers.borrow();
        n.active()?;
        Ok(n.rtt.pto_duration_us(
            n.peer_parameters
                .as_ref()
                .map_or(25_000, |p| p.max_ack_delay_us),
            0,
        )?)
    }
    pub fn take_initial_retirement(&mut self) -> Option<InitialRetirement<'scope>> {
        take_initial(self.book)
    }
    pub fn retire_initial(
        &mut self,
        token: InitialRetirement<'scope>,
    ) -> Result<InitialRetired<'scope>, (Error, InitialRetirement<'scope>)> {
        retire_initial(self.book, token)
    }
    pub fn retire_handshake(&mut self, receipt: &HandshakeConfirmed<'_>) -> Result<u64, Error> {
        retire_handshake(self.book, receipt)
    }
    pub fn apply_packet(
        &mut self,
        receipt: AuthenticatedLevelRead<'scope>,
        plaintext: &[u8],
        received_at: u64,
        now: u64,
        ecn: Option<crate::quic::ecn::Codepoint>,
    ) -> Result<PacketOutcome, Error> {
        if !core::ptr::eq(self.book.scope, receipt.scope())
            || !receipt.authenticates_plaintext(plaintext)
            || receipt.len() != plaintext.len()
        {
            return Err(Error::Binding);
        }
        let index = match receipt.kind() {
            KeyKind::Initial => 0,
            KeyKind::Handshake => 1,
            _ => return Err(Error::UnsupportedLevel),
        };
        let mut n = self.book.numbers.borrow_mut();
        let outcome = process_packet(
            &mut n,
            self.book.scope,
            index,
            receipt.packet_number(),
            None,
            plaintext,
            received_at,
            now,
            ecn,
        )?;
        if index == 1 && n.side == Side::Server {
            n.path.mark_validated()?;
            n.mint_initial_event(InitialRetirementEvent::ServerHandshakeAuthenticated);
        }
        Ok(PacketOutcome {
            duplicate: outcome.duplicate,
            ack_eliciting: outcome.ack_eliciting,
            newly_acknowledged: outcome.newly_acknowledged,
        })
    }
    /// Only actual quarantine retention and an accepted, same-generation server
    /// Finished can add early packets to the application ACK history.
    pub fn apply_stored_early(
        &mut self,
        packet: crate::quic::early_data::owner::StoredPacket<'scope>,
        finished: &crate::tls::handshake::key_source::FinishedAuthenticated<'scope>,
        now: u64,
    ) -> Result<PacketOutcome, Error> {
        if !core::ptr::eq(self.book.scope, packet.scope())
            || !core::ptr::eq(self.book.scope, finished.scope())
            || finished.side() != crate::tls::schedule::Side::Server
            || finished.early_status() != crate::quic::early_data::EarlyStatus::Accepted
            || finished.early_generation() != Some(packet.generation())
        {
            return Err(Error::Binding);
        }
        let mut n = self.book.numbers.borrow_mut();
        n.ordinary()?;
        if n.side != Side::Server {
            return Err(Error::Binding);
        }
        if n.retired_space[2] || packet.packet_number() < n.received[2].floor {
            return Err(AccountingError::HistoryUnavailable.into());
        }
        n.check_time(now)?;
        let mut received = n.received[2];
        let duplicate = received.insert(packet.packet_number(), now)?;
        commit_received(&mut n, 2, received, packet.ack_eliciting(), now)?;
        if !duplicate {
            n.received_ecn
                .processed(PacketNumberSpace::ApplicationData, packet.ecn())?;
        }
        Ok(PacketOutcome {
            duplicate,
            ack_eliciting: packet.ack_eliciting(),
            newly_acknowledged: 0,
        })
    }

    pub fn apply_application_packet(
        &mut self,
        receipt: AckEligible<'scope>,
        plaintext: &[u8],
        received_at: u64,
        now: u64,
        ecn: Option<crate::quic::ecn::Codepoint>,
    ) -> Result<ApplicationOutcome<'scope>, Error> {
        if !core::ptr::eq(self.book.scope, receipt.scope())
            || !receipt.authenticates_plaintext(plaintext)
            || receipt.opened().len != plaintext.len()
        {
            return Err(Error::Binding);
        }
        process_packet(
            &mut self.book.numbers.borrow_mut(),
            self.book.scope,
            2,
            receipt.packet_number(),
            Some(receipt.opened().generation),
            plaintext,
            received_at,
            now,
            ecn,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn process_packet<'scope, const B: usize>(
    n: &mut Numbers<'_, B>,
    scope: &'scope ApplicationKeyScope,
    index: usize,
    packet_number: u64,
    received_epoch: Option<u64>,
    plaintext: &[u8],
    received_at: u64,
    now: u64,
    ecn: Option<crate::quic::ecn::Codepoint>,
) -> Result<ApplicationOutcome<'scope>, Error> {
    if received_at > now {
        return Err(kernel::RecoveryError::TimeWentBackwards.into());
    }
    n.ordinary()?;
    if n.retired_space[index] {
        return Err(AccountingError::HistoryUnavailable.into());
    }
    n.check_time(now)?;
    if packet_number < n.received[index].floor {
        return Err(AccountingError::HistoryUnavailable.into());
    }
    let level = [
        EncryptionLevel::Initial,
        EncryptionLevel::Handshake,
        EncryptionLevel::OneRtt,
    ][index];
    let space = SPACES[index];
    let mut ack_eliciting = false;
    let mut handshake_done = false;
    // Validate the complete plaintext, including every ACK, before delivery,
    // confirmation, ACK history, or sent-data ownership can change.
    for frame in frames(plaintext, level)? {
        let frame = frame?;
        ack_eliciting |= frame.ack_eliciting();
        match frame {
            Frame::Ack { ranges, delay, .. } => {
                let (ranges, len) = ack_ranges(ranges)?;
                n.ledger.validate_ack(space, &ranges[..len])?;
                if index != 0 {
                    let factor = 1_u64
                        .checked_shl(u32::from(
                            n.peer_parameters
                                .as_ref()
                                .map_or(3, |p| p.ack_delay_exponent),
                        ))
                        .ok_or(AccountingError::Overflow)?;
                    delay.checked_mul(factor).ok_or(AccountingError::Overflow)?;
                }
            }
            Frame::HandshakeDone => {
                if index != 2 || n.side != Side::Client || n.peer_parameters.is_none() {
                    return Err(Error::UnsupportedFrame);
                }
                handshake_done = true;
            }
            Frame::Padding { .. }
            | Frame::Ping
            | Frame::Crypto { .. }
            | Frame::ConnectionClose { .. } => {}
            _ if index == 2 => {}
            _ => return Err(Error::UnsupportedFrame),
        }
    }
    let mut received = n.received[index];
    let duplicate = received.insert(packet_number, received_at)?;
    let mut outcome = ApplicationOutcome {
        frame_acks: None,
        duplicate,
        ack_eliciting,
        newly_acknowledged: 0,
        packets: [None; LEDGER_CAPACITY],
        key_acks: core::array::from_fn(|_| None),
        confirmation: None,
        history_floor: n.floor[2],
    };
    if !duplicate {
        for frame in frames(plaintext, level)? {
            if let Frame::Ack { ranges, delay, ecn } = frame? {
                let (ranges, len) = ack_ranges(ranges)?;
                apply_ack(
                    n,
                    scope,
                    space,
                    &ranges[..len],
                    delay,
                    ecn,
                    received_epoch,
                    now - received_at,
                    now,
                    &mut outcome,
                )?;
            }
        }
        // Existing scoped key-ACK receipts prove actual 1-RTT publication and
        // an authenticated peer acknowledgment. Zero-RTT ACKs never create
        // these receipts. Use that evidence when HANDSHAKE_DONE is lost rather
        // than retaining an independent first-packet/progress flag.
        if !n.handshake_confirmed
            && (handshake_done
                || (n.side == Side::Client
                    && n.peer_parameters.is_some()
                    && outcome.key_acks.iter().any(Option::is_some)))
        {
            n.handshake_confirmed = true;
            outcome.confirmation = Some(HandshakeConfirmed {
                scope,
                side: n.side,
            });
        }
    }
    // Even an incoming packet below a newly pruned cutoff commits that cutoff.
    // No frame effects are applied when the insertion reported it discarded.
    commit_received(n, index, received, ack_eliciting, now)?;
    if !duplicate {
        n.received_ecn.processed(space, ecn)?;
        n.idle_activity.received(now);
    }
    outcome.history_floor = n.floor[2];
    if space == PacketNumberSpace::ApplicationData && outcome.packets.iter().any(Option::is_some) {
        outcome.frame_acks = Some(FrameAcknowledgments {
            scope,
            packets: outcome.packets,
        });
    }
    Ok(outcome)
}
fn commit_received<const B: usize>(
    n: &mut Numbers<'_, B>,
    index: usize,
    received: Received,
    ack_eliciting: bool,
    now: u64,
) -> Result<(), Error> {
    n.received[index] = received;
    if ack_eliciting {
        n.ack_revision[index] = n.ack_revision[index]
            .checked_add(1)
            .ok_or(AccountingError::Overflow)?;
        n.ack_pending[index] = true;
    }
    n.detect_loss(SPACES[index], now)?;
    n.reclaim_application()?;
    n.changed()?;
    Ok(())
}
#[allow(clippy::too_many_arguments)]
fn apply_ack<'scope, const B: usize>(
    n: &mut Numbers<'_, B>,
    scope: &'scope ApplicationKeyScope,
    space: PacketNumberSpace,
    ranges: &[AckRange],
    delay: u64,
    peer_ecn: Option<packet::EcnCounts>,
    received_epoch: Option<u64>,
    local_decryption_delay_us: u64,
    now: u64,
    output: &mut ApplicationOutcome<'scope>,
) -> Result<(), Error> {
    let index = space as usize;
    let largest = ranges.last().ok_or(Error::Binding)?.end;
    let largest_packet = PacketNumber {
        space,
        value: largest,
    };
    let largest_new = n.ledger.is_new_ack(largest_packet);
    let largest_sent = n.ledger.sent_packet(largest_packet);
    let mut packets = [None; LEDGER_CAPACITY];
    let mut count = 0;
    for packet in n.ledger.unacknowledged_sent().filter(|packet| {
        packet.packet.space == space
            && ranges
                .iter()
                .any(|range| range.start <= packet.packet.value && packet.packet.value <= range.end)
    }) {
        packets[count] = Some(packet);
        count += 1;
    }
    // RFC 9000 13.4.2.1: reordered ACKs that do not increase Largest
    // Acknowledged cannot fail validation or advance the ECN baseline.
    if n.first_ecn_failure.is_none()
        && n.path_changes == 0
        && n.largest_acked[index].is_none_or(|previous| largest > previous)
    {
        let newly = packets[..count].iter().flatten().fold(
            crate::quic::ecn::MarkedPackets::default(),
            |mut counts, packet| {
                match packet.ecn {
                    crate::quic::ecn::Codepoint::Ect0 => counts.ect0 += 1,
                    crate::quic::ecn::Codepoint::Ect1 => counts.ect1 += 1,
                    _ => {}
                }
                counts
            },
        );
        match crate::quic::ecn::validate_feedback(
            n.ledger.accepted_ecn_counts(space),
            n.peer_ecn[index],
            newly,
            peer_ecn,
        ) {
            Ok(Some(delta)) => {
                if delta.ce_increase != 0
                    && let Some(sent_at) = n.ledger.congestion_sent_at_upper_bound(largest_packet)
                {
                    n.congestion.on_congestion_event(now, sent_at)?;
                }
                n.peer_ecn[index] = peer_ecn.ok_or(Error::Binding)?;
                n.validated_ecn_packets = n
                    .validated_ecn_packets
                    .checked_add(delta.newly_validated)
                    .ok_or(AccountingError::Overflow)?;
            }
            Ok(None) => {}
            Err(reason) => {
                n.first_ecn_failure = Some(EcnFailure {
                    space,
                    largest,
                    previous: n.peer_ecn[index],
                    reported: peer_ecn,
                    newly,
                    reason,
                });
            }
        }
    }
    // Save original sent epochs before ACK/loss reclamation removes history.
    if index == 2 {
        if output
            .newly_acknowledged
            .checked_add(count)
            .is_none_or(|total| total > LEDGER_CAPACITY)
        {
            return Err(Error::Capacity);
        }
        let received_key_generation = received_epoch.ok_or(Error::Binding)?;
        for (offset, packet) in packets[..count].iter().flatten().enumerate() {
            let slot = output.newly_acknowledged + offset;
            output.packets[slot] = Some(packet.packet);
            // Acknowledging early data retires its bytes, but cannot authorize
            // an update of the later 1-RTT key generation.
            if n.ledger.sent_kind(packet.packet) == Some(PacketKind::ZeroRtt) {
                continue;
            }
            if n.ledger.sent_kind(packet.packet) != Some(PacketKind::OneRtt) {
                return Err(Error::Binding);
            }
            let epoch = n
                .epochs
                .iter()
                .flatten()
                .find(|epoch| epoch.packet == packet.packet)
                .ok_or(Error::Binding)?;
            output.key_acks[slot] = Some(KeyAcknowledged {
                scope,
                packet: packet.packet,
                sent_key_generation: epoch.generation,
                received_key_generation,
            });
        }
    }
    let any_ack_eliciting = packets[..count]
        .iter()
        .flatten()
        .any(|packet| packet.ack_eliciting);
    let ack_delay_us = if index != 0 {
        let factor = 1_u64
            .checked_shl(u32::from(
                n.peer_parameters
                    .as_ref()
                    .map_or(3, |p| p.ack_delay_exponent),
            ))
            .ok_or(AccountingError::Overflow)?;
        delay.checked_mul(factor).ok_or(AccountingError::Overflow)?
    } else {
        0
    };
    if let Some(packet) = largest_sent.filter(|packet| {
        n.path_start.is_none_or(|first| {
            packet.packet.space == PacketNumberSpace::ApplicationData
                && packet.packet.value >= first
        })
    }) {
        n.rtt.on_ack(RttSample {
            now,
            sent_at: packet.sent_at,
            ack_delay_us,
            max_ack_delay_us: n
                .peer_parameters
                .as_ref()
                .map_or(25_000, |p| p.max_ack_delay_us),
            space,
            handshake_confirmed: n.handshake_confirmed,
            largest_newly_acknowledged: largest_new,
            any_newly_acknowledged_ack_eliciting: any_ack_eliciting,
            // RFC 9002 5.3: the packet's retained observation measures local
            // key wait; it is not path RTT. Keep commit/loss time monotonic.
            // The estimator applies this only before handshake confirmation.
            local_decryption_delay_us,
        })?;
    }
    let summary = n.ledger.acknowledge(space, ranges)?;
    n.flights.acknowledge(space, ranges);
    for packet in packets[..count].iter().flatten() {
        if n.path_start.is_some_and(|first| {
            packet.packet.space != PacketNumberSpace::ApplicationData || packet.packet.value < first
        }) {
            continue;
        }
        n.congestion.on_ack(
            now,
            packet.sent_at,
            if packet.in_flight { packet.bytes } else { 0 },
            false,
        )?;
    }
    output.newly_acknowledged += summary.newly_acknowledged;
    // Ignore completely reclaimed ACK prefixes; they cannot establish new loss
    // or key-update authority even though validate_ack intentionally accepts them.
    if largest >= n.floor[index] {
        n.largest_acked[index] =
            Some(n.largest_acked[index].map_or(largest, |old| old.max(largest)));
    }
    if index == 1 && summary.newly_acknowledged != 0 {
        n.handshake_ack_received = true;
    }
    let peer_validated = n.context().peer_completed_address_validation();
    n.timer
        .on_new_ack(summary.newly_acknowledged != 0, peer_validated);
    if summary.newly_acknowledged != 0 {
        n.probe_epoch = n
            .probe_epoch
            .checked_add(1)
            .ok_or(AccountingError::Overflow)?;
        n.probe_credits = 0;
        n.probe_space = None;
    }
    Ok(())
}

impl<'book, const B: usize> Clock<'book, '_, B> {
    pub fn update(&mut self, now: u64, keys: [bool; 2]) -> Result<Option<Deadline<'book>>, Error> {
        self.update_application(now, [keys[0], keys[1], false])
    }
    pub fn update_application(
        &mut self,
        now: u64,
        keys: [bool; 3],
    ) -> Result<Option<Deadline<'book>>, Error> {
        let mut borrowed = self.book.numbers.borrow_mut();
        let n = &mut *borrowed;
        n.ordinary()?;
        n.check_time(now)?;
        // A fired PTO already supplied bounded probe credit. Wait for publication
        // or cancellation before arming another allowance for the same event.
        if n.probe_credits != 0 {
            return Ok(None);
        }
        let mut spaces = [SpaceTimer::default(); 3];
        for index in 0..3 {
            spaces[index] = SpaceTimer {
                keys_available: keys[index] && !n.retired_space[index],
                loss_time: n.loss_time[index],
                last_ack_eliciting_sent_at: n.last_ack_eliciting[index],
                ack_eliciting_in_flight: n
                    .ledger
                    .outstanding_sent()
                    .any(|packet| packet.packet.space == SPACES[index] && packet.ack_eliciting),
            };
        }
        let context = n.context();
        let old = n.timer.deadline();
        let deadline = n.timer.update(
            now,
            &n.rtt,
            &spaces,
            context,
            n.peer_parameters
                .as_ref()
                .map_or(25_000, |p| p.max_ack_delay_us),
        )?;
        if deadline != old {
            n.changed()?;
        }
        Ok(deadline.map(|deadline| Deadline {
            identity: &self.book.identity,
            revision: n.revision,
            deadline,
        }))
    }
    pub fn expire(
        &mut self,
        deadline: Deadline<'book>,
        now: u64,
    ) -> Result<Option<TimeoutAction>, Error> {
        let mut n = self.book.numbers.borrow_mut();
        n.ordinary()?;
        if !core::ptr::eq(&self.book.identity, deadline.identity)
            || deadline.revision != n.revision
            || n.timer.deadline() != Some(deadline.deadline)
        {
            return Err(Error::StaleDeadline);
        }
        n.check_time(now)?;
        let action = n.timer.on_timeout(now)?;
        match action {
            Some(TimeoutAction::DetectLoss(space)) => {
                n.detect_loss(space, now)?;
                n.reclaim_application()?;
            }
            Some(TimeoutAction::Probe {
                space,
                max_datagrams,
                minimum_datagram_size,
            }) => {
                n.probe_epoch = n
                    .probe_epoch
                    .checked_add(1)
                    .ok_or(AccountingError::Overflow)?;
                n.probe_space = Some(space);
                n.probe_credits = max_datagrams;
                n.probe_minimum = minimum_datagram_size;
            }
            None => return Ok(None),
        }
        n.changed()?;
        Ok(action)
    }
    pub fn snapshot(&self) -> Snapshot {
        self.book.snapshot()
    }
}

#[cfg(test)]
use crate::tls_fixture;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        self, CipherSuite, IntegrityBudget, PacketKey,
        directional::{ApplicationReadKeys, AuthenticatedRead, ValidatedKeyAck},
    };
    use actor_test_allocator::NoAlloc;

    macro_rules! book {
        ($book:ident, $scope:ident, $installation:ident, $arena:ident, $side:expr, $generation:expr) => {
            let mut $scope = ApplicationKeyScope::new($generation);
            let mut $installation = $scope.claim().unwrap();
            let mut $book = Recovery::<2048>::new(
                $installation.take_recovery().unwrap(),
                $side,
                333_000,
                1200,
                3,
            )
            .unwrap();
        };
    }
    fn key(kind: KeyKind, byte: u8) -> PacketKey {
        PacketKey::from_secret(CipherSuite::Aes128GcmSha256, kind, &[byte; 32]).unwrap()
    }
    fn initial_receipt<'a>(
        scope: &'a ApplicationKeyScope,
        peer: &mut PacketKey,
        packet_number: u64,
        plaintext: &[u8],
    ) -> AuthenticatedLevelRead<'a> {
        let rx = crate::tls::handshake::key_source::ReceivePacketKey::from_initial(
            scope,
            key(KeyKind::Initial, 7),
        )
        .unwrap();
        let mut bytes = [0; 2048];
        bytes[..plaintext.len()].copy_from_slice(plaintext);
        let len = peer
            .seal(
                packet_number,
                b"real Initial header",
                &mut bytes,
                plaintext.len(),
            )
            .unwrap();
        rx.open_authenticated(
            packet_number,
            b"real Initial header",
            &mut bytes[..len],
            &mut IntegrityBudget::new(),
        )
        .unwrap()
    }
    fn app_receipt<'a>(
        rx: &mut ApplicationReadKeys<'a>,
        peer: &mut PacketKey,
        packet_number: u64,
        plaintext: &[u8],
        now: u64,
    ) -> AckEligible<'a> {
        let mut bytes = [0; 2048];
        bytes[..plaintext.len()].copy_from_slice(plaintext);
        let len = peer
            .seal(packet_number, &[0x40], &mut bytes, plaintext.len())
            .unwrap();
        match rx
            .open(
                packet_number,
                false,
                &[0x40],
                &mut bytes[..len],
                &mut IntegrityBudget::new(),
                now,
                1000,
            )
            .unwrap()
        {
            AuthenticatedRead::Ready(receipt) => receipt,
            AuthenticatedRead::PeerUpdate(_) => panic!("unexpected key transition"),
        }
    }
    fn ack(pn: u64, output: &mut [u8]) -> usize {
        packet::encode_frame(
            &Frame::Ack {
                delay: 0,
                ranges: packet::AckRanges::new(&[packet::AckRange {
                    smallest: pn,
                    largest: pn,
                }])
                .unwrap(),
                ecn: None,
            },
            output,
        )
        .unwrap()
    }

    #[test]
    fn migrated_path_does_not_inherit_old_packet_rtt_or_congestion_growth() {
        book!(book, scope, installation, arena, Side::Client, 204);
        let scope = book.scope();
        let (mut tx, mut rx, _, mut publication, mut retirement) = book.split().unwrap();
        let old = crate::quic::path::Address {
            local: "127.0.0.1:1000".parse().unwrap(),
            remote: "127.0.0.1:2000".parse().unwrap(),
        };
        let new = crate::quic::path::Address {
            remote: "127.0.0.2:2000".parse().unwrap(),
            ..old
        };
        let flight = tx.store_crypto(Level::Initial, 0, b"old flight").unwrap();
        let reservation = tx
            .reserve(Level::Initial, 1200, Some(flight), true, true, false, 0)
            .unwrap();
        let pn = reservation.packet().value;
        assert!(tx.validated_path(old, new, 0).is_err());
        publication
            .settle(Completion::from_adapter(
                reservation,
                Some(1),
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        tx.validated_path(old, new, 10).unwrap();
        let initial_window = tx.book.numbers.borrow().congestion.congestion_window();
        let mut plaintext = [0; 64];
        let len = ack(pn, &mut plaintext);
        let receipt = initial_receipt(scope, &mut key(KeyKind::Initial, 7), 0, &plaintext[..len]);
        rx.apply_packet(receipt, &plaintext[..len], 100, 100, None)
            .unwrap();
        let n = tx.book.numbers.borrow();
        assert_eq!(n.rtt.smoothed_us(), 333_000);
        assert_eq!(n.congestion.congestion_window(), initial_window);
        assert_eq!(n.ledger.bytes_in_flight(), 0);
        assert_eq!(n.path_start, Some(0));
        assert_eq!(n.path_changes, 1);
        assert!(n.first_ecn_failure.is_none());
        drop(n);
        retirement.disarm();
    }

    #[test]
    fn port_only_rebinding_keeps_rtt_but_invalidates_inherited_ecn_capability() {
        book!(book, scope, installation, arena, Side::Client, 205);
        let (mut tx, _, _, _, mut retirement) = book.split().unwrap();
        let old = crate::quic::path::Address {
            local: "127.0.0.1:1000".parse().unwrap(),
            remote: "127.0.0.1:2000".parse().unwrap(),
        };
        let new = crate::quic::path::Address {
            remote: "127.0.0.1:3000".parse().unwrap(),
            ..old
        };
        tx.book.numbers.borrow_mut().rtt = RttEstimator::new(42_000).unwrap();
        tx.validated_path(old, new, 1).unwrap();
        let n = tx.book.numbers.borrow();
        assert_eq!(n.rtt.smoothed_us(), 42_000);
        assert_eq!(n.path_start, None);
        assert_eq!(n.path_changes, 1);
        drop(n);
        retirement.disarm();
    }

    #[test]
    fn rejected_early_epoch_preserves_actual_one_rtt_and_burned_packet_numbers() {
        // Numerical rejection kernel test. Production entry is guarded by the
        // authenticated Finished receipt in bind_peer, never a copied status.
        book!(book, scope, installation, arena, Side::Client, 173);
        let (mut tx, _, _, mut publication, mut retirement) = book.split().unwrap();
        let guard = NoAlloc::start();
        let early = reserve_kind(
            tx.book,
            PacketKind::ZeroRtt,
            64,
            None,
            true,
            false,
            false,
            0,
            0,
            Some(PlaintextBinding::new(&[1])),
            None,
            false,
        )
        .unwrap();
        let early_packet = early.packet();
        let before = tx.snapshot();
        assert_eq!(
            tx.book.numbers.borrow_mut().reject_zero_rtt(),
            Err(Error::Accounting(AccountingError::OutstandingPackets))
        );
        assert_eq!(tx.snapshot(), before);
        publication
            .settle(Completion::from_adapter(
                early,
                Some(1),
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        let ordinary = tx.reserve_application(&[1], 0, 80, false, 2).unwrap();
        let ordinary_packet = ordinary.packet();
        publication
            .settle(Completion::from_adapter(
                ordinary,
                Some(2),
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        let before = tx.snapshot();
        assert_eq!(tx.book.numbers.borrow_mut().reject_zero_rtt().unwrap(), 64);
        let after = tx.snapshot();
        assert_eq!(after.bytes_in_flight, 80);
        assert_eq!(after.accepted_bytes, before.accepted_bytes);
        assert_eq!(after.next_packet_number, before.next_packet_number);
        assert_eq!(after.congestion_window, before.congestion_window);
        assert_eq!(after.pto_count, before.pto_count);
        {
            let numbers = tx.book.numbers.borrow();
            assert!(numbers.ledger.sent_packet(early_packet).is_none());
            assert!(numbers.ledger.sent_packet(ordinary_packet).is_some());
            assert_eq!(numbers.last_ack_eliciting[2], Some(2));
        }
        assert_eq!(tx.book.numbers.borrow_mut().reject_zero_rtt().unwrap(), 0);
        let replay = tx.reserve_application(&[1], 0, 64, false, 3).unwrap();
        assert_eq!(replay.packet().value, 2);
        tx.cancel(replay).unwrap();
        retirement.disarm();
        drop(guard);
    }

    #[test]
    fn early_and_application_share_pns_but_early_acks_never_grant_key_updates() {
        // Numerical accounting fixture: the public early entry additionally
        // requires an actual scoped TLS-owned ZeroRtt key.
        book!(book, scope, installation, arena, Side::Client, 172);
        // The real application continuation has bound the authenticated TLS
        // parameters before accepting application acknowledgments.
        book.numbers.borrow_mut().peer_parameters = Some(PeerRecoveryParameters {
            ack_delay_exponent: 3,
            max_ack_delay_us: 25_000,
            idle_timeout_ms: 0,
        });
        let (mut read, _) = crate::crypto::directional::ApplicationReadKeys::install(
            installation,
            key(KeyKind::OneRtt, 8),
            key(KeyKind::OneRtt, 7),
        )
        .unwrap();
        let (mut tx, mut rx, _, mut publication, mut retirement) = book.split().unwrap();
        let guard = NoAlloc::start();
        let cancelled = reserve_kind(
            tx.book,
            PacketKind::ZeroRtt,
            64,
            None,
            true,
            false,
            false,
            0,
            0,
            Some(PlaintextBinding::new(&[1])),
            None,
            false,
        )
        .unwrap();
        assert_eq!(cancelled.packet().value, 0);
        tx.cancel(cancelled).unwrap();
        let early = reserve_kind(
            tx.book,
            PacketKind::ZeroRtt,
            64,
            None,
            true,
            false,
            false,
            1,
            0,
            Some(PlaintextBinding::new(&[1])),
            None,
            false,
        )
        .unwrap();
        assert_eq!(early.packet().value, 1);
        assert_eq!(early.kind(), PacketKind::ZeroRtt);
        publication
            .settle(Completion::from_adapter(
                early,
                Some(1),
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        let ordinary = tx.reserve_application(&[1], 0, 64, false, 2).unwrap();
        assert_eq!(ordinary.packet().value, 2);
        publication
            .settle(Completion::from_adapter(
                ordinary,
                Some(2),
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        let mut plain = [0; 128];
        let len = ack(1, &mut plain);
        let receipt = app_receipt(
            &mut read,
            &mut key(KeyKind::OneRtt, 7),
            0,
            &plain[..len],
            10,
        );
        let outcome = rx
            .apply_application_packet(receipt, &plain[..len], 10, 10, None)
            .unwrap();
        assert_eq!(outcome.newly_acknowledged, 1);
        assert!(outcome.key_acks.iter().all(Option::is_none));
        assert!(outcome.confirmation.is_none());
        assert_eq!(outcome.packets[0].unwrap().value, 1);
        let len = ack(2, &mut plain);
        let receipt = app_receipt(
            &mut read,
            &mut key(KeyKind::OneRtt, 7),
            1,
            &plain[..len],
            11,
        );
        let outcome = rx
            .apply_application_packet(receipt, &plain[..len], 11, 11, None)
            .unwrap();
        assert!(outcome.key_acks.iter().any(Option::is_some));
        assert!(
            outcome.confirmation.is_some(),
            "a real 1-RTT ACK confirms the handshake even when HANDSHAKE_DONE was lost"
        );
        retirement.disarm();
        drop(guard);
    }

    #[test]
    fn application_crypto_is_bound_to_the_retained_flight_and_acked_in_application_space() {
        book!(book, scope, installation, arena, Side::Client, 171);
        let (mut read, _) = crate::crypto::directional::ApplicationReadKeys::install(
            installation,
            key(KeyKind::OneRtt, 8),
            key(KeyKind::OneRtt, 7),
        )
        .unwrap();
        let (mut tx, mut rx, _, mut publication, mut retirement) = book.split().unwrap();
        let guard = NoAlloc::start();
        let completion = tx.completion_observer();
        assert!(completion.ordinary_settled().unwrap());
        let flight = tx.store_crypto(Level::OneRtt, 0, b"ticket").unwrap();
        assert!(!completion.ordinary_settled().unwrap());
        let mut plaintext = [0; 128];
        let len = packet::encode_frame(
            &Frame::Crypto {
                offset: 0,
                data: b"ticket",
            },
            &mut plaintext,
        )
        .unwrap();
        let reservation = tx
            .reserve_application_crypto(&plaintext[..len], 0, 64, flight, false, 0)
            .unwrap();
        assert!(reservation.matches_plaintext(&plaintext[..len]).unwrap());
        assert!(reservation.matches_crypto(0, b"ticket"));
        let pn = reservation.packet().value;
        assert_eq!(
            reservation.packet().space,
            PacketNumberSpace::ApplicationData
        );
        publication
            .settle(Completion::from_adapter(
                reservation,
                Some(0),
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        assert!(!completion.ordinary_settled().unwrap());
        let wrong = packet::encode_frame(
            &Frame::Crypto {
                offset: 1,
                data: b"ticket",
            },
            &mut plaintext,
        )
        .unwrap();
        assert!(matches!(
            tx.reserve_application_crypto(&plaintext[..wrong], 0, 64, flight, false, 1),
            Err(Error::Binding)
        ));
        let len = ack(pn, &mut plaintext);
        let receipt = app_receipt(
            &mut read,
            &mut key(KeyKind::OneRtt, 7),
            0,
            &plaintext[..len],
            10,
        );
        rx.apply_application_packet(receipt, &plaintext[..len], 10, 10, None)
            .unwrap();
        assert_eq!(tx.snapshot().active_flights, 0);
        assert!(completion.ordinary_settled().unwrap());
        retirement.disarm();
        drop(guard);
    }

    #[test]
    fn buffered_ack_delay_preserves_actual_receive_time_and_prevents_rtt_inflation() {
        book!(book, scope, installation, arena, Side::Client, 901);
        let (mut read, _) = ApplicationReadKeys::install(
            installation,
            key(KeyKind::OneRtt, 8),
            key(KeyKind::OneRtt, 7),
        )
        .unwrap();
        let (tx, mut rx, _, _, mut retirement) = book.split().unwrap();
        let receipt = app_receipt(&mut read, &mut key(KeyKind::OneRtt, 7), 0, &[1], 16_020_000);
        rx.apply_application_packet(receipt, &[1], 20_000, 16_020_000, None)
            .unwrap();
        let ack = tx.pending_ack().unwrap();
        assert_eq!(ack.encoded_delay(16_020_000), Ok(2_000_000));
        assert_eq!(
            ack.encoded_delay(19_999),
            Err(Error::Recovery(kernel::RecoveryError::TimeWentBackwards))
        );
        let mut rtt = RttEstimator::new(333_000).unwrap();
        rtt.on_ack(RttSample {
            now: 40_000,
            sent_at: 0,
            ack_delay_us: 0,
            max_ack_delay_us: 25_000,
            space: PacketNumberSpace::Handshake,
            handshake_confirmed: false,
            largest_newly_acknowledged: true,
            any_newly_acknowledged_ack_eliciting: true,
            local_decryption_delay_us: 0,
        })
        .unwrap();
        rtt.on_ack(RttSample {
            now: 16_040_000,
            sent_at: 0,
            ack_delay_us: ack.encoded_delay(16_020_000).unwrap() * 8,
            max_ack_delay_us: 25_000,
            space: PacketNumberSpace::ApplicationData,
            handshake_confirmed: false,
            largest_newly_acknowledged: true,
            any_newly_acknowledged_ack_eliciting: true,
            local_decryption_delay_us: 0,
        })
        .unwrap();
        assert_eq!(rtt.smoothed_us(), 40_000);
        assert!(rtt.pto_duration_us(25_000, 0).unwrap() < 200_000);
        retirement.disarm();
    }

    #[test]
    fn ack_delay_uses_largest_packet_not_latest_duplicate_or_reordered_arrival() {
        let mut history = Received::EMPTY;
        assert!(!history.insert(7, 10).unwrap());
        assert!(history.insert(7, 100).unwrap());
        assert!(!history.insert(3, 200).unwrap());
        assert_eq!(history.largest_received_at, 10);
        assert!(!history.insert(8, 300).unwrap());
        assert_eq!(history.largest_received_at, 300);
        for number in 0..(ACK_CAPACITY as u64 * 2) {
            history.insert(10 + number * 2, 400 + number).unwrap();
        }
        let last = history.largest_received_at;
        assert!(history.insert(0, 10000).unwrap());
        assert_eq!(history.largest_received_at, last);
    }

    #[test]
    fn impossible_receive_time_cannot_change_authenticated_history() {
        book!(book, scope, installation, arena, Side::Client, 902);
        let (tx, mut rx, _, _, mut retirement) = book.split().unwrap();
        let before = tx.snapshot();
        let receipt = initial_receipt(tx.book.scope, &mut key(KeyKind::Initial, 7), 0, &[1]);
        assert_eq!(
            rx.apply_packet(receipt, &[1], 11, 10, None),
            Err(Error::Recovery(kernel::RecoveryError::TimeWentBackwards))
        );
        assert_eq!(tx.snapshot(), before);
        assert!(tx.pending_ack().is_none());
        retirement.disarm();
    }

    #[test]
    fn local_ack_exponent_is_bounded_and_encoding_is_exact() {
        let identity = Identity { _generation: 0 };
        for exponent in [0, 3, 20] {
            let ack = AckSnapshot {
                identity: &identity,
                index: 2,
                revision: 0,
                ranges: [packet::AckRange {
                    smallest: 0,
                    largest: 0,
                }; ACK_CAPACITY],
                len: 1,
                ecn: None,
                largest_received_at: 1,
                delay_exponent: exponent,
            };
            assert_eq!(ack.encoded_delay(10_000_002), Ok(10_000_001 >> exponent));
            if exponent == 0 {
                assert_eq!(ack.encoded_delay(u64::MAX), Err(Error::Capacity));
            }
        }
        let mut scope = ApplicationKeyScope::new(903);
        let mut installation = scope.claim().unwrap();
        assert!(matches!(
            Recovery::<2048>::new(
                installation.take_recovery().unwrap(),
                Side::Client,
                333_000,
                1200,
                21
            ),
            Err(Error::Recovery(kernel::RecoveryError::InvalidConfiguration))
        ));
    }

    #[test]
    fn retained_crypto_can_carry_actual_ack_without_fabricating_peer_delivery() {
        book!(book, scope, installation, arena, Side::Client, 271);
        let (mut read, _) = crate::crypto::directional::ApplicationReadKeys::install(
            installation,
            key(KeyKind::OneRtt, 8),
            key(KeyKind::OneRtt, 7),
        )
        .unwrap();
        let (mut tx, mut rx, _, mut publication, mut retirement) = book.split().unwrap();
        let incoming = [1];
        let receipt = app_receipt(&mut read, &mut key(KeyKind::OneRtt, 7), 7, &incoming, 10);
        rx.apply_application_packet(receipt, &incoming, 10, 10, None)
            .unwrap();
        let ack = tx.ack_for_packet(Level::OneRtt).unwrap();
        let flight = tx.store_crypto(Level::OneRtt, 0, b"ticket").unwrap();
        let mut plain = [0; 128];
        let mut len = packet::encode_frame(
            &Frame::Crypto {
                offset: 0,
                data: b"ticket",
            },
            &mut plain,
        )
        .unwrap();
        len += packet::encode_frame(
            &Frame::Ack {
                delay: 0,
                ranges: packet::AckRanges::new(ack.ranges()).unwrap(),
                ecn: ack.ecn(),
            },
            &mut plain[len..],
        )
        .unwrap();
        let cancelled = tx
            .reserve_application_crypto(&plain[..len], 0, 64, flight, false, 11)
            .unwrap();
        tx.cancel(cancelled).unwrap();
        assert!(
            tx.pending_ack().is_some(),
            "cancelled publication cannot consume ACK evidence"
        );
        let sent = tx
            .reserve_application_crypto(&plain[..len], 0, 64, flight, false, 12)
            .unwrap();
        assert!(sent.matches_crypto(0, b"ticket"));
        assert!(sent.matches_plaintext(&plain[..len]).unwrap());
        publication
            .settle(Completion::from_adapter(
                sent,
                Some(12),
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        publication.acknowledgment_sent(ack).unwrap();
        assert!(tx.pending_ack().is_none());
        assert_eq!(
            tx.snapshot().active_flights,
            1,
            "sending an ACK is not receiving a peer ACK"
        );
        assert!(!tx.completion_observer().ordinary_settled().unwrap());
        retirement.retire_all();
    }

    #[test]
    fn authenticated_ack_releases_crypto_without_refunding_accepted_amplification() {
        book!(book, scope, installation, arena, Side::Server, 71);
        let guard = NoAlloc::start();
        let scope = book.scope();
        let (mut tx, mut rx, _, mut publication, mut retirement) = book.split().unwrap();
        rx.received_datagram(1200).unwrap();
        let flight = tx
            .store_crypto(Level::Initial, 0, b"retained transcript")
            .unwrap();
        let reservation = tx
            .reserve(Level::Initial, 1200, Some(flight), true, true, false, 0)
            .unwrap();
        let pn = reservation.packet().value;
        publication
            .settle(Completion::from_adapter(
                reservation,
                Some(1),
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        let mut plaintext = [0; 64];
        let len = ack(pn, &mut plaintext);
        let receipt = initial_receipt(scope, &mut key(KeyKind::Initial, 7), 0, &plaintext[..len]);
        let outcome = rx
            .apply_packet(receipt, &plaintext[..len], 100, 100, None)
            .unwrap();
        assert_eq!(outcome.newly_acknowledged, 1);
        assert!(!tx.has_outstanding_crypto());
        let snapshot = tx.snapshot();
        assert_eq!(snapshot.bytes_in_flight, 0);
        assert_eq!(snapshot.accepted_bytes, 1200);
        assert_eq!(snapshot.available_bytes, 2400);
        retirement.disarm();
        guard.finish();
    }

    #[test]
    fn ecn_feedback_uses_actual_marking_and_ignores_reordered_ack_counts() {
        book!(book, scope, installation, arena, Side::Client, 194);
        let scope = book.scope();
        let (mut tx, mut rx, _, mut publication, mut retirement) = book.split().unwrap();
        let observer = tx.completion_observer();
        for now in 0..4 {
            let pending = tx
                .reserve(Level::Initial, 1200, None, true, true, false, now)
                .unwrap();
            publication
                .settle(Completion::from_adapter(
                    pending,
                    Some(now),
                    crate::quic::ecn::Codepoint::Ect0,
                ))
                .unwrap();
        }
        let mut peer_key = key(KeyKind::Initial, 7);
        let mut plain = [0; 128];
        for (incoming, largest, counts) in [
            (
                0,
                2,
                Some(packet::EcnCounts {
                    ect0: 1,
                    ect1: 0,
                    ce: 0,
                }),
            ),
            (1, 1, None),
            (
                2,
                3,
                Some(packet::EcnCounts {
                    ect0: 3,
                    ect1: 0,
                    ce: 0,
                }),
            ),
        ] {
            let len = packet::encode_frame(
                &Frame::Ack {
                    delay: 0,
                    ranges: packet::AckRanges::new(&[packet::AckRange {
                        smallest: largest,
                        largest,
                    }])
                    .unwrap(),
                    ecn: counts,
                },
                &mut plain,
            )
            .unwrap();
            let receipt = initial_receipt(scope, &mut peer_key, incoming, &plain[..len]);
            rx.apply_packet(
                receipt,
                &plain[..len],
                10 + incoming,
                10 + incoming,
                Some(crate::quic::ecn::Codepoint::NotEct),
            )
            .unwrap();
            assert!(observer.ecn_observation().unwrap().first_failure.is_none());
        }
        let evidence = observer.ecn_observation().unwrap();
        assert_eq!(evidence.accepted, 4);
        assert_eq!(evidence.validated, 2);
        assert_eq!(evidence.first_sent_at, Some(0));
        assert!(evidence.probe_period > 0);
        let next = tx
            .reserve(Level::Initial, 1200, None, true, true, false, 13)
            .unwrap();
        let pn = next.packet().value;
        publication
            .settle(Completion::from_adapter(
                next,
                Some(13),
                crate::quic::ecn::Codepoint::Ect0,
            ))
            .unwrap();
        let len = ack(pn, &mut plain);
        let receipt = initial_receipt(scope, &mut peer_key, 3, &plain[..len]);
        rx.apply_packet(
            receipt,
            &plain[..len],
            14,
            14,
            Some(crate::quic::ecn::Codepoint::NotEct),
        )
        .unwrap();
        let evidence = observer.ecn_observation().unwrap();
        assert_eq!(evidence.accepted, 5);
        let failure = evidence.first_failure.unwrap();
        assert_eq!(failure.largest, pn);
        assert_eq!(
            failure.reason,
            crate::quic::ecn::Error::Validation(crate::quic::ecn::Failure::MissingCounts)
        );
        retirement.disarm();
    }

    #[test]
    fn ecn_ce_reduces_congestion_once_but_reordered_counts_do_not() {
        book!(book, scope, installation, arena, Side::Client, 195);
        let scope = book.scope();
        let (mut tx, mut rx, _, mut publication, mut retirement) = book.split().unwrap();
        for now in 0..4 {
            let pending = tx
                .reserve(Level::Initial, 1200, None, true, true, false, now)
                .unwrap();
            publication
                .settle(Completion::from_adapter(
                    pending,
                    Some(now),
                    crate::quic::ecn::Codepoint::Ect0,
                ))
                .unwrap();
        }
        let before = tx.snapshot().congestion_window;
        let mut peer_key = key(KeyKind::Initial, 7);
        let mut plain = [0; 128];
        for (incoming, largest, ect0, ce) in [(0, 2, 0, 1), (1, 1, 0, 999), (2, 3, 1, 1)] {
            let len = packet::encode_frame(
                &Frame::Ack {
                    delay: 0,
                    ranges: packet::AckRanges::new(&[packet::AckRange {
                        smallest: largest,
                        largest,
                    }])
                    .unwrap(),
                    ecn: Some(packet::EcnCounts { ect0, ect1: 0, ce }),
                },
                &mut plain,
            )
            .unwrap();
            let receipt = initial_receipt(scope, &mut peer_key, incoming, &plain[..len]);
            rx.apply_packet(
                receipt,
                &plain[..len],
                10 + incoming,
                10 + incoming,
                Some(crate::quic::ecn::Codepoint::NotEct),
            )
            .unwrap();
            assert!(
                tx.completion_observer()
                    .ecn_observation()
                    .unwrap()
                    .first_failure
                    .is_none()
            );
            assert_eq!(tx.snapshot().congestion_window, before / 2);
        }
        retirement.disarm();
    }

    #[test]
    fn authenticated_ecn_counts_once_and_missing_metadata_disables_ack_ecn() {
        use crate::quic::ecn::Codepoint;
        book!(book, scope, installation, arena, Side::Client, 740);
        let scope = book.scope();
        let (tx, mut rx, _, _, mut retirement) = book.split().unwrap();
        let plaintext = [1]; // PING is ACK-eliciting.
        let first = initial_receipt(scope, &mut key(KeyKind::Initial, 7), 0, &plaintext);
        assert!(
            !rx.apply_packet(first, &plaintext, 0, 0, Some(Codepoint::Ect0))
                .unwrap()
                .duplicate
        );
        assert_eq!(
            tx.pending_ack().unwrap().ecn(),
            Some(packet::EcnCounts {
                ect0: 1,
                ect1: 0,
                ce: 0
            })
        );
        let replay = initial_receipt(scope, &mut key(KeyKind::Initial, 7), 0, &plaintext);
        assert!(
            rx.apply_packet(replay, &plaintext, 1, 1, Some(Codepoint::Ce))
                .unwrap()
                .duplicate
        );
        assert_eq!(
            tx.pending_ack().unwrap().ecn(),
            Some(packet::EcnCounts {
                ect0: 1,
                ect1: 0,
                ce: 0
            })
        );
        let next = initial_receipt(scope, &mut key(KeyKind::Initial, 7), 1, &plaintext);
        rx.apply_packet(next, &plaintext, 2, 2, Some(Codepoint::Ce))
            .unwrap();
        assert_eq!(
            tx.pending_ack().unwrap().ecn(),
            Some(packet::EcnCounts {
                ect0: 1,
                ect1: 0,
                ce: 1
            })
        );
        let unknown = initial_receipt(scope, &mut key(KeyKind::Initial, 7), 2, &plaintext);
        rx.apply_packet(unknown, &plaintext, 3, 3, None).unwrap();
        assert_eq!(tx.pending_ack().unwrap().ecn(), None);
        let known_again = initial_receipt(scope, &mut key(KeyKind::Initial, 7), 3, &plaintext);
        rx.apply_packet(known_again, &plaintext, 4, 4, Some(Codepoint::Ect1))
            .unwrap();
        assert_eq!(
            tx.pending_ack().unwrap().ecn(),
            None,
            "missing history must not become fabricated Not-ECT"
        );
        retirement.disarm();
    }

    #[test]
    fn ecn_metadata_without_matching_authentication_cannot_create_an_ack_count() {
        book!(book, scope, installation, arena, Side::Client, 741);
        let scope = book.scope();
        let (tx, mut rx, _, _, mut retirement) = book.split().unwrap();
        let receipt = initial_receipt(scope, &mut key(KeyKind::Initial, 7), 0, &[1]);
        assert_eq!(
            rx.apply_packet(receipt, &[0], 0, 0, Some(crate::quic::ecn::Codepoint::Ect0)),
            Err(Error::Binding)
        );
        assert!(tx.pending_ack().is_none());
        let valid = initial_receipt(scope, &mut key(KeyKind::Initial, 7), 0, &[1]);
        rx.apply_packet(valid, &[1], 1, 1, Some(crate::quic::ecn::Codepoint::Ect1))
            .unwrap();
        assert_eq!(
            tx.pending_ack().unwrap().ecn(),
            Some(packet::EcnCounts {
                ect0: 0,
                ect1: 1,
                ce: 0
            })
        );
        retirement.disarm();
    }

    #[test]
    fn retry_numeric_join_preserves_crypto_pn_and_actual_path_bytes() {
        book!(book, scope, installation, arena, Side::Client, 730);
        let (mut tx, mut rx, mut clock, mut publication, mut retirement) = book.split().unwrap();
        let flight = tx
            .store_crypto(Level::Initial, 0, b"same ClientHello")
            .unwrap();
        let first = tx
            .reserve(Level::Initial, 1200, Some(flight), true, true, false, 0)
            .unwrap();
        publication
            .settle(Completion::from_adapter(
                first,
                Some(0),
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        rx.received_datagram(160).unwrap();
        let deadline = clock.update(0, [true, false]).unwrap().unwrap();
        let before = tx.snapshot();
        tx.retry_initial(100).unwrap();
        let after = tx.snapshot();
        assert_eq!(after.next_packet_number, before.next_packet_number);
        assert_eq!(after.received_bytes, 160);
        assert_eq!(after.accepted_bytes, 1200);
        assert_eq!(after.bytes_in_flight, 0);
        assert_eq!(after.active_flights, 1);
        assert_eq!(after.pto_count, 0);
        assert_eq!(tx.flight_data(flight).unwrap().bytes(), b"same ClientHello");
        assert_eq!(tx.next_retransmit(), Some((flight, false)));
        assert!(matches!(
            clock.expire(deadline, 100),
            Err(Error::StaleDeadline)
        ));
        let next = tx
            .reserve(Level::Initial, 1200, Some(flight), true, true, false, 100)
            .unwrap();
        assert_eq!(next.packet().value, 1);
        publication
            .settle(Completion::from_adapter(
                next,
                Some(100),
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        retirement.disarm();
    }

    #[test]
    fn retry_numeric_join_rejects_pending_publication_without_mutation() {
        book!(book, scope, installation, arena, Side::Client, 731);
        let (mut tx, _, _, mut publication, mut retirement) = book.split().unwrap();
        let flight = tx.store_crypto(Level::Initial, 0, b"retained").unwrap();
        let pending = tx
            .reserve(Level::Initial, 1200, Some(flight), true, true, false, 0)
            .unwrap();
        let before = tx.snapshot();
        assert_eq!(tx.retry_initial(100), Err(Error::PendingInitialPublication));
        assert_eq!(tx.snapshot(), before);
        publication.cancel(pending).unwrap();
        tx.retry_initial(100).unwrap();
        assert_eq!(tx.flight_data(flight).unwrap().bytes(), b"retained");
        assert_eq!(tx.snapshot().next_packet_number[0], Some(1));
        retirement.disarm();
    }

    #[test]
    fn server_initial_probe_hands_remaining_credit_to_handshake_only_after_acceptance() {
        book!(book, scope, installation, arena, Side::Server, 723);
        let (mut tx, mut rx, mut clock, mut publication, mut retirement) = book.split().unwrap();
        rx.received_datagram(5000).unwrap();
        for level in [Level::Initial, Level::Handshake] {
            let packet = tx
                .reserve(level, 1200, None, true, false, false, 0)
                .unwrap();
            publication
                .settle(Completion::from_adapter(
                    packet,
                    Some(0),
                    crate::quic::ecn::Codepoint::NotEct,
                ))
                .unwrap();
        }
        let deadline = clock.update(0, [true, true]).unwrap().unwrap();
        let at = deadline.at();
        clock.expire(deadline, at).unwrap();
        assert_eq!(tx.pending_probe(), Some(Level::Initial));
        let cancelled = tx
            .reserve(Level::Initial, 1200, None, true, false, true, at)
            .unwrap();
        publication.cancel(cancelled).unwrap();
        assert_eq!(tx.pending_probe(), Some(Level::Initial));
        assert_eq!(tx.snapshot().probe_credits, 2);
        let first = tx
            .reserve(Level::Initial, 1200, None, true, false, true, at)
            .unwrap();
        publication
            .settle(Completion::from_adapter(
                first,
                Some(at),
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        assert_eq!(tx.pending_probe(), Some(Level::Handshake));
        assert_eq!(tx.snapshot().probe_credits, 1);
        let cancelled = tx
            .reserve(Level::Handshake, 1200, None, true, false, true, at)
            .unwrap();
        publication.cancel(cancelled).unwrap();
        assert_eq!(tx.pending_probe(), Some(Level::Handshake));
        assert_eq!(tx.snapshot().probe_credits, 1);
        let second = tx
            .reserve(Level::Handshake, 1200, None, true, false, true, at)
            .unwrap();
        publication
            .settle(Completion::from_adapter(
                second,
                Some(at),
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        assert_eq!(tx.snapshot().probe_credits, 0);
        assert!(
            tx.reserve(Level::Handshake, 1200, None, true, false, true, at)
                .is_err()
        );
        retirement.disarm();
    }

    #[test]
    fn handshake_probe_publication_hands_second_credit_to_one_rtt_and_cancel_preserves_it() {
        book!(book, scope, installation, arena, Side::Client, 722);
        let (mut tx, _, mut clock, mut publication, mut retirement) = book.split().unwrap();
        let app = tx.reserve_application(&[1], 0, 64, false, 0).unwrap();
        publication
            .settle(Completion::from_adapter(
                app,
                Some(0),
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        let handshake = tx
            .reserve(Level::Handshake, 64, None, true, false, false, 0)
            .unwrap();
        publication
            .settle(Completion::from_adapter(
                handshake,
                Some(0),
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        let deadline = clock
            .update_application(0, [false, true, true])
            .unwrap()
            .unwrap();
        let at = deadline.at();
        clock.expire(deadline, at).unwrap();
        assert_eq!(tx.pending_probe(), Some(Level::Handshake));
        let cancelled = tx
            .reserve(Level::Handshake, 64, None, true, false, true, at)
            .unwrap();
        assert_eq!(tx.pending_probe(), Some(Level::Handshake));
        publication.cancel(cancelled).unwrap();
        assert_eq!(tx.snapshot().probe_credits, 2);
        let first = tx
            .reserve(Level::Handshake, 64, None, true, false, true, at)
            .unwrap();
        publication
            .settle(Completion::from_adapter(
                first,
                Some(at),
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        assert_eq!(tx.pending_probe(), Some(Level::OneRtt));
        assert_eq!(tx.snapshot().probe_credits, 1);
        let cancelled = tx.reserve_application(&[1], 0, 64, true, at).unwrap();
        publication.cancel(cancelled).unwrap();
        assert_eq!(tx.pending_probe(), Some(Level::OneRtt));
        assert_eq!(tx.snapshot().probe_credits, 1);
        let second = tx.reserve_application(&[1], 0, 64, true, at).unwrap();
        publication
            .settle(Completion::from_adapter(
                second,
                Some(at),
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        assert_eq!(tx.pending_probe(), None);
        assert_eq!(tx.snapshot().probe_credits, 0);
        assert!(tx.reserve_application(&[1], 0, 64, true, at).is_err());
        retirement.disarm();
    }

    #[test]
    fn empty_flight_handshake_pto_has_two_actual_publications_and_no_third_credit() {
        book!(book, scope, installation, arena, Side::Client, 721);
        let (mut tx, _, mut clock, mut publication, mut retirement) = book.split().unwrap();
        let deadline = clock.update(0, [true, true]).unwrap().unwrap();
        let at = deadline.at();
        assert!(matches!(
            clock.expire(deadline, at).unwrap(),
            Some(TimeoutAction::Probe {
                space: PacketNumberSpace::Handshake,
                max_datagrams: 2,
                ..
            })
        ));
        for number in 0..2 {
            let probe = tx
                .reserve(Level::Handshake, 64, None, true, false, true, at)
                .unwrap();
            assert_eq!(probe.packet().value, number);
            publication
                .settle(Completion::from_adapter(
                    probe,
                    Some(at),
                    crate::quic::ecn::Codepoint::NotEct,
                ))
                .unwrap();
        }
        assert_eq!(tx.snapshot().probe_credits, 0);
        assert!(
            tx.reserve(Level::Handshake, 64, None, true, false, true, at)
                .is_err()
        );
        retirement.disarm();
    }

    #[test]
    fn lost_first_flight_pto_retains_data_burns_new_numbers_and_refunds_rejected_probe() {
        book!(book, scope, installation, arena, Side::Client, 72);
        let (mut tx, _, mut clock, mut publication, mut retirement) = book.split().unwrap();
        let flight = tx.store_crypto(Level::Initial, 0, b"first").unwrap();
        let first = tx
            .reserve(Level::Initial, 1200, Some(flight), true, true, false, 0)
            .unwrap();
        publication
            .settle(Completion::from_adapter(
                first,
                Some(0),
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        let deadline = clock.update(0, [true, false]).unwrap().unwrap();
        let at = deadline.at();
        assert!(matches!(
            clock.expire(deadline, at).unwrap(),
            Some(TimeoutAction::Probe { .. })
        ));
        assert_eq!(tx.snapshot().bytes_in_flight, 1200);
        assert_eq!(tx.next_retransmit(), Some((flight, true)));
        let credits = tx.snapshot().probe_credits;
        let rejected = tx
            .reserve(Level::Initial, 1200, Some(flight), true, true, true, at)
            .unwrap();
        assert_eq!(rejected.packet().value, 1);
        publication
            .settle(Completion::from_adapter(
                rejected,
                None,
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        assert_eq!(tx.snapshot().probe_credits, credits);
        let retry = tx
            .reserve(Level::Initial, 1200, Some(flight), true, true, true, at)
            .unwrap();
        assert_eq!(retry.packet().value, 2);
        assert!(retry.matches_crypto(0, b"first"));
        publication
            .settle(Completion::from_adapter(
                retry,
                Some(at),
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        assert_eq!(tx.snapshot().bytes_in_flight, 2400);
        retirement.disarm();
    }

    #[test]
    fn delayed_adapter_completion_keeps_real_send_time_after_later_rx_and_timer_observations() {
        book!(book, scope, installation, arena, Side::Client, 85);
        let own_scope = book.scope();
        let (mut tx, mut rx, mut clock, mut publication, mut retirement) = book.split().unwrap();
        let flight = tx
            .store_crypto(Level::Initial, 0, b"delayed acceptance")
            .unwrap();
        let reservation = tx
            .reserve(Level::Initial, 1200, Some(flight), true, true, false, 10)
            .unwrap();
        let packet = reservation.packet();
        let stale = clock.update(30, [true, false]).unwrap().unwrap();
        let receipt = initial_receipt(own_scope, &mut key(KeyKind::Initial, 7), 0, &[1]);
        rx.apply_packet(receipt, &[1], 40, 40, None).unwrap();
        publication
            .settle(Completion::from_adapter(
                reservation,
                Some(20),
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        {
            let numbers = tx.book.numbers.borrow();
            assert_eq!(numbers.last_now, Some(40));
            assert_eq!(numbers.ledger.sent_at(packet), Some(20));
            assert_eq!(numbers.flights.sent_at(packet), Some(20));
            assert_eq!(numbers.last_ack_eliciting[0], Some(20));
        }
        assert_eq!(tx.snapshot().next_packet_number[0], Some(1));
        assert!(matches!(clock.expire(stale, 40), Err(Error::StaleDeadline)));
        let deadline = clock.update(40, [true, false]).unwrap().unwrap();
        assert_eq!(deadline.at(), 20 + 999_000);
        // Ordinary callers still supply current clock readings. Historical
        // completion handling does not relax their monotonic-time contract.
        assert!(matches!(
            tx.reserve(Level::Initial, 1200, None, true, true, false, 39),
            Err(Error::Recovery(kernel::RecoveryError::TimeWentBackwards))
        ));
        assert_eq!(tx.snapshot().next_packet_number[0], Some(1));
        retirement.disarm();
    }

    #[test]
    fn completion_before_reservation_preparation_is_rejected_without_acceptance_effects() {
        book!(book, scope, installation, arena, Side::Client, 86);
        let (mut tx, _, mut clock, mut publication, mut retirement) = book.split().unwrap();
        let reservation = tx
            .reserve(Level::Initial, 1200, None, true, true, false, 10)
            .unwrap();
        let packet = reservation.packet();
        clock.update(30, [true, false]).unwrap();
        let before = tx.snapshot();
        assert_eq!(
            publication.settle(Completion::from_adapter(
                reservation,
                Some(9),
                crate::quic::ecn::Codepoint::NotEct
            )),
            Err(Error::Recovery(kernel::RecoveryError::TimeWentBackwards))
        );
        assert_eq!(tx.snapshot(), before);
        let numbers = tx.book.numbers.borrow();
        assert_eq!(numbers.last_now, Some(30));
        assert_eq!(numbers.ledger.sent_at(packet), None);
        drop(numbers);
        // Invalid adapter evidence terminates this run; it cannot be changed
        // into a successful send or silently reclaimed for ordinary reuse.
        retirement.retire_all();
        assert_eq!(tx.snapshot().next_packet_number[0], Some(1));
        assert_eq!(tx.snapshot().reserved_bytes, 0);
    }

    #[test]
    fn buffered_authenticated_ack_excludes_local_key_wait_from_rtt() {
        book!(book, scope, installation, arena, Side::Client, 902);
        let own_scope = book.scope();
        let (mut tx, mut rx, _, mut publication, mut retirement) = book.split().unwrap();
        let sent = tx
            .reserve(Level::Initial, 1200, None, true, true, false, 0)
            .unwrap();
        let pn = sent.packet().value;
        publication
            .settle(Completion::from_adapter(
                sent,
                Some(10_000),
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        let mut plaintext = [0; 64];
        let len = ack(pn, &mut plaintext);
        let receipt = initial_receipt(
            own_scope,
            &mut key(KeyKind::Initial, 7),
            0,
            &plaintext[..len],
        );
        // Arrival is 40 ms after publication. Processing waits another 16 s.
        rx.apply_packet(receipt, &plaintext[..len], 50_000, 16_050_000, None)
            .unwrap();
        let n = tx.book.numbers.borrow();
        assert_eq!(n.rtt.latest_us(), 40_000);
        assert_eq!(n.rtt.smoothed_us(), 40_000);
        assert_eq!(n.last_now, Some(16_050_000));
        drop(n);
        retirement.disarm();
    }

    #[test]
    fn reordered_completion_callbacks_preserve_pn_send_times_latest_pto_and_rtt_sample() {
        book!(book, scope, installation, arena, Side::Client, 87);
        let own_scope = book.scope();
        let (mut tx, mut rx, mut clock, mut publication, mut retirement) = book.split().unwrap();
        let first = tx
            .reserve(Level::Initial, 1200, None, true, true, false, 0)
            .unwrap();
        let first_packet = first.packet();
        let second = tx
            .reserve(Level::Initial, 1200, None, true, true, false, 1)
            .unwrap();
        let second_packet = second.packet();
        publication
            .settle(Completion::from_adapter(
                second,
                Some(20),
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        clock.update(30, [true, false]).unwrap();
        publication
            .settle(Completion::from_adapter(
                first,
                Some(10),
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        {
            let numbers = tx.book.numbers.borrow();
            assert_eq!(numbers.ledger.sent_at(first_packet), Some(10));
            assert_eq!(numbers.ledger.sent_at(second_packet), Some(20));
            assert_eq!(numbers.last_ack_eliciting[0], Some(20));
            assert_eq!(numbers.last_now, Some(30));
        }
        assert_eq!(tx.snapshot().next_packet_number[0], Some(2));
        assert_eq!(
            clock.update(30, [true, false]).unwrap().unwrap().at(),
            20 + 999_000
        );
        let mut plaintext = [0; 64];
        let len = ack(first_packet.value, &mut plaintext);
        let receipt = initial_receipt(
            own_scope,
            &mut key(KeyKind::Initial, 7),
            0,
            &plaintext[..len],
        );
        rx.apply_packet(receipt, &plaintext[..len], 40, 40, None)
            .unwrap();
        // RTT uses actual acceptance at 10, not callback processing after 30.
        assert_eq!(tx.book.numbers.borrow().rtt.latest_us(), 30);
        assert_eq!(tx.snapshot().bytes_in_flight, 1200);
        retirement.disarm();
    }

    #[test]
    fn delayed_acceptance_rechecks_loss_after_a_later_packet_was_acknowledged() {
        book!(book, scope, installation, arena, Side::Client, 88);
        let (mut read, _) = crate::crypto::directional::ApplicationReadKeys::install(
            installation,
            key(KeyKind::OneRtt, 8),
            key(KeyKind::OneRtt, 9),
        )
        .unwrap();
        let mut peer = key(KeyKind::OneRtt, 9);
        let (mut tx, mut rx, _, mut publication, mut retirement) = book.split().unwrap();
        let delayed = tx.reserve_application(&[1], 0, 32, false, 0).unwrap();
        let delayed_packet = delayed.packet();
        // Prepare all packets before processing their completion callbacks.
        let second = tx.reserve_application(&[1], 0, 32, false, 1).unwrap();
        let third = tx.reserve_application(&[1], 0, 32, false, 2).unwrap();
        let fourth = tx.reserve_application(&[1], 0, 32, false, 3).unwrap();
        publication
            .settle(Completion::from_adapter(
                second,
                Some(11),
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        publication
            .settle(Completion::from_adapter(
                third,
                Some(12),
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        publication
            .settle(Completion::from_adapter(
                fourth,
                Some(13),
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        let mut plaintext = [0; 64];
        let len = ack(3, &mut plaintext);
        let receipt = app_receipt(&mut read, &mut peer, 0, &plaintext[..len], 20);
        rx.apply_application_packet(receipt, &plaintext[..len], 20, 20, None)
            .unwrap();
        assert_eq!(tx.take_lost_application().map(|grant| grant.packet()), None);
        assert_eq!(tx.snapshot().reserved_in_flight, 32);
        publication
            .settle(Completion::from_adapter(
                delayed,
                Some(10),
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        // Only now does PN 0 carry actual accepted-send evidence; its three
        // genuinely accepted successors already establish packet-threshold loss.
        assert_eq!(
            tx.take_lost_application().map(|grant| grant.packet()),
            Some(delayed_packet)
        );
        assert_eq!(tx.take_lost_application().map(|grant| grant.packet()), None);
        assert_eq!(tx.snapshot().history_floor[2], 1);
        assert_eq!(tx.snapshot().bytes_in_flight, 64);
        assert_eq!(tx.snapshot().accepted_bytes, 128);
        assert_eq!(tx.snapshot().next_packet_number[2], Some(4));
        let numbers = tx.book.numbers.borrow();
        assert_eq!(numbers.last_now, Some(20));
        assert_eq!(numbers.last_ack_eliciting[2], Some(13));
        assert_eq!(numbers.rtt.latest_us(), 7);
        drop(numbers);
        retirement.disarm();
    }

    #[test]
    fn reserved_cancelled_foreign_or_changed_ack_never_mutates_sent_history() {
        book!(book, scope, installation, arena, Side::Client, 73);
        let own_scope = book.scope();
        let foreign = ApplicationKeyScope::new(73);
        let (mut tx, mut rx, _, _, mut retirement) = book.split().unwrap();
        let mut peer = key(KeyKind::Initial, 7);
        let reservation = tx
            .reserve(Level::Initial, 1200, None, true, true, false, 0)
            .unwrap();
        let mut plaintext = [0; 64];
        let len = ack(reservation.packet().value, &mut plaintext);
        let receipt = initial_receipt(own_scope, &mut peer, 0, &plaintext[..len]);
        assert_eq!(
            rx.apply_packet(receipt, &plaintext[..len], 1, 1, None),
            Err(Error::Accounting(AccountingError::UnsentPacket))
        );
        let before = tx.snapshot();
        let receipt = initial_receipt(&foreign, &mut peer, 1, &plaintext[..len]);
        assert_eq!(
            rx.apply_packet(receipt, &plaintext[..len], 1, 1, None),
            Err(Error::Binding)
        );
        let receipt = initial_receipt(own_scope, &mut peer, 2, &plaintext[..len]);
        assert_eq!(
            rx.apply_packet(receipt, &[1], 1, 1, None),
            Err(Error::Binding)
        );
        assert_eq!(tx.snapshot(), before);
        tx.cancel(reservation).unwrap();
        let receipt = initial_receipt(own_scope, &mut peer, 3, &plaintext[..len]);
        assert_eq!(
            rx.apply_packet(receipt, &plaintext[..len], 2, 2, None),
            Err(Error::Accounting(AccountingError::UnsentPacket))
        );
        retirement.disarm();
    }

    #[test]
    fn ack_only_receive_is_available_for_piggyback_without_an_ack_loop() {
        book!(book, scope, installation, arena, Side::Client, 7401);
        let own_scope = book.scope();
        let (mut tx, mut rx, _, mut publication, mut retirement) = book.split().unwrap();
        let reservation = tx
            .reserve(Level::Initial, 1200, None, true, true, false, 0)
            .unwrap();
        publication
            .settle(Completion::from_adapter(
                reservation,
                Some(0),
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        let mut plaintext = [0; 64];
        let len = ack(0, &mut plaintext);
        let mut peer = key(KeyKind::Initial, 7);
        let receipt = initial_receipt(own_scope, &mut peer, 3, &plaintext[..len]);
        rx.apply_packet(receipt, &plaintext[..len], 1, 1, None)
            .unwrap();
        assert!(
            tx.pending_ack().is_none(),
            "ACK-only input must not start an ACK loop"
        );
        let carried = tx
            .ack_for_packet(Level::Initial)
            .expect("next outgoing probe must be able to carry received ACK-only packet ranges");
        assert_eq!(
            carried.ranges(),
            &[packet::AckRange {
                smallest: 3,
                largest: 3
            }]
        );
        assert!(tx.ack_for_packet(Level::Handshake).is_none());
        let receipt = initial_receipt(own_scope, &mut peer, 4, &[1]);
        rx.apply_packet(receipt, &[1], 2, 2, None).unwrap();
        publication.acknowledgment_sent(carried).unwrap();
        assert!(
            tx.pending_ack().is_some(),
            "old piggyback cannot clear a later eliciting packet"
        );
        retirement.disarm();
    }

    #[test]
    fn authenticated_ack_invalidates_a_stale_timer_and_ack_snapshot() {
        book!(book, scope, installation, arena, Side::Client, 74);
        let own_scope = book.scope();
        let (mut tx, mut rx, mut clock, mut publication, mut retirement) = book.split().unwrap();
        let reservation = tx
            .reserve(Level::Initial, 1200, None, true, true, false, 0)
            .unwrap();
        publication
            .settle(Completion::from_adapter(
                reservation,
                Some(0),
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        let deadline = clock.update(0, [true, false]).unwrap().unwrap();
        let at = deadline.at();
        let mut peer = key(KeyKind::Initial, 7);
        let receipt = initial_receipt(own_scope, &mut peer, 0, &[1]);
        rx.apply_packet(receipt, &[1], 1, 1, None).unwrap();
        let old_ack = tx.pending_ack().unwrap();
        let receipt = initial_receipt(own_scope, &mut peer, 2, &[1]);
        rx.apply_packet(receipt, &[1], 2, 2, None).unwrap();
        publication.acknowledgment_sent(old_ack).unwrap();
        assert!(tx.pending_ack().is_some());
        let mut plaintext = [0; 64];
        let len = ack(0, &mut plaintext);
        let receipt = initial_receipt(own_scope, &mut peer, 3, &plaintext[..len]);
        rx.apply_packet(receipt, &plaintext[..len], 3, 3, None)
            .unwrap();
        assert!(matches!(
            clock.expire(deadline, at),
            Err(Error::StaleDeadline)
        ));
        retirement.disarm();
    }

    #[test]
    fn completion_observer_waits_for_current_ack_acceptance_and_every_pending_publication() {
        book!(book, scope, installation, arena, Side::Client, 84);
        let own_scope = book.scope();
        let (mut tx, mut rx, _, mut publication, mut retirement) = book.split().unwrap();
        let observer = tx.completion_observer();
        assert!(observer.ordinary_settled().unwrap());
        assert!(!observer.handshake_confirmed().unwrap());
        let pending = tx.reserve_application(&[1], 0, 32, false, 0).unwrap();
        assert!(!observer.ordinary_settled().unwrap());
        publication.cancel(pending).unwrap();
        assert!(observer.ordinary_settled().unwrap());

        let mut peer = key(KeyKind::Initial, 7);
        let receipt = initial_receipt(own_scope, &mut peer, 0, &[1]);
        rx.apply_packet(receipt, &[1], 1, 1, None).unwrap();
        let stale_ack = tx.pending_ack().unwrap();
        assert!(!observer.ordinary_settled().unwrap());
        let receipt = initial_receipt(own_scope, &mut peer, 1, &[1]);
        rx.apply_packet(receipt, &[1], 2, 2, None).unwrap();
        let send = tx
            .reserve(Level::Initial, 1200, None, false, true, false, 2)
            .unwrap();
        publication
            .settle(Completion::from_adapter(
                send,
                Some(2),
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        publication.acknowledgment_sent(stale_ack).unwrap();
        assert!(!observer.ordinary_settled().unwrap());

        let send = tx
            .reserve(Level::Initial, 1200, None, false, true, false, 3)
            .unwrap();
        publication
            .settle(Completion::from_adapter(
                send,
                None,
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        assert!(!observer.ordinary_settled().unwrap());
        let current_ack = tx.pending_ack().unwrap();
        let send = tx
            .reserve(Level::Initial, 1200, None, false, true, false, 4)
            .unwrap();
        assert!(!observer.ordinary_settled().unwrap());
        publication
            .settle(Completion::from_adapter(
                send,
                Some(4),
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        assert!(!observer.ordinary_settled().unwrap());
        publication.acknowledgment_sent(current_ack).unwrap();
        assert!(observer.ordinary_settled().unwrap());
        assert!(!observer.handshake_confirmed().unwrap());
        retirement.retire_all();
        assert_eq!(
            observer.ordinary_settled(),
            Err(Error::Accounting(AccountingError::Retired))
        );
        assert_eq!(
            observer.handshake_confirmed(),
            Err(Error::Accounting(AccountingError::Retired))
        );
    }

    #[test]
    fn gapped_receive_history_remains_bounded_without_terminating_transfer() {
        let mut ranges = Received::EMPTY;
        for pn in 0..(ACK_CAPACITY as u64 * 4) {
            assert!(
                ranges.insert(pn * 2, 0).is_ok(),
                "a legal loss gap must not terminate the connection"
            );
            assert!(ranges.len <= ACK_CAPACITY);
            assert_eq!(ranges.ranges[0].largest, pn * 2);
        }
        assert!(
            ranges.insert(0, 0).unwrap(),
            "discarded packet numbers cannot be accepted again"
        );
    }

    #[test]
    fn bounded_ranges_reorder_merge_without_acknowledging_gaps() {
        let mut ranges = Received::EMPTY;
        for pn in 0..ACK_CAPACITY as u64 {
            ranges.insert(pn * 2, 0).unwrap();
        }
        ranges.insert(1, 0).unwrap();
        assert_eq!(ranges.len, ACK_CAPACITY - 1);
        assert!(ranges.insert(2, 0).unwrap());
    }

    #[test]
    fn aggregate_cancellation_clears_reservations_and_preserves_burned_packet_numbers() {
        book!(book, scope, installation, arena, Side::Client, 75);
        {
            let (mut tx, _, _, _, retirement) = book.split().unwrap();
            let r = tx.reserve_application(&[1], 0, 32, false, 0).unwrap();
            assert_eq!(r.packet().value, 0);
            drop(r);
            drop(retirement);
            assert_eq!(tx.snapshot().pending_publications, [0; 3]);
            assert_eq!(tx.snapshot().reserved_in_flight, 0);
            assert_eq!(tx.snapshot().reserved_bytes, 0);
            assert_eq!(tx.snapshot().next_packet_number[2], Some(1));
            assert!(matches!(
                tx.reserve_application(&[1], 0, 32, false, 0),
                Err(Error::Accounting(AccountingError::Retired))
            ));
        }
        assert!(book.split().is_err());
        assert!(installation.take_recovery().is_err());
    }

    #[test]
    fn failed_recovery_construction_consumes_the_one_shot_scope_claim() {
        let mut scope = ApplicationKeyScope::new(82);
        let mut installation = scope.claim().unwrap();
        assert!(matches!(
            Recovery::<2048>::new(
                installation.take_recovery().unwrap(),
                Side::Client,
                0,
                1200,
                3
            ),
            Err(Error::Recovery(kernel::RecoveryError::InvalidConfiguration))
        ));
        assert!(installation.take_recovery().is_err());
    }

    #[test]
    fn outstanding_data_backpressure_preserves_actual_pto_publication() {
        book!(book, scope, installation, arena, Side::Client, 178);
        book.numbers.borrow_mut().handshake_confirmed = true;
        let (mut tx, _, mut clock, mut publication, mut retirement) = book.split().unwrap();
        let mut admitted = 0;
        for now in 0..LEDGER_CAPACITY as u64 {
            match tx.reserve_application(&[1], 0, 64, false, now) {
                Ok(packet) => {
                    publication
                        .settle(Completion::from_adapter(
                            packet,
                            Some(now),
                            crate::quic::ecn::Codepoint::NotEct,
                        ))
                        .unwrap();
                    admitted += 1;
                }
                Err(Error::Accounting(AccountingError::Full) | Error::CongestionLimited) => break,
                Err(error) => panic!("unexpected ordinary reservation: {error:?}"),
            }
        }
        assert!(admitted > 0);
        let deadline = clock
            .update_application(LEDGER_CAPACITY as u64, [false, false, true])
            .unwrap()
            .unwrap();
        let at = deadline.at();
        assert!(matches!(
            clock.expire(deadline, at).unwrap(),
            Some(TimeoutAction::Probe { .. })
        ));
        let probe = tx
            .reserve_application(&[1], 0, 1200, true, at)
            .expect("ordinary outstanding packets must leave publication capacity for actual PTO");
        tx.cancel(probe).unwrap();
        retirement.disarm();
    }

    #[test]
    fn repeated_unanswered_pto_uses_only_backed_headroom_then_fails_explicitly() {
        book!(book, scope, installation, arena, Side::Client, 179);
        book.numbers.borrow_mut().handshake_confirmed = true;
        let (mut tx, _, mut clock, mut publication, mut retirement) = book.split().unwrap();
        let guard = NoAlloc::start();
        for now in 0..(LEDGER_CAPACITY - PTO_RECORD_RESERVE) as u64 {
            let packet = tx.reserve_application(&[1], 0, 64, false, now).unwrap();
            publication
                .settle(Completion::from_adapter(
                    packet,
                    Some(now),
                    crate::quic::ecn::Codepoint::NotEct,
                ))
                .unwrap();
        }
        let mut now = LEDGER_CAPACITY as u64;
        for _ in 0..PTO_RECORD_RESERVE / 2 {
            let deadline = clock
                .update_application(now, [false, false, true])
                .unwrap()
                .unwrap();
            now = deadline.at();
            assert!(matches!(
                clock.expire(deadline, now).unwrap(),
                Some(TimeoutAction::Probe { .. })
            ));
            for _ in 0..2 {
                let probe = tx.reserve_application(&[1], 0, 1200, true, now).unwrap();
                publication
                    .settle(Completion::from_adapter(
                        probe,
                        Some(now),
                        crate::quic::ecn::Codepoint::NotEct,
                    ))
                    .unwrap();
            }
        }
        assert_eq!(
            tx.snapshot().bytes_in_flight,
            ((LEDGER_CAPACITY - PTO_RECORD_RESERVE) * 64 + PTO_RECORD_RESERVE * 1200) as u64
        );
        let deadline = clock
            .update_application(now, [false, false, true])
            .unwrap()
            .unwrap();
        now = deadline.at();
        clock.expire(deadline, now).unwrap();
        assert!(matches!(
            tx.reserve_application(&[1], 0, 1200, true, now),
            Err(Error::Capacity)
        ));
        retirement.disarm();
        drop(guard);
    }

    #[test]
    fn outstanding_packet_does_not_let_ack_only_history_exhaust_recovery() {
        book!(book, scope, installation, arena, Side::Client, 177);
        // Numerical recovery fixture after handshake confirmation. Actual TLS
        // authorization is covered by the scoped-handshake integration below.
        book.numbers.borrow_mut().handshake_confirmed = true;
        let (mut tx, _, mut clock, mut publication, mut retirement) = book.split().unwrap();
        let guard = NoAlloc::start();
        // A real eliciting packet whose peer ACK was lost stays outstanding.
        let first = tx.reserve_application(&[1], 0, 32, false, 0).unwrap();
        publication
            .settle(Completion::from_adapter(
                first,
                Some(0),
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        let mut bytes = [0; 128];
        let len = ack(0, &mut bytes);
        for now in 1..=256 {
            let sent = tx
                .reserve_application(&bytes[..len], 0, 32, false, now)
                .expect("non-eliciting ACK history must leave publication capacity");
            publication
                .settle(Completion::from_adapter(
                    sent,
                    Some(now),
                    crate::quic::ecn::Codepoint::NotEct,
                ))
                .unwrap();
        }
        let deadline = clock
            .update_application(257, [false, false, true])
            .unwrap()
            .unwrap();
        let at = deadline.at();
        assert!(matches!(
            clock.expire(deadline, at).unwrap(),
            Some(TimeoutAction::Probe {
                space: PacketNumberSpace::ApplicationData,
                ..
            })
        ));
        let probe = tx.reserve_application(&[1], 0, 1200, true, at).unwrap();
        tx.cancel(probe).unwrap();
        retirement.disarm();
        drop(guard);
    }

    #[test]
    fn more_than_64_real_acknowledged_or_rejected_sends_reclaim_bounded_storage_without_allocating()
    {
        book!(book, scope, installation, arena, Side::Client, 76);
        let (mut read, _) = crate::crypto::directional::ApplicationReadKeys::install(
            installation,
            key(KeyKind::OneRtt, 8),
            key(KeyKind::OneRtt, 9),
        )
        .unwrap();
        let mut peer = key(KeyKind::OneRtt, 9);
        let guard = NoAlloc::start();
        let (mut tx, mut rx, _, mut publication, mut retirement) = book.split().unwrap();
        let mut reservations: [Option<Reservation<'_>>; ORDINARY_RECORD_CAPACITY] =
            core::array::from_fn(|_| None);
        for slot in &mut reservations {
            *slot = Some(tx.reserve_application(&[1], 0, 32, false, 0).unwrap());
        }
        assert!(matches!(
            tx.reserve_application(&[1], 0, 32, false, 0),
            Err(Error::Accounting(AccountingError::Full))
        ));
        tx.cancel(reservations[0].take().unwrap()).unwrap();
        let extra = tx.reserve_application(&[1], 0, 32, false, 0).unwrap();
        assert_eq!(extra.packet().value, ORDINARY_RECORD_CAPACITY as u64);
        for r in reservations.into_iter().flatten() {
            tx.cancel(r).unwrap();
        }
        tx.cancel(extra).unwrap();
        let mut peer_pn = 0;
        for iteration in 0..192_u64 {
            let now = iteration * 10 + 1;
            let before = tx.snapshot().revision;
            let r = tx.reserve_application(&[1], 0, 32, false, now).unwrap();
            let pn = r.packet().value;
            if iteration % 3 == 0 {
                publication
                    .settle(Completion::from_adapter(
                        r,
                        None,
                        crate::quic::ecn::Codepoint::NotEct,
                    ))
                    .unwrap();
            } else {
                publication
                    .settle(Completion::from_adapter(
                        r,
                        Some(now),
                        crate::quic::ecn::Codepoint::NotEct,
                    ))
                    .unwrap();
                let mut plaintext = [0; 64];
                let len = ack(pn, &mut plaintext);
                let receipt =
                    app_receipt(&mut read, &mut peer, peer_pn, &plaintext[..len], now + 1);
                peer_pn += 1;
                let result = rx
                    .apply_application_packet(receipt, &plaintext[..len], now + 1, now + 1, None)
                    .unwrap();
                assert_eq!(result.newly_acknowledged, 1);
                assert_eq!(
                    result.packets[0],
                    Some(PacketNumber {
                        space: PacketNumberSpace::ApplicationData,
                        value: pn
                    })
                );
                let grant = result.key_acks.into_iter().flatten().next().unwrap();
                assert_eq!(grant.sent_key_generation(), 0);
                assert_eq!(grant.received_key_generation(), 0);
                ValidatedKeyAck::from_connection_ack(grant).unwrap();
            }
            assert!(tx.snapshot().revision > before);
        }
        let snapshot = tx.snapshot();
        assert_eq!(
            snapshot.next_packet_number[2],
            Some(ORDINARY_RECORD_CAPACITY as u64 + 193)
        );
        assert_eq!(
            snapshot.history_floor[2],
            ORDINARY_RECORD_CAPACITY as u64 + 193
        );
        assert_eq!(snapshot.retained_packets, 0);
        assert_eq!(snapshot.reserved_bytes, 0);
        assert_eq!(snapshot.bytes_in_flight, 0);
        retirement.disarm();
        guard.finish();
    }

    #[test]
    fn initial_retirement_requires_actual_acceptance_and_returns_token_until_initial_reservations_settle()
     {
        book!(book, scope, installation, arena, Side::Client, 77);
        let (mut tx, _, _, mut publication, mut retirement) = book.split().unwrap();
        let mut owner = tx.initial_retirement_owner();
        let initial = tx
            .reserve(Level::Initial, 1200, None, true, true, false, 0)
            .unwrap();
        let rejected = tx
            .reserve(Level::Handshake, 32, None, true, false, false, 0)
            .unwrap();
        publication
            .settle(Completion::from_adapter(
                rejected,
                None,
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        assert!(publication.take_initial_retirement().is_none());
        let handshake = tx
            .reserve(Level::Handshake, 32, None, true, false, false, 1)
            .unwrap();
        publication
            .settle(Completion::from_adapter(
                handshake,
                Some(1),
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        let token = publication.take_initial_retirement().unwrap();
        assert_eq!(
            token.event(),
            InitialRetirementEvent::ClientHandshakeAccepted
        );
        assert!(publication.take_initial_retirement().is_none());
        let token = match owner.retire_initial(token) {
            Err((Error::PendingInitialPublication, token)) => token,
            _ => panic!("pending Initial publication was discarded"),
        };
        publication.cancel(initial).unwrap();
        let proof = owner.retire_initial(token).unwrap();
        assert_eq!(
            proof.event(),
            InitialRetirementEvent::ClientHandshakeAccepted
        );
        let snapshot = tx.snapshot();
        assert_eq!(snapshot.bytes_in_flight, 32);
        assert_eq!(snapshot.next_packet_number, [Some(1), Some(2), Some(0)]);
        assert_eq!(snapshot.history_floor[0], 1);
        assert!(matches!(
            tx.reserve(Level::Initial, 1200, None, false, true, false, 1),
            Err(Error::Accounting(AccountingError::Retired))
        ));
        retirement.disarm();
    }

    #[test]
    fn direct_received_packet_rejects_wrong_plaintext_and_foreign_scope() {
        book!(book, scope, installation, arena, Side::Client, 78);
        let foreign = ApplicationKeyScope::new(78);
        let mut peer = key(KeyKind::Initial, 7);
        let receipt = initial_receipt(book.scope(), &mut peer, 0, &[1]);
        let (_, mut rx, _, _, mut retirement) = book.split().unwrap();
        assert!(rx.apply_packet(receipt, &[0], 0, 0, None).is_err());
        let receipt = initial_receipt(&foreign, &mut peer, 1, &[1]);
        assert!(rx.apply_packet(receipt, &[1], 1, 1, None).is_err());
        retirement.disarm();
    }

    #[test]
    fn old_space_transport_close_passes_authenticated_preflight_without_delivery_effects() {
        book!(book, scope, installation, arena, Side::Client, 83);
        let own_scope = book.scope();
        let (_, mut rx, _, _, mut retirement) = book.split().unwrap();
        let mut peer = key(KeyKind::Initial, 7);
        let plaintext = [0x1c, 0, 0, 0];
        let receipt = initial_receipt(own_scope, &mut peer, 0, &plaintext);
        let outcome = rx.apply_packet(receipt, &plaintext, 0, 0, None).unwrap();
        assert!(!outcome.ack_eliciting);
        assert_eq!(outcome.newly_acknowledged, 0);
        assert_eq!(rx.snapshot().retained_packets, 0);
        let invalid = [0x1d, 0, 0];
        let receipt = initial_receipt(own_scope, &mut peer, 1, &invalid);
        assert!(matches!(
            rx.apply_packet(receipt, &invalid, 1, 1, None),
            Err(Error::Packet(packet::Error::FrameNotAllowed { .. }))
        ));
        retirement.disarm();
    }

    #[test]
    fn actual_ack_declares_only_eligible_loss_and_duplicate_ack_mints_no_new_key_receipt() {
        book!(book, scope, installation, arena, Side::Client, 81);
        let (mut read, _) = crate::crypto::directional::ApplicationReadKeys::install(
            installation,
            key(KeyKind::OneRtt, 8),
            key(KeyKind::OneRtt, 9),
        )
        .unwrap();
        let mut peer = key(KeyKind::OneRtt, 9);
        let (mut tx, mut rx, mut clock, mut publication, mut retirement) = book.split().unwrap();
        for pn in 0..4 {
            let r = tx.reserve_application(&[1], 0, 32, false, pn).unwrap();
            publication
                .settle(Completion::from_adapter(
                    r,
                    Some(pn),
                    crate::quic::ecn::Codepoint::NotEct,
                ))
                .unwrap();
        }
        let mut plaintext = [0; 64];
        let len = ack(3, &mut plaintext);
        let receipt = app_receipt(&mut read, &mut peer, 0, &plaintext[..len], 4);
        let outcome = rx
            .apply_application_packet(receipt, &plaintext[..len], 4, 4, None)
            .unwrap();
        assert_eq!(outcome.newly_acknowledged, 1);
        assert_eq!(outcome.history_floor, 1);
        assert_eq!(
            tx.take_lost_application().map(|grant| grant.packet()),
            Some(PacketNumber {
                space: PacketNumberSpace::ApplicationData,
                value: 0
            })
        );
        assert_eq!(tx.take_lost_application().map(|grant| grant.packet()), None);
        let receipt = app_receipt(&mut read, &mut peer, 1, &plaintext[..len], 5);
        let duplicate = rx
            .apply_application_packet(receipt, &plaintext[..len], 5, 5, None)
            .unwrap();
        assert_eq!(duplicate.newly_acknowledged, 0);
        assert!(duplicate.key_acks.into_iter().all(|grant| grant.is_none()));
        let deadline = clock
            .update_application(5, [false, false, true])
            .unwrap()
            .unwrap();
        let at = deadline.at();
        assert_eq!(
            clock.expire(deadline, at).unwrap(),
            Some(TimeoutAction::DetectLoss(
                PacketNumberSpace::ApplicationData
            ))
        );
        assert_eq!(
            tx.take_lost_application().map(|grant| grant.packet()),
            Some(PacketNumber {
                space: PacketNumberSpace::ApplicationData,
                value: 1
            })
        );
        assert!(tx.snapshot().bytes_in_flight <= 32);
        retirement.disarm();
    }

    #[test]
    fn key_ack_bridge_preserves_actual_scope_and_rejects_an_older_receiving_epoch() {
        book!(book, scope, installation, arena, Side::Client, 79);
        let (mut read, mut write) = crate::crypto::directional::ApplicationReadKeys::install(
            installation,
            key(KeyKind::OneRtt, 8),
            key(KeyKind::OneRtt, 9),
        )
        .unwrap();
        let mut foreign_scope = ApplicationKeyScope::new(79);
        let (_, mut foreign_write) = crate::crypto::directional::ApplicationReadKeys::install(
            foreign_scope.claim().unwrap(),
            key(KeyKind::OneRtt, 8),
            key(KeyKind::OneRtt, 9),
        )
        .unwrap();
        let mut old_peer = key(KeyKind::OneRtt, 9);
        let (mut tx, mut rx, _, mut publication, mut retirement) = book.split().unwrap();
        let first = tx.reserve_application(&[1], 0, 22, false, 0).unwrap();
        let sealed = match crate::quic::application_wire::seal::<2048>(&mut write, first, &[], &[1])
        {
            Ok(sealed) => sealed,
            Err(_) => panic!("actual epoch-zero seal failed"),
        };
        publication
            .settle(Completion::from_adapter(
                sealed.into_reservation(),
                Some(0),
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        let mut plaintext = [0; 64];
        let len = ack(0, &mut plaintext);
        let receipt = app_receipt(&mut read, &mut old_peer, 0, &plaintext[..len], 1);
        let outcome = rx
            .apply_application_packet(receipt, &plaintext[..len], 1, 1, None)
            .unwrap();
        let grant = ValidatedKeyAck::from_connection_ack(
            outcome.key_acks.into_iter().flatten().next().unwrap(),
        )
        .unwrap();
        assert_eq!(
            foreign_write.acknowledge(grant, 1, 1000),
            Err(crypto::Error::InvalidAcknowledgment)
        );

        // A real peer key update installs write epoch one. Retained previous
        // read keys can still authenticate a reordered lower-numbered packet,
        // but that old receive epoch cannot acknowledge the new write epoch.
        let mut new_peer = key(KeyKind::OneRtt, 9);
        new_peer.update_key().unwrap();
        read.maintain(2, 1000).unwrap();
        let mut bytes = [0; 64];
        bytes[0] = 1;
        let len = new_peer.seal(10, &[0x44], &mut bytes, 1).unwrap();
        let transition = match read
            .open(
                10,
                true,
                &[0x44],
                &mut bytes[..len],
                &mut IntegrityBudget::new(),
                2,
                1000,
            )
            .unwrap()
        {
            AuthenticatedRead::PeerUpdate(transition) => transition,
            _ => panic!("next epoch bypassed write installation"),
        };
        let installed = write.install_peer_update(transition).unwrap();
        let ready = read.accept_write_epoch(installed).unwrap();
        rx.apply_application_packet(ready, &[1], 2, 2, None)
            .unwrap();
        let next = tx
            .reserve_application(&[1], write.generation(), 22, false, 3)
            .unwrap();
        let pn = next.packet().value;
        let sealed = match crate::quic::application_wire::seal::<2048>(&mut write, next, &[], &[1])
        {
            Ok(sealed) => sealed,
            Err(_) => panic!("actual epoch-one seal failed"),
        };
        publication
            .settle(Completion::from_adapter(
                sealed.into_reservation(),
                Some(3),
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        let len = ack(pn, &mut plaintext);
        let receipt = app_receipt(&mut read, &mut old_peer, 1, &plaintext[..len], 4);
        let outcome = rx
            .apply_application_packet(receipt, &plaintext[..len], 4, 4, None)
            .unwrap();
        let grant = outcome.key_acks.into_iter().flatten().next().unwrap();
        assert_eq!(grant.sent_key_generation(), 1);
        assert_eq!(grant.received_key_generation(), 0);
        assert!(matches!(
            ValidatedKeyAck::from_connection_ack(grant),
            Err(crypto::Error::KeyUpdateError)
        ));
        retirement.disarm();
    }

    #[test]
    fn actual_validated_finished_and_handshake_done_gate_confirmation_and_old_space_retirement() {
        use super::tls_fixture as fixture;
        use crate::{
            tls::certificate::{CertificateDer, Limits, trust_anchor_from_der},
            tls::handshake::{BoundedTls, ClientConfig, ServerConfig},
        };
        let root = CertificateDer::from(fixture::ROOT_DER);
        let anchors = [trust_anchor_from_der(&root).unwrap()];
        let chain = [fixture::LEAF_DER];
        let signer = fixture::signing_key();
        let mut cb = fixture::Buffers::new();
        let mut sb = fixture::Buffers::new();
        // Mandatory CID parameters are bound by actual TLS Finished and then
        // independently verified at the public parameter gate.
        let cp = [15, 0, 4, 1, 42];
        let sp = [0, 0, 15, 0, 4, 1, 63, 10, 1, 2, 11, 1, 7];
        book!(
            client_book,
            client_scope,
            client_install,
            client_arena,
            Side::Client,
            80
        );
        book!(
            server_book,
            server_scope,
            server_install,
            server_arena,
            Side::Server,
            80
        );
        let mut client = BoundedTls::client(
            ClientConfig {
                protocol: Default::default(),
                version: crate::quic::kernel::version::Version::V1,
                server_name: "localhost",
                trust_anchors: &anchors,
                now: fixture::now(),
                certificate_limits: Limits::default(),
                transport_parameters: &cp,
            },
            cb.storage(),
            &mut fixture::TestRandom(121),
        )
        .unwrap()
        .into_key_source(client_install)
        .unwrap();
        let mut server = BoundedTls::server(
            ServerConfig {
                protocol: Default::default(),
                version: crate::quic::kernel::version::Version::V1,
                certificate_chain: &chain,
                signing_key: &signer,
                transport_parameters: &sp,
            },
            sb.storage(),
            &mut fixture::TestRandom(143),
        )
        .unwrap()
        .into_key_source(server_install)
        .unwrap();
        let (mut cm, mut sm) = crate::scoped_tls_fixture::handshake_key_sources_observe(
            &mut client,
            &mut server,
            |_, _| {},
        );
        let (_, mut client_handshake) = cm.handshake.take().unwrap().install();
        let (server_handshake, _) = sm.handshake.take().unwrap().install();
        let (ci, cl, cr) = cm.application.take().unwrap().into_parts();
        let (si, sl, sr) = sm.application.take().unwrap().into_parts();
        let (mut client_read, mut client_write) =
            crate::crypto::directional::ApplicationReadKeys::install(ci, cl, cr).unwrap();
        let (_, mut server_write) =
            crate::crypto::directional::ApplicationReadKeys::install(si, sl, sr).unwrap();
        let client_scope = client_book.scope();
        let server_scope = server_book.scope();
        let cf = cm.finished.take().unwrap();
        let sf = sm.finished.take().unwrap();
        let client_peer = super::super::parameters::validate(
            cf,
            client_scope,
            Side::Client,
            &[],
            Some(&[]),
            None,
        )
        .unwrap();
        let server_peer =
            super::super::parameters::validate(sf, server_scope, Side::Server, &[], None, None)
                .unwrap();
        assert!(
            client_book
                .bind_validated_peer(&client_peer)
                .unwrap()
                .is_none()
        );
        assert!(!client_book.snapshot().handshake_confirmed);
        let server_confirmation = server_book
            .bind_validated_peer(&server_peer)
            .unwrap()
            .unwrap();
        assert!(
            server_book
                .bind_validated_peer(&server_peer)
                .unwrap()
                .is_none()
        );
        assert!(server_book.snapshot().handshake_confirmed);
        server_write
            .confirm_handshake(
                crypto::directional::ScopedHandshakeConfirmation::from_connection(
                    server_confirmation,
                ),
            )
            .unwrap();

        let (mut stx, mut srx, _, _, mut sr) = server_book.split().unwrap();
        srx.received_datagram(1200).unwrap();
        assert!(srx.take_initial_retirement().is_none());
        let mut buffer = [0; 64];
        buffer[0] = 1;
        let len = client_handshake
            .seal(0, b"real Handshake header", &mut buffer, 1)
            .unwrap();
        let receipt = server_handshake
            .open_authenticated(
                0,
                b"real Handshake header",
                &mut buffer[..len],
                &mut IntegrityBudget::new(),
            )
            .unwrap();
        srx.apply_packet(receipt, &[1], 0, 0, None).unwrap();
        assert!(srx.snapshot().address_validated);
        let initial = srx.take_initial_retirement().unwrap();
        assert_eq!(
            initial.event(),
            InitialRetirementEvent::ServerHandshakeAuthenticated
        );
        srx.retire_initial(initial).unwrap();
        let hd = stx
            .store_handshake_done_token(server_peer.finished(), Some(b"a"))
            .unwrap();
        assert!(stx.is_handshake_done(hd).unwrap());
        let control = [0x1e, 0x07, 0x01, b'a'];
        let retained_hd = stx
            .reserve_application_control(&control, server_write.generation(), 25, hd, false, 0)
            .unwrap();
        assert!(retained_hd.matches_plaintext(&control).unwrap());
        stx.cancel(retained_hd).unwrap();
        assert!(
            stx.reserve_application_control(
                &[0x1e, 7, 1, b'b'],
                server_write.generation(),
                25,
                hd,
                false,
                0
            )
            .is_err()
        );
        assert!(
            stx.reserve_application_control(&[0x1e], server_write.generation(), 22, hd, false, 0)
                .is_err()
        );
        assert!(
            stx.reserve_application(&[7, 1, b'a'], server_write.generation(), 24, false, 0)
                .is_err()
        );

        let (mut tx, mut rx, _, mut publication, mut retirement) = client_book.split().unwrap();
        let completion = tx.completion_observer();
        assert!(!completion.handshake_confirmed().unwrap());
        let initial = tx
            .reserve(Level::Initial, 1200, None, true, true, false, 0)
            .unwrap();
        let handshake = tx
            .reserve(Level::Handshake, 32, None, true, false, false, 0)
            .unwrap();
        let app = tx.reserve_application(&[1], 0, 32, false, 0).unwrap();
        publication
            .settle(Completion::from_adapter(
                app,
                Some(0),
                crate::quic::ecn::Codepoint::NotEct,
            ))
            .unwrap();
        buffer[0] = 0x1e;
        let len = server_write.seal(0, &[0x40], &mut buffer, 1).unwrap();
        let receipt = match client_read
            .open(
                0,
                false,
                &[0x40],
                &mut buffer[..len],
                &mut IntegrityBudget::new(),
                10,
                1000,
            )
            .unwrap()
        {
            AuthenticatedRead::Ready(receipt) => receipt,
            _ => panic!("unexpected update"),
        };
        let result = rx
            .apply_application_packet(receipt, &[0x1e], 10, 10, None)
            .unwrap();
        assert!(completion.handshake_confirmed().unwrap());
        let confirmation = result.confirmation.unwrap();
        assert_eq!(
            rx.retire_handshake(&confirmation),
            Err(Error::Accounting(AccountingError::OutstandingPackets))
        );
        publication.cancel(initial).unwrap();
        assert_eq!(
            rx.retire_handshake(&confirmation),
            Err(Error::Accounting(AccountingError::OutstandingPackets))
        );
        publication.cancel(handshake).unwrap();
        rx.retire_handshake(&confirmation).unwrap();
        assert_eq!(tx.snapshot().bytes_in_flight, 32);
        assert_eq!(
            tx.snapshot().next_packet_number,
            [Some(1), Some(1), Some(1)]
        );
        assert!(matches!(
            tx.reserve(Level::Handshake, 32, None, true, false, false, 10),
            Err(Error::Accounting(AccountingError::Retired))
        ));
        let app = tx.reserve_application(&[1], 0, 32, false, 10).unwrap();
        tx.cancel(app).unwrap();
        client_write
            .confirm_handshake(
                crypto::directional::ScopedHandshakeConfirmation::from_connection(confirmation),
            )
            .unwrap();
        retirement.disarm();
        sr.disarm();
    }
}
