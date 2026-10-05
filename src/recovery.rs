//! Allocation-free RFC 9002 recovery calculations for a single connection/path.
//!
//! All durations and timestamps are **monotonic microseconds**, supplied by the
//! caller. Timestamps are not wall clocks. Overflow and time reversal are errors,
//! never wrapped deadlines. Packet parsing, authenticated ACK validation, sent
//! history, retransmittable frames and bytes-in-flight remain owned elsewhere.
//!
//! In particular, `RecoveryTimer` emits a probe instruction on PTO. It does not
//! mark outstanding packets lost. `NewReno` consumes once-filtered ledger events
//! and never subtracts or owns another bytes-in-flight counter. The caller must
//! account for accepted probes in the normal ledger, even above the cwnd.
//!
//! This module implements arithmetic/state kernels from RFC 9002 sections 5–7.
//! It does not claim endpoint integration, ECN validation, or source refinement.
//! Reference: <https://www.rfc-editor.org/rfc/rfc9002.html>.

use crate::accounting::{MAX_PACKET_NUMBER, PacketNumberSpace};

pub const INITIAL_RTT_US: u64 = 333_000;
pub const TIMER_GRANULARITY_US: u64 = 1_000;
pub const PACKET_THRESHOLD: u64 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryError {
    InvalidConfiguration,
    TimeWentBackwards,
    InvalidSample,
    InvalidPacketEvidence,
    InconsistentTimerState,
    Overflow,
    TooManyRecords,
    UnorderedHistory,
    PacingLimited,
}

fn narrow(value: u128) -> Result<u64, RecoveryError> {
    u64::try_from(value).map_err(|_| RecoveryError::Overflow)
}

fn check_time(previous: Option<u64>, now: u64) -> Result<(), RecoveryError> {
    if previous.is_some_and(|previous| now < previous) {
        Err(RecoveryError::TimeWentBackwards)
    } else {
        Ok(())
    }
}

/// Facts from an authenticated, once-filtered ACK, not peer-supplied assertions.
#[derive(Clone, Copy, Debug)]
pub struct RttSample {
    pub now: u64,
    pub sent_at: u64,
    /// Already decoded into microseconds using the peer's ACK delay exponent.
    pub ack_delay_us: u64,
    pub max_ack_delay_us: u64,
    pub space: PacketNumberSpace,
    pub handshake_confirmed: bool,
    pub largest_newly_acknowledged: bool,
    pub any_newly_acknowledged_ack_eliciting: bool,
    /// Known local wait for unavailable keys; subtracted before confirmation.
    pub local_decryption_delay_us: u64,
}

#[derive(Debug)]
pub struct RttEstimator {
    latest: u64,
    minimum: Option<u64>,
    smoothed: u64,
    variation: u64,
    first_sample_at: Option<u64>,
    last_sample_at: Option<u64>,
}

impl RttEstimator {
    pub fn new(initial_rtt_us: u64) -> Result<Self, RecoveryError> {
        if initial_rtt_us == 0 {
            return Err(RecoveryError::InvalidConfiguration);
        }
        Ok(Self {
            latest: initial_rtt_us,
            minimum: None,
            smoothed: initial_rtt_us,
            variation: initial_rtt_us / 2,
            first_sample_at: None,
            last_sample_at: None,
        })
    }

    /// Returns false when RFC 9002 section 5.1 forbids a sample. The first
    /// sample ignores peer ACK delay. Later samples preserve the observed
    /// minimum and use the previous smoothed value to update variation first.
    pub fn on_ack(&mut self, sample: RttSample) -> Result<bool, RecoveryError> {
        if !sample.largest_newly_acknowledged || !sample.any_newly_acknowledged_ack_eliciting {
            return Ok(false);
        }
        check_time(self.last_sample_at, sample.now)?;
        let elapsed = sample
            .now
            .checked_sub(sample.sent_at)
            .ok_or(RecoveryError::TimeWentBackwards)?;
        let local_delay = if sample.handshake_confirmed {
            0
        } else {
            sample.local_decryption_delay_us
        };
        let latest = elapsed
            .checked_sub(local_delay)
            .ok_or(RecoveryError::InvalidSample)?;
        let minimum = self.minimum.map_or(latest, |old| old.min(latest));
        let (smoothed, variation) = if self.first_sample_at.is_none() {
            (latest, latest / 2)
        } else {
            // RFC 9002 5.3 permits ignoring Initial ACK delay, not Handshake
            // buffering delay. Before confirmation, unavailable peer keys can
            // cause a large, non-repeating delay that is not path latency.
            let delay = if sample.space == PacketNumberSpace::Initial {
                0
            } else if sample.handshake_confirmed {
                sample.ack_delay_us.min(sample.max_ack_delay_us)
            } else {
                sample.ack_delay_us
            };
            // RFC 9002 5.3 allows ignoring a pre-confirmation sample when
            // delay adjustment would fall below the observed path minimum.
            // Do not clamp an implausible peer claim into a fabricated RTT.
            if !sample.handshake_confirmed && delay > latest - minimum {
                return Ok(false);
            }
            let adjusted = if latest - minimum >= delay {
                latest - delay
            } else {
                latest
            };
            let variation =
                (3 * u128::from(self.variation) + u128::from(self.smoothed.abs_diff(adjusted))) / 4;
            let smoothed = (7 * u128::from(self.smoothed) + u128::from(adjusted)) / 8;
            // Weighted means of u64 values cannot exceed u64::MAX.
            (smoothed as u64, variation as u64)
        };
        self.latest = latest;
        self.minimum = Some(minimum);
        self.smoothed = smoothed;
        self.variation = variation;
        self.first_sample_at.get_or_insert(sample.now);
        self.last_sample_at = Some(sample.now);
        Ok(true)
    }

    pub fn latest_us(&self) -> u64 {
        self.latest
    }
    pub fn min_us(&self) -> Option<u64> {
        self.minimum
    }
    pub fn smoothed_us(&self) -> u64 {
        self.smoothed
    }
    pub fn variation_us(&self) -> u64 {
        self.variation
    }
    pub fn first_sample_at(&self) -> Option<u64> {
        self.first_sample_at
    }

    /// Nine-eighths of the larger recent/smoothed RTT, rounded upward so integer
    /// precision never declares time-threshold loss before the chosen delay.
    pub fn loss_delay_us(&self) -> Result<u64, RecoveryError> {
        let delay = (9 * u128::from(self.latest.max(self.smoothed))).div_ceil(8);
        narrow(delay.max(u128::from(TIMER_GRANULARITY_US)))
    }

    pub fn pto_duration_us(
        &self,
        max_ack_delay_us: u64,
        backoff: u32,
    ) -> Result<u64, RecoveryError> {
        let base = u128::from(self.smoothed)
            + (4 * u128::from(self.variation)).max(u128::from(TIMER_GRANULARITY_US))
            + u128::from(max_ack_delay_us);
        let factor = 1_u64.checked_shl(backoff).ok_or(RecoveryError::Overflow)?;
        narrow(
            base.checked_mul(u128::from(factor))
                .ok_or(RecoveryError::Overflow)?,
        )
    }

    /// Unlike PTO, persistent congestion always includes max_ack_delay and
    /// never includes exponential PTO backoff, regardless of packet space.
    pub fn persistent_congestion_duration_us(
        &self,
        max_ack_delay_us: u64,
    ) -> Result<u64, RecoveryError> {
        self.pto_duration_us(max_ack_delay_us, 0)?
            .checked_mul(3)
            .ok_or(RecoveryError::Overflow)
    }

    pub fn reset_min_after_persistent_congestion(&mut self) {
        if self.first_sample_at.is_some() {
            self.minimum = Some(self.latest);
        }
    }
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self {
            latest: INITIAL_RTT_US,
            minimum: None,
            smoothed: INITIAL_RTT_US,
            variation: INITIAL_RTT_US / 2,
            first_sample_at: None,
            last_sample_at: None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LossCandidate {
    pub packet_number: u64,
    pub sent_at: u64,
    /// Count of actually sent packets later than this packet, up to and
    /// including largest_acked, in the same space. Do not count cancelled or
    /// skipped PNs. Zero conservatively disables packet-threshold detection.
    pub newer_sent_packets: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LossDecision {
    /// No equal/later packet in this space has been acknowledged yet.
    NotEligible,
    Lost,
    WaitUntil(u64),
}

/// Call only for an outstanding sent record. Ledger state rejects duplicates
/// when applying Lost. Tail loss without later ACK evidence is handled by PTO.
pub fn loss_decision(
    rtt: &RttEstimator,
    candidate: LossCandidate,
    largest_acked: Option<u64>,
    now: u64,
) -> Result<LossDecision, RecoveryError> {
    if candidate.packet_number > MAX_PACKET_NUMBER
        || largest_acked.is_some_and(|pn| pn > MAX_PACKET_NUMBER)
    {
        return Err(RecoveryError::InvalidPacketEvidence);
    }
    if candidate.sent_at > now {
        return Err(RecoveryError::TimeWentBackwards);
    }
    let Some(largest) = largest_acked.filter(|largest| *largest >= candidate.packet_number) else {
        return Ok(LossDecision::NotEligible);
    };
    if candidate.newer_sent_packets > largest - candidate.packet_number {
        return Err(RecoveryError::InvalidPacketEvidence);
    }
    if candidate.newer_sent_packets >= PACKET_THRESHOLD {
        return Ok(LossDecision::Lost);
    }
    let delay = rtt.loss_delay_us()?;
    if now - candidate.sent_at >= delay {
        return Ok(LossDecision::Lost);
    }
    let deadline = candidate
        .sent_at
        .checked_add(delay)
        .ok_or(RecoveryError::Overflow)?;
    Ok(LossDecision::WaitUntil(deadline))
}

/// Caller-owned per-space facts. Array order is Initial, Handshake, Application.
#[derive(Clone, Copy, Debug, Default)]
pub struct SpaceTimer {
    pub keys_available: bool,
    pub loss_time: Option<u64>,
    pub ack_eliciting_in_flight: bool,
    pub last_ack_eliciting_sent_at: Option<u64>,
}

#[derive(Clone, Copy, Debug)]
pub struct TimerContext {
    pub is_server: bool,
    pub handshake_confirmed: bool,
    pub handshake_ack_received: bool,
    pub server_amplification_blocked: bool,
}

impl TimerContext {
    pub fn peer_completed_address_validation(self) -> bool {
        self.is_server || self.handshake_confirmed || self.handshake_ack_received
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimerKind {
    Loss(PacketNumberSpace),
    Probe {
        space: PacketNumberSpace,
        anti_deadlock: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimerDeadline {
    pub at: u64,
    pub kind: TimerKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimeoutAction {
    DetectLoss(PacketNumberSpace),
    /// Emit ack-eliciting probes with fresh PNs. No record is declared lost by
    /// this event. Anti-amplification still applies; congestion window does not.
    Probe {
        space: PacketNumberSpace,
        max_datagrams: u8,
        minimum_datagram_size: u16,
    },
}

pub struct RecoveryTimer {
    pto_count: u32,
    armed: Option<TimerDeadline>,
    anti_deadlock_duration: Option<u64>,
    last_now: Option<u64>,
}

const SPACES: [PacketNumberSpace; 3] = [
    PacketNumberSpace::Initial,
    PacketNumberSpace::Handshake,
    PacketNumberSpace::ApplicationData,
];

impl RecoveryTimer {
    pub const fn new() -> Self {
        Self {
            pto_count: 0,
            armed: None,
            anti_deadlock_duration: None,
            last_now: None,
        }
    }
    pub fn pto_count(&self) -> u32 {
        self.pto_count
    }
    pub fn deadline(&self) -> Option<TimerDeadline> {
        self.armed
    }

    /// Recompute after send/ACK/key discard/path-unblocking. Loss timers take
    /// priority over PTO. An overdue deadline is preserved and fires immediately.
    /// Invalid inputs leave the previously armed timer and backoff unchanged.
    pub fn update(
        &mut self,
        now: u64,
        rtt: &RttEstimator,
        spaces: &[SpaceTimer; 3],
        context: TimerContext,
        max_ack_delay_us: u64,
    ) -> Result<Option<TimerDeadline>, RecoveryError> {
        check_time(self.last_now, now)?;
        for facts in spaces {
            if facts.keys_available
                && facts.ack_eliciting_in_flight
                && facts.last_ack_eliciting_sent_at.is_none()
            {
                return Err(RecoveryError::InconsistentTimerState);
            }
            if facts.last_ack_eliciting_sent_at.is_some_and(|at| at > now) {
                return Err(RecoveryError::TimeWentBackwards);
            }
        }
        let mut next: Option<TimerDeadline> = None;
        let mut anti_deadlock_duration = None;
        for (index, facts) in spaces.iter().enumerate() {
            if let Some(at) = facts.loss_time.filter(|_| facts.keys_available)
                && next.is_none_or(|old| at < old.at)
            {
                next = Some(TimerDeadline {
                    at,
                    kind: TimerKind::Loss(SPACES[index]),
                });
            }
        }
        if next.is_none() && !(context.is_server && context.server_amplification_blocked) {
            for (index, facts) in spaces.iter().enumerate() {
                let space = SPACES[index];
                if !facts.keys_available
                    || !facts.ack_eliciting_in_flight
                    || (space == PacketNumberSpace::ApplicationData && !context.handshake_confirmed)
                {
                    continue;
                }
                let delay = if space == PacketNumberSpace::ApplicationData {
                    max_ack_delay_us
                } else {
                    0
                };
                let duration = rtt.pto_duration_us(delay, self.pto_count)?;
                let sent_at = facts
                    .last_ack_eliciting_sent_at
                    .ok_or(RecoveryError::InconsistentTimerState)?;
                let at = sent_at
                    .checked_add(duration)
                    .ok_or(RecoveryError::Overflow)?;
                if next.is_none_or(|old| at < old.at) {
                    next = Some(TimerDeadline {
                        at,
                        kind: TimerKind::Probe {
                            space,
                            anti_deadlock: false,
                        },
                    });
                }
            }
            if next.is_none() && !context.peer_completed_address_validation() {
                // Also covers only-0RTT-in-flight before confirmation: it must
                // not arm an Application PTO, but the client cannot deadlock.
                let space = if spaces[1].keys_available {
                    PacketNumberSpace::Handshake
                } else if spaces[0].keys_available {
                    PacketNumberSpace::Initial
                } else {
                    return Err(RecoveryError::InconsistentTimerState);
                };
                let duration = rtt.pto_duration_us(0, self.pto_count)?;
                let kind = TimerKind::Probe {
                    space,
                    anti_deadlock: true,
                };
                // Repeated clock/receive refreshes are not a new anti-deadlock
                // event. Preserve the original deadline while the eligible
                // space and backed-off duration remain equivalent; otherwise
                // continuous polling could postpone this mandatory probe forever.
                let at = if let Some(previous) = self.armed.filter(|timer| {
                    timer.kind == kind && self.anti_deadlock_duration == Some(duration)
                }) {
                    previous.at
                } else {
                    now.checked_add(duration).ok_or(RecoveryError::Overflow)?
                };
                anti_deadlock_duration = Some(duration);
                next = Some(TimerDeadline { at, kind });
            }
        }
        self.armed = next;
        self.anti_deadlock_duration = anti_deadlock_duration;
        self.last_now = Some(now);
        Ok(next)
    }

    /// Consumes an expired timer, so calling twice cannot emit duplicate probes.
    /// The caller rearms after applying the action and updated sent-history facts.
    pub fn on_timeout(&mut self, now: u64) -> Result<Option<TimeoutAction>, RecoveryError> {
        check_time(self.last_now, now)?;
        let Some(deadline) = self.armed.filter(|timer| timer.at <= now) else {
            self.last_now = Some(now);
            return Ok(None);
        };
        let action = match deadline.kind {
            TimerKind::Loss(space) => TimeoutAction::DetectLoss(space),
            TimerKind::Probe {
                space,
                anti_deadlock,
            } => {
                let count = self
                    .pto_count
                    .checked_add(1)
                    .ok_or(RecoveryError::Overflow)?;
                self.pto_count = count;
                TimeoutAction::Probe {
                    space,
                    max_datagrams: if anti_deadlock { 1 } else { 2 },
                    minimum_datagram_size: if space == PacketNumberSpace::Initial {
                        1200
                    } else {
                        0
                    },
                }
            }
        };
        self.armed = None;
        self.anti_deadlock_duration = None;
        self.last_now = Some(now);
        Ok(Some(action))
    }

    pub fn on_new_ack(
        &mut self,
        newly_acknowledged: bool,
        peer_completed_address_validation: bool,
    ) {
        if newly_acknowledged && peer_completed_address_validation {
            self.pto_count = 0;
        }
    }

    /// Caller separately removes discarded-space bytes from its sole ledger,
    /// updates keys_available, and calls update. Never a congestion-loss signal.
    pub fn on_keys_discarded(&mut self, space: PacketNumberSpace) -> Result<(), RecoveryError> {
        if space == PacketNumberSpace::ApplicationData {
            return Err(RecoveryError::InvalidConfiguration);
        }
        self.pto_count = 0;
        self.armed = None;
        self.anti_deadlock_duration = None;
        Ok(())
    }
}

impl Default for RecoveryTimer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketOutcome {
    Lost,
    Acknowledged,
    Outstanding,
    Discarded,
}

#[derive(Clone, Copy, Debug)]
pub struct PersistentPacket {
    pub sent_at: u64,
    pub ack_eliciting: bool,
    pub outcome: PacketOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersistentCongestion {
    first_sent_at: u64,
    last_sent_at: u64,
}

impl PersistentCongestion {
    pub fn first_sent_at(self) -> u64 {
        self.first_sent_at
    }
    pub fn last_sent_at(self) -> u64 {
        self.last_sent_at
    }
}

/// Examine a complete, time-ordered window across all packet-number spaces
/// after an authenticated ACK/loss pass. The caller must include every packet
/// in the interval, including ACK-only and acknowledged packets. Missing
/// history must not be represented as a continuous lost run. Outstanding or
/// discarded packets conservatively break the run. This is bounded by CAPACITY.
pub fn persistent_congestion<const CAPACITY: usize>(
    rtt: &RttEstimator,
    history: &[PersistentPacket],
    max_ack_delay_us: u64,
) -> Result<Option<PersistentCongestion>, RecoveryError> {
    if history.len() > CAPACITY {
        return Err(RecoveryError::TooManyRecords);
    }
    if history
        .windows(2)
        .any(|pair| pair[0].sent_at > pair[1].sent_at)
    {
        return Err(RecoveryError::UnorderedHistory);
    }
    let Some(first_sample) = rtt.first_sample_at() else {
        return Ok(None);
    };
    let duration = rtt.persistent_congestion_duration_us(max_ack_delay_us)?;
    let mut first = None;
    for packet in history {
        if packet.sent_at <= first_sample || packet.outcome != PacketOutcome::Lost {
            first = None;
            continue;
        }
        if !packet.ack_eliciting {
            continue;
        }
        match first {
            // Check the whole candidate interval: a later array entry ACKed
            // at the same endpoint timestamp must not be hidden by an early
            // return. Work is still bounded by CAPACITY².
            Some(start)
                if packet.sent_at - start > duration
                    && history.iter().all(|entry| {
                        entry.sent_at < start
                            || entry.sent_at > packet.sent_at
                            || entry.outcome == PacketOutcome::Lost
                    }) =>
            {
                return Ok(Some(PersistentCongestion {
                    first_sent_at: start,
                    last_sent_at: packet.sent_at,
                }));
            }
            None => first = Some(packet.sent_at),
            _ => {}
        }
    }
    Ok(None)
}

/// Per-path NewReno. Flight accounting is intentionally absent: use SentLedger
/// once-only ACK/loss outcomes, and pass its current totals into `can_send`.
pub struct NewReno {
    max_datagram_size: u64,
    minimum_window: u64,
    congestion_window: u64,
    slow_start_threshold: u64,
    recovery_started: Option<u64>,
    additive_credit: u128,
    last_event_at: Option<u64>,
    persistent_end: Option<u64>,
}

impl NewReno {
    pub fn new(max_datagram_size: u64) -> Result<Self, RecoveryError> {
        if max_datagram_size < 1200 {
            return Err(RecoveryError::InvalidConfiguration);
        }
        let minimum_window = max_datagram_size
            .checked_mul(2)
            .ok_or(RecoveryError::Overflow)?;
        let initial =
            (10 * u128::from(max_datagram_size)).min(u128::from(minimum_window.max(14_720)));
        Ok(Self {
            max_datagram_size,
            minimum_window,
            congestion_window: narrow(initial)?,
            slow_start_threshold: u64::MAX,
            recovery_started: None,
            additive_credit: 0,
            last_event_at: None,
            persistent_end: None,
        })
    }

    pub fn congestion_window(&self) -> u64 {
        self.congestion_window
    }
    pub fn slow_start_threshold(&self) -> u64 {
        self.slow_start_threshold
    }
    pub fn minimum_window(&self) -> u64 {
        self.minimum_window
    }
    pub fn recovery_started(&self) -> Option<u64> {
        self.recovery_started
    }
    pub fn in_slow_start(&self) -> bool {
        self.congestion_window < self.slow_start_threshold
    }

    /// `reserved` comes from the same single-owner ledger as actual flight.
    /// Probe/ACK-only exceptions bypass cwnd only, never path anti-amplification.
    pub fn can_send(
        &self,
        actual_flight: u64,
        reserved: u64,
        bytes: u64,
        in_flight: bool,
        pto_probe: bool,
    ) -> bool {
        if !in_flight || pto_probe {
            return true;
        }
        actual_flight
            .checked_add(reserved)
            .and_then(|sum| sum.checked_add(bytes))
            .is_some_and(|total| total <= self.congestion_window)
    }

    /// Pass only bytes the ledger has just removed from flight due to a *new*
    /// ACK for this packet. Late ACKs after declared loss and duplicates supply
    /// zero. Does not itself subtract flight. App/flow-limited ACKs do not grow.
    pub fn on_ack(
        &mut self,
        now: u64,
        sent_at: u64,
        newly_removed_bytes: u64,
        app_or_flow_limited: bool,
    ) -> Result<(), RecoveryError> {
        check_time(self.last_event_at, now)?;
        if sent_at > now {
            return Err(RecoveryError::TimeWentBackwards);
        }
        if newly_removed_bytes != 0
            && !app_or_flow_limited
            && self.recovery_started.is_none_or(|start| sent_at > start)
        {
            if self.in_slow_start() {
                self.congestion_window = self.congestion_window.saturating_add(newly_removed_bytes);
            } else {
                // Retain fractional growth so tiny newly-ACKed packets cannot
                // stall integer congestion avoidance. All products fit u128:
                // max_datagram_size <= u64::MAX/2, and remainder < old cwnd.
                let numerator = self.additive_credit
                    + u128::from(self.max_datagram_size) * u128::from(newly_removed_bytes);
                let growth = narrow(numerator / u128::from(self.congestion_window))?;
                self.additive_credit = numerator % u128::from(self.congestion_window);
                self.congestion_window = self.congestion_window.saturating_add(growth);
            }
        }
        self.last_event_at = Some(now);
        Ok(())
    }

    /// Call only on newly lost in-flight data or independently validated new
    /// ECN-CE evidence. Repeated losses from the same recovery epoch do not halve
    /// the window again. Packet send-time zero is valid, not a sentinel.
    pub fn on_congestion_event(
        &mut self,
        now: u64,
        latest_lost_sent_at: u64,
    ) -> Result<bool, RecoveryError> {
        check_time(self.last_event_at, now)?;
        if latest_lost_sent_at > now {
            return Err(RecoveryError::TimeWentBackwards);
        }
        if self
            .recovery_started
            .is_some_and(|start| latest_lost_sent_at <= start)
        {
            self.last_event_at = Some(now);
            return Ok(false);
        }
        self.slow_start_threshold = self.congestion_window / 2;
        self.congestion_window = self.slow_start_threshold.max(self.minimum_window);
        self.recovery_started = Some(now);
        self.additive_credit = 0;
        self.last_event_at = Some(now);
        Ok(true)
    }

    pub fn on_persistent_congestion(
        &mut self,
        now: u64,
        evidence: PersistentCongestion,
        rtt: &mut RttEstimator,
    ) -> Result<bool, RecoveryError> {
        check_time(self.last_event_at, now)?;
        if evidence.last_sent_at > now {
            return Err(RecoveryError::TimeWentBackwards);
        }
        if self
            .persistent_end
            .is_some_and(|end| evidence.last_sent_at <= end)
        {
            self.last_event_at = Some(now);
            return Ok(false);
        }
        self.congestion_window = self.minimum_window;
        self.recovery_started = None;
        self.additive_credit = 0;
        self.persistent_end = Some(evidence.last_sent_at);
        self.last_event_at = Some(now);
        rtt.reset_min_after_persistent_congestion();
        Ok(true)
    }
}

/// Bounded token-bucket pacing at 1.25*cwnd/smoothed_rtt. The configured burst
/// must not exceed the allowed initial window without explicit path knowledge.
/// Use one serialized submission at a time; poll does not reserve credit.
/// Charge accepted packets with `on_sent`; cancelled adapter submissions do not
/// consume credit. PTO probes and ACK-only packets bypass delay; probes still
/// drain available tokens. Path and sent-ledger reservations remain mandatory.
pub struct Pacer {
    capacity: u64,
    tokens: u64,
    fraction: u128,
    rate_numerator: u128,
    rate_denominator: u128,
    last_update: u64,
}

impl Pacer {
    pub fn new(
        now: u64,
        burst_bytes: u64,
        congestion_window: u64,
        smoothed_rtt_us: u64,
    ) -> Result<Self, RecoveryError> {
        if burst_bytes == 0 || congestion_window == 0 || burst_bytes > congestion_window {
            return Err(RecoveryError::InvalidConfiguration);
        }
        Ok(Self {
            capacity: burst_bytes,
            tokens: burst_bytes,
            fraction: 0,
            rate_numerator: 5 * u128::from(congestion_window),
            rate_denominator: 4 * u128::from(smoothed_rtt_us.max(TIMER_GRANULARITY_US)),
            last_update: now,
        })
    }

    fn credit_at(&self, now: u64) -> Result<(u64, u128), RecoveryError> {
        let elapsed = now
            .checked_sub(self.last_update)
            .ok_or(RecoveryError::TimeWentBackwards)?;
        let earned = u128::from(elapsed)
            .checked_mul(self.rate_numerator)
            .and_then(|value| value.checked_add(self.fraction))
            .ok_or(RecoveryError::Overflow)?;
        let whole = earned / self.rate_denominator;
        if whole >= u128::from(self.capacity - self.tokens) {
            return Ok((self.capacity, 0));
        }
        Ok((self.tokens + whole as u64, earned % self.rate_denominator))
    }

    /// Apply the previous rate until now, then update. Dropping any sub-byte
    /// remainder on a rate change is conservative and prevents retroactive bursts.
    pub fn set_rate(
        &mut self,
        now: u64,
        congestion_window: u64,
        smoothed_rtt_us: u64,
    ) -> Result<(), RecoveryError> {
        if congestion_window == 0 {
            return Err(RecoveryError::InvalidConfiguration);
        }
        let (tokens, _) = self.credit_at(now)?;
        self.tokens = tokens;
        self.fraction = 0;
        self.rate_numerator = 5 * u128::from(congestion_window);
        self.rate_denominator = 4 * u128::from(smoothed_rtt_us.max(TIMER_GRANULARITY_US));
        self.last_update = now;
        Ok(())
    }

    /// Return None when ready, otherwise the earliest microsecond deadline.
    pub fn next_send_at(
        &self,
        now: u64,
        bytes: u64,
        ack_only: bool,
        pto_probe: bool,
    ) -> Result<Option<u64>, RecoveryError> {
        let (tokens, fraction) = self.credit_at(now)?;
        if ack_only || pto_probe {
            return Ok(None);
        }
        if bytes > self.capacity {
            return Err(RecoveryError::InvalidConfiguration);
        }
        if bytes <= tokens {
            return Ok(None);
        }
        let needed = u128::from(bytes - tokens)
            .checked_mul(self.rate_denominator)
            .ok_or(RecoveryError::Overflow)?
            - fraction;
        let wait = narrow(needed.div_ceil(self.rate_numerator))?;
        Ok(Some(now.checked_add(wait).ok_or(RecoveryError::Overflow)?))
    }

    pub fn on_sent(
        &mut self,
        now: u64,
        bytes: u64,
        ack_only: bool,
        pto_probe: bool,
    ) -> Result<(), RecoveryError> {
        let (tokens, fraction) = self.credit_at(now)?;
        if !ack_only && !pto_probe && bytes > tokens {
            return Err(RecoveryError::PacingLimited);
        }
        self.tokens = if ack_only {
            tokens
        } else {
            tokens.saturating_sub(bytes)
        };
        self.fraction = fraction;
        self.last_update = now;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounting::{AckRange, PacketKind, SentLedger};

    const APP: PacketNumberSpace = PacketNumberSpace::ApplicationData;

    fn sample(now: u64, sent_at: u64) -> RttSample {
        RttSample {
            now,
            sent_at,
            ack_delay_us: 0,
            max_ack_delay_us: 25_000,
            space: APP,
            handshake_confirmed: true,
            largest_newly_acknowledged: true,
            any_newly_acknowledged_ack_eliciting: true,
            local_decryption_delay_us: 0,
        }
    }

    fn server(confirmed: bool) -> TimerContext {
        TimerContext {
            is_server: true,
            handshake_confirmed: confirmed,
            handshake_ack_received: false,
            server_amplification_blocked: false,
        }
    }

    fn client() -> TimerContext {
        TimerContext {
            is_server: false,
            ..server(false)
        }
    }

    fn sent(at: u64) -> SpaceTimer {
        SpaceTimer {
            keys_available: true,
            ack_eliciting_in_flight: true,
            last_ack_eliciting_sent_at: Some(at),
            loss_time: None,
        }
    }

    #[test]
    fn rtt_initial_values_first_sample_and_standard_update() {
        let mut rtt = RttEstimator::default();
        assert_eq!(rtt.smoothed_us(), 333_000);
        assert_eq!(rtt.variation_us(), 166_500);
        assert_eq!(rtt.min_us(), None);
        assert_eq!(rtt.pto_duration_us(0, 0), Ok(999_000));
        assert_eq!(rtt.pto_duration_us(25_000, 1), Ok(2_048_000));
        let mut first = sample(100_000, 0);
        first.ack_delay_us = 90_000;
        assert_eq!(rtt.on_ack(first), Ok(true));
        assert_eq!(rtt.latest_us(), 100_000);
        assert_eq!(rtt.min_us(), Some(100_000));
        assert_eq!(rtt.smoothed_us(), 100_000);
        assert_eq!(rtt.variation_us(), 50_000);
        let mut second = sample(230_000, 100_000);
        second.ack_delay_us = 40_000; // Confirmed cap is 25ms.
        rtt.on_ack(second).unwrap();
        assert_eq!(rtt.latest_us(), 130_000);
        assert_eq!(rtt.min_us(), Some(100_000));
        assert_eq!(rtt.smoothed_us(), 100_625);
        assert_eq!(rtt.variation_us(), 38_750);
    }

    #[test]
    fn rtt_delay_is_uncapped_before_confirmation_and_never_below_minimum() {
        let mut rtt = RttEstimator::default();
        rtt.on_ack(sample(100_000, 0)).unwrap();
        let mut next = sample(240_000, 100_000);
        next.handshake_confirmed = false;
        next.ack_delay_us = 40_000;
        rtt.on_ack(next).unwrap();
        assert_eq!(rtt.smoothed_us(), 100_000);
        assert_eq!(rtt.variation_us(), 37_500);
        let mut lower = sample(320_000, 240_000);
        lower.ack_delay_us = 25_000;
        rtt.on_ack(lower).unwrap();
        assert_eq!(rtt.min_us(), Some(80_000));
        assert_eq!(rtt.smoothed_us(), 97_500); // Uses 80ms, not 55ms.
    }

    #[test]
    fn initial_ack_delays_are_ignored() {
        for space in [PacketNumberSpace::Initial] {
            let mut rtt = RttEstimator::default();
            rtt.on_ack(sample(100_000, 0)).unwrap();
            let mut ack = sample(240_000, 100_000);
            ack.space = space;
            ack.ack_delay_us = u64::MAX;
            rtt.on_ack(ack).unwrap();
            assert_eq!(rtt.smoothed_us(), 105_000);
        }
    }

    #[test]
    fn handshake_key_buffering_delay_does_not_inflate_path_rtt() {
        let mut rtt = RttEstimator::default();
        rtt.on_ack(sample(30_000, 0)).unwrap();
        let mut ack = sample(75_030_000, 0);
        ack.space = PacketNumberSpace::Handshake;
        ack.handshake_confirmed = false;
        ack.ack_delay_us = 75_000_000;
        assert!(rtt.on_ack(ack).unwrap());
        assert_eq!(rtt.smoothed_us(), 30_000);
        assert_eq!(rtt.variation_us(), 11_250);
        assert_eq!(rtt.pto_duration_us(25_000, 0), Ok(100_000));
    }

    #[test]
    fn preconfirmation_delay_below_minimum_is_ignored_not_clamped() {
        let mut rtt = RttEstimator::default();
        rtt.on_ack(sample(31_000, 0)).unwrap();
        let before = (
            rtt.latest_us(),
            rtt.min_us(),
            rtt.smoothed_us(),
            rtt.variation_us(),
        );
        let mut ack = sample(75_030_000, 0);
        ack.space = PacketNumberSpace::Handshake;
        ack.handshake_confirmed = false;
        ack.ack_delay_us = 75_000_000;
        assert!(!rtt.on_ack(ack).unwrap());
        assert_eq!(
            (
                rtt.latest_us(),
                rtt.min_us(),
                rtt.smoothed_us(),
                rtt.variation_us()
            ),
            before
        );
        ack.handshake_confirmed = true;
        assert!(rtt.on_ack(ack).unwrap());
        assert!(rtt.smoothed_us() > 31_000); // Confirmed delay is capped.
    }

    #[test]
    fn rtt_sampling_gates_and_invalid_times_do_not_change_estimator() {
        let mut rtt = RttEstimator::default();
        let mut ack = sample(1, 2);
        ack.largest_newly_acknowledged = false;
        assert_eq!(rtt.on_ack(ack), Ok(false));
        ack.largest_newly_acknowledged = true;
        ack.any_newly_acknowledged_ack_eliciting = false;
        assert_eq!(rtt.on_ack(ack), Ok(false));
        ack.any_newly_acknowledged_ack_eliciting = true;
        assert_eq!(rtt.on_ack(ack), Err(RecoveryError::TimeWentBackwards));
        assert_eq!(rtt.min_us(), None);
        rtt.on_ack(sample(100, 0)).unwrap();
        assert_eq!(
            rtt.on_ack(sample(99, 0)),
            Err(RecoveryError::TimeWentBackwards)
        );
        assert_eq!(rtt.smoothed_us(), 100);
        let mut invalid = sample(200, 150);
        invalid.handshake_confirmed = false;
        invalid.local_decryption_delay_us = 51;
        assert_eq!(rtt.on_ack(invalid), Err(RecoveryError::InvalidSample));
        assert_eq!(rtt.latest_us(), 100);
    }

    #[test]
    fn local_key_wait_and_zero_timestamp_are_explicit() {
        let mut rtt = RttEstimator::default();
        let mut first = sample(150_000, 0);
        first.handshake_confirmed = false;
        first.local_decryption_delay_us = 50_000;
        rtt.on_ack(first).unwrap();
        assert_eq!(rtt.latest_us(), 100_000);
        let mut zero = RttEstimator::default();
        zero.on_ack(sample(0, 0)).unwrap();
        assert_eq!(zero.first_sample_at(), Some(0));
        assert_eq!(zero.min_us(), Some(0));
        assert_eq!(zero.pto_duration_us(0, 0), Ok(1_000));
        assert_eq!(zero.loss_delay_us(), Ok(1_000));
    }

    #[test]
    fn extreme_rtt_math_never_wraps() {
        assert!(matches!(
            RttEstimator::new(0),
            Err(RecoveryError::InvalidConfiguration)
        ));
        let mut rtt = RttEstimator::default();
        rtt.on_ack(sample(u64::MAX, 0)).unwrap();
        rtt.on_ack(sample(u64::MAX, 0)).unwrap();
        assert_eq!(rtt.smoothed_us(), u64::MAX);
        assert_eq!(rtt.loss_delay_us(), Err(RecoveryError::Overflow));
        assert_eq!(rtt.pto_duration_us(0, 0), Err(RecoveryError::Overflow));
        assert_eq!(
            RttEstimator::default().pto_duration_us(0, 64),
            Err(RecoveryError::Overflow)
        );
    }

    #[test]
    fn time_and_gap_aware_packet_loss_thresholds() {
        let rtt = RttEstimator::default();
        let candidate = LossCandidate {
            packet_number: 10,
            sent_at: 100,
            newer_sent_packets: 2,
        };
        let deadline = 100 + 374_625;
        assert_eq!(
            loss_decision(&rtt, candidate, Some(12), deadline - 1),
            Ok(LossDecision::WaitUntil(deadline))
        );
        assert_eq!(
            loss_decision(&rtt, candidate, Some(12), deadline),
            Ok(LossDecision::Lost)
        );
        assert_eq!(
            loss_decision(
                &rtt,
                LossCandidate {
                    newer_sent_packets: 3,
                    ..candidate
                },
                Some(13),
                101
            ),
            Ok(LossDecision::Lost)
        );
        // Ninety cancelled/skipped PNs must not act like three sent packets.
        assert_eq!(
            loss_decision(
                &rtt,
                LossCandidate {
                    newer_sent_packets: 1,
                    ..candidate
                },
                Some(100),
                101
            ),
            Ok(LossDecision::WaitUntil(deadline))
        );
        assert_eq!(
            loss_decision(&rtt, candidate, None, u64::MAX),
            Ok(LossDecision::NotEligible)
        );
        assert_eq!(
            loss_decision(&rtt, candidate, Some(9), u64::MAX),
            Ok(LossDecision::NotEligible)
        );
        assert_eq!(
            loss_decision(&rtt, candidate, Some(11), 101),
            Err(RecoveryError::InvalidPacketEvidence)
        );
    }

    #[test]
    fn loss_time_rounding_and_integer_boundaries() {
        let mut rtt = RttEstimator::default();
        rtt.on_ack(sample(1_001, 0)).unwrap();
        assert_eq!(rtt.loss_delay_us(), Ok(1_127));
        let candidate = LossCandidate {
            packet_number: MAX_PACKET_NUMBER,
            sent_at: u64::MAX - 1,
            newer_sent_packets: 0,
        };
        assert_eq!(
            loss_decision(&rtt, candidate, Some(MAX_PACKET_NUMBER), u64::MAX),
            Err(RecoveryError::Overflow)
        );
        assert_eq!(
            loss_decision(&rtt, candidate, Some(MAX_PACKET_NUMBER), 0),
            Err(RecoveryError::TimeWentBackwards)
        );
        assert_eq!(
            loss_decision(
                &rtt,
                LossCandidate {
                    packet_number: u64::MAX,
                    ..candidate
                },
                None,
                u64::MAX
            ),
            Err(RecoveryError::InvalidPacketEvidence)
        );
    }

    #[test]
    fn pto_emits_probes_once_and_backs_off_without_loss() {
        let rtt = RttEstimator::default();
        let spaces = [sent(0), SpaceTimer::default(), SpaceTimer::default()];
        let mut timer = RecoveryTimer::new();
        assert_eq!(
            timer
                .update(0, &rtt, &spaces, server(false), 25_000)
                .unwrap()
                .unwrap()
                .at,
            999_000
        );
        assert_eq!(timer.on_timeout(998_999), Ok(None));
        assert_eq!(
            timer.on_timeout(999_000),
            Ok(Some(TimeoutAction::Probe {
                space: PacketNumberSpace::Initial,
                max_datagrams: 2,
                minimum_datagram_size: 1200,
            }))
        );
        assert_eq!(timer.pto_count(), 1);
        assert_eq!(timer.on_timeout(999_000), Ok(None));
        assert_eq!(
            timer
                .update(999_000, &rtt, &spaces, server(false), 25_000)
                .unwrap()
                .unwrap()
                .at,
            1_998_000
        );
        timer.on_new_ack(false, true);
        assert_eq!(timer.pto_count(), 1);
        timer.on_new_ack(true, false);
        assert_eq!(timer.pto_count(), 1);
        timer.on_new_ack(true, true);
        assert_eq!(timer.pto_count(), 0);
    }

    #[test]
    fn loss_timer_takes_precedence_even_when_server_cannot_probe() {
        let rtt = RttEstimator::default();
        let mut spaces = [sent(0), sent(0), SpaceTimer::default()];
        spaces[0].loss_time = Some(200);
        spaces[1].loss_time = Some(100);
        let context = TimerContext {
            server_amplification_blocked: true,
            ..server(false)
        };
        let mut timer = RecoveryTimer::new();
        assert_eq!(
            timer.update(100, &rtt, &spaces, context, 25_000),
            Ok(Some(TimerDeadline {
                at: 100,
                kind: TimerKind::Loss(PacketNumberSpace::Handshake)
            }))
        );
        assert_eq!(
            timer.on_timeout(100),
            Ok(Some(TimeoutAction::DetectLoss(
                PacketNumberSpace::Handshake
            )))
        );
        assert_eq!(timer.pto_count(), 0);
        spaces[0].loss_time = None;
        spaces[1].loss_time = None;
        assert_eq!(timer.update(100, &rtt, &spaces, context, 25_000), Ok(None));
    }

    #[test]
    fn pto_selects_earliest_space_and_applies_ack_delay_only_to_application() {
        let rtt = RttEstimator::default();
        let mut timer = RecoveryTimer::new();
        let spaces = [sent(50_000), sent(10_000), sent(0)];
        let next = timer
            .update(50_000, &rtt, &spaces, server(true), 25_000)
            .unwrap()
            .unwrap();
        assert_eq!(
            next,
            TimerDeadline {
                at: 1_009_000,
                kind: TimerKind::Probe {
                    space: PacketNumberSpace::Handshake,
                    anti_deadlock: false
                }
            }
        );
        let only_app = [SpaceTimer::default(), SpaceTimer::default(), sent(0)];
        let next = timer
            .update(50_000, &rtt, &only_app, server(true), 25_000)
            .unwrap()
            .unwrap();
        assert_eq!(next.at, 1_024_000);
        assert_eq!(
            timer.update(50_000, &rtt, &only_app, server(false), 25_000),
            Ok(None)
        );
    }

    #[test]
    fn client_anti_deadlock_pto_survives_empty_flight_and_only_zero_rtt() {
        let rtt = RttEstimator::default();
        let mut timer = RecoveryTimer::new();
        let mut spaces = [SpaceTimer {
            keys_available: true,
            ..SpaceTimer::default()
        }; 3];
        spaces[1].keys_available = false;
        let next = timer
            .update(1, &rtt, &spaces, client(), 25_000)
            .unwrap()
            .unwrap();
        assert_eq!(
            next,
            TimerDeadline {
                at: 999_001,
                kind: TimerKind::Probe {
                    space: PacketNumberSpace::Initial,
                    anti_deadlock: true
                }
            }
        );
        spaces[1].keys_available = true;
        spaces[2] = sent(0); // Unconfirmed 0-RTT uses Application PN space.
        let next = timer
            .update(1, &rtt, &spaces, client(), 25_000)
            .unwrap()
            .unwrap();
        assert_eq!(
            next.kind,
            TimerKind::Probe {
                space: PacketNumberSpace::Handshake,
                anti_deadlock: true
            }
        );
        assert_eq!(
            timer.on_timeout(next.at).unwrap(),
            Some(TimeoutAction::Probe {
                space: PacketNumberSpace::Handshake,
                max_datagrams: 1,
                minimum_datagram_size: 0
            })
        );
        spaces[2].ack_eliciting_in_flight = false;
        let validated = TimerContext {
            handshake_ack_received: true,
            ..client()
        };
        assert_eq!(
            timer.update(next.at, &rtt, &spaces, validated, 25_000),
            Ok(None)
        );
    }

    #[test]
    fn equivalent_anti_deadlock_updates_preserve_the_original_deadline() {
        let rtt = RttEstimator::default();
        let spaces = [
            SpaceTimer {
                keys_available: true,
                ..SpaceTimer::default()
            },
            SpaceTimer::default(),
            SpaceTimer::default(),
        ];
        let mut timer = RecoveryTimer::new();
        let original = timer.update(0, &rtt, &spaces, client(), 0).unwrap();
        assert_eq!(original.unwrap().at, 999_000);
        for now in [1, 100, 998_999, 999_000] {
            assert_eq!(timer.update(now, &rtt, &spaces, client(), 0), Ok(original));
        }
        assert!(matches!(
            timer.on_timeout(999_000),
            Ok(Some(TimeoutAction::Probe {
                max_datagrams: 1,
                ..
            }))
        ));
        let next = timer.update(999_000, &rtt, &spaces, client(), 0).unwrap();
        assert_eq!(next.unwrap().at, 2_997_000);
        assert_eq!(
            timer.update(1_000_000, &rtt, &spaces, client(), 0),
            Ok(next)
        );
        // Even near clock exhaustion an already armed overdue deadline must
        // remain overdue; adding another duration would overflow or postpone it.
        assert_eq!(timer.update(u64::MAX, &rtt, &spaces, client(), 0), Ok(next));
    }

    #[test]
    fn anti_deadlock_rearms_when_space_duration_or_timer_mode_changes() {
        let rtt = RttEstimator::default();
        let mut spaces = [
            SpaceTimer {
                keys_available: true,
                ..SpaceTimer::default()
            },
            SpaceTimer::default(),
            SpaceTimer::default(),
        ];
        let mut timer = RecoveryTimer::new();
        timer.update(0, &rtt, &spaces, client(), 0).unwrap();
        spaces[1].keys_available = true;
        let handshake = timer
            .update(100, &rtt, &spaces, client(), 0)
            .unwrap()
            .unwrap();
        assert_eq!(handshake.at, 999_100);
        assert_eq!(
            handshake.kind,
            TimerKind::Probe {
                space: PacketNumberSpace::Handshake,
                anti_deadlock: true
            }
        );
        let changed_rtt = RttEstimator::new(10_000).unwrap();
        let shortened = timer
            .update(200, &changed_rtt, &spaces, client(), 0)
            .unwrap();
        assert_eq!(shortened.unwrap().at, 30_200);
        assert_eq!(
            timer.update(199, &changed_rtt, &spaces, client(), 0),
            Err(RecoveryError::TimeWentBackwards)
        );
        assert_eq!(timer.deadline(), shortened);
        spaces[1] = sent(250);
        let regular = timer
            .update(250, &changed_rtt, &spaces, client(), 0)
            .unwrap()
            .unwrap();
        assert_eq!(regular.at, 30_250);
        assert_eq!(
            regular.kind,
            TimerKind::Probe {
                space: PacketNumberSpace::Handshake,
                anti_deadlock: false
            }
        );
        spaces[1].ack_eliciting_in_flight = false;
        assert_eq!(
            timer
                .update(300, &changed_rtt, &spaces, client(), 0)
                .unwrap()
                .unwrap()
                .at,
            30_300
        );
        timer.on_keys_discarded(PacketNumberSpace::Initial).unwrap();
        assert_eq!(
            timer
                .update(400, &changed_rtt, &spaces, client(), 0)
                .unwrap()
                .unwrap()
                .at,
            30_400
        );
    }

    #[test]
    fn timer_discard_reversal_missing_metadata_and_overflow_are_safe() {
        let rtt = RttEstimator::default();
        let mut timer = RecoveryTimer::new();
        let mut spaces = [sent(0), SpaceTimer::default(), SpaceTimer::default()];
        let old = timer.update(100, &rtt, &spaces, server(false), 0).unwrap();
        assert_eq!(
            timer.update(99, &rtt, &spaces, server(false), 0),
            Err(RecoveryError::TimeWentBackwards)
        );
        assert_eq!(timer.deadline(), old);
        spaces[0].last_ack_eliciting_sent_at = None;
        assert_eq!(
            timer.update(100, &rtt, &spaces, server(false), 0),
            Err(RecoveryError::InconsistentTimerState)
        );
        assert_eq!(timer.deadline(), old);
        assert_eq!(
            timer.on_keys_discarded(APP),
            Err(RecoveryError::InvalidConfiguration)
        );
        assert_eq!(timer.deadline(), old);
        timer.on_keys_discarded(PacketNumberSpace::Initial).unwrap();
        assert_eq!(timer.deadline(), None);
        spaces[0] = sent(u64::MAX - 1);
        assert_eq!(
            timer.update(u64::MAX, &rtt, &spaces, server(false), 0),
            Err(RecoveryError::Overflow)
        );
        assert_eq!(timer.deadline(), None);
        timer.pto_count = 64;
        spaces[0] = sent(100);
        assert_eq!(
            timer.update(100, &rtt, &spaces, server(false), 0),
            Err(RecoveryError::Overflow)
        );
        assert_eq!(timer.pto_count(), 64);
    }

    #[test]
    fn initial_window_minimum_and_cwnd_probe_exception() {
        for (mtu, expected) in [
            (1200, 12_000),
            (1472, 14_720),
            (1500, 14_720),
            (9000, 18_000),
        ] {
            let cc = NewReno::new(mtu).unwrap();
            assert_eq!(cc.congestion_window(), expected);
            assert_eq!(cc.minimum_window(), 2 * mtu);
        }
        assert!(matches!(
            NewReno::new(1199),
            Err(RecoveryError::InvalidConfiguration)
        ));
        assert!(matches!(
            NewReno::new(u64::MAX),
            Err(RecoveryError::Overflow)
        ));
        let cc = NewReno::new(1200).unwrap();
        assert!(cc.can_send(10_000, 800, 1200, true, false));
        assert!(!cc.can_send(10_000, 801, 1200, true, false));
        assert!(!cc.can_send(u64::MAX, 1, 1, true, false));
        assert!(cc.can_send(u64::MAX, 1, 1200, true, true));
        assert!(cc.can_send(u64::MAX, 1, 80, false, false));
    }

    #[test]
    fn newreno_uses_once_only_ledger_bytes_without_double_subtraction() {
        let mut ledger = SentLedger::<1>::new(1);
        let mut cc = NewReno::new(1200).unwrap();
        let packet = ledger.reserve(PacketKind::OneRtt, 1200, true).unwrap();
        ledger.adapter_accepted(packet, 0).unwrap();
        let range = [AckRange { start: 0, end: 0 }];
        for now in [10, 11] {
            let summary = ledger.acknowledge(APP, &range).unwrap();
            cc.on_ack(now, 0, summary.bytes_removed_from_flight, false)
                .unwrap();
        }
        assert_eq!(ledger.bytes_in_flight(), 0);
        assert_eq!(cc.congestion_window(), 13_200);
    }

    #[test]
    fn newreno_loss_epoch_ack_suppression_and_additive_increase() {
        let mut cc = NewReno::new(1200).unwrap();
        cc.on_ack(0, 0, 1200, false).unwrap();
        assert_eq!(cc.congestion_window(), 13_200);
        assert_eq!(cc.on_congestion_event(10, 0), Ok(true));
        assert_eq!(cc.congestion_window(), 6600);
        assert_eq!(cc.slow_start_threshold(), 6600);
        assert_eq!(cc.on_congestion_event(11, 5), Ok(false));
        cc.on_ack(11, 5, 1200, false).unwrap();
        assert_eq!(cc.congestion_window(), 6600);
        cc.on_ack(12, 11, 1200, false).unwrap();
        assert_eq!(cc.congestion_window(), 6818);
        assert_eq!(cc.on_congestion_event(13, 11), Ok(true));
        assert_eq!(cc.congestion_window(), 3409);
        cc.on_congestion_event(15, 14).unwrap();
        assert_eq!(cc.congestion_window(), 2400);
        cc.on_congestion_event(17, 16).unwrap();
        assert_eq!(cc.congestion_window(), 2400);
    }

    #[test]
    fn newreno_small_acks_accumulate_and_underutilized_ack_does_not_grow() {
        let mut cc = NewReno::new(1200).unwrap();
        cc.on_ack(0, 0, 1200, true).unwrap();
        assert_eq!(cc.congestion_window(), 12_000);
        cc.on_congestion_event(1, 0).unwrap();
        for now in 2..7 {
            cc.on_ack(now, now, 1, false).unwrap();
        }
        assert_eq!(cc.congestion_window(), 6001);
        let old = cc.congestion_window();
        assert_eq!(
            cc.on_ack(5, 5, 1000, false),
            Err(RecoveryError::TimeWentBackwards)
        );
        assert_eq!(
            cc.on_congestion_event(7, 8),
            Err(RecoveryError::TimeWentBackwards)
        );
        assert_eq!(cc.congestion_window(), old);
    }

    #[test]
    fn newreno_growth_saturates_safely_at_counter_limit() {
        let mut cc = NewReno::new(1200).unwrap();
        cc.on_ack(1, 0, u64::MAX, false).unwrap();
        assert_eq!(cc.congestion_window(), u64::MAX);
        cc.on_ack(2, 1, u64::MAX, false).unwrap();
        assert_eq!(cc.congestion_window(), u64::MAX);
        let mut largest_mtu = NewReno::new(u64::MAX / 2).unwrap();
        largest_mtu.on_congestion_event(1, 0).unwrap();
        largest_mtu.on_ack(2, 2, u64::MAX, false).unwrap();
        assert_eq!(largest_mtu.congestion_window(), u64::MAX);
    }

    fn known_rtt() -> RttEstimator {
        RttEstimator {
            latest: 1_000_000,
            minimum: Some(900_000),
            smoothed: 1_000_000,
            variation: 250_000,
            first_sample_at: Some(0),
            last_sample_at: Some(0),
        }
    }

    fn lost(at: u64) -> PersistentPacket {
        PersistentPacket {
            sent_at: at,
            ack_eliciting: true,
            outcome: PacketOutcome::Lost,
        }
    }

    #[test]
    fn persistent_congestion_duration_is_strict_and_has_no_pto_backoff() {
        let rtt = known_rtt();
        assert_eq!(rtt.persistent_congestion_duration_us(0), Ok(6_000_000));
        assert_eq!(rtt.persistent_congestion_duration_us(25_000), Ok(6_075_000));
        assert_eq!(
            persistent_congestion::<2>(&rtt, &[lost(1_000_000), lost(7_000_000)], 0),
            Ok(None)
        );
        let evidence = persistent_congestion::<2>(&rtt, &[lost(1_000_000), lost(8_000_000)], 0)
            .unwrap()
            .unwrap();
        assert_eq!(evidence.first_sent_at(), 1_000_000);
        assert_eq!(evidence.last_sent_at(), 8_000_000);
    }

    #[test]
    fn persistent_congestion_requires_prior_rtt_two_ack_eliciting_ends_and_complete_loss() {
        let mut rtt = known_rtt();
        for outcome in [
            PacketOutcome::Acknowledged,
            PacketOutcome::Outstanding,
            PacketOutcome::Discarded,
        ] {
            let middle = PersistentPacket {
                outcome,
                ..lost(2_000_000)
            };
            assert_eq!(
                persistent_congestion::<3>(&rtt, &[lost(1_000_000), middle, lost(8_000_000)], 0),
                Ok(None)
            );
        }
        let not_eliciting = PersistentPacket {
            ack_eliciting: false,
            ..lost(8_000_000)
        };
        assert_eq!(
            persistent_congestion::<2>(&rtt, &[lost(1_000_000), not_eliciting], 0),
            Ok(None)
        );
        rtt.first_sample_at = Some(1_000_000);
        assert_eq!(
            persistent_congestion::<2>(&rtt, &[lost(1_000_000), lost(8_000_000)], 0),
            Ok(None)
        );
        rtt.first_sample_at = None;
        assert_eq!(
            persistent_congestion::<2>(&rtt, &[lost(1_000_000), lost(8_000_000)], 0),
            Ok(None)
        );
    }

    #[test]
    fn persistent_history_order_capacity_and_duplicate_reset_are_checked() {
        let mut rtt = known_rtt();
        let history = [lost(1_000_000), lost(8_000_000)];
        assert_eq!(
            persistent_congestion::<1>(&rtt, &history, 0),
            Err(RecoveryError::TooManyRecords)
        );
        assert_eq!(
            persistent_congestion::<2>(&rtt, &[history[1], history[0]], 0),
            Err(RecoveryError::UnorderedHistory)
        );
        let evidence = persistent_congestion::<2>(&rtt, &history, 0)
            .unwrap()
            .unwrap();
        let mut cc = NewReno::new(1200).unwrap();
        assert_eq!(
            cc.on_persistent_congestion(7_000_000, evidence, &mut rtt),
            Err(RecoveryError::TimeWentBackwards)
        );
        assert_eq!(cc.congestion_window(), 12_000);
        assert_eq!(
            cc.on_persistent_congestion(9_000_000, evidence, &mut rtt),
            Ok(true)
        );
        assert_eq!(cc.congestion_window(), 2400);
        assert_eq!(rtt.min_us(), Some(1_000_000));
        cc.on_ack(10_000_000, 9_500_000, 1200, false).unwrap();
        assert_eq!(cc.congestion_window(), 3600);
        assert_eq!(
            cc.on_persistent_congestion(11_000_000, evidence, &mut rtt),
            Ok(false)
        );
        assert_eq!(cc.congestion_window(), 3600);
    }

    #[test]
    fn persistent_congestion_does_not_hide_acknowledged_timestamp_ties() {
        let rtt = known_rtt();
        let tied_ack = PersistentPacket {
            sent_at: 8_000_000,
            ack_eliciting: true,
            outcome: PacketOutcome::Acknowledged,
        };
        assert_eq!(
            persistent_congestion::<3>(&rtt, &[lost(1_000_000), lost(8_000_000), tied_ack], 0),
            Ok(None)
        );
    }

    #[test]
    fn pacing_burst_refill_and_fractional_deadlines() {
        let mut pacer = Pacer::new(0, 2400, 12_000, 100_000).unwrap();
        pacer.on_sent(0, 1200, false, false).unwrap();
        pacer.on_sent(0, 1200, false, false).unwrap();
        assert_eq!(pacer.next_send_at(0, 1200, false, false), Ok(Some(8000)));
        assert_eq!(pacer.next_send_at(7999, 1200, false, false), Ok(Some(8000)));
        assert_eq!(
            pacer.on_sent(7999, 1200, false, false),
            Err(RecoveryError::PacingLimited)
        );
        assert_eq!(pacer.next_send_at(8000, 1200, false, false), Ok(None));
        pacer.on_sent(8000, 1200, false, false).unwrap();
        pacer.on_sent(100_000, 2400, false, false).unwrap();
        assert_eq!(
            pacer.next_send_at(100_000, 1, false, false),
            Ok(Some(100_007))
        );
    }

    #[test]
    fn pacing_ack_bypass_probe_credit_and_old_rate_accounting() {
        let mut pacer = Pacer::new(0, 1200, 12_000, 100_000).unwrap();
        pacer.on_sent(0, 1200, true, false).unwrap();
        assert_eq!(pacer.tokens, 1200);
        pacer.on_sent(0, 1200, false, false).unwrap();
        assert_eq!(pacer.next_send_at(0, 1200, true, false), Ok(None));
        assert_eq!(pacer.next_send_at(0, 1200, false, true), Ok(None));
        pacer.on_sent(0, 1200, false, true).unwrap();
        pacer.set_rate(4000, 6000, 100_000).unwrap();
        assert_eq!(pacer.tokens, 600);
        assert_eq!(
            pacer.next_send_at(4000, 1200, false, false),
            Ok(Some(12_000))
        );
    }

    #[test]
    fn pacing_invalid_inputs_clock_reversal_and_overflow_are_non_mutating() {
        assert!(matches!(
            Pacer::new(0, 0, 1200, 0),
            Err(RecoveryError::InvalidConfiguration)
        ));
        assert!(matches!(
            Pacer::new(0, 2400, 1200, 1000),
            Err(RecoveryError::InvalidConfiguration)
        ));
        let mut pacer = Pacer::new(1, 1200, 12_000, 100_000).unwrap();
        assert_eq!(
            pacer.on_sent(0, 1200, false, false),
            Err(RecoveryError::TimeWentBackwards)
        );
        assert_eq!(
            pacer.next_send_at(1, 1201, false, false),
            Err(RecoveryError::InvalidConfiguration)
        );
        assert_eq!(
            pacer.set_rate(2, 0, 1000),
            Err(RecoveryError::InvalidConfiguration)
        );
        assert_eq!(pacer.last_update, 1);
        assert_eq!(pacer.tokens, 1200);
        let huge = Pacer::new(0, 1, u64::MAX, 1).unwrap();
        assert_eq!(
            huge.next_send_at(u64::MAX, 1, false, false),
            Err(RecoveryError::Overflow)
        );
        let mut edge = Pacer::new(u64::MAX, 1, 1, 1000).unwrap();
        edge.on_sent(u64::MAX, 1, false, false).unwrap();
        assert_eq!(
            edge.next_send_at(u64::MAX, 1, false, false),
            Err(RecoveryError::Overflow)
        );
    }
}
