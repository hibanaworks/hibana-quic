//! Bounded ECN observation and single-path validation (RFC 9000 §13.4/A.4).
//!
//! This module does not authenticate packets or own sent history. The caller
//! supplies only processed, authenticated, nonduplicate receives and exact
//! first-ACK/first-loss summaries from its sent ledger. Counts are per packet
//! number space, including one count for each processed coalesced QUIC packet.
//! Adapter rejection is not a send. CE feedback must be validated before the
//! caller invokes its RFC 9002 congestion-event handler.
//!
//! One instance belongs to one immutable path identity for a connection. There
//! is deliberately no migration/reset API: transferring cumulative per-space
//! counts and ACK baselines between paths needs separate connection-level work.

use crate::accounting::{MAX_PACKET_NUMBER, PacketNumber, PacketNumberSpace};
use crate::packet::EcnCounts;

const ZERO: EcnCounts = EcnCounts {
    ect0: 0,
    ect1: 0,
    ce: 0,
};
const PROBE_PACKETS: u64 = 10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Codepoint {
    NotEct = 0,
    Ect1 = 1,
    Ect0 = 2,
    Ce = 3,
}
impl Codepoint {
    /// The upper six bits are DSCP, not ECN.
    pub const fn from_ip_tos(tos: u8) -> Self {
        match tos & 3 {
            0 => Self::NotEct,
            1 => Self::Ect1,
            2 => Self::Ect0,
            _ => Self::Ce,
        }
    }
    pub const fn bits(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathIdentity {
    pub connection_generation: u64,
    pub slot: u16,
    pub path_generation: u64,
}

/// Trusted adapter observation for a datagram on the endpoint's fixed path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Metadata {
    pub path: PathIdentity,
    pub codepoint: Option<Codepoint>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub enabled: bool,
    pub state: State,
    pub failure: Option<Failure>,
    pub sent: [MarkedPackets; 3],
    pub received: [Option<EcnCounts>; 3],
    pub validated_ce: u64,
    pub congestion_events: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    WrongPath,
    CounterLimit,
    InvalidPacketNumber,
    RepeatedSend,
    InvalidSentCodepoint,
    InconsistentLedger,
}

/// Exact numbers of newly acknowledged packets, classified by their original
/// accepted send marking. Include late first ACKs of declared-lost packets.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MarkedPackets {
    pub ect0: u64,
    pub ect1: u64,
}
impl MarkedPackets {
    fn total(self) -> Result<u64, Error> {
        self.ect0.checked_add(self.ect1).ok_or(Error::CounterLimit)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Testing,
    Unknown,
    Capable,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Failure {
    MissingCounts,
    DecreasedCounts,
    Bleached,
    Remarked,
    ExcessCounts,
    AllProbesLost,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Feedback {
    /// A reordered/repeated largest ACK cannot cause validation failure.
    Reordered,
    /// No usable ECN confirmation, or a previously failed path.
    Unvalidated,
    Validated {
        ce_increase: u64,
    },
    Failed(Failure),
}

/// Connection-level receive counts. A missing observation never becomes a
/// fabricated Not-ECT observation: ACK_ECN is disabled for that PN space once
/// any processed packet's metadata is unavailable. Payload admission is separate.
pub struct RxCounts {
    counts: [EcnCounts; 3],
    observed: [bool; 3],
    complete: [bool; 3],
}
impl RxCounts {
    pub const fn new() -> Self {
        Self {
            counts: [ZERO; 3],
            observed: [false; 3],
            complete: [true; 3],
        }
    }
    pub fn processed(
        &mut self,
        space: PacketNumberSpace,
        codepoint: Option<Codepoint>,
    ) -> Result<(), Error> {
        let i = space as usize;
        let Some(codepoint) = codepoint else {
            self.complete[i] = false;
            return Ok(());
        };
        let mut next = self.counts[i];
        let count = match codepoint {
            Codepoint::NotEct => None,
            Codepoint::Ect0 => Some(&mut next.ect0),
            Codepoint::Ect1 => Some(&mut next.ect1),
            Codepoint::Ce => Some(&mut next.ce),
        };
        if let Some(count) = count {
            *count = add_count(*count, 1)?;
        }
        self.counts[i] = next;
        self.observed[i] = true;
        Ok(())
    }
    pub fn ack_counts(&self, space: PacketNumberSpace) -> Option<EcnCounts> {
        let i = space as usize;
        (self.observed[i] && self.complete[i]).then_some(self.counts[i])
    }
}
impl Default for RxCounts {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy)]
struct Space {
    sent: MarkedPackets,
    acknowledged: MarkedPackets,
    feedback: EcnCounts,
    largest_ack: Option<u64>,
    last_sent: Option<u64>,
}
impl Space {
    const EMPTY: Self = Self {
        sent: MarkedPackets { ect0: 0, ect1: 0 },
        acknowledged: MarkedPackets { ect0: 0, ect1: 0 },
        feedback: ZERO,
        largest_ack: None,
        last_sent: None,
    };
}

pub struct PathEcn {
    identity: PathIdentity,
    state: State,
    failure: Option<Failure>,
    spaces: [Space; 3],
    marked_sent: u64,
    marked_acked: u64,
    marked_lost: u64,
    probe_deadline: Option<u64>,
}
impl PathEcn {
    /// Begin testing the initial path of a new connection with zero baselines.
    pub const fn new(identity: PathIdentity) -> Self {
        Self {
            identity,
            state: State::Testing,
            failure: None,
            spaces: [Space::EMPTY; 3],
            marked_sent: 0,
            marked_acked: 0,
            marked_lost: 0,
            probe_deadline: None,
        }
    }
    pub const fn identity(&self) -> PathIdentity {
        self.identity
    }
    pub const fn state(&self) -> State {
        self.state
    }
    pub const fn failure(&self) -> Option<Failure> {
        self.failure
    }
    pub fn sent(&self, space: PacketNumberSpace) -> MarkedPackets {
        self.spaces[space as usize].sent
    }
    fn check_path(&self, path: PathIdentity) -> Result<(), Error> {
        if path != self.identity {
            return Err(Error::WrongPath);
        }
        Ok(())
    }
    fn fail(&mut self, why: Failure) -> Feedback {
        self.state = State::Failed;
        self.failure = Some(why);
        Feedback::Failed(why)
    }
    /// Stop probing after ten accepted marked packets or three initial PTOs.
    /// Unknown stops marking but can become Capable on later valid feedback.
    pub fn marking(&mut self, path: PathIdentity, now: u64) -> Result<Codepoint, Error> {
        self.check_path(path)?;
        if self.state == State::Testing
            && (self.marked_sent >= PROBE_PACKETS
                || self.probe_deadline.is_some_and(|deadline| now >= deadline))
        {
            self.state = State::Unknown;
        }
        Ok(if matches!(self.state, State::Testing | State::Capable) {
            Codepoint::Ect0
        } else {
            Codepoint::NotEct
        })
    }
    /// Call exactly once after adapter acceptance, in increasing PN order per
    /// space. The original marking survives loss; retries use fresh PNs.
    pub fn accepted(
        &mut self,
        path: PathIdentity,
        packet: PacketNumber,
        codepoint: Codepoint,
        now: u64,
        pto: u64,
    ) -> Result<(), Error> {
        self.check_path(path)?;
        if packet.value > MAX_PACKET_NUMBER {
            return Err(Error::InvalidPacketNumber);
        }
        if codepoint == Codepoint::Ce {
            return Err(Error::InvalidSentCodepoint);
        }
        let i = packet.space as usize;
        let mut next = self.spaces[i];
        if next.last_sent.is_some_and(|pn| packet.value <= pn) {
            return Err(Error::RepeatedSend);
        }
        let marked = codepoint != Codepoint::NotEct;
        let count = match codepoint {
            Codepoint::Ect0 => Some(&mut next.sent.ect0),
            Codepoint::Ect1 => Some(&mut next.sent.ect1),
            _ => None,
        };
        if let Some(count) = count {
            *count = add_count(*count, 1)?;
        }
        let sent = self
            .marked_sent
            .checked_add(u64::from(marked))
            .ok_or(Error::CounterLimit)?;
        let deadline = if marked && self.probe_deadline.is_none() {
            Some(
                now.checked_add(pto.checked_mul(3).ok_or(Error::CounterLimit)?)
                    .ok_or(Error::CounterLimit)?,
            )
        } else {
            self.probe_deadline
        };
        next.last_sent = Some(packet.value);
        self.spaces[i] = next;
        self.marked_sent = sent;
        self.probe_deadline = deadline;
        Ok(())
    }
    /// The ledger must first validate all ACK ranges, reject ACKs of unsent PNs,
    /// and compute exact first-ACK marking counts before reclaiming history.
    pub fn acknowledged(
        &mut self,
        path: PathIdentity,
        space: PacketNumberSpace,
        largest: u64,
        newly: MarkedPackets,
        peer: Option<EcnCounts>,
    ) -> Result<Feedback, Error> {
        self.check_path(path)?;
        if largest > MAX_PACKET_NUMBER {
            return Err(Error::InvalidPacketNumber);
        }
        let i = space as usize;
        let mut next = self.spaces[i];
        let ack0 = add_count(next.acknowledged.ect0, newly.ect0)?;
        let ack1 = add_count(next.acknowledged.ect1, newly.ect1)?;
        if ack0 > next.sent.ect0 || ack1 > next.sent.ect1 {
            return Err(Error::InconsistentLedger);
        }
        let newly_total = newly.total()?;
        let total_acked = self
            .marked_acked
            .checked_add(newly_total)
            .ok_or(Error::CounterLimit)?;
        next.acknowledged = MarkedPackets {
            ect0: ack0,
            ect1: ack1,
        };
        self.marked_acked = total_acked;
        self.spaces[i].acknowledged = next.acknowledged;
        if next.largest_ack.is_some_and(|pn| largest <= pn) {
            return Ok(Feedback::Reordered);
        }
        self.spaces[i].largest_ack = Some(largest);
        if self.state == State::Failed {
            return Ok(Feedback::Unvalidated);
        }
        let Some(peer) = peer else {
            return Ok(if newly_total > 0 {
                self.fail(Failure::MissingCounts)
            } else {
                Feedback::Unvalidated
            });
        };
        if peer.ect0 > next.sent.ect0 || peer.ect1 > next.sent.ect1 {
            return Ok(self.fail(Failure::Remarked));
        }
        let peer_total = peer
            .ect0
            .checked_add(peer.ect1)
            .and_then(|sum| sum.checked_add(peer.ce));
        if peer.ce > MAX_PACKET_NUMBER
            || peer_total.is_none_or(|sum| sum > next.sent.ect0 + next.sent.ect1)
        {
            return Ok(self.fail(Failure::ExcessCounts));
        }
        let Some(d0) = peer.ect0.checked_sub(next.feedback.ect0) else {
            return Ok(self.fail(Failure::DecreasedCounts));
        };
        let Some(d1) = peer.ect1.checked_sub(next.feedback.ect1) else {
            return Ok(self.fail(Failure::DecreasedCounts));
        };
        let Some(dc) = peer.ce.checked_sub(next.feedback.ce) else {
            return Ok(self.fail(Failure::DecreasedCounts));
        };
        if d0 + dc < newly.ect0 || d1 + dc < newly.ect1 || d0 + d1 + dc < newly_total {
            return Ok(self.fail(Failure::Bleached));
        }
        self.spaces[i].feedback = peer;
        if newly_total > 0 {
            self.state = State::Capable;
        }
        Ok(if self.state == State::Capable {
            Feedback::Validated { ce_increase: dc }
        } else {
            Feedback::Unvalidated
        })
    }
    /// Exact count of newly declared-lost marked packets from the ledger.
    /// Loss alone does not remove accepted sent totals or resurrect failed ECN.
    pub fn lost(&mut self, path: PathIdentity, newly_marked: u64) -> Result<Feedback, Error> {
        self.check_path(path)?;
        let lost = self
            .marked_lost
            .checked_add(newly_marked)
            .ok_or(Error::CounterLimit)?;
        if lost > self.marked_sent {
            return Err(Error::InconsistentLedger);
        }
        self.marked_lost = lost;
        if matches!(self.state, State::Testing | State::Unknown)
            && self.marked_sent > 0
            && lost == self.marked_sent
            && self.marked_acked == 0
        {
            return Ok(self.fail(Failure::AllProbesLost));
        }
        Ok(Feedback::Unvalidated)
    }
}

fn add_count(value: u64, amount: u64) -> Result<u64, Error> {
    value
        .checked_add(amount)
        .filter(|n| *n <= MAX_PACKET_NUMBER)
        .ok_or(Error::CounterLimit)
}

#[cfg(test)]
mod tests {
    use super::*;
    const PATH: PathIdentity = PathIdentity {
        connection_generation: 7,
        slot: 0,
        path_generation: 1,
    };
    const APP: PacketNumberSpace = PacketNumberSpace::ApplicationData;
    fn pn(value: u64) -> PacketNumber {
        PacketNumber { space: APP, value }
    }
    fn one() -> MarkedPackets {
        MarkedPackets { ect0: 1, ect1: 0 }
    }
    fn counts(ect0: u64, ect1: u64, ce: u64) -> Option<EcnCounts> {
        Some(EcnCounts { ect0, ect1, ce })
    }
    fn sent(n: u64) -> PathEcn {
        let mut p = PathEcn::new(PATH);
        for i in 0..n {
            p.accepted(PATH, pn(i), Codepoint::Ect0, i, 100).unwrap();
        }
        p
    }

    #[test]
    fn tos_masks_only_ecn_bits() {
        for i in 0..=255 {
            assert_eq!(Codepoint::from_ip_tos(i).bits(), i & 3);
        }
    }
    #[test]
    fn receive_counts_are_per_space_and_require_real_observation() {
        let mut rx = RxCounts::new();
        assert_eq!(rx.ack_counts(APP), None);
        for s in [
            PacketNumberSpace::Initial,
            PacketNumberSpace::Handshake,
            APP,
        ] {
            rx.processed(s, Some(Codepoint::Ect0)).unwrap();
            assert_eq!(rx.ack_counts(s), counts(1, 0, 0));
        }
        rx.processed(APP, Some(Codepoint::Ce)).unwrap();
        rx.processed(APP, Some(Codepoint::Ect1)).unwrap();
        rx.processed(APP, Some(Codepoint::NotEct)).unwrap();
        assert_eq!(rx.ack_counts(APP), counts(1, 1, 1));
        assert_eq!(rx.ack_counts(PacketNumberSpace::Initial), counts(1, 0, 0));
        rx.processed(APP, None).unwrap();
        rx.processed(APP, Some(Codepoint::Ect0)).unwrap();
        assert_eq!(rx.ack_counts(APP), None);
    }
    #[test]
    fn receive_overflow_is_atomic() {
        let mut rx = RxCounts::new();
        rx.counts[2].ce = MAX_PACKET_NUMBER;
        assert_eq!(
            rx.processed(APP, Some(Codepoint::Ce)),
            Err(Error::CounterLimit)
        );
        assert!(!rx.observed[2]);
        assert_eq!(rx.counts[2].ce, MAX_PACKET_NUMBER);
    }
    #[test]
    fn ten_packets_or_three_ptos_end_testing_without_claiming_capability() {
        let mut p = sent(10);
        assert_eq!(p.marking(PATH, 10), Ok(Codepoint::NotEct));
        assert_eq!(p.state(), State::Unknown);
        assert_eq!(
            p.acknowledged(
                PATH,
                APP,
                9,
                MarkedPackets { ect0: 10, ect1: 0 },
                counts(10, 0, 0)
            ),
            Ok(Feedback::Validated { ce_increase: 0 })
        );
        assert_eq!(p.marking(PATH, 500), Ok(Codepoint::Ect0));
        let mut p = sent(1);
        assert_eq!(p.marking(PATH, 299), Ok(Codepoint::Ect0));
        assert_eq!(p.marking(PATH, 300), Ok(Codepoint::NotEct));
    }
    #[test]
    fn missing_or_bleached_feedback_disables_path() {
        for (peer, why) in [
            (None, Failure::MissingCounts),
            (counts(0, 0, 0), Failure::Bleached),
        ] {
            let mut p = sent(1);
            assert_eq!(
                p.acknowledged(PATH, APP, 0, one(), peer),
                Ok(Feedback::Failed(why))
            );
            assert_eq!(p.marking(PATH, 1), Ok(Codepoint::NotEct));
        }
    }
    #[test]
    fn impossible_remarking_and_ce_counts_disable_path() {
        for (peer, why) in [
            (counts(0, 1, 0), Failure::Remarked),
            (counts(2, 0, 0), Failure::Remarked),
            (counts(0, 0, 2), Failure::ExcessCounts),
            (counts(1, 0, u64::MAX), Failure::ExcessCounts),
        ] {
            let mut p = sent(1);
            assert_eq!(
                p.acknowledged(PATH, APP, 0, one(), peer),
                Ok(Feedback::Failed(why))
            );
        }
    }
    #[test]
    fn reordered_acks_never_fail_validation_or_reuse_ce_delta() {
        let mut p = sent(3);
        assert_eq!(
            p.acknowledged(PATH, APP, 2, one(), counts(1, 0, 1)),
            Ok(Feedback::Validated { ce_increase: 1 })
        );
        assert_eq!(
            p.acknowledged(PATH, APP, 1, one(), None),
            Ok(Feedback::Reordered)
        );
        assert_eq!(
            p.acknowledged(PATH, APP, 2, MarkedPackets::default(), counts(0, 1, 999)),
            Ok(Feedback::Reordered)
        );
        assert_eq!(p.state(), State::Capable);
    }
    #[test]
    fn ack_loss_allows_counter_increase_larger_than_new_ack_count() {
        let mut p = sent(5);
        assert_eq!(
            p.acknowledged(PATH, APP, 4, one(), counts(3, 0, 2)),
            Ok(Feedback::Validated { ce_increase: 2 })
        );
    }
    #[test]
    fn advancing_ack_counters_cannot_decrease() {
        let mut p = sent(3);
        p.acknowledged(PATH, APP, 0, one(), counts(1, 0, 1))
            .unwrap();
        assert_eq!(
            p.acknowledged(PATH, APP, 2, one(), counts(2, 0, 0)),
            Ok(Feedback::Failed(Failure::DecreasedCounts))
        );
    }
    #[test]
    fn ce_is_not_double_counted_for_mixed_ect_codepoints() {
        let mut p = sent(1);
        p.accepted(PATH, pn(1), Codepoint::Ect1, 1, 100).unwrap();
        assert_eq!(
            p.acknowledged(
                PATH,
                APP,
                1,
                MarkedPackets { ect0: 1, ect1: 1 },
                counts(0, 0, 1)
            ),
            Ok(Feedback::Failed(Failure::Bleached))
        );
    }
    #[test]
    fn real_ce_delta_is_reported_once_and_later_validation_can_fail() {
        let mut p = sent(3);
        assert_eq!(
            p.acknowledged(PATH, APP, 0, one(), counts(0, 0, 1)),
            Ok(Feedback::Validated { ce_increase: 1 })
        );
        assert_eq!(
            p.acknowledged(PATH, APP, 1, one(), counts(1, 0, 1)),
            Ok(Feedback::Validated { ce_increase: 0 })
        );
        assert_eq!(
            p.acknowledged(PATH, APP, 2, one(), None),
            Ok(Feedback::Failed(Failure::MissingCounts))
        );
        assert_eq!(p.marking(PATH, 3), Ok(Codepoint::NotEct));
    }
    #[test]
    fn all_probe_loss_disables_marking_and_late_ack_does_not_reenable() {
        let mut p = sent(2);
        assert_eq!(p.lost(PATH, 1), Ok(Feedback::Unvalidated));
        assert_eq!(
            p.lost(PATH, 1),
            Ok(Feedback::Failed(Failure::AllProbesLost))
        );
        assert_eq!(
            p.acknowledged(PATH, APP, 1, one(), counts(1, 0, 0)),
            Ok(Feedback::Unvalidated)
        );
        assert_eq!(p.state(), State::Failed);
    }
    #[test]
    fn no_marked_ack_cannot_create_capability() {
        let mut p = sent(1);
        assert_eq!(
            p.acknowledged(PATH, APP, 0, MarkedPackets::default(), counts(0, 0, 0)),
            Ok(Feedback::Unvalidated)
        );
        assert_eq!(p.state(), State::Testing);
    }
    #[test]
    fn spaces_do_not_share_counters_or_ack_highwaters() {
        let mut p = sent(1);
        let hs = PacketNumber {
            space: PacketNumberSpace::Handshake,
            value: 0,
        };
        p.accepted(PATH, hs, Codepoint::Ect0, 1, 100).unwrap();
        p.acknowledged(PATH, APP, 0, one(), counts(1, 0, 0))
            .unwrap();
        assert_eq!(
            p.acknowledged(PATH, hs.space, 0, one(), counts(1, 0, 0)),
            Ok(Feedback::Validated { ce_increase: 0 })
        );
    }
    #[test]
    fn stale_path_send_reuse_and_bad_ledger_are_rejected_without_credit() {
        let mut p = sent(1);
        let stale = PathIdentity {
            path_generation: 2,
            ..PATH
        };
        assert_eq!(
            p.accepted(stale, pn(1), Codepoint::Ect0, 1, 100),
            Err(Error::WrongPath)
        );
        assert_eq!(p.marking(stale, 1), Err(Error::WrongPath));
        assert_eq!(p.lost(stale, 1), Err(Error::WrongPath));
        assert_eq!(
            p.accepted(PATH, pn(0), Codepoint::Ect0, 1, 100),
            Err(Error::RepeatedSend)
        );
        assert_eq!(
            p.accepted(PATH, pn(1), Codepoint::Ce, 1, 100),
            Err(Error::InvalidSentCodepoint)
        );
        assert_eq!(p.lost(PATH, 2), Err(Error::InconsistentLedger));
        assert_eq!(
            p.acknowledged(
                PATH,
                APP,
                0,
                MarkedPackets { ect0: 2, ect1: 0 },
                counts(1, 0, 0)
            ),
            Err(Error::InconsistentLedger)
        );
        assert_eq!(p.sent(APP), one());
        assert_eq!(p.state(), State::Testing);
    }
    #[test]
    fn timer_overflow_does_not_publish_send_counts() {
        let mut p = PathEcn::new(PATH);
        assert_eq!(
            p.accepted(PATH, pn(0), Codepoint::Ect0, u64::MAX, 1),
            Err(Error::CounterLimit)
        );
        assert_eq!(p.sent(APP), MarkedPackets::default());
        assert_eq!(p.accepted(PATH, pn(0), Codepoint::Ect0, 0, 1), Ok(()));
    }
}
