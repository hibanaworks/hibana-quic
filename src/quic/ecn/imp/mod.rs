//! Bounded ECN observations and pure counter validation (RFC 9000 §13.4/A.4).
//! The unconnected PathEcn phase controller has been deleted; marking policy
//! and probe lifetimes must be implemented as Hibana contracts.
//!
//! This module does not authenticate packets or own sent history. The caller
//! supplies only processed, authenticated, nonduplicate receives and exact
//! first-ACK/first-loss summaries from its sent ledger. Counts are per packet
//! number space, including one count for each processed coalesced QUIC packet.
//! Adapter rejection is not a send. CE feedback must be validated before the
//! caller invokes its RFC 9002 congestion-event handler.
//!
//! Receive counts are observations only. Future projected path owners must keep
//! cumulative counters, first-ACK facts and peer baselines bound to the actual
//! path; this arithmetic module cannot authorize migration or marking.

use crate::quic::imp::kernel::accounting::MAX_PACKET_NUMBER;
use crate::quic::imp::kernel::accounting::PacketNumberSpace;
use crate::quic::imp::kernel::packet::EcnCounts;

const ZERO: EcnCounts = EcnCounts {
    ect0: 0,
    ect1: 0,
    ce: 0,
};

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
pub enum Error {
    Validation(Failure),
    CounterLimit,
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
pub enum Failure {
    MissingCounts,
    DecreasedCounts,
    Bleached,
    Remarked,
    ExcessCounts,
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
    /// Known processed markings, including partial observations. This does not
    /// authorize an ACK_ECN when any datagram metadata was unavailable.
    pub(crate) fn marked_packets(&self) -> Result<u64, Error> {
        self.counts.iter().try_fold(0u64, |sum, counts| {
            sum.checked_add(counts.ect0)
                .and_then(|n| n.checked_add(counts.ect1))
                .and_then(|n| n.checked_add(counts.ce))
                .ok_or(Error::CounterLimit)
        })
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

/// Pure arithmetic result. This grants no ECN marking or path capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeedbackDelta {
    pub ce_increase: u64,
    pub newly_validated: u64,
}

/// Validate counter arithmetic after actual recovery supplies first-ACK counts.
/// No probing, failed/capable phase or retransmission policy is stored here.
/// The projected owner must handle ordering, path identity and marking decisions.
pub fn validate_feedback(
    sent: MarkedPackets,
    previous: EcnCounts,
    newly: MarkedPackets,
    peer: Option<EcnCounts>,
) -> Result<Option<FeedbackDelta>, Error> {
    if sent.ect0 > MAX_PACKET_NUMBER
        || sent.ect1 > MAX_PACKET_NUMBER
        || newly.ect0 > sent.ect0
        || newly.ect1 > sent.ect1
    {
        return Err(Error::InconsistentLedger);
    }
    let newly_total = newly.total()?;
    let Some(peer) = peer else {
        return if newly_total == 0 {
            Ok(None)
        } else {
            Err(Error::Validation(Failure::MissingCounts))
        };
    };
    if peer.ect0 > sent.ect0 || peer.ect1 > sent.ect1 {
        return Err(Error::Validation(Failure::Remarked));
    }
    let peer_total = peer
        .ect0
        .checked_add(peer.ect1)
        .and_then(|v| v.checked_add(peer.ce));
    if peer.ce > MAX_PACKET_NUMBER || peer_total.is_none_or(|v| v > sent.ect0 + sent.ect1) {
        return Err(Error::Validation(Failure::ExcessCounts));
    }
    let d0 = peer
        .ect0
        .checked_sub(previous.ect0)
        .ok_or(Error::Validation(Failure::DecreasedCounts))?;
    let d1 = peer
        .ect1
        .checked_sub(previous.ect1)
        .ok_or(Error::Validation(Failure::DecreasedCounts))?;
    let dc = peer
        .ce
        .checked_sub(previous.ce)
        .ok_or(Error::Validation(Failure::DecreasedCounts))?;
    if d0 + dc < newly.ect0 || d1 + dc < newly.ect1 || d0 + d1 + dc < newly_total {
        return Err(Error::Validation(Failure::Bleached));
    }
    Ok(Some(FeedbackDelta {
        ce_increase: dc,
        newly_validated: newly_total,
    }))
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
    const APP: PacketNumberSpace = PacketNumberSpace::ApplicationData;
    fn counts(ect0: u64, ect1: u64, ce: u64) -> Option<EcnCounts> {
        Some(EcnCounts { ect0, ect1, ce })
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
    fn counter_validation_preserves_bleaching_remarking_and_ce_checks() {
        let sent = MarkedPackets { ect0: 2, ect1: 1 };
        let newly = MarkedPackets { ect0: 1, ect1: 1 };
        assert_eq!(
            validate_feedback(sent, ZERO, newly, None),
            Err(Error::Validation(Failure::MissingCounts))
        );
        assert_eq!(
            validate_feedback(
                sent,
                ZERO,
                newly,
                Some(EcnCounts {
                    ect0: 0,
                    ect1: 0,
                    ce: 1
                })
            ),
            Err(Error::Validation(Failure::Bleached))
        );
        assert_eq!(
            validate_feedback(
                sent,
                ZERO,
                newly,
                Some(EcnCounts {
                    ect0: 3,
                    ect1: 0,
                    ce: 0
                })
            ),
            Err(Error::Validation(Failure::Remarked))
        );
        assert_eq!(
            validate_feedback(
                sent,
                ZERO,
                newly,
                Some(EcnCounts {
                    ect0: 0,
                    ect1: 0,
                    ce: 4
                })
            ),
            Err(Error::Validation(Failure::ExcessCounts))
        );
        assert_eq!(
            validate_feedback(
                sent,
                ZERO,
                newly,
                Some(EcnCounts {
                    ect0: 0,
                    ect1: 0,
                    ce: 2
                })
            ),
            Ok(Some(FeedbackDelta {
                ce_increase: 2,
                newly_validated: 2
            }))
        );
        assert_eq!(
            validate_feedback(
                sent,
                EcnCounts {
                    ect0: 1,
                    ect1: 0,
                    ce: 0
                },
                MarkedPackets::default(),
                Some(ZERO)
            ),
            Err(Error::Validation(Failure::DecreasedCounts))
        );
    }
}
