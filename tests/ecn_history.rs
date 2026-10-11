//! Migrated accounting/ECN regression assertions from the removed endpoint.
use hibana_quic::io::Codepoint;
use hibana_quic::quic::accounting;
use hibana_quic::quic::accounting::PacketKind;
use hibana_quic::quic::accounting::PacketNumberSpace;
use hibana_quic::quic::accounting::SentLedger;
use hibana_quic::quic::ecn;
use hibana_quic::quic::ecn::MarkedPackets;
use hibana_quic::quic::loss;
use hibana_quic::quic::packet;
fn ecn_congestion_event<const N: usize>(
    cc: &mut loss::NewReno,
    sent: &SentLedger<N>,
    largest: accounting::PacketNumber,
    now: u64,
) -> Result<bool, loss::RecoveryError> {
    let upper_bound = sent.congestion_sent_at_upper_bound(largest).unwrap_or(now);
    cc.on_congestion_event(now, upper_bound)
}

const APP: PacketNumberSpace = PacketNumberSpace::ApplicationData;
fn counts(ect0: u64, ce: u64) -> Option<packet::EcnCounts> {
    Some(packet::EcnCounts { ect0, ect1: 0, ce })
}
fn accept(ledger: &mut SentLedger<4>, at: u64, in_flight: bool) -> accounting::PacketNumber {
    let reserved = ledger
        .reserve(PacketKind::OneRtt, 40, in_flight, in_flight)
        .unwrap();
    ledger
        .adapter_accepted_ecn(reserved, at, Codepoint::Ect0)
        .unwrap();
    reserved.packet()
}
#[test]
fn reclaimed_ack_only_and_lost_ce_react_without_fabricated_exact_time() {
    let mut ledger = SentLedger::<4>::new(7);
    let mut cc = loss::NewReno::new(1200).unwrap();
    let initial = accept(&mut ledger, 1, true);
    ledger
        .acknowledge(
            APP,
            &[accounting::AckRange {
                start: initial.value,
                end: initial.value,
            }],
        )
        .unwrap();
    ledger.reclaim_completed_prefix(APP).unwrap();
    let ack_only = accept(&mut ledger, 10, false);
    ledger.reclaim_completed_prefix(APP).unwrap();
    assert_eq!(ledger.sent_at(ack_only), None);
    assert_eq!(ledger.congestion_sent_at_upper_bound(ack_only), Some(10));
    assert_eq!(
        ecn::validate_feedback(
            MarkedPackets { ect0: 2, ect1: 0 },
            counts(1, 0).unwrap(),
            MarkedPackets::default(),
            counts(1, 1)
        )
        .unwrap()
        .unwrap()
        .ce_increase,
        1
    );
    assert!(ecn_congestion_event(&mut cc, &ledger, ack_only, 20).unwrap());
    let reduced = cc.congestion_window();
    assert_eq!(
        ecn::validate_feedback(
            MarkedPackets { ect0: 2, ect1: 0 },
            counts(1, 1).unwrap(),
            MarkedPackets::default(),
            counts(1, 1)
        )
        .unwrap()
        .unwrap()
        .ce_increase,
        0
    );
    assert!(!ecn_congestion_event(&mut cc, &ledger, ack_only, 21).unwrap());
    assert_eq!(cc.congestion_window(), reduced);
    let later = accept(&mut ledger, 30, false);
    ledger.reclaim_completed_prefix(APP).unwrap();
    assert!(ecn_congestion_event(&mut cc, &ledger, later, 40).unwrap());
    assert!(cc.congestion_window() < reduced);
    let lost = accept(&mut ledger, 50, true);
    ledger.declare_lost(lost).unwrap();
    cc.on_congestion_event(60, 50).unwrap();
    ledger.reclaim_completed_prefix(APP).unwrap();
    assert_eq!(ledger.sent_at(lost), None);
    assert!(!ecn_congestion_event(&mut cc, &ledger, lost, 70).unwrap());
}
#[test]
fn unknown_history_uses_explicit_conservative_now_bound() {
    let ledger = SentLedger::<1>::new(7);
    let mut cc = loss::NewReno::new(1200).unwrap();
    let unknown = accounting::PacketNumber {
        space: APP,
        value: 0,
    };
    assert!(ecn_congestion_event(&mut cc, &ledger, unknown, 10).unwrap());
    assert_eq!(cc.recovery_started(), Some(10));
    assert_eq!(ledger.sent_at(unknown), None);
}
