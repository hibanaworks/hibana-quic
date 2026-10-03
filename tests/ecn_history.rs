//! Migrated accounting/ECN regression assertions from the removed endpoint.
use hibana_quic::{
    accounting::{self, PacketKind, PacketNumberSpace, SentLedger},
    ecn::{self, Codepoint, MarkedPackets, PathEcn, PathIdentity},
    packet, recovery,
};
fn ecn_congestion_event<const N: usize>(
    cc: &mut recovery::NewReno,
    sent: &SentLedger<N>,
    largest: accounting::PacketNumber,
    now: u64,
) -> Result<bool, recovery::RecoveryError> {
    let upper_bound = sent.congestion_sent_at_upper_bound(largest).unwrap_or(now);
    cc.on_congestion_event(now, upper_bound)
}

const APP: PacketNumberSpace = PacketNumberSpace::ApplicationData;
const PATH: PathIdentity = PathIdentity {
    connection_generation: 7,
    slot: 0,
    path_generation: 0,
};
fn counts(ect0: u64, ce: u64) -> Option<packet::EcnCounts> {
    Some(packet::EcnCounts { ect0, ect1: 0, ce })
}
fn accept(
    ledger: &mut SentLedger<4>,
    path: &mut PathEcn,
    at: u64,
    in_flight: bool,
) -> accounting::PacketNumber {
    let reserved = ledger.reserve(PacketKind::OneRtt, 40, in_flight).unwrap();
    ledger
        .adapter_accepted_ecn(reserved, at, Codepoint::Ect0)
        .unwrap();
    path.accepted(PATH, reserved.packet(), Codepoint::Ect0, at, 100)
        .unwrap();
    reserved.packet()
}
#[test]
fn reclaimed_ack_only_and_lost_ce_react_without_fabricated_exact_time() {
    let mut ledger = SentLedger::<4>::new(7);
    let mut path = PathEcn::new(PATH);
    let mut cc = recovery::NewReno::new(1200).unwrap();
    let initial = accept(&mut ledger, &mut path, 1, true);
    path.acknowledged(
        PATH,
        APP,
        initial.value,
        MarkedPackets { ect0: 1, ect1: 0 },
        counts(1, 0),
    )
    .unwrap();
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
    let ack_only = accept(&mut ledger, &mut path, 10, false);
    ledger.reclaim_completed_prefix(APP).unwrap();
    assert_eq!(ledger.sent_at(ack_only), None);
    assert_eq!(ledger.congestion_sent_at_upper_bound(ack_only), Some(10));
    assert_eq!(
        path.acknowledged(
            PATH,
            APP,
            ack_only.value,
            MarkedPackets::default(),
            counts(1, 1)
        )
        .unwrap(),
        ecn::Feedback::Validated { ce_increase: 1 }
    );
    assert!(ecn_congestion_event(&mut cc, &ledger, ack_only, 20).unwrap());
    let reduced = cc.congestion_window();
    assert_eq!(
        path.acknowledged(
            PATH,
            APP,
            ack_only.value,
            MarkedPackets::default(),
            counts(1, 1)
        )
        .unwrap(),
        ecn::Feedback::Reordered
    );
    assert!(!ecn_congestion_event(&mut cc, &ledger, ack_only, 21).unwrap());
    assert_eq!(cc.congestion_window(), reduced);

    let later = accept(&mut ledger, &mut path, 30, false);
    ledger.reclaim_completed_prefix(APP).unwrap();
    assert_eq!(
        path.acknowledged(
            PATH,
            APP,
            later.value,
            MarkedPackets::default(),
            counts(1, 2)
        )
        .unwrap(),
        ecn::Feedback::Validated { ce_increase: 1 }
    );
    assert!(ecn_congestion_event(&mut cc, &ledger, later, 40).unwrap());
    assert!(cc.congestion_window() < reduced);

    let lost = accept(&mut ledger, &mut path, 50, true);
    ledger.declare_lost(lost).unwrap();
    cc.on_congestion_event(60, 50).unwrap();
    ledger.reclaim_completed_prefix(APP).unwrap();
    assert_eq!(ledger.sent_at(lost), None);
    assert_eq!(
        path.acknowledged(
            PATH,
            APP,
            lost.value,
            MarkedPackets::default(),
            counts(1, 3)
        )
        .unwrap(),
        ecn::Feedback::Validated { ce_increase: 1 }
    );
    // This congestion was already covered by the actual loss response.
    assert!(!ecn_congestion_event(&mut cc, &ledger, lost, 70).unwrap());
}
#[test]
fn unknown_history_uses_explicit_conservative_now_bound() {
    let ledger = SentLedger::<1>::new(7);
    let mut cc = recovery::NewReno::new(1200).unwrap();
    let unknown = accounting::PacketNumber {
        space: APP,
        value: 0,
    };
    assert!(ecn_congestion_event(&mut cc, &ledger, unknown, 10).unwrap());
    assert_eq!(cc.recovery_started(), Some(10));
    assert_eq!(ledger.sent_at(unknown), None);
}

