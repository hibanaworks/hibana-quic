//! Real authenticated sparse packet numbers must not exhaust ACK storage.
use actor_test_allocator::NoAlloc;
use hibana_quic::crypto::CipherSuite;
use hibana_quic::crypto::IntegrityBudget;
use hibana_quic::crypto::KeyKind;
use hibana_quic::crypto::PacketKey;
use hibana_quic::crypto::directional::ApplicationKeyScope;
use hibana_quic::crypto::directional::AuthenticatedRead;
use hibana_quic::quic::Side;
use hibana_quic::quic::imp::kernel::accounting::AccountingError;
use hibana_quic::quic::imp::recovery;
use hibana_quic::quic::imp::recovery::Recovery;

#[test]
fn authenticated_loss_gaps_prune_without_fabricating_acks_or_readmitting_replays() {
    let mut scope = ApplicationKeyScope::new(601);
    let mut installation = scope.claim().unwrap();
    let recovery = installation.take_recovery().unwrap();
    let key =
        || PacketKey::from_secret(CipherSuite::Aes128GcmSha256, KeyKind::OneRtt, &[9; 32]).unwrap();
    let (mut read, _write) =
        hibana_quic::crypto::directional::ApplicationReadKeys::install(installation, key(), key())
            .unwrap();
    let mut peer = key();
    let mut integrity = IntegrityBudget::new();
    let mut book = Recovery::<128>::new(recovery, Side::Client, 333_000, 1200, 3).unwrap();
    let (tx, mut rx, _clock, _publication, mut retirement) = book.split().unwrap();
    let mut original = [0; 17];
    let guard = NoAlloc::start();
    for number in 0..2048_u64 {
        let pn = number * 2;
        let mut bytes = [0; 17];
        bytes[0] = 1; // PING
        assert_eq!(peer.seal(pn, b"header", &mut bytes, 1).unwrap(), 17);
        if pn == 0 {
            original = bytes;
        }
        let AuthenticatedRead::Ready(receipt) = read
            .open(pn, false, b"header", &mut bytes, &mut integrity, pn, 10)
            .unwrap()
        else {
            panic!("unexpected key update")
        };
        let outcome = rx
            .apply_application_packet(receipt, &bytes[..1], pn, pn, None)
            .unwrap();
        assert!(!outcome.duplicate);
        let ack = tx.pending_ack().unwrap();
        assert!(ack.ranges().len() <= recovery::ACK_CAPACITY);
        assert_eq!(ack.ranges()[0].largest, pn);
        for range in ack.ranges() {
            assert_eq!(range.smallest, range.largest);
            assert_eq!(
                range.smallest % 2,
                0,
                "a missing odd packet must never be acknowledged"
            );
        }
    }
    let AuthenticatedRead::Ready(replay) = read
        .open(0, false, b"header", &mut original, &mut integrity, 5000, 10)
        .unwrap()
    else {
        panic!("unexpected key update")
    };
    assert!(matches!(
        rx.apply_application_packet(replay, &original[..1], 5000, 5000, None),
        Err(recovery::Error::Accounting(
            AccountingError::HistoryUnavailable
        ))
    ));
    retirement.disarm();
    guard.finish();
}
