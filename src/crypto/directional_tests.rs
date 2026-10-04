//! Directional cryptography, affine update receipts and numerical limits.
use super::*;
use crate::crypto::{CipherSuite, KeyKind};
use actor_test_allocator::NoAlloc;

type Packet = ([u8; 1], [u8; 20]);
fn key(suite: CipherSuite, byte: u8) -> PacketKey {
    PacketKey::from_secret(suite, KeyKind::OneRtt, &[byte; 32]).unwrap()
}
fn combined(suite: CipherSuite, reverse: bool) -> ApplicationKeys {
    let (send, receive) = if reverse { (2, 1) } else { (1, 2) };
    ApplicationKeys::new(key(suite, send), key(suite, receive)).unwrap()
}
fn install(
    scope: &mut ApplicationKeyScope,
    suite: CipherSuite,
    reverse: bool,
) -> (ApplicationReadKeys<'_>, ApplicationWriteKeys<'_>) {
    let (send, receive) = if reverse { (2, 1) } else { (1, 2) };
    scope
        .install(key(suite, send), key(suite, receive))
        .unwrap()
}
fn packet(tx: &mut ApplicationWriteKeys<'_>, pn: u64) -> Packet {
    let header = [0x40 | if tx.phase() { 4 } else { 0 }];
    let mut body = [0; 20];
    body[..4].copy_from_slice(b"test");
    assert_eq!(tx.seal(pn, &header, &mut body, 4), Ok(20));
    (header, body)
}
fn reference_packet(tx: &mut ApplicationKeys, pn: u64) -> Packet {
    let header = [0x40 | if tx.phase() { 4 } else { 0 }];
    let mut body = [0; 20];
    body[..4].copy_from_slice(b"test");
    assert_eq!(tx.seal(pn, &header, &mut body, 4), Ok(20));
    (header, body)
}
fn open<'a>(
    rx: &mut ApplicationReadKeys<'a>,
    pn: u64,
    packet: Packet,
    budget: &mut IntegrityBudget,
    now: u64,
) -> Result<AuthenticatedRead<'a>, Error> {
    let (header, mut body) = packet;
    let outcome = rx.open(pn, header[0] & 4 != 0, &header, &mut body, budget, now, 10)?;
    assert_eq!(&body[..4], b"test");
    Ok(outcome)
}
fn settle<'a>(
    rx: &mut ApplicationReadKeys<'a>,
    tx: &mut ApplicationWriteKeys<'a>,
    outcome: AuthenticatedRead<'a>,
) -> AckEligible<'a> {
    match outcome {
        AuthenticatedRead::Ready(ready) => ready,
        AuthenticatedRead::PeerUpdate(peer) => {
            let installed = tx.install_peer_update(peer).unwrap();
            rx.accept_write_epoch(installed).unwrap()
        }
    }
}
fn authorize(tx: &mut ApplicationWriteKeys<'_>, now: u64) {
    // Private numerical-policy fixture, not a substitute for real producer
    // integration. Public callers require actual scoped Path/Recovery evidence.
    tx.handshake_confirmed = true;
    tx.acknowledge_validated(
        tx.current.last_sealed.unwrap(),
        tx.receive_generation,
        now,
        10,
    )
    .unwrap();
}
fn initiate<'a>(rx: &mut ApplicationReadKeys<'a>, tx: &mut ApplicationWriteKeys<'a>, now: u64) {
    let ready = rx.prepare_local_update().unwrap();
    let installed = tx.initiate(ready, now, 10).unwrap();
    rx.accept_local_write_epoch(installed).unwrap();
}
fn reference_authorize(keys: &mut ApplicationKeys, now: u64) {
    keys.confirm_handshake().unwrap();
    keys.acknowledge(
        keys.local.last_sealed.unwrap(),
        keys.receive_generation(),
        now,
        10,
    )
    .unwrap();
}

#[test]
fn directional_epochs_match_combined_ciphertext_plaintext_masks_and_limits_without_allocation() {
    let guard = NoAlloc::start();
    for suite in [
        CipherSuite::Aes128GcmSha256,
        CipherSuite::ChaCha20Poly1305Sha256,
    ] {
        let mut ascope = ApplicationKeyScope::new(11);
        let mut bscope = ApplicationKeyScope::new(12);
        let (mut arx, mut atx) = install(&mut ascope, suite, false);
        let (mut brx, mut btx) = install(&mut bscope, suite, true);
        let mut a = combined(suite, false);
        let mut b = combined(suite, true);
        let (mut ab, mut bb, mut refab, mut refbb) = (
            IntegrityBudget::new(),
            IntegrityBudget::new(),
            IntegrityBudget::new(),
            IntegrityBudget::new(),
        );
        for generation in 0..=4 {
            let now = generation * 40;
            if generation > 0 {
                arx.maintain(now, 10).unwrap();
                atx.maintain(now, 10).unwrap();
                brx.maintain(now, 10).unwrap();
                btx.maintain(now, 10).unwrap();
                a.maintain(now, 10).unwrap();
                b.maintain(now, 10).unwrap();
                initiate(&mut arx, &mut atx, now);
                a.initiate(now, 10).unwrap();
            }
            let apacket = packet(&mut atx, generation);
            assert_eq!(apacket, reference_packet(&mut a, generation));
            let bout = open(&mut brx, generation, apacket, &mut bb, now).unwrap();
            let (header, mut body) = apacket;
            let expected = b
                .open(
                    generation,
                    header[0] & 4 != 0,
                    &header,
                    &mut body,
                    &mut refbb,
                    now,
                    10,
                )
                .unwrap();
            assert_eq!(bout.opened(), expected);
            if generation > 0 {
                assert_eq!(btx.generation(), generation - 1);
                assert!(matches!(&bout, AuthenticatedRead::PeerUpdate(_)));
            }
            let back = settle(&mut brx, &mut btx, bout);
            assert_eq!(back.opened(), expected);
            assert!(back.authenticates_plaintext(b"test"));
            assert!(!back.authenticates_plaintext(b"best"));
            assert!(!back.authenticates_plaintext(b"tes"));
            assert!(core::ptr::eq(back.scope(), brx.scope()));
            assert_eq!(back.packet_number(), generation);
            assert_eq!(back.connection_generation(), 12);
            assert_eq!(btx.generation(), b.generation());
            let bpacket = packet(&mut btx, generation);
            assert_eq!(bpacket, reference_packet(&mut b, generation));
            let aout = open(&mut arx, generation, bpacket, &mut ab, now).unwrap();
            let (header, mut body) = bpacket;
            let expected = a
                .open(
                    generation,
                    header[0] & 4 != 0,
                    &header,
                    &mut body,
                    &mut refab,
                    now,
                    10,
                )
                .unwrap();
            assert_eq!(settle(&mut arx, &mut atx, aout).opened(), expected);
            assert_eq!(atx.header_mask(&[9; 16]), a.header_mask(true, &[9; 16]));
            assert_eq!(arx.header_mask(&[9; 16]), a.header_mask(false, &[9; 16]));
            assert_eq!(arx.previous_key_deadline(), a.previous_key_deadline());
            authorize(&mut atx, now);
            authorize(&mut btx, now);
            reference_authorize(&mut a, now);
            reference_authorize(&mut b, now);
            assert_eq!(
                atx.seal(
                    generation,
                    &[0x40 | if atx.phase() { 4 } else { 0 }],
                    &mut [0; 16],
                    0
                ),
                Err(Error::PacketNumberReuse)
            );
            if generation > 0 {
                arx.maintain(now, 10).unwrap();
                atx.maintain(now, 10).unwrap();
                a.maintain(now, 10).unwrap();
                let failed = atx
                    .initiate(arx.prepare_local_update().unwrap(), now + 29, 10)
                    .unwrap_err();
                assert_eq!(failed.error, Error::KeyUpdateNotAllowed);
                arx.cancel_local_update(failed.ready).unwrap();
                assert_eq!(a.initiate(now + 29, 10), Err(Error::KeyUpdateNotAllowed));
            }
        }
        assert_eq!(ab.failed_packets(), 0);
        assert_eq!(bb.failed_packets(), 0);
        assert_eq!(refab.failed_packets(), 0);
        assert_eq!(refbb.failed_packets(), 0);
    }
    guard.finish();
}

#[test]
fn dropped_peer_or_install_receipt_never_releases_new_epoch_ack_authority() {
    for drop_after_install in [false, true] {
        let mut scope = ApplicationKeyScope::new(1);
        let (mut rx, mut tx) = install(&mut scope, CipherSuite::Aes128GcmSha256, true);
        let mut peer = key(CipherSuite::Aes128GcmSha256, 1);
        peer.update_key().unwrap();
        let mut budget = IntegrityBudget::new();
        let mut body = [0; 20];
        body[..4].copy_from_slice(b"test");
        peer.seal(10, &[0x44], &mut body, 4).unwrap();
        let AuthenticatedRead::PeerUpdate(receipt) =
            open(&mut rx, 10, ([0x44], body), &mut budget, 0).unwrap()
        else {
            panic!()
        };
        assert_eq!(tx.generation(), 0);
        if drop_after_install {
            drop(tx.install_peer_update(receipt).unwrap());
        } else {
            drop(receipt);
        }
        body[..4].copy_from_slice(b"test");
        peer.seal(11, &[0x44], &mut body, 4).unwrap();
        let saved = body;
        assert!(matches!(
            rx.open(11, true, &[0x44], &mut body, &mut budget, 0, 10),
            Err(Error::KeyUpdateNotAllowed)
        ));
        assert_eq!(body, saved);
        assert_eq!(budget.failed_packets(), 0);
        assert_eq!(
            rx.prepare_local_update().unwrap_err(),
            Error::KeyUpdateNotAllowed
        );
    }
}

#[test]
fn cross_scope_peer_installation_is_rejected_even_with_same_numeric_connection_generation() {
    let mut scope = ApplicationKeyScope::new(1);
    let mut other = ApplicationKeyScope::new(1);
    let (mut rx, mut tx) = install(&mut scope, CipherSuite::Aes128GcmSha256, true);
    let (_, mut wrong_tx) = install(&mut other, CipherSuite::Aes128GcmSha256, true);
    let mut peer = key(CipherSuite::Aes128GcmSha256, 1);
    peer.update_key().unwrap();
    let mut body = [0; 20];
    body[..4].copy_from_slice(b"test");
    peer.seal(10, &[0x44], &mut body, 4).unwrap();
    let mut budget = IntegrityBudget::new();
    let AuthenticatedRead::PeerUpdate(receipt) =
        open(&mut rx, 10, ([0x44], body), &mut budget, 0).unwrap()
    else {
        panic!()
    };
    assert!(matches!(
        wrong_tx.install_peer_update(receipt),
        Err(Error::KeyUpdateError)
    ));
    assert_eq!(wrong_tx.generation(), 0);
    assert_eq!(tx.generation(), 0);
    assert_eq!(
        rx.prepare_local_update().unwrap_err(),
        Error::KeyUpdateNotAllowed
    );
    tx.discard();
}

#[test]
fn forged_phase_and_missing_prepared_key_debit_one_attempt_and_never_promote() {
    for missing in [false, true] {
        let mut scope = ApplicationKeyScope::new(1);
        let (mut rx, tx) = install(&mut scope, CipherSuite::ChaCha20Poly1305Sha256, true);
        if missing {
            rx.next = None;
        }
        let mut peer = key(CipherSuite::ChaCha20Poly1305Sha256, 1);
        let mut body = [0; 20];
        body[..4].copy_from_slice(b"test");
        // A current-key surrogate that authenticates is still not a next key.
        peer.seal(50, &[0x44], &mut body, 4).unwrap();
        let mut budget = IntegrityBudget::new();
        assert!(matches!(
            rx.open(50, true, &[0x44], &mut body, &mut budget, 0, 10),
            Err(Error::AuthenticationFailed)
        ));
        assert_eq!(body, [0; 20]);
        assert_eq!(budget.failed_packets(), 1);
        assert_eq!(rx.generation(), 0);
        assert_eq!(tx.generation(), 0);
        assert_eq!(rx.next.is_none(), missing);
        assert!(rx.pending.is_none());
    }
}

#[test]
fn retained_old_key_expires_only_three_pto_after_authenticated_peer_response() {
    let mut ascope = ApplicationKeyScope::new(1);
    let mut bscope = ApplicationKeyScope::new(2);
    let (mut arx, mut atx) = install(&mut ascope, CipherSuite::Aes128GcmSha256, false);
    let (mut brx, mut btx) = install(&mut bscope, CipherSuite::Aes128GcmSha256, true);
    let (mut ab, mut bb) = (IntegrityBudget::new(), IntegrityBudget::new());
    let old0 = packet(&mut btx, 0);
    let old1 = packet(&mut btx, 1);
    let outcome = open(&mut brx, 0, packet(&mut atx, 0), &mut bb, 0).unwrap();
    let _eligible = settle(&mut brx, &mut btx, outcome);
    authorize(&mut atx, 0);
    initiate(&mut arx, &mut atx, 0);
    arx.maintain(1000, 10).unwrap();
    atx.maintain(1000, 10).unwrap();
    assert_eq!(
        open(&mut arx, 0, old0, &mut ab, 1000)
            .unwrap()
            .opened()
            .generation,
        0
    );
    assert_eq!(arx.previous_key_deadline(), None);
    let outcome = open(&mut brx, 1, packet(&mut atx, 1), &mut bb, 1000).unwrap();
    let _eligible = settle(&mut brx, &mut btx, outcome);
    let outcome = open(&mut arx, 2, packet(&mut btx, 2), &mut ab, 1000).unwrap();
    let _eligible = settle(&mut arx, &mut atx, outcome);
    assert_eq!(arx.previous_key_deadline(), Some(1030));
    assert_eq!(
        open(&mut arx, 1, old1, &mut ab, 1029)
            .unwrap()
            .opened()
            .generation,
        0
    );
    assert!(matches!(
        open(&mut arx, 1, old1, &mut ab, 1030),
        Err(Error::AuthenticationFailed)
    ));
    assert_eq!(ab.failed_packets(), 1);
    assert!(arx.previous.is_none());
}

#[test]
fn local_readiness_requires_confirmation_valid_ack_and_matching_owners() {
    let mut scope = ApplicationKeyScope::new(1);
    let (mut rx, mut tx) = install(&mut scope, CipherSuite::Aes128GcmSha256, false);
    let failure = tx
        .initiate(rx.prepare_local_update().unwrap(), 0, 10)
        .unwrap_err();
    assert_eq!(failure.error, Error::KeyUpdateNotAllowed);
    rx.cancel_local_update(failure.ready).unwrap();
    tx.handshake_confirmed = true;
    let failure = tx
        .initiate(rx.prepare_local_update().unwrap(), 0, 10)
        .unwrap_err();
    assert_eq!(failure.error, Error::KeyUpdateNotAllowed);
    rx.cancel_local_update(failure.ready).unwrap();
    packet(&mut tx, 10);
    assert_eq!(
        tx.acknowledge_validated(11, 0, 0, 10),
        Err(Error::InvalidAcknowledgment)
    );
    assert_eq!(
        tx.acknowledge_validated(10, 1, 0, 10),
        Err(Error::InvalidAcknowledgment)
    );
    tx.acknowledge_validated(10, 0, 0, 10).unwrap();
    initiate(&mut rx, &mut tx, 0);
    assert_eq!(tx.generation(), 1);
    assert_eq!(rx.generation(), 0);
    assert_eq!(
        rx.prepare_local_update().unwrap_err(),
        Error::KeyUpdateNotAllowed
    );
    packet(&mut tx, 11);
    assert_eq!(
        tx.acknowledge_validated(11, 0, 0, 10),
        Err(Error::KeyUpdateError)
    );
    assert_eq!(tx.header_mask(&[0; 16]), Err(Error::KeyDiscarded));
}

#[test]
fn dropped_local_readiness_blocks_rx_and_cannot_be_recreated_from_snapshot() {
    let mut scope = ApplicationKeyScope::new(1);
    let (mut rx, _) = install(&mut scope, CipherSuite::Aes128GcmSha256, false);
    let generation = rx.generation();
    drop(rx.prepare_local_update().unwrap());
    assert_eq!(rx.generation(), generation);
    assert_eq!(
        rx.prepare_local_update().unwrap_err(),
        Error::KeyUpdateNotAllowed
    );
}

#[test]
fn authenticated_generation_pn_violation_is_terminal_and_wipes_plaintext() {
    let mut scope = ApplicationKeyScope::new(1);
    let (mut rx, mut tx) = install(&mut scope, CipherSuite::Aes128GcmSha256, true);
    let mut budget = IntegrityBudget::new();
    let mut peer = key(CipherSuite::Aes128GcmSha256, 1);
    let mut body = [0; 20];
    body[..4].copy_from_slice(b"test");
    peer.seal(20, &[0x40], &mut body, 4).unwrap();
    open(&mut rx, 20, ([0x40], body), &mut budget, 0).unwrap();
    peer.update_key().unwrap();
    body[..4].copy_from_slice(b"test");
    peer.seal(30, &[0x44], &mut body, 4).unwrap();
    let outcome = open(&mut rx, 30, ([0x44], body), &mut budget, 0).unwrap();
    let _eligible = settle(&mut rx, &mut tx, outcome);
    let mut stale = key(CipherSuite::Aes128GcmSha256, 1);
    stale.update_key().unwrap();
    stale.seal(19, &[0x44], &mut body, 4).unwrap();
    assert!(matches!(
        rx.open(19, true, &[0x44], &mut body, &mut budget, 0, 10),
        Err(Error::KeyUpdateError)
    ));
    assert_eq!(body, [0; 20]);
    assert_eq!(budget.failed_packets(), 0);
    assert_eq!(rx.header_mask(&[0; 16]), Err(Error::KeyDiscarded));
}

#[test]
fn both_directions_keep_monotonic_time_and_discard_is_terminal() {
    let mut scope = ApplicationKeyScope::new(1);
    let (mut rx, mut tx) = install(&mut scope, CipherSuite::Aes128GcmSha256, false);
    rx.maintain(10, 10).unwrap();
    tx.maintain(10, 10).unwrap();
    for (now, pto) in [(9, 10), (10, 0), (u64::MAX, 10)] {
        assert_eq!(rx.maintain(now, pto), Err(Error::InvalidTime));
        assert_eq!(tx.maintain(now, pto), Err(Error::InvalidTime));
    }
    rx.discard();
    tx.discard();
    assert_eq!(rx.maintain(10, 10), Err(Error::KeyDiscarded));
    assert_eq!(tx.maintain(10, 10), Err(Error::KeyDiscarded));
}

#[test]
fn installed_receipt_cannot_complete_another_receivers_pending_transition() {
    let mut first = ApplicationKeyScope::new(7);
    let mut second = ApplicationKeyScope::new(7);
    let (mut arx, mut atx) = install(&mut first, CipherSuite::Aes128GcmSha256, true);
    let (mut brx, mut btx) = install(&mut second, CipherSuite::Aes128GcmSha256, true);
    let mut peer = key(CipherSuite::Aes128GcmSha256, 1);
    peer.update_key().unwrap();
    let mut body = [0; 20];
    body[..4].copy_from_slice(b"test");
    peer.seal(20, &[0x44], &mut body, 4).unwrap();
    let (mut ab, mut bb) = (IntegrityBudget::new(), IntegrityBudget::new());
    let AuthenticatedRead::PeerUpdate(a) = open(&mut arx, 20, ([0x44], body), &mut ab, 0).unwrap()
    else {
        panic!()
    };
    let AuthenticatedRead::PeerUpdate(b) = open(&mut brx, 20, ([0x44], body), &mut bb, 0).unwrap()
    else {
        panic!()
    };
    assert!(matches!(
        brx.accept_write_epoch(atx.install_peer_update(a).unwrap()),
        Err(Error::KeyUpdateError)
    ));
    let receipt = brx
        .accept_write_epoch(btx.install_peer_update(b).unwrap())
        .unwrap();
    assert_eq!(receipt.opened().generation, 1);
    assert!(brx.pending.is_none());
    assert!(arx.pending.is_some());
}

#[test]
fn installed_transition_carries_monotonic_clock_forward_between_directions() {
    let mut first = ApplicationKeyScope::new(7);
    let (mut rx, mut tx) = install(&mut first, CipherSuite::Aes128GcmSha256, false);
    packet(&mut tx, 0);
    authorize(&mut tx, 0);
    initiate(&mut rx, &mut tx, 1000);
    assert_eq!(rx.maintain(999, 10), Err(Error::InvalidTime));
    let mut peer = key(CipherSuite::Aes128GcmSha256, 2);
    peer.update_key().unwrap();
    let mut body = [0; 20];
    body[..4].copy_from_slice(b"test");
    peer.seal(20, &[0x44], &mut body, 4).unwrap();
    let mut budget = IntegrityBudget::new();
    let AuthenticatedRead::PeerUpdate(peer) =
        open(&mut rx, 20, ([0x44], body), &mut budget, 1100).unwrap()
    else {
        panic!()
    };
    let installed = tx.install_peer_update(peer).unwrap();
    assert_eq!(installed.generation(), 1);
    assert_eq!(tx.maintain(1099, 10), Err(Error::InvalidTime));
    let _eligible = rx.accept_write_epoch(installed).unwrap();
}

#[test]
fn shared_integrity_exhaustion_survives_both_directional_maintenance_and_updates() {
    let mut scope = ApplicationKeyScope::new(7);
    let (mut rx, mut tx) = install(&mut scope, CipherSuite::Aes128GcmSha256, true);
    let mut budget = IntegrityBudget {
        failed: 0,
        limit: 2,
    };
    let mut body = [0; 20];
    assert!(matches!(
        rx.open(0, false, &[0x40], &mut body, &mut budget, 0, 10),
        Err(Error::AuthenticationFailed)
    ));
    let mut peer = key(CipherSuite::Aes128GcmSha256, 1);
    peer.update_key().unwrap();
    body[..4].copy_from_slice(b"test");
    peer.seal(1, &[0x44], &mut body, 4).unwrap();
    let opened = open(&mut rx, 1, ([0x44], body), &mut budget, 0).unwrap();
    let _eligible = settle(&mut rx, &mut tx, opened);
    rx.maintain(0, 10).unwrap();
    tx.maintain(0, 10).unwrap();
    assert_eq!(budget.failed_packets(), 1);
    body = [0; 20];
    assert!(matches!(
        rx.open(2, true, &[0x44], &mut body, &mut budget, 0, 10),
        Err(Error::IntegrityLimit)
    ));
    assert_eq!(budget.failed_packets(), 2);
    body = [9; 20];
    assert!(matches!(
        rx.open(0, false, &[0x40], &mut body, &mut budget, 0, 10),
        Err(Error::IntegrityLimit)
    ));
    assert_eq!(body, [9; 20]);
    assert_eq!(budget.failed_packets(), 2);
}

#[test]
fn same_generation_foreign_handshake_and_validated_ack_scopes_cannot_authorize_updates() {
    let mut first = ApplicationKeyScope::new(7);
    let mut second = ApplicationKeyScope::new(7);
    let (mut rx, mut tx) = install(&mut first, CipherSuite::Aes128GcmSha256, false);
    let (foreign_rx, _) = install(&mut second, CipherSuite::Aes128GcmSha256, false);
    packet(&mut tx, 0);
    // Private fixtures model already-issued producer evidence; separate actual
    // producer integration must verify real Path/Recovery issuance.
    let foreign = foreign_rx.scope();
    assert_eq!(
        tx.scope().connection_generation(),
        foreign.connection_generation()
    );
    assert_eq!(
        tx.confirm_handshake(ScopedHandshakeConfirmation { scope: foreign }),
        Err(Error::KeyUpdateNotAllowed)
    );
    assert!(!tx.handshake_confirmed);
    assert_eq!(
        tx.acknowledge(
            ValidatedKeyAck {
                scope: foreign,
                sent_packet_number: 0,
                sent_key_generation: Some(0),
                received_key_generation: 0
            },
            0,
            10
        ),
        Err(Error::InvalidAcknowledgment)
    );
    assert!(!tx.current_acked);
    let own = tx.scope();
    tx.confirm_handshake(ScopedHandshakeConfirmation { scope: own })
        .unwrap();
    tx.acknowledge(
        ValidatedKeyAck {
            scope: own,
            sent_packet_number: 0,
            sent_key_generation: Some(0),
            received_key_generation: 0,
        },
        0,
        10,
    )
    .unwrap();
    initiate(&mut rx, &mut tx, 0);
    assert_eq!(tx.generation(), 1);
}

#[test]
fn installation_is_claimed_once_before_keys_arrive_and_identity_stays_stable() {
    let mut scope = ApplicationKeyScope::new(12);
    let install = scope.claim().unwrap();
    let producer_domain = install.scope();
    assert_eq!(producer_domain.connection_generation(), 12);
    let (rx, tx) = install
        .install(
            key(CipherSuite::Aes128GcmSha256, 1),
            key(CipherSuite::Aes128GcmSha256, 2),
        )
        .unwrap();
    assert!(core::ptr::eq(producer_domain, rx.scope()));
    assert!(core::ptr::eq(producer_domain, tx.scope()));
    drop(rx);
    drop(tx);
    assert!(matches!(scope.claim(), Err(Error::KeyUpdateNotAllowed)));
    let mut cancelled = ApplicationKeyScope::new(13);
    drop(cancelled.claim().unwrap());
    assert!(matches!(cancelled.claim(), Err(Error::KeyUpdateNotAllowed)));
}

#[test]
fn local_update_cannot_predate_rx_readiness_and_rejected_readiness_can_be_cancelled() {
    let mut scope = ApplicationKeyScope::new(12);
    let (mut rx, mut tx) = install(&mut scope, CipherSuite::Aes128GcmSha256, false);
    packet(&mut tx, 0);
    authorize(&mut tx, 0);
    rx.maintain(100, 10).unwrap();
    let refused = tx
        .initiate(rx.prepare_local_update().unwrap(), 99, 10)
        .unwrap_err();
    assert_eq!(refused.error, Error::InvalidTime);
    rx.cancel_local_update(refused.ready).unwrap();
    initiate(&mut rx, &mut tx, 100);
    assert_eq!(tx.generation(), 1);
}

// These helpers model already-issued sent-ledger evidence for the TX numeric
// policy. Actual Recovery receipt construction remains its integration boundary.
fn epoch_ack<'a>(
    scope: &'a ApplicationKeyScope,
    pn: u64,
    sent: u64,
    received: u64,
) -> ValidatedKeyAck<'a> {
    ValidatedKeyAck {
        scope,
        sent_packet_number: pn,
        sent_key_generation: Some(sent),
        received_key_generation: received,
    }
}
fn install_peer_epoch_one<'a>(
    rx: &mut ApplicationReadKeys<'a>,
    tx: &mut ApplicationWriteKeys<'a>,
    suite: CipherSuite,
) {
    let mut peer = key(suite, 1);
    peer.update_key().unwrap();
    let mut body = [0; 20];
    body[..4].copy_from_slice(b"test");
    peer.seal(10, &[0x44], &mut body, 4).unwrap();
    let mut budget = IntegrityBudget::new();
    let authenticated = open(rx, 10, ([0x44], body), &mut budget, 10).unwrap();
    let eligible = settle(rx, tx, authenticated);
    assert_eq!(eligible.opened().generation, 1);
    assert_eq!(tx.generation(), 1);
    assert_eq!(tx.first_sent, None);
}

#[test]
fn old_epoch_ack_before_current_send_preserves_progress_without_current_update_permission() {
    let measured = NoAlloc::start();
    for suite in [
        CipherSuite::Aes128GcmSha256,
        CipherSuite::ChaCha20Poly1305Sha256,
    ] {
        for current_key_has_high_water in [true, false] {
            let mut scope = ApplicationKeyScope::new(101);
            let (mut rx, mut tx) = install(&mut scope, suite, true);
            packet(&mut tx, 7);
            install_peer_epoch_one(&mut rx, &mut tx, suite);
            assert_eq!(tx.current.last_sealed, Some(7));
            tx.handshake_confirmed = true;
            if !current_key_has_high_water {
                // Private numeric fixture for the reported empty-current-key
                // accounting case. Normal promote() retains the old PN bound.
                tx.current.last_sealed = None;
                assert_eq!(
                    tx.acknowledge_validated(7, 0, 10, 10),
                    Err(Error::InvalidAcknowledgment)
                );
            }
            let own_scope = tx.scope();
            assert_eq!(
                tx.acknowledge(epoch_ack(own_scope, 7, 0, 0), 10, 10),
                Ok(())
            );
            assert_eq!(
                tx.acknowledge(epoch_ack(own_scope, 7, 0, 1), 10, 10),
                Ok(())
            );
            assert_eq!(tx.first_sent, None);
            assert!(!tx.current_acked);
            assert_eq!(tx.update_after, None);
            assert_eq!(tx.generation(), 1);
            tx.maintain(10, 10).unwrap();
            rx.maintain(10, 10).unwrap();
            let rejected = tx
                .initiate(rx.prepare_local_update().unwrap(), 10, 10)
                .unwrap_err();
            assert_eq!(rejected.error, Error::KeyUpdateNotAllowed);
            rx.cancel_local_update(rejected.ready).unwrap();
            if current_key_has_high_water {
                assert_eq!(
                    tx.seal(7, &[0x44], &mut [0; 16], 0),
                    Err(Error::PacketNumberReuse)
                );
            }
        }
    }
    measured.finish();
}

#[test]
fn current_epoch_ack_requires_a_current_seal_and_matching_epoch_packet_bounds() {
    let mut scope = ApplicationKeyScope::new(102);
    let (mut rx, mut tx) = install(&mut scope, CipherSuite::Aes128GcmSha256, true);
    packet(&mut tx, 7);
    install_peer_epoch_one(&mut rx, &mut tx, CipherSuite::Aes128GcmSha256);
    tx.handshake_confirmed = true;
    let own_scope = tx.scope();
    // A prior packet cannot be mislabeled current merely because the new key
    // inherited its packet-number high-water mark.
    assert_eq!(
        tx.acknowledge(epoch_ack(own_scope, 7, 1, 1), 10, 10),
        Err(Error::InvalidAcknowledgment)
    );
    packet(&mut tx, 8);
    for (pn, sent, received) in [(7, 1, 1), (9, 1, 1), (8, 0, 1), (8, 2, 1), (8, 1, 2)] {
        assert_eq!(
            tx.acknowledge(epoch_ack(own_scope, pn, sent, received), 10, 10),
            Err(Error::InvalidAcknowledgment)
        );
        assert!(!tx.current_acked);
        assert_eq!(tx.update_after, None);
        assert!(tx.active);
    }
    tx.acknowledge(epoch_ack(own_scope, 8, 1, 1), 10, 10)
        .unwrap();
    assert!(tx.current_acked);
    assert_eq!(tx.update_after, Some(40));
    // A later old-epoch ACK must neither reauthorize nor postpone the current
    // epoch's already-established three-PTO barrier.
    tx.acknowledge(epoch_ack(own_scope, 7, 0, 0), 20, 10)
        .unwrap();
    assert_eq!(tx.update_after, Some(40));
    tx.maintain(20, 10).unwrap();
    rx.maintain(20, 10).unwrap();
    let rejected = tx
        .initiate(rx.prepare_local_update().unwrap(), 39, 10)
        .unwrap_err();
    assert_eq!(rejected.error, Error::KeyUpdateNotAllowed);
    rx.cancel_local_update(rejected.ready).unwrap();
    initiate(&mut rx, &mut tx, 40);
    assert_eq!(tx.generation(), 2);
}

#[test]
fn old_epoch_exception_retains_scope_packet_number_and_authenticated_receive_bounds() {
    let mut scope = ApplicationKeyScope::new(103);
    let foreign_scope = ApplicationKeyScope::new(103);
    let (mut rx, mut tx) = install(&mut scope, CipherSuite::Aes128GcmSha256, true);
    packet(&mut tx, 7);
    install_peer_epoch_one(&mut rx, &mut tx, CipherSuite::Aes128GcmSha256);
    let own_scope = tx.scope();
    assert_eq!(
        tx.acknowledge(epoch_ack(&foreign_scope, 7, 0, 1), 10, 10),
        Err(Error::InvalidAcknowledgment)
    );
    assert_eq!(
        tx.acknowledge(epoch_ack(own_scope, 8, 0, 1), 10, 10),
        Err(Error::InvalidAcknowledgment)
    );
    tx.current.last_sealed = None;
    assert_eq!(
        tx.acknowledge(
            epoch_ack(own_scope, super::super::MAX_PACKET_NUMBER + 1, 0, 1),
            10,
            10
        ),
        Err(Error::InvalidAcknowledgment)
    );
    assert_eq!(
        tx.acknowledge(epoch_ack(own_scope, 7, 0, 2), 10, 10),
        Err(Error::InvalidAcknowledgment)
    );
    assert_eq!(
        tx.acknowledge(epoch_ack(own_scope, 7, 2, 1), 10, 10),
        Err(Error::InvalidAcknowledgment)
    );
    assert_eq!(
        tx.acknowledge(epoch_ack(own_scope, 7, 0, 1), 10, 10),
        Ok(())
    );
    assert!(!tx.current_acked);
    assert_eq!(tx.update_after, None);
}

#[test]
fn epoch_bound_ack_carried_under_older_read_keys_remains_terminal() {
    let mut scope = ApplicationKeyScope::new(104);
    let (mut rx, mut tx) = install(&mut scope, CipherSuite::ChaCha20Poly1305Sha256, true);
    packet(&mut tx, 7);
    install_peer_epoch_one(&mut rx, &mut tx, CipherSuite::ChaCha20Poly1305Sha256);
    packet(&mut tx, 8);
    let own_scope = tx.scope();
    assert_eq!(
        tx.acknowledge(epoch_ack(own_scope, 8, 1, 0), 10, 10),
        Err(Error::KeyUpdateError)
    );
    assert_eq!(tx.header_mask(&[0; 16]), Err(Error::KeyDiscarded));
}
