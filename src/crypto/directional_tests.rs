//! Directional cryptography, affine update receipts and numerical limits.
use super::*;
use crate::crypto::{CipherSuite, KeyKind};
use actor_test_allocator::NoAlloc;

type Packet = ([u8; 1], [u8; 20]);
fn key(suite: CipherSuite, byte: u8) -> PacketKey {
    PacketKey::from_secret(suite, KeyKind::OneRtt, &[byte; 32]).unwrap()
}
fn install(
    scope: &mut ApplicationKeyScope,
    suite: CipherSuite,
    reverse: bool,
) -> (ApplicationReadKeys<'_>, ApplicationWriteKeys<'_>) {
    let (send, receive) = if reverse { (2, 1) } else { (1, 2) };
    crate::crypto::directional::ApplicationReadKeys::install(
        scope.claim().unwrap(),
        key(suite, send),
        key(suite, receive),
    )
    .unwrap()
}
fn packet(tx: &mut ApplicationWriteKeys<'_>, pn: u64) -> Packet {
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
    tx.confirm_handshake(ScopedHandshakeConfirmation { scope: tx.scope() })
        .unwrap();
    tx.acknowledge_validated(
        tx.current.last_sealed_packet_number().unwrap(),
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
#[test]
fn directional_epochs_preserve_ciphertext_masks_and_nonce_limits_without_allocation() {
    let guard = NoAlloc::start();
    for suite in [
        CipherSuite::Aes128GcmSha256,
        CipherSuite::ChaCha20Poly1305Sha256,
    ] {
        let mut ascope = ApplicationKeyScope::new(11);
        let mut bscope = ApplicationKeyScope::new(12);
        let (mut arx, mut atx) = install(&mut ascope, suite, false);
        let (mut brx, mut btx) = install(&mut bscope, suite, true);
        let mut expected_a = key(suite, 1);
        let mut expected_b = key(suite, 2);
        let (mut ab, mut bb) = (IntegrityBudget::new(), IntegrityBudget::new());
        let mask_a = atx.header_mask(&[9; 16]).unwrap();
        let mask_b = btx.header_mask(&[9; 16]).unwrap();
        for generation in 0..=4 {
            let now = generation * 40;
            if generation > 0 {
                arx.maintain(now, 10).unwrap();
                atx.maintain(now, 10).unwrap();
                brx.maintain(now, 10).unwrap();
                btx.maintain(now, 10).unwrap();
                expected_a.update_key().unwrap();
                expected_b.update_key().unwrap();
                initiate(&mut arx, &mut atx, now);
            }
            let apacket = packet(&mut atx, generation);
            let mut expected = [0; 20];
            expected[..4].copy_from_slice(b"test");
            expected_a
                .seal(generation, &apacket.0, &mut expected, 4)
                .unwrap();
            assert_eq!(apacket.1, expected);
            let bout = open(&mut brx, generation, apacket, &mut bb, now).unwrap();
            if generation > 0 {
                assert_eq!(btx.generation(), generation - 1);
            }
            let back = settle(&mut brx, &mut btx, bout);
            assert_eq!(back.opened().generation, generation);
            assert!(back.authenticates_plaintext(b"test"));
            assert!(!back.authenticates_plaintext(b"best"));
            assert_eq!(back.packet_number(), generation);
            assert_eq!(btx.generation(), generation);
            let bpacket = packet(&mut btx, generation);
            expected[..4].copy_from_slice(b"test");
            expected_b
                .seal(generation, &bpacket.0, &mut expected, 4)
                .unwrap();
            assert_eq!(bpacket.1, expected);
            let aout = open(&mut arx, generation, bpacket, &mut ab, now).unwrap();
            assert_eq!(
                settle(&mut arx, &mut atx, aout).opened().generation,
                generation
            );
            assert_eq!(atx.header_mask(&[9; 16]).unwrap(), mask_a);
            assert_eq!(arx.header_mask(&[9; 16]).unwrap(), mask_b);
            authorize(&mut atx, now);
            authorize(&mut btx, now);
            assert_eq!(
                atx.seal(generation, &apacket.0, &mut [0; 16], 0),
                Err(Error::PacketNumberReuse)
            );
            if generation > 0 {
                arx.maintain(now, 10).unwrap();
                atx.maintain(now, 10).unwrap();
                let failed = atx
                    .initiate(arx.prepare_local_update().unwrap(), now + 29, 10)
                    .unwrap_err();
                assert_eq!(failed.error, Error::KeyUpdateNotAllowed);
                arx.cancel_local_update(failed.ready).unwrap();
            }
        }
        assert_eq!(ab.failed_packets(), 0);
        assert_eq!(bb.failed_packets(), 0);
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
            rx.material.as_mut().unwrap().next = None;
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
        assert_eq!(rx.material.as_ref().unwrap().next.is_none(), missing);
        assert!(rx.material.as_ref().unwrap().current.is_some());
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
    assert!(arx.material.as_ref().unwrap().previous.is_none());
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
    tx.confirm_handshake(ScopedHandshakeConfirmation { scope: tx.scope() })
        .unwrap();
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
    assert!(brx.material.as_ref().unwrap().current.is_some());
    assert!(arx.material.as_ref().unwrap().current.is_none());
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
    let mut budget = IntegrityBudget::new();
    // Tighten the numerical policy through the existing monotone admission API.
    // This synthetic successful attempt is not packet-authentication evidence.
    budget.authenticate(2, || Ok::<(), ()>(())).unwrap();
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
    assert!(tx.confirmation.is_none());
    assert_eq!(
        tx.acknowledge(
            ValidatedKeyAck {
                scope: foreign,
                sent_packet_number: 0,
                sent_key_generation: 0,
                received_key_generation: 0
            },
            0,
            10
        ),
        Err(Error::InvalidAcknowledgment)
    );
    assert!(tx.update_evidence.is_none());
    let own = tx.scope();
    tx.confirm_handshake(ScopedHandshakeConfirmation { scope: own })
        .unwrap();
    tx.acknowledge(
        ValidatedKeyAck {
            scope: own,
            sent_packet_number: 0,
            sent_key_generation: 0,
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
    let (rx, tx) = crate::crypto::directional::ApplicationReadKeys::install(
        install,
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
        sent_key_generation: sent,
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
            assert_eq!(tx.current.last_sealed_packet_number(), Some(7));
            tx.confirm_handshake(ScopedHandshakeConfirmation { scope: tx.scope() })
                .unwrap();
            if !current_key_has_high_water {
                // Private numeric fixture for the reported empty-current-key
                // accounting case. Normal promote() retains the old PN bound.
                let mut fresh = key(suite, 2);
                fresh.update_key().unwrap();
                tx.current = fresh;
                assert_eq!(
                    tx.acknowledge(epoch_ack(tx.scope(), 7, 1, 1), 10, 10),
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
            assert!(tx.update_evidence.is_none());
            assert_eq!(tx.update_evidence.as_ref().map(|e| e.not_before), None);
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
    tx.confirm_handshake(ScopedHandshakeConfirmation { scope: tx.scope() })
        .unwrap();
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
        assert!(tx.update_evidence.is_none());
        assert_eq!(tx.update_evidence.as_ref().map(|e| e.not_before), None);
        assert!(tx.ensure_active().is_ok());
    }
    tx.acknowledge(epoch_ack(own_scope, 8, 1, 1), 10, 10)
        .unwrap();
    assert!(tx.update_evidence.is_some());
    assert_eq!(tx.update_evidence.as_ref().map(|e| e.not_before), Some(40));
    // A later old-epoch ACK must neither reauthorize nor postpone the current
    // epoch's already-established three-PTO barrier.
    tx.acknowledge(epoch_ack(own_scope, 7, 0, 0), 20, 10)
        .unwrap();
    assert_eq!(tx.update_evidence.as_ref().map(|e| e.not_before), Some(40));
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
    let mut fresh = key(CipherSuite::Aes128GcmSha256, 2);
    fresh.update_key().unwrap();
    tx.current = fresh;
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
    assert!(tx.update_evidence.is_none());
    assert_eq!(tx.update_evidence.as_ref().map(|e| e.not_before), None);
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

#[test]
fn retired_read_collection_rejects_a_late_local_key_return() {
    let mut scope = ApplicationKeyScope::new(901);
    let (mut rx, mut tx) = install(&mut scope, CipherSuite::Aes128GcmSha256, false);
    let ready = rx.prepare_local_update().unwrap();
    assert!(rx.material.as_ref().unwrap().current.is_none());
    rx.discard();
    assert_eq!(rx.cancel_local_update(ready), Err(Error::KeyDiscarded));
    assert!(rx.material.is_none());
    assert_eq!(rx.header_mask(&[0; 16]), Err(Error::KeyDiscarded));
    tx.discard();
    assert!(tx.confirmation.is_none());
    assert!(tx.update_evidence.is_none());
}

#[test]
fn retired_read_collection_rejects_a_late_peer_epoch_receipt() {
    let mut scope = ApplicationKeyScope::new(902);
    let (mut rx, mut tx) = install(&mut scope, CipherSuite::Aes128GcmSha256, true);
    let mut peer = key(CipherSuite::Aes128GcmSha256, 1);
    peer.update_key().unwrap();
    let mut body = [0; 20];
    body[..4].copy_from_slice(b"test");
    peer.seal(20, &[0x44], &mut body, 4).unwrap();
    let AuthenticatedRead::PeerUpdate(update) =
        open(&mut rx, 20, ([0x44], body), &mut IntegrityBudget::new(), 0).unwrap()
    else {
        panic!()
    };
    let installed = tx.install_peer_update(update).unwrap();
    rx.discard();
    assert!(matches!(
        rx.accept_write_epoch(installed),
        Err(Error::KeyDiscarded)
    ));
    assert!(rx.material.is_none());
}

use crate::{scoped_tls_fixture as owned_tls_fixture, tls_fixture};

#[test]
fn actual_tls_finished_and_packet_ownership_do_not_fabricate_quic_update_permission() {
    use crate::tls::{
        certificate::{CertificateDer, Limits, trust_anchor_from_der},
        handshake::{BoundedTls, CipherPolicy, ClientConfig, ServerConfig},
    };
    for policy in [CipherPolicy::Aes128Only, CipherPolicy::ChaCha20Only] {
        for p256 in [false, true] {
            let root = CertificateDer::from(tls_fixture::ROOT_DER);
            let anchors = [trust_anchor_from_der(&root).unwrap()];
            let chain = [tls_fixture::LEAF_DER];
            let signer = tls_fixture::signing_key();
            let mut cb = tls_fixture::Buffers::new();
            let mut sb = tls_fixture::Buffers::new();
            let mut cs = ApplicationKeyScope::new(910);
            let mut ss = ApplicationKeyScope::new(911);
            let guard = NoAlloc::start();
            let mut client = BoundedTls::client_with_policy(
                ClientConfig {
                    protocol: Default::default(),
                    version: crate::quic::kernel::version::Version::V1,
                    server_name: "localhost",
                    trust_anchors: &anchors,
                    now: tls_fixture::now(),
                    certificate_limits: Limits::default(),
                    transport_parameters: tls_fixture::CLIENT_PARAMS,
                },
                cb.storage(),
                &mut tls_fixture::TestRandom(81),
                policy,
            )
            .unwrap()
            .into_key_source(cs.claim().unwrap())
            .unwrap();
            let config = ServerConfig {
                protocol: Default::default(),
                version: crate::quic::kernel::version::Version::V1,
                certificate_chain: &chain,
                signing_key: &signer,
                transport_parameters: tls_fixture::SERVER_PARAMS,
            };
            let server = if p256 {
                BoundedTls::server_p256(config, sb.storage(), &mut tls_fixture::TestRandom(91))
            } else {
                BoundedTls::server_with_policy(
                    config,
                    sb.storage(),
                    &mut tls_fixture::TestRandom(91),
                    policy,
                )
            }
            .unwrap();
            let mut server = server.into_key_source(ss.claim().unwrap()).unwrap();
            let (mut cm, mut sm) = owned_tls_fixture::handshake_key_sources_observe(
                &mut client,
                &mut server,
                |_, _| {},
            );
            let (ci, cl, cr) = cm.application.take().unwrap().into_parts();
            let (si, sl, sr) = sm.application.take().unwrap().into_parts();
            let (mut crx, mut ctx) = ApplicationReadKeys::install(ci, cl, cr).unwrap();
            let (mut srx, mut stx) = ApplicationReadKeys::install(si, sl, sr).unwrap();
            let _client_finished = cm.finished.take().unwrap();
            let _server_finished = sm.finished.take().unwrap();
            let mut cbudget = client.take_integrity_budget().unwrap();
            let mut sbudget = server.take_integrity_budget().unwrap();
            for (tx, rx, budget) in [
                (&mut ctx, &mut srx, &mut sbudget),
                (&mut stx, &mut crx, &mut cbudget),
            ] {
                let ready = rx.prepare_local_update().unwrap();
                let refused = tx.initiate(ready, 0, 10).unwrap_err();
                assert_eq!(refused.error, Error::KeyUpdateNotAllowed);
                rx.cancel_local_update(refused.ready).unwrap();
                let mut bytes = [0; 20];
                bytes[..4].copy_from_slice(b"apps");
                tx.seal(0, b"header", &mut bytes, 4).unwrap();
                assert!(matches!(
                    rx.open(0, false, b"header", &mut bytes, budget, 0, 10),
                    Ok(AuthenticatedRead::Ready(_))
                ));
                assert_eq!(&bytes[..4], b"apps");
                let ready = rx.prepare_local_update().unwrap();
                let refused = tx.initiate(ready, 0, 10).unwrap_err();
                assert_eq!(refused.error, Error::KeyUpdateNotAllowed);
                rx.cancel_local_update(refused.ready).unwrap();
            }
            guard.finish();
        }
    }
}
