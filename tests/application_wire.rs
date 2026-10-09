//! Reconstructed integration tests; not executed after environment replacement.
use hibana_quic::crypto::CipherSuite;
use hibana_quic::crypto::IntegrityBudget;
use hibana_quic::crypto::KeyKind;
use hibana_quic::crypto::PacketKey;
use hibana_quic::crypto::directional::ApplicationKeyScope;
use hibana_quic::crypto::directional::AuthenticatedRead;
use hibana_quic::quic::Error;
use hibana_quic::quic::imp::application_wire::open;
use hibana_quic::quic::imp::application_wire::seal;
use hibana_quic::quic::imp::kernel::packet;
use hibana_quic::quic::imp::kernel::packet::ShortHeader;
fn key(suite: CipherSuite, byte: u8) -> PacketKey {
    PacketKey::from_secret(suite, KeyKind::OneRtt, &[byte; 32]).unwrap()
}
fn protected(
    suite: CipherSuite,
    cid: &[u8],
    pn: u64,
    plain: &[u8],
    reserved: bool,
    updated: bool,
) -> ([u8; 128], usize) {
    let mut k = key(suite, 1);
    if updated {
        k.update_key().unwrap();
    }
    let mut bytes = [0; 128];
    let start = packet::encode_short_header(
        &ShortHeader {
            destination_id: cid,
            packet_number: pn,
            packet_number_len: 4,
            spin: false,
            key_phase: updated,
        },
        &mut bytes,
    )
    .unwrap();
    if reserved {
        bytes[0] |= 8;
    }
    bytes[start..start + plain.len()].copy_from_slice(plain);
    let (h, p) = bytes.split_at_mut(start);
    let n = k.seal(pn, h, p, plain.len()).unwrap();
    let len = start + n;
    k.protect_header(&mut bytes[..len], start - 4).unwrap();
    (bytes, len)
}
#[test]
fn short_packet_retains_actual_affine_authentication_for_both_suites_and_zero_cid() {
    let guard = actor_test_allocator::NoAlloc::start();
    for suite in [
        CipherSuite::Aes128GcmSha256,
        CipherSuite::ChaCha20Poly1305Sha256,
    ] {
        for cid in [b"".as_slice(), b"peerid".as_slice()] {
            let mut scope = ApplicationKeyScope::new(91);
            let (mut rx, _tx) = hibana_quic::crypto::directional::ApplicationReadKeys::install(
                scope.claim().unwrap(),
                key(suite, 2),
                key(suite, 1),
            )
            .unwrap();
            let (bytes, len) = protected(suite, cid, 0x1_0000_0001, &[1], false, false);
            let mut opened = open::<128>(
                &mut rx,
                &mut IntegrityBudget::new(),
                &bytes[..len],
                cid,
                Some(0x1_0000_0000),
                0,
                1000,
            )
            .unwrap();
            assert_eq!(opened.packet_number(), 0x1_0000_0001);
            assert_eq!(opened.plaintext(), &[1]);
            match opened.take_receipt().unwrap() {
                AuthenticatedRead::Ready(r) => {
                    assert!(r.authenticates_plaintext(opened.plaintext()));
                    assert!(!r.authenticates_plaintext(&[0]));
                }
                _ => panic!("unexpected epoch"),
            }
            assert!(opened.take_receipt().is_none());
        }
    }
    guard.finish();
}
#[test]
fn bad_tag_wrong_cid_capacity_and_authenticated_empty_or_reserved_are_rejected() {
    let suite = CipherSuite::Aes128GcmSha256;
    let mut scope = ApplicationKeyScope::new(92);
    let (mut rx, _tx) = hibana_quic::crypto::directional::ApplicationReadKeys::install(
        scope.claim().unwrap(),
        key(suite, 2),
        key(suite, 1),
    )
    .unwrap();
    let (mut bytes, len) = protected(suite, b"cid", 1, &[1], false, false);
    assert!(matches!(
        open::<128>(
            &mut rx,
            &mut IntegrityBudget::new(),
            &bytes[..len],
            b"bad",
            None,
            0,
            1000
        ),
        Err(Error::Binding)
    ));
    assert!(matches!(
        open::<8>(
            &mut rx,
            &mut IntegrityBudget::new(),
            &bytes[..len],
            b"cid",
            None,
            0,
            1000
        ),
        Err(Error::Capacity)
    ));
    bytes[len - 1] ^= 1;
    assert!(matches!(
        open::<128>(
            &mut rx,
            &mut IntegrityBudget::new(),
            &bytes[..len],
            b"cid",
            None,
            0,
            1000
        ),
        Err(Error::Crypto(
            hibana_quic::crypto::Error::AuthenticationFailed
        ))
    ));
    for (plain, reserved, expected) in [
        ([].as_slice(), false, packet::Error::EmptyPayload),
        ([1].as_slice(), true, packet::Error::ReservedBits),
    ] {
        let (bytes, len) = protected(suite, b"cid", 2, plain, reserved, false);
        assert!(
            matches!(open::<128>(&mut rx,&mut IntegrityBudget::new(),&bytes[..len],b"cid",None,0,1000),Err(Error::Packet(e))if e==expected)
        );
    }
}
#[test]
fn authenticated_peer_epoch_waits_for_actual_tx_install_before_ack_authority() {
    let suite = CipherSuite::Aes128GcmSha256;
    let mut scope = ApplicationKeyScope::new(93);
    let (mut rx, mut tx) = hibana_quic::crypto::directional::ApplicationReadKeys::install(
        scope.claim().unwrap(),
        key(suite, 2),
        key(suite, 1),
    )
    .unwrap();
    rx.maintain(0, 1000).unwrap();
    let (bytes, len) = protected(suite, b"cid", 1, &[1], false, true);
    let mut opened = open::<128>(
        &mut rx,
        &mut IntegrityBudget::new(),
        &bytes[..len],
        b"cid",
        None,
        0,
        1000,
    )
    .unwrap();
    let peer = match opened.take_receipt().unwrap() {
        AuthenticatedRead::PeerUpdate(p) => p,
        _ => panic!("premature ACK authority"),
    };
    assert!(
        open::<128>(
            &mut rx,
            &mut IntegrityBudget::new(),
            &bytes[..len],
            b"cid",
            None,
            0,
            1000
        )
        .is_err()
    );
    let installed = tx.install_peer_update(peer).unwrap();
    let ready = rx.accept_write_epoch(installed).unwrap();
    assert!(ready.authenticates_plaintext(opened.plaintext()));
    assert_eq!(tx.generation(), 1);
}
#[test]
fn seal_retains_reservation_and_rejects_changed_plaintext_scope_epoch_or_length() {
    use hibana_quic::quic::Side;
    use hibana_quic::quic::imp::recovery::Recovery;
    let guard = actor_test_allocator::NoAlloc::start();
    let suite = CipherSuite::Aes128GcmSha256;
    let mut scope = ApplicationKeyScope::new(94);
    let mut install = scope.claim().unwrap();
    let recovery = install.take_recovery().unwrap();
    let (_rx, mut tx) = hibana_quic::crypto::directional::ApplicationReadKeys::install(
        install,
        key(suite, 1),
        key(suite, 2),
    )
    .unwrap();
    let mut book = Recovery::<128>::new(recovery, Side::Client, 333_000, 1200, 3).unwrap();
    let (mut tx_book, _rx_book, _clock, _publication, _retirement) = book.split().unwrap();
    let cid = b"cid";
    let wire_len = 1 + cid.len() + 4 + 1 + 16;
    for (plain, epoch, length) in [
        ([0u8].as_slice(), 0, wire_len),
        ([1].as_slice(), 1, wire_len),
        ([1].as_slice(), 0, wire_len + 1),
    ] {
        let r = tx_book
            .reserve_application(&[1], epoch, length as u64, false, 0)
            .unwrap();
        let (_, r) = match seal::<128>(&mut tx, r, cid, plain) {
            Err(e) => e,
            Ok(_) => panic!("altered reservation accepted"),
        };
        tx_book.cancel(r).unwrap();
        assert_eq!(tx.last_sealed_packet_number(), None);
    }
    let mut other = ApplicationKeyScope::new(94);
    let (_r, mut other_tx) = hibana_quic::crypto::directional::ApplicationReadKeys::install(
        other.claim().unwrap(),
        key(suite, 1),
        key(suite, 2),
    )
    .unwrap();
    let r = tx_book
        .reserve_application(&[1], 0, wire_len as u64, false, 0)
        .unwrap();
    let (_, r) = match seal::<128>(&mut other_tx, r, cid, &[1]) {
        Err(e) => e,
        Ok(_) => panic!("foreign scope accepted"),
    };
    tx_book.cancel(r).unwrap();
    let r = tx_book
        .reserve_application(&[1], 0, wire_len as u64, false, 0)
        .unwrap();
    let pn = r.packet().value;
    let sealed = match seal::<128>(&mut tx, r, cid, &[1]) {
        Ok(v) => v,
        Err(_) => panic!("valid packet rejected"),
    };
    let mut peer = ApplicationKeyScope::new(95);
    let (mut rx, _t) = hibana_quic::crypto::directional::ApplicationReadKeys::install(
        peer.claim().unwrap(),
        key(suite, 2),
        key(suite, 1),
    )
    .unwrap();
    let opened = open::<128>(
        &mut rx,
        &mut IntegrityBudget::new(),
        sealed.bytes(),
        cid,
        None,
        0,
        1000,
    )
    .unwrap();
    assert_eq!(opened.plaintext(), &[1]);
    assert_eq!(opened.packet_number(), pn);
    assert_eq!(tx.last_sealed_packet_number(), Some(pn));
    tx_book.cancel(sealed.into_reservation()).unwrap();
    guard.finish();
}
