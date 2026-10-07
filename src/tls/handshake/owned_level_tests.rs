//! New regression tests for the reconstructed direct RX boundary.
//! Reimplementation only: these tests have not been compiled or executed.
use super::*;
use actor_test_allocator::NoAlloc;

fn raw_key(suite: CipherSuite, kind: KeyKind) -> PacketKey {
    PacketKey::from_secret(suite, kind, &[41; 32]).unwrap()
}
fn receive_key<'a>(
    scope: &'a ApplicationKeyScope,
    suite: CipherSuite,
    kind: KeyKind,
) -> ReceivePacketKey<'a> {
    let key = raw_key(suite, kind);
    if kind == KeyKind::Initial {
        ReceivePacketKey::from_initial(scope, key).unwrap()
    } else {
        // Test only: the real Handshake producer is HandshakeKeyMaterial::install.
        ReceivePacketKey { scope, key }
    }
}

#[test]
fn owned_level_receipt_binds_actual_aead_scope_packet_and_exact_plaintext() {
    for (suite, kind) in [
        (CipherSuite::Aes128GcmSha256, KeyKind::Initial),
        (CipherSuite::Aes128GcmSha256, KeyKind::Handshake),
        (CipherSuite::ChaCha20Poly1305Sha256, KeyKind::Handshake),
    ] {
        let first = ApplicationKeyScope::new(23);
        let other = ApplicationKeyScope::new(23);
        let no_alloc = NoAlloc::start();
        let rx = receive_key(&first, suite, kind);
        let mut tx = raw_key(suite, kind);
        let mut budget = IntegrityBudget::new();
        let mut buffer = [0; 64];
        buffer[..5].copy_from_slice(b"exact");
        let len = tx.seal(7, b"authenticated header", &mut buffer, 5).unwrap();
        let receipt = rx
            .open_authenticated(7, b"authenticated header", &mut buffer[..len], &mut budget)
            .unwrap();
        assert!(core::ptr::eq(receipt.scope(), &first));
        assert!(!core::ptr::eq(receipt.scope(), &other));
        assert_eq!(
            receipt.scope().connection_generation(),
            other.connection_generation()
        );
        assert_eq!(receipt.kind(), kind);
        assert_eq!(receipt.packet_number(), 7);
        assert_eq!(receipt.len(), 5);
        assert!(!receipt.is_empty());
        assert!(receipt.authenticates_plaintext(&buffer[..5]));
        assert!(receipt.authenticates_plaintext(b"exact"));
        assert!(!receipt.authenticates_plaintext(b"exacT"));
        assert!(!receipt.authenticates_plaintext(b"exac"));
        assert!(!receipt.authenticates_plaintext(b"exact\0"));
        assert_eq!(budget.failed_packets(), 0);

        // A zero-byte AEAD result is represented faithfully; transport decides
        // whether an empty QUIC payload is acceptable. No metadata is invented.
        let len = tx.seal(8, b"header", &mut buffer, 0).unwrap();
        let empty = rx
            .open_authenticated(8, b"header", &mut buffer[..len], &mut budget)
            .unwrap();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert_eq!(empty.packet_number(), 8);
        assert!(empty.authenticates_plaintext(b""));
        assert!(!empty.authenticates_plaintext(b"x"));
        no_alloc.finish();
    }
}

#[test]
fn owned_level_tamper_wipes_buffer_and_counts_failure_without_minting_receipt() {
    for (suite, kind) in [
        (CipherSuite::Aes128GcmSha256, KeyKind::Initial),
        (CipherSuite::Aes128GcmSha256, KeyKind::Handshake),
        (CipherSuite::ChaCha20Poly1305Sha256, KeyKind::Handshake),
    ] {
        let scope = ApplicationKeyScope::new(29);
        let no_alloc = NoAlloc::start();
        let rx = receive_key(&scope, suite, kind);
        let mut tx = raw_key(suite, kind);
        let mut budget = IntegrityBudget::new();
        let mut buffer = [0; 32];
        buffer[..4].copy_from_slice(b"data");
        let len = tx.seal(1, b"header", &mut buffer, 4).unwrap();
        let valid = buffer;
        buffer[len - 1] ^= 1;
        assert!(matches!(
            rx.open_authenticated(1, b"header", &mut buffer[..len], &mut budget),
            Err(crypto::Error::AuthenticationFailed)
        ));
        assert!(buffer[..len].iter().all(|byte| *byte == 0));
        assert_eq!(budget.failed_packets(), 1);
        let mut buffer = valid;
        let receipt = rx
            .open_authenticated(1, b"header", &mut buffer[..len], &mut budget)
            .unwrap();
        assert!(receipt.authenticates_plaintext(b"data"));
        assert_eq!(budget.failed_packets(), 1);
        no_alloc.finish();
    }
}

#[test]
fn owned_level_rejects_wrong_kind_before_aead_and_discarded_initial_attachment() {
    let scope = ApplicationKeyScope::new(31);
    let no_alloc = NoAlloc::start();
    for kind in [KeyKind::Handshake, KeyKind::ZeroRtt, KeyKind::OneRtt] {
        assert!(matches!(
            ReceivePacketKey::from_initial(&scope, raw_key(CipherSuite::Aes128GcmSha256, kind)),
            Err(crypto::Error::KeyDerivation)
        ));
    }
    let mut dead = raw_key(CipherSuite::Aes128GcmSha256, KeyKind::Initial);
    dead.discard();
    assert!(matches!(
        ReceivePacketKey::from_initial(&scope, dead),
        Err(crypto::Error::KeyDiscarded)
    ));
    for kind in [KeyKind::ZeroRtt, KeyKind::OneRtt] {
        // Test only: fabricate neither a receipt nor public metadata. Construct
        // the private key holder to exercise its mandatory level rejection.
        let rx = ReceivePacketKey {
            scope: &scope,
            key: raw_key(CipherSuite::Aes128GcmSha256, kind),
        };
        let mut tx = raw_key(CipherSuite::Aes128GcmSha256, kind);
        let mut buffer = [0; 20];
        buffer[..4].copy_from_slice(b"data");
        tx.seal(1, b"header", &mut buffer, 4).unwrap();
        let before = buffer;
        let mut budget = IntegrityBudget::new();
        assert!(matches!(
            rx.open_authenticated(1, b"header", &mut buffer, &mut budget),
            Err(crypto::Error::KeyDerivation)
        ));
        assert_eq!(buffer, before);
        assert_eq!(budget.failed_packets(), 0);
    }
    no_alloc.finish();
}

#[path = "../../../tests/support/tls_actor_fixture.rs"]
mod fixture;

#[test]
fn failed_source_polls_are_fatal_and_ordinary_absence_is_temporary() {
    use crate::{
        tls::certificate::{CertificateDer, Limits, trust_anchor_from_der},
        tls::handshake::ClientConfig,
    };
    let root = CertificateDer::from(fixture::ROOT_DER);
    let anchors = [trust_anchor_from_der(&root).unwrap()];
    let mut buffers = fixture::Buffers::new();
    let mut scope = ApplicationKeyScope::new(37);
    let no_alloc = NoAlloc::start();
    let mut source = BoundedTls::client(
        ClientConfig {
            protocol: Default::default(),
            version: crate::version::Version::V1,
            server_name: "localhost",
            trust_anchors: &anchors,
            now: fixture::now(),
            certificate_limits: Limits::default(),
            transport_parameters: fixture::CLIENT_PARAMS,
        },
        buffers.storage(),
        &mut fixture::TestRandom(97),
    )
    .unwrap()
    .into_key_source(scope.claim().unwrap())
    .unwrap();
    assert_eq!(source.side(), Side::Client);
    assert!(matches!(
        source.take_handshake_keys(),
        Err(tls::Error::KeysUnavailable)
    ));
    assert!(matches!(
        source.take_application_keys(),
        Err(tls::Error::KeysUnavailable)
    ));
    assert!(matches!(
        source.take_early_key(),
        Err(tls::Error::KeysUnavailable)
    ));
    assert!(matches!(
        source.take_finished(),
        Err(tls::Error::KeysUnavailable)
    ));
    let _budget = source.take_integrity_budget().unwrap();
    assert!(matches!(
        source.take_integrity_budget(),
        Err(tls::Error::KeysUnavailable)
    ));
    // A complete message at the wrong TLS level causes a genuine fatal source
    // transition, rather than changing private state merely to test polling.
    assert!(source.receive(Level::Handshake, &[1, 0, 0, 0]).is_err());
    assert_eq!(source.state(), State::Failed);
    assert!(source.last_failure().is_some());
    assert!(matches!(
        source.take_handshake_keys(),
        Err(tls::Error::Handshake)
    ));
    assert!(matches!(
        source.take_application_keys(),
        Err(tls::Error::Handshake)
    ));
    assert!(matches!(
        source.take_early_key(),
        Err(tls::Error::Handshake)
    ));
    assert!(matches!(source.take_finished(), Err(tls::Error::Handshake)));
    assert!(matches!(
        source.take_integrity_budget(),
        Err(tls::Error::Handshake)
    ));
    assert_eq!(source.transmit(&mut [0; 64]), Err(tls::Error::Handshake));
    no_alloc.finish();
}
