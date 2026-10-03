// Reconstructed from retained original test bodies; these bytes are unverified.
use super::*;
use crate::{
    bounded_tls::{ApplicationMaterial, CipherPolicy, ClientConfig, ServerConfig},
    crypto::directional::AuthenticatedRead,
    tls_certificate::{CertificateDer, Limits, trust_anchor_from_der},
};
use actor_test_allocator::NoAlloc;
#[path = "../../tests/support/tls_actor_fixture.rs"]
mod fixture;
use fixture::{Buffers, TestRandom, CLIENT_PARAMS, SERVER_PARAMS};

fn drain(source: &mut KeySource<'_, '_, '_>, target: &mut KeySource<'_, '_, '_>) {
    let mut output = [0; 2048];
    while let Some(message) = source.transmit(&mut output).unwrap() {
        target.receive(message.level, &output[..message.len]).unwrap();
    }
}
fn handshake(source: &mut KeySource<'_, '_, '_>, target: &mut KeySource<'_, '_, '_>) {
    for _ in 0..4 { drain(source, target); drain(target, source); }
    assert!(!source.is_handshaking() && !target.is_handshaking());
}
fn legacy_denied(provider: &mut BoundedTls<'_, '_>) {
    let mut buffer = [0; 32];
    for level in [Level::Handshake, Level::OneRtt] {
        assert!(!provider.has_keys(level));
        assert_eq!(provider.seal(level, 1, b"h", &mut buffer, 4), Err(tls::Error::KeysUnavailable));
        assert_eq!(provider.open(level, 1, b"h", &mut buffer), Err(tls::Error::KeysUnavailable));
        assert_eq!(provider.header_mask(level, true, &[0; 16]), Err(tls::Error::KeysUnavailable));
    }
    assert!(provider.integrity_budget().is_none());
    assert_eq!(provider.confirm_handshake(), Err(tls::Error::KeysUnavailable));
    assert_eq!(provider.maintain_keys(0, 10), Err(tls::Error::KeysUnavailable));
    assert_eq!(provider.initiate_key_update(0, 10), Err(tls::Error::KeysUnavailable));
    assert_eq!(provider.acknowledge_one_rtt(1, 0, 0, 10), Err(tls::Error::KeysUnavailable));
    assert_eq!(provider.open_one_rtt(1, false, b"h", &mut buffer, 0, 10), Err(tls::Error::KeysUnavailable));
    assert!(!provider.has_early_keys());
    assert_eq!(provider.seal_early(1, b"h", &mut buffer, 4), Err(tls::Error::KeysUnavailable));
    assert_eq!(provider.open_early(1, b"h", &mut buffer), Err(tls::Error::KeysUnavailable));
}

#[test]
fn actual_owned_tls_keys_and_finished_are_affine_scoped_and_allocation_free() {
    for policy in [CipherPolicy::Aes128Only, CipherPolicy::ChaCha20Only] {
        for p256 in [false, true] {
            let root = CertificateDer::from(fixture::ROOT_DER);
            let anchors = [trust_anchor_from_der(&root).unwrap()];
            let chain = [fixture::LEAF_DER];
            let signer = fixture::signing_key();
            let mut cb = Buffers::new();
            let mut sb = Buffers::new();
            let mut client_scope = ApplicationKeyScope::new(17);
            let mut server_scope = ApplicationKeyScope::new(17);
            let allocation = NoAlloc::start();
            let client_installation = client_scope.claim().unwrap();
            let server_installation = server_scope.claim().unwrap();
            let mut client = BoundedTls::client_with_policy(ClientConfig {
                server_name: "localhost", trust_anchors: &anchors, now: fixture::now(),
                certificate_limits: Limits::default(), transport_parameters: CLIENT_PARAMS,
            }, cb.storage(), &mut TestRandom(121), policy).unwrap();
            // Existing Initial failures must transfer with their budget, never reset.
            assert!(client.integrity_budget().unwrap().authenticate(100, || Err::<(), _>(())).is_err());
            let mut server = BoundedTls::server_with_policy(ServerConfig {
                certificate_chain: &chain, signing_key: &signer, transport_parameters: SERVER_PARAMS,
            }, sb.storage(), &mut TestRandom(143), policy).unwrap();
            if p256 { server.allow_x25519 = false; server.x25519 = None; }
            let mut client = client.into_key_source(client_installation).unwrap();
            let mut server = server.into_key_source(server_installation).unwrap();
            let mut cbudget = client.take_integrity_budget().unwrap();
            let mut sbudget = server.take_integrity_budget().unwrap();
            assert_eq!(cbudget.failed_packets(), 1);
            assert!(client.take_integrity_budget().is_err());
            assert_eq!(client.observations().failed_authentications, None);
            assert!(client.provider.integrity.authenticate(100, || Ok::<_, ()>(())).is_err());
            assert!(client.take_handshake_keys().is_err());
            assert!(client.take_application_keys().is_err());
            assert!(client.take_finished().is_err());
            legacy_denied(&mut client.provider);
            drain(&mut client, &mut server);
            assert_eq!(server.state(), State::ServerClientFinished);
            assert!(server.take_finished().is_err());
            let (shs_rx, mut shs_tx) = server.take_handshake_keys().unwrap().install();
            let smaterial = server.take_application_keys().unwrap();
            assert!(core::ptr::eq(smaterial.scope(), server.scope()));
            let (mut srx, mut stx) = smaterial.install().unwrap();
            assert!(matches!(server.provider.application, ApplicationMaterial::Empty));
            assert!(server.take_handshake_keys().is_err());
            assert!(server.take_application_keys().is_err());
            assert!(server.provider.install_application().is_err());
            assert!(server.provider.packet_keys(KeyKind::Handshake).is_err());
            assert!(server.provider.packet_keys(KeyKind::OneRtt).is_err());
            legacy_denied(&mut server.provider);
            let refused = stx.initiate(srx.prepare_local_update().unwrap(), 0, 10).unwrap_err();
            assert_eq!(refused.error, crypto::Error::KeyUpdateNotAllowed);
            srx.cancel_local_update(refused.ready).unwrap();
            drain(&mut server, &mut client);
            assert_eq!(client.state(), State::Connected);
            let (chs_rx, mut chs_tx) = client.take_handshake_keys().unwrap().install();
            let (mut crx, mut ctx) = client.take_application_keys().unwrap().install().unwrap();
            let cfinished = client.take_finished().unwrap();
            assert_eq!(cfinished.side(), Side::Client);
            assert!(core::ptr::eq(cfinished.scope(), crx.scope()));
            assert!(cfinished.authenticates_peer_parameters(SERVER_PARAMS));
            assert!(!cfinished.authenticates_peer_parameters(CLIENT_PARAMS));
            assert!(client.take_finished().is_err());
            assert!(server.take_finished().is_err());
            // Actual independently owned handshake keys interoperate in both directions.
            let mut cipher = [0; 20]; cipher[..4].copy_from_slice(b"hand");
            chs_tx.seal(3, b"header", &mut cipher, 4).unwrap();
            assert_eq!(shs_rx.open(3, b"header", &mut cipher, &mut sbudget), Ok(4));
            assert_eq!(&cipher[..4], b"hand");
            assert_eq!(chs_tx.seal(3, b"header", &mut cipher, 4), Err(crypto::Error::PacketNumberReuse));
            shs_tx.seal(9, b"header", &mut cipher, 4).unwrap();
            assert_eq!(chs_rx.open(9, b"header", &mut cipher, &mut cbudget), Ok(4));
            assert_eq!(chs_tx.header_mask(&[1; 16]), shs_rx.header_mask(&[1; 16]));
            assert_eq!(shs_tx.header_mask(&[2; 16]), chs_rx.header_mask(&[2; 16]));
            drain(&mut client, &mut server);
            let sfinished = server.take_finished().unwrap();
            assert_eq!(sfinished.side(), Side::Server);
            assert!(sfinished.authenticates_peer_parameters(CLIENT_PARAMS));
            assert!(core::ptr::eq(sfinished.scope(), stx.scope()));
            assert!(!core::ptr::eq(sfinished.scope(), cfinished.scope()));
            assert!(server.take_finished().is_err());
            assert_eq!(client.negotiated_suite(), server.negotiated_suite());
            assert_eq!(client.negotiated_group(), Some(if p256 { crate::tls_wire::GROUP_P256 } else { crate::tls_wire::GROUP_X25519 }));
            for (tx, rx, budget) in [(&mut ctx, &mut srx, &mut sbudget), (&mut stx, &mut crx, &mut cbudget)] {
                cipher[..4].copy_from_slice(b"apps");
                tx.seal(0, b"header", &mut cipher, 4).unwrap();
                assert!(matches!(rx.open(0, false, b"header", &mut cipher, budget, 0, 10), Ok(AuthenticatedRead::Ready(_))));
                assert_eq!(&cipher[..4], b"apps");
                // Finished and a sent packet still do not import raw ACK/confirmation.
                let refused = tx.initiate(rx.prepare_local_update().unwrap(), 0, 10).unwrap_err();
                assert_eq!(refused.error, crypto::Error::KeyUpdateNotAllowed);
                rx.cancel_local_update(refused.ready).unwrap();
            }
            legacy_denied(&mut client.provider);
            assert!(client.provider.install_application().is_err());
            allocation.finish();
        }
    }
}

#[test]
fn cancelled_installations_and_legacy_state_cannot_be_reissued_or_migrated() {
    let root = CertificateDer::from(fixture::ROOT_DER);
    let anchors = [trust_anchor_from_der(&root).unwrap()];
    let chain = [fixture::LEAF_DER];
    let signer = fixture::signing_key();
    let mut cb = Buffers::new(); let mut sb = Buffers::new();
    let mut client_scope = ApplicationKeyScope::new(31); let mut server_scope = ApplicationKeyScope::new(32);
    let mut client = BoundedTls::client(ClientConfig {
        server_name: "localhost", trust_anchors: &anchors, now: fixture::now(),
        certificate_limits: Limits::default(), transport_parameters: CLIENT_PARAMS,
    }, cb.storage(), &mut TestRandom(191)).unwrap().into_key_source(client_scope.claim().unwrap()).unwrap();
    let mut server = BoundedTls::server(ServerConfig {
        certificate_chain: &chain, signing_key: &signer, transport_parameters: SERVER_PARAMS,
    }, sb.storage(), &mut TestRandom(199)).unwrap().into_key_source(server_scope.claim().unwrap()).unwrap();
    let allocation = NoAlloc::start();
    drain(&mut client, &mut server);
    drop(server.take_handshake_keys().unwrap());
    drop(server.take_application_keys().unwrap());
    assert!(server.take_handshake_keys().is_err()); assert!(server.take_application_keys().is_err());
    assert!(server.provider.install_application().is_err());
    assert!(server.provider.install_handshake(0, &[], 0).is_err());
    drain(&mut server, &mut client);
    let mut bad_finished = [0; 128];
    let finished = client.transmit(&mut bad_finished).unwrap().unwrap();
    bad_finished[finished.len - 1] ^= 1;
    assert!(server.receive(finished.level, &bad_finished[..finished.len]).is_err());
    assert_eq!(server.state(), State::Failed);
    assert!(server.take_finished().is_err());
    assert!(server.take_application_keys().is_err());
    drop(server);
    assert!(server_scope.claim().is_err());
    allocation.finish();

    let mut legacy_storage = Buffers::new();
    let mut legacy = BoundedTls::server(ServerConfig {
        certificate_chain: &chain, signing_key: &signer, transport_parameters: SERVER_PARAMS,
    }, legacy_storage.storage(), &mut TestRandom(211)).unwrap();
    let mut fresh_storage = Buffers::new();
    let mut fresh = BoundedTls::client(ClientConfig {
        server_name: "localhost", trust_anchors: &anchors, now: fixture::now(),
        certificate_limits: Limits::default(), transport_parameters: CLIENT_PARAMS,
    }, fresh_storage.storage(), &mut TestRandom(223)).unwrap();
    let mut bytes = [0; 2048];
    while let Some(ch) = fresh.transmit(&mut bytes).unwrap() { legacy.receive(ch.level, &bytes[..ch.len]).unwrap(); }
    assert!(legacy.has_keys(Level::Handshake)); assert!(legacy.has_keys(Level::OneRtt));
    let mut rejected_scope = ApplicationKeyScope::new(32);
    assert!(legacy.into_key_source(rejected_scope.claim().unwrap()).is_err());
    assert!(rejected_scope.claim().is_err());
}

#[test]
fn key_source_preserves_strict_cookie_hrr_and_never_mints_early_keys_or_finished() {
    let root = CertificateDer::from(fixture::ROOT_DER);
    let anchors = [trust_anchor_from_der(&root).unwrap()];
    let mut buffers = Buffers::new();
    let mut scope = ApplicationKeyScope::new(5);
    let allocation = NoAlloc::start();
    let mut source = BoundedTls::client(ClientConfig {
        server_name: "localhost", trust_anchors: &anchors, now: fixture::now(),
        certificate_limits: Limits::default(), transport_parameters: CLIENT_PARAMS,
    }, buffers.storage(), &mut TestRandom(241)).unwrap().into_key_source(scope.claim().unwrap()).unwrap();
    let mut first = [0; 2048];
    let ch1 = source.transmit(&mut first).unwrap().unwrap();
    let mut retry = [0; 512];
    let n = crate::tls_wire::encode_hello_retry_request(&mut retry, 0x1301, None, Some(b"cookie")).unwrap();
    source.receive(Level::Initial, &retry[..n]).unwrap();
    assert_eq!(source.state(), State::ClientServerHelloRetry);
    assert!(source.take_handshake_keys().is_err()); assert!(source.take_application_keys().is_err());
    assert!(source.take_early_key().is_err()); assert!(source.take_finished().is_err());
    let mut second = [0; 2048];
    let ch2 = source.transmit(&mut second).unwrap().unwrap();
    let hrr = crate::tls_wire::parse_hello_retry_request(&retry[..n]).unwrap();
    let hello = crate::tls_wire::validate_client_hello_retry(&first[..ch1.len], &second[..ch2.len], &hrr).unwrap();
    assert_eq!(hello.cookie, Some(&b"cookie"[..]));
    assert!(source.receive(Level::Initial, &retry[..n]).is_err());
    assert_eq!(source.state(), State::Failed);
    assert!(source.take_finished().is_err());
    allocation.finish();
}

#[test]
fn actual_resumption_early_keys_and_post_transfer_tickets_preserve_separate_authority() {
    use crate::{
        bounded_tls::{ClientEarlyData, ClientResumption, ServerEarlyData, ServerResumption},
        early_data::{EarlyFreshness, QuarantineSlot, ReplayStorage, ServerPolicy},
        tls_ticket::{self, Binding, ClientCache, ClientSlot, ReplayPolicy, TicketKey, VerificationContext},
    };
    struct Clock;
    impl tls_ticket::TicketClock for Clock {
        fn now_ms(&self) -> Result<u64, tls_ticket::Error> { Ok(1000) }
    }
    const PARAMETERS: &[u8] = &[0, 0, 15, 0, 4, 1, 16, 5, 1, 16, 6, 1, 16, 8, 1, 1];
    let root = CertificateDer::from(fixture::ROOT_DER);
    let anchors = [trust_anchor_from_der(&root).unwrap()];
    let chain = [fixture::LEAF_DER];
    let signer = fixture::signing_key();
    let client_config = || ClientConfig {
        server_name: "localhost", trust_anchors: &anchors, now: fixture::now(),
        certificate_limits: Limits::default(), transport_parameters: CLIENT_PARAMS,
    };
    let server_config = || ServerConfig {
        certificate_chain: &chain, signing_key: &signer, transport_parameters: PARAMETERS,
    };
    let geometry = [QuarantineSlot::<16>::EMPTY];
    let admission = || ServerEarlyData::buffered(71,
        ServerPolicy::BufferedReplaySafeRequests { max_bytes: 16, max_streams: 1 },
        PARAMETERS, &geometry, EarlyFreshness::new(1000).unwrap()).unwrap();
    let mut replay = ReplayStorage::<2>::new();
    let mut ordinary = [];
    let mut slots = [ClientSlot::<4096>::empty()];
    let mut cache = ClientCache::new(&mut slots);
    let mut ticket_key = TicketKey::generate_with_early_replay(&mut TestRandom(51),
        ReplayPolicy::ReusableOneRtt, &mut ordinary, &mut replay).unwrap();
    let clock = Clock;
    let allocation = NoAlloc::start();
    {
        let mut cb = Buffers::new(); let mut sb = Buffers::new();
        let mut cs = ApplicationKeyScope::new(61); let mut ss = ApplicationKeyScope::new(62);
        let mut entropy = TestRandom(91);
        let mut client = BoundedTls::client_with_tickets(client_config(), cb.storage(), &mut TestRandom(71),
            ClientResumption { store: &mut cache, clock: &clock }).unwrap()
            .into_key_source(cs.claim().unwrap()).unwrap();
        let mut server = BoundedTls::server_with_early_data(server_config(), sb.storage(), &mut TestRandom(89),
            ServerResumption { store: &mut ticket_key, entropy: &mut entropy, clock: &clock,
                policy: b"handoff-early-v1", lifetime_seconds: 60, max_age_skew_ms: 1000 }, admission()).unwrap()
            .into_key_source(ss.claim().unwrap()).unwrap();
        drain(&mut client, &mut server);
        drop(server.take_handshake_keys().unwrap()); drop(server.take_application_keys().unwrap());
        drain(&mut server, &mut client);
        drop(client.take_handshake_keys().unwrap()); drop(client.take_application_keys().unwrap());
        // Ticket processing must survive the application Option becoming empty.
        handshake(&mut client, &mut server);
        assert_eq!(client.state(), State::Connected);
        assert_eq!(client.early_status(), EarlyStatus::Disabled);
    }
    let offer = cache.take_verified_for_origin(1000,
        &Binding::new("localhost", b"hq-interop", &[]).unwrap(), 0x1301,
        VerificationContext::new(&anchors, Limits::default()).unwrap()).unwrap().unwrap();
    let mut cb = Buffers::new(); let mut sb = Buffers::new();
    let mut cs = ApplicationKeyScope::new(71); let mut ss = ApplicationKeyScope::new(71);
    let mut entropy = TestRandom(225);
    let mut client = BoundedTls::client_resuming_early(client_config(), cb.storage(), &mut TestRandom(119),
        ClientResumption { store: &mut cache, clock: &clock }, offer,
        ClientEarlyData::replay_safe_requests(71)).unwrap();
    let mut previous = [0; 20]; previous[..4].copy_from_slice(b"zero");
    client.seal_early(1, b"header", &mut previous, 4).unwrap();
    let mut client = client.into_key_source(cs.claim().unwrap()).unwrap();
    let mut server = BoundedTls::server_with_early_data(server_config(), sb.storage(), &mut TestRandom(223),
        ServerResumption { store: &mut ticket_key, entropy: &mut entropy, clock: &clock,
            policy: b"handoff-early-v1", lifetime_seconds: 60, max_age_skew_ms: 1000 }, admission()).unwrap()
        .into_key_source(ss.claim().unwrap()).unwrap();
    let EarlyKeyMaterial::Transmit(mut early_tx) = client.take_early_key().unwrap() else { panic!("client owns TX"); };
    assert!(client.take_early_key().is_err());
    assert_eq!(early_tx.last_sealed_packet_number(), Some(1));
    assert_eq!(early_tx.sealed_packets(), 1);
    let mut next = [0; 20]; next[..4].copy_from_slice(b"next");
    assert_eq!(early_tx.seal(1, b"header", &mut next, 4), Err(crypto::Error::PacketNumberReuse));
    early_tx.seal(2, b"header", &mut next, 4).unwrap();
    let mut budget = server.take_integrity_budget().unwrap();
    drain(&mut client, &mut server);
    // Public resumption reporting stays false until actual Finished.
    assert!(!server.is_resumed());
    assert_eq!(server.early_status(), EarlyStatus::AcceptedPendingFinished);
    assert!(server.take_finished().is_err());
    let EarlyKeyMaterial::Receive(mut early_rx) = server.take_early_key().unwrap() else { panic!("server owns RX"); };
    assert!(server.take_early_key().is_err());
    assert!(server.take_early_replay_claim().is_some());
    assert!(server.take_early_replay_claim().is_none());
    let mut invalid = previous;
    assert_eq!(early_rx.open(1, b"wrong", &mut invalid, &mut budget), Err(crypto::Error::AuthenticationFailed));
    assert_eq!(budget.failed_packets(), 1);
    assert_eq!(early_rx.open(1, b"header", &mut previous, &mut budget), Ok(4));
    assert_eq!(early_rx.open(2, b"header", &mut next, &mut budget), Ok(4));
    assert_eq!(&previous[..4], b"zero"); assert_eq!(&next[..4], b"next");
    assert!(server.take_finished().is_err());
    let (mut app_rx, mut app_tx) = server.take_application_keys().unwrap().install().unwrap();
    let rejected = app_tx.initiate(app_rx.prepare_local_update().unwrap(), 0, 10).unwrap_err();
    assert_eq!(rejected.error, crypto::Error::KeyUpdateNotAllowed);
    app_rx.cancel_local_update(rejected.ready).unwrap();
    handshake(&mut client, &mut server);
    let finished = server.take_finished().unwrap();
    assert!(server.is_resumed());
    assert_eq!(finished.side(), Side::Server);
    assert_eq!(finished.early_status(), EarlyStatus::Accepted);
    assert_eq!(finished.early_generation(), Some(71));
    assert!(core::ptr::eq(finished.scope(), early_rx.scope()));
    assert_eq!(client.early_status(), EarlyStatus::Accepted);
    assert!(client.is_resumed());
    legacy_denied(&mut client.provider); legacy_denied(&mut server.provider);
    early_rx.discard(); early_tx.discard();
    assert_eq!(early_tx.seal(3, b"header", &mut next, 4), Err(crypto::Error::KeyDiscarded));
    assert_eq!(budget.failed_packets(), 1);
    allocation.finish();
}
