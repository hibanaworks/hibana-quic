//! Test evidence comes from the production actors, never receipt constructors.
use crate::{
    carrier::CarrierStorage,
    crypto,
    mailbox::Mailbox,
    roles::{
        client::KeyClient,
        packet_protection::{self, Command, Exchange, Packet, Reply},
        protocol::key_choreography,
    },
    runtime::join2,
};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use hibana::runtime::{SessionKitStorage, ids::SessionId, program::project};

pub(super) fn drive<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..65536 {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
    panic!("actor evidence fixture did not terminate")
}

pub(super) fn initial(generation: u64) -> super::ReceiveEvidence {
    key_evidence(generation, crypto::KeyKind::Initial)
}

pub(super) fn key_evidence(generation: u64, kind: crypto::KeyKind) -> super::ReceiveEvidence {
    let key = || {
        if kind == crypto::KeyKind::Initial {
            crypto::initial_keys(b"driver-evidence").unwrap().client
        } else {
            crypto::PacketKey::from_secret(crypto::CipherSuite::Aes128GcmSha256, kind, &[11; 32])
                .unwrap()
        }
    };
    let mut peer = key();
    let key = key();
    let mut cipher = [0; 64];
    cipher[..7].copy_from_slice(b"payload");
    let n = peer.seal(1, b"header", &mut cipher, 7).unwrap();
    let carrier = CarrierStorage::<1, 16, 16>::new();
    let mut slab = [0; 32 * 1024];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init();
    let sid = SessionId::new(71);
    let rv = kit
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    let global = key_choreography::<16, 17>();
    let (cp, op) = (project::<16, _>(&global), project::<17, _>(&global));
    let (mut c, mut o) = (rv.enter(sid, &cp).unwrap(), rv.enter(sid, &op).unwrap());
    let (mut cq, mut rq): ([Option<Command<128>>; 1], [Option<Reply<128>>; 1]) = ([None], [None]);
    let (cq, rq) = (
        Mailbox::new(&mut cq).unwrap(),
        Mailbox::new(&mut rq).unwrap(),
    );
    let (cs, cr) = cq.split().unwrap();
    let (rs, rr) = rq.split().unwrap();
    let mut exchange = Exchange::new();
    let mut receipt = None;
    let consumer = async {
        let mut client = KeyClient::connect(cs, rr, generation).await.unwrap();
        let (opened, _) = client
            .open(
                Packet::new(1, b"header", &cipher[..n]).unwrap(),
                crypto::IntegrityBudget::new(),
            )
            .await
            .unwrap();
        let opened = opened.unwrap();
        assert_eq!(opened.packet.body(), b"payload");
        receipt = Some(opened.receipt);
        client.retire().await.unwrap();
        Ok(())
    };
    drive(join2(
        packet_protection::run_borrowed(&mut c, &mut o, generation, key, cr, rs, &mut exchange),
        consumer,
    ))
    .unwrap();
    assert!(exchange.is_empty());
    super::ReceiveEvidence::Initial(receipt.unwrap())
}

#[path = "../../tests/support/tls_actor_fixture.rs"]
mod fixture;

/// A real certificate-authenticated handshake ends inside the TLS actor. The
/// peer is the production BoundedTls client; no state flag substitutes for its
/// cryptographic Finished or certificate verification.
#[allow(long_running_const_eval)]
pub(super) fn finished(generation: u64) -> crate::roles::tls_owner::FinishedReceipt {
    finished_with_parameters(generation, fixture::CLIENT_PARAMS)
}
#[allow(long_running_const_eval)]
pub(crate) fn finished_with_parameters(
    generation: u64,
    client_parameters: &[u8],
) -> crate::roles::tls_owner::FinishedReceipt {
    use crate::{
        bounded_tls::{BoundedTls, ClientConfig, ServerConfig},
        roles::{protocol_tls::tls_choreography, tls_owner},
        tls::Provider,
        tls_certificate::{CertificateDer, Limits, trust_anchor_from_der},
    };
    let root = CertificateDer::from(fixture::ROOT_DER);
    let anchors = [trust_anchor_from_der(&root).unwrap()];
    let chain = [fixture::LEAF_DER];
    let signer = fixture::signing_key();
    let mut cb = fixture::Buffers::new();
    let mut sb = fixture::Buffers::new();
    let mut crng = fixture::TestRandom(119);
    let mut srng = fixture::TestRandom(223);
    let mut peer = BoundedTls::client(
        ClientConfig {
            server_name: "localhost",
            trust_anchors: &anchors,
            now: fixture::now(),
            certificate_limits: Limits::default(),
            transport_parameters: client_parameters,
        },
        cb.storage(),
        &mut crng,
    )
    .unwrap();
    let provider = BoundedTls::server(
        ServerConfig {
            certificate_chain: &chain,
            signing_key: &signer,
            transport_parameters: fixture::SERVER_PARAMS,
        },
        sb.storage(),
        &mut srng,
    )
    .unwrap();
    let carrier = CarrierStorage::<1, 16, 32>::new();
    let mut slab = [0; 64 * 1024];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init();
    let sid = SessionId::new(72);
    let rv = kit
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    let global = tls_choreography::<24, 25>();
    let (cp, op) = (project::<24, _>(&global), project::<25, _>(&global));
    let (mut c, mut o) = (rv.enter(sid, &cp).unwrap(), rv.enter(sid, &op).unwrap());
    let (mut cq, mut rq): (
        [Option<tls_owner::Command<1536>>; 1],
        [Option<tls_owner::Reply<1536, 32>>; 1],
    ) = ([None], [None]);
    let (cq, rq) = (
        Mailbox::new(&mut cq).unwrap(),
        Mailbox::new(&mut rq).unwrap(),
    );
    let (cs, cr) = cq.split().unwrap();
    let (rs, rr) = rq.split().unwrap();
    let mut exchange = tls_owner::Exchange::new();
    let mut receipt = None;
    let consumer = async {
        let mut client = tls_owner::Client::connect(cs, rr, generation)
            .await
            .unwrap();
        assert!(client.take_finished_receipt().is_none());
        let mut output = [0; 1536];
        for _ in 0..32 {
            let mut progress = false;
            while let Some(message) = peer.transmit(&mut output).unwrap() {
                client
                    .receive_crypto(message.level, &output[..message.len])
                    .await
                    .unwrap()
                    .unwrap();
                if let Some(finished) = client.take_finished_receipt() {
                    assert!(receipt.is_none());
                    assert_eq!(finished.generation(), generation);
                    receipt = Some(finished);
                }
                progress = true;
            }
            while let Some((level, bytes)) = client.take_crypto_flight(1536).await.unwrap().unwrap()
            {
                peer.receive(level, bytes.as_bytes()).unwrap();
                progress = true;
            }
            if !progress {
                break;
            }
        }
        assert!(!peer.is_handshaking());
        assert!(!client.snapshot().handshaking);
        assert!(client.take_finished_receipt().is_none());
        client.retire().await.unwrap();
        Ok(())
    };
    drive(join2(
        tls_owner::run_borrowed(&mut c, &mut o, generation, provider, cr, rs, &mut exchange),
        consumer,
    ))
    .unwrap();
    assert!(exchange.is_empty());
    receipt.expect("real TLS actor must emit exactly one verified-Finished receipt")
}

/// Certificate-authenticated ticket issuance followed by an actual resumed
/// ClientHello inside the TLS actor. The actor itself burns/transfers the replay
/// claim and opens the early packet; no provider-state adapter mints evidence.
#[allow(long_running_const_eval)]
pub(super) fn early(
    generation: u64,
) -> (
    crate::roles::tls_owner::EarlyOpenReceipt,
    crate::early_data::ReplayClaim,
) {
    use crate::{
        bounded_tls::{
            BoundedTls, ClientConfig, ClientEarlyData, ClientResumption, ServerConfig,
            ServerEarlyData, ServerResumption,
        },
        early_data::{EarlyFreshness, QuarantineSlot, ReplayStorage, ServerPolicy},
        roles::{protocol_tls::tls_choreography, tls_owner},
        tls::Provider,
        tls_certificate::{CertificateDer, Limits, trust_anchor_from_der},
        tls_ticket::{
            self, Binding, ClientCache, ClientSlot, ReplayPolicy, TicketKey, VerificationContext,
        },
    };
    struct Clock;
    impl tls_ticket::TicketClock for Clock {
        fn now_ms(&self) -> Result<u64, tls_ticket::Error> {
            Ok(1000)
        }
    }
    const PARAMETERS: &[u8] = &[0, 0, 15, 0, 4, 1, 16, 5, 1, 16, 6, 1, 16, 8, 1, 1];
    const POLICY: ServerPolicy = ServerPolicy::BufferedReplaySafeRequests {
        max_bytes: 16,
        max_streams: 1,
    };
    let root = CertificateDer::from(fixture::ROOT_DER);
    let anchors = [trust_anchor_from_der(&root).unwrap()];
    let chain = [fixture::LEAF_DER];
    let signer = fixture::signing_key();
    let client_config = || ClientConfig {
        server_name: "localhost",
        trust_anchors: &anchors,
        now: fixture::now(),
        certificate_limits: Limits::default(),
        transport_parameters: fixture::CLIENT_PARAMS,
    };
    let server_config = || ServerConfig {
        certificate_chain: &chain,
        signing_key: &signer,
        transport_parameters: PARAMETERS,
    };
    let geometry = [QuarantineSlot::<16>::EMPTY];
    let admission = || {
        ServerEarlyData::buffered(
            generation,
            POLICY,
            PARAMETERS,
            &geometry,
            EarlyFreshness::new(1000).unwrap(),
        )
        .unwrap()
    };
    let mut replay = ReplayStorage::<2>::new();
    let mut ordinary = [];
    let mut cache_slots = [ClientSlot::<4096>::empty()];
    let mut cache = ClientCache::new(&mut cache_slots);
    let mut rng = fixture::TestRandom(57);
    let mut key = TicketKey::generate_with_early_replay(
        &mut rng,
        ReplayPolicy::ReusableOneRtt,
        &mut ordinary,
        &mut replay,
    )
    .unwrap();
    let clock = Clock;
    {
        let mut cb = fixture::Buffers::new();
        let mut sb = fixture::Buffers::new();
        let mut crng = fixture::TestRandom(71);
        let mut srng = fixture::TestRandom(89);
        let mut entropy = fixture::TestRandom(91);
        let mut client = BoundedTls::client_with_tickets(
            client_config(),
            cb.storage(),
            &mut crng,
            ClientResumption {
                store: &mut cache,
                clock: &clock,
            },
        )
        .unwrap();
        let mut server = BoundedTls::server_with_early_data(
            server_config(),
            sb.storage(),
            &mut srng,
            ServerResumption {
                store: &mut key,
                entropy: &mut entropy,
                clock: &clock,
                policy: b"driver-early-v1",
                lifetime_seconds: 60,
                max_age_skew_ms: 1000,
            },
            admission(),
        )
        .unwrap();
        let mut output = [0; 1536];
        for _ in 0..32 {
            let mut progress = false;
            while let Some(message) = client.transmit(&mut output).unwrap() {
                server
                    .receive(message.level, &output[..message.len])
                    .unwrap();
                progress = true;
            }
            while let Some(message) = server.transmit(&mut output).unwrap() {
                client
                    .receive(message.level, &output[..message.len])
                    .unwrap();
                progress = true;
            }
            if !progress {
                break;
            }
        }
        assert!(!client.is_handshaking() && !server.is_handshaking());
    }
    let offer = cache
        .take_verified_for_origin(
            1000,
            &Binding::new("localhost", b"hq-interop", &[]).unwrap(),
            0x1301,
            VerificationContext::new(&anchors, Limits::default()).unwrap(),
        )
        .unwrap()
        .unwrap();
    let mut cb = fixture::Buffers::new();
    let mut sb = fixture::Buffers::new();
    let mut crng = fixture::TestRandom(119);
    let mut srng = fixture::TestRandom(223);
    let mut entropy = fixture::TestRandom(225);
    let mut peer = BoundedTls::client_resuming_early(
        client_config(),
        cb.storage(),
        &mut crng,
        ClientResumption {
            store: &mut cache,
            clock: &clock,
        },
        offer,
        ClientEarlyData::replay_safe_requests(generation),
    )
    .unwrap();
    let provider = BoundedTls::server_with_early_data(
        server_config(),
        sb.storage(),
        &mut srng,
        ServerResumption {
            store: &mut key,
            entropy: &mut entropy,
            clock: &clock,
            policy: b"driver-early-v1",
            lifetime_seconds: 60,
            max_age_skew_ms: 1000,
        },
        admission(),
    )
    .unwrap();
    let mut cipher = [0; 64];
    cipher[..7].copy_from_slice(b"payload");
    let n = peer.seal_early(1, b"header", &mut cipher, 7).unwrap();
    let carrier = CarrierStorage::<1, 16, 32>::new();
    let mut slab = [0; 64 * 1024];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init();
    let sid = SessionId::new(73);
    let rv = kit
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    let global = tls_choreography::<24, 25>();
    let (cp, op) = (project::<24, _>(&global), project::<25, _>(&global));
    let (mut c, mut o) = (rv.enter(sid, &cp).unwrap(), rv.enter(sid, &op).unwrap());
    let (mut cq, mut rq): (
        [Option<tls_owner::Command<1536>>; 1],
        [Option<tls_owner::Reply<1536, 32>>; 1],
    ) = ([None], [None]);
    let (cq, rq) = (
        Mailbox::new(&mut cq).unwrap(),
        Mailbox::new(&mut rq).unwrap(),
    );
    let (cs, cr) = cq.split().unwrap();
    let (rs, rr) = rq.split().unwrap();
    let mut exchange = tls_owner::Exchange::new();
    let mut evidence = None;
    let consumer = async {
        let mut client = tls_owner::Client::connect(cs, rr, generation)
            .await
            .unwrap();
        let mut hello = [0; 1536];
        while let Some(message) = peer.transmit(&mut hello).unwrap() {
            client
                .receive_crypto(message.level, &hello[..message.len])
                .await
                .unwrap()
                .unwrap();
        }
        assert!(client.snapshot().early_keys);
        let claim = client
            .take_early_replay_claim()
            .await
            .unwrap()
            .expect("actual claim transfer");
        assert!(client.take_early_replay_claim().await.unwrap().is_none());
        let mut corrupt = cipher;
        corrupt[0] ^= 1;
        assert!(matches!(
            client
                .open_early(Packet::new(1, b"header", &corrupt[..n]).unwrap())
                .await
                .unwrap(),
            Err(crate::tls::Error::Authentication)
        ));
        let opened = client
            .open_early(Packet::new(1, b"header", &cipher[..n]).unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(opened.packet.body(), b"payload");
        assert_eq!(opened.receipt.generation(), generation);
        assert_eq!(opened.receipt.packet_number(), 1);
        evidence = Some((opened.receipt, claim));
        client.retire().await.unwrap();
        Ok(())
    };
    drive(join2(
        tls_owner::run_borrowed(&mut c, &mut o, generation, provider, cr, rs, &mut exchange),
        consumer,
    ))
    .unwrap();
    assert!(exchange.is_empty());
    evidence.unwrap()
}
