//! Real server-issued ticket + resumed client TLS owner yields one early-send grant.
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use hibana::runtime::{SessionKitStorage, ids::SessionId, program::project};
use hibana_quic::{carrier::CarrierStorage, mailbox::Mailbox, runtime::join2};
#[path = "tls_actor_fixture.rs"]
mod fixture;
fn drive<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..65536 {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
    }
    panic!("TLS fixture stalled")
}
#[allow(long_running_const_eval)]
pub fn early_send_ready(generation: u64) -> hibana_quic::roles::tls_owner::EarlySendReady {
    use hibana_quic::{
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
    let mut crng = fixture::TestRandom(119);
    let provider = BoundedTls::client_resuming_early(
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

    let carrier = CarrierStorage::<1, 16, 32>::new();
    let mut slab = [0; 64 * 1024];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init();
    let sid = SessionId::new(974);
    let rv = kit
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    let global = tls_choreography::<24, 25>();
    let cp = project::<24, _>(&global);
    let op = project::<25, _>(&global);
    let mut c = rv.enter(sid, &cp).unwrap();
    let mut o = rv.enter(sid, &op).unwrap();
    let mut requests: [Option<tls_owner::Command<1536>>; 1] = [None];
    let mut replies: [Option<tls_owner::Reply<1536, 32>>; 1] = [None];
    let requests = Mailbox::new(&mut requests).unwrap();
    let replies = Mailbox::new(&mut replies).unwrap();
    let (tx, rx) = requests.split().unwrap();
    let (rtx, rrx) = replies.split().unwrap();
    let mut exchange = tls_owner::Exchange::new();
    let mut permission = None;
    let consumer = async {
        let mut client = tls_owner::Client::connect(tx, rrx, generation)
            .await
            .unwrap();
        permission = client.take_early_send_ready();
        assert!(permission.is_some());
        assert!(client.take_early_send_ready().is_none());
        client.retire().await.unwrap();
        Ok(())
    };
    drive(join2(
        tls_owner::run_borrowed(&mut c, &mut o, generation, provider, rx, rtx, &mut exchange),
        consumer,
    ))
    .unwrap();
    permission.unwrap()
}
