//! Scoped Application-local early-key lifetime test. Real ticket issuance and
//! resumed TLS run through Finished; this fixture then directly confirms the
//! server Provider and discards its Handshake keys before entering the actual
//! application command/provider locals. It does not fabricate Finished or Path
//! grants, and does not qualify the full root's affine phase transitions.
use super::*;
use crate::{carrier::CarrierStorage, mailbox::Mailbox};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use hibana::{
    g,
    runtime::{SessionKitStorage, ids::SessionId, program::project},
};
#[path = "../../../tests/support/tls_actor_fixture.rs"]
mod fixture;

fn drive<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..65536 {
        if let Poll::Ready(result) = future.as_mut().poll(&mut context) {
            return result;
        }
    }
    panic!("application early-key lifetime slice did not terminate");
}

#[test]
fn application_local_retains_late_zero_rtt_then_destroys_actual_early_keys() {
    let generation = 719;
    let payload = b"late early bytes";
    use hibana_quic::{
        bounded_tls::{
            BoundedTls, ClientConfig, ClientEarlyData, ClientResumption, ServerConfig,
            ServerEarlyData, ServerResumption,
        },
        early_data::{EarlyFreshness, QuarantineSlot, ReplayStorage, ServerPolicy},
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
        transport_parameters: &[15, 0, 4, 1, 16],
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
    let mut provider = BoundedTls::server_with_early_data(
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
    let mut cipher = [0; 512];
    cipher[..payload.len()].copy_from_slice(payload);
    let n = peer
        .seal_early(1, b"header", &mut cipher, payload.len())
        .unwrap();

    let sample = [7; 16];
    let expected_mask = peer.early_header_mask(true, &sample).unwrap();
    // Complete real resumed TLS before entering the Handshake-retired slice.
    let mut output = [0; 1536];
    for _ in 0..32 {
        let mut progress = false;
        while let Some(message) = peer.transmit(&mut output).unwrap() {
            provider
                .receive(message.level, &output[..message.len])
                .unwrap();
            progress = true;
        }
        while let Some(message) = provider.transmit(&mut output).unwrap() {
            peer.receive(message.level, &output[..message.len]).unwrap();
            progress = true;
        }
        if !progress {
            break;
        }
    }
    assert!(!peer.is_handshaking() && !provider.is_handshaking());
    assert!(provider.is_resumed());
    assert_eq!(provider.early_status(), EarlyStatus::Accepted);
    provider.confirm_handshake().unwrap();
    provider.discard_keys(Level::Handshake);
    assert!(!provider.has_keys(Level::Handshake));
    assert!(provider.has_keys(Level::OneRtt) && provider.has_early_keys());
    assert!(
        !peer.has_early_keys(),
        "client discarded early keys on application installation"
    );

    let carrier = CarrierStorage::<1, 16, 32>::new();
    let mut slab = [0; 64 * 1024];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init();
    let sid = SessionId::new(719);
    let rendezvous = kit
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    let global = g::seq(
        p::application_work::<24, 25>(),
        g::seq(
            g::send::<25, 24, p::application::Retired>(),
            g::send::<24, 25, p::application::RetirementAcknowledged>(),
        ),
    );
    let cp = project::<24, _>(&global);
    let op = project::<25, _>(&global);
    let mut c = rendezvous.enter(sid, &cp).unwrap();
    let mut o = rendezvous.enter(sid, &op).unwrap();
    let mut request_slots = [None::<Command<1536>>];
    let mut reply_slots = [None::<Reply<1536, 32>>];
    let requests = Mailbox::new(&mut request_slots).unwrap();
    let replies = Mailbox::new(&mut reply_slots).unwrap();
    let (sender, mut receiver) = requests.split().unwrap();
    let (mut reply_sender, reply_receiver) = replies.split().unwrap();
    let exchange = Exchange::<1536, 32>::new();
    let observed = snapshot(&provider).unwrap();
    let measured = actor_test_allocator::NoAlloc::start();
    {
        let _clear = Clear(&exchange);
        let command_local = async {
            // Mailbox client setup for this already-established local slice.
            // This copied snapshot is not a substitute phase/Finished grant.
            reply_sender
                .send(Reply {
                    descriptor: Descriptor {
                        generation,
                        sequence: 0,
                    },
                    snapshot: observed,
                    outcome: Outcome::Installed { early_send: None },
                })
                .await
                .map_err(|_| Error::RepliesClosed)?;
            let mut retirement_reply = None;
            match application::command(
                &mut c,
                generation,
                &mut receiver,
                &mut reply_sender,
                &exchange,
                CommandAuthority::<Application> {
                    sequence: 1,
                    phase: core::marker::PhantomData,
                },
                &mut retirement_reply,
            )
            .await?
            {
                CommandExit::Advanced(_, never) => match never {},
                CommandExit::Retiring(wire) => {
                    same(c.recv::<p::application::Retired>().await?, wire)?;
                    c.send::<p::application::RetirementAcknowledged>(&wire)
                        .await?;
                    reply_sender
                        .send(retirement_reply.take().ok_or(Error::MissingSlot)?)
                        .await
                        .map_err(|_| Error::RepliesClosed)?;
                }
            }
            Ok(())
        };
        let provider_local = async {
            match application::provider(
                &mut o,
                generation,
                OwnerAuthority::<Application, _> {
                    provider,
                    phase: core::marker::PhantomData,
                },
                &exchange,
            )
            .await?
            {
                OwnerExit::Advanced(_, never) => match never {},
                OwnerExit::Retiring(wire) => {
                    o.send::<p::application::Retired>(&wire).await?;
                    same(
                        o.recv::<p::application::RetirementAcknowledged>().await?,
                        wire,
                    )?;
                }
            }
            Ok(())
        };
        let consumer = async {
            let mut client = Client::connect(sender, reply_receiver, generation)
                .await
                .unwrap();
            let claim = client.take_early_replay_grant().await.unwrap().unwrap();
            assert_eq!(claim.generation(), generation);
            assert_eq!(claim.early_generation(), generation);
            assert!(client.take_early_replay_grant().await.unwrap().is_none());
            assert_eq!(
                client
                    .early_header_mask(false, sample)
                    .await
                    .unwrap()
                    .unwrap(),
                expected_mask
            );
            let opened = client
                .open_early(Packet::new(1, b"header", &cipher[..n]).unwrap())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(opened.packet.body(), payload);
            assert!(opened.receipt.authenticates_plaintext(payload));
            assert_eq!(opened.receipt.generation(), generation);
            client.discard_early_keys().await.unwrap().unwrap();
            assert!(!client.snapshot().early_keys);
            assert!(matches!(
                client
                    .open_early(Packet::new(1, b"header", &cipher[..n]).unwrap())
                    .await
                    .unwrap(),
                Err(tls::Error::KeysUnavailable)
            ));
            assert_eq!(
                client.early_header_mask(false, sample).await.unwrap(),
                Err(tls::Error::KeysUnavailable)
            );
            client.retire().await.unwrap();
            Ok(())
        };
        drive(runtime::join2(
            runtime::join2(command_local, provider_local),
            consumer,
        ))
        .unwrap();
    }
    assert!(exchange.is_empty() && requests.is_empty() && replies.is_empty());
    measured.finish();
}
