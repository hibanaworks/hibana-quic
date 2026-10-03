//! Scoped runtime evidence for the actual production TLS root, using its
//! installation + InitialWork + retirement prefix, plus a separate real
//! Initial-to-Handshake key-grant slice. These tests do not qualify the full
//! staged projection or certificate/Finished authentication. The existing
//! full-graph tests remain unchanged and their compilation/runtime blockers
//! must be reported separately. No fake TLS provider or priming operation.
#![allow(long_running_const_eval)]
#[path = "support/tls_actor_fixture.rs"]
mod fixture;

use core::{
    cell::Cell,
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use fixture::{Buffers, CLIENT_PARAMS, TestRandom};
use hibana::{
    Endpoint, g,
    runtime::{SessionKitStorage, ids::SessionId, program::project},
};
use hibana_quic::{
    bounded_tls::{BoundedTls, ClientConfig, ServerConfig},
    carrier::CarrierStorage,
    crypto,
    mailbox::Mailbox,
    roles::{
        packet_protection::Packet,
        protocol_tls_phases as p,
        tls_owner::{self, Bytes, Command, Exchange, Outcome, Reply},
    },
    runtime::join2,
    tls::{self, Level, Provider},
    tls_certificate::{CertificateDer, Limits, trust_anchor_from_der},
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::Wake,
};

type Client<'c, 's> = tls_owner::Client<'c, 's, 1536, 32, 1, 1>;

#[global_allocator]
static ALLOCATOR: actor_test_allocator::Counting = actor_test_allocator::Counting;
use actor_test_allocator::NoAlloc;

struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
fn waker() -> (Arc<WakeCount>, Waker) {
    let count = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = Waker::from(count.clone());
    (count, waker)
}
fn drive<F: Future>(future: F, count: &WakeCount, waker: &Waker) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(waker);
    for _ in 0..65536 {
        let before = count.0.load(Ordering::SeqCst);
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => return output,
            Poll::Pending => assert!(
                count.0.load(Ordering::SeqCst) > before,
                "actors parked without an expected wake"
            ),
        }
    }
    panic!("bounded actor scenario did not terminate")
}
fn with_pair<R>(body: impl for<'r> FnOnce(Endpoint<'r, 24>, Endpoint<'r, 25>) -> R) -> R {
    let carrier = CarrierStorage::<1, 16, 32>::new();
    let mut slab = [0; 64 * 1024];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init();
    let sid = SessionId::new(92);
    let rv = kit
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    // Same installation, complete InitialWork body and boundary choices.
    // The advance branch stops after its real grant; these tests never select it.
    // This small graph cannot qualify the whole production projection.
    let global = g::seq(
        g::send::<24, 25, p::Install>(),
        g::seq(
            g::send::<25, 24, p::Installed>(),
            g::seq(
                p::initial_work::<24, 25>(),
                g::route(
                    g::send::<25, 24, p::HandshakeKeyGrant>(),
                    g::seq(
                        g::send::<25, 24, p::initial::Retired>(),
                        g::send::<24, 25, p::initial::RetirementAcknowledged>(),
                    ),
                ),
            ),
        ),
    );
    let p24 = project::<24, _>(&global);
    let p25 = project::<25, _>(&global);
    body(rv.enter(sid, &p24).unwrap(), rv.enter(sid, &p25).unwrap())
}

fn with_handshake_prefix<R>(
    body: impl for<'r> FnOnce(Endpoint<'r, 24>, Endpoint<'r, 25>) -> R,
) -> R {
    let carrier = CarrierStorage::<1, 16, 32>::new();
    let mut slab = [0; 64 * 1024];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init();
    let sid = SessionId::new(92);
    let rv = kit
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    // Exact installation + InitialWork + HandshakeWork and their boundaries.
    // The unselected ApplicationTrafficGrant branch stops at that real grant.
    // This slice does not qualify the complete production projection.
    let global = g::seq(
        g::send::<24, 25, p::Install>(),
        g::seq(
            g::send::<25, 24, p::Installed>(),
            g::seq(
                p::initial_work::<24, 25>(),
                g::route(
                    g::seq(
                        g::send::<25, 24, p::HandshakeKeyGrant>(),
                        g::seq(
                            p::handshake_work::<24, 25>(),
                            g::route(
                                g::send::<25, 24, p::ApplicationTrafficGrant>(),
                                g::seq(
                                    g::send::<25, 24, p::handshake::Retired>(),
                                    g::send::<24, 25, p::handshake::RetirementAcknowledged>(),
                                ),
                            ),
                        ),
                    ),
                    g::seq(
                        g::send::<25, 24, p::initial::Retired>(),
                        g::send::<24, 25, p::initial::RetirementAcknowledged>(),
                    ),
                ),
            ),
        ),
    );
    let p24 = project::<24, _>(&global);
    let p25 = project::<25, _>(&global);
    body(rv.enter(sid, &p24).unwrap(), rv.enter(sid, &p25).unwrap())
}

/// Drop instrumentation around the real provider. Every implemented operation
/// delegates to its real cryptography; this wrapper never invents success.
struct Tracked<'a, P> {
    provider: P,
    dropped: &'a Cell<usize>,
    crypto_calls: Option<&'a Cell<usize>>,
}
impl<P> Drop for Tracked<'_, P> {
    fn drop(&mut self) {
        self.dropped.set(self.dropped.get() + 1);
    }
}
impl<P: Provider> Provider for Tracked<'_, P> {
    fn receive(&mut self, level: Level, bytes: &[u8]) -> Result<(), tls::Error> {
        self.provider.receive(level, bytes)
    }

    fn transmit(&mut self, output: &mut [u8]) -> Result<Option<tls::Output>, tls::Error> {
        self.provider.transmit(output)
    }
    fn has_keys(&self, level: Level) -> bool {
        self.provider.has_keys(level)
    }
    fn discard_keys(&mut self, level: Level) {
        self.provider.discard_keys(level);
    }
    fn is_handshaking(&self) -> bool {
        self.provider.is_handshaking()
    }
    fn peer_transport_parameters(&self) -> Option<&[u8]> {
        self.provider.peer_transport_parameters()
    }
    fn seal(
        &mut self,
        level: Level,
        pn: u64,
        header: &[u8],
        buffer: &mut [u8],
        plaintext_len: usize,
    ) -> Result<usize, tls::Error> {
        if let Some(calls) = self.crypto_calls {
            calls.set(calls.get() + 1);
        }
        self.provider.seal(level, pn, header, buffer, plaintext_len)
    }
    fn open(
        &mut self,
        level: Level,
        pn: u64,
        header: &[u8],
        buffer: &mut [u8],
    ) -> Result<usize, tls::Error> {
        if let Some(calls) = self.crypto_calls {
            calls.set(calls.get() + 1);
        }
        self.provider.open(level, pn, header, buffer)
    }
    fn header_mask(
        &self,
        level: Level,
        local: bool,
        sample: &[u8; 16],
    ) -> Result<[u8; 5], tls::Error> {
        self.provider.header_mask(level, local, sample)
    }
    fn negotiated_group(&self) -> Option<u16> {
        self.provider.negotiated_group()
    }
    fn key_phase(&self) -> bool {
        self.provider.key_phase()
    }
    fn integrity_budget(&mut self) -> Option<&mut crypto::IntegrityBudget> {
        self.provider.integrity_budget()
    }
    fn receive_key_generation(&self) -> u64 {
        self.provider.receive_key_generation()
    }
    fn key_generation(&self) -> u64 {
        self.provider.key_generation()
    }
    fn confirm_handshake(&mut self) -> Result<(), tls::Error> {
        self.provider.confirm_handshake()
    }
    fn maintain_keys(&mut self, now: u64, pto: u64) -> Result<(), tls::Error> {
        self.provider.maintain_keys(now, pto)
    }
    fn initiate_key_update(&mut self, now: u64, pto: u64) -> Result<(), tls::Error> {
        self.provider.initiate_key_update(now, pto)
    }
    fn acknowledge_one_rtt(
        &mut self,
        pn: u64,
        generation: u64,
        now: u64,
        pto: u64,
    ) -> Result<(), tls::Error> {
        self.provider.acknowledge_one_rtt(pn, generation, now, pto)
    }
    fn open_one_rtt(
        &mut self,
        pn: u64,
        phase: bool,
        header: &[u8],
        buffer: &mut [u8],
        now: u64,
        pto: u64,
    ) -> Result<crypto::Opened, tls::Error> {
        self.provider
            .open_one_rtt(pn, phase, header, buffer, now, pto)
    }
}

#[test]
fn initial_prefix_q1_cancellation_drops_provider_and_closes_stale_commands() {
    // 0: never polled; 1: installed and idle; 2: queued owned CRYPTO request;
    // 3: full reply mailbox after provider has processed a request.
    for stage in 0..=3 {
        with_pair(|mut c, mut co| {
            let mut requests = [None::<Command<1536>>];
            let mut responses = [None::<Reply<1536, 32>>];
            let requests = Mailbox::new(&mut requests).unwrap();
            let responses = Mailbox::new(&mut responses).unwrap();
            let (mut sender, receiver) = requests.split().unwrap();
            let (reply_sender, mut reply_receiver) = responses.split().unwrap();
            let mut exchange = Exchange::new();
            let root = CertificateDer::from(fixture::ROOT_DER);
            let anchors = [trust_anchor_from_der(&root).unwrap()];
            let mut cb = Buffers::new();
            let dropped = Cell::new(0);
            let (count, waker) = waker();
            let mut cx = Context::from_waker(&waker);
            let measured = NoAlloc::start();
            let provider = BoundedTls::client(
                ClientConfig {
                    server_name: "localhost",
                    trust_anchors: &anchors,
                    now: fixture::now(),
                    certificate_limits: Limits::default(),
                    transport_parameters: CLIENT_PARAMS,
                },
                cb.storage(),
                &mut TestRandom(789),
            )
            .unwrap();
            let tracked = Tracked {
                provider,
                dropped: &dropped,
                crypto_calls: None,
            };
            {
                let mut running = pin!(tls_owner::run_borrowed(
                    &mut c,
                    &mut co,
                    12,
                    tracked,
                    receiver,
                    reply_sender,
                    &mut exchange
                ));
                if stage > 0 {
                    for _ in 0..64 {
                        assert!(running.as_mut().poll(&mut cx).is_pending());
                        if !responses.is_empty() {
                            break;
                        }
                    }
                    assert_eq!(responses.len(), 1);
                    if stage < 3 {
                        assert!(matches!(
                            drive(reply_receiver.recv(), &count, &waker)
                                .unwrap()
                                .outcome,
                            Outcome::Installed { .. }
                        ));
                    }
                }
                if stage == 2 {
                    drive(
                        sender.send(Command::ReceiveCrypto {
                            level: Level::Handshake,
                            bytes: Bytes::new(b"queued owned bytes").unwrap(),
                        }),
                        &count,
                        &waker,
                    )
                    .unwrap_or_else(|_| panic!("closed before cancellation"));
                    assert_eq!(requests.len(), 1);
                }
                if stage == 3 {
                    drive(
                        sender.send(Command::TakeCryptoFlight { max_len: 1536 }),
                        &count,
                        &waker,
                    )
                    .unwrap_or_else(|_| panic!("closed before response backpressure"));
                    for _ in 0..64 {
                        assert!(running.as_mut().poll(&mut cx).is_pending());
                    }
                    assert!(requests.is_empty());
                    assert_eq!(responses.len(), 1);
                }
                assert_eq!(dropped.get(), 0);
            }
            assert_eq!(
                dropped.get(),
                1,
                "the aggregate uniquely owns and drops the provider"
            );
            assert!(exchange.is_empty());
            assert!(requests.is_empty());
            assert!(sender.is_closed());
            assert!(
                drive(
                    sender.send(Command::TakeCryptoFlight { max_len: 1536 }),
                    &count,
                    &waker
                )
                .is_err()
            );
            // Published results may drain after sender closure. No new result
            // can appear and no result grants a live provider after cancellation.
            while drive(reply_receiver.recv(), &count, &waker).is_ok() {}
            assert!(responses.is_empty());
            measured.finish();
        });
    }
}

#[test]
fn initial_prefix_first_retirement_drops_provider_once_and_closes_admission() {
    with_pair(|mut c, mut co| {
        let mut requests = [const { None::<Command<1536>> }; 2];
        let mut responses = [None::<Reply<1536, 32>>];
        let requests = Mailbox::new(&mut requests).unwrap();
        let responses = Mailbox::new(&mut responses).unwrap();
        let (mut sender, receiver) = requests.split().unwrap();
        let (reply_sender, mut reply_receiver) = responses.split().unwrap();
        let mut exchange = Exchange::new();
        let root = CertificateDer::from(fixture::ROOT_DER);
        let anchors = [trust_anchor_from_der(&root).unwrap()];
        let mut cb = Buffers::new();
        let dropped = Cell::new(0);
        let (count, waker) = waker();
        let measured = NoAlloc::start();
        let provider = BoundedTls::client(
            ClientConfig {
                server_name: "localhost",
                trust_anchors: &anchors,
                now: fixture::now(),
                certificate_limits: Limits::default(),
                transport_parameters: CLIENT_PARAMS,
            },
            cb.storage(),
            &mut TestRandom(987),
        )
        .unwrap();
        let work = async {
            assert!(matches!(
                reply_receiver.recv().await.unwrap().outcome,
                Outcome::Installed { .. }
            ));
            sender
                .send(Command::Retire)
                .await
                .unwrap_or_else(|_| panic!("closed"));
            sender
                .send(Command::TakeCryptoFlight { max_len: 1536 })
                .await
                .unwrap_or_else(|_| panic!("queue closed too early"));
            assert!(matches!(
                reply_receiver.recv().await.unwrap().outcome,
                Outcome::Retired
            ));
            assert!(
                sender
                    .send(Command::TakeCryptoFlight { max_len: 1536 })
                    .await
                    .is_err()
            );
            assert!(reply_receiver.recv().await.is_err());
            Ok(())
        };
        drive(
            join2(
                tls_owner::run_borrowed(
                    &mut c,
                    &mut co,
                    13,
                    Tracked {
                        provider,
                        dropped: &dropped,
                        crypto_calls: None,
                    },
                    receiver,
                    reply_sender,
                    &mut exchange,
                ),
                work,
            ),
            &count,
            &waker,
        )
        .unwrap();
        assert_eq!(dropped.get(), 1);
        assert!(exchange.is_empty() && requests.is_empty() && responses.is_empty());
        measured.finish();
    });
}

#[test]
fn initial_prefix_multiple_real_client_hello_fragments_then_retirement() {
    with_pair(|mut c, mut co| {
        let mut requests = [None::<Command<1536>>];
        let mut responses = [None::<Reply<1536, 32>>];
        let requests = Mailbox::new(&mut requests).unwrap();
        let responses = Mailbox::new(&mut responses).unwrap();
        let (sender, receiver) = requests.split().unwrap();
        let (reply_sender, reply_receiver) = responses.split().unwrap();
        let mut exchange = Exchange::new();
        let root = CertificateDer::from(fixture::ROOT_DER);
        let anchors = [trust_anchor_from_der(&root).unwrap()];
        let mut cb = Buffers::new();
        let dropped = Cell::new(0);
        let (count, waker) = waker();
        let measured = NoAlloc::start();
        let provider = BoundedTls::client(
            ClientConfig {
                server_name: "localhost",
                trust_anchors: &anchors,
                now: fixture::now(),
                certificate_limits: Limits::default(),
                transport_parameters: CLIENT_PARAMS,
            },
            cb.storage(),
            &mut TestRandom(114),
        )
        .unwrap();
        let work = async {
            let mut client = Client::connect(sender, reply_receiver, 14).await.unwrap();
            let mut fragments = 0;
            let mut total = 0;
            while let Some((level, bytes)) = client.take_crypto_flight(31).await.unwrap().unwrap() {
                assert_eq!(level, Level::Initial);
                assert!(!bytes.as_bytes().is_empty() && bytes.as_bytes().len() <= 31);
                fragments += 1;
                total += bytes.as_bytes().len();
            }
            assert!(fragments > 1 && total > 31);
            assert!(client.snapshot().handshaking && !client.snapshot().handshake_keys);
            client.retire().await.unwrap();
            Ok(())
        };
        drive(
            join2(
                tls_owner::run_borrowed(
                    &mut c,
                    &mut co,
                    14,
                    Tracked {
                        provider,
                        dropped: &dropped,
                        crypto_calls: None,
                    },
                    receiver,
                    reply_sender,
                    &mut exchange,
                ),
                work,
            ),
            &count,
            &waker,
        )
        .unwrap();
        assert_eq!(dropped.get(), 1);
        assert!(exchange.is_empty() && requests.is_empty() && responses.is_empty());
        measured.finish();
    });
}

#[test]
fn initial_prefix_rejects_handshake_crypto_without_calling_provider() {
    with_pair(|mut c, mut co| {
        let mut requests = [None::<Command<1536>>];
        let mut responses = [None::<Reply<1536, 32>>];
        let requests = Mailbox::new(&mut requests).unwrap();
        let responses = Mailbox::new(&mut responses).unwrap();
        let (sender, receiver) = requests.split().unwrap();
        let (reply_sender, reply_receiver) = responses.split().unwrap();
        let mut exchange = Exchange::new();
        let root = CertificateDer::from(fixture::ROOT_DER);
        let anchors = [trust_anchor_from_der(&root).unwrap()];
        let mut cb = Buffers::new();
        let dropped = Cell::new(0);
        let crypto_calls = Cell::new(0);
        let (count, waker) = waker();
        let measured = NoAlloc::start();
        let provider = BoundedTls::client(
            ClientConfig {
                server_name: "localhost",
                trust_anchors: &anchors,
                now: fixture::now(),
                certificate_limits: Limits::default(),
                transport_parameters: CLIENT_PARAMS,
            },
            cb.storage(),
            &mut TestRandom(115),
        )
        .unwrap();
        let work = async {
            let mut client = Client::connect(sender, reply_receiver, 15).await.unwrap();
            // A copied readiness observation is not required or consulted here.
            // The current local continuation rejects this selector outright.
            let _ = client
                .open_handshake(Packet::new(0, b"header", b"ciphertext").unwrap())
                .await;
            Ok(())
        };
        let result = drive(
            join2(
                tls_owner::run_borrowed(
                    &mut c,
                    &mut co,
                    15,
                    Tracked {
                        provider,
                        dropped: &dropped,
                        crypto_calls: Some(&crypto_calls),
                    },
                    receiver,
                    reply_sender,
                    &mut exchange,
                ),
                work,
            ),
            &count,
            &waker,
        );
        assert!(matches!(result, Err(tls_owner::Error::UnexpectedCommand)));
        assert_eq!(
            crypto_calls.get(),
            0,
            "phase rejection must precede Provider crypto"
        );
        assert_eq!(dropped.get(), 1);
        assert!(exchange.is_empty() && requests.is_empty() && responses.is_empty());
        measured.finish();
    });
}

#[test]
fn handshake_prefix_consumes_real_server_hello_key_grant_then_retires() {
    with_handshake_prefix(|mut c, mut co| {
        let mut requests = [None::<Command<1536>>];
        let mut responses = [None::<Reply<1536, 32>>];
        let requests = Mailbox::new(&mut requests).unwrap();
        let responses = Mailbox::new(&mut responses).unwrap();
        let (sender, receiver) = requests.split().unwrap();
        let (reply_sender, reply_receiver) = responses.split().unwrap();
        let mut exchange = Exchange::new();
        let root = CertificateDer::from(fixture::ROOT_DER);
        let anchors = [trust_anchor_from_der(&root).unwrap()];
        let chain = [fixture::LEAF_DER];
        let signing = fixture::signing_key();
        let mut cb = Buffers::new();
        let mut sb = Buffers::new();
        let dropped = Cell::new(0);
        let (count, waker) = waker();
        let measured = NoAlloc::start();
        let provider = BoundedTls::client(
            ClientConfig {
                server_name: "localhost",
                trust_anchors: &anchors,
                now: fixture::now(),
                certificate_limits: Limits::default(),
                transport_parameters: CLIENT_PARAMS,
            },
            cb.storage(),
            &mut TestRandom(116),
        )
        .unwrap();
        let mut server = BoundedTls::server(
            ServerConfig {
                certificate_chain: &chain,
                signing_key: &signing,
                transport_parameters: fixture::SERVER_PARAMS,
            },
            sb.storage(),
            &mut TestRandom(117),
        )
        .unwrap();
        let work = async {
            let mut client = Client::connect(sender, reply_receiver, 16).await.unwrap();
            while let Some((level, bytes)) = client.take_crypto_flight(1536).await.unwrap().unwrap()
            {
                server.receive(level, bytes.as_bytes()).unwrap();
            }
            let mut bytes = [0; 1536];
            let output = server.transmit(&mut bytes).unwrap().unwrap();
            assert_eq!(
                output.level,
                Level::Initial,
                "real ServerHello is Initial CRYPTO"
            );
            client
                .receive_crypto(output.level, &bytes[..output.len])
                .await
                .unwrap()
                .unwrap();
            assert!(client.snapshot().handshake_keys);
            // ServerHello derives keys, but does not authenticate the server.
            assert!(client.snapshot().handshaking);
            assert!(client.take_finished_receipt().is_none());
            // No priming request: the first operation in the new local phase is retirement.
            client.retire().await.unwrap();
            Ok(())
        };
        drive(
            join2(
                tls_owner::run_borrowed(
                    &mut c,
                    &mut co,
                    16,
                    Tracked {
                        provider,
                        dropped: &dropped,
                        crypto_calls: None,
                    },
                    receiver,
                    reply_sender,
                    &mut exchange,
                ),
                work,
            ),
            &count,
            &waker,
        )
        .unwrap();
        assert_eq!(dropped.get(), 1);
        assert!(exchange.is_empty() && requests.is_empty() && responses.is_empty());
        drop(server);
        measured.finish();
    });
}
