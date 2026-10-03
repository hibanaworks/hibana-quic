//! Real certificate-authenticated BoundedTls providers owned by projected roles.
//! This qualifies the local actor boundary, not QUIC/network interoperability.
//! Full-handshake/key-update tests retain their original names and allocation
//! scope under roles::tls_owner::authority_tests, where private affine evidence
//! can be exercised without exposing a public capability constructor.
// The bounded, composed two-provider choreography exceeds the default const
// evaluator time lint while producing its four projected role programs.
#![allow(long_running_const_eval)]
#[path = "support/tls_actor_fixture.rs"]
mod fixture;

use core::{
    cell::Cell,
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use fixture::{Buffers, CLIENT_PARAMS, SERVER_PARAMS, TestRandom};
use hibana::{
    Endpoint,
    runtime::{SessionKitStorage, ids::SessionId, program::project},
};
use hibana_quic::{
    bounded_tls::{BoundedTls, ClientConfig, ServerConfig},
    carrier::CarrierStorage,
    crypto,
    mailbox::Mailbox,
    roles::{
        protocol_tls::tls_choreography,
        tls_owner::{self, Bytes, Command, Exchange, Outcome, Reply},
    },
    runtime::join2,
    tls::{self, Level, Provider},
    tls_certificate::{CertificateDer, Limits, trust_anchor_from_der},
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::Wake,
};

type Client<'c, 's> = tls_owner::Client<'c, 's, 1536, 32, 1, 1>;

struct Counting;
thread_local! { static TRACK: Cell<Option<usize>> = const { Cell::new(None) }; }
fn allocation() {
    let _ = TRACK.try_with(|n| {
        if let Some(count) = n.get() {
            n.set(Some(count + 1));
        }
    });
}
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        allocation();
        unsafe { System.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        allocation();
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        allocation();
        unsafe { System.realloc(p, l, n) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
}
#[global_allocator]
static ALLOCATOR: Counting = Counting;
struct NoAlloc;
impl NoAlloc {
    fn start() -> Self {
        TRACK.with(|n| {
            assert!(n.get().is_none());
            n.set(Some(0));
        });
        Self
    }
    fn finish(self) {
        let count = TRACK.with(|n| n.replace(None).unwrap());
        assert_eq!(count, 0, "TLS constructors and actor operations allocated");
    }
}
impl Drop for NoAlloc {
    fn drop(&mut self) {
        TRACK.with(|n| n.set(None));
    }
}
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
    let global = tls_choreography::<24, 25>();
    let p24 = project::<24, _>(&global);
    let p25 = project::<25, _>(&global);
    body(rv.enter(sid, &p24).unwrap(), rv.enter(sid, &p25).unwrap())
}

#[test]
fn real_certificate_rejection_and_failed_provider_metadata_allocate_zero() {
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
        let chain = [fixture::LEAF_DER];
        let signing = fixture::signing_key();
        let mut cb = Buffers::new();
        let mut sb = Buffers::new();
        let (count, waker) = waker();
        let failed_probe = Cell::new(false);
        let dropped = Cell::new(0);
        let measured = NoAlloc::start();
        let client = BoundedTls::client(
            ClientConfig {
                server_name: "wrong.example",
                trust_anchors: &anchors,
                now: fixture::now(),
                certificate_limits: Limits::default(),
                transport_parameters: CLIENT_PARAMS,
            },
            cb.storage(),
            &mut TestRandom(123),
        )
        .unwrap();
        let mut server = BoundedTls::server(
            ServerConfig {
                certificate_chain: &chain,
                signing_key: &signing,
                transport_parameters: SERVER_PARAMS,
            },
            sb.storage(),
            &mut TestRandom(456),
        )
        .unwrap();
        let work = async {
            let mut client = Client::connect(sender, reply_receiver, 11).await.unwrap();
            while let Some((level, bytes)) = client.take_crypto_flight(1536).await.unwrap().unwrap()
            {
                server.receive(level, bytes.as_bytes()).unwrap();
            }
            let mut scratch = [0; 1536];
            let mut rejected = false;
            while let Some(output) = server.transmit(&mut scratch).unwrap() {
                match client
                    .receive_crypto(output.level, &scratch[..output.len])
                    .await
                    .unwrap()
                {
                    Ok(()) => {}
                    Err(tls::Error::Authentication) => {
                        rejected = true;
                        break;
                    }
                    Err(other) => panic!("unexpected certificate rejection: {other:?}"),
                }
            }
            assert!(
                rejected,
                "real localhost certificate cannot authenticate wrong.example"
            );
            assert!(client.snapshot().handshaking);
            assert!(!client.snapshot().handshake_keys && !client.snapshot().one_rtt_keys);
            assert_eq!(client.snapshot().peer_parameters(), None);
            assert!(matches!(
                client.take_crypto_flight(1536).await.unwrap(),
                Err(tls::Error::Handshake)
            ));
            assert!(
                failed_probe.get(),
                "the failed real provider rejected 1-RTT sealing before phase retirement"
            );
            client.retire().await.unwrap();
            Ok(())
        };
        drive(
            join2(
                tls_owner::run_borrowed(
                    &mut c,
                    &mut co,
                    11,
                    Tracked {
                        provider: client,
                        dropped: &dropped,
                        failed_probe: Some(&failed_probe),
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
        measured.finish();
        assert!(exchange.is_empty());
    });
}

/// Drop instrumentation around the real provider. Every implemented operation
/// delegates to its real cryptography; this wrapper never invents success.
struct Tracked<'a, P> {
    provider: P,
    dropped: &'a Cell<usize>,
    failed_probe: Option<&'a Cell<bool>>,
}
impl<P> Drop for Tracked<'_, P> {
    fn drop(&mut self) {
        self.dropped.set(self.dropped.get() + 1);
    }
}
impl<P: Provider> Provider for Tracked<'_, P> {
    fn receive(&mut self, level: Level, bytes: &[u8]) -> Result<(), tls::Error> {
        let result = self.provider.receive(level, bytes);
        if matches!(result, Err(tls::Error::Authentication))
            && let Some(probed) = self.failed_probe
        {
            let mut packet = [0; 64];
            packet[..16].copy_from_slice(b"failed handshake");
            assert_eq!(
                self.provider
                    .seal(Level::OneRtt, 0, b"header", &mut packet, 16),
                Err(tls::Error::Handshake)
            );
            probed.set(true);
        }
        result
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
        self.provider.seal(level, pn, header, buffer, plaintext_len)
    }
    fn open(
        &mut self,
        level: Level,
        pn: u64,
        header: &[u8],
        buffer: &mut [u8],
    ) -> Result<usize, tls::Error> {
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
fn cancellation_drops_real_provider_and_closes_stale_commands_at_every_await_boundary() {
    // 0: never polled; 1: installed and idle; 2: queued owned CRYPTO request;
    // 3: full reply mailbox after provider has processed a request.
    for stage in 0..=3 {
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
                failed_probe: None,
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
fn terminal_retirement_closes_admission_and_drops_the_real_provider_once() {
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
                        failed_probe: None,
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
