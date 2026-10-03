//! Real provider budget moves through an affine loan into real Initial crypto.
#![allow(long_running_const_eval)]
#[path = "support/tls_actor_fixture.rs"]
mod fixture;
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use hibana::{
    Endpoint, g,
    runtime::{SessionKitStorage, ids::SessionId, program::project},
};
use hibana_quic::{
    bounded_tls::{BoundedTls, ClientConfig},
    carrier::CarrierStorage,
    crypto,
    mailbox::Mailbox,
    roles::{
        client::KeyClient,
        packet_protection::{
            self, Command as KeyCommand, Exchange as KeyExchange, Packet, Reply as KeyReply,
        },
        protocol::key_choreography,
        protocol_tls::tls_choreography,
        tls_owner::{self, Command, Exchange, Reply},
    },
    runtime::join2,
    tls_certificate::{CertificateDer, Limits, trust_anchor_from_der},
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::Wake,
};
struct Counting;
thread_local! { static TRACK: core::cell::Cell<Option<usize>> = const { core::cell::Cell::new(None) }; }
fn allocated() {
    let _ = TRACK.try_with(|n| {
        if let Some(count) = n.get() {
            n.set(Some(count + 1));
        }
    });
}
unsafe impl std::alloc::GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: std::alloc::Layout) -> *mut u8 {
        allocated();
        unsafe { std::alloc::System.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: std::alloc::Layout) -> *mut u8 {
        allocated();
        unsafe { std::alloc::System.alloc_zeroed(l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: std::alloc::Layout, n: usize) -> *mut u8 {
        allocated();
        unsafe { std::alloc::System.realloc(p, l, n) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: std::alloc::Layout) {
        unsafe { std::alloc::System.dealloc(p, l) }
    }
}
#[global_allocator]
static ALLOCATOR: Counting = Counting;
struct NoAlloc;
impl NoAlloc {
    fn start() -> Self {
        TRACK.with(|n| n.set(Some(0)));
        Self
    }
    fn finish(self) {
        let n = TRACK.with(|n| n.replace(None).unwrap());
        assert_eq!(n, 0, "affine loan actor operations allocated");
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
        self.wake_by_ref()
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
fn drive<F: Future>(f: F) -> F::Output {
    let count = Arc::new(WakeCount(AtomicUsize::new(0)));
    let w = Waker::from(count.clone());
    let mut cx = Context::from_waker(&w);
    let mut f = pin!(f);
    let measured = NoAlloc::start();
    for _ in 0..2048 {
        let before = count.0.load(Ordering::SeqCst);
        match f.as_mut().poll(&mut cx) {
            Poll::Ready(v) => {
                measured.finish();
                return v;
            }
            Poll::Pending => assert!(
                count.0.load(Ordering::SeqCst) > before,
                "unexpectedly parked"
            ),
        }
    }
    panic!("loan failed to terminate")
}
fn with_roles<R>(
    f: impl for<'r> FnOnce(Endpoint<'r, 24>, Endpoint<'r, 25>, Endpoint<'r, 16>, Endpoint<'r, 17>) -> R,
) -> R {
    let carrier = CarrierStorage::<1, 16, 64>::new();
    let mut slab = [0; 65536];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init();
    let sid = SessionId::new(83);
    let rv = kit
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    let global = g::par(tls_choreography::<24, 25>(), key_choreography::<16, 17>());
    let (a, b, c, d) = (
        project::<24, _>(&global),
        project::<25, _>(&global),
        project::<16, _>(&global),
        project::<17, _>(&global),
    );
    f(
        rv.enter(sid, &a).unwrap(),
        rv.enter(sid, &b).unwrap(),
        rv.enter(sid, &c).unwrap(),
        rv.enter(sid, &d).unwrap(),
    )
}
#[test]
fn real_initial_open_returns_the_same_provider_budget_through_private_loan() {
    let root = CertificateDer::from(fixture::ROOT_DER);
    let anchors = [trust_anchor_from_der(&root).unwrap()];
    let mut buffers = fixture::Buffers::new();
    let mut random = fixture::TestRandom(91);
    let provider = BoundedTls::client(
        ClientConfig {
            server_name: "localhost",
            trust_anchors: &anchors,
            now: fixture::now(),
            certificate_limits: Limits::default(),
            transport_parameters: fixture::CLIENT_PARAMS,
        },
        buffers.storage(),
        &mut random,
    )
    .unwrap();
    let mut peer = crypto::initial_keys(b"loan-key").unwrap().client;
    let mut cipher = [0; 64];
    cipher[..7].copy_from_slice(b"payload");
    let n = peer.seal(1, b"header", &mut cipher, 7).unwrap();
    with_roles(|mut c, mut o, mut kc, mut ko| {
        let (mut cq, mut rq): ([Option<Command<128>>; 1], [Option<Reply<128, 32>>; 1]) =
            ([None], [None]);
        let (mut kcq, mut krq): ([Option<KeyCommand<128>>; 1], [Option<KeyReply<128>>; 1]) =
            ([None], [None]);
        let (cq, rq, kcq, krq) = (
            Mailbox::new(&mut cq).unwrap(),
            Mailbox::new(&mut rq).unwrap(),
            Mailbox::new(&mut kcq).unwrap(),
            Mailbox::new(&mut krq).unwrap(),
        );
        let (cs, cr) = cq.split().unwrap();
        let (rs, rr) = rq.split().unwrap();
        let (kcs, kcr) = kcq.split().unwrap();
        let (krs, krr) = krq.split().unwrap();
        let (mut x, mut kx) = (Exchange::new(), KeyExchange::new());
        let key = crypto::initial_keys(b"loan-key").unwrap().client;
        let consumer = async {
            let mut tls = tls_owner::Client::connect(cs, rr, 31).await.unwrap();
            let mut key = KeyClient::connect(kcs, krr, 31).await.unwrap();
            let mut loan = tls
                .loan_integrity()
                .await
                .unwrap()
                .expect("bounded provider has budget");
            assert_eq!(loan.failed_packets().unwrap(), 0);
            let mut forged = cipher;
            forged[0] ^= 1;
            assert!(matches!(
                loan.open_initial(&mut key, Packet::new(1, b"header", &forged[..n]).unwrap())
                    .await
                    .unwrap(),
                Err(crypto::Error::AuthenticationFailed)
            ));
            assert_eq!(loan.failed_packets().unwrap(), 1);
            let opened = loan
                .open_initial(&mut key, Packet::new(1, b"header", &cipher[..n]).unwrap())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(opened.packet.body(), b"payload");
            assert_eq!(opened.receipt.generation(), 31);
            assert_eq!(loan.failed_packets().unwrap(), 1);
            loan.return_to_owner().await.unwrap();
            let loan = tls.loan_integrity().await.unwrap().unwrap();
            assert_eq!(
                loan.failed_packets().unwrap(),
                1,
                "same provider counter survives return and second loan"
            );
            loan.return_to_owner().await.unwrap();
            key.retire().await.unwrap();
            tls.retire().await.unwrap();
            Ok(())
        };
        let keys = async {
            packet_protection::run_borrowed(&mut kc, &mut ko, 31, key, kcr, krs, &mut kx)
                .await
                .map_err(|_| tls_owner::Error::UnexpectedCommand)
        };
        drive(join2(
            join2(
                tls_owner::run_borrowed(&mut c, &mut o, 31, provider, cr, rs, &mut x),
                keys,
            ),
            consumer,
        ))
        .unwrap();
        assert!(x.is_empty() && kx.is_empty());
    });
}

/// The real provider remains the crypto implementation. This adapter only
/// observes destruction and exercises the trait's optional budget boundary.
struct Observed<T> {
    inner: T,
    expose_budget: bool,
    drops: std::rc::Rc<core::cell::Cell<u32>>,
}
impl<T> Drop for Observed<T> {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1)
    }
}
impl<T: hibana_quic::tls::Provider> hibana_quic::tls::Provider for Observed<T> {
    fn receive(
        &mut self,
        l: hibana_quic::tls::Level,
        b: &[u8],
    ) -> Result<(), hibana_quic::tls::Error> {
        self.inner.receive(l, b)
    }
    fn transmit(
        &mut self,
        b: &mut [u8],
    ) -> Result<Option<hibana_quic::tls::Output>, hibana_quic::tls::Error> {
        self.inner.transmit(b)
    }
    fn has_keys(&self, l: hibana_quic::tls::Level) -> bool {
        self.inner.has_keys(l)
    }
    fn discard_keys(&mut self, l: hibana_quic::tls::Level) {
        self.inner.discard_keys(l)
    }
    fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }
    fn peer_transport_parameters(&self) -> Option<&[u8]> {
        self.inner.peer_transport_parameters()
    }
    fn seal(
        &mut self,
        l: hibana_quic::tls::Level,
        pn: u64,
        h: &[u8],
        b: &mut [u8],
        n: usize,
    ) -> Result<usize, hibana_quic::tls::Error> {
        self.inner.seal(l, pn, h, b, n)
    }
    fn open(
        &mut self,
        l: hibana_quic::tls::Level,
        pn: u64,
        h: &[u8],
        b: &mut [u8],
    ) -> Result<usize, hibana_quic::tls::Error> {
        self.inner.open(l, pn, h, b)
    }
    fn header_mask(
        &self,
        l: hibana_quic::tls::Level,
        local: bool,
        sample: &[u8; 16],
    ) -> Result<[u8; 5], hibana_quic::tls::Error> {
        self.inner.header_mask(l, local, sample)
    }
    fn integrity_budget(&mut self) -> Option<&mut crypto::IntegrityBudget> {
        if self.expose_budget {
            self.inner.integrity_budget()
        } else {
            None
        }
    }
}

#[test]
fn dropping_affine_loan_retires_real_provider_and_absence_never_invents_a_budget() {
    for expose_budget in [true, false] {
        let chain = [fixture::LEAF_DER];
        let signing = fixture::signing_key();
        let mut buffers = fixture::Buffers::new();
        let mut random = fixture::TestRandom(92);
        let provider = BoundedTls::server(
            hibana_quic::bounded_tls::ServerConfig {
                certificate_chain: &chain,
                signing_key: &signing,
                transport_parameters: fixture::SERVER_PARAMS,
            },
            buffers.storage(),
            &mut random,
        )
        .unwrap();
        let drops = std::rc::Rc::new(core::cell::Cell::new(0));
        let provider = Observed {
            inner: provider,
            expose_budget,
            drops: drops.clone(),
        };
        with_roles(|mut c, mut o, _kc, _ko| {
            let (mut cq, mut rq): ([Option<Command<128>>; 1], [Option<Reply<128, 32>>; 1]) =
                ([None], [None]);
            let (cq, rq) = (
                Mailbox::new(&mut cq).unwrap(),
                Mailbox::new(&mut rq).unwrap(),
            );
            let (cs, cr) = cq.split().unwrap();
            let (rs, rr) = rq.split().unwrap();
            let mut exchange = Exchange::new();
            let consumer = async {
                let mut client = tls_owner::Client::connect(cs, rr, 32).await.unwrap();
                if expose_budget {
                    let loan = client.loan_integrity().await.unwrap().unwrap();
                    assert_eq!(loan.failed_packets().unwrap(), 0);
                    drop(loan);
                    // Any subsequent request must observe closure; flight retrieval needs
                    // no fabricated handshake-confirmation capability.
                    assert!(matches!(
                        client.take_crypto_flight(128).await,
                        Err(tls_owner::ClientError::Closed)
                    ));
                } else {
                    assert!(client.loan_integrity().await.unwrap().is_none());
                    assert!(
                        client
                            .take_crypto_flight(128)
                            .await
                            .unwrap()
                            .unwrap()
                            .is_none()
                    );
                    client.retire().await.unwrap();
                }
                Ok(())
            };
            let result = drive(join2(
                tls_owner::run_borrowed(&mut c, &mut o, 32, provider, cr, rs, &mut exchange),
                consumer,
            ));
            if expose_budget {
                assert!(matches!(result, Err(tls_owner::Error::CommandsClosed)));
            } else {
                result.unwrap();
            }
            assert!(exchange.is_empty());
        });
        assert_eq!(
            drops.get(),
            1,
            "cancel/retire must destroy the real provider exactly once"
        );
    }
}
