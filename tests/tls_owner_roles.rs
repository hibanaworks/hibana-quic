//! Real certificate-authenticated BoundedTls providers owned by projected roles.
//! This qualifies the local actor boundary, not QUIC/network interoperability.
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
fn with_two_pairs<R>(
    body: impl for<'r> FnOnce(
        Endpoint<'r, 24>,
        Endpoint<'r, 25>,
        Endpoint<'r, 26>,
        Endpoint<'r, 27>,
        &CarrierStorage<1, 16, 64>,
    ) -> R,
) -> R {
    let carrier = CarrierStorage::<1, 16, 64>::new();
    let mut slab = [0; 64 * 1024];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init();
    let sid = SessionId::new(91);
    let rv = kit
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    let global = g::par(tls_choreography::<24, 25>(), tls_choreography::<26, 27>());
    let p24 = project::<24, _>(&global);
    let p25 = project::<25, _>(&global);
    let p26 = project::<26, _>(&global);
    let p27 = project::<27, _>(&global);
    body(
        rv.enter(sid, &p24).unwrap(),
        rv.enter(sid, &p25).unwrap(),
        rv.enter(sid, &p26).unwrap(),
        rv.enter(sid, &p27).unwrap(),
        &carrier,
    )
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

async fn drain(from: &mut Client<'_, '_>, to: &mut Client<'_, '_>, fragment: usize) -> bool {
    let mut progressed = false;
    for _ in 0..8192 {
        let Some((level, bytes)) = from.take_crypto_flight(fragment).await.unwrap().unwrap() else {
            return progressed;
        };
        assert!(!bytes.as_bytes().is_empty());
        for fragment in bytes.as_bytes().chunks(fragment) {
            to.receive_crypto(level, fragment).await.unwrap().unwrap();
        }
        progressed = true;
    }
    panic!("unbounded CRYPTO output")
}
async fn handshake(client: &mut Client<'_, '_>, server: &mut Client<'_, '_>, fragment: usize) {
    for _ in 0..16 {
        let c = drain(client, server, fragment).await;
        let s = drain(server, client, fragment).await;
        if !c && !s {
            assert!(!client.snapshot().handshaking);
            assert!(!server.snapshot().handshaking);
            return;
        }
    }
    panic!("real TLS handshake did not finish")
}
fn packet(pn: u64, text: &[u8]) -> Packet<1536> {
    phase_packet(pn, false, text)
}
fn phase_packet(pn: u64, phase: bool, text: &[u8]) -> Packet<1536> {
    Packet::new(pn, if phase { b"\x44header" } else { b"\x40header" }, text).unwrap()
}
fn copied(source: &Packet<1536>) -> Packet<1536> {
    Packet::new(source.packet_number(), source.header(), source.body()).unwrap()
}
fn corrupt(source: &Packet<1536>) -> Packet<1536> {
    let mut bytes = [0; 1536];
    let n = source.body().len();
    bytes[..n].copy_from_slice(source.body());
    bytes[n - 1] ^= 1;
    Packet::new(source.packet_number(), source.header(), &bytes[..n]).unwrap()
}

async fn handshake_packet(sender: &mut Client<'_, '_>, receiver: &mut Client<'_, '_>) {
    let sealed = sender
        .seal_handshake(packet(7, b"real handshake keys"))
        .await
        .unwrap()
        .unwrap();
    assert_ne!(sealed.body(), b"real handshake keys");
    assert!(matches!(
        receiver.open_handshake(corrupt(&sealed)).await.unwrap(),
        Err(tls::Error::Authentication)
    ));
    let opened = receiver.open_handshake(sealed).await.unwrap().unwrap();
    assert_eq!(opened.packet.body(), b"real handshake keys");
    assert_eq!(opened.receipt.level(), Level::Handshake);
    assert_eq!(opened.receipt.packet_number(), 7);
    assert!(matches!(
        sender
            .seal_handshake(packet(7, b"nonce reuse"))
            .await
            .unwrap(),
        Err(tls::Error::PacketNumberReuse)
    ));
    let local = sender
        .header_mask(Level::Handshake, true, [7; 16])
        .await
        .unwrap()
        .unwrap();
    let remote = receiver
        .header_mask(Level::Handshake, false, [7; 16])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(local, remote);
}

async fn packets_and_updates(client: &mut Client<'_, '_>, server: &mut Client<'_, '_>) {
    let original = *client.snapshot();
    assert!(original.handshake_keys && original.one_rtt_keys);
    assert!(!original.early_keys);
    assert_eq!(original.peer_parameters(), Some(SERVER_PARAMS));
    assert_eq!(server.snapshot().peer_parameters(), Some(CLIENT_PARAMS));
    assert_eq!(original.negotiated_group, Some(0x001d));
    assert_eq!(
        (
            original.send_generation,
            original.receive_generation,
            original.key_phase
        ),
        (0, 0, false)
    );
    let initial_header_mask = client
        .header_mask(Level::OneRtt, true, [9; 16])
        .await
        .unwrap()
        .unwrap();
    handshake_packet(client, server).await;
    handshake_packet(server, client).await;
    // Application update authorization is not implied merely by TLS completion.
    assert_eq!(
        client.initiate_key_update(0, 10).await.unwrap(),
        Err(tls::Error::KeyUpdateNotAllowed)
    );
    client.confirm_handshake().await.unwrap().unwrap();
    server.confirm_handshake().await.unwrap().unwrap();
    client.maintain_keys(0, 10).await.unwrap().unwrap();
    server.maintain_keys(0, 10).await.unwrap().unwrap();
    assert_eq!(
        client.initiate_key_update(0, 10).await.unwrap(),
        Err(tls::Error::KeyUpdateNotAllowed)
    );
    assert!(matches!(
        client
            .seal_one_rtt(phase_packet(10, true, b"incorrect outgoing phase"))
            .await
            .unwrap(),
        Err(tls::Error::InvalidInput)
    ));
    let old = client
        .seal_one_rtt(packet(10, b"old generation delayed"))
        .await
        .unwrap()
        .unwrap();
    let old_copy = copied(&old);
    let initial = server
        .open_one_rtt(copied(&old), false, 0, 10)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(initial.packet.body(), b"old generation delayed");
    assert_eq!((initial.generation, initial.key_updated), (0, false));
    let response = server
        .seal_one_rtt(packet(20, b"generation zero ACK carrier"))
        .await
        .unwrap()
        .unwrap();
    let response = client
        .open_one_rtt(response, false, 0, 10)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        client
            .acknowledge_one_rtt(11, response.generation, 0, 10)
            .await
            .unwrap(),
        Err(tls::Error::InvalidInput),
        "an unsent packet number is not valid ACK evidence"
    );
    assert_eq!(
        client
            .acknowledge_one_rtt(10, response.generation + 1, 0, 10)
            .await
            .unwrap(),
        Err(tls::Error::InvalidInput),
        "an unseen receive generation is not valid ACK evidence"
    );
    // The test's sent history contains pn 10, and this authenticated packet
    // supplies generation 0. The actor does not manufacture ACK validity.
    client
        .acknowledge_one_rtt(10, response.generation, 0, 10)
        .await
        .unwrap()
        .unwrap();
    client.initiate_key_update(0, 10).await.unwrap().unwrap();
    assert_eq!(
        (
            client.snapshot().send_generation,
            client.snapshot().receive_generation
        ),
        (1, 0)
    );
    assert!(client.snapshot().key_phase);
    let updated = client
        .seal_one_rtt(phase_packet(11, true, b"updated traffic"))
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        server
            .open_one_rtt(corrupt(&updated), true, 1, 10)
            .await
            .unwrap(),
        Err(tls::Error::Authentication)
    ));
    assert_eq!(
        (
            server.snapshot().send_generation,
            server.snapshot().receive_generation
        ),
        (0, 0)
    );
    let opened = server
        .open_one_rtt(updated, true, 1, 10)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(opened.packet.body(), b"updated traffic");
    assert_eq!((opened.generation, opened.key_updated), (1, true));
    assert_eq!(
        (
            server.snapshot().send_generation,
            server.snapshot().receive_generation
        ),
        (1, 1)
    );
    let response = server
        .seal_one_rtt(phase_packet(21, true, b"updated response"))
        .await
        .unwrap()
        .unwrap();
    let opened = client
        .open_one_rtt(response, true, 1, 10)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((opened.generation, opened.key_updated), (1, true));
    assert_eq!(
        (
            client.snapshot().send_generation,
            client.snapshot().receive_generation
        ),
        (1, 1)
    );
    let delayed = server
        .open_one_rtt(old, false, 30, 10)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((delayed.generation, delayed.key_updated), (0, false));
    assert_eq!(delayed.packet.body(), b"old generation delayed");
    server.maintain_keys(31, 10).await.unwrap().unwrap();
    assert!(matches!(
        server.open_one_rtt(old_copy, false, 31, 10).await.unwrap(),
        Err(tls::Error::Authentication)
    ));
    client
        .acknowledge_one_rtt(11, opened.generation, 1, 10)
        .await
        .unwrap()
        .unwrap();
    client.maintain_keys(30, 10).await.unwrap().unwrap();
    assert_eq!(
        client.initiate_key_update(30, 10).await.unwrap(),
        Err(tls::Error::KeyUpdateNotAllowed)
    );
    client.maintain_keys(31, 10).await.unwrap().unwrap();
    client.initiate_key_update(31, 10).await.unwrap().unwrap();
    assert_eq!(
        (
            client.snapshot().send_generation,
            client.snapshot().receive_generation
        ),
        (2, 1)
    );
    assert!(!client.snapshot().key_phase);
    let phase_wrapped = client
        .seal_one_rtt(packet(12, b"phase bit wrapped"))
        .await
        .unwrap()
        .unwrap();
    let wrapped = server
        .open_one_rtt(phase_wrapped, false, 31, 10)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((wrapped.generation, wrapped.key_updated), (2, true));
    assert_eq!(wrapped.packet.body(), b"phase bit wrapped");
    assert_eq!(
        client.maintain_keys(30, 10).await.unwrap(),
        Err(tls::Error::InvalidInput)
    );
    assert_eq!(
        client.maintain_keys(31, 0).await.unwrap(),
        Err(tls::Error::InvalidInput)
    );
    assert!(matches!(
        client
            .seal_one_rtt(packet(11, b"nonce reuse across update"))
            .await
            .unwrap(),
        Err(tls::Error::PacketNumberReuse)
    ));
    let local = client
        .header_mask(Level::OneRtt, true, [9; 16])
        .await
        .unwrap()
        .unwrap();
    let remote = server
        .header_mask(Level::OneRtt, false, [9; 16])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        local, remote,
        "header protection keys stay stable across updates"
    );
    assert_eq!(local, initial_header_mask);
    client.discard_handshake().await.unwrap().unwrap();
    assert!(!client.snapshot().handshake_keys);
    assert!(client.snapshot().one_rtt_keys);
    assert!(matches!(
        client
            .seal_handshake(packet(8, b"retired handshake"))
            .await
            .unwrap(),
        Err(tls::Error::KeysUnavailable)
    ));
    assert_eq!(
        client
            .header_mask(Level::Handshake, true, [0; 16])
            .await
            .unwrap(),
        Err(tls::Error::KeysUnavailable)
    );
    assert_eq!(
        original.send_generation, 0,
        "snapshots are copied observations"
    );
    assert!(original.handshake_keys);
    assert_eq!(original.peer_parameters(), Some(SERVER_PARAMS));
}

#[test]
fn real_full_handshake_packets_metadata_and_key_updates_allocate_zero() {
    full_handshake_with_fragments(&[900]);
}

#[test]
fn fragmented_full_handshake_packets_and_key_updates_allocate_zero() {
    full_handshake_with_fragments(&[17]);
}

#[test]
#[ignore = "explicit 1-byte composed-role stress; expensive in the debug interpreter"]
fn one_byte_full_handshake_actor_stress_allocates_zero() {
    full_handshake_with_fragments(&[1]);
}

fn full_handshake_with_fragments(fragments: &[usize]) {
    for &fragment in fragments {
        with_two_pairs(|mut c, mut co, mut s, mut so, carrier| {
            let mut cr = [None::<Command<1536>>];
            let mut cp = [None::<Reply<1536, 32>>];
            let mut sr = [None::<Command<1536>>];
            let mut sp = [None::<Reply<1536, 32>>];
            let cr = Mailbox::new(&mut cr).unwrap();
            let cp = Mailbox::new(&mut cp).unwrap();
            let sr = Mailbox::new(&mut sr).unwrap();
            let sp = Mailbox::new(&mut sp).unwrap();
            let (cs, cor) = cr.split().unwrap();
            let (cos, crr) = cp.split().unwrap();
            let (ss, sor) = sr.split().unwrap();
            let (sos, srr) = sp.split().unwrap();
            let mut ce = Exchange::new();
            let mut se = Exchange::new();
            let root = CertificateDer::from(fixture::ROOT_DER);
            let anchors = [trust_anchor_from_der(&root).unwrap()];
            let chain = [fixture::LEAF_DER];
            let signing = fixture::signing_key();
            let mut cb = Buffers::new();
            let mut sb = Buffers::new();
            let (count, waker) = waker();
            let measured = NoAlloc::start();
            let client = BoundedTls::client(
                ClientConfig {
                    server_name: "localhost",
                    trust_anchors: &anchors,
                    now: fixture::now(),
                    certificate_limits: Limits::default(),
                    transport_parameters: CLIENT_PARAMS,
                },
                cb.storage(),
                &mut TestRandom(123),
            )
            .unwrap();
            let server = BoundedTls::server(
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
                let mut client = Client::connect(cs, crr, 9).await.unwrap();
                let mut server = Client::connect(ss, srr, 10).await.unwrap();
                assert!(client.snapshot().handshaking);
                assert!(!client.snapshot().handshake_keys && !client.snapshot().one_rtt_keys);
                assert_eq!(client.snapshot().peer_parameters(), None);
                assert!(matches!(
                    client.take_crypto_flight(0).await.unwrap(),
                    Err(tls::Error::Capacity)
                ));
                assert!(matches!(
                    client.take_crypto_flight(1537).await.unwrap(),
                    Err(tls::Error::Capacity)
                ));
                assert_eq!(
                    client.confirm_handshake().await.unwrap(),
                    Err(tls::Error::KeysUnavailable)
                );
                handshake(&mut client, &mut server, fragment).await;
                packets_and_updates(&mut client, &mut server).await;
                client.retire().await.unwrap();
                assert!(
                    !carrier.is_closed(),
                    "one completed TLS facet must not close its peer"
                );
                let _ = server
                    .seal_one_rtt(packet(22, b"other provider still live"))
                    .await
                    .unwrap()
                    .unwrap();
                server.retire().await.unwrap();
                Ok(())
            };
            drive(
                join2(
                    join2(
                        tls_owner::run_borrowed(&mut c, &mut co, 9, client, cor, cos, &mut ce),
                        tls_owner::run_borrowed(&mut s, &mut so, 10, server, sor, sos, &mut se),
                    ),
                    work,
                ),
                &count,
                &waker,
            )
            .unwrap();
            measured.finish();
            assert!(ce.is_empty() && se.is_empty());
            assert!(cr.is_empty() && cp.is_empty() && sr.is_empty() && sp.is_empty());
        });
    }
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
            assert!(matches!(
                client
                    .seal_one_rtt(packet(0, b"failed handshake"))
                    .await
                    .unwrap(),
                Err(tls::Error::Handshake)
            ));
            client.retire().await.unwrap();
            Ok(())
        };
        drive(
            join2(
                tls_owner::run_borrowed(
                    &mut c,
                    &mut co,
                    11,
                    client,
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
