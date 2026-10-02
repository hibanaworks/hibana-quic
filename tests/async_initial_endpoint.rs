//! Live endpoint Initial integration, with the real bounded TLS ClientHello.
//! This proves packet-protection plumbing/Retry/cancellation, not a completed
//! TLS handshake or independent-peer interoperability. The legacy Driver has
//! its own fixture session; the two actual key facets share one global g::par.
use core::{
    cell::Cell,
    future::{Future, poll_fn},
    pin::{Pin, pin},
    task::{Context, Poll, Waker},
    time::Duration,
};
use hibana::{
    g,
    runtime::{SessionKitStorage, ids::SessionId, program::project},
};
use hibana_quic::{
    bounded_tls::{BoundedTls, ClientConfig, Storage},
    carrier::CarrierStorage,
    crypto::{self, IntegrityBudget},
    driver::{Driver, Roles},
    handshake::CryptoBuffer,
    handshake_endpoint::{
        Config, HandshakeEndpoint, INITIAL_PACKET_BYTES, InitialProtection, Side,
    },
    mailbox::Mailbox,
    packet::{
        self, EncryptionLevel, Frame, FrameIter, Header, LongHeader, LongType, PacketIter,
        ParseLimits,
    },
    protocol::*,
    retry,
    roles::{
        client::KeyClient,
        packet_protection::{self, Command, Exchange, Reply},
        protocol::key_choreography,
    },
    runtime::join2,
    tls_certificate::{CertificateDer, Limits, UnixTime, trust_anchor_from_der},
};
use rand_core::{CryptoRng, RngCore};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::Wake,
};

// Test-only allocator instrumentation, matching the existing no-allocation
// fixture convention. No unsafe code is added to the production core.
struct Counter;
thread_local! { static ALLOCATIONS: Cell<Option<usize>> = const { Cell::new(None) }; }
fn allocation() {
    let _ = ALLOCATIONS.try_with(|n| {
        if let Some(v) = n.get() {
            n.set(Some(v + 1));
        }
    });
}
unsafe impl GlobalAlloc for Counter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        allocation();
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        allocation();
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        allocation();
        unsafe { System.realloc(pointer, layout, size) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Counter = Counter;
struct Measure;
impl Measure {
    fn start() -> Self {
        ALLOCATIONS.with(|n| n.set(Some(0)));
        Self
    }
}
impl Drop for Measure {
    fn drop(&mut self) {
        ALLOCATIONS.with(|n| n.set(None));
    }
}

/// Park the actual caller future after its HP reply and Open publication but
/// before the receiving actor runs the Open. Its owned budget is now in the
/// mailbox; dropping the future must terminally abandon that budget/connection.
async fn cancel_after_open<F: Future>(
    future: F,
    commands: &Mailbox<'_, Command<INITIAL_PACKET_BYTES>, 1>,
    pause_actor: &Cell<bool>,
) {
    let mut future = pin!(future);
    let mut saw_header = false;
    let mut header_taken = false;
    poll_fn(|cx| {
        if saw_header && commands.is_empty() {
            header_taken = true;
        }
        assert!(
            future.as_mut().poll(cx).is_pending(),
            "operation unexpectedly completed before cancellation"
        );
        if !commands.is_empty() {
            if header_taken {
                pause_actor.set(true);
                return Poll::Ready(());
            }
            saw_header = true;
        }
        Poll::Pending
    })
    .await;
    assert_eq!(
        commands.len(),
        1,
        "Open request owns the live integrity budget"
    );
}

struct TestRandom(u64);
impl RngCore for TestRandom {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for part in dest.chunks_mut(8) {
            part.copy_from_slice(&self.next_u64().to_le_bytes()[..part.len()]);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for TestRandom {}
struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
fn drive<F: Future + ?Sized>(
    mut future: Pin<&mut F>,
    wake: &WakeCount,
    waker: &Waker,
) -> F::Output {
    let mut context = Context::from_waker(waker);
    for _ in 0..2048 {
        let before = wake.0.load(Ordering::SeqCst);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(result) => return result,
            Poll::Pending => assert!(
                wake.0.load(Ordering::SeqCst) > before,
                "fixture parked without a registered wake"
            ),
        }
    }
    panic!("fixture did not finish")
}
fn initial_packet(dcid: &[u8], source: &[u8], pn: u64, close: bool) -> [u8; 1200] {
    let mut out = [0; 1200];
    let h = LongHeader {
        kind: LongType::Initial,
        destination_id: b"client01",
        source_id: source,
        token: &[],
        packet_number: pn,
        packet_number_len: 4,
    };
    let mut hlen = packet::encode_long_header(&h, 1180, &mut out).unwrap();
    hlen = packet::encode_long_header(&h, 1200 - hlen, &mut out).unwrap();
    hlen = packet::encode_long_header(&h, 1200 - hlen, &mut out).unwrap();
    let frame = if close {
        Frame::ConnectionClose {
            error_code: 0,
            frame_type: Some(0),
            reason: b"fixture done",
        }
    } else {
        Frame::Ping
    };
    packet::encode_frame(&frame, &mut out[hlen..]).unwrap();
    let mut key = crypto::initial_keys(dcid).unwrap().server;
    let (header, body) = out.split_at_mut(hlen);
    let len = body.len() - 16;
    key.seal(pn, header, body, len).unwrap();
    let sample: &[u8; 16] = out[hlen..hlen + 16].try_into().unwrap();
    let mask = key.header_mask(sample).unwrap();
    out[0] ^= mask[0] & 0x0f;
    for i in 0..4 {
        out[hlen - 4 + i] ^= mask[i + 1];
    }
    out
}
fn client_crypto(wire: &[u8], dcid: &[u8]) -> (u64, [u8; 900], usize) {
    let packet = PacketIter::new(wire, 8, 1)
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    let Header::Long {
        packet_number_offset: pn_offset,
        ..
    } = packet.header
    else {
        panic!("not Initial")
    };
    let mut storage = [0; INITIAL_PACKET_BYTES];
    storage[..wire.len()].copy_from_slice(wire);
    let bytes = &mut storage[..wire.len()];
    let key = crypto::initial_keys(dcid).unwrap().client;
    let mask = key
        .header_mask(bytes[pn_offset + 4..pn_offset + 20].try_into().unwrap())
        .unwrap();
    bytes[0] ^= mask[0] & 0x0f;
    assert_eq!(bytes[0] & 3, 3);
    for i in 0..4 {
        bytes[pn_offset + i] ^= mask[i + 1];
    }
    let pn = u32::from_be_bytes(bytes[pn_offset..pn_offset + 4].try_into().unwrap()) as u64;
    let (header, body) = bytes.split_at_mut(pn_offset + 4);
    let len = key
        .open(pn, header, body, &mut IntegrityBudget::new())
        .unwrap();
    let crypto = FrameIter::new(
        &body[..len],
        EncryptionLevel::Initial,
        ParseLimits::default(),
    )
    .unwrap()
    .find_map(|frame| match frame.unwrap() {
        Frame::Crypto { data, .. } => Some(data),
        _ => None,
    })
    .unwrap();
    assert_eq!(crypto[0], 1, "real TLS ClientHello");
    let mut copied = [0; 900];
    copied[..crypto.len()].copy_from_slice(crypto);
    (pn, copied, crypto.len())
}

#[test]
fn actor_initial_endpoint_preserves_retry_packet_numbers_budget_and_graceful_retirement() {
    run_case(0);
}
#[test]
fn cancelled_pending_initial_operation_retires_endpoint_without_reopening_admission() {
    run_case(1);
}

#[test]
fn cancelled_transport_open_closes_stream_admission_and_actor_clients() {
    run_case(2);
}

fn run_case(cancel: u8) {
    let wake = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = Waker::from(wake.clone());
    let root = CertificateDer::from(include_bytes!("vectors/certificates/root.der").as_slice());
    let anchors = [trust_anchor_from_der(&root).unwrap()];
    let mut rx = [0; 8192];
    let mut tx = [0; 8192];
    let mut cert = [0; 8192];
    let mut parameters = [0; 512];
    let tls = BoundedTls::client(
        ClientConfig {
            server_name: "localhost",
            trust_anchors: &anchors,
            now: UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_000)),
            certificate_limits: Limits::default(),
            transport_parameters: &[15, 8, b'c', b'l', b'i', b'e', b'n', b't', b'0', b'1'],
        },
        Storage {
            rx_message: &mut rx,
            tx_flight: &mut tx,
            peer_certificates: &mut cert,
            peer_parameters: &mut parameters,
        },
        &mut TestRandom(0xd1a2_9183_5f31_0077),
    )
    .unwrap();
    let old_carrier = CarrierStorage::<1, 16, SERVICE_PORTS>::new();
    let mut old_slab = [0; 32768];
    let mut old_storage = SessionKitStorage::uninit();
    let old_kit = old_storage.init();
    let old_sid = SessionId::new(71);
    let old_rv = old_kit
        .rendezvous(&mut old_slab, old_carrier.bind(old_sid).unwrap())
        .unwrap();
    let p0 = service_program::<INGRESS>();
    let p1 = service_program::<PACKET>();
    let p2 = service_program::<APPLICATION>();
    let p3 = service_program::<RECOVERY>();
    let p4 = service_program::<ADAPTER>();
    let p5 = service_program::<TIMER>();
    let driver = Driver::new(
        71,
        Roles {
            ingress: old_rv.enter(old_sid, &p0).unwrap(),
            packet: old_rv.enter(old_sid, &p1).unwrap(),
            application: old_rv.enter(old_sid, &p2).unwrap(),
            recovery: old_rv.enter(old_sid, &p3).unwrap(),
            adapter: old_rv.enter(old_sid, &p4).unwrap(),
            timer: old_rv.enter(old_sid, &p5).unwrap(),
        },
    );
    assert!(!driver.is_key_installed(hibana_quic::tls::Level::Initial));
    let carrier = CarrierStorage::<1, 16, 32>::new();
    let mut slab = [0; 32768];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init();
    let sid = SessionId::new(72);
    let rv = kit
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    let global = g::par(key_choreography::<16, 17>(), key_choreography::<18, 19>());
    let p16 = project::<16, _>(&global);
    let p17 = project::<17, _>(&global);
    let p18 = project::<18, _>(&global);
    let p19 = project::<19, _>(&global);
    let mut e16 = rv.enter(sid, &p16).unwrap();
    let mut e17 = rv.enter(sid, &p17).unwrap();
    let mut e18 = rv.enter(sid, &p18).unwrap();
    let mut e19 = rv.enter(sid, &p19).unwrap();
    let mut rxc: [Option<Command<INITIAL_PACKET_BYTES>>; 1] = [None];
    let mut rxr: [Option<Reply<INITIAL_PACKET_BYTES>>; 1] = [None];
    let mut txc: [Option<Command<INITIAL_PACKET_BYTES>>; 1] = [None];
    let mut txr: [Option<Reply<INITIAL_PACKET_BYTES>>; 1] = [None];
    let rxc = Mailbox::new(&mut rxc).unwrap();
    let rxr = Mailbox::new(&mut rxr).unwrap();
    let txc = Mailbox::new(&mut txc).unwrap();
    let txr = Mailbox::new(&mut txr).unwrap();
    let (rx_send, rx_recv) = rxc.split().unwrap();
    let (rx_reply_send, rx_reply_recv) = rxr.split().unwrap();
    let (tx_send, tx_recv) = txc.split().unwrap();
    let (tx_reply_send, tx_reply_recv) = txr.split().unwrap();
    let mut rx_exchange = Exchange::new();
    let mut tx_exchange = Exchange::new();
    let keys = crypto::initial_keys(b"original").unwrap();
    let mut data = [[0; 2048]; 3];
    let mut maps = [[0; 256]; 3];
    let [d0, d1, d2] = &mut data;
    let [m0, m1, m2] = &mut maps;
    let buffers = [
        CryptoBuffer::new(d0, m0).unwrap(),
        CryptoBuffer::new(d1, m1).unwrap(),
        CryptoBuffer::new(d2, m2).unwrap(),
    ];
    let pause_actor = Cell::new(false);
    let work = async {
        let receive = KeyClient::connect(rx_send, rx_reply_recv, 71)
            .await
            .unwrap();
        let transmit = KeyClient::connect(tx_send, tx_reply_recv, 71)
            .await
            .unwrap();
        let protection = InitialProtection::new(receive, transmit).unwrap();
        let mut endpoint = HandshakeEndpoint::new(
            Config {
                side: Side::Client,
                local_id: b"client01",
                original_destination_id: b"original",
                generation: 71,
            },
            tls,
            driver,
            buffers,
            protection,
        )
        .unwrap();
        let mut out = [0; 1536];
        let mut scratch = [0; 1536];
        let first = endpoint.transmit(&mut out).await.unwrap().unwrap();
        let (first_pn, first_crypto, first_crypto_len) =
            client_crypto(&out[..first.len], b"original");
        let mut forged = initial_packet(b"original", b"server01", 4, false);
        forged[1199] ^= 1;
        for failed in 1..=2 {
            assert_eq!(
                endpoint
                    .receive(&forged, &mut scratch)
                    .await
                    .unwrap()
                    .discarded,
                1
            );
            assert_eq!(endpoint.tls().failed_authentications(), failed);
        }
        let mut retry_packet = [0; 512];
        let len = retry::encode_retry(
            b"original",
            b"client01",
            b"retrykey",
            b"opaque token",
            3,
            &mut retry_packet,
            &mut scratch,
        )
        .unwrap();
        endpoint
            .receive(&retry_packet[..len], &mut scratch)
            .await
            .unwrap();
        assert!(
            endpoint.retry_is_pending(),
            "Retry must wait for old-key adapter callback"
        );
        endpoint.adapter_result(first, true, 0).await.unwrap();
        assert!(!endpoint.retry_is_pending());
        assert_eq!(endpoint.tls().failed_authentications(), 2);
        let resent = endpoint.transmit(&mut out).await.unwrap().unwrap();
        let (next_pn, next_crypto, next_crypto_len) =
            client_crypto(&out[..resent.len], b"retrykey");
        assert!(next_pn > first_pn);
        assert_eq!(first_crypto, next_crypto);
        assert_eq!(first_crypto_len, next_crypto_len);
        endpoint.adapter_result(resent, true, 1).await.unwrap();
        let incoming = initial_packet(b"retrykey", b"retrykey", 5, false);
        assert_eq!(
            endpoint
                .receive(&incoming, &mut scratch)
                .await
                .unwrap()
                .authenticated,
            1
        );
        assert_eq!(endpoint.tls().failed_authentications(), 2);
        if cancel == 1 {
            cancel_after_open(
                endpoint.receive(&incoming, &mut scratch),
                &rxc,
                &pause_actor,
            )
            .await;
            assert!(endpoint.is_retired());
            assert_eq!(endpoint.tls().failed_authentications(), 2);
            assert!(matches!(
                endpoint.transmit(&mut out).await,
                Err(hibana_quic::handshake_endpoint::Error::Retired)
            ));
            return Err("cancelled as requested");
        }
        if cancel == 2 {
            use hibana_quic::{streams, transport_endpoint::TransportEndpoint};
            let mut slots = [streams::StreamSlot::<64>::EMPTY];
            let mut chunks = [streams::SendChunk::<64>::EMPTY];
            let mut references = [streams::PacketReference::EMPTY];
            let mut transport = TransportEndpoint::<_, 64, 64, 16, 64, _>::new(
                endpoint,
                streams::Limits::ZERO,
                &mut slots,
                &mut chunks,
                &mut references,
                2,
            )
            .unwrap();
            cancel_after_open(
                transport.receive(&incoming, &mut scratch),
                &rxc,
                &pause_actor,
            )
            .await;
            assert!(transport.is_retired());
            assert_eq!(transport.streams().lookup(0), Err(streams::Error::Closed));
            assert!(transport.open(true).is_err());
            return Err("cancelled as requested");
        }
        let closing = initial_packet(b"retrykey", b"retrykey", 6, true);
        assert_eq!(
            endpoint
                .receive(&closing, &mut scratch)
                .await
                .unwrap()
                .authenticated,
            1
        );
        assert!(endpoint.keys_discarded(hibana_quic::tls::Level::Initial));
        Ok(())
    };
    let actors = async {
        let mut roles = pin!(join2(
            packet_protection::run_borrowed(
                &mut e16,
                &mut e17,
                71,
                keys.server,
                rx_recv,
                rx_reply_send,
                &mut rx_exchange,
            ),
            packet_protection::run_borrowed(
                &mut e18,
                &mut e19,
                71,
                keys.client,
                tx_recv,
                tx_reply_send,
                &mut tx_exchange,
            ),
        ));
        poll_fn(|cx| {
            if pause_actor.get() {
                Poll::Pending
            } else {
                roles.as_mut().poll(cx)
            }
        })
        .await
        .map_err(|_| "actor closed")
    };
    let measured = Measure::start();
    let result = {
        let mut execution = pin!(join2(actors, work));
        drive(execution.as_mut(), &wake, &waker)
    };
    let allocations = ALLOCATIONS.with(|n| n.get().unwrap());
    drop(measured);
    assert_eq!(
        allocations, 0,
        "actual Initial I/O, Retry, retirement and cancellation allocate zero"
    );
    if cancel != 0 {
        assert_eq!(result, Err("cancelled as requested"));
    } else {
        assert_eq!(result, Ok(()));
    }
    assert!(rx_exchange.is_empty());
    assert!(tx_exchange.is_empty());
}
