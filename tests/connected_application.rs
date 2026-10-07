//! One projected connection per peer, from real TLS through encrypted GETs,
//! response FIN, handshake confirmation and closing/draining retirement.
//! The deterministic executor advances time only after all real wakes settle.

#[allow(dead_code)]
#[path = "support/connected_tls_fixture.rs"]
mod fixture;
#[path = "support/loss_certificate.rs"]
mod loss_certificate;

use core::{
    cell::{Cell, RefCell},
    future::{Future, poll_fn},
    pin::Pin,
    task::{Context, Poll, Waker},
};
use hibana::runtime::{SessionKitStorage, ids::SessionId};
use hibana_quic::{
    bounded_tls::{BoundedTls, ClientConfig, ServerConfig, State, key_source::ReceivePacketKey},
    carrier::CarrierStorage,
    connection::publication_gate::PublicationGate,
    connection::{
        self, Clock, Config, DatagramRx, DatagramTx, IoError, Side,
        application::{self, BodyReader, ClientRequests, ServerHandler, StreamSink},
        recovery::Recovery,
        tls::Transcript,
    },
    crypto::{
        IntegrityBudget,
        directional::{ApplicationKeyScope, ApplicationReadKeys},
    },
    handshake::CryptoBuffer,
    packet::{
        self, EncryptionLevel, Frame, FrameIter, Header, LongType, PacketIter, ParseLimits,
        encode_varint,
    },
    streams::{Limits, PacketReference, SendChunk, StreamSlot},
    tls::Provider,
    tls_certificate::{CertificateDer, Limits as CertificateLimits, trust_anchor_from_der},
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::task::Wake;

const DATAGRAM: usize = 1536;
const PARAMS: usize = 512;
const RECEIVE_WINDOW: usize = 4096;
const CHUNK: usize = 256;
const STREAMS: usize = 4;
const ORIGINAL: &[u8] = b"original";
const CLIENT_ID: &[u8] = b"client01";
const SERVER_ID: &[u8] = b"server01";
const REQUESTS: [&[u8]; STREAMS] = [
    b"GET /alpha\r\n",
    b"GET /beta\r\n",
    b"GET /gamma\r\n",
    b"GET /empty\r\n",
];
const BODY_SIZES: [usize; STREAMS] = [1537, 2051, 3073, 0];

fn limits(side: Side) -> Limits {
    Limits {
        max_data: (STREAMS * RECEIVE_WINDOW) as u64,
        stream_data_bidi_local: RECEIVE_WINDOW as u64,
        stream_data_bidi_remote: RECEIVE_WINDOW as u64,
        stream_data_uni: 0,
        max_streams_bidi: if side == Side::Server {
            STREAMS as u64
        } else {
            0
        },
        max_streams_uni: 0,
    }
}

fn parameters(id: &[u8], original: Option<&[u8]>) -> Vec<u8> {
    parameters_with_limits(
        id,
        original,
        limits(if original.is_some() {
            Side::Server
        } else {
            Side::Client
        }),
    )
}

fn parameters_with_limits(id: &[u8], original: Option<&[u8]>, limits: Limits) -> Vec<u8> {
    fn field(out: &mut Vec<u8>, kind: u64, value: &[u8]) {
        let mut encoded = [0; 8];
        let n = encode_varint(kind, &mut encoded).unwrap();
        out.extend_from_slice(&encoded[..n]);
        let n = encode_varint(value.len() as u64, &mut encoded).unwrap();
        out.extend_from_slice(&encoded[..n]);
        out.extend_from_slice(value);
    }
    let mut out = Vec::new();
    field(&mut out, 15, id);
    if let Some(original) = original {
        field(&mut out, 0, original);
    }
    for (kind, value) in [
        (3, DATAGRAM as u64),
        (4, limits.max_data),
        (5, limits.stream_data_bidi_local),
        (6, limits.stream_data_bidi_remote),
        (8, limits.max_streams_bidi),
    ] {
        let mut encoded = [0; 8];
        let n = encode_varint(value, &mut encoded).unwrap();
        field(&mut out, kind, &encoded[..n]);
    }
    out
}

// A separate deterministic TLS exchange derives observation-only read keys.
// It cannot mint authority for either connection under test. The actual test
// connections still perform their own TLS, certificate and AEAD verification.
// This lets the loss cases name encrypted frames only after successful AEAD.
struct Inspector<'scope> {
    handshake: ReceivePacketKey<'scope>,
    application: ApplicationReadKeys<'scope>,
    integrity: IntegrityBudget,
    largest_handshake: Option<u64>,
    largest_application: Option<u64>,
    handshake_acks: usize,
    handshake_done: usize,
}
fn inspection_keys<'scope>(
    scope: &'scope mut ApplicationKeyScope,
    client_config: ClientConfig<'_>,
    server_config: ServerConfig<'_>,
) -> Inspector<'scope> {
    let mut client_buffers = fixture::Buffers::new();
    let mut server_buffers = fixture::Buffers::new();
    let client = BoundedTls::client(
        client_config,
        client_buffers.storage(),
        &mut fixture::TestRandom(349),
    )
    .unwrap()
    .into_key_source(scope.claim().unwrap())
    .unwrap();
    let server = BoundedTls::server(
        server_config,
        server_buffers.storage(),
        &mut fixture::TestRandom(701),
    )
    .unwrap();
    use core::pin::pin;
    use hibana_quic::bounded_tls::{
        key_source::KeySource, locals as direct, protocol as tls_graph,
    };
    let client = RefCell::new(client);
    let server = RefCell::new(server);
    struct ServerInput<'a, 'scope, 'cfg, 'buf> {
        client: &'a RefCell<KeySource<'scope, 'cfg, 'buf>>,
        finished: usize,
    }
    impl direct::MessageInput for ServerInput<'_, '_, '_, '_> {
        async fn read_message(
            &mut self,
            level: hibana_quic::tls::Level,
            out: &mut [u8],
        ) -> Result<usize, direct::Error> {
            let output = poll_fn(|_| match self.client.borrow_mut().transmit(out) {
                Ok(Some(output)) => Poll::Ready(Ok(output)),
                Ok(None) => Poll::Pending,
                Err(e) => Poll::Ready(Err(direct::Error::Input(e))),
            })
            .await?;
            assert_eq!(output.level, level);
            if level == hibana_quic::tls::Level::Handshake {
                assert_eq!(&out[..4], &[20, 0, 0, 32]);
                assert_eq!(output.len, 36);
                self.finished += 1;
            }
            Ok(output.len)
        }
    }
    struct ClientInput<'a, 'cfg, 'buf> {
        server: &'a RefCell<BoundedTls<'cfg, 'buf>>,
        bytes: [u8; 8192],
        offset: usize,
        end: usize,
        level: hibana_quic::tls::Level,
    }
    impl direct::MessageInput for ClientInput<'_, '_, '_> {
        async fn read_message(
            &mut self,
            level: hibana_quic::tls::Level,
            out: &mut [u8],
        ) -> Result<usize, direct::Error> {
            if self.offset == self.end {
                let output =
                    poll_fn(
                        |_| match self.server.borrow_mut().transmit(&mut self.bytes) {
                            Ok(Some(output)) => Poll::Ready(Ok(output)),
                            Ok(None) => Poll::Pending,
                            Err(e) => Poll::Ready(Err(direct::Error::Input(e))),
                        },
                    )
                    .await?;
                self.offset = 0;
                self.end = output.len;
                self.level = output.level;
            }
            assert_eq!(self.level, level);
            let bytes = &self.bytes[self.offset..self.end];
            assert!(bytes.len() >= 4);
            let n =
                4 + ((bytes[1] as usize) << 16) + ((bytes[2] as usize) << 8) + bytes[3] as usize;
            assert!(n <= bytes.len() && n <= out.len());
            out[..n].copy_from_slice(&bytes[..n]);
            self.offset += n;
            Ok(n)
        }
    }
    let mut ci = ClientInput {
        server: &server,
        bytes: [0; 8192],
        offset: 0,
        end: 0,
        level: hibana_quic::tls::Level::Initial,
    };
    let mut si = ServerInput {
        client: &client,
        finished: 0,
    };
    let mut cb = [0; 8192];
    let mut sb = [0; 8192];
    let cm = direct::MessageSlot::new(&mut cb);
    let sm = direct::MessageSlot::new(&mut sb);
    let cc = CarrierStorage::<1, 16, 4>::new();
    let sc = CarrierStorage::<1, 16, 4>::new();
    let mut cslab = vec![0; 65536];
    let mut sslab = vec![0; 65536];
    let mut ck = SessionKitStorage::uninit();
    let mut sk = SessionKitStorage::uninit();
    let ck = ck.init();
    let sk = sk.init();
    let cid = SessionId::new(4891);
    let sid = SessionId::new(4892);
    let cr = ck.rendezvous(&mut cslab, cc.bind(cid).unwrap()).unwrap();
    let sr = sk.rendezvous(&mut sslab, sc.bind(sid).unwrap()).unwrap();
    let cp = tls_graph::client_programs();
    let sp = tls_graph::server_programs();
    let mut cin = cr.enter(cid, &cp.input).unwrap();
    let mut cv = cr.enter(cid, &cp.verify).unwrap();
    let mut sin = sr.enter(sid, &sp.input).unwrap();
    let mut sv = sr.enter(sid, &sp.verify).unwrap();
    {
        let mut co = pin!(KeySource::client_transcript_role(&mut cv, &client, &cm));
        let mut ci = pin!(direct::client_input(&mut cin, &cm, &mut ci));
        let mut so = pin!(direct::server_owner(&mut sv, &server, &sm));
        let mut si = pin!(direct::server_input(&mut sin, &sm, &mut si));
        let tasks = hibana_quic::runtime::TaskSet::new([
            co.as_mut(),
            ci.as_mut(),
            so.as_mut(),
            si.as_mut(),
        ]);
        let mut tasks = pin!(tasks);
        let mut context = Context::from_waker(Waker::noop());
        let mut complete = false;
        for _ in 0..4096 {
            if let Poll::Ready(result) = tasks.as_mut().poll(&mut context) {
                result.unwrap();
                complete = true;
                break;
            }
        }
        assert!(
            complete,
            "direct projected observation-only TLS handshake stalled"
        );
    }
    assert_eq!(si.finished, 1);
    assert_eq!(client.borrow().state(), State::Connected);
    assert_eq!(server.borrow().state(), State::Connected);
    let handshake = client
        .borrow_mut()
        .take_handshake_keys()
        .unwrap()
        .install()
        .0;
    let application = client
        .borrow_mut()
        .take_application_keys()
        .unwrap()
        .install()
        .unwrap()
        .0;
    let integrity = client.borrow_mut().take_integrity_budget().unwrap();
    Inspector {
        handshake,
        application,
        integrity,
        largest_handshake: None,
        largest_application: None,
        handshake_acks: 0,
        handshake_done: 0,
    }
}

#[derive(Default)]
struct Classification {
    handshake_ack: bool,
    application_ack: bool,
    handshake_done: bool,
}
fn classify_frames(bytes: &[u8], level: EncryptionLevel) -> Classification {
    let mut result = Classification::default();
    let mut only_ack_or_padding = true;
    for frame in FrameIter::new(bytes, level, ParseLimits::default()).unwrap() {
        match frame.unwrap() {
            Frame::Ack { .. } => {
                result.handshake_ack = level == EncryptionLevel::Handshake;
                result.application_ack = level == EncryptionLevel::OneRtt;
            }
            Frame::Padding { .. } => {}
            Frame::HandshakeDone => {
                result.handshake_done = true;
                only_ack_or_padding = false;
            }
            _ => only_ack_or_padding = false,
        }
    }
    result.handshake_ack &= only_ack_or_padding;
    result.application_ack &= only_ack_or_padding;
    result
}
impl Inspector<'_> {
    fn inspect(&mut self, bytes: &[u8], now: u64) -> Classification {
        let mut result = Classification::default();
        for packet in PacketIter::new(bytes, CLIENT_ID.len(), 8).unwrap() {
            let packet = packet.unwrap();
            let current = match packet.header {
                Header::Long {
                    kind: LongType::Handshake,
                    destination_id,
                    packet_number_offset,
                    ..
                } => {
                    assert_eq!(destination_id, CLIENT_ID);
                    let mut storage = [0; DATAGRAM];
                    storage[..packet.bytes.len()].copy_from_slice(packet.bytes);
                    let bytes = &mut storage[..packet.bytes.len()];
                    let pn_len = self
                        .handshake
                        .unprotect_header(bytes, packet_number_offset)
                        .unwrap();
                    let (truncated, _) = packet::decode_truncated_packet_number(
                        bytes[0],
                        &bytes[packet_number_offset..],
                    )
                    .unwrap();
                    let pn = packet::restore_packet_number(
                        truncated,
                        pn_len as u8,
                        self.largest_handshake,
                    )
                    .unwrap();
                    let (header, payload) = bytes.split_at_mut(packet_number_offset + pn_len);
                    let len = self
                        .handshake
                        .open(pn, header, payload, &mut self.integrity)
                        .expect(
                            "deterministic replay must authenticate the actual Handshake packet",
                        );
                    self.largest_handshake =
                        Some(self.largest_handshake.map_or(pn, |old| old.max(pn)));
                    classify_frames(&payload[..len], EncryptionLevel::Handshake)
                }
                Header::Short { .. } => {
                    let opened = connection::application_wire::open::<DATAGRAM>(
                        &mut self.application,
                        &mut self.integrity,
                        packet.bytes,
                        CLIENT_ID,
                        self.largest_application,
                        now,
                        30_000,
                    )
                    .expect("deterministic replay must authenticate the actual application packet");
                    let pn = opened.packet_number();
                    self.largest_application =
                        Some(self.largest_application.map_or(pn, |old| old.max(pn)));
                    classify_frames(opened.plaintext(), EncryptionLevel::OneRtt)
                }
                _ => Classification::default(),
            };
            result.handshake_ack |= current.handshake_ack;
            result.application_ack |= current.application_ack;
            result.handshake_done |= current.handshake_done;
        }
        self.handshake_acks += usize::from(result.handshake_ack);
        self.handshake_done += usize::from(result.handshake_done);
        result
    }
}

struct Alarm {
    deadline: u64,
    waker: Waker,
}
struct TestClock {
    limit: u64,
    now: Cell<u64>,
    alarms: RefCell<[Option<Alarm>; 8]>,
}
impl TestClock {
    fn new() -> Self {
        Self {
            limit: 30_000_000,
            now: Cell::new(0),
            alarms: RefCell::new(core::array::from_fn(|_| None)),
        }
    }
    fn advance(&self) {
        let deadline = self
            .alarms
            .borrow()
            .iter()
            .flatten()
            .map(|a| a.deadline)
            .min()
            .expect("connection parked without a wake or a timer");
        assert!(
            deadline > self.now.get(),
            "expired timer did not become ready"
        );
        assert!(
            deadline <= self.limit,
            "connection exceeded its explicit simulated-time budget"
        );
        self.now.set(deadline);
        let wakes: Vec<_> = self
            .alarms
            .borrow()
            .iter()
            .flatten()
            .filter(|a| a.deadline <= deadline)
            .map(|a| a.waker.clone())
            .collect();
        for wake in wakes {
            wake.wake();
        }
    }
}
struct WaitUntil<'a> {
    clock: &'a TestClock,
    deadline: u64,
    slot: Option<usize>,
}
impl Future for WaitUntil<'_> {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.clock.now.get() >= self.deadline {
            return Poll::Ready(());
        }
        let slot = match self.slot {
            Some(slot) => slot,
            None => {
                let slot = self
                    .clock
                    .alarms
                    .borrow()
                    .iter()
                    .position(Option::is_none)
                    .expect("too many outstanding real clock waits");
                self.slot = Some(slot);
                slot
            }
        };
        let next = Alarm {
            deadline: self.deadline,
            waker: cx.waker().clone(),
        };
        let previous = self.clock.alarms.borrow_mut()[slot].replace(next);
        drop(previous);
        Poll::Pending
    }
}
impl Drop for WaitUntil<'_> {
    fn drop(&mut self) {
        if let Some(slot) = self.slot {
            let previous = self.clock.alarms.borrow_mut()[slot].take();
            drop(previous);
        }
    }
}
impl Clock for TestClock {
    fn now(&self) -> u64 {
        self.now.get()
    }
    fn wait_until(&self, deadline: u64) -> impl Future<Output = ()> {
        WaitUntil {
            clock: self,
            deadline,
            slot: None,
        }
    }
}
struct Ready(AtomicBool);
impl Wake for Ready {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
}
fn execute<F: Future>(clock: &TestClock, future: F, trace: impl Fn()) -> F::Output {
    let ready = Arc::new(Ready(AtomicBool::new(true)));
    let waker = Waker::from(ready.clone());
    let mut cx = Context::from_waker(&waker);
    let mut future = core::pin::pin!(future);
    for _ in 0..200_000 {
        if !ready.0.swap(false, Ordering::SeqCst) {
            if clock.alarms.borrow().iter().all(Option::is_none)
                || clock
                    .alarms
                    .borrow()
                    .iter()
                    .flatten()
                    .map(|alarm| alarm.deadline)
                    .min()
                    .is_some_and(|deadline| deadline > clock.limit)
            {
                trace();
            }
            clock.advance();
        }
        if let Poll::Ready(result) = future.as_mut().poll(&mut cx) {
            return result;
        }
    }
    panic!("connection exceeded the bounded executor poll budget");
}

struct Datagram {
    bytes: [u8; DATAGRAM],
    len: usize,
    ready_at: u64,
    ecn: Option<hibana_quic::ecn::Codepoint>,
}
struct Path {
    queued: RefCell<std::collections::VecDeque<Datagram>>,
    capacity: usize,
    reader: RefCell<Option<Waker>>,
    writer: RefCell<Option<Waker>>,
    accepted: Cell<usize>,
    delivered: Cell<usize>,
    dropped: Cell<usize>,
}
impl Path {
    fn new(capacity: usize) -> Self {
        Self {
            queued: RefCell::new(std::collections::VecDeque::new()),
            capacity,
            reader: RefCell::new(None),
            writer: RefCell::new(None),
            accepted: Cell::new(0),
            delivered: Cell::new(0),
            dropped: Cell::new(0),
        }
    }
}
struct Rx<'a>(&'a Path, &'a TestClock);
impl DatagramRx for Rx<'_> {
    async fn receive(
        &mut self,
        output: &mut [u8],
    ) -> Result<hibana_quic::connection::ReceivedDatagram, IoError> {
        let ready_at = poll_fn(|cx| {
            if let Some(packet) = self.0.queued.borrow().front() {
                Poll::Ready(packet.ready_at)
            } else {
                let previous = self.0.reader.borrow_mut().replace(cx.waker().clone());
                drop(previous);
                Poll::Pending
            }
        })
        .await;
        self.1.wait_until(ready_at).await;
        let packet = self
            .0
            .queued
            .borrow_mut()
            .pop_front()
            .expect("single RX owns queued packet");
        assert!(packet.len <= output.len());
        output[..packet.len].copy_from_slice(&packet.bytes[..packet.len]);
        self.0.delivered.set(self.0.delivered.get() + 1);
        if let Some(wake) = self.0.writer.borrow_mut().take() {
            wake.wake();
        }
        Ok(hibana_quic::connection::ReceivedDatagram {
            path: None,
            len: packet.len,
            ecn: packet.ecn,
        })
    }
}
#[derive(Clone, Copy)]
enum Loss {
    None,
    MissingEcnMetadata,
    BleachedEcn,
    ServerApplicationAcks,
    ServerApplicationAcksPersistentServer,
    FirstServerOneRtt,
    ServerPacketBurst { first: usize, count: usize },
    ClientPacketBurst { first: usize, count: usize },
    DuplexPacketMask { client: u64, server: u64 },
    ServerHandshakeAck,
    HandshakeDone,
}
struct Tx<'a, 'scope> {
    path: &'a Path,
    clock: &'a TestClock,
    loss: Loss,
    inspector: Option<&'a mut Inspector<'scope>>,
}
impl DatagramTx for Tx<'_, '_> {
    async fn send(
        &mut self,
        bytes: &[u8],
        ecn: hibana_quic::ecn::Codepoint,
    ) -> Result<u64, IoError> {
        poll_fn(|cx| {
            if self.path.queued.borrow().len() == self.path.capacity {
                let next = cx.waker().clone();
                let previous = self.path.writer.borrow_mut().replace(next);
                drop(previous);
                return Poll::Pending;
            }
            assert!(bytes.len() <= DATAGRAM);
            self.path.accepted.set(self.path.accepted.get() + 1);
            let classification = self
                .inspector
                .as_mut()
                .map(|inspector| inspector.inspect(bytes, self.clock.now()));
            // The first-1RTT smoke selects its target only by public header.
            // The two frame-specific cases below require authenticated parsing.
            let selected = match self.loss {
                Loss::None | Loss::MissingEcnMetadata | Loss::BleachedEcn => false,
                Loss::DuplexPacketMask { client, server } => {
                    let mask = if self.inspector.is_some() {
                        server
                    } else {
                        client
                    };
                    let ordinal = self.path.accepted.get();
                    bytes[0] & 0x80 != 0 && ordinal <= 64 && (mask & (1 << (ordinal - 1))) != 0
                }
                Loss::ServerPacketBurst { first, count }
                | Loss::ClientPacketBurst { first, count } => {
                    let ordinal = self.path.accepted.get();
                    (first..first + count).contains(&ordinal)
                }
                Loss::ServerApplicationAcks | Loss::ServerApplicationAcksPersistentServer => {
                    classification.as_ref().is_some_and(|p| p.application_ack)
                }
                Loss::FirstServerOneRtt => bytes[0] & 0x80 == 0,
                Loss::ServerHandshakeAck => classification
                    .as_ref()
                    .is_some_and(|packet| packet.handshake_ack),
                Loss::HandshakeDone => classification
                    .as_ref()
                    .is_some_and(|packet| packet.handshake_done),
            };
            if selected
                && (matches!(
                    self.loss,
                    Loss::ServerApplicationAcks
                        | Loss::ServerApplicationAcksPersistentServer
                        | Loss::ServerPacketBurst { .. }
                        | Loss::ClientPacketBurst { .. }
                        | Loss::DuplexPacketMask { .. }
                ) || self.path.dropped.get() == 0)
            {
                self.path.dropped.set(self.path.dropped.get() + 1);
                return Poll::Ready(Ok(self.clock.now()));
            }
            let mut datagram = Datagram {
                bytes: [0; DATAGRAM],
                len: bytes.len(),
                ecn: match self.loss {
                    Loss::MissingEcnMetadata => None,
                    Loss::BleachedEcn => Some(hibana_quic::ecn::Codepoint::NotEct),
                    _ => Some(ecn),
                },
                ready_at: self.clock.now()
                    + if matches!(self.loss, Loss::DuplexPacketMask { .. }) {
                        15_000
                    } else {
                        0
                    },
            };
            datagram.bytes[..bytes.len()].copy_from_slice(bytes);
            self.path.queued.borrow_mut().push_back(datagram);
            let wake = self.path.reader.borrow_mut().take();
            if let Some(wake) = wake {
                wake.wake();
            }
            Poll::Ready(Ok(self.clock.now()))
        })
        .await
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FileFailure {
    None,
    Request,
    Open,
    Read,
    Write,
    Finish,
}

struct Requests {
    failure: FileFailure,
    count: usize,
    next: usize,
    started: Vec<u64>,
}
impl ClientRequests for Requests {
    async fn next(&mut self, output: &mut [u8]) -> Result<Option<usize>, ()> {
        if self.failure == FileFailure::Request {
            return Err(());
        }
        if self.next == self.count {
            return Ok(None);
        }
        let request = REQUESTS[self.next];
        output[..request.len()].copy_from_slice(request);
        Ok(Some(request.len()))
    }
    fn started(&mut self, stream_id: u64) -> Result<(), ()> {
        assert_eq!(stream_id, (self.next * 4) as u64);
        self.started.push(stream_id);
        self.next += 1;
        Ok(())
    }
}
fn body_byte(request: usize, offset: usize) -> u8 {
    ((request * 53 + offset * 17 + 11) % 251) as u8
}
struct Body {
    failure: FileFailure,
    request: usize,
    offset: usize,
}
impl BodyReader for Body {
    async fn read(&mut self, output: &mut [u8]) -> Result<usize, ()> {
        if self.failure == FileFailure::Read {
            return Err(());
        }
        let len = output.len().min(BODY_SIZES[self.request] - self.offset);
        for (i, byte) in output[..len].iter_mut().enumerate() {
            *byte = body_byte(self.request, self.offset + i);
        }
        self.offset += len;
        Ok(len)
    }
}
struct Handler {
    limit: Option<core::num::NonZeroUsize>,
    failure: FileFailure,
    opened: Vec<(u64, usize)>,
}
impl ServerHandler for Handler {
    type Body = Body;
    fn request_limit(&self) -> Option<core::num::NonZeroUsize> {
        self.limit
    }
    async fn open(&mut self, stream_id: u64, request: &[u8]) -> Result<Body, ()> {
        if self.failure == FileFailure::Open {
            return Err(());
        }
        let request = REQUESTS
            .iter()
            .position(|expected| *expected == request)
            .expect("handler must see the actual, complete authenticated GET");
        assert!(
            !self.opened.iter().any(|(id, _)| *id == stream_id),
            "request delivered twice"
        );
        self.opened.push((stream_id, request));
        Ok(Body {
            request,
            offset: 0,
            failure: self.failure,
        })
    }
}
struct Sink {
    failure: FileFailure,
    bytes: [Vec<u8>; STREAMS],
    finished: [usize; STREAMS],
}
impl StreamSink for Sink {
    async fn write(&mut self, stream_id: u64, bytes: &[u8]) -> Result<(), ()> {
        if self.failure == FileFailure::Write {
            return Err(());
        }
        assert_eq!(stream_id % 4, 0);
        let stream = (stream_id / 4) as usize;
        assert_eq!(self.finished[stream], 0, "body bytes arrived after FIN");
        self.bytes[stream].extend_from_slice(bytes);
        assert!(self.bytes[stream].len() <= BODY_SIZES[stream]);
        Ok(())
    }
    async fn finish(&mut self, stream_id: u64) -> Result<(), ()> {
        if self.failure == FileFailure::Finish {
            return Err(());
        }
        let stream = (stream_id / 4) as usize;
        self.finished[stream] += 1;
        assert_eq!(self.finished[stream], 1, "FIN delivered twice");
        assert_eq!(self.bytes[stream].len(), BODY_SIZES[stream]);
        Ok(())
    }
}

// Endpoints are created once from this one combined global and remain alive
// until both peers have completed their close/drain continuation.
macro_rules! roles {
    ($rv:expr, $sid:expr, $program:expr) => {
        application::Roles {
            ecn_owner: $rv.enter($sid, &$program.ecn_owner).unwrap(),
            handshake: connection::Roles {
                rx: $rv.enter($sid, &$program.handshake.rx).unwrap(),
                tls_rx: $rv.enter($sid, &$program.handshake.tls_rx).unwrap(),
                tx: $rv.enter($sid, &$program.handshake.tx).unwrap(),
                tls_tx: $rv.enter($sid, &$program.handshake.tls_tx).unwrap(),
                udp: $rv.enter($sid, &$program.handshake.udp).unwrap(),
                timer: $rv.enter($sid, &$program.handshake.timer).unwrap(),
                timer_tx: $rv.enter($sid, &$program.handshake.timer_tx).unwrap(),
                tx_wire: $rv.enter($sid, &$program.handshake.tx_wire).unwrap(),
                initial_event: $rv.enter($sid, &$program.handshake.initial_event).unwrap(),
                initial_owner: $rv.enter($sid, &$program.handshake.initial_owner).unwrap(),
                timer_stop: $rv.enter($sid, &$program.handshake.timer_stop).unwrap(),
                receive_stop: $rv.enter($sid, &$program.handshake.receive_stop).unwrap(),
            },
            source: $rv.enter($sid, &$program.source).unwrap(),
            source_join: $rv.enter($sid, &$program.source_join).unwrap(),
            ingress: $rv.enter($sid, &$program.ingress).unwrap(),
            receive: $rv.enter($sid, &$program.receive).unwrap(),
            sink: $rv.enter($sid, &$program.sink).unwrap(),
            rx_keys: $rv.enter($sid, &$program.rx_keys).unwrap(),
            tx_keys: $rv.enter($sid, &$program.tx_keys).unwrap(),
            clock: $rv.enter($sid, &$program.clock).unwrap(),
            tx_clock: $rv.enter($sid, &$program.tx_clock).unwrap(),
            transmit: $rv.enter($sid, &$program.transmit).unwrap(),
            adapter: $rv.enter($sid, &$program.adapter).unwrap(),
            peer_event: $rv.enter($sid, &$program.peer_event).unwrap(),
            peer_close: $rv.enter($sid, &$program.peer_close).unwrap(),
            files_event: $rv.enter($sid, &$program.files_event).unwrap(),
            files_close: $rv.enter($sid, &$program.files_close).unwrap(),
            close_join: $rv.enter($sid, &$program.close_join).unwrap(),
            source_collector: $rv.enter($sid, &$program.source_collector).unwrap(),
            input_collector: $rv.enter($sid, &$program.input_collector).unwrap(),
            delivery_collector: $rv.enter($sid, &$program.delivery_collector).unwrap(),
        }
    };
}

#[test]
fn actual_get_selects_encrypted_body_and_completes_close() {
    run_connection(1, Loss::None);
}

#[test]
fn advertised_connection_credit_cannot_exceed_reserved_receive_windows() {
    use hibana_quic::connection::application_stream::{Error, StreamNumbers};
    let scope = ApplicationKeyScope::new(101);
    let mut slots: Vec<_> = (0..STREAMS)
        .map(|_| StreamSlot::<RECEIVE_WINDOW>::EMPTY)
        .collect();
    let mut chunks: Vec<_> = (0..8).map(|_| SendChunk::<CHUNK>::EMPTY).collect();
    let mut references = [PacketReference::EMPTY; 64];
    let mut unbacked = limits(Side::Client);
    unbacked.max_data = 64 * 1024;
    assert!(matches!(
        StreamNumbers::new(
            &scope,
            hibana_quic::streams::Role::Client,
            limits(Side::Server),
            unbacked,
            &mut slots,
            &mut chunks,
            &mut references
        ),
        Err(Error::Streams(
            hibana_quic::streams::Error::InvalidConfiguration
        ))
    ));
    StreamNumbers::new(
        &scope,
        hibana_quic::streams::Role::Client,
        limits(Side::Server),
        limits(Side::Client),
        &mut slots,
        &mut chunks,
        &mut references,
    )
    .unwrap();
}

#[test]
fn client_slots_are_reserved_for_its_requests_not_peer_initiated_streams() {
    use hibana_quic::connection::application_stream::StreamNumbers;
    let scope = ApplicationKeyScope::new(102);
    let mut slots: Vec<_> = (0..STREAMS)
        .map(|_| StreamSlot::<RECEIVE_WINDOW>::EMPTY)
        .collect();
    let mut chunks: Vec<_> = (0..8).map(|_| SendChunk::<CHUNK>::EMPTY).collect();
    let mut references = [PacketReference::EMPTY; 64];
    let mut numbers = StreamNumbers::new(
        &scope,
        hibana_quic::streams::Role::Client,
        limits(Side::Server),
        limits(Side::Client),
        &mut slots,
        &mut chunks,
        &mut references,
    )
    .unwrap();
    let mut facets = numbers.split();
    for id in (0..STREAMS as u64).map(|index| index * 4) {
        assert_eq!(facets.app.open_local().unwrap().id(), id);
    }
    assert!(matches!(
        facets.app.open_local(),
        Err(hibana_quic::connection::application_stream::Error::Streams(
            hibana_quic::streams::Error::StreamLimit
        ))
    ));
}

#[test]
fn three_distinct_stream_requests_deliver_each_body_and_fin_once() {
    run_connection(3, Loss::None);
}

#[test]
fn empty_response_uses_explicit_fin_after_three_nonempty_streams() {
    run_connection(4, Loss::None);
}

#[test]
fn drop_first_server_one_rtt_still_confirms_delivers_and_closes() {
    run_connection(3, Loss::FirstServerOneRtt);
}

#[test]
fn accepted_but_lost_server_final_handshake_ack_does_not_gate_application() {
    // In this full, non-resumed handshake the client's only Handshake CRYPTO
    // flight is Finished. Drop the server's authenticated ACK-only response.
    run_connection(3, Loss::ServerHandshakeAck);
}

#[test]
fn lost_authenticated_handshake_done_is_retransmitted_before_client_completion() {
    run_connection(3, Loss::HandshakeDone);
}

fn run_connection(count: usize, loss: Loss) {
    connection_case(count, loss);
}

fn connection_case(count: usize, loss: Loss) {
    connection_case_with_slots(count, loss, STREAMS);
}

#[test]
fn four_requests_reuse_two_actual_client_slots() {
    connection_case_with_slots(4, Loss::None, 2);
}

#[test]
fn slot_reuse_preserves_loss_recovery_and_late_packet_accounting() {
    connection_case_with_slots(4, Loss::FirstServerOneRtt, 2);
}

fn connection_case_with_slots(count: usize, loss: Loss, client_slots: usize) {
    connection_case_with_failure(count, loss, client_slots, FileFailure::None);
}

#[test]
fn actual_request_failure_closes_without_successful_source_completion() {
    connection_case_with_failure(1, Loss::None, STREAMS, FileFailure::Request);
}
#[test]
fn actual_open_failure_closes_without_successful_source_completion() {
    connection_case_with_failure(1, Loss::None, STREAMS, FileFailure::Open);
}
#[test]
fn actual_body_failure_closes_without_fabricated_fin() {
    connection_case_with_failure(1, Loss::None, STREAMS, FileFailure::Read);
}
#[test]
fn actual_sink_write_failure_uses_explicit_failure_reply() {
    connection_case_with_failure(1, Loss::None, STREAMS, FileFailure::Write);
}
#[test]
fn actual_sink_finish_failure_uses_explicit_failure_reply() {
    connection_case_with_failure(1, Loss::None, STREAMS, FileFailure::Finish);
}

fn connection_case_with_failure(
    count: usize,
    loss: Loss,
    client_slots: usize,
    failure: FileFailure,
) {
    let client_limits = Limits {
        max_data: (client_slots * RECEIVE_WINDOW) as u64,
        ..limits(Side::Client)
    };

    let root = CertificateDer::from(fixture::ROOT_DER);
    let leaf = CertificateDer::from(if matches!(loss, Loss::DuplexPacketMask { .. }) {
        loss_certificate::LARGE_LEAF_DER
    } else {
        fixture::LEAF_DER
    });
    let signing = fixture::signing_key();
    let anchors = [trust_anchor_from_der(&root).unwrap()];
    let chain = [leaf.as_ref()];
    let client_params = parameters_with_limits(CLIENT_ID, None, client_limits);
    let server_params = parameters(SERVER_ID, Some(ORIGINAL));
    let mut observation_scope = ApplicationKeyScope::new(99);
    let mut inspector = inspection_keys(
        &mut observation_scope,
        ClientConfig {
            version: hibana_quic::version::Version::V1,
            server_name: "localhost",
            trust_anchors: &anchors,
            now: fixture::now(),
            certificate_limits: CertificateLimits::default(),
            transport_parameters: &client_params,
        },
        ServerConfig {
            version: hibana_quic::version::Version::V1,
            certificate_chain: &chain,
            signing_key: &signing,
            transport_parameters: &server_params,
        },
    );
    let mut client_tls_buffers = fixture::Buffers::new();
    let mut server_tls_buffers = fixture::Buffers::new();
    let client_tls = BoundedTls::client(
        ClientConfig {
            version: hibana_quic::version::Version::V1,
            server_name: "localhost",
            trust_anchors: &anchors,
            now: fixture::now(),
            certificate_limits: CertificateLimits::default(),
            transport_parameters: &client_params,
        },
        client_tls_buffers.storage(),
        &mut fixture::TestRandom(349),
    )
    .unwrap();
    struct TicketTime;
    impl hibana_quic::tls_ticket::TicketClock for TicketTime {
        fn now_ms(&self) -> Result<u64, hibana_quic::tls_ticket::Error> {
            Ok(1_000_000)
        }
    }
    let mut replay = [const { hibana_quic::tls_ticket::ReplaySlot::empty() }; 8];
    let mut ticket_key = hibana_quic::tls_ticket::TicketKey::generate(
        &mut fixture::TestRandom(991),
        hibana_quic::tls_ticket::ReplayPolicy::ReusableOneRtt,
        &mut replay,
    )
    .unwrap();
    let mut ticket_entropy = fixture::TestRandom(992);
    let server_config = ServerConfig {
        version: hibana_quic::version::Version::V1,
        certificate_chain: &chain,
        signing_key: &signing,
        transport_parameters: &server_params,
    };
    let server_tls = if matches!(loss, Loss::DuplexPacketMask { .. }) {
        BoundedTls::server_with_tickets(
            server_config,
            server_tls_buffers.storage(),
            &mut fixture::TestRandom(701),
            hibana_quic::bounded_tls::ServerResumption {
                store: &mut ticket_key,
                entropy: &mut ticket_entropy,
                clock: &TicketTime,
                policy: b"paired loss diagnostic",
                lifetime_seconds: 3600,
                max_age_skew_ms: 300000,
            },
        )
    } else {
        BoundedTls::server(
            server_config,
            server_tls_buffers.storage(),
            &mut fixture::TestRandom(701),
        )
    }
    .unwrap();
    let mut client_scope = ApplicationKeyScope::new(1);
    let mut server_scope = ApplicationKeyScope::new(2);
    let mut client_install = client_scope.claim().unwrap();
    let mut server_install = server_scope.claim().unwrap();
    let client_recovery = client_install.take_recovery().unwrap();
    let server_recovery = server_install.take_recovery().unwrap();
    let mut client_gate = PublicationGate::new(client_install.take_publication_gate().unwrap());
    let mut server_gate = PublicationGate::new(server_install.take_publication_gate().unwrap());
    let mut client_transcript =
        Transcript::new(client_tls.into_key_source(client_install).unwrap());
    let mut server_transcript =
        Transcript::new(server_tls.into_key_source(server_install).unwrap());
    let initial_rtt = if matches!(loss, Loss::DuplexPacketMask { .. }) {
        333_000
    } else {
        10_000
    };
    let mut client_book =
        Recovery::<DATAGRAM>::new(client_recovery, Side::Client, initial_rtt, DATAGRAM as u64)
            .unwrap();
    let mut server_book =
        Recovery::<DATAGRAM>::new(server_recovery, Side::Server, initial_rtt, DATAGRAM as u64)
            .unwrap();
    let (mut client_issuer, client_stop) = client_gate.split().unwrap();
    let (mut server_issuer, server_stop) = server_gate.split().unwrap();
    let programs = application::protocol::programs();
    let client_outcomes = application::Outcomes::new();
    let server_outcomes = application::Outcomes::new();
    let client_carrier = CarrierStorage::<1, 16, 128>::new();
    let server_carrier = CarrierStorage::<1, 16, 128>::new();
    // The host fixture owns these fixed-size rendezvous slabs, as the real
    // adapter does. Keep them off libtest's default stack; this does not change
    // any carrier capacity or let the no-alloc core allocate its own storage.
    let mut client_slab = vec![0; 262144];
    let mut server_slab = vec![0; 262144];
    let mut client_kit = SessionKitStorage::uninit();
    let mut server_kit = SessionKitStorage::uninit();
    let client_sid = SessionId::new(11);
    let server_sid = SessionId::new(12);
    let client_rv = client_kit
        .init()
        .rendezvous(&mut client_slab, client_carrier.bind(client_sid).unwrap())
        .unwrap();
    let server_rv = server_kit
        .init()
        .rendezvous(&mut server_slab, server_carrier.bind(server_sid).unwrap())
        .unwrap();
    macro_rules! resolvers {
        ($rv:expr, $outcomes:expr) => {{
            $rv.set_resolver(
                &programs.handshake.udp,
                $outcomes
                    .handshake_adapter
                    .resolver::<{ connection::protocol::ADAPTER_RESULT }>(),
            )
            .unwrap();
            $rv.set_resolver(
                &programs.adapter,
                $outcomes
                    .application_adapter
                    .resolver::<{ application::protocol::SUBMISSION_RESULT }>(),
            )
            .unwrap();
            $rv.set_resolver(
                &programs.adapter,
                $outcomes
                    .application_reset
                    .resolver::<{ application::protocol::STOP_RESULT }>(),
            )
            .unwrap();
        }};
    }
    resolvers!(client_rv, client_outcomes);
    resolvers!(server_rv, server_outcomes);
    let mut client_roles = roles!(client_rv, client_sid, programs);
    let mut server_roles = roles!(server_rv, server_sid, programs);
    let mut client_data = [[0; 8192]; 3];
    let mut client_maps = [[0; hibana_quic::handshake::bitmap_bytes(8192)]; 3];
    let mut server_data = [[0; 8192]; 3];
    let mut server_maps = [[0; hibana_quic::handshake::bitmap_bytes(8192)]; 3];
    let [c0, c1, ca] = &mut client_data;
    let [cm0, cm1, cma] = &mut client_maps;
    let [s0, s1, sa] = &mut server_data;
    let [sm0, sm1, sma] = &mut server_maps;
    let mut client_streams = [const { StreamSlot::<RECEIVE_WINDOW>::EMPTY }; STREAMS];
    let mut server_streams = [const { StreamSlot::<RECEIVE_WINDOW>::EMPTY }; STREAMS];
    let mut client_chunks = [const { SendChunk::<CHUNK>::EMPTY }; 8];
    let mut server_chunks = [const { SendChunk::<CHUNK>::EMPTY }; 8];
    let mut client_refs = [PacketReference::EMPTY; 64];
    let mut server_refs = [PacketReference::EMPTY; 64];
    let client_setup = application::Setup {
        local_ids: None,
        server_token: None,
        local_idle_timeout_ms: 0,
        key_update_target: 0,
        early: None,
        config: Config {
            initial_path: None,
            version: hibana_quic::version::Version::V1,
            side: Side::Client,
            local_connection_id: CLIENT_ID,
            original_destination_id: ORIGINAL,
            retry_source_id: None,
            initial_token: &[],
            peer_connection_id: ORIGINAL,
        },
        local_limits: client_limits,
        handshake_crypto: [
            CryptoBuffer::new(c0, cm0).unwrap(),
            CryptoBuffer::new(c1, cm1).unwrap(),
        ],
        application: application::Buffers {
            streams: &mut client_streams[..client_slots],
            chunks: &mut client_chunks,
            references: &mut client_refs,
            crypto: CryptoBuffer::new(ca, cma).unwrap(),
        },
    };
    let server_setup = application::Setup {
        local_ids: None,
        server_token: None,
        local_idle_timeout_ms: 0,
        key_update_target: 0,
        early: None,
        config: Config {
            initial_path: None,
            version: hibana_quic::version::Version::V1,
            side: Side::Server,
            local_connection_id: SERVER_ID,
            original_destination_id: ORIGINAL,
            retry_source_id: None,
            initial_token: &[],
            peer_connection_id: CLIENT_ID,
        },
        local_limits: limits(Side::Server),
        handshake_crypto: [
            CryptoBuffer::new(s0, sm0).unwrap(),
            CryptoBuffer::new(s1, sm1).unwrap(),
        ],
        application: application::Buffers {
            streams: &mut server_streams,
            chunks: &mut server_chunks,
            references: &mut server_refs,
            crypto: CryptoBuffer::new(sa, sma).unwrap(),
        },
    };
    let mut clock = TestClock::new();
    if matches!(loss, Loss::DuplexPacketMask { .. }) {
        // Diagnostic bound matches the runner outer limit. The earlier 30 s
        // experiment failed with the first nine client datagrams all dropped:
        // the real next PTO remained armed at 30.969 s, not a missing wake.
        // This changes no product deadline and does not qualify the runner.
        clock.limit = 300_000_000;
    }
    let capacity = if matches!(loss, Loss::DuplexPacketMask { .. }) {
        25
    } else {
        1
    };
    let to_client = Path::new(capacity);
    let to_server = Path::new(capacity);
    let mut client_rx = Rx(&to_client, &clock);
    let mut server_rx = Rx(&to_server, &clock);
    let mut client_tx = Tx {
        path: &to_server,
        clock: &clock,
        loss: if matches!(
            loss,
            Loss::ClientPacketBurst { .. }
                | Loss::DuplexPacketMask { .. }
                | Loss::MissingEcnMetadata
                | Loss::BleachedEcn
        ) {
            loss
        } else {
            Loss::None
        },
        inspector: None,
    };
    let mut server_tx = Tx {
        path: &to_client,
        clock: &clock,
        loss: if matches!(loss, Loss::ClientPacketBurst { .. }) {
            Loss::None
        } else {
            loss
        },
        inspector: Some(&mut inspector),
    };
    let mut requests = Requests {
        failure,
        count,
        next: 0,
        started: Vec::new(),
    };
    let mut handler = Handler {
        limit: if matches!(loss, Loss::ServerApplicationAcks) {
            core::num::NonZeroUsize::new(count)
        } else {
            None
        },
        opened: Vec::new(),
        failure,
    };
    let mut sink = Sink {
        failure,
        bytes: core::array::from_fn(|_| Vec::new()),
        finished: [0; STREAMS],
    };
    let mut client_report = None;
    let mut server_report = None;
    // Pin the connection futures in caller-owned host storage too. The
    // executor polls a pointer, rather than moving both peers onto its stack.
    let client = Box::pin(
        application::client::<DATAGRAM, PARAMS, RECEIVE_WINDOW, CHUNK>(
            &mut client_roles,
            &mut client_transcript,
            client_setup,
            &mut client_rx,
            &mut client_tx,
            &clock,
            &mut client_issuer,
            client_stop,
            &mut client_book,
            &client_outcomes,
            &mut requests,
            &mut sink,
        ),
    );
    let server = Box::pin(
        application::server::<DATAGRAM, PARAMS, RECEIVE_WINDOW, CHUNK>(
            &mut server_roles,
            &mut server_transcript,
            server_setup,
            &mut server_rx,
            &mut server_tx,
            &clock,
            &mut server_issuer,
            server_stop,
            &mut server_book,
            &server_outcomes,
            &mut handler,
        ),
    );
    execute(
        &clock,
        hibana_quic::runtime::join2(
            async {
                client_report = Some(client.await);
                Ok::<(), application::Error>(())
            },
            async {
                server_report = Some(server.await);
                Ok::<(), application::Error>(())
            },
        ),
        || {
            eprintln!("diagnostic now={} next={:?} client_sent={} client_dropped={} client_delivered={} server_sent={} server_dropped={} server_delivered={}", clock.now(), clock.alarms.borrow().iter().flatten().map(|alarm| alarm.deadline).min(), to_server.accepted.get(), to_server.dropped.get(), to_server.delivered.get(), to_client.accepted.get(), to_client.dropped.get(), to_client.delivered.get());
            for event in client_rv.tap() {
                eprintln!("client role: {event:?}");
            }
            for event in server_rv.tap() {
                eprintln!("server role: {event:?}");
            }
        },
    )
    .unwrap();
    assert_eq!(
        client_carrier.queued(),
        0,
        "client left internal messages retained"
    );
    assert_eq!(
        server_carrier.queued(),
        0,
        "server left internal messages retained"
    );
    let client = client_report.unwrap();
    let server = server_report.unwrap();
    if matches!(loss, Loss::DuplexPacketMask { .. }) {
        eprintln!("duplex elapsed_us={}", clock.now());
    }
    if failure != FileFailure::None {
        assert!(
            matches!(client, Err(application::Error::Application)),
            "client result: {client:?}"
        );
        assert!(
            matches!(server, Err(application::Error::Application)),
            "server result: {server:?}"
        );
        assert_eq!(
            sink.finished[0], 0,
            "failed IO fabricated successful FIN delivery"
        );
        return;
    }
    let client = client.unwrap();
    let server = server.unwrap();
    assert_eq!(client_transcript.state(), State::Connected);
    assert_eq!(server_transcript.state(), State::Connected);
    for transcript in [&client_transcript, &server_transcript] {
        assert!(
            transcript.received_offset(hibana_quic::tls::Level::Initial) > 0,
            "verified Initial consumption must cross the application handoff"
        );
        assert!(
            transcript.received_offset(hibana_quic::tls::Level::Handshake) > 0,
            "verified Handshake consumption must cross the application handoff"
        );
    }
    assert!(
        client.confirmed && server.confirmed,
        "Finished alone is not client confirmation"
    );
    assert!(
        client.close_completed && server.close_completed,
        "all ordinary roles must retire before close completes"
    );
    if matches!(loss, Loss::None) {
        for report in [&client, &server] {
            assert!(
                report.ecn_accepted_packets > 0,
                "no actual marked send: {report:?}"
            );
            assert!(
                report.ecn_validated_packets > 0,
                "no authenticated ECN validation: {report:?}"
            );
            assert!(
                report.ecn_received_packets > 0 && report.ecn_acknowledgments_sent > 0,
                "missing actual ACK_ECN: {report:?}"
            );
            assert!(
                report.ecn_feedback_error.is_none(),
                "unexpected ECN failure: {report:?}"
            );
        }
    }
    if matches!(loss, Loss::MissingEcnMetadata | Loss::BleachedEcn) {
        let expected = if matches!(loss, Loss::MissingEcnMetadata) {
            hibana_quic::ecn::Failure::MissingCounts
        } else {
            hibana_quic::ecn::Failure::Bleached
        };
        for report in [&client, &server] {
            assert!(
                (1..=10).contains(&report.ecn_accepted_packets),
                "probing did not stop: {report:?}"
            );
            assert_eq!(report.ecn_validated_packets, 0);
            assert_eq!(report.ecn_received_packets, 0);
            assert_eq!(report.ecn_acknowledgments_sent, 0);
            assert_eq!(
                report.ecn_feedback_error,
                Some(hibana_quic::ecn::Error::Validation(expected))
            );
        }
    }
    assert_eq!(client.submitted_streams, count);
    assert_eq!(client.completed_streams, count);
    assert_eq!(server.completed_streams, count);
    if matches!(
        loss,
        Loss::ServerApplicationAcks | Loss::ServerApplicationAcksPersistentServer
    ) {
        assert!(
            !client.all_streams_acked,
            "lost request ACK must not be invented"
        );
        assert!(server.all_streams_acked);
    } else if !matches!(
        loss,
        Loss::ServerPacketBurst { .. }
            | Loss::ClientPacketBurst { .. }
            | Loss::DuplexPacketMask { .. }
    ) {
        assert!(client.all_streams_acked && server.all_streams_acked);
    }
    assert!(client.received_bytes > BODY_SIZES[..count].iter().sum::<usize>() as u64);
    assert!(client.sent_bytes >= 1200 && server.sent_bytes >= 1200);
    assert_eq!(requests.started.len(), count);
    assert_eq!(handler.opened.len(), count);
    for stream in 0..count {
        assert!(handler.opened.contains(&((stream * 4) as u64, stream)));
        let expected: Vec<_> = (0..BODY_SIZES[stream])
            .map(|offset| body_byte(stream, offset))
            .collect();
        assert_eq!(
            sink.bytes[stream], expected,
            "wrong response selected or bytes lost"
        );
        assert_eq!(sink.finished[stream], 1);
    }
    for stream in count..STREAMS {
        assert!(sink.bytes[stream].is_empty());
        assert_eq!(sink.finished[stream], 0);
    }
    assert!(to_client.accepted.get() >= to_client.delivered.get());
    assert!(to_server.accepted.get() >= to_server.delivered.get());
    if let Loss::ClientPacketBurst { count, .. } = loss {
        assert!(to_server.dropped.get() > 0 && to_server.dropped.get() <= count);
    } else if let Loss::DuplexPacketMask { client, .. } = loss {
        assert!(to_server.dropped.get() <= client.count_ones() as usize);
    } else {
        assert_eq!(to_server.dropped.get(), 0);
    }
    if matches!(
        loss,
        Loss::ServerApplicationAcks | Loss::ServerApplicationAcksPersistentServer
    ) {
        assert!(to_client.dropped.get() > 0);
    } else if let Loss::DuplexPacketMask { server, .. } = loss {
        assert!(to_client.dropped.get() <= server.count_ones() as usize);
    } else if let Loss::ServerPacketBurst { count, .. } = loss {
        assert!(to_client.dropped.get() > 0 && to_client.dropped.get() <= count);
    } else {
        assert_eq!(
            to_client.dropped.get(),
            if matches!(
                loss,
                Loss::None
                    | Loss::ClientPacketBurst { .. }
                    | Loss::MissingEcnMetadata
                    | Loss::BleachedEcn
            ) {
                0
            } else {
                1
            }
        );
    }
    if matches!(loss, Loss::ServerHandshakeAck) {
        assert!(inspector.handshake_acks >= 1);
    }
    if matches!(loss, Loss::HandshakeDone) {
        assert!(
            inspector.handshake_done >= 2,
            "HANDSHAKE_DONE must be retransmitted as an authenticated frame"
        );
    }
}

#[test]
fn authenticated_peer_close_after_complete_response_does_not_invent_lost_request_ack() {
    connection_case(1, Loss::ServerApplicationAcks);
}

#[test]
fn complete_responses_can_close_when_request_ack_is_lost_and_server_stays_open() {
    connection_case(1, Loss::ServerApplicationAcksPersistentServer);
}

#[test]
fn finite_handshake_survives_each_early_server_packet_loss_burst() {
    for first in 1..=16 {
        for count in 1..=3 {
            eprintln!("server loss burst: first={first} count={count}");
            connection_case(1, Loss::ServerPacketBurst { first, count });
        }
    }
}

#[test]
fn finite_handshake_survives_each_early_client_packet_loss_burst() {
    for first in 1..=16 {
        for count in 1..=3 {
            eprintln!("client loss burst: first={first} count={count}");
            connection_case(1, Loss::ClientPacketBurst { first, count });
        }
    }
}

#[test]
fn finite_handshake_survives_reproducible_duplex_packet_loss() {
    for seed in 1u64..=32 {
        let mut word = seed;
        let mut masks = [0u64; 2];
        for mask in &mut masks {
            let mut ordinal = 0;
            while ordinal < 32 {
                word ^= word << 13;
                word ^= word >> 7;
                word ^= word << 17;
                // Three-packet bursts started with probability 1/8 give a
                // long-run packet loss fraction (3/8)/(1+2/8) = 30 percent.
                if word % 8 == 0 {
                    for dropped in ordinal..(ordinal + 3).min(32) {
                        *mask |= 1 << dropped;
                    }
                    ordinal += 3;
                } else {
                    ordinal += 1;
                }
            }
        }
        eprintln!(
            "duplex loss: seed={seed} client={} server={}",
            masks[0], masks[1]
        );
        connection_case(
            1,
            Loss::DuplexPacketMask {
                client: masks[0],
                server: masks[1],
            },
        );
    }
}

#[test]
fn missing_ecn_metadata_disables_marking_without_blocking_delivery() {
    run_connection(3, Loss::MissingEcnMetadata);
}
#[test]
fn bleached_ecn_disables_marking_without_blocking_delivery() {
    run_connection(3, Loss::BleachedEcn);
}
