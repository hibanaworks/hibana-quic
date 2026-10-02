//! Actual bounded resumed0RTT QUIC/stream/Hibana acceptance and rejection tests.
//! PKI fixture generation/import, caller storage preparation and test harness are
//! outside the counter; constructors, runtime rendezvous, handshake, streaming,
//! key updates, local retirement and provider/runtime drops are inside it.
use hibana::runtime::{SessionKitStorage, ids::SessionId};
use hibana_quic::{
    bounded_tls::{
        BoundedTls, ClientConfig, ClientEarlyData, ClientResumption, ServerConfig, ServerEarlyData,
        ServerResumption, SigningKey, Storage,
    },
    carrier::{CarrierStorage, LocalCarrier},
    driver::{Driver, Roles},
    early_data::{EarlyFreshness, EarlyStatus, QuarantineSlot, ReplayStorage, ServerPolicy},
    early_send::RequestSlot,
    handshake::CryptoBuffer,
    handshake_endpoint::{Config, HandshakeEndpoint, Side},
    packet::encode_varint,
    protocol::*,
    streams::{self, Limits, PacketReference, SendChunk, StreamSlot},
    tls::{Level, Provider},
    tls_certificate::{
        CertificateDer, Limits as CertificateLimits, UnixTime, trust_anchor_from_der,
    },
    tls_ticket::{
        self as ticket, Binding, ClientCache, ClientSlot, ReplayPolicy, TicketKey,
        VerificationContext,
    },
    transport_endpoint::TransportEndpoint,
};
use p256::pkcs8::DecodePrivateKey;
use rand_core::OsRng;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    time::Duration,
};
type Endpoint<'r, 's, 'c, 'b> = TransportEndpoint<'r, 's, BoundedTls<'c, 'b>, 1024, 1024>;
thread_local! {static TRACK:Cell<Option<usize>>=const{Cell::new(None)};}
struct Counter;
fn allocation() {
    let _ = TRACK.try_with(|c| {
        if let Some(n) = c.get() {
            c.set(Some(n + 1))
        }
    });
}
unsafe impl GlobalAlloc for Counter {
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
static ALLOCATOR: Counter = Counter;
struct Identity {
    root: CertificateDer<'static>,
    leaf: CertificateDer<'static>,
    signing: SigningKey,
}
fn identity() -> Identity {
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_key = KeyPair::generate().unwrap();
    let ca = ca.self_signed(&ca_key).unwrap();
    let key = KeyPair::generate().unwrap();
    let mut p = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let leaf = p.signed_by(&key, &ca, &ca_key).unwrap();
    let signing = SigningKey::from_pkcs8_der(&key.serialize_der()).unwrap();
    Identity {
        root: ca.der().clone(),
        leaf: leaf.der().clone(),
        signing,
    }
}
struct Buffers {
    rx: [u8; 8192],
    tx: [u8; 8192],
    cert: [u8; 8192],
    params: [u8; 512],
}
impl Buffers {
    fn new() -> Self {
        Self {
            rx: [0; 8192],
            tx: [0; 8192],
            cert: [0; 8192],
            params: [0; 512],
        }
    }
    fn storage(&mut self) -> Storage<'_> {
        Storage {
            rx_message: &mut self.rx,
            tx_flight: &mut self.tx,
            peer_certificates: &mut self.cert,
            peer_parameters: &mut self.params,
        }
    }
}
fn parameters(id: &[u8], original: Option<&[u8]>, limits: Limits) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0; 8];
    for (kind, data) in [(15, Some(id)), (0, original)] {
        if let Some(data) = data {
            let n = encode_varint(kind, &mut buf).unwrap();
            out.extend_from_slice(&buf[..n]);
            let n = encode_varint(data.len() as u64, &mut buf).unwrap();
            out.extend_from_slice(&buf[..n]);
            out.extend_from_slice(data);
        }
    }
    for (kind, value) in [
        (4, limits.max_data),
        (5, limits.stream_data_bidi_local),
        (6, limits.stream_data_bidi_remote),
        (7, limits.stream_data_uni),
        (8, limits.max_streams_bidi),
        (9, limits.max_streams_uni),
    ] {
        let mut value_bytes = [0; 8];
        let len = encode_varint(value, &mut value_bytes).unwrap();
        let n = encode_varint(kind, &mut buf).unwrap();
        out.extend_from_slice(&buf[..n]);
        let n = encode_varint(len as u64, &mut buf).unwrap();
        out.extend_from_slice(&buf[..n]);
        out.extend_from_slice(&value_bytes[..len]);
    }
    out
}
const EARLY_POLICY: ServerPolicy = ServerPolicy::BufferedReplaySafeRequests {
    max_bytes: 2048,
    max_streams: 2,
};
struct Clock;
impl ticket::TicketClock for Clock {
    fn now_ms(&self) -> Result<u64, ticket::Error> {
        Ok(1000)
    }
}
fn issue(
    id: &Identity,
    anchors: &[hibana_quic::tls_certificate::TrustAnchor<'_>],
    cp: &[u8],
    sp: &[u8],
    key: &mut TicketKey<'_>,
    cache: &mut ClientCache<'_, 4096>,
    clock: &Clock,
) {
    let mut cb = Buffers::new();
    let mut sb = Buffers::new();
    let chain = [id.leaf.as_ref()];
    let mut entropy = OsRng;
    let held = [QuarantineSlot::<1024>::EMPTY, QuarantineSlot::EMPTY];
    let mut client = BoundedTls::client_with_tickets(
        ClientConfig {
            server_name: "localhost",
            trust_anchors: anchors,
            now: UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_000)),
            certificate_limits: CertificateLimits::default(),
            transport_parameters: cp,
        },
        cb.storage(),
        &mut OsRng,
        ClientResumption {
            store: cache,
            clock,
        },
    )
    .unwrap();
    let admission = ServerEarlyData::buffered(
        0,
        EARLY_POLICY,
        sp,
        &held,
        EarlyFreshness::new(1000).unwrap(),
    )
    .unwrap();
    let mut server = BoundedTls::server_with_early_data(
        ServerConfig {
            certificate_chain: &chain,
            signing_key: &id.signing,
            transport_parameters: sp,
        },
        sb.storage(),
        &mut OsRng,
        ServerResumption {
            store: key,
            entropy: &mut entropy,
            clock,
            policy: b"early GET v1",
            lifetime_seconds: 60,
            max_age_skew_ms: 1000,
        },
        admission,
    )
    .unwrap();
    let mut cpns = [0; 3];
    let mut spns = [0; 3];
    for _ in 0..32 {
        let c = move_tls(&mut client, &mut server, &mut cpns);
        let s = move_tls(&mut server, &mut client, &mut spns);
        if !c && !s {
            assert!(!client.is_handshaking() && !server.is_handshaking());
            return;
        }
    }
    panic!("ticket fixture handshake stalled")
}
fn move_tls(
    from: &mut BoundedTls<'_, '_>,
    to: &mut BoundedTls<'_, '_>,
    pns: &mut [u64; 3],
) -> bool {
    let mut out = [0; 528];
    let mut moved = false;
    for _ in 0..128 {
        let Some(tx) = from.transmit(&mut out[..512]).unwrap() else {
            return moved;
        };
        if tx.level != Level::Initial {
            let index = if tx.level == Level::Handshake { 1 } else { 2 };
            let pn = pns[index];
            pns[index] += 1;
            let n = from
                .seal(tx.level, pn, b"header", &mut out, tx.len)
                .unwrap();
            assert_eq!(to.open(tx.level, pn, b"header", &mut out[..n]), Ok(tx.len));
        }
        to.receive(tx.level, &out[..tx.len]).unwrap();
        moved = true;
    }
    panic!("fixture output did not yield")
}
fn with_pair(
    accept_early: bool,
    f: impl FnOnce(&mut Endpoint<'_, '_, '_, '_>, &mut Endpoint<'_, '_, '_, '_>),
) {
    let limits = Limits {
        max_data: 2048,
        max_streams_bidi: 1,
        max_streams_uni: 0,
        stream_data_bidi_local: 1024,
        stream_data_bidi_remote: 1024,
        stream_data_uni: 1024,
    };
    let id = identity();
    let anchors = [trust_anchor_from_der(&id.root).unwrap()];
    let chain = [id.leaf.as_ref()];
    let client_params = parameters(b"client01", None, limits);
    let server_params = parameters(b"server01", Some(b"original"), limits);
    let first_client_params = parameters(b"client00", None, limits);
    let first_server_params = parameters(b"server00", Some(b"firstcid"), limits);
    let clock = Clock;
    let mut ordinary = [];
    let mut replay = ReplayStorage::<4>::new();
    let mut cache_slots = [ClientSlot::<4096>::empty()];
    let mut held = [QuarantineSlot::<1024>::EMPTY, QuarantineSlot::EMPTY];
    let mut intents = [RequestSlot::<1024>::EMPTY];
    let mut cb = Buffers::new();
    let mut sb = Buffers::new();
    let client_queue = CarrierStorage::<8, 16, { hibana_quic::protocol::SERVICE_PORTS }>::new();
    let server_queue = CarrierStorage::<8, 16, { hibana_quic::protocol::SERVICE_PORTS }>::new();
    let mut client_slab = [0; 32768];
    let mut server_slab = [0; 32768];
    let mut client_kit = SessionKitStorage::<
        LocalCarrier<'_, 8, 16, { hibana_quic::protocol::SERVICE_PORTS }>,
    >::uninit();
    let mut server_kit = SessionKitStorage::<
        LocalCarrier<'_, 8, 16, { hibana_quic::protocol::SERVICE_PORTS }>,
    >::uninit();
    let mut cb0 = [0; 8192];
    let mut cb1 = [0; 8192];
    let mut cb2 = [0; 8192];
    let mut cm0 = [0; hibana_quic::handshake::bitmap_bytes(8192)];
    let mut cm1 = [0; hibana_quic::handshake::bitmap_bytes(8192)];
    let mut cm2 = [0; hibana_quic::handshake::bitmap_bytes(8192)];
    let mut sb0 = [0; 8192];
    let mut sb1 = [0; 8192];
    let mut sb2 = [0; 8192];
    let mut sm0 = [0; hibana_quic::handshake::bitmap_bytes(8192)];
    let mut sm1 = [0; hibana_quic::handshake::bitmap_bytes(8192)];
    let mut sm2 = [0; hibana_quic::handshake::bitmap_bytes(8192)];
    let mut client_streams = [const { StreamSlot::<1024>::EMPTY }; 2];
    let mut server_streams = [const { StreamSlot::<1024>::EMPTY }; 2];
    let mut client_chunks = [const { SendChunk::<1024>::EMPTY }; 4];
    let mut server_chunks = [const { SendChunk::<1024>::EMPTY }; 4];
    let mut client_refs = [PacketReference::EMPTY; 16];
    let mut server_refs = [PacketReference::EMPTY; 16];
    TRACK.with(|c| c.set(Some(0)));
    {
        let mut key = TicketKey::generate_with_early_replay(
            &mut OsRng,
            ReplayPolicy::ReusableOneRtt,
            &mut ordinary,
            &mut replay,
        )
        .unwrap();
        let mut cache = ClientCache::new(&mut cache_slots);
        issue(
            &id,
            &anchors,
            &first_client_params,
            &first_server_params,
            &mut key,
            &mut cache,
            &clock,
        );
        let cached = cache
            .take_verified_for_origin(
                1000,
                &Binding::new("localhost", b"hq-interop", &[]).unwrap(),
                0x1301,
                VerificationContext::new(&anchors, CertificateLimits::default()).unwrap(),
            )
            .unwrap()
            .unwrap();
        let client_tls = BoundedTls::client_resuming_early(
            ClientConfig {
                server_name: "localhost",
                trust_anchors: &anchors,
                now: UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_000)),
                certificate_limits: CertificateLimits::default(),
                transport_parameters: &client_params,
            },
            cb.storage(),
            &mut OsRng,
            ClientResumption {
                store: &mut cache,
                clock: &clock,
            },
            cached,
            ClientEarlyData::replay_safe_requests(1),
        )
        .unwrap();
        let mut entropy = OsRng;
        let server_config = ServerConfig {
            certificate_chain: &chain,
            signing_key: &id.signing,
            transport_parameters: &server_params,
        };
        let tickets = ServerResumption {
            store: &mut key,
            entropy: &mut entropy,
            clock: &clock,
            policy: b"early GET v1",
            lifetime_seconds: 60,
            max_age_skew_ms: 1000,
        };
        let server_tls = if accept_early {
            let admission = ServerEarlyData::buffered(
                2,
                EARLY_POLICY,
                &server_params,
                &held,
                EarlyFreshness::new(1000).unwrap(),
            )
            .unwrap();
            BoundedTls::server_with_early_data(
                server_config,
                sb.storage(),
                &mut OsRng,
                tickets,
                admission,
            )
        } else {
            BoundedTls::server_with_tickets(server_config, sb.storage(), &mut OsRng, tickets)
        }
        .unwrap();
        let p0 = service_program::<INGRESS>();
        let p1 = service_program::<PACKET>();
        let p2 = service_program::<APPLICATION>();
        let p3 = service_program::<RECOVERY>();
        let p4 = service_program::<ADAPTER>();
        let p5 = service_program::<TIMER>();
        let crv = client_kit
            .init()
            .rendezvous(
                &mut client_slab,
                client_queue.bind(SessionId::new(1)).unwrap(),
            )
            .unwrap();
        let srv = server_kit
            .init()
            .rendezvous(
                &mut server_slab,
                server_queue.bind(SessionId::new(2)).unwrap(),
            )
            .unwrap();
        macro_rules! attach {
            ($rv:expr,$sid:expr) => {
                Driver::new(
                    $sid,
                    Roles {
                        ingress: $rv.enter(SessionId::new($sid as u32), &p0).unwrap(),
                        packet: $rv.enter(SessionId::new($sid as u32), &p1).unwrap(),
                        application: $rv.enter(SessionId::new($sid as u32), &p2).unwrap(),
                        recovery: $rv.enter(SessionId::new($sid as u32), &p3).unwrap(),
                        adapter: $rv.enter(SessionId::new($sid as u32), &p4).unwrap(),
                        timer: $rv.enter(SessionId::new($sid as u32), &p5).unwrap(),
                    },
                )
            };
        }
        let cc = [
            CryptoBuffer::new(&mut cb0, &mut cm0).unwrap(),
            CryptoBuffer::new(&mut cb1, &mut cm1).unwrap(),
            CryptoBuffer::new(&mut cb2, &mut cm2).unwrap(),
        ];
        let sc = [
            CryptoBuffer::new(&mut sb0, &mut sm0).unwrap(),
            CryptoBuffer::new(&mut sb1, &mut sm1).unwrap(),
            CryptoBuffer::new(&mut sb2, &mut sm2).unwrap(),
        ];
        let client = HandshakeEndpoint::new(
            Config {
                side: Side::Client,
                local_id: b"client01",
                original_destination_id: b"original",
                generation: 1,
            },
            client_tls,
            attach!(crv, 1),
            cc,
        )
        .unwrap();
        let server = HandshakeEndpoint::new(
            Config {
                side: Side::Server,
                local_id: b"server01",
                original_destination_id: b"original",
                generation: 2,
            },
            server_tls,
            attach!(srv, 2),
            sc,
        )
        .unwrap();
        let mut client = TransportEndpoint::new(
            client,
            limits,
            &mut client_streams,
            &mut client_chunks,
            &mut client_refs,
            1,
        )
        .unwrap();
        let mut server = TransportEndpoint::new(
            server,
            limits,
            &mut server_streams,
            &mut server_chunks,
            &mut server_refs,
            2,
        )
        .unwrap();
        client.configure_early_send(&mut intents).unwrap();
        if accept_early {
            server
                .configure_early_receive(EARLY_POLICY, &mut held)
                .unwrap();
        }
        f(&mut client, &mut server);
        if !client.is_retired() {
            client.close().unwrap();
        }
        if !server.is_retired() {
            server.close().unwrap();
        }
        assert!(client.is_retired());
        assert!(server.is_retired());
    }
    drop(client_kit);
    drop(server_kit);
    drop(client_queue);
    drop(server_queue);
    let allocations = TRACK.with(|c| c.replace(None).unwrap());
    assert_eq!(allocations, 0, "full bounded transport flow allocated");
}
#[test]
fn real_early_wire_is_quarantined_or_requeued_with_shared_pn_and_zero_allocation() {
    for accept in [true, false] {
        with_pair(accept, |client, server| {
            let request = b"GET /early-wire\r\n";
            let handle = client.enqueue_early_request(request).unwrap();
            let stream = client.early_stream_id(handle).unwrap();
            let mut early_count = 0;
            let mut early_authenticated = 0;
            let mut last_early = None;
            let mut later_one_rtt = false;
            let mut out = [0; 1500];
            let mut scratch = [0; 1500];
            for round in 0..100 {
                let now = round * 1000;
                client.timer(now).unwrap();
                server.timer(now).unwrap();
                let mut progress = false;
                for _ in 0..64 {
                    let Some(tx) = client.transmit(&mut out).unwrap() else {
                        break;
                    };
                    client.adapter_result(tx, true, now).unwrap();
                    if tx.is_early_data() {
                        early_count += 1;
                        last_early = Some(tx.packet_number.value);
                    } else if tx.encryption_level() == hibana_quic::packet::EncryptionLevel::OneRtt
                    {
                        if let Some(early) = last_early {
                            assert!(tx.packet_number.value > early);
                            later_one_rtt = true;
                        }
                    }
                    let received = server.receive(&out[..tx.len], &mut scratch).unwrap();
                    if tx.is_early_data() {
                        early_authenticated += received.authenticated;
                        assert!(!server.handshake_complete());
                        assert_eq!(
                            server.streams().lookup(stream),
                            Err(streams::Error::NotOpened)
                        );
                    }
                    progress = true;
                }
                for _ in 0..64 {
                    let Some(tx) = server.transmit(&mut out).unwrap() else {
                        break;
                    };
                    server.adapter_result(tx, true, now).unwrap();
                    client.receive(&out[..tx.len], &mut scratch).unwrap();
                    progress = true;
                }
                if client.handshake_complete() && server.handshake_complete() {
                    if let Ok(handle) = server.streams().lookup(stream) {
                        let view = server.read(handle).unwrap();
                        if view.first.len() + view.second.len() == request.len() && view.fin {
                            assert_eq!(view.first, request);
                            assert!(view.second.is_empty());
                            break;
                        }
                    }
                }
                assert!(progress || round < 99, "wire stalled");
            }
            assert!(early_count > 0);
            assert_eq!(early_authenticated > 0, accept);
            assert!(client.handshake_complete() && server.handshake_complete());
            assert!(client.tls().is_resumed() && server.tls().is_resumed());
            assert_eq!(
                client.tls().early_status(),
                if accept {
                    EarlyStatus::Accepted
                } else {
                    EarlyStatus::Rejected
                }
            );
            let delivered = server.streams().lookup(stream).unwrap();
            let view = server.read(delivered).unwrap();
            assert_eq!(view.first, request);
            assert!(view.fin);
            assert!(later_one_rtt, "application PN never progressed to1RTT");
            server.consume(delivered, request.len()).unwrap();
            assert!(server.read(delivered).unwrap().first.is_empty());
        });
    }
}
