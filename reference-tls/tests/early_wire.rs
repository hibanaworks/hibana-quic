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
    out.extend_from_slice(&[1, 1, 1]); // advertise exactly1ms idle, with PTO floor
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
    let mut early_controls = [const { hibana_quic::early_control::Slot::<128>::EMPTY }; 4];
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
        let mut client = HandshakeEndpoint::new(
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
        let mut server = HandshakeEndpoint::new(
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
        client.configure_idle_timeout(1).unwrap();
        server.configure_idle_timeout(1).unwrap();
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
            server
                .configure_early_controls(&mut early_controls)
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
fn with_raw_client_pair(
    accept_early: bool,
    f: impl FnOnce(&mut HandshakeEndpoint<'_, '_, BoundedTls<'_, '_>>, &mut Endpoint<'_, '_, '_, '_>),
) {
    with_raw_client_pair_limits(accept_early, false, f);
}
fn with_raw_client_pair_limits(
    accept_early: bool,
    changed_limits: bool,
    f: impl FnOnce(&mut HandshakeEndpoint<'_, '_, BoundedTls<'_, '_>>, &mut Endpoint<'_, '_, '_, '_>),
) {
    with_raw_client_pair_profile(accept_early, changed_limits, false, f);
}
fn with_raw_managed_pair(
    f: impl FnOnce(&mut HandshakeEndpoint<'_, '_, BoundedTls<'_, '_>>, &mut Endpoint<'_, '_, '_, '_>),
) {
    with_raw_client_pair_profile(true, false, true, f);
}
fn with_raw_client_pair_profile(
    accept_early: bool,
    changed_limits: bool,
    managed: bool,
    f: impl FnOnce(&mut HandshakeEndpoint<'_, '_, BoundedTls<'_, '_>>, &mut Endpoint<'_, '_, '_, '_>),
) {
    let limits = Limits {
        max_data: 1500,
        max_streams_bidi: 2,
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
    let remembered = if changed_limits {
        Limits {
            max_data: 512,
            max_streams_bidi: 1,
            stream_data_bidi_local: 512,
            stream_data_bidi_remote: 512,
            stream_data_uni: 512,
            ..limits
        }
    } else {
        limits
    };
    let first_server_params = parameters(b"server00", Some(b"firstcid"), remembered);
    let clock = Clock;
    let mut ordinary = [];
    let mut replay = ReplayStorage::<4>::new();
    let mut cache_slots = [ClientSlot::<4096>::empty()];
    let mut held = [QuarantineSlot::<1024>::EMPTY, QuarantineSlot::EMPTY];
    let mut early_controls = [const { hibana_quic::early_control::Slot::<128>::EMPTY }; 4];
    let mut network_paths = [const { hibana_quic::path::PathSlot::<1, 3>::empty() }; 2];
    let mut network_local = [const { hibana_quic::connection_id::LocalCidSlot::EMPTY }; 8];
    let mut network_peer = [const { hibana_quic::connection_id::PeerCidSlot::<2>::EMPTY }; 16];
    let mut network_rng = OsRng;
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
    let mut server_streams = [const { StreamSlot::<1024>::EMPTY }; 2];
    let mut server_chunks = [const { SendChunk::<1024>::EMPTY }; 4];
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
        let mut client = HandshakeEndpoint::new(
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
        let mut server = HandshakeEndpoint::new(
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
        client.configure_idle_timeout(1).unwrap();
        server.configure_idle_timeout(1).unwrap();
        let mut server = TransportEndpoint::new(
            server,
            limits,
            &mut server_streams,
            &mut server_chunks,
            &mut server_refs,
            2,
        )
        .unwrap();
        if accept_early {
            server
                .configure_early_receive(EARLY_POLICY, &mut held)
                .unwrap();
            server
                .configure_early_controls(&mut early_controls)
                .unwrap();
        }
        if managed {
            server
                .enable_network(
                    hibana_quic::handshake_endpoint::NetworkConfig::new(early_server_address()),
                    hibana_quic::handshake_endpoint::NetworkResources {
                        paths: &mut network_paths,
                        local_cids: &mut network_local,
                        peer_cids: &mut network_peer,
                        preferred_advertisement: None,
                    },
                    &mut network_rng,
                )
                .unwrap();
        }
        f(&mut client, &mut server);
        if !client.is_retired() {
            client.retire();
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
                        && let Some(early) = last_early
                    {
                        assert!(tx.packet_number.value > early);
                        later_one_rtt = true;
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
                if client.handshake_complete()
                    && server.handshake_complete()
                    && let Ok(handle) = server.streams().lookup(stream)
                {
                    let view = server.read(handle).unwrap();
                    if view.first.len() + view.second.len() == request.len()
                        && view.fin
                        && later_one_rtt
                    {
                        assert_eq!(view.first, request);
                        assert!(view.second.is_empty());
                        break;
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

#[test]
fn sparse_early_quarantine_yields_after128_ranges_and_drains_without_network() {
    with_raw_client_pair(true, |client, server| {
        let mut out = [0; 1500];
        let mut scratch = [0; 1500];
        for _ in 0..16 {
            let Some(tx) = client.transmit(&mut out).unwrap() else {
                break;
            };
            client.adapter_result(tx, true, 0).unwrap();
            server.receive(&out[..tx.len], &mut scratch).unwrap();
        }
        let mut expected = [b'!'; 259];
        for i in 0..130 {
            expected[2 * i] = b'A' + (i % 26) as u8;
        }
        for start in [0, 65] {
            let mut frames = [0; 1056];
            let mut len = 0;
            for i in start..start + 65 {
                len += hibana_quic::packet::encode_frame(
                    &hibana_quic::packet::Frame::Stream {
                        id: 0,
                        offset: (2 * i) as u64,
                        fin: false,
                        data: &expected[2 * i..2 * i + 1],
                    },
                    &mut frames[len..],
                )
                .unwrap();
            }
            let tx = client
                .transmit_early_application(&frames[..len], &mut out)
                .unwrap()
                .unwrap();
            assert!(tx.is_early_data());
            client.adapter_result(tx, true, 0).unwrap();
            assert_eq!(
                server
                    .receive(&out[..tx.len], &mut scratch)
                    .unwrap()
                    .authenticated,
                1
            );
        }
        assert!(!server.handshake_complete());
        assert_eq!(server.streams().lookup(0), Err(streams::Error::NotOpened));
        let mut resumed_drain = false;
        for _ in 0..32 {
            for _ in 0..64 {
                let Some(tx) = server.transmit(&mut out).unwrap() else {
                    break;
                };
                server.adapter_result(tx, true, 0).unwrap();
                client.receive(&out[..tx.len], &mut scratch).unwrap();
            }
            for _ in 0..64 {
                let Some(tx) = client.transmit(&mut out).unwrap() else {
                    break;
                };
                client.adapter_result(tx, true, 0).unwrap();
                server.receive(&out[..tx.len], &mut scratch).unwrap();
                if server.handshake_complete() && !resumed_drain {
                    assert_eq!(
                        server.streams().receive_charged(),
                        255,
                        "first bounded drain must expose exactly128 ranges"
                    );
                    assert!(!server.drain_early_data().unwrap());
                    assert_eq!(server.streams().receive_charged(), 259);
                    resumed_drain = true;
                }
            }
            if resumed_drain && client.handshake_complete() {
                break;
            }
        }
        assert!(resumed_drain);
        assert!(!server.is_retired());
        // The low-level client retains this complete byte intent throughout;
        // filling gaps uses the same actual PN owner and an ordinary1RTT frame.
        let mut encoded = [0; 1056];
        let n = hibana_quic::packet::encode_frame(
            &hibana_quic::packet::Frame::Stream {
                id: 0,
                offset: 0,
                fin: true,
                data: &expected,
            },
            &mut encoded,
        )
        .unwrap();
        let tx = client
            .transmit_application(&encoded[..n], &mut out)
            .unwrap()
            .unwrap();
        assert!(!tx.is_early_data());
        assert!(tx.packet_number.value >= 2);
        client.adapter_result(tx, true, 0).unwrap();
        server.receive(&out[..tx.len], &mut scratch).unwrap();
        let stream = server.streams().lookup(0).unwrap();
        let view = server.read(stream).unwrap();
        assert_eq!(view.first, &expected);
        assert!(view.second.is_empty() && view.fin);
        assert_eq!(server.streams().receive_charged(), 259);
    });
}
#[test]
fn terminal_and_closing_endpoints_invalidate_early_handles_and_enqueue() {
    for closing in [false, true] {
        with_pair(true, |client, _server| {
            let handle = client.enqueue_early_request(b"GET /pending\r\n").unwrap();
            if closing {
                client
                    .initiate_close(
                        hibana_quic::lifecycle::CloseReason::application(0, "test close").unwrap(),
                    )
                    .unwrap();
            } else {
                client.close().unwrap();
            }
            assert!(client.early_stream_id(handle).is_err());
            assert!(client.enqueue_early_request(b"GET /late\r\n").is_err());
        });
    }
}
#[test]
fn idle_version_negotiation_and_peer_close_retire_pending_early_intent() {
    for scenario in 0..3 {
        with_pair(true, |client, server| {
            let handle = client.enqueue_early_request(b"GET /pending\r\n").unwrap();
            let mut out = [0; 1500];
            let mut scratch = [0; 1500];
            match scenario {
                0 => {
                    client.timer(4_000_000).unwrap();
                    assert!(client.is_retired());
                }
                1 => {
                    let tx = client.transmit(&mut out).unwrap().unwrap();
                    client.adapter_result(tx, true, 0).unwrap();
                    let mut vn = [0; 27];
                    vn[0] = 0x80;
                    vn[5] = 8;
                    vn[6..14].copy_from_slice(b"client01");
                    vn[14] = 8;
                    vn[15..23].copy_from_slice(b"original");
                    vn[23..27].copy_from_slice(&0x6b3343cfu32.to_be_bytes());
                    assert!(client.receive(&vn, &mut scratch).is_err());
                    assert!(client.is_retired());
                }
                _ => {
                    let tx = client.transmit(&mut out).unwrap().unwrap();
                    client.adapter_result(tx, true, 0).unwrap();
                    server.receive(&out[..tx.len], &mut scratch).unwrap();
                    server
                        .initiate_close(
                            hibana_quic::lifecycle::CloseReason::transport(1, 0, "peer test")
                                .unwrap(),
                        )
                        .unwrap();
                    // The server already derived Handshake keys, but its
                    // ServerHello has not reached this client. Drive every
                    // level in the close round, including decryptable Initial.
                    let mut close_packets = 0;
                    for _ in 0..3 {
                        let Some(tx) = server.transmit(&mut out).unwrap() else {
                            break;
                        };
                        close_packets += 1;
                        server.adapter_result(tx, true, 0).unwrap();
                        client.receive(&out[..tx.len], &mut scratch).unwrap();
                    }
                    assert_eq!(close_packets, 2);
                    assert_ne!(
                        client.connection_state(),
                        hibana_quic::lifecycle::State::Active
                    );
                }
            }
            assert!(client.early_stream_id(handle).is_err());
            assert!(client.enqueue_early_request(b"GET /late\r\n").is_err());
        });
    }
}
#[test]
fn empty_configured_early_journal_closes_after_finished_without_stream_zero_conflict() {
    with_pair(true, |client, server| {
        let mut out = [0; 1500];
        let mut scratch = [0; 1500];
        for _ in 0..32 {
            for _ in 0..64 {
                let Some(tx) = client.transmit(&mut out).unwrap() else {
                    break;
                };
                client.adapter_result(tx, true, 0).unwrap();
                server.receive(&out[..tx.len], &mut scratch).unwrap();
            }
            for _ in 0..64 {
                let Some(tx) = server.transmit(&mut out).unwrap() else {
                    break;
                };
                server.adapter_result(tx, true, 0).unwrap();
                client.receive(&out[..tx.len], &mut scratch).unwrap();
            }
            if client.handshake_complete() && server.handshake_complete() {
                break;
            }
        }
        assert!(client.handshake_complete() && server.handshake_complete());
        assert!(client.enqueue_early_request(b"GET /late\r\n").is_err());
        let stream = client.open(true).unwrap();
        assert_eq!(stream.id(), 0);
        client.send(stream, b"GET /ordinary\r\n", true).unwrap();
    });
}

#[test]
fn rejecting_ee_preserves_a_pending_initial_adapter_callback() {
    with_raw_client_pair(false, |client, server| {
        let mut out = [0; 1500];
        let mut scratch = [0; 1500];
        let initial = client.transmit(&mut out).unwrap().unwrap();
        assert_eq!(
            initial.encryption_level(),
            hibana_quic::packet::EncryptionLevel::Initial
        );
        client.adapter_result(initial, true, 0).unwrap();
        server.receive(&out[..initial.len], &mut scratch).unwrap();
        let mut frame = [0; 64];
        let len = hibana_quic::packet::encode_frame(
            &hibana_quic::packet::Frame::Stream {
                id: 0,
                offset: 0,
                fin: true,
                data: b"GET /retained\r\n",
            },
            &mut frame,
        )
        .unwrap();
        let early = client
            .transmit_early_application(&frame[..len], &mut out)
            .unwrap()
            .unwrap();
        client.adapter_result(early, true, 0).unwrap();
        // The accepted early datagram is lost; retain the server's entire
        // rejecting flight until an independent Initial callback is pending.
        assert!(client.bytes_in_flight() >= early.len as u64);
        let deadline = client.next_deadline().unwrap();
        client.timer(deadline).unwrap();
        let pending = client.transmit(&mut out).unwrap().unwrap();
        assert_eq!(
            pending.encryption_level(),
            hibana_quic::packet::EncryptionLevel::Initial
        );
        let mut pending_bytes = [0; 1500];
        pending_bytes[..pending.len].copy_from_slice(&out[..pending.len]);
        for _ in 0..16 {
            let Some(tx) = server.transmit(&mut out).unwrap() else {
                break;
            };
            server.adapter_result(tx, true, 0).unwrap();
            client.receive(&out[..tx.len], &mut scratch).unwrap();
        }
        assert_eq!(client.tls().early_status(), EarlyStatus::Rejected);
        assert!(!client.is_retired());
        assert_eq!(
            client.bytes_in_flight(),
            0,
            "rejected early bytes remain in flight"
        );
        client.adapter_result(pending, true, deadline).unwrap();
        assert!(!client.is_retired());
        server
            .receive(&pending_bytes[..pending.len], &mut scratch)
            .unwrap();
    });
}

fn early_server_address() -> hibana_quic::path::Address {
    use std::net::{Ipv4Addr, SocketAddr};
    hibana_quic::path::Address {
        local: SocketAddr::from((Ipv4Addr::LOCALHOST, 443)),
        remote: SocketAddr::from((Ipv4Addr::LOCALHOST, 40000)),
    }
}
fn raw_server_receive(
    server: &mut Endpoint<'_, '_, '_, '_>,
    wire: &[u8],
    scratch: &mut [u8],
) -> Result<hibana_quic::handshake_endpoint::Received, hibana_quic::transport_endpoint::Error> {
    if server.network_path_state().is_some() {
        server.receive_from(wire, scratch, early_server_address(), None)
    } else {
        server.receive(wire, scratch)
    }
}
fn raw_initial(
    client: &mut HandshakeEndpoint<'_, '_, BoundedTls<'_, '_>>,
    server: &mut Endpoint<'_, '_, '_, '_>,
) {
    let mut wire = [0; 1500];
    let mut scratch = [0; 1500];
    let tx = client.transmit(&mut wire).unwrap().unwrap();
    client.adapter_result(tx, true, 0).unwrap();
    raw_server_receive(server, &wire[..tx.len], &mut scratch).unwrap();
}
fn raw_early(
    client: &mut HandshakeEndpoint<'_, '_, BoundedTls<'_, '_>>,
    frames: &[hibana_quic::packet::Frame<'_>],
    wire: &mut [u8; 1500],
) -> hibana_quic::handshake_endpoint::Transmit {
    let mut payload = [0; 1056];
    let mut n = 0;
    for frame in frames {
        n += hibana_quic::packet::encode_frame(frame, &mut payload[n..]).unwrap();
    }
    let tx = client
        .transmit_early_application(&payload[..n], wire)
        .unwrap()
        .unwrap();
    assert!(tx.is_early_data());
    client.adapter_result(tx, true, 0).unwrap();
    tx
}
fn raw_finish_before_one_rtt(
    client: &mut HandshakeEndpoint<'_, '_, BoundedTls<'_, '_>>,
    server: &mut Endpoint<'_, '_, '_, '_>,
) {
    let mut wire = [0; 1500];
    let mut scratch = [0; 1500];
    for _ in 0..32 {
        for _ in 0..64 {
            let Some(tx) = server.transmit(&mut wire).unwrap() else {
                break;
            };
            server.adapter_result(tx, true, 0).unwrap();
            client.receive(&wire[..tx.len], &mut scratch).unwrap();
        }
        for _ in 0..64 {
            let Some(tx) = client.transmit(&mut wire).unwrap() else {
                break;
            };
            client.adapter_result(tx, true, 0).unwrap();
            raw_server_receive(server, &wire[..tx.len], &mut scratch).unwrap();
            if server.handshake_complete() {
                assert!(client.handshake_complete());
                return;
            }
        }
    }
    panic!("handshake did not complete");
}

#[test]
fn deferred_controls_and_reset_are_held_until_finished_with_original_credit() {
    use hibana_quic::packet::Frame;
    with_raw_client_pair(true, |client, server| {
        raw_initial(client, server);
        let mut wire = [0; 1500];
        let mut scratch = [0; 1500];
        let tx = raw_early(
            client,
            &[
                Frame::Stream {
                    id: 0,
                    offset: 0,
                    fin: false,
                    data: b"secret",
                },
                Frame::MaxData { maximum: 9000 },
                Frame::ResetStream {
                    id: 0,
                    error_code: 17,
                    final_size: 6,
                },
            ],
            &mut wire,
        );
        assert_eq!(
            server
                .receive(&wire[..tx.len], &mut scratch)
                .unwrap()
                .authenticated,
            1
        );
        assert!(!server.handshake_complete());
        assert!(server.streams().lookup(0).is_err());
        assert_ne!(server.streams().peer_limits().max_data, 9000);
        raw_finish_before_one_rtt(client, server);
        let stream = server.streams().lookup(0).unwrap();
        let view = server.read(stream).unwrap();
        assert_eq!(view.reset, Some(17));
        assert!(view.first.is_empty() && view.second.is_empty());
        assert_eq!(server.streams().receive_charged(), 6);
        assert_eq!(server.streams().peer_limits().max_data, 9000);
    });
}

struct AckObservation {
    accepted: u64,
    dropped: u64,
    accepted_seen: bool,
    dropped_seen: bool,
}
impl hibana_quic::handshake_endpoint::ApplicationHandler for AckObservation {
    fn frame(&mut self, _: hibana_quic::packet::Frame<'_>) -> Result<(), streams::Error> {
        Ok(())
    }
    fn acknowledged(
        &mut self,
        ranges: hibana_quic::packet::AckRanges<'_>,
    ) -> Result<(), streams::Error> {
        for range in ranges.iter() {
            self.accepted_seen |= range.smallest <= self.accepted && self.accepted <= range.largest;
            self.dropped_seen |= range.smallest <= self.dropped && self.dropped <= range.largest;
        }
        Ok(())
    }
}

#[test]
fn deferred_capacity_drop_preserves_stream_bytes_and_same_packet_can_be_retried_after_finished() {
    use hibana_quic::packet::Frame;
    with_raw_client_pair(true, |client, server| {
        raw_initial(client, server);
        let mut wire = [0; 1500];
        let mut scratch = [0; 1500];
        let tx = raw_early(
            client,
            &[
                Frame::MaxData { maximum: 3000 },
                Frame::MaxData { maximum: 4000 },
                Frame::MaxData { maximum: 5000 },
            ],
            &mut wire,
        );
        assert_eq!(
            server
                .receive(&wire[..tx.len], &mut scratch)
                .unwrap()
                .authenticated,
            1
        );
        assert_eq!(server.admitted_early_packets(), 1);
        let dropped = raw_early(
            client,
            &[
                Frame::Stream {
                    id: 0,
                    offset: 0,
                    fin: true,
                    data: b"GET /retained\r\n",
                },
                Frame::MaxData { maximum: 6000 },
                Frame::MaxData { maximum: 7000 },
            ],
            &mut wire,
        );
        let mut retained = [0; 1500];
        retained[..dropped.len].copy_from_slice(&wire[..dropped.len]);
        assert_eq!(
            server
                .receive(&wire[..dropped.len], &mut scratch)
                .unwrap()
                .authenticated,
            0
        );
        assert!(server.streams().lookup(0).is_err());
        assert_eq!(server.admitted_early_packets(), 1);
        assert!(!server.is_retired());
        raw_finish_before_one_rtt(client, server);
        assert_eq!(server.streams().peer_limits().max_data, 5000);
        assert!(
            server.streams().lookup(0).is_err(),
            "capacity failure partially stored STREAM"
        );
        let mut ack = AckObservation {
            accepted: tx.packet_number.value,
            dropped: dropped.packet_number.value,
            accepted_seen: false,
            dropped_seen: false,
        };
        for _ in 0..32 {
            let Some(tx) = server.transmit(&mut wire).unwrap() else {
                break;
            };
            server.adapter_result(tx, true, 0).unwrap();
            client
                .receive_with(&wire[..tx.len], &mut scratch, &mut ack)
                .unwrap();
        }
        assert!(ack.accepted_seen, "accepted early packet was never ACKed");
        assert!(!ack.dropped_seen, "capacity-dropped early packet was ACKed");
        // The exact same AEAD packet and PN becomes admissible once slots free;
        // this separately proves the capacity drop did not mark it Seen.
        assert_eq!(
            server
                .receive(&retained[..dropped.len], &mut scratch)
                .unwrap()
                .authenticated,
            1
        );
        assert_eq!(server.admitted_early_packets(), 2);
        let stream = server.streams().lookup(0).unwrap();
        assert_eq!(server.read(stream).unwrap().first, b"GET /retained\r\n");
        assert_eq!(server.streams().peer_limits().max_data, 7000);
        assert_eq!(
            server
                .receive(&retained[..dropped.len], &mut scratch)
                .unwrap()
                .authenticated,
            0
        );
        assert_eq!(server.streams().receive_charged(), 15);
        assert_eq!(server.admitted_early_packets(), 2);
    });
}

#[test]
fn early_control_remembered_limit_direction_and_final_size_violations_are_rejected() {
    use hibana_quic::packet::Frame;
    for scenario in 0..7 {
        with_raw_client_pair(true, |client, server| {
            raw_initial(client, server);
            let one = match scenario {
                0 => Frame::ResetStream {
                    id: 0,
                    error_code: 1,
                    final_size: 1025,
                },
                1 => Frame::ResetStream {
                    id: 8,
                    error_code: 1,
                    final_size: 0,
                },
                2 => Frame::ResetStream {
                    id: 0,
                    error_code: 1,
                    final_size: 800,
                },
                3 => Frame::Stream {
                    id: 0,
                    offset: 0,
                    fin: false,
                    data: b"ten bytes!",
                },
                4 => Frame::StopSending {
                    id: 8,
                    error_code: 1,
                },
                5 => Frame::MaxStreamData {
                    id: 2,
                    maximum: 100,
                },
                _ => Frame::StreamDataBlocked { id: 8, limit: 100 },
            };
            let two = match scenario {
                2 => Frame::ResetStream {
                    id: 4,
                    error_code: 2,
                    final_size: 800,
                },
                3 => Frame::ResetStream {
                    id: 0,
                    error_code: 2,
                    final_size: 9,
                },
                _ => Frame::Ping,
            };
            let mut wire = [0; 1500];
            let mut scratch = [0; 1500];
            let tx = raw_early(client, &[one, two], &mut wire);
            assert!(server.receive(&wire[..tx.len], &mut scratch).is_err());
            assert_eq!(server.streams().receive_charged(), 0);
            assert_eq!(server.admitted_early_packets(), 0);
            assert!(!server.handshake_complete());
        });
    }
}

#[test]
fn only_authenticated_accepted_early_close_enters_draining_without_finished_or_delivery() {
    use hibana_quic::{
        lifecycle::State,
        packet::{EncryptionLevel, Frame},
    };
    for scenario in 0..3 {
        with_raw_client_pair(scenario != 2, |client, server| {
            raw_initial(client, server);
            let mut wire = [0; 1500];
            let mut scratch = [0; 1500];
            let reason = [b'r'; 300];
            let tx = raw_early(
                client,
                &[
                    Frame::Ping,
                    Frame::Stream {
                        id: 0,
                        offset: 0,
                        fin: true,
                        data: b"never deliver",
                    },
                    Frame::PathChallenge { data: &[3; 8] },
                    Frame::ConnectionClose {
                        error_code: 77,
                        frame_type: None,
                        reason: &reason,
                    },
                ],
                &mut wire,
            );
            if scenario == 1 {
                wire[tx.len - 1] ^= 1;
            }
            let result = server.receive(&wire[..tx.len], &mut scratch).unwrap();
            assert!(!server.handshake_complete());
            assert_eq!(server.streams().receive_charged(), 0);
            if scenario == 0 {
                assert_eq!(result.authenticated, 1);
                assert_eq!(server.admitted_early_packets(), 1);
                assert_eq!(server.connection_state(), State::Draining);
                let close = server.peer_close().unwrap();
                assert_eq!(close.error_code, 77);
                assert_eq!(close.frame_type, None);
                assert_eq!(close.protection, EncryptionLevel::ZeroRtt);
                assert!(server.transmit(&mut wire).unwrap().is_none());
            } else {
                assert_eq!(result.authenticated, 0);
                assert_eq!(server.admitted_early_packets(), 0);
                assert_eq!(server.connection_state(), State::Active);
                assert!(server.peer_close().is_none());
            }
        });
    }
}

#[test]
fn changed_fresh_limits_reject_old_early_control_and_fall_back_to_full_authentication() {
    use hibana_quic::packet::Frame;
    with_raw_client_pair_limits(true, true, |client, server| {
        assert_eq!(
            client.tls().remembered_early_limits().unwrap().max_data(),
            512
        );
        raw_initial(client, server);
        let mut wire = [0; 1500];
        let mut scratch = [0; 1500];
        // This stream/final size is valid only under the new2/1024 limits.
        // The production ticket's exact policy binding requires full fallback.
        let tx = raw_early(
            client,
            &[
                Frame::ResetStream {
                    id: 4,
                    error_code: 7,
                    final_size: 800,
                },
                Frame::Ping,
            ],
            &mut wire,
        );
        assert_eq!(
            server
                .receive(&wire[..tx.len], &mut scratch)
                .unwrap()
                .authenticated,
            0
        );
        assert_eq!(server.streams().receive_charged(), 0);
        assert_eq!(server.admitted_early_packets(), 0);
        raw_finish_before_one_rtt(client, server);
        assert!(!client.tls().is_resumed() && !server.tls().is_resumed());
        assert_eq!(client.tls().early_status(), EarlyStatus::Rejected);
        assert!(server.streams().lookup(4).is_err());
        assert_eq!(server.streams().receive_charged(), 0);
        assert_eq!(server.admitted_early_packets(), 0);
    });
}

#[test]
fn valid_early_packet_over_frame_budget_is_dropped_without_retirement_or_ack() {
    use hibana_quic::packet::Frame;
    with_raw_client_pair(true, |client, server| {
        raw_initial(client, server);
        let mut wire = [0; 1500];
        let mut scratch = [0; 1500];
        let accepted = raw_early(client, &[Frame::Ping], &mut wire);
        assert_eq!(
            server
                .receive(&wire[..accepted.len], &mut scratch)
                .unwrap()
                .authenticated,
            1
        );
        assert_eq!(server.admitted_early_packets(), 1);
        let dropped = raw_early(client, &[Frame::Ping; 129], &mut wire);
        assert_eq!(
            server
                .receive(&wire[..dropped.len], &mut scratch)
                .unwrap()
                .authenticated,
            0
        );
        assert_eq!(
            server.connection_state(),
            hibana_quic::lifecycle::State::Active
        );
        assert_eq!(server.streams().receive_charged(), 0);
        assert_eq!(server.admitted_early_packets(), 1);
        raw_finish_before_one_rtt(client, server);
        let mut ack = AckObservation {
            accepted: accepted.packet_number.value,
            dropped: dropped.packet_number.value,
            accepted_seen: false,
            dropped_seen: false,
        };
        for _ in 0..32 {
            let Some(tx) = server.transmit(&mut wire).unwrap() else {
                break;
            };
            server.adapter_result(tx, true, 0).unwrap();
            client
                .receive_with(&wire[..tx.len], &mut scratch, &mut ack)
                .unwrap();
        }
        assert!(ack.accepted_seen);
        assert!(!ack.dropped_seen);
        assert!(!server.is_retired());
        assert_eq!(server.admitted_early_packets(), 1);
    });
}

#[derive(Default)]
struct ControlObservation {
    reset: Option<(u64, u64, u64)>,
    path_response: Option<[u8; 8]>,
}
impl hibana_quic::handshake_endpoint::ApplicationHandler for ControlObservation {
    fn frame(&mut self, frame: hibana_quic::packet::Frame<'_>) -> Result<(), streams::Error> {
        if let hibana_quic::packet::Frame::ResetStream {
            id,
            error_code,
            final_size,
        } = frame
        {
            self.reset = Some((id, error_code, final_size));
        }
        if let hibana_quic::packet::Frame::PathResponse { data } = frame {
            self.path_response = Some(*data);
        }
        Ok(())
    }
    fn acknowledged(
        &mut self,
        _: hibana_quic::packet::AckRanges<'_>,
    ) -> Result<(), streams::Error> {
        Ok(())
    }
}
#[test]
fn legal_credit_blocked_and_stop_controls_use_finished_authority_and_real_reset_output() {
    use hibana_quic::packet::Frame;
    for scenario in 0..3 {
        with_raw_client_pair(true, |client, server| {
            raw_initial(client, server);
            let frames = match scenario {
                0 => [
                    Frame::MaxStreamData {
                        id: 0,
                        maximum: 4096,
                    },
                    Frame::StreamDataBlocked { id: 0, limit: 1024 },
                    Frame::MaxStreams {
                        bidirectional: true,
                        maximum: 4,
                    },
                    Frame::DataBlocked { limit: 1500 },
                ],
                1 => [
                    Frame::StopSending {
                        id: 0,
                        error_code: 13,
                    },
                    Frame::StreamsBlocked {
                        bidirectional: true,
                        limit: 2,
                    },
                    Frame::MaxData { maximum: 3000 },
                    Frame::Ping,
                ],
                _ => [
                    Frame::MaxStreams {
                        bidirectional: false,
                        maximum: 1,
                    },
                    Frame::StreamsBlocked {
                        bidirectional: false,
                        limit: 0,
                    },
                    Frame::DataBlocked { limit: 1500 },
                    Frame::Ping,
                ],
            };
            let mut wire = [0; 1500];
            let mut scratch = [0; 1500];
            let tx = raw_early(client, &frames, &mut wire);
            assert_eq!(
                server
                    .receive(&wire[..tx.len], &mut scratch)
                    .unwrap()
                    .authenticated,
                1
            );
            assert!(server.streams().lookup(0).is_err());
            raw_finish_before_one_rtt(client, server);
            assert_eq!(server.streams().receive_charged(), 0);
            match scenario {
                0 => {
                    let stream = server.streams().lookup(0).unwrap();
                    assert_eq!(
                        server.streams().send_credit(stream).unwrap().stream_limit,
                        4096
                    );
                    assert_eq!(server.streams().peer_limits().max_streams_bidi, 4);
                }
                1 => {
                    let stream = server.streams().lookup(0).unwrap();
                    assert_eq!(
                        server.streams().send_credit(stream),
                        Err(streams::Error::SendClosed)
                    );
                    let mut observed = ControlObservation::default();
                    for _ in 0..32 {
                        let Some(tx) = server.transmit(&mut wire).unwrap() else {
                            break;
                        };
                        server.adapter_result(tx, true, 0).unwrap();
                        client
                            .receive_with(&wire[..tx.len], &mut scratch, &mut observed)
                            .unwrap();
                    }
                    assert_eq!(observed.reset, Some((0, 13, 0)));
                }
                _ => assert_eq!(server.streams().peer_limits().max_streams_uni, 1),
            }
            assert!(!server.is_retired());
        });
    }
}

#[test]
fn managed_early_new_cid_and_challenge_release_after_finished_on_original_path() {
    use hibana_quic::packet::Frame;
    with_raw_managed_pair(|client, server| {
        raw_initial(client, server);
        let original = server.path_identity();
        let mut wire = [0; 1500];
        let mut scratch = [0; 1500];
        let tx = raw_early(
            client,
            &[
                Frame::NewConnectionId {
                    sequence: 1,
                    retire_prior_to: 0,
                    id: b"client02",
                    reset_token: &[7; 16],
                },
                Frame::PathChallenge { data: &[9; 8] },
            ],
            &mut wire,
        );
        assert_eq!(
            raw_server_receive(server, &wire[..tx.len], &mut scratch)
                .unwrap()
                .authenticated,
            1
        );
        assert!(!server.handshake_complete());
        raw_finish_before_one_rtt(client, server);
        let mut observed = ControlObservation::default();
        for _ in 0..32 {
            let Some(tx) = server.transmit(&mut wire).unwrap() else {
                break;
            };
            assert_eq!(tx.address, Some(early_server_address()));
            server.adapter_result(tx, true, 0).unwrap();
            client
                .receive_with(&wire[..tx.len], &mut scratch, &mut observed)
                .unwrap();
        }
        assert_eq!(observed.path_response, Some([9; 8]));
        assert_eq!(server.path_identity(), original);
        assert!(!server.is_retired());
    });
}

#[test]
fn managed_early_cid_admission_counts_held_ids_and_rejects_conflicts_before_stream_effects() {
    use hibana_quic::packet::Frame;
    for conflict in [false, true] {
        with_raw_managed_pair(|client, server| {
            raw_initial(client, server);
            let mut wire = [0; 1500];
            let mut scratch = [0; 1500];
            let first = raw_early(
                client,
                &[Frame::NewConnectionId {
                    sequence: 1,
                    retire_prior_to: 0,
                    id: b"client02",
                    reset_token: &[7; 16],
                }],
                &mut wire,
            );
            assert_eq!(
                raw_server_receive(server, &wire[..first.len], &mut scratch)
                    .unwrap()
                    .authenticated,
                1
            );
            let second = raw_early(
                client,
                &[
                    Frame::Stream {
                        id: 0,
                        offset: 0,
                        fin: true,
                        data: b"must stay absent",
                    },
                    Frame::NewConnectionId {
                        sequence: if conflict { 1 } else { 2 },
                        retire_prior_to: 0,
                        id: b"client03",
                        reset_token: &[8; 16],
                    },
                ],
                &mut wire,
            );
            assert!(raw_server_receive(server, &wire[..second.len], &mut scratch).is_err());
            assert_eq!(server.streams().receive_charged(), 0);
            assert!(!server.handshake_complete());
        });
    }
}

#[test]
fn managed_early_cid_retirement_floor_selects_a_real_replacement_destination() {
    use hibana_quic::packet::{Frame, Header, PacketIter};
    with_raw_managed_pair(|client, server| {
        raw_initial(client, server);
        let mut wire = [0; 1500];
        let mut scratch = [0; 1500];
        let tx = raw_early(
            client,
            &[Frame::NewConnectionId {
                sequence: 1,
                retire_prior_to: 1,
                id: b"client02",
                reset_token: &[7; 16],
            }],
            &mut wire,
        );
        assert_eq!(
            raw_server_receive(server, &wire[..tx.len], &mut scratch)
                .unwrap()
                .authenticated,
            1
        );
        raw_finish_before_one_rtt(client, server);
        let tx = server.transmit(&mut wire).unwrap().unwrap();
        assert_eq!(
            tx.encryption_level(),
            hibana_quic::packet::EncryptionLevel::OneRtt
        );
        let packet = PacketIter::new(&wire[..tx.len], 8, 8)
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        let Header::Short { destination_id, .. } = packet.header else {
            panic!("expected protected application packet");
        };
        assert_eq!(destination_id, b"client02");
        server.adapter_result(tx, true, 0).unwrap();
        assert!(!server.is_retired());
    });
}

#[test]
fn managed_early_retire_checks_advertisement_and_retains_original_packet_dcid() {
    use hibana_quic::packet::Frame;
    for scenario in 0..4 {
        with_raw_managed_pair(|client, server| {
            raw_initial(client, server);
            let mut wire = [0; 1500];
            let mut scratch = [0; 1500];
            let mut server_initial = [0; 1500];
            let mut initial_len = 0;
            if scenario != 0 {
                let tx = server.transmit(&mut wire).unwrap().unwrap();
                assert_eq!(
                    tx.encryption_level(),
                    hibana_quic::packet::EncryptionLevel::Initial
                );
                server.adapter_result(tx, true, 0).unwrap();
                initial_len = tx.len;
                server_initial[..tx.len].copy_from_slice(&wire[..tx.len]);
                if scenario != 3 {
                    client
                        .receive(&server_initial[..initial_len], &mut scratch)
                        .unwrap();
                }
            }
            let tx = raw_early(
                client,
                &[Frame::RetireConnectionId {
                    sequence: if scenario == 2 { 1 } else { 0 },
                }],
                &mut wire,
            );
            let result = raw_server_receive(server, &wire[..tx.len], &mut scratch);
            if scenario == 3 {
                assert_eq!(result.unwrap().authenticated, 1);
                // This Initial was accepted by the adapter before RETIRE, but
                // delivered afterward. Release must retain the original DCID,
                // rather than substitute the now-current server01 identity.
                client
                    .receive(&server_initial[..initial_len], &mut scratch)
                    .unwrap();
                raw_finish_before_one_rtt(client, server);
                assert!(!server.is_retired());
            } else {
                assert!(result.is_err());
                assert!(!server.handshake_complete());
            }
        });
    }
}
