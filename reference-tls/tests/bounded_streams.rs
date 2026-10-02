//! Full bounded TLS/QUIC/stream/Hibana allocation and recovery tests.
//! PKI fixture generation/import, caller storage preparation and test harness are
//! outside the counter; constructors, runtime rendezvous, handshake, streaming,
//! key updates, local retirement and provider/runtime drops are inside it.
use hibana::runtime::{SessionKitStorage, ids::SessionId};
use hibana_quic::{
    bounded_tls::{BoundedTls, ClientConfig, ServerConfig, SigningKey, Storage},
    carrier::{CarrierStorage, LocalCarrier},
    driver::{Driver, Roles},
    handshake::CryptoBuffer,
    handshake_endpoint::{Config, HandshakeEndpoint, Side},
    packet::encode_varint,
    protocol::*,
    streams::{self, Limits, PacketReference, SendChunk, StreamSlot},
    tls_certificate::{
        CertificateDer, Limits as CertificateLimits, UnixTime, trust_anchor_from_der,
    },
    transport_endpoint::{self as transport, TransportEndpoint},
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
fn with_pair(
    valid_root: bool,
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
    let wrong = identity();
    let root = if valid_root { &id.root } else { &wrong.root };
    let anchors = [trust_anchor_from_der(root).unwrap()];
    let chain = [id.leaf.as_ref()];
    let client_params = parameters(b"client01", None, limits);
    let server_params = parameters(b"server01", Some(b"original"), limits);
    let mut cb = Buffers::new();
    let mut sb = Buffers::new();
    let client_queue = CarrierStorage::<8, 16, { hibana_quic::protocol::SERVICE_PORTS }>::new();
    let server_queue = CarrierStorage::<8, 16, { hibana_quic::protocol::SERVICE_PORTS }>::new();
    let mut client_slab = [0; 32768];
    let mut server_slab = [0; 32768];
    let mut client_kit = SessionKitStorage::<LocalCarrier<'_, 8, 16, { hibana_quic::protocol::SERVICE_PORTS }>>::uninit();
    let mut server_kit = SessionKitStorage::<LocalCarrier<'_, 8, 16, { hibana_quic::protocol::SERVICE_PORTS }>>::uninit();
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
        let client_tls = BoundedTls::client(
            ClientConfig {
                server_name: "localhost",
                trust_anchors: &anchors,
                now: UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_000)),
                certificate_limits: CertificateLimits::default(),
                transport_parameters: &client_params,
            },
            cb.storage(),
            &mut OsRng,
        )
        .unwrap();
        let server_tls = BoundedTls::server(
            ServerConfig {
                certificate_chain: &chain,
                signing_key: &id.signing,
                transport_parameters: &server_params,
            },
            sb.storage(),
            &mut OsRng,
        )
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
fn transfer(
    from: &mut Endpoint<'_, '_, '_, '_>,
    to: &mut Endpoint<'_, '_, '_, '_>,
    now: u64,
) -> usize {
    let mut out = [0; 1500];
    let mut scratch = [0; 1500];
    for n in 0..64 {
        let Some(tx) = from.transmit(&mut out).unwrap() else {
            return n;
        };
        from.adapter_result(tx, true, now).unwrap();
        to.receive(&out[..tx.len], &mut scratch).unwrap();
    }
    panic!("bounded transfer failed to yield")
}
fn pump(client: &mut Endpoint<'_, '_, '_, '_>, server: &mut Endpoint<'_, '_, '_, '_>, now: u64) {
    client.timer(now).unwrap();
    server.timer(now).unwrap();
    for _ in 0..32 {
        let a = transfer(client, server, now);
        let b = transfer(server, client, now);
        if a + b == 0 {
            return;
        }
    }
    panic!("wire did not become idle")
}
fn handshake(client: &mut Endpoint<'_, '_, '_, '_>, server: &mut Endpoint<'_, '_, '_, '_>) {
    pump(client, server, 0);
    assert!(client.handshake_complete());
    assert!(server.handshake_complete());
}

#[test]
fn full_bounded_five_mebibyte_stream_loss_corruption_key_updates_and_retirement_allocate_zero() {
    with_pair(true, |client, server| {
        handshake(client, server);
        let request = client.open(true).unwrap();
        client.send(request, b"GET /five-mib\r\n", true).unwrap();
        let mut out = [0; 1500];
        let mut scratch = [0; 1500];
        let first = client.transmit(&mut out).unwrap().unwrap();
        client.adapter_result(first, true, 1).unwrap();
        out[first.len - 1] ^= 1;
        assert_eq!(
            server
                .receive(&out[..first.len], &mut scratch)
                .unwrap()
                .authenticated,
            0
        );
        assert_eq!(
            server.streams().lookup(request.id()),
            Err(streams::Error::NotOpened)
        );
        let mut now = client.next_deadline().expect("lost request PTO");
        client.timer(now).unwrap();
        server.timer(now).unwrap();
        let replay = client.transmit(&mut out).unwrap().unwrap();
        assert!(replay.packet_number.value > first.packet_number.value);
        client.adapter_result(replay, true, now).unwrap();
        server.receive(&out[..replay.len], &mut scratch).unwrap();
        assert_eq!(
            server
                .receive(&out[..replay.len], &mut scratch)
                .unwrap()
                .discarded,
            1
        );
        pump(client, server, now);
        let response = server.streams().lookup(request.id()).unwrap();
        let view = server.read(response).unwrap();
        assert_eq!(view.first, b"GET /five-mib\r\n");
        assert!(view.fin);
        server.consume(response, 15).unwrap();
        pump(client, server, now);
        const BLOCKS: usize = 5 * 1024;
        for i in 0..BLOCKS {
            now += 100;
            if i == 1024 || i == 3072 {
                now += 10_000_000;
                pump(client, server, now);
                if i == 1024 {
                    server.initiate_key_update().unwrap();
                } else {
                    client.initiate_key_update().unwrap();
                }
            }
            let block = [(i % 251) as u8; 1024];
            server.send(response, &block, i + 1 == BLOCKS).unwrap();
            if i == 256 {
                // Lose an accepted stream packet and corrupt a copy. Only a
                // freshly numbered PTO retransmission may reach the owner.
                let sent = server.transmit(&mut out).unwrap().unwrap();
                server.adapter_result(sent, true, now).unwrap();
                out[sent.len - 1] ^= 1;
                assert_eq!(
                    client
                        .receive(&out[..sent.len], &mut scratch)
                        .unwrap()
                        .authenticated,
                    0
                );
                assert!(client.read(request).unwrap().first.is_empty());
                now = server.next_deadline().unwrap().max(now);
                client.timer(now).unwrap();
                server.timer(now).unwrap();
                let replay = server.transmit(&mut out).unwrap().unwrap();
                assert!(replay.packet_number.value > sent.packet_number.value);
                server.adapter_result(replay, true, now).unwrap();
                client.receive(&out[..replay.len], &mut scratch).unwrap();
            }
            if i == 512 {
                let rejected = server.transmit(&mut out).unwrap().unwrap();
                server.adapter_result(rejected, false, now).unwrap();
                let fresh = server.transmit(&mut out).unwrap().unwrap();
                assert!(fresh.packet_number.value > rejected.packet_number.value);
                server.adapter_result(fresh, true, now).unwrap();
                client.receive(&out[..fresh.len], &mut scratch).unwrap();
            }
            pump(client, server, now);
            let view = client.read(request).unwrap();
            assert_eq!(view.first, &block);
            assert!(view.second.is_empty());
            assert_eq!(view.fin, i + 1 == BLOCKS);
            client.consume(request, 1024).unwrap();
            pump(client, server, now);
        }
        assert_eq!(client.streams().receive_charged(), 5 * 1024 * 1024);
        assert_eq!(client.key_generation(), 2);
        assert_eq!(server.key_generation(), 2);
        assert_eq!(client.receive_key_generation(), 2);
        assert_eq!(server.receive_key_generation(), 2);
        client.retire_stream(request).unwrap();
        server.retire_stream(response).unwrap();
        pump(client, server, now + 1);
        assert_eq!(
            client.streams().lookup(request.id()),
            Err(streams::Error::Retired)
        );
        assert_eq!(
            server.streams().lookup(request.id()),
            Err(streams::Error::Retired)
        );
        assert_eq!(client.streams().live_count(), 0);
        assert_eq!(server.streams().live_count(), 0);
    });
}

#[test]
fn bounded_transport_bad_ca_fails_terminally_and_drops_without_allocating() {
    with_pair(false, |client, server| {
        transfer(client, server, 0);
        let mut out = [0; 1500];
        let mut scratch = [0; 1500];
        let mut rejected = false;
        for _ in 0..32 {
            let Some(tx) = server.transmit(&mut out).unwrap() else {
                break;
            };
            server.adapter_result(tx, true, 0).unwrap();
            if let Err(error) = client.receive(&out[..tx.len], &mut scratch) {
                assert!(matches!(
                    error,
                    transport::Error::Engine(hibana_quic::handshake_endpoint::Error::Tls(
                        hibana_quic::tls::Error::Authentication
                    ))
                ));
                rejected = true;
                break;
            }
        }
        assert!(rejected);
        assert!(client.is_retired());
        assert!(!client.handshake_complete());
        assert!(client.open(true).is_err());
    });
}
