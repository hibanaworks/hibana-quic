//! Unprotected Version Negotiation decisions around real encrypted BoundedTls packets.
use hibana::runtime::{SessionKitStorage, ids::SessionId};
use hibana_quic::{
    bounded_tls::{BoundedTls, ClientConfig, ServerConfig, SigningKey, Storage},
    carrier::{CarrierStorage, LocalCarrier},
    driver::{Driver, Roles},
    handshake::CryptoBuffer,
    handshake_endpoint::{Config, HandshakeEndpoint, Side},
    packet::encode_varint,
    protocol::*,
    tls_certificate::{CertificateDer, Limits, UnixTime, trust_anchor_from_der},
};
use p256::pkcs8::DecodePrivateKey;
use rand_core::OsRng;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    time::Duration,
};
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
fn parameters(id: &[u8], original: Option<&[u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0; 8];
    for (kind, value) in [(15, Some(id)), (0, original)] {
        if let Some(value) = value {
            let n = encode_varint(kind, &mut buf).unwrap();
            out.extend_from_slice(&buf[..n]);
            let n = encode_varint(value.len() as u64, &mut buf).unwrap();
            out.extend_from_slice(&buf[..n]);
            out.extend_from_slice(value);
        }
    }
    out
}
type Endpoint<'r, 's, 'c, 't> = HandshakeEndpoint<'r, 's, BoundedTls<'c, 't>>;
fn transfer(
    from: &mut Endpoint<'_, '_, '_, '_>,
    to: &mut Endpoint<'_, '_, '_, '_>,
    now: u64,
) -> usize {
    let mut out = [0; 1500];
    let mut scratch = [0; 1500];
    for count in 0..64 {
        let Some(tx) = from.transmit(&mut out).unwrap() else {
            return count;
        };
        from.adapter_result(tx, true, now).unwrap();
        let received = to.receive(&out[..tx.len], &mut scratch).unwrap();
        assert!(received.authenticated + received.discarded >= 1);
    }
    panic!("unbounded output")
}

fn idle_parameters(id: &[u8], original: Option<&[u8]>, timeout_ms: u64) -> Vec<u8> {
    let mut out = parameters(id, original);
    let mut encoded = [0; 8];
    let n = encode_varint(timeout_ms, &mut encoded).unwrap();
    out.extend_from_slice(&[1, n as u8]);
    out.extend_from_slice(&encoded[..n]);
    for (id, value) in [
        (4, 8_192),
        (5, 2_048),
        (6, 2_048),
        (7, 2_048),
        (8, 2),
        (9, 2),
    ] {
        let n = encode_varint(value, &mut encoded).unwrap();
        out.extend_from_slice(&[id, n as u8]);
        out.extend_from_slice(&encoded[..n]);
    }
    out
}
fn with_idle_pair(
    client_ms: u64,
    server_ms: u64,
    test: impl FnOnce(&mut Endpoint<'_, '_, '_, '_>, &mut Endpoint<'_, '_, '_, '_>),
) {
    with_owned_idle_pair(client_ms, server_ms, |mut client, mut server| {
        test(&mut client, &mut server)
    });
}
fn with_owned_idle_pair(
    client_ms: u64,
    server_ms: u64,
    test: impl FnOnce(Endpoint<'_, '_, '_, '_>, Endpoint<'_, '_, '_, '_>),
) {
    let id = identity();
    let anchors = [trust_anchor_from_der(&id.root).unwrap()];
    let chain = [id.leaf.as_ref()];
    let client_params = idle_parameters(b"client01", None, client_ms);
    let server_params = idle_parameters(b"server01", Some(b"original"), server_ms);
    let mut cb = Buffers::new();
    let mut sb = Buffers::new();
    // Caller-owned storage and test PKI setup precede the measurement.
    let mut client_slab = [0; hibana_quic::protocol::SERVICE_SLAB_BYTES];
    let mut server_slab = [0; hibana_quic::protocol::SERVICE_SLAB_BYTES];
    let mut cd = [[0; 8192]; 3];
    let mut cm = [[0; hibana_quic::handshake::bitmap_bytes(8192)]; 3];
    let mut sd = [[0; 8192]; 3];
    let mut sm = [[0; hibana_quic::handshake::bitmap_bytes(8192)]; 3];
    TRACK.with(|c| c.set(Some(0)));
    {
        let client_tls = BoundedTls::client(
            ClientConfig {
                server_name: "localhost",
                trust_anchors: &anchors,
                now: UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_000)),
                certificate_limits: Limits::default(),
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
        let cq = CarrierStorage::<8, 16, { hibana_quic::protocol::SERVICE_PORTS }>::new();
        let sq = CarrierStorage::<8, 16, { hibana_quic::protocol::SERVICE_PORTS }>::new();
        let mut ck = SessionKitStorage::<
            LocalCarrier<'_, 8, 16, { hibana_quic::protocol::SERVICE_PORTS }>,
        >::uninit();
        let mut sk = SessionKitStorage::<
            LocalCarrier<'_, 8, 16, { hibana_quic::protocol::SERVICE_PORTS }>,
        >::uninit();
        let crv = ck
            .init()
            .rendezvous(&mut client_slab, cq.bind(SessionId::new(1)).unwrap())
            .unwrap();
        let srv = sk
            .init()
            .rendezvous(&mut server_slab, sq.bind(SessionId::new(2)).unwrap())
            .unwrap();
        macro_rules! driver {
            ($rv:expr,$id:expr) => {
                Driver::new(
                    $id,
                    Roles {
                        ingress: $rv.enter(SessionId::new($id as u32), &p0).unwrap(),
                        packet: $rv.enter(SessionId::new($id as u32), &p1).unwrap(),
                        application: $rv.enter(SessionId::new($id as u32), &p2).unwrap(),
                        recovery: $rv.enter(SessionId::new($id as u32), &p3).unwrap(),
                        adapter: $rv.enter(SessionId::new($id as u32), &p4).unwrap(),
                        timer: $rv.enter(SessionId::new($id as u32), &p5).unwrap(),
                    },
                )
            };
        }
        let [d0, d1, d2] = &mut cd;
        let [m0, m1, m2] = &mut cm;
        let client_crypto = [
            CryptoBuffer::new(d0, m0).unwrap(),
            CryptoBuffer::new(d1, m1).unwrap(),
            CryptoBuffer::new(d2, m2).unwrap(),
        ];
        let [d0, d1, d2] = &mut sd;
        let [m0, m1, m2] = &mut sm;
        let server_crypto = [
            CryptoBuffer::new(d0, m0).unwrap(),
            CryptoBuffer::new(d1, m1).unwrap(),
            CryptoBuffer::new(d2, m2).unwrap(),
        ];
        let mut client = HandshakeEndpoint::new(
            Config {
                side: Side::Client,
                local_id: b"client01",
                original_destination_id: b"original",
                generation: 1,
            },
            client_tls,
            driver!(crv, 1),
            client_crypto,
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
            driver!(srv, 2),
            server_crypto,
        )
        .unwrap();
        client.configure_idle_timeout(client_ms).unwrap();
        server.configure_idle_timeout(server_ms).unwrap();
        test(client, server);
    }
    let allocations = TRACK.with(|counter| counter.replace(None).unwrap());
    assert_eq!(
        allocations, 0,
        "bounded construction, encrypted traffic, idle/error/drop paths"
    );
}
fn handshake(client: &mut Endpoint<'_, '_, '_, '_>, server: &mut Endpoint<'_, '_, '_, '_>) -> u64 {
    for turn in 1..64 {
        let now = turn * 1_000;
        client.timer(now).unwrap();
        server.timer(now).unwrap();
        let sent = transfer(client, server, now) + transfer(server, client, now);
        if client.handshake_complete() && server.handshake_complete() && sent == 0 {
            return now;
        }
    }
    panic!("handshake/control flight did not settle")
}

fn vn<'a>(out: &'a mut [u8], dcid: &[u8], scid: &[u8], versions: &[u32]) -> &'a [u8] {
    out[0] = 0x80; // All seven unused bits must be ignored, including Fixed Bit.
    out[1..5].fill(0);
    out[5] = dcid.len() as u8;
    out[6..6 + dcid.len()].copy_from_slice(dcid);
    let mut at = 6 + dcid.len();
    out[at] = scid.len() as u8;
    at += 1;
    out[at..at + scid.len()].copy_from_slice(scid);
    at += scid.len();
    for version in versions {
        out[at..at + 4].copy_from_slice(&version.to_be_bytes());
        at += 4;
    }
    &out[..at]
}
fn initial(client: &mut Endpoint<'_, '_, '_, '_>, out: &mut [u8]) -> usize {
    let tx = client.transmit(out).unwrap().unwrap();
    assert_eq!(tx.level, hibana_quic::tls::Level::Initial);
    client.adapter_result(tx, true, 0).unwrap();
    tx.len
}

#[test]
fn vn_abandons_only_after_initial_acceptance_and_never_restarts_or_authenticates() {
    use hibana_quic::{handshake_endpoint::Error, version_negotiation::ClientState};
    with_idle_pair(5_000, 5_000, |client, _| {
        let mut wire = [0; 128];
        let vn = vn(&mut wire, b"client01", b"original", &[0x6b33_43cf]);
        let mut scratch = [0; 1500];
        assert_eq!(client.receive(vn, &mut scratch).unwrap().authenticated, 0);
        assert_eq!(
            client.version_negotiation_state(),
            Some(ClientState::InitialNotSent)
        );
        let mut out = [0; 1500];
        let rejected = client.transmit(&mut out).unwrap().unwrap();
        assert_eq!(client.receive(vn, &mut scratch).unwrap().discarded, 1);
        client.adapter_result(rejected, false, 0).unwrap();
        assert_eq!(client.receive(vn, &mut scratch).unwrap().discarded, 1);
        assert_eq!(
            client.version_negotiation_state(),
            Some(ClientState::InitialNotSent)
        );
        initial(client, &mut out);
        assert_eq!(
            client.version_negotiation_state(),
            Some(ClientState::AwaitingPeer)
        );
        assert!(matches!(
            client.receive(vn, &mut scratch),
            Err(Error::VersionNegotiationNoCommonVersion)
        ));
        assert_eq!(
            client.version_negotiation_state(),
            Some(ClientState::Abandoned)
        );
        assert!(client.is_retired());
        assert_eq!(client.close_deadline(), None);
        assert!(!client.handshake_complete());
        assert!(matches!(client.transmit(&mut out), Err(Error::Retired)));
    });
}

#[test]
fn vn_containing_v1_wrong_cids_or_truncated_versions_cannot_derail_real_handshake() {
    use hibana_quic::version_negotiation::ClientState;
    with_idle_pair(5_000, 5_000, |client, server| {
        let mut sent = [0; 1500];
        let len = initial(client, &mut sent);
        let mut wire = [0; 128];
        let mut scratch = [0; 1500];
        for (dcid, scid, versions) in [
            (b"client01".as_slice(), b"original".as_slice(), &[1][..]),
            (
                b"client01".as_slice(),
                b"original".as_slice(),
                &[2, 1, 3][..],
            ),
            (b"wrongcid".as_slice(), b"original".as_slice(), &[2][..]),
            (b"client01".as_slice(), b"wrongcid".as_slice(), &[2][..]),
        ] {
            let packet = vn(&mut wire, dcid, scid, versions);
            let report = client.receive(packet, &mut scratch).unwrap();
            assert_eq!(report.authenticated, 0);
            assert_eq!(report.discarded, 1);
            assert_eq!(
                client.version_negotiation_state(),
                Some(ClientState::AwaitingPeer)
            );
        }
        let packet = vn(&mut wire, b"client01", b"original", &[2]);
        assert_eq!(
            client
                .receive(&packet[..packet.len() - 1], &mut scratch)
                .unwrap()
                .authenticated,
            0
        );
        assert_eq!(
            client.version_negotiation_state(),
            Some(ClientState::AwaitingPeer)
        );
        server.receive(&sent[..len], &mut scratch).unwrap();
        handshake(client, server);
        assert!(client.handshake_complete() && server.handshake_complete());
    });
}

#[test]
fn authenticated_initial_closes_vn_window_before_tls_handshake_finishes() {
    use hibana_quic::version_negotiation::ClientState;
    with_idle_pair(5_000, 5_000, |client, server| {
        let mut out = [0; 1500];
        let mut scratch = [0; 1500];
        let n = initial(client, &mut out);
        server.receive(&out[..n], &mut scratch).unwrap();
        let reply = server.transmit(&mut out).unwrap().unwrap();
        assert_eq!(reply.level, hibana_quic::tls::Level::Initial);
        server.adapter_result(reply, true, 0).unwrap();
        assert_eq!(
            client
                .receive(&out[..reply.len], &mut scratch)
                .unwrap()
                .authenticated,
            1
        );
        assert!(!client.handshake_complete());
        assert_eq!(
            client.version_negotiation_state(),
            Some(ClientState::PeerPacketProcessed)
        );
        let mut wire = [0; 128];
        let packet = vn(&mut wire, b"client01", b"original", &[2]);
        assert_eq!(client.receive(packet, &mut scratch).unwrap().discarded, 1);
        assert!(!client.is_retired());
        handshake(client, server);
        assert!(client.handshake_complete() && server.handshake_complete());
        assert_eq!(client.receive(packet, &mut scratch).unwrap().discarded, 1);
        assert!(client.handshake_complete());
    });
}

#[test]
fn corrupt_initial_cannot_count_as_successful_peer_processing() {
    use hibana_quic::{handshake_endpoint::Error, version_negotiation::ClientState};
    with_idle_pair(5_000, 5_000, |client, server| {
        let mut out = [0; 1500];
        let mut scratch = [0; 1500];
        let n = initial(client, &mut out);
        server.receive(&out[..n], &mut scratch).unwrap();
        let reply = server.transmit(&mut out).unwrap().unwrap();
        server.adapter_result(reply, true, 0).unwrap();
        out[reply.len - 1] ^= 1;
        assert_eq!(
            client
                .receive(&out[..reply.len], &mut scratch)
                .unwrap()
                .authenticated,
            0
        );
        assert_eq!(
            client.version_negotiation_state(),
            Some(ClientState::AwaitingPeer)
        );
        let mut wire = [0; 128];
        let packet = vn(&mut wire, b"client01", b"original", &[2]);
        assert!(matches!(
            client.receive(packet, &mut scratch),
            Err(Error::VersionNegotiationNoCommonVersion)
        ));
    });
}

#[test]
fn valid_retry_closes_vn_window_without_claiming_authenticated_tls() {
    use hibana_quic::{retry, version_negotiation::ClientState};
    with_idle_pair(5_000, 5_000, |client, _| {
        let mut out = [0; 1500];
        let mut scratch = [0; 1500];
        initial(client, &mut out);
        let n = retry::encode_retry(
            b"original",
            b"client01",
            b"retry001",
            b"opaque",
            5,
            &mut out,
            &mut scratch,
        )
        .unwrap();
        let valid = out;
        out[n - 1] ^= 1;
        assert_eq!(
            client
                .receive(&out[..n], &mut scratch)
                .unwrap()
                .authenticated,
            0
        );
        assert_eq!(
            client.version_negotiation_state(),
            Some(ClientState::AwaitingPeer)
        );
        assert_eq!(
            client
                .receive(&valid[..n], &mut scratch)
                .unwrap()
                .authenticated,
            0
        );
        assert_eq!(client.retry_source_id(), Some(b"retry001".as_slice()));
        assert_eq!(
            client.version_negotiation_state(),
            Some(ClientState::PeerPacketProcessed)
        );
        let mut wire = [0; 128];
        let packet = vn(&mut wire, b"client01", b"original", &[2]);
        assert_eq!(client.receive(packet, &mut scratch).unwrap().discarded, 1);
        assert!(!client.is_retired());
        assert!(!client.handshake_complete());
    });
}

#[test]
fn server_ignores_vn_without_response_or_peer_authentication() {
    with_idle_pair(5_000, 5_000, |_, server| {
        let mut out = [0; 1500];
        let mut scratch = [0; 1500];
        let packet = vn(&mut out, b"server01", b"original", &[2]);
        let report = server.receive(packet, &mut scratch).unwrap();
        assert_eq!(report.authenticated, 0);
        assert_eq!(report.discarded, 1);
        assert_eq!(server.version_negotiation_state(), None);
        assert!(server.transmit(&mut out).unwrap().is_none());
        assert!(!server.is_retired());
    });
}

#[test]
fn listener_real_entropy_bounded_responses_and_failures_allocate_zero() {
    use hibana_quic::version_negotiation::{
        DiscardReason, Error, Listener, ListenerAction, MAX_RESPONSE_BYTES,
    };
    let mut input = [0; 1200];
    input[0] = 0x80;
    input[1..5].copy_from_slice(&0x6b33_43cf_u32.to_be_bytes());
    input[5] = 8;
    input[6..14].copy_from_slice(b"original");
    input[14] = 8;
    input[15..23].copy_from_slice(b"client01");
    let mut out = [0; MAX_RESPONSE_BYTES];
    let mut rng = OsRng;
    TRACK.with(|counter| counter.set(Some(0)));
    {
        let mut listener = Listener::new(1200, 2, 1_000_000).unwrap();
        assert_eq!(
            listener.on_datagram(0, &input, &mut rng, &mut []),
            Err(Error::Capacity)
        );
        for at in [0, 1] {
            assert!(matches!(
                listener.on_datagram(at, &input, &mut rng, &mut out),
                Ok(ListenerAction::Send { len: 27 })
            ));
        }
        assert_eq!(
            listener.on_datagram(2, &input, &mut rng, &mut out),
            Ok(ListenerAction::Discard(DiscardReason::RateLimited))
        );
        assert_eq!(
            listener.on_datagram(1, &input, &mut rng, &mut out),
            Err(Error::TimeWentBackwards)
        );
        assert!(matches!(
            listener.on_datagram(1_000_000, &input, &mut rng, &mut out),
            Ok(ListenerAction::Send { len: 27 })
        ));
    }
    let allocations = TRACK.with(|counter| counter.replace(None).unwrap());
    assert_eq!(allocations, 0);
}
