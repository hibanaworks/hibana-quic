//! Real encrypted endpoint idle-timeout tests; fixture PKI/buffers precede allocation tracking.
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

#[derive(Default)]
struct MaxDataHandler {
    delivered: usize,
}
impl hibana_quic::handshake_endpoint::ApplicationHandler for MaxDataHandler {
    fn frame(
        &mut self,
        frame: hibana_quic::packet::Frame<'_>,
    ) -> Result<(), hibana_quic::streams::Error> {
        assert!(matches!(frame, hibana_quic::packet::Frame::MaxData { .. }));
        self.delivered += 1;
        Ok(())
    }
    fn acknowledged(
        &mut self,
        _: hibana_quic::packet::AckRanges<'_>,
    ) -> Result<(), hibana_quic::streams::Error> {
        Ok(())
    }
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

#[test]
fn idle_negotiation_uses_authenticated_nonzero_minimum_without_allocations() {
    for (local, peer, expected) in [
        (8_000, 5_000, 5_000),
        (0, 5_000, 5_000),
        (8_000, 0, 8_000),
        (0, 0, 0),
    ] {
        with_idle_pair(local, peer, |client, server| {
            assert_eq!(client.idle_timeout_ms(), local);
            assert_eq!(server.idle_timeout_ms(), peer);
            handshake(client, server);
            assert_eq!(client.idle_timeout_ms(), expected);
            assert_eq!(server.idle_timeout_ms(), expected);
            assert_eq!(client.idle_deadline().is_none(), expected == 0);
            assert_eq!(server.idle_deadline().is_none(), expected == 0);
        });
    }
}

#[test]
fn idle_activity_requires_valid_receive_or_first_actual_eliciting_send() {
    with_idle_pair(5_000, 8_000, |client, server| {
        let now = handshake(client, server);
        let mut out = [0; 1500];
        let mut scratch = [0; 1500];
        let mut handler = MaxDataHandler::default();
        let client_before = client.idle_deadline().unwrap();
        let server_before = server.idle_deadline().unwrap();
        let at = now + 10_000;
        client.timer(at).unwrap();
        server.timer(at).unwrap();
        let rejected = client
            .transmit_application(&[0x10, 1], &mut out)
            .unwrap()
            .unwrap();
        assert_eq!(client.idle_deadline(), Some(client_before));
        client.adapter_result(rejected, false, at).unwrap();
        assert_eq!(client.idle_deadline(), Some(client_before));
        let accepted = client
            .transmit_application(&[0x10, 1], &mut out)
            .unwrap()
            .unwrap();
        client.adapter_result(accepted, true, at).unwrap();
        assert_eq!(client.idle_deadline(), Some(at + 5_000_000));
        let first_send_deadline = client.idle_deadline();
        let valid = out;
        out[accepted.len - 1] ^= 1;
        assert_eq!(
            server
                .receive_with(&out[..accepted.len], &mut scratch, &mut handler)
                .unwrap()
                .authenticated,
            0
        );
        assert_eq!(server.idle_deadline(), Some(server_before));
        assert_eq!(handler.delivered, 0);
        assert_eq!(
            server
                .receive_with(&valid[..accepted.len], &mut scratch, &mut handler)
                .unwrap()
                .authenticated,
            1
        );
        assert_eq!(server.idle_deadline(), Some(at + 5_000_000));
        assert_eq!(handler.delivered, 1);
        server.timer(at + 1_000).unwrap();
        assert_eq!(
            server
                .receive_with(&valid[..accepted.len], &mut scratch, &mut handler)
                .unwrap()
                .authenticated,
            0
        );
        assert_eq!(server.idle_deadline(), Some(at + 5_000_000));
        client.timer(at + 2_000).unwrap();
        let second = client
            .transmit_application(&[0x10, 2], &mut out)
            .unwrap()
            .unwrap();
        client.adapter_result(second, true, at + 2_000).unwrap();
        assert_eq!(client.idle_deadline(), first_send_deadline);
        // The server's ACK-only response does not consume its send allowance or
        // restart its timer; its successful processing does restart the client.
        server.timer(at + 2_000).unwrap();
        let ack = server.transmit(&mut out).unwrap().unwrap();
        server.adapter_result(ack, true, at + 2_000).unwrap();
        assert_eq!(server.idle_deadline(), Some(at + 5_000_000));
        assert_eq!(
            client
                .receive(&out[..ack.len], &mut scratch)
                .unwrap()
                .authenticated,
            1
        );
        assert_eq!(client.idle_deadline(), Some(at + 2_000 + 5_000_000));
        client.timer(at + 3_000).unwrap();
        let third = client
            .transmit_application(&[0x10, 3], &mut out)
            .unwrap()
            .unwrap();
        client.adapter_result(third, true, at + 3_000).unwrap();
        assert_eq!(client.idle_deadline(), Some(at + 3_000 + 5_000_000));
    });
}

#[test]
fn idle_expiry_silently_invalidates_prepared_output_and_discards_keys() {
    use hibana_quic::{
        lifecycle::State,
        tls::{Level, Provider},
    };
    with_idle_pair(5_000, 5_000, |client, server| {
        let now = handshake(client, server);
        let mut out = [0; 1500];
        client.timer(now + 1_000).unwrap();
        let prepared = client
            .transmit_application(&[0x10, 1], &mut out)
            .unwrap()
            .unwrap();
        let deadline = client.idle_deadline().unwrap();
        assert!(client.next_deadline().unwrap() <= deadline);
        client.timer(deadline).unwrap();
        assert!(client.idle_expired());
        assert!(client.is_retired());
        assert_eq!(client.connection_state(), State::Closed);
        assert_eq!(client.close_deadline(), None);
        assert_eq!(client.next_deadline(), None);
        assert!(!client.transmit_permitted(prepared, deadline).unwrap());
        assert!(client.adapter_result(prepared, true, deadline).is_err());
        assert!(client.transmit(&mut out).is_err());
        assert!(!client.tls().has_keys(Level::Handshake));
        assert!(!client.tls().has_keys(Level::OneRtt));
    });
}

#[test]
fn queued_idle_timers_reject_foreign_and_superseded_descriptors_without_clock_effects() {
    use hibana_quic::{handshake_endpoint::Error, idle};
    with_idle_pair(5_000, 5_000, |client, server| {
        let old = client.idle_deadline_token().unwrap();
        let foreign = server.idle_deadline_token().unwrap();
        assert!(matches!(
            client.idle_timeout(foreign, u64::MAX),
            Err(Error::Idle(idle::Error::StaleTimer))
        ));
        let now = handshake(client, server);
        assert!(matches!(
            client.idle_timeout(old, u64::MAX),
            Err(Error::Idle(idle::Error::StaleTimer))
        ));
        client.timer(now + 1).unwrap();
        let current = client.idle_deadline_token().unwrap();
        assert!(matches!(
            client.idle_timeout(current, now + 1),
            Err(Error::Idle(idle::Error::TimerNotDue))
        ));
        client.idle_timeout(current, current.at()).unwrap();
        assert!(client.idle_expired());
        assert!(matches!(
            client.idle_timeout(current, u64::MAX),
            Err(Error::Idle(idle::Error::StaleTimer))
        ));
    });
}

#[test]
fn idle_setup_freezes_before_io_and_closing_uses_its_own_retention() {
    use hibana_quic::lifecycle::{CloseReason, State};
    with_idle_pair(5_000, 5_000, |client, server| {
        let now = handshake(client, server);
        assert!(client.configure_idle_timeout(50).is_err());
        let token = client.idle_deadline_token().unwrap();
        client
            .close(CloseReason::application(0, "done").unwrap())
            .unwrap();
        assert_eq!(client.idle_deadline(), None);
        let close_deadline = client.close_deadline().unwrap();
        assert!(client.idle_timeout(token, u64::MAX).is_err());
        let mut out = [0; 1500];
        let prepared = client.transmit(&mut out).unwrap().unwrap();
        assert_eq!(client.connection_state(), State::Closing);
        assert!(client.transmit_permitted(prepared, now).unwrap());
        client.timer(close_deadline).unwrap();
        assert_eq!(client.connection_state(), State::Closed);
        assert!(!client.idle_expired());
        assert!(!client.transmit_permitted(prepared, close_deadline).unwrap());
    });
}

#[test]
fn transport_pending_stream_output_cannot_pin_an_idle_connection() {
    use hibana_quic::{
        lifecycle::State,
        streams::{self, Limits, PacketReference, SendChunk, StreamSlot},
        transport_endpoint::TransportEndpoint,
    };
    for expire_via in 0..3 {
        with_owned_idle_pair(5_000, 5_000, |mut client, mut server| {
            let now = handshake(&mut client, &mut server);
            let deadline = client.idle_deadline().unwrap();
            let mut slots = [const { StreamSlot::<2048>::EMPTY }; 8];
            let mut chunks = [const { SendChunk::<64>::EMPTY }; 4];
            let mut references = [PacketReference::EMPTY; 8];
            let mut client = TransportEndpoint::<_, 2048, 64>::new(
                client,
                Limits {
                    max_data: 8_192,
                    stream_data_bidi_local: 2_048,
                    stream_data_bidi_remote: 2_048,
                    stream_data_uni: 2_048,
                    max_streams_bidi: 2,
                    max_streams_uni: 2,
                },
                &mut slots,
                &mut chunks,
                &mut references,
                77,
            )
            .unwrap();
            client.timer(now + 1_000).unwrap();
            let stream = client.open(true).unwrap();
            client.send(stream, b"pending", false).unwrap();
            let mut bytes = [0; 1500];
            let prepared = client.transmit(&mut bytes).unwrap().unwrap();
            match expire_via {
                0 => client.timer(deadline).unwrap(),
                1 => assert!(!client.transmit_permitted(prepared, deadline).unwrap()),
                _ => assert!(client.adapter_result(prepared, true, deadline).is_err()),
            }
            assert_eq!(client.connection_state(), State::Closed);
            assert_eq!(client.close_deadline(), None);
            assert_eq!(client.next_deadline(), None);
            assert!(client.is_retired());
            assert!(matches!(
                client.read(stream),
                Err(hibana_quic::transport_endpoint::Error::Streams(
                    streams::Error::Closed
                ))
            ));
            assert!(!client.transmit_permitted(prepared, deadline).unwrap());
            assert!(client.adapter_result(prepared, true, deadline).is_err());
            assert!(client.transmit(&mut bytes).is_err());
        });
    }
}
