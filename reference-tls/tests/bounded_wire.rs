//! Real QUIC packet/Hibana integration using BoundedTls at both endpoints.
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

#[test]
fn bounded_tls_quic_wire_hibana_corruption_loss_recovery_and_1rtt_allocate_zero() {
    run_bounded_wire(None);
}
#[test]
fn real_trace_covers_authenticated_packets_keys_and_rejects_phantom_sends() {
    run_bounded_wire(Some(32768));
}
#[test]
fn trace_capacity_loss_is_sticky_and_never_changes_transport_outcome() {
    run_bounded_wire(Some(512));
}
fn run_bounded_wire(trace_capacity: Option<usize>) {
    let id = identity();
    let anchors = [trust_anchor_from_der(&id.root).unwrap()];
    let chain = [id.leaf.as_ref()];
    let client_params = parameters(b"client01", None);
    let server_params = parameters(b"server01", Some(b"original"));
    let mut cb = Buffers::new();
    let mut sb = Buffers::new();
    // Caller-owned storage and test PKI setup precede the measurement.
    let mut client_slab = [0; 32768];
    let mut server_slab = [0; 32768];
    let mut cd = [[0; 8192]; 3];
    let mut cm = [[0; hibana_quic::handshake::bitmap_bytes(8192)]; 3];
    let mut sd = [[0; 8192]; 3];
    let mut sm = [[0; hibana_quic::handshake::bitmap_bytes(8192)]; 3];
    let mut client_trace = [0; 32768];
    let mut server_trace = [0; 32768];
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
        if let Some(capacity) = trace_capacity {
            client.enable_trace(&mut client_trace[..capacity]).unwrap();
            server.enable_trace(&mut server_trace[..capacity]).unwrap();
        }
        let mut out = [0; 1500];
        let mut scratch = [0; 1500];
        let first = client.transmit(&mut out).unwrap().unwrap();
        client.adapter_result(first, true, 0).unwrap();
        let after_send = client.trace_status();
        assert!(client.adapter_result(first, true, 0).is_err());
        assert_eq!(
            client.trace_status(),
            after_send,
            "stale callback fabricated a send"
        );
        let original = out;
        out[first.len - 1] ^= 1;
        assert_eq!(
            server
                .receive(&out[..first.len], &mut scratch)
                .unwrap()
                .authenticated,
            0
        );
        assert!(!server.is_retired());
        if let Some(status) = server.trace_status() {
            assert_eq!(
                status.recorded_events, 0,
                "corrupt ciphertext fabricated authenticated receive"
            );
        }
        assert_eq!(server.tls().failed_authentications(), 1);
        let deadline = client.next_deadline().unwrap();
        client.timer(deadline).unwrap();
        server.timer(deadline).unwrap();
        let replay = client.transmit(&mut out).unwrap().unwrap();
        assert_ne!(&out[..replay.len], &original[..first.len]);
        client.adapter_result(replay, true, deadline).unwrap();
        assert_eq!(
            server
                .receive(&out[..replay.len], &mut scratch)
                .unwrap()
                .authenticated,
            1
        );
        let mut count = 0;
        for turn in 1..32 {
            let now = deadline + turn * 100;
            client.timer(now).unwrap();
            server.timer(now).unwrap();
            count += transfer(&mut client, &mut server, now);
            count += transfer(&mut server, &mut client, now);
            if client.handshake_complete() && server.handshake_complete() {
                break;
            }
        }
        assert!(
            client.handshake_complete(),
            "{:?}",
            client.tls().last_failure()
        );
        assert!(
            server.handshake_complete(),
            "{:?}",
            server.tls().last_failure()
        );
        assert!(count >= 3);
        // Drain post-handshake acknowledgments/key retirement before application PN use.
        transfer(&mut client, &mut server, deadline + 10_000);
        transfer(&mut server, &mut client, deadline + 10_000);
        use hibana_quic::tls::{Level, Provider};
        assert!(
            !client.tls().has_keys(Level::Handshake),
            "authenticated 1-RTT HANDSHAKE_DONE retires client handshake keys"
        );
        assert!(!server.tls().has_keys(Level::Handshake));
        // RFC 9001 key updates traverse actual encrypted packets, the sent ACK
        // ledger and Hibana key/receive/publication authorities. A real MaxData
        // frame makes each test packet ACK-eliciting without inventing TLS input.
        let mut ch = MaxDataHandler::default();
        let mut sh = MaxDataHandler::default();
        let now = deadline + 20_000;
        client.timer(now).unwrap();
        server.timer(now).unwrap();
        let tx = client
            .transmit_application(&[0x10, 1], &mut out)
            .unwrap()
            .unwrap();
        client.adapter_result(tx, true, now).unwrap();
        server
            .receive_with(&out[..tx.len], &mut scratch, &mut sh)
            .unwrap();
        transfer(&mut server, &mut client, now);
        transfer(&mut client, &mut server, now);
        assert_eq!(client.tls().key_generation(), 0);

        // Retain an actually sent generation-zero server packet for reordering.
        let delayed_tx = server
            .transmit_application(&[0x10, 2], &mut out)
            .unwrap()
            .unwrap();
        server.adapter_result(delayed_tx, true, now).unwrap();
        let delayed = out;
        // A second old-phase datagram is prepared but NOT accepted by the adapter.
        let pending = server
            .transmit_application(&[0x10, 3], &mut out)
            .unwrap()
            .unwrap();
        client.initiate_key_update().unwrap();
        assert!(client.tls().key_phase());
        let update = client
            .transmit_application(&[0x10, 4], &mut out)
            .unwrap()
            .unwrap();
        client.adapter_result(update, true, now).unwrap();
        let before_busy = server.trace_status();
        assert!(matches!(
            server.receive_with(&out[..update.len], &mut scratch, &mut sh),
            Err(hibana_quic::handshake_endpoint::Error::Busy)
        ));
        assert!(!server.is_retired());
        assert_eq!(
            server.trace_status(),
            before_busy,
            "Busy retry was logged as receive"
        );
        assert_eq!(server.tls().key_generation(), 0);
        let before_reject = server.trace_status();
        server.adapter_result(pending, false, now).unwrap();
        assert_eq!(
            server.trace_status(),
            before_reject,
            "rejected output fabricated a send"
        );
        let received = server
            .receive_with(&out[..update.len], &mut scratch, &mut sh)
            .unwrap();
        assert_eq!(received.authenticated, 1);
        assert_eq!(server.tls().key_generation(), 1); // before generating its ACK
        transfer(&mut server, &mut client, now);
        assert_eq!(client.tls().key_generation(), 1);
        let received = client
            .receive_with(&delayed[..delayed_tx.len], &mut scratch, &mut ch)
            .unwrap();
        assert_eq!(received.authenticated, 1);
        transfer(&mut client, &mut server, now);
        transfer(&mut server, &mut client, now);
        assert!(matches!(
            client.initiate_key_update(),
            Err(hibana_quic::handshake_endpoint::Error::Tls(
                hibana_quic::tls::Error::KeyUpdateNotAllowed
            ))
        ));
        // Advance the real injected clock beyond the conservative three-PTO wait
        // and update from the other role, exercising phase-bit wrap to zero.
        let now = now + 10_000_000;
        client.timer(now).unwrap();
        server.timer(now).unwrap();
        transfer(&mut client, &mut server, now);
        transfer(&mut server, &mut client, now);
        server.initiate_key_update().unwrap();
        assert_eq!(server.tls().key_generation(), 2);
        assert!(!server.tls().key_phase());
        let update = server
            .transmit_application(&[0x10, 5], &mut out)
            .unwrap()
            .unwrap();
        server.adapter_result(update, true, now).unwrap();
        assert_eq!(
            client
                .receive_with(&out[..update.len], &mut scratch, &mut ch)
                .unwrap()
                .authenticated,
            1
        );
        assert_eq!(client.tls().key_generation(), 2);
        transfer(&mut client, &mut server, now);
        transfer(&mut server, &mut client, now);
        // Retired generation-zero ciphertext cannot authenticate after wrap.
        assert_eq!(
            client
                .receive_with(&delayed[..delayed_tx.len], &mut scratch, &mut ch)
                .unwrap()
                .authenticated,
            0
        );
        assert_eq!(ch.delivered, 2);
        assert_eq!(sh.delivered, 2);
        assert_eq!(
            server.tls().failed_authentications(),
            1,
            "Initial failure survives application key updates"
        );
        assert_eq!(
            client.tls().failed_authentications(),
            1,
            "retired generation fails one shared-budget attempt"
        );
        // Produce a genuine threshold loss, distinct from the earlier PTO.
        // Newer MAX_DATA values supersede the dropped control's information.
        for value in 6..10 {
            let dropped_or_delivered = client
                .transmit_application(&[0x10, value], &mut out)
                .unwrap()
                .unwrap();
            client
                .adapter_result(dropped_or_delivered, true, now)
                .unwrap();
            if value != 6 {
                server
                    .receive_with(&out[..dropped_or_delivered.len], &mut scratch, &mut sh)
                    .unwrap();
                transfer(&mut server, &mut client, now);
            }
        }
        if trace_capacity == Some(32768) {
            assert!(
                core::str::from_utf8(client.trace_pending())
                    .unwrap()
                    .contains("quic:packet_lost")
            );
        }
        // Real protected close/draining now runs inside the same allocator scope.
        use hibana_quic::lifecycle::{CloseReason, State as ConnectionState};
        client
            .close(CloseReason::application(0, "complete").unwrap())
            .unwrap();
        let close = client.transmit(&mut out).unwrap().unwrap();
        assert!(client.transmit_permitted(close, now).unwrap());
        client.adapter_result(close, true, now).unwrap();
        assert_eq!(
            server
                .receive(&out[..close.len], &mut scratch)
                .unwrap()
                .authenticated,
            1
        );
        assert_eq!(server.connection_state(), ConnectionState::Draining);
        assert!(server.transmit(&mut out).unwrap().is_none());
        client.timer(client.close_deadline().unwrap()).unwrap();
        server.timer(server.close_deadline().unwrap()).unwrap();
        assert_eq!(client.connection_state(), ConnectionState::Closed);
        assert_eq!(server.connection_state(), ConnectionState::Closed);
        for endpoint in [&mut client, &mut server] {
            match trace_capacity {
                None => {
                    assert!(endpoint.trace_status().is_none());
                    assert!(endpoint.trace_pending().is_empty());
                }
                Some(capacity) => {
                    let status = endpoint.trace_status().unwrap();
                    if capacity == 32768 {
                        assert!(!status.incomplete, "{status:?}");
                        assert!(status.recorded_events > 8);
                        let json = core::str::from_utf8(endpoint.trace_pending()).unwrap();
                        assert!(json.contains("quic:packet_sent"));
                        assert!(json.contains("quic:packet_received"));
                        assert!(json.contains("quic:key_updated"));
                        assert!(json.contains("remote_update"));
                        assert!(json.contains("local_update"));
                    } else {
                        assert!(status.incomplete);
                        assert!(status.lost_events > 0);
                    }
                    // Retirement retains bytes. Simulate a sink accepting short
                    // writes; draining cannot erase a previous loss diagnostic.
                    while !endpoint.trace_pending().is_empty() {
                        let n = endpoint.trace_pending().len().min(7);
                        endpoint.consume_trace(n).unwrap();
                    }
                    let drained = endpoint.trace_status().unwrap();
                    assert_eq!(drained.incomplete, status.incomplete);
                    assert_eq!(drained.recorded_events, status.recorded_events);
                    assert_eq!(drained.lost_events, status.lost_events);
                    endpoint.mark_trace_sink_failed();
                    assert!(endpoint.trace_status().unwrap().incomplete);
                }
            }
        }
    }
    let allocations = TRACK.with(|c| c.replace(None).unwrap());
    assert_eq!(allocations, 0, "bounded QUIC/TLS/Hibana flow allocated");
}
