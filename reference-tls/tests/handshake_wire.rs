//! Development-only reference-TLS endpoints exchanging actual protected QUIC bytes.
use hibana::runtime::{SessionKitStorage, ids::SessionId};
use hibana_quic::{
    carrier::{CarrierStorage, LocalCarrier},
    driver::{Driver, Roles},
    handshake::CryptoBuffer,
    handshake_endpoint::{Config, HandshakeEndpoint, Side},
    packet::encode_varint,
    protocol::*,
};
use hibana_quic_reference_tls::{RustlsProvider, rustls};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use rustls::{
    RootCertStore,
    pki_types::{PrivatePkcs8KeyDer, ServerName},
};

use hibana_quic::tls::{self, Level, Provider};
use std::cell::Cell;
struct Instrumented {
    inner: RustlsProvider,
    fail_seal: Cell<bool>,
    keys_unavailable: Cell<bool>,
}
impl Instrumented {
    fn new(inner: RustlsProvider) -> Self {
        Self {
            inner,
            fail_seal: Cell::new(false),
            keys_unavailable: Cell::new(false),
        }
    }
}
impl Provider for Instrumented {
    fn receive(&mut self, l: Level, b: &[u8]) -> Result<(), tls::Error> {
        self.inner.receive(l, b)
    }
    fn transmit(&mut self, b: &mut [u8]) -> Result<Option<tls::Output>, tls::Error> {
        self.inner.transmit(b)
    }
    fn discard_keys(&mut self, l: Level) {
        self.inner.discard_keys(l)
    }
    fn has_keys(&self, l: Level) -> bool {
        self.inner.has_keys(l)
    }
    fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }
    fn peer_transport_parameters(&self) -> Option<&[u8]> {
        self.inner.peer_transport_parameters()
    }
    fn seal(
        &mut self,
        l: Level,
        pn: u64,
        h: &[u8],
        b: &mut [u8],
        n: usize,
    ) -> Result<usize, tls::Error> {
        if self.fail_seal.get() {
            return Err(tls::Error::ConfidentialityLimit);
        }
        self.inner.seal(l, pn, h, b, n)
    }
    fn open(&mut self, l: Level, pn: u64, h: &[u8], b: &mut [u8]) -> Result<usize, tls::Error> {
        if self.keys_unavailable.get() {
            return Err(tls::Error::KeysUnavailable);
        }
        self.inner.open(l, pn, h, b)
    }
    fn header_mask(&self, l: Level, local: bool, s: &[u8; 16]) -> Result<[u8; 5], tls::Error> {
        self.inner.header_mask(l, local, s)
    }
}
type Endpoint<'a, 'b> = HandshakeEndpoint<'a, 'b, Instrumented>;
fn parameters(id: &[u8], original: Option<&[u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut b = [0; 8];
    for (kind, data) in [(15, Some(id)), (0, original)] {
        if let Some(data) = data {
            let n = encode_varint(kind, &mut b).unwrap();
            out.extend_from_slice(&b[..n]);
            let n = encode_varint(data.len() as u64, &mut b).unwrap();
            out.extend_from_slice(&b[..n]);
            out.extend_from_slice(data);
        }
    }
    out
}
fn with_ids(
    client_id: &[u8],
    server_id: &[u8],
    f: impl FnOnce(&mut Endpoint<'_, '_>, &mut Endpoint<'_, '_>),
) {
    with_original(client_id, server_id, b"original", false, f)
}
fn with_original(
    client_id: &[u8],
    server_id: &[u8],
    original: &[u8],
    expect_invalid: bool,
    f: impl FnOnce(&mut Endpoint<'_, '_>, &mut Endpoint<'_, '_>),
) {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_key = KeyPair::generate().unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .signed_by(&key, &ca, &ca_key)
        .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    let client_tls = RustlsProvider::client(
        roots,
        ServerName::try_from("localhost").unwrap(),
        parameters(client_id, None),
    )
    .unwrap();
    let server_tls = RustlsProvider::server(
        vec![cert.der().clone()],
        PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        parameters(server_id, Some(original)),
    )
    .unwrap();
    let p0 = service_program::<INGRESS>();
    let p1 = service_program::<PACKET>();
    let p2 = service_program::<APPLICATION>();
    let p3 = service_program::<RECOVERY>();
    let p4 = service_program::<ADAPTER>();
    let p5 = service_program::<TIMER>();
    let client_queue = CarrierStorage::<8, 16, { hibana_quic::protocol::SERVICE_PORTS }>::new();
    let server_queue = CarrierStorage::<8, 16, { hibana_quic::protocol::SERVICE_PORTS }>::new();
    let mut client_slab = [0; 32768];
    let mut server_slab = [0; 32768];
    let mut client_kit = SessionKitStorage::<LocalCarrier<'_, 8, 16, { hibana_quic::protocol::SERVICE_PORTS }>>::uninit();
    let mut server_kit = SessionKitStorage::<LocalCarrier<'_, 8, 16, { hibana_quic::protocol::SERVICE_PORTS }>>::uninit();
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
    let mut cb0 = [0; 8192];
    let mut cb1 = [0; 8192];
    let mut cb2 = [0; 8192];
    let mut cm0 = [0; 8192];
    let mut cm1 = [0; 8192];
    let mut cm2 = [0; 8192];
    let mut sb0 = [0; 8192];
    let mut sb1 = [0; 8192];
    let mut sb2 = [0; 8192];
    let mut sm0 = [0; 8192];
    let mut sm1 = [0; 8192];
    let mut sm2 = [0; 8192];
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
            local_id: client_id,
            original_destination_id: original,
            generation: 1,
        },
        Instrumented::new(client_tls),
        attach!(crv, 1),
        cc,
    );
    if expect_invalid {
        assert!(matches!(
            client,
            Err(hibana_quic::handshake_endpoint::Error::InvalidConfig)
        ));
        return;
    }
    let mut client = client.unwrap();
    let mut server = HandshakeEndpoint::new(
        Config {
            side: Side::Server,
            local_id: server_id,
            original_destination_id: original,
            generation: 2,
        },
        Instrumented::new(server_tls),
        attach!(srv, 2),
        sc,
    )
    .unwrap();
    f(&mut client, &mut server);
}
fn with_pair(f: impl FnOnce(&mut Endpoint<'_, '_>, &mut Endpoint<'_, '_>)) {
    with_ids(b"client01", b"server01", f)
}
fn transfer(from: &mut Endpoint<'_, '_>, to: &mut Endpoint<'_, '_>, now: u64) -> usize {
    let mut count = 0;
    let mut out = [0; 1500];
    let mut scratch = [0; 1500];
    for _ in 0..32 {
        let Some(tx) = from.transmit(&mut out).unwrap() else {
            return count;
        };
        from.adapter_result(tx, true, now).unwrap();
        let received = to.receive(&out[..tx.len], &mut scratch).unwrap();
        assert_eq!(
            received.authenticated, 1,
            "real AEAD packet must authenticate"
        );
        count += 1;
    }
    panic!("unexpected unbounded output");
}
#[test]
fn real_protected_quic_handshake_in_both_roles() {
    with_pair(|client, server| {
        let mut total = 0;
        for now in 0..16 {
            total += transfer(client, server, now);
            total += transfer(server, client, now);
            if client.handshake_complete() && server.handshake_complete() {
                break;
            }
        }
        assert!(client.handshake_complete());
        assert!(server.handshake_complete());
        assert!(total >= 4);
    });
}
#[test]
fn corrupt_and_oversized_unauthenticated_input_does_not_retire() {
    with_pair(|client, server| {
        let mut out = [0; 1500];
        let tx = client.transmit(&mut out).unwrap().unwrap();
        client.adapter_result(tx, true, 0).unwrap();
        let mut corrupted = out;
        corrupted[tx.len - 1] ^= 1;
        assert_eq!(
            server
                .receive(&corrupted[..tx.len], &mut [0; 1500])
                .unwrap()
                .authenticated,
            0
        );
        assert!(!server.is_retired());
        assert_eq!(
            server
                .receive(&out[..tx.len], &mut [0; 100])
                .unwrap()
                .authenticated,
            0
        );
        assert!(!server.is_retired());
        assert_eq!(
            server
                .receive(&out[..tx.len], &mut [0; 1500])
                .unwrap()
                .authenticated,
            1
        );
    });
}
#[test]
fn cancelled_adapter_submission_repacketizes_tls_under_new_pn() {
    with_pair(|client, server| {
        let mut a = [0; 1500];
        let first = client.transmit(&mut a).unwrap().unwrap();
        client.adapter_result(first, false, 0).unwrap();
        let mut b = [0; 1500];
        let second = client.transmit(&mut b).unwrap().unwrap();
        assert_ne!(&a[..first.len], &b[..second.len]);
        client.adapter_result(second, true, 1).unwrap();
        assert_eq!(
            server
                .receive(&b[..second.len], &mut [0; 1500])
                .unwrap()
                .authenticated,
            1
        );
        assert!(client.adapter_result(first, true, 2).is_err());
        assert!(!client.is_retired());
    });
}

#[test]
fn rejected_sends_reuse_bounded_history_without_reusing_pn() {
    with_pair(|client, server| {
        let mut out = [0; 1500];
        for now in 0..128 {
            let tx = client
                .transmit(&mut out)
                .unwrap()
                .expect("cancelled history reclaimed");
            client.adapter_result(tx, false, now).unwrap();
        }
        let tx = client.transmit(&mut out).unwrap().unwrap();
        client.adapter_result(tx, true, 129).unwrap();
        assert_eq!(
            server
                .receive(&out[..tx.len], &mut [0; 1500])
                .unwrap()
                .authenticated,
            1
        );
    });
}

// The following helper emits only a real authenticated Initial PING, with the
// standard public Initial derivation. It is test input, not a TLS substitute.
fn initial_ping(pn: u64) -> [u8; 1200] {
    use hibana_quic::{
        crypto::initial_keys,
        packet::{LongHeader, LongType, encode_long_header},
    };
    let mut packet = [0_u8; 1200];
    let header = LongHeader {
        kind: LongType::Initial,
        destination_id: b"original",
        source_id: b"client01",
        token: &[],
        packet_number: pn,
        packet_number_len: 4,
    };
    let h = encode_long_header(&header, 1170, &mut packet).unwrap();
    let h = encode_long_header(&header, 1200 - h, &mut packet).unwrap();
    packet[h] = 1;
    let (header, body) = packet.split_at_mut(h);
    let mut keys = initial_keys(b"original").unwrap();
    keys.client.seal(pn, header, body, 1200 - h - 16).unwrap();
    keys.client.protect_header(&mut packet, h - 4).unwrap();
    packet
}
#[test]
fn ack_snapshot_preserves_new_out_of_order_receive() {
    with_pair(|_client, server| {
        assert_eq!(
            server
                .receive(&initial_ping(10), &mut [0; 1500])
                .unwrap()
                .authenticated,
            1
        );
        let mut output = [0; 1500];
        let old_ack = server.transmit(&mut output).unwrap().unwrap();
        assert_eq!(
            server
                .receive(&initial_ping(9), &mut [0; 1500])
                .unwrap()
                .authenticated,
            1
        );
        server.adapter_result(old_ack, true, 0).unwrap();
        assert!(
            server.transmit(&mut output).unwrap().is_some(),
            "new PN9 must still be acknowledged"
        );
    });
}
#[test]
fn duplicate_eliciting_packet_rearms_ack() {
    with_pair(|_client, server| {
        let ping = initial_ping(0);
        server.receive(&ping, &mut [0; 1500]).unwrap();
        let mut output = [0; 1500];
        let ack = server.transmit(&mut output).unwrap().unwrap();
        server.adapter_result(ack, true, 0).unwrap();
        assert!(server.transmit(&mut output).unwrap().is_none());
        assert_eq!(server.receive(&ping, &mut [0; 1500]).unwrap().discarded, 1);
        assert!(server.transmit(&mut output).unwrap().is_some());
    });
}

#[test]
fn crypto_failure_after_reservation_retires_without_ghost_success() {
    with_pair(|client, server| {
        transfer(client, server, 0);
        transfer(server, client, 1);
        client.tls().fail_seal.set(true);
        assert!(client.transmit(&mut [0; 1500]).is_err());
        assert!(client.is_retired());
        assert!(matches!(
            client.transmit(&mut [0; 1500]),
            Err(hibana_quic::handshake_endpoint::Error::Retired)
        ));
    });
}
#[test]
fn temporarily_unavailable_receive_keys_discard_without_retirement() {
    with_pair(|client, server| {
        transfer(client, server, 0);
        let mut out = [0; 1500];
        let mut scratch = [0; 1500];
        let initial = server.transmit(&mut out).unwrap().unwrap();
        assert_eq!(initial.level, Level::Initial);
        server.adapter_result(initial, true, 1).unwrap();
        client.receive(&out[..initial.len], &mut scratch).unwrap();
        let handshake = server.transmit(&mut out).unwrap().unwrap();
        assert_eq!(handshake.level, Level::Handshake);
        server.adapter_result(handshake, true, 2).unwrap();
        client.tls().keys_unavailable.set(true);
        assert_eq!(
            client
                .receive(&out[..handshake.len], &mut scratch)
                .unwrap()
                .discarded,
            1
        );
        assert!(!client.is_retired());
        client.tls().keys_unavailable.set(false);
        assert_eq!(
            client
                .receive(&out[..handshake.len], &mut scratch)
                .unwrap()
                .authenticated,
            1
        );
    });
}

#[test]
fn lost_initial_is_repacketized_on_pto_without_plaintext_or_pn_reuse() {
    with_pair(|client, server| {
        let mut first = [0; 1500];
        let original = client.transmit(&mut first).unwrap().unwrap();
        client.adapter_result(original, true, 0).unwrap();
        // UDP accepted, then lost: it is NOT an adapter cancellation.
        let deadline = client
            .next_deadline()
            .expect("PTO armed for retained CRYPTO");
        client.timer(deadline).unwrap();
        server.timer(deadline).unwrap();
        let mut replay = [0; 1500];
        let probe = client
            .transmit(&mut replay)
            .unwrap()
            .expect("fresh-PN probe");
        assert_ne!(&first[..original.len], &replay[..probe.len]);
        client.adapter_result(probe, true, deadline).unwrap();
        assert_eq!(
            server
                .receive(&replay[..probe.len], &mut [0; 1500])
                .unwrap()
                .authenticated,
            1
        );
        for turn in 1..16 {
            let now = deadline + turn * 100;
            client.timer(now).unwrap();
            server.timer(now).unwrap();
            transfer(client, server, now);
            transfer(server, client, now);
            if client.handshake_complete() && server.handshake_complete() {
                break;
            }
        }
        assert!(client.handshake_complete());
        assert!(server.handshake_complete());
        transfer(client, server, deadline + 2_000);
        transfer(server, client, deadline + 2_000);
        assert!(client.keys_discarded(Level::Initial));
        assert!(server.keys_discarded(Level::Initial));
        assert!(client.keys_discarded(Level::Handshake));
        assert!(server.keys_discarded(Level::Handshake));
        assert_eq!(
            client.bytes_in_flight(),
            0,
            "discard removes original lost Initial/Handshake flight"
        );
        assert_eq!(
            server.bytes_in_flight(),
            0,
            "HANDSHAKE_DONE ACK removes final flight"
        );
    });
}

#[test]
fn ack_of_padding_only_packet_never_creates_rtt_sample() {
    with_pair(|_client, server| {
        use hibana_quic::{
            crypto::initial_keys,
            packet::{
                AckRange, AckRanges, Frame, LongHeader, LongType, encode_frame, encode_long_header,
            },
        };
        server.receive(&initial_ping(0), &mut [0; 1500]).unwrap();
        let mut output = [0; 1500];
        let tx = server.transmit(&mut output).unwrap().unwrap();
        server.adapter_result(tx, true, 0).unwrap();
        assert!(!server.has_rtt_sample());
        assert_eq!(server.bytes_in_flight(), 1200);
        let mut ack = [0; 1200];
        let header = LongHeader {
            kind: LongType::Initial,
            destination_id: b"original",
            source_id: b"client01",
            token: &[],
            packet_number: 1,
            packet_number_len: 4,
        };
        let n = encode_long_header(&header, 1170, &mut ack).unwrap();
        let n = encode_long_header(&header, 1200 - n, &mut ack).unwrap();
        let ranges = [AckRange {
            smallest: tx.packet_number.value,
            largest: tx.packet_number.value,
        }];
        encode_frame(
            &Frame::Ack {
                delay: 0,
                ranges: AckRanges::new(&ranges).unwrap(),
                ecn: None,
            },
            &mut ack[n..],
        )
        .unwrap();
        let (header, body) = ack.split_at_mut(n);
        let mut keys = initial_keys(b"original").unwrap();
        keys.client.seal(1, header, body, 1200 - n - 16).unwrap();
        keys.client.protect_header(&mut ack, n - 4).unwrap();
        server.timer(10_000).unwrap();
        server.receive(&ack, &mut [0; 1500]).unwrap();
        assert!(!server.has_rtt_sample());
        assert_eq!(server.bytes_in_flight(), 0);
    });
}

#[test]
fn zero_length_peer_connection_ids_use_standard_wire_and_verified_parameters() {
    for (client_id, server_id) in [
        (&b""[..], &b"server01"[..]),
        (&b"client01"[..], &b""[..]),
        (&b""[..], &b""[..]),
    ] {
        with_ids(client_id, server_id, |client, server| {
            for now in 0..16 {
                transfer(client, server, now);
                transfer(server, client, now);
                if client.handshake_complete() && server.handshake_complete() {
                    break;
                }
            }
            assert!(client.handshake_complete());
            assert!(server.handshake_complete());
        });
    }
}

#[test]
fn first_retry_after_processed_server_initial_is_ignored() {
    with_pair(|client, server| {
        transfer(client, server, 0);
        let mut out = [0; 1500];
        let tx = server.transmit(&mut out).unwrap().unwrap();
        assert_eq!(tx.level, Level::Initial);
        server.adapter_result(tx, true, 1).unwrap();
        assert_eq!(
            client
                .receive(&out[..tx.len], &mut [0; 1500])
                .unwrap()
                .authenticated,
            1
        );
        let mut retry = [0; 256];
        let n = hibana_quic::retry::encode_retry(
            b"original",
            b"client01",
            b"retry001",
            b"opaque",
            0,
            &mut retry,
            &mut [0; 300],
        )
        .unwrap();
        assert_eq!(
            client
                .receive(&retry[..n], &mut [0; 1500])
                .unwrap()
                .discarded,
            1
        );
        assert!(client.retry_source_id().is_none());
        assert!(!client.is_retired());
    });
}

#[test]
fn client_initial_dcid_requires_eight_bytes() {
    for len in 0..8 {
        with_original(
            b"client01",
            b"server01",
            &b"original"[..len],
            true,
            |_, _| panic!("invalid client created"),
        );
    }
    with_original(b"client01", b"server01", b"original", false, |client, _| {
        assert!(!client.is_retired())
    });
}
#[test]
fn authenticated_zero_frame_payload_is_protocol_violation() {
    with_pair(|client, _| {
        use hibana_quic::{
            crypto,
            handshake_endpoint::Error,
            packet::{self, LongHeader, LongType},
        };
        let mut packet = [0; 128];
        let h = LongHeader {
            kind: LongType::Initial,
            destination_id: b"client01",
            source_id: b"server01",
            token: &[],
            packet_number: 0,
            packet_number_len: 4,
        };
        let n = packet::encode_long_header(&h, 16, &mut packet).unwrap();
        let mut keys = crypto::initial_keys(b"original").unwrap();
        let (header, body) = packet[..n + 16].split_at_mut(n);
        keys.server.seal(0, header, body, 0).unwrap();
        keys.server
            .protect_header(&mut packet[..n + 16], n - 4)
            .unwrap();
        assert!(matches!(
            client.receive(&packet[..n + 16], &mut [0; 1500]),
            Err(Error::ProtocolViolation)
        ));
        assert!(client.is_retired());
    });
}

#[test]
fn adapter_descriptor_is_bound_to_connection_generation() {
    with_pair(|client, server| {
        let mut bytes = [0; 1500];
        let old = client.transmit(&mut bytes).unwrap().unwrap();
        client.adapter_result(old, true, 0).unwrap();
        server.receive(&bytes[..old.len], &mut [0; 1500]).unwrap();
        let current = server.transmit(&mut bytes).unwrap().unwrap();
        assert_eq!(old.id, current.id);
        assert_eq!(old.len, current.len);
        assert_eq!(old.level, current.level);
        assert_eq!(old.packet_number, current.packet_number);
        assert_eq!(old.ecn, current.ecn);
        assert_ne!(old.connection_generation, current.connection_generation);
        assert!(server.adapter_result(old, true, 1).is_err());
        let mut relabeled = old;
        relabeled.connection_generation = current.connection_generation;
        assert!(
            server.adapter_result(relabeled, true, 1).is_err(),
            "public metadata is not a fresh authority"
        );
        assert!(!server.is_retired());
        server.adapter_result(current, true, 1).unwrap();
    });
}

#[test]
fn protected_close_drains_without_reply_and_retires_at_deadline() {
    with_pair(|client, server| {
        use hibana_quic::lifecycle::{CloseReason, State};
        for now in 0..8 {
            transfer(client, server, now * 10);
            transfer(server, client, now * 10 + 1);
        }
        assert!(client.handshake_complete() && server.handshake_complete());
        client
            .close(CloseReason::application(0, "done").unwrap())
            .unwrap();
        let deadline = client.close_deadline().unwrap();
        let mut bytes = [0; 1500];
        let tx = client.transmit(&mut bytes).unwrap().unwrap();
        assert_eq!(tx.level, Level::OneRtt);
        assert!(client.transmit_permitted(tx, 1000).unwrap());
        client.adapter_result(tx, true, 1000).unwrap();
        server.timer(1000).unwrap();
        assert_eq!(
            server
                .receive(&bytes[..tx.len], &mut [0; 1500])
                .unwrap()
                .authenticated,
            1
        );
        assert_eq!(server.connection_state(), State::Draining);
        assert_eq!(server.peer_close().unwrap().error_code, 0);
        assert_eq!(server.peer_close().unwrap().frame_type, None);
        assert!(server.transmit(&mut bytes).unwrap().is_none());
        assert!(!server.tls().has_keys(Level::OneRtt));
        assert_eq!(
            server
                .receive(&bytes[..tx.len], &mut [0; 1500])
                .unwrap()
                .discarded,
            1
        );
        assert_eq!(client.close_deadline(), Some(deadline));
        client.timer(deadline).unwrap();
        assert_eq!(client.connection_state(), State::Closed);
        server.timer(server.close_deadline().unwrap()).unwrap();
        assert_eq!(server.connection_state(), State::Closed);
    });
}
#[test]
fn close_rejection_uses_fresh_pn_and_expired_output_cannot_submit() {
    with_pair(|client, server| {
        use hibana_quic::lifecycle::{CloseReason, State};
        for now in 0..8 {
            transfer(client, server, now * 10);
            transfer(server, client, now * 10 + 1);
        }
        client
            .close(CloseReason::transport(0, 0, "end").unwrap())
            .unwrap();
        let mut bytes = [0; 1500];
        let first = client.transmit(&mut bytes).unwrap().unwrap();
        client.adapter_result(first, false, 1000).unwrap();
        assert!(client.transmit(&mut bytes).unwrap().is_none());
        let next = client.next_deadline().unwrap();
        client.timer(next).unwrap();
        let second = client.transmit(&mut bytes).unwrap().unwrap();
        assert!(second.packet_number.value > first.packet_number.value);
        let deadline = client.close_deadline().unwrap();
        client.timer(deadline).unwrap();
        assert_eq!(client.connection_state(), State::Closed);
        assert!(!client.transmit_permitted(second, deadline).unwrap());
        assert!(client.adapter_result(second, true, deadline).is_err());
    });
}
#[test]
fn early_server_close_uses_lower_level_fallback_and_hides_application_reason() {
    with_pair(|client, server| {
        use hibana_quic::lifecycle::{APPLICATION_ERROR, CloseReason, State};
        transfer(client, server, 0);
        server
            .close(CloseReason::application(42, "private application detail").unwrap())
            .unwrap();
        let mut bytes = [0; 1500];
        let high = server.transmit(&mut bytes).unwrap().unwrap();
        assert_eq!(high.level, Level::Handshake);
        server.adapter_result(high, true, 1).unwrap();
        assert_eq!(
            client
                .receive(&bytes[..high.len], &mut [0; 1500])
                .unwrap()
                .discarded,
            1
        );
        let low = server.transmit(&mut bytes).unwrap().unwrap();
        assert_eq!(low.level, Level::Initial);
        assert_eq!(low.len, 1200);
        server.adapter_result(low, true, 2).unwrap();
        client.receive(&bytes[..low.len], &mut [0; 1500]).unwrap();
        assert_eq!(client.connection_state(), State::Draining);
        let info = client.peer_close().unwrap();
        assert_eq!(info.error_code, APPLICATION_ERROR);
        assert_eq!(info.frame_type, Some(0));
        assert_eq!(info.level, Level::Initial);
    });
}
