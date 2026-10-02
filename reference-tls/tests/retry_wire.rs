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
    params: [u8; 1536],
}
impl Buffers {
    fn new() -> Self {
        Self {
            rx: [0; 8192],
            tx: [0; 8192],
            cert: [0; 8192],
            params: [0; 1536],
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

use hibana_quic::{
    crypto,
    packet::{self, EncryptionLevel, Frame, FrameIter, Header, PacketIter, ParseLimits},
    retry::{self, ClientAddress, RetryTokens, TokenContext},
};
const ADDRESS: ClientAddress = ClientAddress::V4 {
    ip: [192, 0, 2, 1],
    port: 12345,
};
fn crypto_fragment(packet: &[u8], key_id: &[u8]) -> ([u8; 900], usize, u64, bool) {
    let parsed = PacketIter::new(packet, 0, 1)
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    let Header::Long {
        packet_number_offset,
        ..
    } = parsed.header
    else {
        panic!("Initial expected")
    };
    let mut copy = [0; 1500];
    copy[..packet.len()].copy_from_slice(packet);
    let keys = crypto::initial_keys(key_id).unwrap();
    let pn_len = keys
        .client
        .unprotect_header(&mut copy[..packet.len()], packet_number_offset)
        .unwrap();
    let (pn, _) =
        packet::decode_truncated_packet_number(copy[0], &copy[packet_number_offset..]).unwrap();
    let (header, body) = copy[..packet.len()].split_at_mut(packet_number_offset + pn_len);
    let len = keys
        .client
        .open(pn, header, body, &mut crypto::IntegrityBudget::new())
        .unwrap();
    let mut result = [0; 900];
    let mut fragment = None;
    let mut ack = false;
    for f in FrameIter::new(
        &body[..len],
        EncryptionLevel::Initial,
        ParseLimits::default(),
    )
    .unwrap()
    {
        match f.unwrap() {
            Frame::Crypto { offset, data } => {
                result[..data.len()].copy_from_slice(data);
                fragment = Some((data.len(), offset));
            }
            Frame::Ack { .. } => ack = true,
            _ => {}
        }
    }
    let (len, offset) = fragment.expect("CRYPTO expected");
    (result, len, offset, ack)
}
fn server_initial_ping(client_id: &[u8], server_id: &[u8], retry_id: &[u8], pn: u64) -> [u8; 1200] {
    let mut out = [0; 1200];
    let h = packet::LongHeader {
        kind: packet::LongType::Initial,
        destination_id: client_id,
        source_id: server_id,
        token: &[],
        packet_number: pn,
        packet_number_len: 4,
    };
    let n = packet::encode_long_header(&h, 1000, &mut out).unwrap();
    let n = packet::encode_long_header(&h, 1200 - n, &mut out).unwrap();
    out[n] = 1;
    let mut keys = crypto::initial_keys(retry_id).unwrap();
    let (header, body) = out.split_at_mut(n);
    keys.server.seal(pn, header, body, 1200 - n - 16).unwrap();
    keys.server.protect_header(&mut out, n - 4).unwrap();
    out
}
fn run_retry(pending: Option<bool>, parameter_mode: u8, max_ids: bool) {
    let capacity_probe = parameter_mode == 4;
    let bad_parameters = parameter_mode != 0 && !capacity_probe;
    let client_id: &[u8] = if max_ids {
        b"client01234567890123"
    } else {
        b"client01"
    };
    let server_id: &[u8] = if max_ids {
        b"server01234567890123"
    } else {
        b"server01"
    };
    // Deliberately different from the server's subsequent Initial SCID.
    let retry_id: &[u8] = if max_ids {
        b"retry012345678901234"
    } else {
        b"retry001"
    };
    let id = identity();
    let anchors = [trust_anchor_from_der(&id.root).unwrap()];
    let chain = [id.leaf.as_ref()];
    let mut client_params = parameters(client_id, None);
    if max_ids {
        let mut length = [0; 8];
        client_params.push(42);
        let n = encode_varint(900, &mut length).unwrap();
        client_params.extend_from_slice(&length[..n]);
        client_params.extend_from_slice(&[0x5a; 900]);
    }
    let mut server_params = parameters(
        server_id,
        Some(if parameter_mode == 3 {
            b"wrong"
        } else {
            b"original"
        }),
    );
    if parameter_mode != 1 {
        let retry_tp = if parameter_mode == 2 {
            &b"wrong"[..]
        } else {
            retry_id
        };
        server_params.extend_from_slice(&[16, retry_tp.len() as u8]);
        server_params.extend_from_slice(retry_tp);
    }
    let mut cb = Buffers::new();
    let mut sb = Buffers::new();
    // Caller-owned storage and test PKI setup precede the measurement.
    let mut client_slab = [0; 32768];
    let mut server_slab = [0; 32768];
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
        let mut ck = SessionKitStorage::<LocalCarrier<'_, 8, 16, { hibana_quic::protocol::SERVICE_PORTS }>>::uninit();
        let mut sk = SessionKitStorage::<LocalCarrier<'_, 8, 16, { hibana_quic::protocol::SERVICE_PORTS }>>::uninit();
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
                local_id: client_id,
                original_destination_id: b"original",
                generation: 1,
            },
            client_tls,
            driver!(crv, 1),
            client_crypto,
        )
        .unwrap();
        let mut out = [0; 1500];
        let mut scratch = [0; 1500];
        let first = client.transmit(&mut out).unwrap().unwrap();
        let original = out;
        let first_crypto = crypto_fragment(&original[..first.len], b"original");
        if pending.is_none() {
            client.adapter_result(first, true, 0).unwrap();
            if max_ids {
                // Retain and replay more than one original ClientHello fragment.
                let extra = client.transmit(&mut out).unwrap().unwrap();
                assert_eq!(extra.level, hibana_quic::tls::Level::Initial);
                client.adapter_result(extra, true, 0).unwrap();
            }
        }
        let mut issuer = RetryTokens::<4>::generate(&mut OsRng, 1, 10_000_000).unwrap();
        let mut token = [0; retry::TOKEN_LEN];
        issuer
            .issue(
                1,
                TokenContext {
                    original_destination_id: b"original",
                    retry_source_id: retry_id,
                    client_source_id: client_id,
                    address: ADDRESS,
                },
                &mut token,
            )
            .unwrap();
        let mut large_token = [7; 192];
        large_token[..token.len()].copy_from_slice(&token);
        let token_on_wire = if capacity_probe {
            &large_token[..]
        } else {
            &token[..]
        };
        let mut retry_packet = [0; 512];
        let retry_len = retry::encode_retry(
            b"original",
            client_id,
            retry_id,
            token_on_wire,
            7,
            &mut retry_packet,
            &mut [0; 600],
        )
        .unwrap();
        let mut corrupted = retry_packet;
        corrupted[retry_len - 1] ^= 1;
        assert_eq!(
            client
                .receive(&corrupted[..retry_len], &mut scratch)
                .unwrap()
                .discarded,
            1
        );
        assert!(client.retry_source_id().is_none());
        assert!(!client.is_retired());
        // Valid but unsupported token capacity is a nonterminal local discard.
        let mut too_big = [0; 512];
        let n = retry::encode_retry(
            b"original",
            client_id,
            retry_id,
            &[1; 193],
            0,
            &mut too_big,
            &mut [0; 600],
        )
        .unwrap();
        assert_eq!(
            client
                .receive(&too_big[..n], &mut scratch)
                .unwrap()
                .discarded,
            1
        );
        assert!(client.retry_source_id().is_none());
        client
            .receive(&retry_packet[..retry_len], &mut scratch)
            .unwrap();
        assert_eq!(client.retry_source_id(), Some(retry_id));
        assert_eq!(client.retry_token(), token_on_wire);
        assert_eq!(client.retry_is_pending(), pending.is_some());
        if let Some(accepted) = pending {
            // Duplicates while the original adapter owns ciphertext cannot retire
            // or overwrite the queued Retry; the callback alone ends ownership.
            assert_eq!(
                client
                    .receive(&retry_packet[..retry_len], &mut scratch)
                    .unwrap()
                    .discarded,
                1
            );
            client.adapter_result(first, accepted, 2).unwrap();
        }
        assert!(!client.retry_is_pending());
        assert_eq!(client.bytes_in_flight(), 0);
        assert!(!client.has_rtt_sample());
        assert!(!client.is_retired());
        assert_eq!(
            client
                .receive(&retry_packet[..retry_len], &mut scratch)
                .unwrap()
                .discarded,
            1
        );
        if capacity_probe {
            for pn in 0..32 {
                let ping = server_initial_ping(client_id, server_id, retry_id, pn * 2);
                assert_eq!(
                    client.receive(&ping, &mut scratch).unwrap().authenticated,
                    1
                );
            }
        }
        let cancelled = client.transmit(&mut out).unwrap().unwrap();
        assert!(cancelled.packet_number.value > first.packet_number.value);
        assert_eq!(
            crypto_fragment(&out[..cancelled.len], retry_id),
            first_crypto
        );
        client.adapter_result(cancelled, false, 3).unwrap();
        let next = client.transmit(&mut out).unwrap().unwrap();
        assert!(next.packet_number.value > cancelled.packet_number.value);
        assert_eq!(next.len, 1200);
        assert_eq!(crypto_fragment(&out[..next.len], retry_id), first_crypto);
        let parsed = PacketIter::new(&out[..next.len], 0, 1)
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        let Header::Long {
            destination_id,
            source_id,
            token: echo,
            ..
        } = parsed.header
        else {
            panic!("Initial expected")
        };
        assert_eq!(
            destination_id,
            if capacity_probe { server_id } else { retry_id }
        );
        assert_eq!(source_id, client_id);
        assert_eq!(echo, token_on_wire);
        if capacity_probe {
            // 900-byte CRYPTO with 192-byte token and max CIDs: 32 ACK ranges
            // do not fit. The first replay kept CRYPTO whole and deferred ACK.
            assert_eq!(first_crypto.1, 900);
            assert!(!crypto_fragment(&out[..next.len], retry_id).3);
            client.adapter_result(next, true, 4).unwrap();
            let following = client.transmit(&mut out).unwrap().unwrap();
            assert!(
                crypto_fragment(&out[..following.len], retry_id).3,
                "deferred ACK survives and fits beside the shorter second fragment"
            );
            client.adapter_result(following, true, 5).unwrap();
            client.retire();
        } else {
            // Server bootstrap consumes the actual echoed token and packet CIDs.
            let admission = issuer
                .validate(4, ADDRESS, destination_id, source_id, echo)
                .unwrap();
            assert_eq!(
                issuer.validate(4, ADDRESS, destination_id, source_id, echo),
                Err(retry::Error::Replayed)
            );
            let mut server = HandshakeEndpoint::new_after_retry(
                Config {
                    side: Side::Server,
                    local_id: server_id,
                    original_destination_id: b"original",
                    generation: 2,
                },
                server_tls,
                driver!(srv, 2),
                server_crypto,
                admission,
            )
            .unwrap();
            assert_eq!(server.retry_source_id(), Some(retry_id));
            client.adapter_result(next, true, 4).unwrap();
            assert_eq!(
                server
                    .receive(&original[..first.len], &mut scratch)
                    .unwrap()
                    .authenticated,
                0
            );
            assert_eq!(
                server
                    .receive(&out[..next.len], &mut scratch)
                    .unwrap()
                    .authenticated,
                1
            );
            assert_eq!(
                server
                    .receive(&out[..next.len], &mut scratch)
                    .unwrap()
                    .discarded,
                1
            );
            let mut mismatch = false;
            'handshake: for turn in 1..32 {
                let now = 4 + turn * 100;
                client.timer(now).unwrap();
                server.timer(now).unwrap();
                transfer(&mut client, &mut server, now);
                for _ in 0..32 {
                    let Some(tx) = server.transmit(&mut out).unwrap() else {
                        break;
                    };
                    server.adapter_result(tx, true, now).unwrap();
                    match client.receive(&out[..tx.len], &mut scratch) {
                        Ok(_) => {}
                        Err(hibana_quic::handshake_endpoint::Error::Parameters(
                            hibana_quic::parameters::Error::ConnectionIdMismatch,
                        )) if bad_parameters => {
                            mismatch = true;
                            break 'handshake;
                        }
                        Err(e) => panic!("handshake failed: {e:?}"),
                    }
                }
                if client.handshake_complete() && server.handshake_complete() {
                    break;
                }
            }
            if bad_parameters {
                assert!(mismatch);
                assert!(client.is_retired());
            } else {
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
                assert_eq!(
                    client
                        .receive(&retry_packet[..retry_len], &mut scratch)
                        .unwrap()
                        .discarded,
                    1
                );
            }
            client.retire();
            server.retire();
        }
    }
    let allocations = TRACK.with(|c| c.replace(None).unwrap());
    assert_eq!(allocations, 0, "Retry plus bounded TLS/Hibana allocated");
}
#[test]
fn retry_full_authenticated_handshake_allocates_zero() {
    run_retry(None, 0, false)
}
#[test]
fn retry_waits_for_accepted_adapter_ownership() {
    run_retry(Some(true), 0, false)
}
#[test]
fn retry_waits_for_cancelled_adapter_ownership() {
    run_retry(Some(false), 0, false)
}
#[test]
fn retry_twenty_byte_cids_changed_initial_scid() {
    run_retry(None, 0, true)
}
#[test]
fn retry_missing_authenticated_retry_scid_parameter_fails() {
    run_retry(None, 1, false)
}

#[test]
fn retry_wrong_authenticated_retry_scid_fails() {
    run_retry(None, 2, false)
}
#[test]
fn retry_wrong_authenticated_original_dcid_fails() {
    run_retry(None, 3, false)
}
#[test]
fn max_token_cids_crypto_defer_ack_without_truncating() {
    run_retry(None, 4, true)
}
