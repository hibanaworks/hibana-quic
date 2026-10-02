//! Real managed-path QUIC/TLS/typed-adapter integration, with allocation measurement.
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
use hibana_quic::{
    connection_id::{LocalCidSlot, PeerCidSlot},
    handshake_endpoint::{NetworkConfig, NetworkResources},
    path::{Address, PathSlot},
};
use p256::pkcs8::DecodePrivateKey;
fn address(side: Side) -> Address {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    let local = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        if side == Side::Client { 40000 } else { 443 },
    );
    let remote = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        if side == Side::Client { 443 } else { 40000 },
    );
    Address { local, remote }
}

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
        let target = tx.address.unwrap();
        let received = to
            .receive_from(
                &out[..tx.len],
                &mut scratch,
                Address {
                    local: target.remote,
                    remote: target.local,
                },
                None,
                &mut MaxDataHandler::default(),
            )
            .unwrap();
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
    managed_wire(false);
}
#[test]
fn verified_preferred_address_uses_actual_cid_advertisement_and_path_validation() {
    managed_wire(true);
}
fn managed_wire(preferred: bool) {
    let id = identity();
    let anchors = [trust_anchor_from_der(&id.root).unwrap()];
    let chain = [id.leaf.as_ref()];
    let client_params = parameters(b"client01", None);
    let mut server_params = parameters(b"server01", Some(b"original"));
    if preferred {
        let mut value = [0u8; 49];
        value[..4].copy_from_slice(&[127, 0, 0, 1]);
        value[4..6].copy_from_slice(&444u16.to_be_bytes());
        value[24] = 8;
        value[25..33].copy_from_slice(b"prefer01");
        value[33..].fill(42);
        server_params.extend_from_slice(&[13, 49]);
        server_params.extend_from_slice(&value);
    }
    let mut advertisement = [0u8; 512];
    let mut cb = Buffers::new();
    let mut sb = Buffers::new();
    // Caller-owned storage and test PKI setup precede the measurement.
    let mut client_slab = [0; 32768];
    let mut server_slab = [0; 32768];
    let mut cd = [[0; 8192]; 3];
    let mut cm = [[0; hibana_quic::handshake::bitmap_bytes(8192)]; 3];
    let mut sd = [[0; 8192]; 3];
    let mut sm = [[0; hibana_quic::handshake::bitmap_bytes(8192)]; 3];
    let mut client_paths = [const { PathSlot::<1, 3>::empty() }; 2];
    let mut server_paths = [const { PathSlot::<1, 3>::empty() }; 2];
    let mut client_local = [LocalCidSlot::EMPTY; 8];
    let mut server_local = [LocalCidSlot::EMPTY; 8];
    let mut client_peer = [PeerCidSlot::<2>::EMPTY; 16];
    let mut server_peer = [PeerCidSlot::<2>::EMPTY; 16];
    let mut client_rng = OsRng;
    let mut server_rng = OsRng;
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
        client
            .enable_network(
                NetworkConfig::new(address(Side::Client)),
                NetworkResources {
                    paths: &mut client_paths,
                    local_cids: &mut client_local,
                    peer_cids: &mut client_peer,
                    preferred_advertisement: None,
                },
                &mut client_rng,
            )
            .unwrap();
        let mut server_network = NetworkConfig::new(address(Side::Server));
        if preferred {
            let mut address = address(Side::Server).local;
            address.set_port(444);
            server_network.preferred_server =
                Some(hibana_quic::handshake_endpoint::PreferredServer {
                    address,
                    connection_id: hibana_quic::connection_id::Cid::new(b"prefer01").unwrap(),
                    reset_token: hibana_quic::connection_id::ResetToken::new([42; 16]),
                });
        }
        server
            .enable_network(
                server_network,
                NetworkResources {
                    paths: &mut server_paths,
                    local_cids: &mut server_local,
                    peer_cids: &mut server_peer,
                    preferred_advertisement: preferred.then_some(&mut advertisement[..]),
                },
                &mut server_rng,
            )
            .unwrap();
        let mut out = [0; 1500];
        let mut scratch = [0; 1500];
        let first = client.transmit(&mut out).unwrap().unwrap();
        client.adapter_result(first, true, 0).unwrap();
        let original = out;
        out[first.len - 1] ^= 1;
        assert_eq!(
            server
                .receive_from(
                    &out[..first.len],
                    &mut scratch,
                    address(server.side()),
                    None,
                    &mut MaxDataHandler::default()
                )
                .unwrap()
                .authenticated,
            0
        );
        assert!(!server.is_retired());
        assert_eq!(server.tls().failed_authentications(), 1);
        let deadline = client.next_deadline().unwrap();
        client.timer(deadline).unwrap();
        server.timer(deadline).unwrap();
        let replay = client.transmit(&mut out).unwrap().unwrap();
        assert_ne!(&out[..replay.len], &original[..first.len]);
        client.adapter_result(replay, true, deadline).unwrap();
        assert_eq!(
            server
                .receive_from(
                    &out[..replay.len],
                    &mut scratch,
                    address(server.side()),
                    None,
                    &mut MaxDataHandler::default()
                )
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
        if preferred {
            for _ in 0..16 {
                transfer(&mut client, &mut server, deadline + 10_000);
                transfer(&mut server, &mut client, deadline + 10_000);
                if client.network_path_state().unwrap().1.address.remote.port() == 444
                    && server.network_path_state().unwrap().1.address.local.port() == 444
                {
                    break;
                }
            }
            let c = client.network_path_state().unwrap().1;
            let s = server.network_path_state().unwrap().1;
            assert_eq!(c.address.remote.port(), 444);
            assert_eq!(s.address.local.port(), 444);
            assert!(
                c.address_validated && c.mtu_validated && s.address_validated && s.mtu_validated
            );
            // Verified token plus actual accepted CID use is necessary; random
            // failed authentication and the wrong exact source cannot reset.
            let mut reset = [0x40u8; 37];
            reset[1..9].copy_from_slice(b"client01");
            reset[21..].fill(43);
            let rejected = client
                .receive_from(
                    &reset,
                    &mut scratch,
                    c.address,
                    None,
                    &mut MaxDataHandler::default(),
                )
                .unwrap();
            assert_eq!(rejected.authenticated, 0);
            assert_eq!(
                client.connection_state(),
                hibana_quic::lifecycle::State::Active
            );
            reset[21..].fill(42);
            let wrong_source = client
                .receive_from(
                    &reset,
                    &mut scratch,
                    address(Side::Client),
                    None,
                    &mut MaxDataHandler::default(),
                )
                .unwrap();
            assert_eq!(wrong_source.authenticated, 0);
            assert_eq!(
                client.connection_state(),
                hibana_quic::lifecycle::State::Active
            );
            let accepted = client
                .receive_from(
                    &reset,
                    &mut scratch,
                    c.address,
                    None,
                    &mut MaxDataHandler::default(),
                )
                .unwrap();
            assert_eq!(accepted.authenticated, 0);
            assert_eq!(
                client.connection_state(),
                hibana_quic::lifecycle::State::Draining
            );
            assert!(client.transmit(&mut out).unwrap().is_none());
        } else {
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
                .receive_from(
                    &out[..tx.len],
                    &mut scratch,
                    address(server.side()),
                    None,
                    &mut sh,
                )
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
            assert!(matches!(
                server.receive_from(
                    &out[..update.len],
                    &mut scratch,
                    address(server.side()),
                    None,
                    &mut sh
                ),
                Err(hibana_quic::handshake_endpoint::Error::Busy)
            ));
            assert!(!server.is_retired());
            assert_eq!(server.tls().key_generation(), 0);
            server.adapter_result(pending, false, now).unwrap();
            let received = server
                .receive_from(
                    &out[..update.len],
                    &mut scratch,
                    address(server.side()),
                    None,
                    &mut sh,
                )
                .unwrap();
            assert_eq!(received.authenticated, 1);
            assert_eq!(server.tls().key_generation(), 1); // before generating its ACK
            transfer(&mut server, &mut client, now);
            assert_eq!(client.tls().key_generation(), 1);
            let received = client
                .receive_from(
                    &delayed[..delayed_tx.len],
                    &mut scratch,
                    address(client.side()),
                    None,
                    &mut ch,
                )
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
                    .receive_from(
                        &out[..update.len],
                        &mut scratch,
                        address(client.side()),
                        None,
                        &mut ch
                    )
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
                    .receive_from(
                        &delayed[..delayed_tx.len],
                        &mut scratch,
                        address(client.side()),
                        None,
                        &mut ch
                    )
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
            // Model a NAT's external port change. The client retains its internal
            // tuple, but the server receives each datagram from a fresh exact port.
            // Old-port validation probes really leave the adapter and are dropped.
            let mut rebound = address(Side::Server);
            rebound.remote.set_port(50001);
            // Hold a genuine authenticated ACK of a packet sent on the old
            // tuple, then deliver it after migration on the new tuple.
            let old = server
                .transmit_application(&[0x10, 7], &mut out)
                .unwrap()
                .unwrap();
            server.adapter_result(old, true, now).unwrap();
            client
                .receive_from(
                    &out[..old.len],
                    &mut scratch,
                    address(Side::Client),
                    None,
                    &mut ch,
                )
                .unwrap();
            let old_ack = client.transmit(&mut out).unwrap().unwrap();
            client.adapter_result(old_ack, true, now).unwrap();
            let old_ack_bytes = out;
            let original_path = server.network_path_state().unwrap().0;
            let moved = client
                .transmit_application(&[0x10, 6], &mut out)
                .unwrap()
                .unwrap();
            client.adapter_result(moved, true, now).unwrap();
            let received = server
                .receive_from(&out[..moved.len], &mut scratch, rebound, None, &mut sh)
                .unwrap();
            assert_eq!(received.authenticated, 1);
            assert_ne!(server.network_path_state().unwrap().0, original_path);
            assert_eq!(server.network_path_state().unwrap().1.address, rebound);
            assert!(!server.network_path_state().unwrap().1.address_validated);
            let now = now + 500;
            client.timer(now).unwrap();
            server.timer(now).unwrap();
            assert!(!server.has_rtt_sample());
            let window = server.congestion_window();
            server
                .receive_from(
                    &old_ack_bytes[..old_ack.len],
                    &mut scratch,
                    rebound,
                    None,
                    &mut sh,
                )
                .unwrap();
            assert!(
                !server.has_rtt_sample(),
                "old-path ACK must not sample the new RTT"
            );
            assert_eq!(
                server.congestion_window(),
                window,
                "old-path ACK must not grow new-path cwnd"
            );

            assert!(
                server.network_path_state().unwrap().1.sent
                    <= 3 * server.network_path_state().unwrap().1.received
            );
            let mut short_probe = false;
            let mut full_probe = false;
            let mut dropped_old = 0;
            for _ in 0..16 {
                for _ in 0..16 {
                    let Some(tx) = server.transmit(&mut out).unwrap() else {
                        break;
                    };
                    let target = tx.address.unwrap();
                    server.adapter_result(tx, true, now).unwrap();
                    if target.remote.port() == 40000 {
                        dropped_old += 1;
                        continue;
                    }
                    assert_eq!(target, rebound);
                    let state = server.network_path_state().unwrap().1;
                    if !state.address_validated {
                        assert!(state.sent <= 3 * state.received);
                        short_probe |= tx.len < 1200;
                    }
                    full_probe |= tx.len == 1200;
                    client
                        .receive_from(
                            &out[..tx.len],
                            &mut scratch,
                            address(Side::Client),
                            None,
                            &mut ch,
                        )
                        .unwrap();
                }
                for _ in 0..16 {
                    let Some(tx) = client.transmit(&mut out).unwrap() else {
                        break;
                    };
                    client.adapter_result(tx, true, now).unwrap();
                    server
                        .receive_from(&out[..tx.len], &mut scratch, rebound, None, &mut sh)
                        .unwrap();
                }
                if server.network_path_state().unwrap().1.mtu_validated {
                    break;
                }
            }
            let state = server.network_path_state().unwrap().1;
            assert!(state.address_validated && state.mtu_validated);
            assert!(short_probe && full_probe && dropped_old > 0);
            assert_eq!(state.address, rebound);
            // Explicit initiation identifies each next prepared datagram as
            // genuine protected CLOSE, without guessing encrypted frame types.
            use hibana_quic::lifecycle::{CloseReason, State as ConnectionState};
            let activity = server
                .transmit_application(&[0x10, 8], &mut out)
                .unwrap()
                .unwrap();
            server.adapter_result(activity, true, now).unwrap();
            let activity_bytes = out;
            client
                .close(CloseReason::application(0, "complete").unwrap())
                .unwrap();
            let deadline = client.close_deadline().unwrap();
            let lost = client.transmit(&mut out).unwrap().unwrap();
            assert!(client.transmit_permitted(lost, now).unwrap());
            client.adapter_result(lost, true, now).unwrap();
            let lost_bytes = out; // Accepted by the adapter, deliberately not delivered.
            assert_eq!(server.connection_state(), ConnectionState::Active);
            assert!(client.transmit(&mut out).unwrap().is_none());
            let retry_at = now + (deadline - now) / 12 + 1;
            client.timer(retry_at).unwrap();
            server.timer(retry_at).unwrap();
            client
                .receive_from(
                    &activity_bytes[..activity.len],
                    &mut scratch,
                    address(Side::Client),
                    None,
                    &mut ch,
                )
                .unwrap();
            assert_eq!(client.close_deadline(), Some(deadline));
            assert_eq!(client.connection_state(), ConnectionState::Closing);
            let close = client.transmit(&mut out).unwrap().unwrap();
            assert!(close.packet_number.value > lost.packet_number.value);
            client.adapter_result(close, true, retry_at).unwrap();
            let close_bytes = out;
            let delivered_at = retry_at + (deadline - now) / 24 + 1;
            server.timer(delivered_at).unwrap(); // Delay the unambiguous second CLOSE.
            assert_eq!(server.connection_state(), ConnectionState::Active);
            assert_eq!(
                server
                    .receive_from(
                        &close_bytes[..close.len],
                        &mut scratch,
                        rebound,
                        None,
                        &mut MaxDataHandler::default()
                    )
                    .unwrap()
                    .authenticated,
                1
            );
            assert_eq!(server.connection_state(), ConnectionState::Draining);
            let draining_until = server.close_deadline();
            // A very late first CLOSE cannot restart draining or send a reply.
            server
                .receive_from(
                    &lost_bytes[..lost.len],
                    &mut scratch,
                    rebound,
                    None,
                    &mut MaxDataHandler::default(),
                )
                .unwrap();
            assert_eq!(server.close_deadline(), draining_until);
            assert!(server.transmit(&mut out).unwrap().is_none());
            client.timer(deadline).unwrap();
            server.timer(server.close_deadline().unwrap()).unwrap();
            assert_eq!(client.connection_state(), ConnectionState::Closed);
            assert_eq!(server.connection_state(), ConnectionState::Closed);
        }
    }
    // Endpoint terminal retirement and Drop release the same caller arrays;
    // fresh connection generations retain the slots' increasing epochs.
    let config = hibana_quic::path::Config {
        probe_interval_us: 100,
        validation_timeout_us: 300,
        max_attempts: 3,
    };
    let mut fresh = hibana_quic::path::Paths::new(&mut client_paths, 3, config).unwrap();
    let path = fresh
        .insert(
            address(Side::Client),
            hibana_quic::path::InitialValidation::ClientUnvalidated,
            0,
        )
        .unwrap();
    assert!(path.path_generation > 1);
    assert!(hibana_quic::path::Paths::new(&mut server_paths, 4, config).is_ok());
    let allocations = TRACK.with(|c| c.replace(None).unwrap());
    assert_eq!(allocations, 0, "bounded QUIC/TLS/Hibana flow allocated");
}
