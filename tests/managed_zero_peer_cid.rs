//! Managed nonmigrating zero-peer-CID regression with real actor-owned TLS/QUIC.
//! Initial RX/TX and the whole Provider are distinct projected facets of one
//! session per connection. Every AEAD and integrity-budget loan is awaited.
#![allow(long_running_const_eval)]
#[allow(dead_code)]
#[path = "support/tls_actor_fixture.rs"]
mod fixture;
use hibana::{
    g,
    runtime::{SessionKitStorage, ids::SessionId, program::project},
};
use hibana_quic::{
    bounded_tls::{BoundedTls, ClientConfig, ServerConfig, SigningKey, Storage},
    carrier::{CarrierStorage, LocalCarrier},
    driver::{Driver, Roles},
    handshake::CryptoBuffer,
    handshake_endpoint::{Config, HandshakeEndpoint, Side, TlsClient},
    packet::encode_varint,
    protocol::*,
    tls_certificate::{CertificateDer, Limits, UnixTime, trust_anchor_from_der},
};
use hibana_quic::{
    crypto,
    handshake_endpoint::{InitialKeyProtection, InitialProtection},
    mailbox::Mailbox,
    roles::{
        client::KeyClient,
        packet_protection::{self, Command, Exchange, Reply},
        protocol::key_choreography,
        protocol_tls::tls_choreography,
        tls_owner,
    },
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    time::Duration,
};
use std::{
    future::Future,
    pin::pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
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
    Identity {
        root: CertificateDer::from(fixture::ROOT_DER),
        leaf: CertificateDer::from(fixture::LEAF_DER),
        signing: fixture::signing_key(),
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
async fn transfer<A: InitialKeyProtection, B: InitialKeyProtection>(
    from: &mut HandshakeEndpoint<'_, '_, '_, '_, A>,
    to: &mut HandshakeEndpoint<'_, '_, '_, '_, B>,
    now: u64,
) -> usize {
    let mut out = [0; 1500];
    let mut scratch = [0; 1500];
    for count in 0..64 {
        let Some(tx) = from.transmit(&mut out).await.unwrap() else {
            return count;
        };
        from.adapter_result(tx, true, now).await.unwrap();
        let received = if let Some((_, path)) = to.network_path_state() {
            to.receive_from(
                &out[..tx.len],
                &mut scratch,
                path.address,
                Some(tx.ecn),
                &mut MaxDataHandler::default(),
            )
            .await
            .unwrap()
        } else {
            to.receive_with_metadata(
                &out[..tx.len],
                &mut scratch,
                hibana_quic::ecn::Metadata {
                    path: to.path_identity(),
                    codepoint: Some(tx.ecn),
                },
                &mut MaxDataHandler::default(),
            )
            .await
            .unwrap()
        };
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
        if matches!(frame, hibana_quic::packet::Frame::MaxData { .. }) {
            self.delivered += 1;
        }
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
fn zero_peer_cid_preserves_encrypted_path_accounting_and_rejects_migration() {
    run_zero(0);
}
#[test]
fn zero_peer_cid_rejects_authenticated_new_connection_id() {
    run_zero(1);
}
#[test]
fn zero_peer_cid_keeps_current_local_cid_retirement_rejection() {
    run_zero(2);
}
fn run_zero(violation: u8) {
    let injection = Cell::new(None);
    let id = identity();
    let anchors = [trust_anchor_from_der(&id.root).unwrap()];
    let chain = [id.leaf.as_ref()];
    let client_params = parameters(b"", None);
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
    use hibana_quic::{
        connection_id::{LocalCidSlot, PeerCidSlot},
        handshake_endpoint::{NetworkConfig, NetworkResources},
        path::{Address, PathSlot},
    };
    let address = Address {
        local: "127.0.0.1:4433".parse().unwrap(),
        remote: "127.0.0.1:5566".parse().unwrap(),
    };
    let mut paths = [PathSlot::<1, 3>::empty(), PathSlot::empty()];
    let mut locals = [LocalCidSlot::EMPTY; 8];
    let mut peers = [PeerCidSlot::<2>::EMPTY; 16];
    let mut network_rng = fixture::TestRandom(177);
    let wake = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = Waker::from(wake.clone());
    let sizes;
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
            &mut fixture::TestRandom(349),
        )
        .unwrap();
        let server_tls = BoundedTls::server(
            ServerConfig {
                certificate_chain: &chain,
                signing_key: &id.signing,
                transport_parameters: &server_params,
            },
            sb.storage(),
            &mut fixture::TestRandom(349),
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
        let mut crxc: [Option<Command<1536>>; 1] = [None];
        let mut crxr: [Option<Reply<1536>>; 1] = [None];
        let mut ctxc: [Option<Command<1536>>; 1] = [None];
        let mut ctxr: [Option<Reply<1536>>; 1] = [None];
        let mut srxc: [Option<Command<1536>>; 1] = [None];
        let mut srxr: [Option<Reply<1536>>; 1] = [None];
        let mut stxc: [Option<Command<1536>>; 1] = [None];
        let mut stxr: [Option<Reply<1536>>; 1] = [None];
        let cq = CarrierStorage::<1, 16, 64>::new();
        let mut cslab = [0; 65536];
        let mut cstore = SessionKitStorage::uninit();
        let ckit = cstore.init();
        let csid = SessionId::new(81);
        let car = ckit.rendezvous(&mut cslab, cq.bind(csid).unwrap()).unwrap();
        let cglobal = g::par(
            g::par(key_choreography::<16, 17>(), key_choreography::<18, 19>()),
            tls_choreography::<24, 25>(),
        );
        let cp16 = project::<16, _>(&cglobal);
        let mut ce16 = car.enter(csid, &cp16).unwrap();
        let cp17 = project::<17, _>(&cglobal);
        let mut ce17 = car.enter(csid, &cp17).unwrap();
        let cp18 = project::<18, _>(&cglobal);
        let mut ce18 = car.enter(csid, &cp18).unwrap();
        let cp19 = project::<19, _>(&cglobal);
        let mut ce19 = car.enter(csid, &cp19).unwrap();
        let cp24 = project::<24, _>(&cglobal);
        let mut ce24 = car.enter(csid, &cp24).unwrap();
        let cp25 = project::<25, _>(&cglobal);
        let mut ce25 = car.enter(csid, &cp25).unwrap();
        let mut ctlsc: [Option<tls_owner::Command<1536>>; 1] = [None];
        let mut ctlsr: [Option<tls_owner::Reply<1536, 512>>; 1] = [None];
        let ctlsc = Mailbox::new(&mut ctlsc).unwrap();
        let ctlsr = Mailbox::new(&mut ctlsr).unwrap();
        let (ctlssend, ctlsrecv) = ctlsc.split().unwrap();
        let (ctlsreplysend, ctlsreplyrecv) = ctlsr.split().unwrap();
        let mut ctlsexchange = tls_owner::Exchange::new();
        let crxc = Mailbox::new(&mut crxc).unwrap();
        let crxr = Mailbox::new(&mut crxr).unwrap();
        let (crxsend, crxrecv) = crxc.split().unwrap();
        let (crxreplysend, crxreplyrecv) = crxr.split().unwrap();
        let mut crxexchange = Exchange::new();
        let ctxc = Mailbox::new(&mut ctxc).unwrap();
        let ctxr = Mailbox::new(&mut ctxr).unwrap();
        let (ctxsend, ctxrecv) = ctxc.split().unwrap();
        let (ctxreplysend, ctxreplyrecv) = ctxr.split().unwrap();
        let mut ctxexchange = Exchange::new();
        let ckeys = crypto::initial_keys(b"original").unwrap();
        let sq = CarrierStorage::<1, 16, 64>::new();
        let mut sslab = [0; 65536];
        let mut sstore = SessionKitStorage::uninit();
        let skit = sstore.init();
        let ssid = SessionId::new(82);
        let sar = skit.rendezvous(&mut sslab, sq.bind(ssid).unwrap()).unwrap();
        let sglobal = g::par(
            g::par(key_choreography::<16, 17>(), key_choreography::<18, 19>()),
            tls_choreography::<24, 25>(),
        );
        let sp16 = project::<16, _>(&sglobal);
        let mut se16 = sar.enter(ssid, &sp16).unwrap();
        let sp17 = project::<17, _>(&sglobal);
        let mut se17 = sar.enter(ssid, &sp17).unwrap();
        let sp18 = project::<18, _>(&sglobal);
        let mut se18 = sar.enter(ssid, &sp18).unwrap();
        let sp19 = project::<19, _>(&sglobal);
        let mut se19 = sar.enter(ssid, &sp19).unwrap();
        let sp24 = project::<24, _>(&sglobal);
        let mut se24 = sar.enter(ssid, &sp24).unwrap();
        let sp25 = project::<25, _>(&sglobal);
        let mut se25 = sar.enter(ssid, &sp25).unwrap();
        let mut stlsc: [Option<tls_owner::Command<1536>>; 1] = [None];
        let mut stlsr: [Option<tls_owner::Reply<1536, 512>>; 1] = [None];
        let stlsc = Mailbox::new(&mut stlsc).unwrap();
        let stlsr = Mailbox::new(&mut stlsr).unwrap();
        let (stlssend, stlsrecv) = stlsc.split().unwrap();
        let (stlsreplysend, stlsreplyrecv) = stlsr.split().unwrap();
        let mut stlsexchange = tls_owner::Exchange::new();
        let srxc = Mailbox::new(&mut srxc).unwrap();
        let srxr = Mailbox::new(&mut srxr).unwrap();
        let (srxsend, srxrecv) = srxc.split().unwrap();
        let (srxreplysend, srxreplyrecv) = srxr.split().unwrap();
        let mut srxexchange = Exchange::new();
        let stxc = Mailbox::new(&mut stxc).unwrap();
        let stxr = Mailbox::new(&mut stxr).unwrap();
        let (stxsend, stxrecv) = stxc.split().unwrap();
        let (stxreplysend, stxreplyrecv) = stxr.split().unwrap();
        let mut stxexchange = Exchange::new();
        let skeys = crypto::initial_keys(b"original").unwrap();
        let work = async {
            let client_owner = TlsClient::connect(ctlssend, ctlsreplyrecv, 1)
                .await
                .unwrap();
            let server_owner = TlsClient::connect(stlssend, stlsreplyrecv, 2)
                .await
                .unwrap();
            let cprotection = InitialProtection::new(
                KeyClient::connect(crxsend, crxreplyrecv, 1).await.unwrap(),
                KeyClient::connect(ctxsend, ctxreplyrecv, 1).await.unwrap(),
            )
            .unwrap();
            let sprotection = InitialProtection::new(
                KeyClient::connect(srxsend, srxreplyrecv, 2).await.unwrap(),
                KeyClient::connect(stxsend, stxreplyrecv, 2).await.unwrap(),
            )
            .unwrap();
            let mut client = HandshakeEndpoint::new(
                Config {
                    side: Side::Client,
                    local_id: b"",
                    original_destination_id: b"original",
                    generation: 1,
                },
                client_owner,
                driver!(crv, 1),
                client_crypto,
                cprotection,
            )
            .unwrap();
            let mut server = HandshakeEndpoint::new(
                Config {
                    side: Side::Server,
                    local_id: b"server01",
                    original_destination_id: b"original",
                    generation: 2,
                },
                server_owner,
                driver!(srv, 2),
                server_crypto,
                sprotection,
            )
            .unwrap();
            server
                .enable_network(
                    NetworkConfig::new(address),
                    NetworkResources {
                        paths: &mut paths,
                        local_cids: &mut locals,
                        peer_cids: &mut peers,
                        preferred_advertisement: None,
                    },
                    &mut network_rng,
                )
                .unwrap();
            client.enable_ecn().unwrap();
            server.enable_ecn().unwrap();
            let mut out = [0; 1500];
            let mut scratch = [0; 1500];
            assert!(server.transmit(&mut out).await.unwrap().is_none());
            let first = client.transmit(&mut out).await.unwrap().unwrap();
            client.adapter_result(first, true, 0).await.unwrap();
            let valid = out;
            out[first.len - 1] ^= 1;
            assert_eq!(
                server
                    .receive_from(
                        &out[..first.len],
                        &mut scratch,
                        address,
                        Some(first.ecn),
                        &mut MaxDataHandler::default()
                    )
                    .await
                    .unwrap()
                    .authenticated,
                0
            );
            assert_eq!(server.network_path_state().unwrap().1.received, 0);
            server
                .receive_from(
                    &valid[..first.len],
                    &mut scratch,
                    address,
                    Some(first.ecn),
                    &mut MaxDataHandler::default(),
                )
                .await
                .unwrap();
            let credited = server.network_path_state().unwrap().1;
            assert_eq!(credited.received, first.len as u64);
            assert_eq!(credited.available_bytes, 3 * first.len as u64);
            let pending = server.transmit(&mut out).await.unwrap().unwrap();
            assert_eq!(pending.address, Some(address));
            let packet = hibana_quic::packet::PacketIter::new(&out[..pending.len], 0, 8)
                .unwrap()
                .next()
                .unwrap()
                .unwrap();
            assert!(
                matches!(packet.header, hibana_quic::packet::Header::Long { destination_id, .. } if destination_id.is_empty())
            );
            assert_eq!(
                server.network_path_state().unwrap().1.reserved,
                pending.len as u64
            );
            server.adapter_result(pending, false, 0).await.unwrap();
            assert_eq!(server.network_path_state().unwrap().1.reserved, 0);
            assert_eq!(server.network_path_state().unwrap().1.sent, 0);
            for turn in 1..32 {
                client.timer(turn * 100).await.unwrap();
                server.timer(turn * 100).await.unwrap();
                transfer(&mut server, &mut client, turn * 100).await;
                transfer(&mut client, &mut server, turn * 100).await;
                if client.handshake_complete() && server.handshake_complete() {
                    break;
                }
            }
            assert!(client.handshake_complete() && server.handshake_complete());
            transfer(&mut server, &mut client, 10000).await;
            transfer(&mut client, &mut server, 10000).await;
            let (identity, state) = server.network_path_state().unwrap();
            assert_eq!(state.address, address);
            assert!(state.address_validated && state.mtu_validated);
            assert_eq!(state.reserved, 0);
            assert!(state.sent > 0 && state.received > 0);
            let tx = client
                .transmit_application(&[0x10, 1], &mut out)
                .await
                .unwrap()
                .unwrap();
            client.adapter_result(tx, true, 10000).await.unwrap();
            let mut changed = address;
            changed.remote.set_port(5567);
            let before = server.network_path_state().unwrap();
            let rejected = server
                .receive_from(
                    &out[..tx.len],
                    &mut scratch,
                    changed,
                    Some(tx.ecn),
                    &mut MaxDataHandler::default(),
                )
                .await
                .unwrap();
            assert_eq!(rejected.authenticated, 0);
            assert_eq!(server.network_path_state().unwrap().0, identity);
            assert_eq!(
                server.network_path_state().unwrap().1.received,
                before.1.received
            );
            let mut handler = MaxDataHandler::default();
            assert_eq!(
                server
                    .receive_from(
                        &out[..tx.len],
                        &mut scratch,
                        address,
                        Some(tx.ecn),
                        &mut handler
                    )
                    .await
                    .unwrap()
                    .authenticated,
                1
            );
            assert_eq!(handler.delivered, 1);
            let tx = server
                .transmit_application(&[0x10, 2], &mut out)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(tx.address, Some(address));
            let packet = hibana_quic::packet::PacketIter::new(&out[..tx.len], 0, 8)
                .unwrap()
                .next()
                .unwrap()
                .unwrap();
            assert!(
                matches!(packet.header, hibana_quic::packet::Header::Short { destination_id, .. } if destination_id.is_empty())
            );
            server.adapter_result(tx, true, 10000).await.unwrap();
            let mut handler = MaxDataHandler::default();
            client
                .receive_with_metadata(
                    &out[..tx.len],
                    &mut scratch,
                    hibana_quic::ecn::Metadata {
                        path: client.path_identity(),
                        codepoint: Some(tx.ecn),
                    },
                    &mut handler,
                )
                .await
                .unwrap();
            assert_eq!(handler.delivered, 1);
            transfer(&mut client, &mut server, 10001).await;
            transfer(&mut server, &mut client, 10001).await;
            assert!(
                server
                    .ecn_snapshot()
                    .received
                    .iter()
                    .flatten()
                    .any(|n| n.ect0 > 0)
            );
            assert!(server.ecn_snapshot().failure.is_none());
            if violation != 0 {
                injection.set(Some(violation));
                let mut valid_application = [0; 32];
                for frame in valid_application.chunks_exact_mut(2) {
                    frame.copy_from_slice(&[0x10, 1]);
                }
                let tx = client
                    .transmit_application(&valid_application, &mut out)
                    .await
                    .unwrap()
                    .unwrap();
                client.adapter_result(tx, true, 10002).await.unwrap();
                // The malicious peer has finished all real seal/HP requests.
                // Its unique owner retires normally before the expected receiver abort.
                client.retire_owned().await.unwrap();
                let result = server
                    .receive_from(
                        &out[..tx.len],
                        &mut scratch,
                        address,
                        Some(tx.ecn),
                        &mut MaxDataHandler::default(),
                    )
                    .await;
                if violation == 1 {
                    assert!(matches!(
                        result,
                        Err(hibana_quic::handshake_endpoint::Error::ProtocolViolation)
                    ));
                } else {
                    assert!(matches!(
                        result,
                        Err(hibana_quic::handshake_endpoint::Error::Network(
                            hibana_quic::handshake_endpoint::NetworkError::Cid(
                                hibana_quic::connection_id::CidError::CurrentDestinationCid
                            )
                        ))
                    ));
                }
                assert!(server.is_retired());
                // This exact, assertion-checked application result cancels the
                // expected aborted receiver task. Actor errors never count as success.
                return Err(TestError::ExpectedViolation);
            }
            client.retire_owned().await.unwrap();
            server.retire_owned().await.unwrap();
            Ok::<(), TestError>(())
        };
        let mut crxactor = pin!(async {
            packet_protection::run_borrowed(
                &mut ce16,
                &mut ce17,
                1,
                ckeys.server,
                crxrecv,
                crxreplysend,
                &mut crxexchange,
            )
            .await
            .map_err(TestError::Initial)
        });
        let mut ctxactor = pin!(async {
            packet_protection::run_borrowed(
                &mut ce18,
                &mut ce19,
                1,
                ckeys.client,
                ctxrecv,
                ctxreplysend,
                &mut ctxexchange,
            )
            .await
            .map_err(TestError::Initial)
        });
        let mut srxactor = pin!(async {
            packet_protection::run_borrowed(
                &mut se16,
                &mut se17,
                2,
                skeys.client,
                srxrecv,
                srxreplysend,
                &mut srxexchange,
            )
            .await
            .map_err(TestError::Initial)
        });
        let mut stxactor = pin!(async {
            packet_protection::run_borrowed(
                &mut se18,
                &mut se19,
                2,
                skeys.server,
                stxrecv,
                stxreplysend,
                &mut stxexchange,
            )
            .await
            .map_err(TestError::Initial)
        });
        let mut ctlsactor = pin!(async {
            tls_owner::run_borrowed(
                &mut ce24,
                &mut ce25,
                1,
                Injected {
                    inner: client_tls,
                    next: &injection,
                },
                ctlsrecv,
                ctlsreplysend,
                &mut ctlsexchange,
            )
            .await
            .map_err(TestError::Tls)
        });
        let mut stlsactor = pin!(async {
            tls_owner::run_borrowed(
                &mut se24,
                &mut se25,
                2,
                server_tls,
                stlsrecv,
                stlsreplysend,
                &mut stlsexchange,
            )
            .await
            .map_err(TestError::Tls)
        });
        sizes = [
            core::mem::size_of_val(&work),
            core::mem::size_of_val(crxactor.as_ref().get_ref()),
            core::mem::size_of_val(ctlsactor.as_ref().get_ref()),
        ];
        let mut work = pin!(work);
        let mut complete = pin!(hibana_quic::runtime::TaskSet::new([
            crxactor.as_mut() as hibana_quic::runtime::Task<'_, TestError>,
            ctxactor.as_mut(),
            srxactor.as_mut(),
            stxactor.as_mut(),
            ctlsactor.as_mut(),
            stlsactor.as_mut(),
            work.as_mut(),
        ]));
        match drive(complete.as_mut(), &wake, &waker) {
            Ok(()) => assert_eq!(violation, 0),
            Err(TestError::ExpectedViolation) => assert_ne!(violation, 0),
            Err(TestError::Initial(error)) => panic!("unexpected Initial actor error: {error:?}"),
            Err(TestError::Tls(error)) => panic!("unexpected TLS actor error: {error:?}"),
        }
    }
    let allocations = TRACK.with(|c| c.replace(None).unwrap());
    assert_eq!(allocations, 0, "bounded QUIC/TLS/Hibana flow allocated");
    eprintln!(
        "host future bytes (excluding borrowed storage): work={}, Initial role={}, TLS role={}",
        sizes[0], sizes[1], sizes[2]
    );
}

#[derive(Debug)]
enum TestError {
    Initial(packet_protection::Error),
    Tls(tls_owner::Error),
    ExpectedViolation,
}
struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
fn drive<F: Future>(
    mut future: std::pin::Pin<&mut F>,
    wake: &WakeCount,
    waker: &Waker,
) -> F::Output {
    let mut context = Context::from_waker(waker);
    for _ in 0..2048 {
        let before = wake.0.load(Ordering::SeqCst);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(result) => return result,
            Poll::Pending => assert!(
                wake.0.load(Ordering::SeqCst) > before,
                "fixture parked without a registered wake"
            ),
        }
    }
    panic!("fixture did not finish")
}

/// Test-only malicious peer: replaces one outgoing application payload before
/// the real TLS provider seals it. Authentication/HP and all receives stay real.
struct Injected<'a, T> {
    inner: T,
    next: &'a Cell<Option<u8>>,
}
impl<T: hibana_quic::tls::Provider> hibana_quic::tls::Provider for Injected<'_, T> {
    fn receive(
        &mut self,
        l: hibana_quic::tls::Level,
        b: &[u8],
    ) -> Result<(), hibana_quic::tls::Error> {
        self.inner.receive(l, b)
    }
    fn transmit(
        &mut self,
        b: &mut [u8],
    ) -> Result<Option<hibana_quic::tls::Output>, hibana_quic::tls::Error> {
        self.inner.transmit(b)
    }
    fn has_keys(&self, l: hibana_quic::tls::Level) -> bool {
        self.inner.has_keys(l)
    }
    fn discard_keys(&mut self, l: hibana_quic::tls::Level) {
        self.inner.discard_keys(l)
    }
    fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }
    fn peer_transport_parameters(&self) -> Option<&[u8]> {
        self.inner.peer_transport_parameters()
    }
    fn seal(
        &mut self,
        l: hibana_quic::tls::Level,
        pn: u64,
        h: &[u8],
        b: &mut [u8],
        n: usize,
    ) -> Result<usize, hibana_quic::tls::Error> {
        if l == hibana_quic::tls::Level::OneRtt
            && let Some(violation) = self.next.take()
        {
            b[..n].fill(0);
            let frame = if violation == 1 {
                hibana_quic::packet::Frame::NewConnectionId {
                    sequence: 1,
                    retire_prior_to: 0,
                    id: b"newcid01",
                    reset_token: &[8; 16],
                }
            } else {
                hibana_quic::packet::Frame::RetireConnectionId { sequence: 0 }
            };
            hibana_quic::packet::encode_frame(&frame, &mut b[..n]).unwrap();
        }
        self.inner.seal(l, pn, h, b, n)
    }
    fn open(
        &mut self,
        l: hibana_quic::tls::Level,
        pn: u64,
        h: &[u8],
        b: &mut [u8],
    ) -> Result<usize, hibana_quic::tls::Error> {
        self.inner.open(l, pn, h, b)
    }
    fn header_mask(
        &self,
        l: hibana_quic::tls::Level,
        local: bool,
        s: &[u8; 16],
    ) -> Result<[u8; 5], hibana_quic::tls::Error> {
        self.inner.header_mask(l, local, s)
    }
    fn integrity_budget(&mut self) -> Option<&mut crypto::IntegrityBudget> {
        self.inner.integrity_budget()
    }
    fn key_phase(&self) -> bool {
        self.inner.key_phase()
    }
    fn key_generation(&self) -> u64 {
        self.inner.key_generation()
    }
    fn receive_key_generation(&self) -> u64 {
        self.inner.receive_key_generation()
    }
    fn confirm_handshake(&mut self) -> Result<(), hibana_quic::tls::Error> {
        self.inner.confirm_handshake()
    }
    fn maintain_keys(&mut self, now: u64, pto: u64) -> Result<(), hibana_quic::tls::Error> {
        self.inner.maintain_keys(now, pto)
    }
    fn acknowledge_one_rtt(
        &mut self,
        pn: u64,
        generation: u64,
        now: u64,
        pto: u64,
    ) -> Result<(), hibana_quic::tls::Error> {
        self.inner.acknowledge_one_rtt(pn, generation, now, pto)
    }
    fn open_one_rtt(
        &mut self,
        pn: u64,
        phase: bool,
        h: &[u8],
        b: &mut [u8],
        now: u64,
        pto: u64,
    ) -> Result<crypto::Opened, hibana_quic::tls::Error> {
        self.inner.open_one_rtt(pn, phase, h, b, now, pto)
    }
}
