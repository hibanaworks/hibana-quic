//! Independent cross-peer PSK_DHE tests using pinned rustls QUIC directly.
//! The rustls peer allocates; bounded zero-allocation evidence is in resumption.rs.
use hibana_quic::{
    early_data::{EarlyFreshness, EarlyStatus, QuarantineSlot, ReplayStorage, ServerPolicy},
    tls::handshake::{ClientEarlyData, ServerEarlyData},
};
use hibana_quic::{
    tls::certificate::{CertificateDer, Limits, UnixTime, trust_anchor_from_der},
    tls::handshake::{
        BoundedTls, ClientConfig, ClientResumption, ServerConfig, ServerResumption, SigningKey,
        Storage,
    },
    tls::ticket::{
        self as ticket, Binding, ClientCache, ClientSlot, ReplayPolicy, TicketKey,
        VerificationContext,
    },
    tls::{Level, Provider},
};
use hibana_quic_reference_tls::rustls;
use p256::pkcs8::DecodePrivateKey;
use rand_core::OsRng;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use rustls::quic::{Connection, KeyChange, Keys, Version};
use std::{sync::Arc, time::Duration};
struct Identity {
    root: CertificateDer<'static>,
    leaf: CertificateDer<'static>,
    signing: SigningKey,
    key: Vec<u8>,
}
fn identity() -> Identity {
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_key = KeyPair::generate().unwrap();
    let ca = ca.self_signed(&ca_key).unwrap();
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let leaf = params.signed_by(&key, &ca, &ca_key).unwrap();
    let der = key.serialize_der();
    let signing = SigningKey::from_pkcs8_der(&der).unwrap();
    Identity {
        root: ca.der().clone(),
        leaf: leaf.der().clone(),
        signing,
        key: der,
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
fn now() -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_000))
}
const CLIENT_PARAMS: &[u8] = &[15, 0, 4, 1, 42];
const SERVER_PARAMS: &[u8] = &[0, 0, 15, 0, 4, 2, 0x48, 0, 6, 2, 0x44, 0, 8, 1, 2];
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
struct Peer {
    connection: Connection,
    level: Level,
    application: Option<Keys>,
    saw_hrr: bool,
}
impl Peer {
    fn new(connection: Connection) -> Self {
        Self {
            connection,
            level: Level::Initial,
            application: None,
            saw_hrr: false,
        }
    }
}
fn flush_peer(bounded: &mut BoundedTls<'_, '_>, peer: &mut Peer) -> bool {
    let mut progress = false;
    loop {
        let mut bytes = Vec::new();
        let change = peer.connection.write_hs(&mut bytes);
        let empty = bytes.is_empty();
        for fragment in bytes.chunks(41) {
            let state = bounded.state();
            if let Err(e) = bounded.receive(peer.level, fragment) {
                panic!(
                    "{e:?}: {:?}, before={state:?}, level={:?}, kind={:?}",
                    bounded.last_failure(),
                    peer.level,
                    bytes.first()
                );
            }
        }
        progress |= !empty;
        match change {
            Some(KeyChange::Handshake { .. }) => peer.level = Level::Handshake,
            Some(KeyChange::OneRtt { keys, .. }) => {
                peer.application = Some(keys);
                peer.level = Level::OneRtt;
            }
            None if empty => return progress,
            None => {}
        }
    }
}
fn handshake(bounded: &mut BoundedTls<'_, '_>, peer: &mut Peer) {
    let mut out = [0; 4096];
    for _ in 0..32 {
        let mut progress = flush_peer(bounded, peer);
        while let Some(message) = bounded.transmit(&mut out).unwrap() {
            if hibana_quic::tls::wire::is_hello_retry_request(&out[..message.len]) {
                peer.saw_hrr = true;
            }
            for fragment in out[..message.len].chunks(37) {
                peer.connection.read_hs(fragment).unwrap();
            }
            // Drain key-change notifications before delivering the next level.
            // Otherwise rustls's pending secret notification can advance past it.
            flush_peer(bounded, peer);
            progress = true;
        }
        if !progress {
            assert!(!bounded.is_handshaking());
            assert!(!peer.connection.is_handshaking());
            return;
        }
    }
    panic!("handshake did not quiesce")
}
fn packet_keys_match(bounded: &mut BoundedTls<'_, '_>, peer: &mut Peer) {
    let keys = peer.application.as_mut().unwrap();
    let mut encrypted = [0; 30];
    encrypted[..14].copy_from_slice(b"resumed secret");
    assert_eq!(
        bounded.seal(Level::OneRtt, 0, b"header", &mut encrypted, 14),
        Ok(30)
    );
    let plaintext = keys
        .remote
        .packet
        .decrypt_in_place(0, b"header", &mut encrypted)
        .unwrap();
    assert_eq!(plaintext, b"resumed secret");
    let mut payload = [0; 14];
    payload.copy_from_slice(b"reverse secret");
    let tag = keys
        .local
        .packet
        .encrypt_in_place(0, b"header", &mut payload)
        .unwrap();
    encrypted[..14].copy_from_slice(&payload);
    encrypted[14..].copy_from_slice(tag.as_ref());
    assert_eq!(
        bounded.open(Level::OneRtt, 0, b"header", &mut encrypted),
        Ok(14)
    );
    assert_eq!(&encrypted[..14], b"reverse secret");
}
#[test]
fn bounded_client_early_keys_interoperate_with_rustls_and_explicit_rejection() {
    for reject in [false, true] {
        let id = identity();
        let anchors = [trust_anchor_from_der(&id.root).unwrap()];
        let clock = Clock;
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![id.leaf.clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(id.key.clone()).into(),
        )
        .unwrap();
        config.alpn_protocols = vec![b"hq-interop".to_vec()];
        config.max_early_data_size = u32::MAX;
        config.send_tls13_tickets = 1;
        let config = Arc::new(config);
        let mut slots = [ClientSlot::<4096>::empty()];
        let mut cache = ClientCache::new(&mut slots);
        for resumed in [false, true] {
            let offer = if resumed {
                Some(
                    cache
                        .take_verified_for_origin(
                            1000,
                            &Binding::new("localhost", b"hq-interop", &[]).unwrap(),
                            0x1301,
                            VerificationContext::new(&anchors, Limits::default()).unwrap(),
                        )
                        .unwrap()
                        .unwrap(),
                )
            } else {
                None
            };
            let mut buffers = Buffers::new();
            let client = ClientConfig {
                protocol: Default::default(),
                version: hibana_quic::version::Version::V1,
                server_name: "localhost",
                trust_anchors: &anchors,
                now: now(),
                certificate_limits: Limits::default(),
                transport_parameters: CLIENT_PARAMS,
            };
            let service = ClientResumption {
                store: &mut cache,
                clock: &clock,
            };
            let mut bounded = match offer {
                Some(offer) => BoundedTls::client_resuming_early(
                    client,
                    buffers.storage(),
                    &mut OsRng,
                    service,
                    offer,
                    ClientEarlyData::replay_safe_requests(2),
                ),
                None => {
                    BoundedTls::client_with_tickets(client, buffers.storage(), &mut OsRng, service)
                }
            }
            .unwrap();
            let mut remote = rustls::quic::ServerConnection::new(
                config.clone(),
                Version::V1,
                SERVER_PARAMS.to_vec(),
            )
            .unwrap();
            if resumed && reject {
                remote.reject_early_data();
            }
            let mut peer = Peer::new(Connection::Server(remote));
            if resumed {
                let mut hello = [0; 4096];
                let ch = bounded.transmit(&mut hello).unwrap().unwrap();
                peer.connection.read_hs(&hello[..ch.len]).unwrap();
                let request = b"GET /early\r\n";
                let mut packet = [0; 64];
                packet[..request.len()].copy_from_slice(request);
                let n = bounded
                    .seal_early(0, b"header", &mut packet, request.len())
                    .unwrap();
                if !reject {
                    let keys = peer
                        .connection
                        .zero_rtt_keys()
                        .expect("rustls did not derive early keys");
                    assert_eq!(
                        keys.packet
                            .decrypt_in_place(0, b"header", &mut packet[..n])
                            .unwrap(),
                        request
                    );
                } else {
                    assert!(peer.connection.zero_rtt_keys().is_none());
                }
            }
            handshake(&mut bounded, &mut peer);
            assert_eq!(bounded.is_resumed(), resumed);
            assert_eq!(
                bounded.early_status(),
                if !resumed {
                    EarlyStatus::Disabled
                } else if reject {
                    EarlyStatus::Rejected
                } else {
                    EarlyStatus::Accepted
                }
            );
            assert!(!bounded.has_early_keys());
            packet_keys_match(&mut bounded, &mut peer);
            drop(bounded);
            assert_eq!(cache.len(), 1);
        }
    }
}
#[test]
fn rustls_client_early_keys_interoperate_and_real_hrr_rejects_early_only() {
    for retry in [false, true] {
        let id = identity();
        let chain = [id.leaf.as_ref()];
        let clock = Clock;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(id.root.clone()).unwrap();
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.alpn_protocols = vec![b"hq-interop".to_vec()];
        config.enable_early_data = true;
        let config = Arc::new(config);
        let mut ordinary = [];
        let mut replay = ReplayStorage::<4>::new();
        let mut key = TicketKey::generate_with_early_replay(
            &mut OsRng,
            ReplayPolicy::ReusableOneRtt,
            &mut ordinary,
            &mut replay,
        )
        .unwrap();
        for resumed in [false, true] {
            let mut buffers = Buffers::new();
            let held = [QuarantineSlot::<1024>::EMPTY, QuarantineSlot::EMPTY];
            let mut entropy = OsRng;
            let server = ServerConfig {
                protocol: Default::default(),
                version: hibana_quic::version::Version::V1,
                certificate_chain: &chain,
                signing_key: &id.signing,
                transport_parameters: SERVER_PARAMS,
            };
            let service = ServerResumption {
                store: &mut key,
                entropy: &mut entropy,
                clock: &clock,
                policy: b"early interop",
                lifetime_seconds: 60,
                max_age_skew_ms: 10_000,
            };
            let admission = ServerEarlyData::buffered(
                if resumed { 2 } else { 1 },
                EARLY_POLICY,
                SERVER_PARAMS,
                &held,
                EarlyFreshness::new(1000).unwrap(),
            )
            .unwrap();
            let mut bounded = if retry && resumed {
                BoundedTls::server_p256_with_early_data(
                    server,
                    buffers.storage(),
                    &mut OsRng,
                    service,
                    admission,
                )
            } else {
                BoundedTls::server_with_early_data(
                    server,
                    buffers.storage(),
                    &mut OsRng,
                    service,
                    admission,
                )
            }
            .unwrap();
            let mut peer = Peer::new(Connection::Client(
                rustls::quic::ClientConnection::new(
                    config.clone(),
                    Version::V1,
                    rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                    CLIENT_PARAMS.to_vec(),
                )
                .unwrap(),
            ));
            if resumed {
                assert!(flush_peer(&mut bounded, &mut peer));
                let keys = peer
                    .connection
                    .zero_rtt_keys()
                    .expect("rustls client had no early secret");
                let request = b"GET /early\r\n";
                let mut packet = [0; 64];
                packet[..request.len()].copy_from_slice(request);
                let tag = keys
                    .packet
                    .encrypt_in_place(0, b"header", &mut packet[..request.len()])
                    .unwrap();
                packet[request.len()..request.len() + 16].copy_from_slice(tag.as_ref());
                if !retry {
                    assert_eq!(bounded.early_status(), EarlyStatus::AcceptedPendingFinished);
                    let n = bounded
                        .open_early(0, b"header", &mut packet[..request.len() + 16])
                        .unwrap();
                    assert_eq!(&packet[..n], request);
                    assert!(bounded.is_handshaking());
                } else {
                    assert_eq!(bounded.early_status(), EarlyStatus::Rejected);
                    assert_eq!(
                        bounded.open_early(0, b"header", &mut packet[..request.len() + 16]),
                        Err(hibana_quic::tls::Error::KeysUnavailable)
                    );
                }
            }
            handshake(&mut bounded, &mut peer);
            assert_eq!(bounded.is_resumed(), resumed);
            assert_eq!(
                bounded.early_status(),
                if !resumed {
                    EarlyStatus::Disabled
                } else if retry {
                    EarlyStatus::Rejected
                } else {
                    EarlyStatus::Accepted
                }
            );
            assert_eq!(peer.saw_hrr, retry && resumed);
            let Connection::Client(client) = &peer.connection else {
                panic!()
            };
            assert_eq!(client.is_early_data_accepted(), resumed && !retry);
            packet_keys_match(&mut bounded, &mut peer);
        }
    }
}
