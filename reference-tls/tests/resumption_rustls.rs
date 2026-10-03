//! Independent cross-peer PSK_DHE tests using pinned rustls QUIC directly.
//! The rustls peer allocates; bounded zero-allocation evidence is in resumption.rs.
use hibana_quic::{
    bounded_tls::{
        BoundedTls, ClientConfig, ClientResumption, ServerConfig, ServerResumption, SigningKey,
        Storage,
    },
    tls::{Level, Provider},
    tls_certificate::{CertificateDer, Limits, UnixTime, trust_anchor_from_der},
    tls_ticket::{
        self as ticket, Binding, ClientCache, ClientSlot, ReplayPolicy, TicketKey,
        VerificationContext,
    },
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
const SERVER_PARAMS: &[u8] = &[0, 0, 15, 0, 4, 1, 63];
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
            if hibana_quic::tls_wire::is_hello_retry_request(&out[..message.len]) {
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
fn bounded_client_resumes_with_rustls_server() {
    let id = identity();
    let anchors = [trust_anchor_from_der(&id.root).unwrap()];
    let clock = Clock;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![id.leaf.clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(id.key.clone()).into(),
        )
        .unwrap();
    config.alpn_protocols = vec![b"hq-interop".to_vec()];
    config.max_early_data_size = 0;
    config.send_tls13_tickets = 1;
    let config = Arc::new(config);
    let mut slots = [ClientSlot::<4096>::empty()];
    let mut cache = ClientCache::new(&mut slots);
    for resumed in [false, true] {
        let offer = if resumed {
            cache
                .take_verified_for_origin(
                    1000,
                    &Binding::new("localhost", b"hq-interop", &[]).unwrap(),
                    0x1301,
                    VerificationContext::new(&anchors, Limits::default()).unwrap(),
                )
                .unwrap()
        } else {
            None
        };
        if resumed {
            assert!(offer.is_some());
        }
        let mut buffers = Buffers::new();
        let cfg = ClientConfig {
            server_name: "localhost",
            trust_anchors: &anchors,
            now: now(),
            certificate_limits: Limits::default(),
            transport_parameters: CLIENT_PARAMS,
        };
        let resumption = ClientResumption {
            store: &mut cache,
            clock: &clock,
        };
        let mut bounded = match offer {
            Some(offer) => {
                BoundedTls::client_resuming(cfg, buffers.storage(), &mut OsRng, resumption, offer)
            }
            None => BoundedTls::client_with_tickets(cfg, buffers.storage(), &mut OsRng, resumption),
        }
        .unwrap();
        let mut peer = Peer::new(Connection::Server(
            rustls::quic::ServerConnection::new(
                config.clone(),
                Version::V1,
                SERVER_PARAMS.to_vec(),
            )
            .unwrap(),
        ));
        handshake(&mut bounded, &mut peer);
        assert_eq!(bounded.is_resumed(), resumed);
        assert_eq!(
            peer.connection.handshake_kind(),
            Some(if resumed {
                rustls::HandshakeKind::Resumed
            } else {
                rustls::HandshakeKind::Full
            })
        );
        packet_keys_match(&mut bounded, &mut peer);
        drop(bounded);
        assert_eq!(cache.len(), 1);
    }
}
#[test]
fn rustls_client_resumes_with_bounded_server_including_real_group_hrr() {
    for retry in [false, true] {
        let id = identity();
        let chain = [id.leaf.as_ref()];
        let clock = Clock;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(id.root.clone()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"hq-interop".to_vec()];
        config.enable_early_data = false;
        let config = Arc::new(config);
        let mut replay = [];
        let mut key =
            TicketKey::generate(&mut OsRng, ReplayPolicy::ReusableOneRtt, &mut replay).unwrap();
        for resumed in [false, true] {
            let mut buffers = Buffers::new();
            let mut entropy = OsRng;
            let server = ServerConfig {
                certificate_chain: &chain,
                signing_key: &id.signing,
                transport_parameters: SERVER_PARAMS,
            };
            let tickets = ServerResumption {
                store: &mut key,
                entropy: &mut entropy,
                clock: &clock,
                policy: b"interop",
                lifetime_seconds: 60,
                max_age_skew_ms: ticket::MAX_AGE_SKEW_MS,
            };
            let mut bounded = if retry && resumed {
                BoundedTls::server_p256_with_tickets(server, buffers.storage(), &mut OsRng, tickets)
            } else {
                BoundedTls::server_with_tickets(server, buffers.storage(), &mut OsRng, tickets)
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
            handshake(&mut bounded, &mut peer);
            assert_eq!(bounded.is_resumed(), resumed);
            assert_eq!(
                peer.connection.handshake_kind(),
                Some(if resumed {
                    rustls::HandshakeKind::Resumed
                } else {
                    rustls::HandshakeKind::Full
                })
            );
            assert_eq!(peer.saw_hrr, retry && resumed);
            packet_keys_match(&mut bounded, &mut peer);
        }
    }
}
