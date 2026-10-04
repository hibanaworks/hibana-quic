//! Real bounded TLS full handshakes; rcgen/rustls and fixture setup are host-only.
use hibana_quic::{
    bounded_tls::{BoundedTls, ClientConfig, ServerConfig, SigningKey, State, Storage},
    crypto::CipherSuite,
    tls::{self, Level, Provider},
    tls_certificate::{CertificateDer, Limits, ServerName, UnixTime, trust_anchor_from_der},
};
use hibana_quic_reference_tls::{RustlsProvider, rustls};
use p256::pkcs8::DecodePrivateKey;
use rand_core::{CryptoRng, OsRng, RngCore};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    time::Duration,
};

// Thread-local measurement avoids allocations in unrelated parallel test threads.
thread_local! { static TRACK: Cell<Option<usize>> = const { Cell::new(None) }; }
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
fn measured<T>(f: impl FnOnce() -> T) -> T {
    TRACK.with(|c| c.set(Some(0)));
    let value = f();
    let n = TRACK.with(|c| c.replace(None).unwrap());
    assert_eq!(
        n, 0,
        "bounded TLS constructors and full handshake allocated"
    );
    value
}

struct Identity {
    root: CertificateDer<'static>,
    leaf: CertificateDer<'static>,
    key: Vec<u8>,
    signing: SigningKey,
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
        key: der,
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
fn now() -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_000))
}
const CLIENT_PARAMS: &[u8] = &[4, 1, 42];
const SERVER_PARAMS: &[u8] = &[4, 1, 63];
fn drain(
    from: &mut impl Provider,
    to: &mut impl Provider,
    fragment: usize,
) -> Result<bool, tls::Error> {
    let mut buffer = [0; 4096];
    let mut progress = false;
    for _ in 0..10000 {
        let Some(out) = from.transmit(&mut buffer[..fragment])? else {
            return Ok(progress);
        };
        progress = true;
        to.receive(out.level, &buffer[..out.len])?;
    }
    panic!("unbounded handshake output")
}
fn handshake(
    client: &mut impl Provider,
    server: &mut impl Provider,
    fragment: usize,
) -> Result<(), tls::Error> {
    for _ in 0..16 {
        let c = drain(client, server, fragment)?;
        let s = drain(server, client, fragment)?;
        if !c && !s {
            return if client.is_handshaking() || server.is_handshaking() {
                Err(tls::Error::Handshake)
            } else {
                Ok(())
            };
        }
    }
    Err(tls::Error::Handshake)
}
fn packets(sender: &mut impl Provider, receiver: &mut impl Provider) {
    for level in [Level::Handshake, Level::OneRtt] {
        let mut bytes = [0; 30];
        bytes[..14].copy_from_slice(b"bounded secret");
        assert_eq!(sender.seal(level, 7, b"header", &mut bytes, 14), Ok(30));
        let mut local_mask = sender.header_mask(level, true, &[7; 16]).unwrap();
        let mut remote_mask = receiver.header_mask(level, false, &[7; 16]).unwrap();
        local_mask[0] &= 0x1f;
        remote_mask[0] &= 0x1f;
        assert_eq!(local_mask, remote_mask);
        let mut bad = bytes;
        bad[0] ^= 1;
        assert_eq!(
            receiver.open(level, 7, b"header", &mut bad),
            Err(tls::Error::Authentication)
        );
        assert_eq!(bad, [0; 30]);
        assert_eq!(receiver.open(level, 7, b"header", &mut bytes), Ok(14));
        assert_eq!(&bytes[..14], b"bounded secret");
        assert_eq!(
            sender.seal(level, 7, b"header", &mut bytes, 14),
            Err(tls::Error::PacketNumberReuse)
        );
    }
}

#[test]
fn bounded_both_roles_real_full_handshake_and_packet_keys_allocate_zero() {
    for fragment in [1, 3, 17, 127, 4096] {
        let id = identity();
        let anchors = [trust_anchor_from_der(&id.root).unwrap()];
        let chain = [id.leaf.as_ref()];
        let mut cb = Buffers::new();
        let mut sb = Buffers::new();
        let mut rng = OsRng;
        measured(|| {
            let mut client = BoundedTls::client(
                ClientConfig {
                    server_name: "localhost",
                    trust_anchors: &anchors,
                    now: now(),
                    certificate_limits: Limits::default(),
                    transport_parameters: CLIENT_PARAMS,
                },
                cb.storage(),
                &mut rng,
            )
            .unwrap();
            let mut server = BoundedTls::server(
                ServerConfig {
                    certificate_chain: &chain,
                    signing_key: &id.signing,
                    transport_parameters: SERVER_PARAMS,
                },
                sb.storage(),
                &mut rng,
            )
            .unwrap();
            if let Err(error) = handshake(&mut client, &mut server, fragment) {
                panic!(
                    "{error:?}; client={:?}; server={:?}",
                    client.last_failure(),
                    server.last_failure()
                )
            }
            assert_eq!(client.state(), State::Connected);
            assert_eq!(server.state(), State::Connected);
            assert_eq!(client.peer_transport_parameters(), Some(SERVER_PARAMS));
            assert_eq!(server.peer_transport_parameters(), Some(CLIENT_PARAMS));
            assert_eq!(client.negotiated_alpn(), Some(b"hq-interop".as_slice()));
            assert_eq!(
                client.negotiated_suite(),
                Some(CipherSuite::Aes128GcmSha256)
            );
            packets(&mut client, &mut server);
            packets(&mut server, &mut client);
            client.discard_keys(Level::Handshake);
            assert!(!client.has_keys(Level::Handshake));
            assert_eq!(
                client.header_mask(Level::Handshake, true, &[0; 16]),
                Err(tls::Error::KeysUnavailable)
            );
            server.discard_keys(Level::OneRtt);
            assert!(!server.has_keys(Level::OneRtt));
        });
    }
}

#[test]
fn bounded_client_authenticates_real_rustls_server() {
    let id = identity();
    let anchors = [trust_anchor_from_der(&id.root).unwrap()];
    let mut buffers = Buffers::new();
    let mut client = BoundedTls::client(
        ClientConfig {
            server_name: "localhost",
            trust_anchors: &anchors,
            now: now(),
            certificate_limits: Limits::default(),
            transport_parameters: CLIENT_PARAMS,
        },
        buffers.storage(),
        &mut OsRng,
    )
    .unwrap();
    let mut server = RustlsProvider::server(
        vec![id.leaf],
        rustls::pki_types::PrivatePkcs8KeyDer::from(id.key).into(),
        SERVER_PARAMS.to_vec(),
    )
    .unwrap();
    if let Err(error) = handshake(&mut client, &mut server, 13) {
        panic!(
            "{error:?}; bounded={:?}; rustls={:?}",
            client.last_failure(),
            server.last_tls_error()
        )
    }
    assert_eq!(
        client.negotiated_group(),
        Some(hibana_quic::tls_wire::GROUP_X25519)
    );
    packets(&mut client, &mut server);
    packets(&mut server, &mut client);
    assert_eq!(client.peer_transport_parameters(), Some(SERVER_PARAMS));
}

#[test]
fn rustls_client_authenticates_real_bounded_server() {
    let id = identity();
    let chain = [id.leaf.as_ref()];
    let mut buffers = Buffers::new();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(id.root.clone()).unwrap();
    let mut client = RustlsProvider::client_p256(
        roots,
        ServerName::try_from("localhost").unwrap(),
        CLIENT_PARAMS.to_vec(),
    )
    .unwrap();
    let mut server = BoundedTls::server(
        ServerConfig {
            certificate_chain: &chain,
            signing_key: &id.signing,
            transport_parameters: SERVER_PARAMS,
        },
        buffers.storage(),
        &mut OsRng,
    )
    .unwrap();
    if let Err(error) = handshake(&mut client, &mut server, 19) {
        panic!(
            "{error:?}; rustls={:?}; bounded={:?}",
            client.last_tls_error(),
            server.last_failure()
        )
    }
    packets(&mut client, &mut server);
    packets(&mut server, &mut client);
}

#[test]
fn bounded_client_rejects_wrong_ca_hostname_and_finished() {
    for wrong_ca in [true, false] {
        let id = identity();
        let unrelated = identity();
        let root = if wrong_ca { &unrelated.root } else { &id.root };
        let anchors = [trust_anchor_from_der(root).unwrap()];
        let mut buffers = Buffers::new();
        let name = if wrong_ca {
            "localhost"
        } else {
            "wrong.example"
        };
        let mut client = BoundedTls::client(
            ClientConfig {
                server_name: name,
                trust_anchors: &anchors,
                now: now(),
                certificate_limits: Limits::default(),
                transport_parameters: CLIENT_PARAMS,
            },
            buffers.storage(),
            &mut OsRng,
        )
        .unwrap();
        let mut server = RustlsProvider::server(
            vec![id.leaf],
            rustls::pki_types::PrivatePkcs8KeyDer::from(id.key).into(),
            SERVER_PARAMS.to_vec(),
        )
        .unwrap();
        assert!(handshake(&mut client, &mut server, 7).is_err());
        assert_eq!(client.state(), State::Failed);
        assert!(client.peer_transport_parameters().is_none());
        assert!(!client.has_keys(Level::Handshake));
        assert!(!client.has_keys(Level::OneRtt));
    }
    let id = identity();
    let anchors = [trust_anchor_from_der(&id.root).unwrap()];
    let chain = [id.leaf.as_ref()];
    let mut cb = Buffers::new();
    let mut sb = Buffers::new();
    let mut client = BoundedTls::client(
        ClientConfig {
            server_name: "localhost",
            trust_anchors: &anchors,
            now: now(),
            certificate_limits: Limits::default(),
            transport_parameters: CLIENT_PARAMS,
        },
        cb.storage(),
        &mut OsRng,
    )
    .unwrap();
    let mut server = BoundedTls::server(
        ServerConfig {
            certificate_chain: &chain,
            signing_key: &id.signing,
            transport_parameters: SERVER_PARAMS,
        },
        sb.storage(),
        &mut OsRng,
    )
    .unwrap();
    drain(&mut client, &mut server, 4096).unwrap();
    let mut buf = [0; 4096];
    let initial = server.transmit(&mut buf).unwrap().unwrap();
    assert_eq!(initial.level, Level::Initial);
    client.receive(initial.level, &buf[..initial.len]).unwrap();
    let flight = server.transmit(&mut buf).unwrap().unwrap();
    assert_eq!(flight.level, Level::Handshake);
    buf[flight.len - 1] ^= 1;
    assert!(client.receive(flight.level, &buf[..flight.len]).is_err());
    assert_eq!(client.state(), State::Failed);
    assert!(!client.has_keys(Level::OneRtt));
}

struct NoEntropy;
impl RngCore for NoEntropy {
    fn next_u32(&mut self) -> u32 {
        0
    }
    fn next_u64(&mut self) -> u64 {
        0
    }
    fn fill_bytes(&mut self, _: &mut [u8]) {
        panic!("infallible entropy method must not be used")
    }
    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand_core::Error> {
        Err(core::num::NonZeroU32::new(rand_core::Error::CUSTOM_START)
            .unwrap()
            .into())
    }
}
impl CryptoRng for NoEntropy {}
#[test]
fn caller_entropy_failure_does_not_construct_a_provider() {
    let id = identity();
    let anchors = [trust_anchor_from_der(&id.root).unwrap()];
    let mut buffers = Buffers::new();
    assert!(matches!(
        BoundedTls::client(
            ClientConfig {
                server_name: "localhost",
                trust_anchors: &anchors,
                now: now(),
                certificate_limits: Limits::default(),
                transport_parameters: CLIENT_PARAMS
            },
            buffers.storage(),
            &mut NoEntropy
        ),
        Err(hibana_quic::bounded_tls::Failure::Entropy)
    ));
}

#[test]
fn bounded_entropy_framing_capacity_and_finished_failures_allocate_zero() {
    let id = identity();
    let anchors = [trust_anchor_from_der(&id.root).unwrap()];
    let chain = [id.leaf.as_ref()];
    let mut cb = Buffers::new();
    let mut sb = Buffers::new();
    measured(|| {
        assert!(matches!(
            BoundedTls::client(
                ClientConfig {
                    server_name: "localhost",
                    trust_anchors: &anchors,
                    now: now(),
                    certificate_limits: Limits::default(),
                    transport_parameters: CLIENT_PARAMS,
                },
                cb.storage(),
                &mut NoEntropy
            ),
            Err(hibana_quic::bounded_tls::Failure::Entropy)
        ));
        {
            let mut client = BoundedTls::client(
                ClientConfig {
                    server_name: "localhost",
                    trust_anchors: &anchors,
                    now: now(),
                    certificate_limits: Limits::default(),
                    transport_parameters: CLIENT_PARAMS,
                },
                cb.storage(),
                &mut OsRng,
            )
            .unwrap();
            assert_eq!(client.transmit(&mut []), Err(tls::Error::Capacity));
            assert_eq!(
                client.receive(Level::Initial, &[2, 255, 255, 255]),
                Err(tls::Error::Capacity)
            );
            assert_eq!(client.state(), State::Failed);
        }
        {
            let mut server = BoundedTls::server(
                ServerConfig {
                    certificate_chain: &chain,
                    signing_key: &id.signing,
                    transport_parameters: SERVER_PARAMS,
                },
                sb.storage(),
                &mut OsRng,
            )
            .unwrap();
            assert!(server.receive(Level::Initial, &[1, 0, 0, 0]).is_err());
            assert_eq!(server.state(), State::Failed);
        }
        let mut client = BoundedTls::client(
            ClientConfig {
                server_name: "localhost",
                trust_anchors: &anchors,
                now: now(),
                certificate_limits: Limits::default(),
                transport_parameters: CLIENT_PARAMS,
            },
            cb.storage(),
            &mut OsRng,
        )
        .unwrap();
        let mut server = BoundedTls::server(
            ServerConfig {
                certificate_chain: &chain,
                signing_key: &id.signing,
                transport_parameters: SERVER_PARAMS,
            },
            sb.storage(),
            &mut OsRng,
        )
        .unwrap();
        drain(&mut client, &mut server, 4096).unwrap();
        let mut bytes = [0; 4096];
        let initial = server.transmit(&mut bytes).unwrap().unwrap();
        client
            .receive(initial.level, &bytes[..initial.len])
            .unwrap();
        let flight = server.transmit(&mut bytes).unwrap().unwrap();
        bytes[flight.len - 1] ^= 1;
        assert!(client.receive(flight.level, &bytes[..flight.len]).is_err());
        assert_eq!(client.state(), State::Failed);
        assert!(!client.has_keys(Level::Handshake));
        assert!(!client.has_keys(Level::OneRtt));
    });
}

fn new_session_ticket(extension: &[u8]) -> Vec<u8> {
    let mut message = vec![4, 0, 0, 14, 0, 0, 0, 60, 1, 2, 3, 4, 0, 0, 1, 7, 0, 0];
    let body_len = 14 + extension.len();
    message[1] = (body_len >> 16) as u8;
    message[2] = (body_len >> 8) as u8;
    message[3] = body_len as u8;
    message[16..18].copy_from_slice(&(extension.len() as u16).to_be_bytes());
    message.extend_from_slice(extension);
    message
}

#[test]
fn authenticated_client_discards_valid_tickets_without_allocating_or_changing_keys() {
    let id = identity();
    let anchors = [trust_anchor_from_der(&id.root).unwrap()];
    let chain = [id.leaf.as_ref()];
    let mut cb = Buffers::new();
    let mut sb = Buffers::new();
    let ticket = new_session_ticket(&[0, 42, 0, 4, 255, 255, 255, 255, 0x0a, 0x0a, 0, 1, 7]);
    measured(|| {
        let mut client = BoundedTls::client(
            ClientConfig {
                server_name: "localhost",
                trust_anchors: &anchors,
                now: now(),
                certificate_limits: Limits::default(),
                transport_parameters: CLIENT_PARAMS,
            },
            cb.storage(),
            &mut OsRng,
        )
        .unwrap();
        let mut server = BoundedTls::server(
            ServerConfig {
                certificate_chain: &chain,
                signing_key: &id.signing,
                transport_parameters: SERVER_PARAMS,
            },
            sb.storage(),
            &mut OsRng,
        )
        .unwrap();
        handshake(&mut client, &mut server, 17).unwrap();
        let mask = client.header_mask(Level::OneRtt, true, &[3; 16]).unwrap();
        for byte in &ticket {
            client
                .receive(Level::OneRtt, core::slice::from_ref(byte))
                .unwrap();
        }
        client.receive(Level::OneRtt, &ticket).unwrap();
        assert_eq!(client.state(), State::Connected);
        assert_eq!(
            client.header_mask(Level::OneRtt, true, &[3; 16]).unwrap(),
            mask
        );
        assert_eq!(client.peer_transport_parameters(), Some(SERVER_PARAMS));
        assert_eq!(client.transmit(&mut [0; 32]), Ok(None));
        packets(&mut client, &mut server);
    });
    assert!(
        cb.rx[..ticket.len()].iter().all(|byte| *byte == 0),
        "discarded ticket bytes must not be retained in RX"
    );
}

#[test]
fn tickets_require_client_role_one_rtt_and_valid_structure() {
    for scenario in 0..6 {
        let id = identity();
        let anchors = [trust_anchor_from_der(&id.root).unwrap()];
        let chain = [id.leaf.as_ref()];
        let mut cb = Buffers::new();
        let mut sb = Buffers::new();
        let mut client = BoundedTls::client(
            ClientConfig {
                server_name: "localhost",
                trust_anchors: &anchors,
                now: now(),
                certificate_limits: Limits::default(),
                transport_parameters: CLIENT_PARAMS,
            },
            cb.storage(),
            &mut OsRng,
        )
        .unwrap();
        let mut server = BoundedTls::server(
            ServerConfig {
                certificate_chain: &chain,
                signing_key: &id.signing,
                transport_parameters: SERVER_PARAMS,
            },
            sb.storage(),
            &mut OsRng,
        )
        .unwrap();
        handshake(&mut client, &mut server, 127).unwrap();
        let mut ticket = new_session_ticket(&[]);
        match scenario {
            0 => {
                assert!(server.receive(Level::OneRtt, &ticket).is_err());
                assert_eq!(server.state(), State::Failed);
                continue;
            }
            1 => {
                assert!(client.receive(Level::Handshake, &ticket).is_err());
            }
            2 => {
                ticket = new_session_ticket(&[0, 42, 0, 4, 0, 0, 0, 1]);
                assert_eq!(
                    client.receive(Level::OneRtt, &ticket),
                    Err(tls::Error::ProtocolViolation)
                );
            }
            3 => {
                ticket = new_session_ticket(&[
                    0, 42, 0, 4, 255, 255, 255, 255, 0, 42, 0, 4, 255, 255, 255, 255,
                ]);
                assert!(client.receive(Level::OneRtt, &ticket).is_err());
            }
            4 => {
                ticket[14] = 0;
                ticket.remove(15);
                ticket[3] -= 1;
                assert!(client.receive(Level::OneRtt, &ticket).is_err());
            }
            5 => {
                ticket[0] = 24;
                assert!(client.receive(Level::OneRtt, &ticket).is_err());
            }
            _ => unreachable!(),
        }
        assert_eq!(client.state(), State::Failed);
        assert!(!client.has_keys(Level::OneRtt));
    }
}

#[test]
fn default_rustls_client_completes_real_p256_hello_retry_request() {
    let id = identity();
    let chain = [id.leaf.as_ref()];
    let mut buffers = Buffers::new();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(id.root.clone()).unwrap();
    let mut client = RustlsProvider::client(
        roots,
        ServerName::try_from("localhost").unwrap(),
        CLIENT_PARAMS.to_vec(),
    )
    .unwrap();
    let mut server = BoundedTls::server_p256(
        ServerConfig {
            certificate_chain: &chain,
            signing_key: &id.signing,
            transport_parameters: SERVER_PARAMS,
        },
        buffers.storage(),
        &mut OsRng,
    )
    .unwrap();
    drain(&mut client, &mut server, 17).unwrap();
    assert_eq!(server.state(), State::ServerClientHelloRetry);
    assert!(!server.has_keys(Level::Handshake));
    if let Err(error) = handshake(&mut client, &mut server, 11) {
        panic!(
            "{error:?}; client={:?}; server={:?}",
            client.last_tls_error(),
            server.last_failure()
        )
    }
    assert_eq!(server.state(), State::Connected);
    packets(&mut client, &mut server);
    packets(&mut server, &mut client);
}

#[test]
fn server_rejects_changed_retry_client_hello_before_installing_keys() {
    let id = identity();
    let chain = [id.leaf.as_ref()];
    let mut buffers = Buffers::new();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(id.root.clone()).unwrap();
    let mut client = RustlsProvider::client(
        roots,
        ServerName::try_from("localhost").unwrap(),
        CLIENT_PARAMS.to_vec(),
    )
    .unwrap();
    let mut server = BoundedTls::server_p256(
        ServerConfig {
            certificate_chain: &chain,
            signing_key: &id.signing,
            transport_parameters: SERVER_PARAMS,
        },
        buffers.storage(),
        &mut OsRng,
    )
    .unwrap();
    drain(&mut client, &mut server, 4096).unwrap();
    assert_eq!(server.state(), State::ServerClientHelloRetry);
    let mut bytes = [0; 4096];
    let hrr = server.transmit(&mut bytes).unwrap().unwrap();
    assert_eq!(hrr.level, Level::Initial);
    client.receive(hrr.level, &bytes[..hrr.len]).unwrap();
    let ch2 = client.transmit(&mut bytes).unwrap().unwrap();
    assert_eq!(ch2.level, Level::Initial);
    bytes[6] ^= 1; // ClientHello.random must not change across HRR.
    assert!(server.receive(ch2.level, &bytes[..ch2.len]).is_err());
    assert_eq!(server.state(), State::Failed);
    assert!(!server.has_keys(Level::Handshake));
}

#[test]
fn client_cookie_retry_is_bounded_and_repeated_or_same_group_retry_fails() {
    use hibana_quic::tls_wire;
    for scenario in 0..3 {
        let id = identity();
        let anchors = [trust_anchor_from_der(&id.root).unwrap()];
        let mut buffers = Buffers::new();
        let mut client = BoundedTls::client(
            ClientConfig {
                server_name: "localhost",
                trust_anchors: &anchors,
                now: now(),
                certificate_limits: Limits::default(),
                transport_parameters: CLIENT_PARAMS,
            },
            buffers.storage(),
            &mut OsRng,
        )
        .unwrap();
        let mut first = [0; 2048];
        let ch1 = client.transmit(&mut first).unwrap().unwrap();
        let mut message = [0; 2048];
        let group = if scenario == 0 {
            Some(tls_wire::GROUP_P256)
        } else {
            None
        };
        let n = tls_wire::encode_hello_retry_request(&mut message, 0x1301, group, Some(b"cookie"))
            .unwrap();
        if scenario == 0 {
            assert!(client.receive(Level::Initial, &message[..n]).is_err());
            assert_eq!(client.state(), State::Failed);
            continue;
        }
        measured(|| {
            client.receive(Level::Initial, &message[..n]).unwrap();
        });
        assert_eq!(client.state(), State::ClientServerHelloRetry);
        assert!(!client.has_keys(Level::Handshake));
        let mut second = [0; 2048];
        let ch2 = client.transmit(&mut second).unwrap().unwrap();
        assert_eq!(ch2.level, Level::Initial);
        let hrr = tls_wire::parse_hello_retry_request(&message[..n]).unwrap();
        let parsed =
            tls_wire::validate_client_hello_retry(&first[..ch1.len], &second[..ch2.len], &hrr)
                .unwrap();
        assert_eq!(parsed.cookie, Some(b"cookie".as_slice()));
        if scenario == 1 {
            assert!(client.receive(Level::Initial, &message[..n]).is_err());
        } else {
            let share: [u8; 65] = parsed.key_share.try_into().unwrap();
            let n = tls_wire::encode_server_hello(&mut message, &[6; 32], &share, 0x1303).unwrap();
            assert!(client.receive(Level::Initial, &message[..n]).is_err());
        }
        assert_eq!(client.state(), State::Failed);
        assert!(!client.has_keys(Level::Handshake));
    }
}

struct AllocationChecked<T>(T);
impl<T: Provider> Provider for AllocationChecked<T> {
    fn receive(&mut self, l: Level, b: &[u8]) -> Result<(), tls::Error> {
        measured(|| self.0.receive(l, b))
    }
    fn transmit(&mut self, b: &mut [u8]) -> Result<Option<tls::Output>, tls::Error> {
        measured(|| self.0.transmit(b))
    }
    fn has_keys(&self, l: Level) -> bool {
        measured(|| self.0.has_keys(l))
    }
    fn discard_keys(&mut self, l: Level) {
        measured(|| self.0.discard_keys(l))
    }
    fn is_handshaking(&self) -> bool {
        self.0.is_handshaking()
    }
    fn peer_transport_parameters(&self) -> Option<&[u8]> {
        self.0.peer_transport_parameters()
    }
    fn seal(
        &mut self,
        l: Level,
        pn: u64,
        h: &[u8],
        b: &mut [u8],
        n: usize,
    ) -> Result<usize, tls::Error> {
        measured(|| self.0.seal(l, pn, h, b, n))
    }
    fn open(&mut self, l: Level, pn: u64, h: &[u8], b: &mut [u8]) -> Result<usize, tls::Error> {
        measured(|| self.0.open(l, pn, h, b))
    }
    fn header_mask(&self, l: Level, local: bool, s: &[u8; 16]) -> Result<[u8; 5], tls::Error> {
        measured(|| self.0.header_mask(l, local, s))
    }
}
#[test]
fn every_bounded_server_call_in_real_hrr_handshake_allocates_zero() {
    let id = identity();
    let chain = [id.leaf.as_ref()];
    let mut buffers = Buffers::new();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(id.root.clone()).unwrap();
    let mut client = RustlsProvider::client(
        roots,
        ServerName::try_from("localhost").unwrap(),
        CLIENT_PARAMS.to_vec(),
    )
    .unwrap();
    let server = measured(|| {
        BoundedTls::server_p256(
            ServerConfig {
                certificate_chain: &chain,
                signing_key: &id.signing,
                transport_parameters: SERVER_PARAMS,
            },
            buffers.storage(),
            &mut OsRng,
        )
        .unwrap()
    });
    let mut server = AllocationChecked(server);
    drain(&mut client, &mut server, 1).unwrap();
    assert_eq!(server.0.state(), State::ServerClientHelloRetry);
    handshake(&mut client, &mut server, 1).unwrap();
    assert_eq!(server.0.state(), State::Connected);
    packets(&mut client, &mut server);
    packets(&mut server, &mut client);
}

#[test]
fn bounded_key_updates_match_independent_rustls_secrets_for_both_aeads() {
    use rustls::quic::{KeyChange, PacketKeySet, ServerConnection, Version};
    use std::sync::Arc;
    for suite in [
        rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
        rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
    ] {
        let id = identity();
        let anchors = [trust_anchor_from_der(&id.root).unwrap()];
        let mut cb = Buffers::new();
        let mut client = measured(|| {
            BoundedTls::client(
                ClientConfig {
                    server_name: "localhost",
                    trust_anchors: &anchors,
                    now: now(),
                    certificate_limits: Limits::default(),
                    transport_parameters: CLIENT_PARAMS,
                },
                cb.storage(),
                &mut OsRng,
            )
            .unwrap()
        });
        let mut provider = rustls::crypto::ring::default_provider();
        provider.cipher_suites.retain(|s| s.suite() == suite);
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![id.leaf.clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(id.key.clone()).into(),
            )
            .unwrap();
        config.alpn_protocols = vec![b"hq-interop".to_vec()];
        config.send_tls13_tickets = 0;
        let mut peer =
            ServerConnection::new(Arc::new(config), Version::V1, SERVER_PARAMS.to_vec()).unwrap();
        let mut level = Level::Initial;
        let mut current = None;
        let mut next = None;
        let mut headers = None;
        for _ in 0..20 {
            let mut out = [0; 8192];
            while let Some(output) = measured(|| client.transmit(&mut out).unwrap()) {
                peer.read_hs(&out[..output.len]).unwrap();
            }
            loop {
                let mut output = Vec::new();
                let change = peer.write_hs(&mut output);
                if !output.is_empty() {
                    measured(|| client.receive(level, &output).unwrap());
                }
                let changed = change.is_some();
                match change {
                    Some(KeyChange::Handshake { .. }) => level = Level::Handshake,
                    Some(KeyChange::OneRtt {
                        keys,
                        next: secrets,
                    }) => {
                        level = Level::OneRtt;
                        headers = Some((keys.local.header, keys.remote.header));
                        current = Some(PacketKeySet {
                            local: keys.local.packet,
                            remote: keys.remote.packet,
                        });
                        next = Some(secrets);
                    }
                    None => {}
                }
                if output.is_empty() && !changed {
                    break;
                }
            }
            if !client.is_handshaking() && !peer.is_handshaking() {
                break;
            }
        }
        assert!(!client.is_handshaking());
        assert!(!peer.is_handshaking());
        assert_eq!(peer.quic_transport_parameters(), Some(CLIENT_PARAMS));
        let mut current = current.unwrap();
        let mut next = next.unwrap();
        let (peer_local_hp, peer_remote_hp) = headers.unwrap();
        measured(|| client.confirm_handshake().unwrap());
        for generation in 0..=4u64 {
            let instant = generation * 40;
            measured(|| client.maintain_keys(instant, 10).unwrap());
            if generation > 0 {
                current = next.next_packet_keys(); // independent rustls HKDF "quic ku"
                if generation & 1 != 0 {
                    measured(|| client.initiate_key_update(instant, 10).unwrap());
                }
            }
            let header = [
                0x43 | if generation & 1 != 0 { 4 } else { 0 },
                0,
                0,
                0,
                generation as u8,
            ];
            // Alternating local and peer initiation. The peer's updated packet
            // arrives first in even generations, forcing a synchronous write update.
            let mut incoming = [0; 20];
            incoming[..4].copy_from_slice(b"peer");
            let tag = current
                .local
                .encrypt_in_place(generation, &header, &mut incoming[..4])
                .unwrap();
            incoming[4..].copy_from_slice(tag.as_ref());
            let valid = incoming;
            if generation > 0 {
                incoming[0] ^= 1;
                assert_eq!(
                    measured(|| client.open_one_rtt(
                        generation,
                        generation & 1 != 0,
                        &header,
                        &mut incoming,
                        instant,
                        10
                    )),
                    Err(tls::Error::Authentication)
                );
                assert_eq!(incoming, [0; 20]);
            }
            incoming = valid;
            let opened = measured(|| {
                client
                    .open_one_rtt(
                        generation,
                        generation & 1 != 0,
                        &header,
                        &mut incoming,
                        instant,
                        10,
                    )
                    .unwrap()
            });
            assert_eq!(opened.generation, generation);
            assert_eq!(&incoming[..opened.len], b"peer");
            assert_eq!(client.key_generation(), generation);
            assert_eq!(client.key_phase(), generation & 1 != 0);
            let mut outgoing = [0; 20];
            outgoing[..4].copy_from_slice(b"ours");
            measured(|| {
                client
                    .seal(Level::OneRtt, generation, &header, &mut outgoing, 4)
                    .unwrap()
            });
            assert_eq!(
                current
                    .remote
                    .decrypt_in_place(generation, &header, &mut outgoing)
                    .unwrap(),
                b"ours"
            );
            // Initial rustls HP keys must match every updated bounded generation.
            let sample = [9; 16];
            for (local, peer_hp) in [(true, &peer_remote_hp), (false, &peer_local_hp)] {
                let mask = client.header_mask(Level::OneRtt, local, &sample).unwrap();
                let mut first = 0x43;
                let mut pn = [0; 4];
                peer_hp
                    .encrypt_in_place(&sample, &mut first, &mut pn)
                    .unwrap();
                assert_eq!(first, 0x43 ^ (mask[0] & 0x1f));
                assert_eq!(pn, mask[1..]);
            }
            measured(|| {
                client
                    .acknowledge_one_rtt(generation, opened.generation, instant, 10)
                    .unwrap()
            });
            assert_eq!(
                measured(|| client.seal(Level::OneRtt, generation, &header, &mut outgoing, 4)),
                Err(tls::Error::PacketNumberReuse)
            );
        }
        measured(|| client.discard_keys(Level::OneRtt));
        assert!(!client.has_keys(Level::OneRtt));
        assert_eq!(
            measured(|| client.initiate_key_update(200, 10)),
            Err(tls::Error::KeysUnavailable)
        );
    }
}

#[test]
fn default_rustls_client_negotiates_x25519_without_retry() {
    let id = identity();
    let chain = [id.leaf.as_ref()];
    let mut buffers = Buffers::new();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(id.root.clone()).unwrap();
    let mut client = RustlsProvider::client(
        roots,
        ServerName::try_from("localhost").unwrap(),
        CLIENT_PARAMS.to_vec(),
    )
    .unwrap();
    let mut server = BoundedTls::server(
        ServerConfig {
            certificate_chain: &chain,
            signing_key: &id.signing,
            transport_parameters: SERVER_PARAMS,
        },
        buffers.storage(),
        &mut OsRng,
    )
    .unwrap();
    drain(&mut client, &mut server, 17).unwrap();
    assert_eq!(server.state(), State::ServerClientFinished);
    assert_eq!(
        server.negotiated_group(),
        Some(hibana_quic::tls_wire::GROUP_X25519)
    );
    assert!(server.has_keys(Level::Handshake));
    if let Err(error) = handshake(&mut client, &mut server, 11) {
        panic!(
            "{error:?}; client={:?}; server={:?}",
            client.last_tls_error(),
            server.last_failure()
        )
    }
    assert_eq!(server.state(), State::Connected);
    packets(&mut client, &mut server);
    packets(&mut server, &mut client);
}

#[test]
fn bounded_server_rejects_noncontributory_x25519_before_keys() {
    let id = identity();
    let anchors = [trust_anchor_from_der(&id.root).unwrap()];
    let chain = [id.leaf.as_ref()];
    let mut cb = Buffers::new();
    let mut sb = Buffers::new();
    let mut client = BoundedTls::client(
        ClientConfig {
            server_name: "localhost",
            trust_anchors: &anchors,
            now: now(),
            certificate_limits: Limits::default(),
            transport_parameters: CLIENT_PARAMS,
        },
        cb.storage(),
        &mut OsRng,
    )
    .unwrap();
    let mut first = [0; 4096];
    let n = client.transmit(&mut first).unwrap().unwrap().len;
    let hello = hibana_quic::tls_wire::parse_client_hello(&first[..n]).unwrap();
    let share: &[u8; 65] = hello.key_share.try_into().unwrap();
    for low in [0, 1] {
        let mut x = [0; 32];
        x[0] = low;
        let mut forged = [0; 4096];
        let n = hibana_quic::tls_wire::encode_client_hello_dual(
            &mut forged,
            hello.random,
            share,
            &x,
            "localhost",
            b"hq-interop",
            CLIENT_PARAMS,
        )
        .unwrap();
        let mut server = BoundedTls::server(
            ServerConfig {
                certificate_chain: &chain,
                signing_key: &id.signing,
                transport_parameters: SERVER_PARAMS,
            },
            sb.storage(),
            &mut OsRng,
        )
        .unwrap();
        measured(|| assert!(server.receive(Level::Initial, &forged[..n]).is_err()));
        assert_eq!(server.state(), State::Failed);
        assert!(!server.has_keys(Level::Handshake));
        assert_eq!(server.negotiated_group(), None);
    }
}

#[test]
fn strict_suite_policies_authenticate_and_install_matching_keys_without_allocating() {
    use hibana_quic::bounded_tls::CipherPolicy;
    for (policy, expected) in [
        (CipherPolicy::Aes128Only, CipherSuite::Aes128GcmSha256),
        (
            CipherPolicy::ChaCha20Only,
            CipherSuite::ChaCha20Poly1305Sha256,
        ),
    ] {
        let fragment = 127;
        let id = identity();
        let anchors = [trust_anchor_from_der(&id.root).unwrap()];
        let chain = [id.leaf.as_ref()];
        let mut cb = Buffers::new();
        let mut sb = Buffers::new();
        let mut rng = OsRng;
        measured(|| {
            let mut client = BoundedTls::client_with_policy(
                ClientConfig {
                    server_name: "localhost",
                    trust_anchors: &anchors,
                    now: now(),
                    certificate_limits: Limits::default(),
                    transport_parameters: CLIENT_PARAMS,
                },
                cb.storage(),
                &mut rng,
                policy,
            )
            .unwrap();
            let mut server = BoundedTls::server_with_policy(
                ServerConfig {
                    certificate_chain: &chain,
                    signing_key: &id.signing,
                    transport_parameters: SERVER_PARAMS,
                },
                sb.storage(),
                &mut rng,
                policy,
            )
            .unwrap();
            if let Err(error) = handshake(&mut client, &mut server, fragment) {
                panic!(
                    "{error:?}; client={:?}; server={:?}",
                    client.last_failure(),
                    server.last_failure()
                )
            }
            assert_eq!(client.state(), State::Connected);
            assert_eq!(server.state(), State::Connected);
            assert_eq!(client.peer_transport_parameters(), Some(SERVER_PARAMS));
            assert_eq!(server.peer_transport_parameters(), Some(CLIENT_PARAMS));
            assert_eq!(client.negotiated_alpn(), Some(b"hq-interop".as_slice()));
            assert_eq!(client.negotiated_suite(), Some(expected));
            packets(&mut client, &mut server);
            packets(&mut server, &mut client);
            client.discard_keys(Level::Handshake);
            assert!(!client.has_keys(Level::Handshake));
            assert_eq!(
                client.header_mask(Level::Handshake, true, &[0; 16]),
                Err(tls::Error::KeysUnavailable)
            );
            server.discard_keys(Level::OneRtt);
            assert!(!server.has_keys(Level::OneRtt));
        });
    }
}

#[test]
fn strict_chacha_rejects_unoffered_server_hello_and_retry_before_keys() {
    use hibana_quic::{
        bounded_tls::{CipherPolicy, Failure},
        tls_wire,
    };
    for retry in [false, true] {
        let id = identity();
        let anchors = [trust_anchor_from_der(&id.root).unwrap()];
        let mut cb = Buffers::new();
        let mut client = BoundedTls::client_with_policy(
            ClientConfig {
                server_name: "localhost",
                trust_anchors: &anchors,
                now: now(),
                certificate_limits: Limits::default(),
                transport_parameters: CLIENT_PARAMS,
            },
            cb.storage(),
            &mut OsRng,
            CipherPolicy::ChaCha20Only,
        )
        .unwrap();
        let mut raw = [0; 2048];
        let out = client.transmit(&mut raw).unwrap().unwrap();
        let hello = tls_wire::parse_client_hello(&raw[..out.len]).unwrap();
        assert!(!hello.offers_1301 && hello.offers_1303);
        assert_eq!(&raw[39..43], &[0, 2, 0x13, 3]); // Exact singleton vector, empty legacy session ID.
        let mut response = [0; 2048];
        let n = if retry {
            tls_wire::encode_hello_retry_request(&mut response, 0x1301, None, Some(b"cookie"))
        } else {
            tls_wire::encode_server_hello_group(
                &mut response,
                &[7; 32],
                tls_wire::GROUP_X25519,
                hello.key_share_x25519,
                0x1301,
            )
        }
        .unwrap();
        assert!(client.receive(Level::Initial, &response[..n]).is_err());
        assert!(matches!(
            client.last_failure(),
            Some(Failure::UnsupportedSuite)
        ));
        assert!(!client.has_keys(Level::Handshake));
        assert!(!client.has_keys(Level::OneRtt));
    }
}
#[test]
fn strict_chacha_cookie_retry_preserves_singleton_offer_and_no_overlap_fails() {
    use hibana_quic::{
        bounded_tls::{CipherPolicy, Failure},
        tls_wire,
    };
    let id = identity();
    let anchors = [trust_anchor_from_der(&id.root).unwrap()];
    let mut cb = Buffers::new();
    let mut client = BoundedTls::client_with_policy(
        ClientConfig {
            server_name: "localhost",
            trust_anchors: &anchors,
            now: now(),
            certificate_limits: Limits::default(),
            transport_parameters: CLIENT_PARAMS,
        },
        cb.storage(),
        &mut OsRng,
        CipherPolicy::ChaCha20Only,
    )
    .unwrap();
    let mut first = [0; 2048];
    let ch1 = client.transmit(&mut first).unwrap().unwrap();
    let mut raw = [0; 2048];
    let n = tls_wire::encode_hello_retry_request(&mut raw, 0x1303, None, Some(b"cookie")).unwrap();
    client.receive(Level::Initial, &raw[..n]).unwrap();
    let mut second = [0; 2048];
    let ch2 = client.transmit(&mut second).unwrap().unwrap();
    let hrr = tls_wire::parse_hello_retry_request(&raw[..n]).unwrap();
    let hello =
        tls_wire::validate_client_hello_retry(&first[..ch1.len], &second[..ch2.len], &hrr).unwrap();
    assert!(!hello.offers_1301 && hello.offers_1303);
    let chain = [id.leaf.as_ref()];
    let mut sb = Buffers::new();
    let mut server = BoundedTls::server_with_policy(
        ServerConfig {
            certificate_chain: &chain,
            signing_key: &id.signing,
            transport_parameters: SERVER_PARAMS,
        },
        sb.storage(),
        &mut OsRng,
        CipherPolicy::Aes128Only,
    )
    .unwrap();
    assert!(server.receive(Level::Initial, &first[..ch1.len]).is_err());
    assert!(matches!(
        server.last_failure(),
        Some(Failure::UnsupportedSuite)
    ));
    assert!(!server.has_keys(Level::Handshake));
}

// Fresh real-crypto coverage for the new direct transcript roles. No old
// receive/phase dispatcher runs on the side under test. The opposite side is
// the existing TLS peer, so this does not claim both sides or HQ are migrated.
#[test]
fn direct_transcript_roles_validate_full_tls_without_allocating() {
    use core::cell::RefCell;
    use hibana::runtime::{SessionKitStorage, ids::SessionId};
    use hibana_quic::{
        bounded_tls::{locals, protocol},
        carrier::CarrierStorage,
        runtime,
    };
    struct Peer<'a, 'cfg, 'buf, 'peer> {
        local: &'a RefCell<BoundedTls<'cfg, 'buf>>,
        remote: BoundedTls<'cfg, 'peer>,
        pending: [u8; 8192],
        used: usize,
        end: usize,
        level: Level,
        stall: bool,
    }
    impl locals::MessageInput for Peer<'_, '_, '_, '_> {
        async fn read_message(
            &mut self,
            level: Level,
            out: &mut [u8],
        ) -> Result<usize, locals::Error> {
            if self.stall {
                out[..4].copy_from_slice(&[1, 0, 0, 0]);
                return core::future::pending().await;
            }
            if self.used == self.end {
                let mut flight = [0; 8192];
                for _ in 0..32 {
                    let produced = self.local.borrow_mut().transmit(&mut flight).unwrap();
                    let Some(produced) = produced else { break };
                    self.remote
                        .receive(produced.level, &flight[..produced.len])
                        .unwrap();
                }
                let produced = self
                    .remote
                    .transmit(&mut self.pending)
                    .unwrap()
                    .expect("peer flight");
                self.used = 0;
                self.end = produced.len;
                self.level = produced.level;
            }
            assert_eq!(level, self.level);
            let b = &self.pending[self.used..self.end];
            assert!(b.len() >= 4);
            let n = 4 + ((b[1] as usize) << 16) + ((b[2] as usize) << 8) + b[3] as usize;
            assert!(n <= b.len() && n <= out.len());
            out[..n].copy_from_slice(&b[..n]);
            self.used += n;
            Ok(n)
        }
    }
    for (client, cancel) in [(true, false), (false, false), (true, true), (false, true)] {
        let identity = identity();
        let anchors = [trust_anchor_from_der(&identity.root).unwrap()];
        let chain = [identity.leaf.as_ref()];
        let mut cb = Buffers::new();
        let mut sb = Buffers::new();
        let c = BoundedTls::client(
            ClientConfig {
                server_name: "localhost",
                trust_anchors: &anchors,
                now: now(),
                certificate_limits: Limits::default(),
                transport_parameters: CLIENT_PARAMS,
            },
            cb.storage(),
            &mut OsRng,
        )
        .unwrap();
        let s = BoundedTls::server(
            ServerConfig {
                certificate_chain: &chain,
                signing_key: &identity.signing,
                transport_parameters: SERVER_PARAMS,
            },
            sb.storage(),
            &mut OsRng,
        )
        .unwrap();
        let (local, remote) = if client { (c, s) } else { (s, c) };
        let source = RefCell::new(local);
        let mut peer = Peer {
            local: &source,
            remote,
            pending: [0; 8192],
            used: 0,
            end: 0,
            level: Level::Initial,
            stall: cancel,
        };
        let mut message = [0; 8192];
        let slot = locals::MessageSlot::new(&mut message);
        let carrier = CarrierStorage::<1, 16, 48>::new();
        let mut slab = vec![0; 65536];
        let mut storage = SessionKitStorage::uninit();
        let kit = storage.init();
        let sid = SessionId::new(if client { 4500 } else { 4501 });
        let rv = kit
            .rendezvous(&mut slab, carrier.bind(sid).unwrap())
            .unwrap();
        let programs = if client {
            protocol::client_programs()
        } else {
            protocol::server_programs()
        };
        let mut input = rv.enter(sid, &programs.input).unwrap();
        let mut verify = rv.enter(sid, &programs.verify).unwrap();
        let reactor = hibana_quic_host::async_io::Reactor::<0, 0>::new().unwrap();
        if cancel {
            use core::{
                future::Future,
                pin::pin,
                task::{Context, Waker},
            };
            measured(|| {
                let mut future = pin!(async {
                    if client {
                        runtime::join2(
                            locals::client_owner(&mut verify, &source, &slot),
                            locals::client_input(&mut input, &slot, &mut peer),
                        )
                        .await
                    } else {
                        runtime::join2(
                            locals::server_owner(&mut verify, &source, &slot),
                            locals::server_input(&mut input, &slot, &mut peer),
                        )
                        .await
                    }
                });
                let mut cx = Context::from_waker(Waker::noop());
                for _ in 0..8 {
                    assert!(future.as_mut().poll(&mut cx).is_pending());
                }
            });
            assert_eq!(source.borrow().state(), State::Failed);
            drop(slot);
            assert!(message.iter().all(|b| *b == 0));
            continue;
        }
        measured(|| {
            reactor
                .block_on(async {
                    if client {
                        runtime::join2(
                            locals::client_owner(&mut verify, &source, &slot),
                            locals::client_input(&mut input, &slot, &mut peer),
                        )
                        .await
                    } else {
                        runtime::join2(
                            locals::server_owner(&mut verify, &source, &slot),
                            locals::server_input(&mut input, &slot, &mut peer),
                        )
                        .await
                    }
                })
                .unwrap()
                .unwrap()
        });
        assert_eq!(source.borrow().state(), State::Connected);
        // Deliver the generated client Finished to the reference side.
        if client {
            drain(&mut *source.borrow_mut(), &mut peer.remote, 4096).unwrap();
        }
        assert_eq!(peer.remote.state(), State::Connected);
    }
}
