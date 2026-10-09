//! Depth-eight certificate verification, with runtime-generated private keys.
#[path = "../../support/async_tls_fixture.rs"]
mod async_fixture;
use hibana_quic::{
    tls::certificate::*,
    tls::handshake::{BoundedTls, ClientConfig, Failure, ServerConfig, SigningKey, Storage},
    tls::wire as tls_wire,
    tls::{Level, Provider},
};
use hibana_quic_host::entropy::KernelEntropy;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, GeneralSubtree, IsCa, KeyPair, KeyUsagePurpose,
    NameConstraints,
};
use std::time::Duration;

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};
thread_local! { static ALLOCS: Cell<Option<usize>> = const { Cell::new(None) }; }
struct Counting;
fn count() {
    let _ = ALLOCS.try_with(|n| {
        if let Some(v) = n.get() {
            n.set(Some(v + 1))
        }
    });
}
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        count();
        unsafe { System.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        count();
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        count();
        unsafe { System.realloc(p, l, n) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
}
#[global_allocator]
static ALLOCATOR: Counting = Counting;
fn measured<T>(f: impl FnOnce() -> T) -> T {
    ALLOCS.with(|n| n.set(Some(0)));
    let r = f();
    let n = ALLOCS.with(|n| n.replace(None).unwrap());
    assert_eq!(n, 0, "certificate verification allocated");
    r
}

struct Chain {
    root: Vec<u8>,
    leaf: Vec<u8>,
    intermediates: Vec<Vec<u8>>,
    signing: SigningKey,
}
#[derive(Clone, Copy)]
enum Constraint {
    None,
    Permitted,
    Excluded,
    PathLen,
    BadCaUsage,
    BadLeafUsage,
    EnlargedLeaf,
}
fn chain(count: usize, constraint: Constraint) -> Chain {
    chain_with_names(count, constraint, vec!["server.allowed.test".into()])
}
fn chain_with_names(count: usize, constraint: Constraint, names: Vec<String>) -> Chain {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name.push(DnType::CommonName, "Root");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let mut key = KeyPair::generate().unwrap();
    let mut issuer = params.self_signed(&key).unwrap();
    let root = issuer.der().as_ref().to_vec();
    let mut intermediates = Vec::new();
    for index in 0..count {
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.distinguished_name
            .push(DnType::CommonName, format!("Intermediate {index}"));
        p.is_ca = IsCa::Ca(if index == 0 && matches!(constraint, Constraint::PathLen) {
            BasicConstraints::Constrained(6)
        } else {
            BasicConstraints::Unconstrained
        });
        p.key_usages = vec![
            if index == 0 && matches!(constraint, Constraint::BadCaUsage) {
                KeyUsagePurpose::DigitalSignature
            } else {
                KeyUsagePurpose::KeyCertSign
            },
        ];
        if index == 0 {
            p.name_constraints = match constraint {
                Constraint::Permitted => Some(NameConstraints {
                    permitted_subtrees: vec![GeneralSubtree::DnsName("allowed.test".into())],
                    excluded_subtrees: vec![],
                }),
                Constraint::Excluded => Some(NameConstraints {
                    permitted_subtrees: vec![],
                    excluded_subtrees: vec![GeneralSubtree::DnsName("allowed.test".into())],
                }),
                _ => None,
            };
        }
        let next_key = KeyPair::generate().unwrap();
        let next = p.signed_by(&next_key, &issuer, &key).unwrap();
        intermediates.push(next.der().as_ref().to_vec());
        issuer = next;
        key = next_key;
    }
    let mut p = CertificateParams::new(names).unwrap();
    p.key_usages = vec![if matches!(constraint, Constraint::BadLeafUsage) {
        KeyUsagePurpose::KeyEncipherment
    } else {
        KeyUsagePurpose::DigitalSignature
    }];
    if matches!(constraint, Constraint::EnlargedLeaf) {
        for index in 0..20 {
            let label = format!("{index:02}{}", "a".repeat(58));
            let name = format!("{label}.{label}.{label}.{label}");
            p.subject_alt_names
                .push(rcgen::SanType::DnsName(name.try_into().unwrap()));
        }
    }
    let leaf_key = KeyPair::generate().unwrap();
    let signing = SigningKey::from_pkcs8_der(&leaf_key.serialize_der()).unwrap();
    let leaf = p.signed_by(&leaf_key, &issuer, &key).unwrap().der().as_ref().to_vec();
    intermediates.reverse();
    Chain {
        root,
        leaf,
        intermediates,
        signing,
    }
}
fn check(chain: &Chain, name: &str) -> Result<(), Error> {
    let leaf=CertificateDer::from(chain.leaf.as_slice());
    let certificates:Vec<_>=chain.intermediates.iter().map(|c|CertificateDer::from(c.as_slice())).collect();
    let anchors = [trust_anchor_from_der(&CertificateDer::from(chain.root.as_ref()))?];
    let time = UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_000));
    let verifier = ServerVerifier::new(&anchors, time, Limits::default())?;
    measured(|| {
        verifier
            .verify_server(
                &leaf,
                &certificates,
                &ServerName::try_from(name).unwrap(),
            )
            .map(|_| ())
    })
}
#[test]
fn nine_chain_authentication_constraints_are_preserved() {
    let c = chain(8, Constraint::None);
    assert_eq!(check(&c, "server.allowed.test"), Ok(()));
    assert!(check(&c, "wrong.allowed.test").is_err());
    let foreign = chain(0, Constraint::None);
    let wrong = Chain {
        root: foreign.root,
        leaf: c.leaf,
        intermediates: c.intermediates,
        signing: c.signing,
    };
    assert!(check(&wrong, "server.allowed.test").is_err());
    assert_eq!(
        check(&chain(8, Constraint::Permitted), "server.allowed.test"),
        Ok(())
    );
    assert_eq!(
        format!(
            "{:?}",
            check(&chain(8, Constraint::Excluded), "server.allowed.test")
        ),
        "Err(Certificate(Untrusted))"
    );
    assert_eq!(
        format!(
            "{:?}",
            check(&chain(8, Constraint::PathLen), "server.allowed.test")
        ),
        "Err(Certificate(Untrusted))"
    );
    assert_eq!(
        check(&chain(8, Constraint::BadCaUsage), "server.allowed.test"),
        Err(Error::MissingKeyCertSign)
    );
    assert_eq!(
        check(&chain(8, Constraint::BadLeafUsage), "server.allowed.test"),
        Err(Error::MissingDigitalSignature)
    );
}
#[test]
fn ten_chain_is_rejected_by_bounded_wrapper() {
    let c = chain(9, Constraint::None);
    assert_eq!(
        check(&c, "server.allowed.test"),
        Err(Error::TooManyIntermediates)
    );
    let chain: Vec<_> = core::iter::once(c.leaf.as_ref())
        .chain(c.intermediates.iter().map(|cert| cert.as_ref()))
        .collect();
    let mut storage = Buffers::<16384>::new();
    assert!(matches!(
        measured(|| BoundedTls::server(
            ServerConfig {
                protocol: Default::default(),
                version: hibana_quic::quic::kernel::version::Version::V1,
                certificate_chain: &chain,
                signing_key: &c.signing,
                transport_parameters: &[4, 1, 63]
            },
            storage.storage(),
            &mut KernelEntropy,
        )),
        Err(Failure::InvalidConfig)
    ));
}
#[test]
fn generated_nine_chain_authenticates_only_expected_hosts_and_root() {
    // Reproducible structure, generated keys: no absent historical artifacts.
    let c = chain_with_names(
        8,
        Constraint::None,
        ["server", "server4", "server6", "server46"]
            .map(str::to_owned)
            .to_vec(),
    );
    let leaf = CertificateDer::from(c.leaf.as_slice());
    let certificates:Vec<_> = c.intermediates.iter().map(|c|CertificateDer::from(c.as_slice())).collect();
    assert_eq!(certificates.len(), 8);
    let anchors = [trust_anchor_from_der(&CertificateDer::from(c.root.as_ref())).unwrap()];
    let time = UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_000));
    let verifier = ServerVerifier::new(&anchors, time, Limits::default()).unwrap();
    for name in ["server", "server4", "server6", "server46"] {
        measured(|| {
            verifier.verify_server(&leaf, &certificates, &ServerName::try_from(name).unwrap())
        })
        .unwrap();
    }
    assert!(
        verifier
            .verify_server(
                &leaf,
                &certificates,
                &ServerName::try_from("wrong.test").unwrap()
            )
            .is_err()
    );
    let wrong = chain(0, Constraint::None);
    let wrong_anchors = [trust_anchor_from_der(&CertificateDer::from(wrong.root.as_ref())).unwrap()];
    let wrong_verifier = ServerVerifier::new(&wrong_anchors, time, Limits::default()).unwrap();
    assert!(
        wrong_verifier
            .verify_server(
                &leaf,
                &certificates,
                &ServerName::try_from("server").unwrap()
            )
            .is_err()
    );
}
#[test]
fn deep_chain_time_and_signature_failures_still_reject() {
    let c = chain(8, Constraint::None);
    let leaf=CertificateDer::from(c.leaf.as_slice());
    let certificates:Vec<_>=c.intermediates.iter().map(|c|CertificateDer::from(c.as_slice())).collect();
    let anchors = [trust_anchor_from_der(&CertificateDer::from(c.root.as_ref())).unwrap()];
    let name = ServerName::try_from("server.allowed.test").unwrap();
    for seconds in [0, u64::MAX] {
        let verifier = ServerVerifier::new(
            &anchors,
            UnixTime::since_unix_epoch(Duration::from_secs(seconds)),
            Limits::default(),
        )
        .unwrap();
        assert!(measured(|| verifier.verify_server(&leaf, &certificates, &name)).is_err());
    }
    let mut damaged = c.leaf.clone();
    *damaged.last_mut().unwrap() ^= 1;
    let damaged = CertificateDer::from(damaged.as_slice());
    let verifier = ServerVerifier::new(
        &anchors,
        UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_000)),
        Limits::default(),
    )
    .unwrap();
    assert!(measured(|| verifier.verify_server(&damaged, &certificates, &name)).is_err());
}

struct Buffers<const N: usize> {
    rx: [u8; N],
    tx: [u8; N],
    cert: [u8; N],
    params: [u8; 512],
}
impl<const N: usize> Buffers<N> {
    fn new() -> Self {
        Self {
            rx: [0; N],
            tx: [0; N],
            cert: [0; N],
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
fn handshake(
    client: &mut BoundedTls<'_, '_>,
    server: &mut BoundedTls<'_, '_>,
    fragment: usize,
) -> Result<(), hibana_quic::tls::handshake::local::Error> {
    async_fixture::try_handshake_with::<16384>(client, server, fragment, false).map(|_| ())
}
fn authenticated_packets(client: &mut impl Provider, server: &mut impl Provider) {
    let mut bytes = [0; 32];
    bytes[..16].copy_from_slice(b"nine-chain-proof");
    assert_eq!(
        client.seal(Level::OneRtt, 0, b"header", &mut bytes, 16),
        Ok(32)
    );
    assert_eq!(server.open(Level::OneRtt, 0, b"header", &mut bytes), Ok(16));
    assert_eq!(&bytes[..16], b"nine-chain-proof");
    assert_eq!(
        server.seal(Level::OneRtt, 0, b"header", &mut bytes, 16),
        Ok(32)
    );
    assert_eq!(client.open(Level::OneRtt, 0, b"header", &mut bytes), Ok(16));
    assert_eq!(&bytes[..16], b"nine-chain-proof");
}
fn full_handshake(
    root: &[u8],
    chain: &[&[u8]],
    signing: &SigningKey,
    name: &str,
    time: UnixTime,
    fragment: usize,
) {
    let anchors = [trust_anchor_from_der(&CertificateDer::from(root)).unwrap()];
    let mut cb = Buffers::<16384>::new();
    let mut sb = Buffers::<16384>::new();
    measured(|| {
        let mut client = BoundedTls::client(
            ClientConfig {
                protocol: Default::default(),
                version: hibana_quic::quic::kernel::version::Version::V1,
                server_name: name,
                trust_anchors: &anchors,
                now: time,
                certificate_limits: Limits::default(),
                transport_parameters: &[4, 1, 42],
            },
            cb.storage(),
            &mut KernelEntropy,
        )
        .unwrap();
        let mut server = BoundedTls::server(
            ServerConfig {
                protocol: Default::default(),
                version: hibana_quic::quic::kernel::version::Version::V1,
                certificate_chain: chain,
                signing_key: signing,
                transport_parameters: &[4, 1, 63],
            },
            sb.storage(),
            &mut KernelEntropy,
        )
        .unwrap();
        handshake(&mut client, &mut server, fragment).unwrap();
        assert!(!client.is_handshaking() && !server.is_handshaking());
        authenticated_packets(&mut client, &mut server);
    });
}
#[test]
fn nine_certificate_full_tls_handshake_and_packet_keys_allocate_zero() {
    // Host-only fixture generation; private keys remain in test memory.
    let id = chain(8, Constraint::EnlargedLeaf);
    let chain: Vec<_> = core::iter::once(id.leaf.as_slice())
        .chain(id.intermediates.iter().map(|c| c.as_slice()))
        .collect();
    assert_eq!(chain.len(), 9);
    assert!(chain.iter().map(|c| c.len()).sum::<usize>() > 8192);
    for fragment in [1, 127, 4096] {
        full_handshake(
            &id.root,
            &chain,
            &id.signing,
            "server.allowed.test",
            UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_000)),
            fragment,
        );
    }
    let mut encoded = [0; 16384];
    let n = tls_wire::encode_certificate(&mut encoded, &chain).unwrap();
    assert!(n > 8192);
    let mut ranges = [tls_wire::DerRange::default(); 9];
    assert_eq!(
        tls_wire::parse_certificate(&encoded[..n], &mut ranges),
        Ok(9)
    );
    assert_eq!(
        tls_wire::parse_certificate(&encoded[..n], &mut ranges[..8]),
        Err(tls_wire::Error::Capacity)
    );
    assert_eq!(
        tls_wire::encode_certificate(&mut encoded, &[id.leaf.as_slice(); 10]),
        Err(tls_wire::Error::Capacity)
    );
}
#[test]
fn enlarged_chain_requires_explicit_storage_and_still_rejects_wrong_authentication() {
    let id = chain(8, Constraint::EnlargedLeaf);
    let chain: Vec<_> = core::iter::once(id.leaf.as_slice())
        .chain(id.intermediates.iter().map(|c| c.as_slice()))
        .collect();
    let anchors = [trust_anchor_from_der(&CertificateDer::from(id.root.as_ref())).unwrap()];
    let time = UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_000));
    let mut cb = Buffers::<8192>::new();
    let mut sb = Buffers::<16384>::new();
    measured(|| {
        let mut client = BoundedTls::client(
            ClientConfig {
                protocol: Default::default(),
                version: hibana_quic::quic::kernel::version::Version::V1,
                server_name: "server.allowed.test",
                trust_anchors: &anchors,
                now: time,
                certificate_limits: Limits::default(),
                transport_parameters: &[4, 1, 42],
            },
            cb.storage(),
            &mut KernelEntropy,
        )
        .unwrap();
        let mut server = BoundedTls::server(
            ServerConfig {
                protocol: Default::default(),
                version: hibana_quic::quic::kernel::version::Version::V1,
                certificate_chain: &chain,
                signing_key: &id.signing,
                transport_parameters: &[4, 1, 63],
            },
            sb.storage(),
            &mut KernelEntropy,
        )
        .unwrap();
        let rejected = handshake(&mut client, &mut server, 127);
        assert!(
            matches!(
                rejected,
                Err(hibana_quic::tls::handshake::local::Error::Crypto(
                    Failure::Capacity
                ))
            ),
            "projected capacity rejection: {rejected:?}"
        );
        assert!(!client.has_keys(Level::OneRtt));
    });
    let foreign = chain_identity_root();
    let wrong_anchors = [trust_anchor_from_der(&CertificateDer::from(foreign.as_ref())).unwrap()];
    for (name, trust) in [
        ("wrong.allowed.test", anchors.as_slice()),
        ("server.allowed.test", wrong_anchors.as_slice()),
    ] {
        let mut cb = Buffers::<16384>::new();
        let mut sb = Buffers::<16384>::new();
        measured(|| {
            let mut client = BoundedTls::client(
                ClientConfig {
                    protocol: Default::default(),
                    version: hibana_quic::quic::kernel::version::Version::V1,
                    server_name: name,
                    trust_anchors: trust,
                    now: time,
                    certificate_limits: Limits::default(),
                    transport_parameters: &[4, 1, 42],
                },
                cb.storage(),
                &mut KernelEntropy,
            )
            .unwrap();
            let mut server = BoundedTls::server(
                ServerConfig {
                    protocol: Default::default(),
                    version: hibana_quic::quic::kernel::version::Version::V1,
                    certificate_chain: &chain,
                    signing_key: &id.signing,
                    transport_parameters: &[4, 1, 63],
                },
                sb.storage(),
                &mut KernelEntropy,
            )
            .unwrap();
            let rejected = handshake(&mut client, &mut server, 127);
            assert!(
                matches!(
                    rejected,
                    Err(hibana_quic::tls::handshake::local::Error::Crypto(
                        Failure::Certificate(_)
                    ))
                ),
                "projected certificate rejection: {rejected:?}"
            );
            assert!(!client.has_keys(Level::OneRtt));
        });
    }
}
fn chain_identity_root() -> Vec<u8> {
    chain(0, Constraint::None).root
}

/// Reproduce the exact runner-generated chain with its private leaf key kept
/// outside the repository. Invoke explicitly with HIBANA_RUNNER_CERTS_DIR.
#[test]
#[ignore = "requires ephemeral runner certs and private key outside the repository"]
fn exact_runner_nine_chain_full_tls_handshake_allocate_zero() {
    use rustls_pki_types::{PrivateKeyDer, pem::PemObject};
    let path = std::path::PathBuf::from(
        std::env::var_os("HIBANA_RUNNER_CERTS_DIR")
            .expect("set HIBANA_RUNNER_CERTS_DIR to an ephemeral certs.sh chain9 directory"),
    );
    let root =
        rustls_pki_types::CertificateDer::from_pem_slice(&std::fs::read(path.join("ca.pem")).unwrap()).unwrap();
    let pem = std::fs::read(path.join("cert.pem")).unwrap();
    let certs: Vec<_> = rustls_pki_types::CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(certs.len(), 9);
    let key =
        PrivateKeyDer::from_pem_slice(&std::fs::read(path.join("priv.key")).unwrap()).unwrap();
    let signing = match key {
        PrivateKeyDer::Pkcs8(key) => SigningKey::from_pkcs8_der(key.secret_pkcs8_der()).unwrap(),
        PrivateKeyDer::Sec1(key) => SigningKey::from_sec1_der(key.secret_sec1_der()).unwrap(),
        _ => panic!("test fixture is not P256"),
    };
    let chain: Vec<_> = certs.iter().map(|c| c.as_ref()).collect();
    let now = UnixTime::since_unix_epoch(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap(),
    );
    full_handshake(&root, &chain, &signing, "server", now, 127);
}

#[test]
fn project_owned_verifier_matches_generated_depth_and_constraint_cases() {
    use hibana_tls::x509::{name::Identity, verify};
    for (constraint, expected) in [
        (Constraint::None,true),(Constraint::Permitted,true),
        (Constraint::Excluded,false),(Constraint::PathLen,false),
        (Constraint::BadCaUsage,false),(Constraint::BadLeafUsage,false),
    ] {
        let c=chain(8,constraint);
        let intermediate:Vec<&[u8]>=c.intermediates.iter().map(|c|c.as_ref()).collect();
        let result=measured(||verify::server(c.leaf.as_ref(),&intermediate,&[c.root.as_ref()],Identity::Dns("server.allowed.test"),1800000000));
        assert_eq!(result.is_ok(),expected,"owned verifier: {:?}",result.err());
        assert!(measured(||verify::server(c.leaf.as_ref(),&intermediate,&[c.root.as_ref()],Identity::Dns("wrong.allowed.test"),1800000000)).is_err());
    }
}
