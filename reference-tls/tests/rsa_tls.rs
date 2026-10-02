//! Bounded client authenticated by an independently signing rustls RSA server.
//! OpenSSL key generation and the allocating peer are outside the bounded call
//! counter. No private test key is written to disk or committed to the repository.
use hibana_quic::{
    bounded_tls::{BoundedTls, ClientConfig, State, Storage},
    tls::{self, Level, Provider},
    tls_certificate::{CertificateDer, Limits, UnixTime, trust_anchor_from_der},
};
use hibana_quic_reference_tls::{RustlsProvider, rustls};
use rand_core::OsRng;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    io::Write,
    process::{Command, Stdio},
    time::Duration,
};
thread_local! { static COUNT: Cell<Option<usize>> = const { Cell::new(None) }; }
struct Counter;
fn allocation() {
    let _ = COUNT.try_with(|n| {
        if let Some(v) = n.get() {
            n.set(Some(v + 1));
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
    COUNT.with(|n| n.set(Some(0)));
    let result = f();
    let n = COUNT.with(|n| n.replace(None).unwrap());
    assert_eq!(n, 0, "bounded RSA TLS call allocated");
    result
}
fn rsa_key(bits: u16) -> PrivateKeyDer<'static> {
    let generated = Command::new("openssl")
        .args([
            "genpkey",
            "-quiet",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            &format!("rsa_keygen_bits:{bits}"),
            "-outform",
            "DER",
        ])
        .output()
        .expect("OpenSSL is required for independent test-key generation");
    assert!(
        generated.status.success(),
        "OpenSSL RSA key generation failed"
    );
    let mut convert = Command::new("openssl")
        .args([
            "pkcs8", "-topk8", "-nocrypt", "-inform", "DER", "-outform", "DER",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    convert
        .stdin
        .take()
        .unwrap()
        .write_all(&generated.stdout)
        .unwrap();
    let encoded = convert.wait_with_output().unwrap();
    assert!(encoded.status.success(), "OpenSSL PKCS8 conversion failed");
    PrivatePkcs8KeyDer::from(encoded.stdout).into()
}
struct Identity {
    root: CertificateDer<'static>,
    leaf: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}
fn identity(bits: u16) -> Identity {
    let root_key = rsa_key(2048);
    let ca_key = KeyPair::from_der_and_sign_algo(&root_key, &rcgen::PKCS_RSA_SHA256).unwrap();
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = ca.self_signed(&ca_key).unwrap();
    let key = rsa_key(bits);
    let leaf_key = KeyPair::from_der_and_sign_algo(&key, &rcgen::PKCS_RSA_SHA256).unwrap();
    let mut leaf = CertificateParams::new(vec!["localhost".into()]).unwrap();
    leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let leaf = leaf.signed_by(&leaf_key, &ca, &ca_key).unwrap();
    Identity {
        root: ca.der().clone(),
        leaf: leaf.der().clone(),
        key,
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
const CLIENT_PARAMS: &[u8] = &[15, 0, 4, 1, 42];
const SERVER_PARAMS: &[u8] = &[0, 0, 15, 0, 4, 1, 63];
fn index(level: Level) -> usize {
    match level {
        Level::Initial => 0,
        Level::Handshake => 1,
        Level::OneRtt => 2,
    }
}
fn exchange(
    client: &mut BoundedTls<'_, '_>,
    server: &mut RustlsProvider,
    corrupt_cv: bool,
) -> Result<bool, tls::Error> {
    let mut cpn = [0; 3];
    let mut spn = [0; 3];
    let mut saw_rsa_cv = false;
    let mut wire = [0u8; 8192 + 16];
    for _ in 0..32 {
        let mut progress = false;
        while let Some(out) = measured(|| client.transmit(&mut wire[..8192]))? {
            let plaintext = out.len;
            if out.level != Level::Initial {
                let pn = cpn[index(out.level)];
                cpn[index(out.level)] += 1;
                let len = measured(|| client.seal(out.level, pn, b"header", &mut wire, plaintext))?;
                assert_eq!(
                    server.open(out.level, pn, b"header", &mut wire[..len])?,
                    plaintext
                );
            }
            server.receive(out.level, &wire[..plaintext])?;
            progress = true;
        }
        while let Some(out) = server.transmit(&mut wire[..8192])? {
            if out.level == Level::Handshake {
                let mut pos = 0;
                while pos + 4 <= out.len {
                    let len = ((wire[pos + 1] as usize) << 16)
                        | ((wire[pos + 2] as usize) << 8)
                        | wire[pos + 3] as usize;
                    assert!(
                        pos + 4 + len <= out.len,
                        "test fixture fits one bounded flight"
                    );
                    if wire[pos] == 15 {
                        assert_eq!(&wire[pos + 4..pos + 6], &[0x08, 0x04]);
                        saw_rsa_cv = true;
                        if corrupt_cv {
                            wire[pos + 4 + len - 1] ^= 1;
                        }
                    }
                    pos += 4 + len;
                }
                assert_eq!(pos, out.len);
            }
            let plaintext = out.len;
            if out.level != Level::Initial {
                let pn = spn[index(out.level)];
                spn[index(out.level)] += 1;
                let len = server.seal(out.level, pn, b"header", &mut wire, plaintext)?;
                assert_eq!(
                    measured(|| client.open(out.level, pn, b"header", &mut wire[..len]))?,
                    plaintext
                );
            }
            for fragment in wire[..plaintext].chunks(41) {
                measured(|| client.receive(out.level, fragment))?;
            }
            progress = true;
        }
        if !progress {
            assert!(!client.is_handshaking() && !server.is_handshaking());
            return Ok(saw_rsa_cv);
        }
    }
    Err(tls::Error::Handshake)
}
fn run(bits: u16, corrupt_cv: bool) {
    let id = identity(bits);
    let anchors = [trust_anchor_from_der(&id.root).unwrap()];
    let mut buffers = Buffers::new();
    let mut client = measured(|| {
        BoundedTls::client(
            ClientConfig {
                server_name: "localhost",
                trust_anchors: &anchors,
                now: UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_000)),
                certificate_limits: Limits::default(),
                transport_parameters: CLIENT_PARAMS,
            },
            buffers.storage(),
            &mut OsRng,
        )
    })
    .unwrap();
    let mut server = RustlsProvider::server(vec![id.leaf], id.key, SERVER_PARAMS.to_vec()).unwrap();
    let result = exchange(&mut client, &mut server, corrupt_cv);
    if corrupt_cv {
        assert_eq!(result, Err(tls::Error::Authentication));
        assert_eq!(client.state(), State::Failed);
        assert!(!client.has_keys(Level::OneRtt));
        return;
    }
    assert_eq!(result, Ok(true));
    assert_eq!(client.state(), State::Connected);
    assert_eq!(client.peer_transport_parameters(), Some(SERVER_PARAMS));
    assert_eq!(server.peer_transport_parameters(), Some(CLIENT_PARAMS));
    let mut packet = [0; 32];
    packet[..16].copy_from_slice(b"authenticatedRSA");
    let len = measured(|| client.seal(Level::OneRtt, 10, b"header", &mut packet, 16)).unwrap();
    assert_eq!(
        server.open(Level::OneRtt, 10, b"header", &mut packet[..len]),
        Ok(16)
    );
    let len = server
        .seal(Level::OneRtt, 11, b"header", &mut packet, 16)
        .unwrap();
    assert_eq!(
        measured(|| client.open(Level::OneRtt, 11, b"header", &mut packet[..len])),
        Ok(16)
    );
    assert_eq!(&packet[..16], b"authenticatedRSA");
}
#[test]
fn rsa_2048_3072_4096_servers_authenticate_real_bounded_client() {
    for bits in [2048, 3072, 4096] {
        run(bits, false);
    }
}
#[test]
fn authenticated_packet_with_corrupted_rsa_certificate_verify_fails_closed() {
    run(2048, true);
}
