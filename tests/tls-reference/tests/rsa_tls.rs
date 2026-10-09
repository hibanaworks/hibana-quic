//! Bounded client authenticated by an independently signing rustls RSA server.
//! OpenSSL key generation and the allocating peer are outside the bounded call
//! counter. No private test key is written to disk or committed to the repository.
use hibana_quic_pal::entropy::KernelEntropy;
use hibana_quic_reference_tls::{RustlsProvider, rustls};
use hibana_tls::certificate::CertificateDer;
use hibana_tls::certificate::Limits;
use hibana_tls::certificate::UnixTime;
use hibana_tls::certificate::trust_anchor_from_der;
use hibana_tls::endpoint::Level;
use hibana_tls::endpoint::Provider;
use hibana_tls::handshake::BoundedTls;
use hibana_tls::handshake::ClientConfig;
use hibana_tls::handshake::Storage;
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
    root: rustls_pki_types::CertificateDer<'static>,
    leaf: rustls_pki_types::CertificateDer<'static>,
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
) -> Result<bool, hibana_tls::handshake::local::Error> {
    use core::{
        cell::RefCell,
        future::poll_fn,
        pin::pin,
        task::{Poll, Waker},
    };
    use hibana::runtime::{SessionKitStorage, ids::SessionId};
    use hibana_quic::runtime::TaskSet;
    use hibana_quic::runtime::carrier::CarrierStorage;
    use hibana_tls::handshake::global;
    use hibana_tls::handshake::local;
    struct Access<'a, 'cfg, 'buf> {
        tls: RefCell<&'a mut BoundedTls<'cfg, 'buf>>,
        reader: RefCell<Option<Waker>>,
    }
    struct Input<'a, 'b, 'c, 'cfg, 'buf> {
        client: &'a Access<'b, 'cfg, 'buf>,
        server: &'a RefCell<&'c mut RustlsProvider>,
        reader: &'a RefCell<Option<Waker>>,
        wire: [u8; 8208],
        used: usize,
        end: usize,
        pn: [u64; 3],
        level: Level,
        corrupt: bool,
        saw: bool,
    }
    impl local::MessageInput for Input<'_, '_, '_, '_, '_> {
        async fn read_message(
            &mut self,
            level: Level,
            out: &mut [u8],
        ) -> Result<usize, local::Error> {
            if self.used == self.end {
                let output = poll_fn(|cx| {
                    self.reader.borrow_mut().replace(cx.waker().clone());
                    match self.server.borrow_mut().transmit(&mut self.wire[..8192]) {
                        Ok(Some(o)) => Poll::Ready(Ok(o)),
                        Ok(None) => Poll::Pending,
                        Err(e) => Poll::Ready(Err(local::Error::Input(e))),
                    }
                })
                .await?;
                self.used = 0;
                self.end = output.len;
                self.level = output.level;
                if self.level == Level::Handshake {
                    let mut pos = 0;
                    while pos < self.end {
                        let b = &mut self.wire[pos..self.end];
                        let n =
                            4 + ((b[1] as usize) << 16) + ((b[2] as usize) << 8) + b[3] as usize;
                        assert!(n <= b.len());
                        if b[0] == 15 {
                            assert_eq!(&b[4..6], &[8, 4]);
                            self.saw = true;
                            if self.corrupt {
                                b[n - 1] ^= 1;
                            }
                        }
                        pos += n;
                    }
                }
                if self.level != Level::Initial {
                    let pn = self.pn[index(self.level)];
                    self.pn[index(self.level)] += 1;
                    let n = self
                        .server
                        .borrow_mut()
                        .seal(self.level, pn, b"header", &mut self.wire, self.end)
                        .map_err(local::Error::Input)?;
                    assert_eq!(
                        measured(|| self.client.tls.borrow_mut().open(
                            self.level,
                            pn,
                            b"header",
                            &mut self.wire[..n]
                        ))
                        .map_err(local::Error::Input)?,
                        self.end
                    );
                }
            }
            assert_eq!(level, self.level);
            let b = &self.wire[self.used..self.end];
            let n = 4 + ((b[1] as usize) << 16) + ((b[2] as usize) << 8) + b[3] as usize;
            assert!(n <= b.len() && n <= out.len());
            out[..n].copy_from_slice(&b[..n]);
            self.used += n;
            Ok(n)
        }
    }
    let client = Access {
        tls: RefCell::new(client),
        reader: RefCell::new(None),
    };
    let server = RefCell::new(server);
    let reader = RefCell::new(None);
    let mut input = Input {
        client: &client,
        server: &server,
        reader: &reader,
        wire: [0; 8208],
        used: 0,
        end: 0,
        pn: [0; 3],
        level: Level::Initial,
        corrupt: corrupt_cv,
        saw: false,
    };
    let mut bytes = [0; 8192];
    let slot = local::MessageSlot::new(&mut bytes);
    let carrier = CarrierStorage::<1, 16, 4>::new();
    let mut slab = vec![0; 65536];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init();
    let sid = SessionId::new(5900);
    let rv = kit
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    let programs = global::client_programs();
    let mut owner = rv.enter(sid, &programs.verify).unwrap();
    let mut receiver = rv.enter(sid, &programs.input).unwrap();
    let reactor = hibana_quic_pal::async_io::Reactor::<0, 0>::new().unwrap();
    let result = {
        let feed = async {
            let mut wire = [0; 8208];
            let mut pn = [0; 3];
            loop {
                let output = poll_fn(|cx| {
                    client.reader.borrow_mut().replace(cx.waker().clone());
                    let mut c = client.tls.borrow_mut();
                    match measured(|| c.transmit(&mut wire[..8192])) {
                        Ok(Some(o)) => Poll::Ready(Ok(Some(o))),
                        Ok(None) if !c.is_handshaking() && !server.borrow().is_handshaking() => {
                            Poll::Ready(Ok(None))
                        }
                        Ok(None) => Poll::Pending,
                        Err(e) => Poll::Ready(Err(local::Error::Input(e))),
                    }
                })
                .await?;
                let Some(o) = output else {
                    return Ok(());
                };
                if o.level != Level::Initial {
                    let number = pn[index(o.level)];
                    pn[index(o.level)] += 1;
                    let n = measured(|| {
                        client
                            .tls
                            .borrow_mut()
                            .seal(o.level, number, b"header", &mut wire, o.len)
                    })
                    .map_err(local::Error::Input)?;
                    assert_eq!(
                        server
                            .borrow_mut()
                            .open(o.level, number, b"header", &mut wire[..n])
                            .map_err(local::Error::Input)?,
                        o.len
                    );
                }
                server
                    .borrow_mut()
                    .receive(o.level, &wire[..o.len])
                    .map_err(local::Error::Input)?;
                let w = reader.borrow_mut().take();
                if let Some(w) = w {
                    w.wake();
                }
                hibana_quic::runtime::yield_now().await;
            }
        };
        let mut owner = pin!(local::client_owner(&mut owner, &client.tls, &slot));
        let mut owner = pin!(poll_fn(|cx| {
            let result = measured(|| owner.as_mut().poll(cx));
            if let Some(w) = client.reader.borrow_mut().take() {
                w.wake();
            }
            result
        }));
        let mut receiver = pin!(local::client_input(&mut receiver, &slot, &mut input));
        let mut feed = pin!(feed);
        reactor
            .block_on(TaskSet::new([
                owner.as_mut(),
                receiver.as_mut(),
                feed.as_mut(),
            ]))
            .unwrap()
    };
    result.map(|()| input.saw)
}
fn run(bits: u16, corrupt_cv: bool) {
    let id = identity(bits);
    let anchors = [trust_anchor_from_der(&CertificateDer::from(id.root.as_ref())).unwrap()];
    let mut buffers = Buffers::new();
    let mut client = measured(|| {
        BoundedTls::client(
            ClientConfig {
                protocol: Default::default(),
                version: hibana_quic::quic::imp::kernel::version::Version::V1,
                server_name: "localhost",
                trust_anchors: &anchors,
                now: UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_000)),
                certificate_limits: Limits::default(),
                transport_parameters: CLIENT_PARAMS,
            },
            buffers.storage(),
            &mut KernelEntropy,
        )
    })
    .unwrap();
    let mut server = RustlsProvider::server(vec![id.leaf], id.key, SERVER_PARAMS.to_vec()).unwrap();
    let result = exchange(&mut client, &mut server, corrupt_cv);
    if corrupt_cv {
        assert!(matches!(
            result,
            Err(hibana_tls::handshake::local::Error::Crypto(_))
        ));
        assert!(client.last_failure().is_some());
        assert!(!client.has_keys(Level::OneRtt));
        return;
    }
    assert!(result.unwrap());
    assert!(client.negotiated_alpn().is_some());
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
