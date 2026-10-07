//! Real bounded TLS full handshakes; rcgen/rustls and fixture setup are host-only.
use hibana_quic::{
    bounded_tls::{BoundedTls, ClientConfig, ServerConfig, SigningKey, State, Storage},
    crypto::CipherSuite,
    tls::{self, Level, Provider},
    tls_certificate::{CertificateDer, Limits, UnixTime, trust_anchor_from_der},
};
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

use hibana_quic::bounded_tls::CipherPolicy;
#[derive(Clone, Copy)]
struct Case {
    fragment: usize,
    cancel: bool,
    wrong_ca: bool,
    wrong_name: bool,
    corrupt_server: u8,
    corrupt_client: u8,
    policy: CipherPolicy,
    ticket: Option<u8>,
}
impl Default for Case {
    fn default() -> Self {
        Self {
            fragment: 8192,
            cancel: false,
            wrong_ca: false,
            wrong_name: false,
            corrupt_server: 0,
            corrupt_client: 0,
            policy: CipherPolicy::Aes128Only,
            ticket: None,
        }
    }
}
fn identity_for_wrong_ca() -> Identity {
    identity()
}
#[test]
fn direct_transcript_roles_validate_full_tls_without_allocating() {
    bounded_case(Case::default());
}
#[test]
fn async_partial_input_cancellation_erases_and_fails_closed() {
    bounded_case(Case {
        cancel: true,
        ..Case::default()
    });
}
#[test]
fn async_one_byte_fragmentation() {
    bounded_case(Case {
        fragment: 1,
        ..Case::default()
    });
}
#[test]
fn async_odd_fragmentation() {
    for fragment in [3, 17, 127, 4096] {
        bounded_case(Case {
            fragment,
            ..Case::default()
        });
    }
}
#[test]
fn async_chacha20_full_handshake_and_packet_keys() {
    bounded_case(Case {
        policy: CipherPolicy::ChaCha20Only,
        ..Case::default()
    });
}
#[test]
fn async_rejects_wrong_certificate_authority() {
    bounded_case(Case {
        wrong_ca: true,
        ..Case::default()
    });
}
#[test]
fn async_rejects_wrong_hostname() {
    bounded_case(Case {
        wrong_name: true,
        ..Case::default()
    });
}
#[test]
fn async_rejects_corrupted_certificate_verify() {
    bounded_case(Case {
        corrupt_server: 15,
        ..Case::default()
    });
}
#[test]
fn async_rejects_corrupted_server_finished() {
    bounded_case(Case {
        corrupt_server: 20,
        ..Case::default()
    });
}
#[test]
fn async_rejects_corrupted_client_finished() {
    bounded_case(Case {
        corrupt_client: 20,
        ..Case::default()
    });
}
fn bounded_case(case: Case) {
    {
        let cancel = case.cancel;
        let identity = identity();
        let unrelated = identity_for_wrong_ca();
        let anchors = [trust_anchor_from_der(if case.wrong_ca {
            &unrelated.root
        } else {
            &identity.root
        })
        .unwrap()];
        let chain = [identity.leaf.as_ref()];
        let mut cb = Buffers::new();
        let mut sb = Buffers::new();
        let client = Shared {
            tls: RefCell::new(
                BoundedTls::client_with_policy(
                    ClientConfig {
                        version: hibana_quic::version::Version::V1,
                        server_name: if case.wrong_name {
                            "wrong.invalid"
                        } else {
                            "localhost"
                        },
                        trust_anchors: &anchors,
                        now: now(),
                        certificate_limits: Limits::default(),
                        transport_parameters: CLIENT_PARAMS,
                    },
                    cb.storage(),
                    &mut OsRng,
                    case.policy,
                )
                .unwrap(),
            ),
            reader: RefCell::new(None),
        };
        let server = Shared {
            tls: RefCell::new(
                BoundedTls::server_with_policy(
                    ServerConfig {
                        version: hibana_quic::version::Version::V1,
                        certificate_chain: &chain,
                        signing_key: &identity.signing,
                        transport_parameters: SERVER_PARAMS,
                    },
                    sb.storage(),
                    &mut OsRng,
                    case.policy,
                )
                .unwrap(),
            ),
            reader: RefCell::new(None),
        };
        let mut ci = Input {
            remote: &server,
            pending: [0; 8192],
            used: 0,
            end: 0,
            level: Level::Initial,
            stall: cancel,
            fragment: case.fragment,
            corrupt: 0,
        };
        let mut si = Input {
            remote: &client,
            pending: [0; 8192],
            used: 0,
            end: 0,
            level: Level::Initial,
            stall: cancel,
            fragment: case.fragment,
            corrupt: 0,
        };
        ci.corrupt = case.corrupt_server;
        si.corrupt = case.corrupt_client;
        let mut cm = [0; 8192];
        let mut sm = [0; 8192];
        let cs = locals::MessageSlot::new(&mut cm);
        let ss = locals::MessageSlot::new(&mut sm);
        let cc = CarrierStorage::<1, 16, 4>::new();
        let sc = CarrierStorage::<1, 16, 4>::new();
        let mut cslab = vec![0; 65536];
        let mut sslab = vec![0; 65536];
        let mut ck = SessionKitStorage::uninit();
        let mut sk = SessionKitStorage::uninit();
        let cid = SessionId::new(4500);
        let sid = SessionId::new(4501);
        let ck = ck.init();
        let sk = sk.init();
        let cr = ck.rendezvous(&mut cslab, cc.bind(cid).unwrap()).unwrap();
        let sr = sk.rendezvous(&mut sslab, sc.bind(sid).unwrap()).unwrap();
        let cp = protocol::client_programs();
        let sp = protocol::server_programs();
        let mut cinput = cr.enter(cid, &cp.input).unwrap();
        let mut cverify = cr.enter(cid, &cp.verify).unwrap();
        let mut sinput = sr.enter(sid, &sp.input).unwrap();
        let mut sverify = sr.enter(sid, &sp.verify).unwrap();
        let reactor = hibana_quic_host::async_io::Reactor::<0, 0>::new().unwrap();
        let result = measured(|| {
            let mut co = pin!(locals::client_owner(&mut cverify, &client, &cs));
            let mut cin = pin!(locals::client_input(&mut cinput, &cs, &mut ci));
            let mut so = pin!(locals::server_owner(&mut sverify, &server, &ss));
            let mut sin = pin!(locals::server_input(&mut sinput, &ss, &mut si));
            let tasks = TaskSet::new([co.as_mut(), cin.as_mut(), so.as_mut(), sin.as_mut()]);
            if cancel {
                let mut tasks = pin!(tasks);
                let mut cx = Context::from_waker(Waker::noop());
                for _ in 0..8 {
                    assert!(tasks.as_mut().poll(&mut cx).is_pending());
                }
                Ok(())
            } else {
                reactor.block_on(tasks).unwrap()
            }
        });
        if cancel {
            assert!(result.is_ok());
            assert_eq!(client.tls.borrow().state(), State::Failed);
            assert_eq!(server.tls.borrow().state(), State::Failed);
        } else if case.wrong_ca
            || case.wrong_name
            || case.corrupt_server != 0
            || case.corrupt_client != 0
        {
            assert!(result.is_err(), "invalid transcript accepted");
            if case.corrupt_client != 0 {
                assert_eq!(server.tls.borrow().state(), State::Failed);
            } else {
                assert_eq!(client.tls.borrow().state(), State::Failed);
            }
        } else {
            result.unwrap();
            let mut c = client.tls.borrow_mut();
            let mut s = server.tls.borrow_mut();
            assert_eq!(c.state(), State::Connected);
            assert_eq!(s.state(), State::Connected);
            assert_eq!(c.peer_transport_parameters(), Some(SERVER_PARAMS));
            assert_eq!(s.peer_transport_parameters(), Some(CLIENT_PARAMS));
            assert_eq!(c.negotiated_alpn(), Some(b"hq-interop".as_slice()));
            assert_eq!(
                c.negotiated_suite(),
                Some(match case.policy {
                    CipherPolicy::ChaCha20Only => CipherSuite::ChaCha20Poly1305Sha256,
                    _ => CipherSuite::Aes128GcmSha256,
                })
            );
            measured(|| {
                packets(&mut *c, &mut *s);
                packets(&mut *s, &mut *c);
            });
            if let Some(scenario) = case.ticket {
                let mut ticket = new_session_ticket(&[]);
                match scenario {
                    0 => {
                        let mask = c.header_mask(Level::OneRtt, true, &[3; 16]).unwrap();
                        measured(|| {
                            for byte in &ticket {
                                c.receive(Level::OneRtt, core::slice::from_ref(byte))
                                    .unwrap();
                            }
                            c.receive(Level::OneRtt, &ticket).unwrap();
                        });
                        assert_eq!(c.state(), State::Connected);
                        assert_eq!(c.header_mask(Level::OneRtt, true, &[3; 16]).unwrap(), mask);
                    }
                    1 => {
                        assert!(s.receive(Level::OneRtt, &ticket).is_err());
                        assert_eq!(s.state(), State::Failed);
                    }
                    2 => {
                        assert!(c.receive(Level::Handshake, &ticket).is_err());
                    }
                    3 => {
                        ticket = new_session_ticket(&[0, 42, 0, 4, 0, 0, 0, 1]);
                        assert!(c.receive(Level::OneRtt, &ticket).is_err());
                    }
                    4 => {
                        ticket = new_session_ticket(&[
                            0, 42, 0, 4, 255, 255, 255, 255, 0, 42, 0, 4, 255, 255, 255, 255,
                        ]);
                        assert!(c.receive(Level::OneRtt, &ticket).is_err());
                    }
                    5 => {
                        ticket[14] = 0;
                        ticket.remove(15);
                        ticket[3] -= 1;
                        assert!(c.receive(Level::OneRtt, &ticket).is_err());
                    }
                    6 => {
                        ticket[0] = 24;
                        assert!(c.receive(Level::OneRtt, &ticket).is_err());
                    }
                    _ => unreachable!(),
                }
                if scenario >= 2 {
                    assert_eq!(c.state(), State::Failed);
                    assert!(!c.has_keys(Level::OneRtt));
                }
            }
            c.discard_keys(Level::Handshake);
            assert!(!c.has_keys(Level::Handshake));
            assert_eq!(
                c.header_mask(Level::Handshake, true, &[0; 16]),
                Err(if c.state() == State::Failed {
                    tls::Error::Handshake
                } else {
                    tls::Error::KeysUnavailable
                })
            );
            s.discard_keys(Level::OneRtt);
            assert!(!s.has_keys(Level::OneRtt));
        }
        drop(cs);
        drop(ss);
        assert!(cm.iter().chain(sm.iter()).all(|b| *b == 0));
    }
}
use core::{
    cell::RefCell,
    future::{Future, poll_fn},
    pin::pin,
    task::{Context, Poll, Waker},
};
use hibana::runtime::{SessionKitStorage, ids::SessionId};
use hibana_quic::{
    bounded_tls::{locals, protocol},
    carrier::CarrierStorage,
    runtime::TaskSet,
};
struct Shared<P> {
    tls: RefCell<P>,
    reader: RefCell<Option<Waker>>,
}
impl locals::CryptoAccess for Shared<BoundedTls<'_, '_>> {
    fn with_crypto<R>(&self, f: impl FnOnce(&mut BoundedTls<'_, '_>) -> R) -> R {
        f(&mut self.tls.borrow_mut())
    }
    fn applied(&self) -> Result<(), locals::Error> {
        let w = self.reader.borrow_mut().take();
        if let Some(w) = w {
            w.wake();
        }
        Ok(())
    }
}
struct Input<'a, P> {
    remote: &'a Shared<P>,
    pending: [u8; 8192],
    used: usize,
    end: usize,
    level: Level,
    stall: bool,
    fragment: usize,
    corrupt: u8,
}
impl<P: Provider> locals::MessageInput for Input<'_, P> {
    async fn read_message(&mut self, level: Level, out: &mut [u8]) -> Result<usize, locals::Error> {
        if self.stall {
            out[..4].copy_from_slice(&[1, 0, 0, 0]);
            return core::future::pending().await;
        }
        let mut n = 4;
        let mut copied = 0;
        while copied < n {
            if self.used == self.end {
                let produced = poll_fn(|cx| {
                    self.remote.reader.borrow_mut().replace(cx.waker().clone());
                    match self
                        .remote
                        .tls
                        .borrow_mut()
                        .transmit(&mut self.pending[..self.fragment])
                    {
                        Ok(Some(p)) => Poll::Ready(Ok(p)),
                        Ok(None) => Poll::Pending,
                        Err(e) => Poll::Ready(Err(locals::Error::Input(e))),
                    }
                })
                .await?;
                self.used = 0;
                self.end = produced.len;
                self.level = produced.level;
            }
            assert_eq!(level, self.level);
            let count = (n - copied).min(self.end - self.used);
            out[copied..copied + count]
                .copy_from_slice(&self.pending[self.used..self.used + count]);
            copied += count;
            self.used += count;
            if copied == 4 {
                n = 4 + ((out[1] as usize) << 16) + ((out[2] as usize) << 8) + out[3] as usize;
                if n > out.len() {
                    return Err(locals::Error::Capacity);
                }
            }
        }
        if out[0] == self.corrupt {
            out[n - 1] ^= 1;
        }
        Ok(n)
    }
}

use hibana_quic::tls_certificate::ServerName;
use hibana_quic_reference_tls::{RustlsProvider, rustls};
// Only the independent rustls peer uses its own Provider interface. The candidate
// always executes the public projected owner/input roles under the real reactor.
async fn feed_reference<P: Provider>(
    candidate: &Shared<P>,
    reference: &Shared<RustlsProvider>,
) -> Result<(), locals::Error> {
    let mut bytes = [0; 37];
    loop {
        let output = poll_fn(|cx| {
            candidate.reader.borrow_mut().replace(cx.waker().clone());
            let mut source = candidate.tls.borrow_mut();
            match source.transmit(&mut bytes) {
                Ok(Some(output)) => Poll::Ready(Ok(Some(output))),
                Ok(None)
                    if !source.is_handshaking() && !reference.tls.borrow().is_handshaking() =>
                {
                    Poll::Ready(Ok(None))
                }
                Ok(None) => Poll::Pending,
                Err(e) => Poll::Ready(Err(locals::Error::Input(e))),
            }
        })
        .await?;
        let Some(output) = output else {
            return Ok(());
        };
        reference
            .tls
            .borrow_mut()
            .receive(output.level, &bytes[..output.len])
            .map_err(locals::Error::Input)?;
        let w = reference.reader.borrow_mut().take();
        if let Some(w) = w {
            w.wake();
        }
        hibana_quic::runtime::yield_now().await;
    }
}
fn reference_case(candidate_client: bool, retry: bool) {
    let id = identity();
    let chain = [id.leaf.as_ref()];
    let anchors = [trust_anchor_from_der(&id.root).unwrap()];
    let mut storage = Buffers::new();
    let bounded = if candidate_client {
        BoundedTls::client(
            ClientConfig {
                version: hibana_quic::version::Version::V1,
                server_name: "localhost",
                trust_anchors: &anchors,
                now: now(),
                certificate_limits: Limits::default(),
                transport_parameters: CLIENT_PARAMS,
            },
            storage.storage(),
            &mut OsRng,
        )
        .unwrap()
    } else {
        let config = ServerConfig {
            version: hibana_quic::version::Version::V1,
            certificate_chain: &chain,
            signing_key: &id.signing,
            transport_parameters: SERVER_PARAMS,
        };
        if retry {
            BoundedTls::server_p256(config, storage.storage(), &mut OsRng).unwrap()
        } else {
            BoundedTls::server(config, storage.storage(), &mut OsRng).unwrap()
        }
    };
    let reference = if candidate_client {
        RustlsProvider::server(
            vec![id.leaf.clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(id.key.clone()).into(),
            SERVER_PARAMS.to_vec(),
        )
        .unwrap()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(id.root.clone()).unwrap();
        RustlsProvider::client(
            roots,
            ServerName::try_from("localhost").unwrap(),
            CLIENT_PARAMS.to_vec(),
        )
        .unwrap()
    };
    let candidate = Shared {
        tls: RefCell::new(bounded),
        reader: RefCell::new(None),
    };
    let reference = Shared {
        tls: RefCell::new(reference),
        reader: RefCell::new(None),
    };
    let mut input = Input {
        remote: &reference,
        pending: [0; 8192],
        used: 0,
        end: 0,
        level: Level::Initial,
        stall: false,
        fragment: 13,
        corrupt: 0,
    };
    let mut bytes = [0; 8192];
    let slot = locals::MessageSlot::new(&mut bytes);
    let carrier = CarrierStorage::<1, 16, 4>::new();
    let mut slab = vec![0; 65536];
    let mut kit = SessionKitStorage::uninit();
    let kit = kit.init();
    let id = SessionId::new(4700);
    let rendezvous = kit
        .rendezvous(&mut slab, carrier.bind(id).unwrap())
        .unwrap();
    let programs = if candidate_client {
        protocol::client_programs()
    } else {
        protocol::server_programs()
    };
    let mut verify = rendezvous.enter(id, &programs.verify).unwrap();
    let mut wire = rendezvous.enter(id, &programs.input).unwrap();
    let reactor = hibana_quic_host::async_io::Reactor::<0, 0>::new().unwrap();
    let owner = async {
        if candidate_client {
            locals::client_owner(&mut verify, &candidate, &slot).await
        } else {
            locals::server_owner(&mut verify, &candidate, &slot).await
        }
    };
    let receiver = async {
        if candidate_client {
            locals::client_input(&mut wire, &slot, &mut input).await
        } else {
            locals::server_input(&mut wire, &slot, &mut input).await
        }
    };
    let mut owner = pin!(owner);
    let mut receiver = pin!(receiver);
    let mut feed = pin!(feed_reference(&candidate, &reference));
    reactor
        .block_on(TaskSet::new([
            owner.as_mut(),
            receiver.as_mut(),
            feed.as_mut(),
        ]))
        .unwrap()
        .unwrap();
    let mut candidate = candidate.tls.borrow_mut();
    let mut reference = reference.tls.borrow_mut();
    assert_eq!(candidate.state(), State::Connected);
    assert!(!reference.is_handshaking());
    assert_eq!(
        candidate.negotiated_group(),
        Some(if retry {
            hibana_quic::tls_wire::GROUP_P256
        } else {
            hibana_quic::tls_wire::GROUP_X25519
        })
    );
    packets(&mut *candidate, &mut *reference);
    packets(&mut *reference, &mut *candidate);
}
#[test]
fn async_client_authenticates_independent_rustls_server() {
    reference_case(true, false);
}
#[test]
fn async_server_authenticates_independent_rustls_client() {
    reference_case(false, false);
}
#[test]
fn async_server_hello_retry_with_independent_rustls() {
    reference_case(false, true);
}

fn new_session_ticket(extension: &[u8]) -> Vec<u8> {
    let mut message = vec![4, 0, 0, 14, 0, 0, 0, 60, 1, 2, 3, 4, 0, 0, 1, 7, 0, 0];
    let n = 14 + extension.len();
    message[1] = (n >> 16) as u8;
    message[2] = (n >> 8) as u8;
    message[3] = n as u8;
    message[16..18].copy_from_slice(&(extension.len() as u16).to_be_bytes());
    message.extend_from_slice(extension);
    message
}
#[test]
fn async_authenticated_ticket_keeps_keys_and_allocates_zero() {
    bounded_case(Case {
        ticket: Some(0),
        ..Case::default()
    });
}
#[test]
fn async_authenticated_ticket_rejects_role_level_and_malformed_fields() {
    for scenario in 1..=6 {
        bounded_case(Case {
            ticket: Some(scenario),
            ..Case::default()
        });
    }
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
                version: hibana_quic::version::Version::V1,
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
