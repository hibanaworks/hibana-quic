//! Protected0RTT TLS-provider evidence. This does not qualify QUIC wire routing,
//! congestion/rollback or the external runner; those are engine/host gates.
use hibana_quic::{
    bounded_tls::{BoundedTls, ClientConfig, ServerConfig, SigningKey, State, Storage},
    tls::{self, Level, Provider},
    tls_certificate::{CertificateDer, Limits, TrustAnchor, UnixTime, trust_anchor_from_der},
};
use hibana_quic::{
    bounded_tls::{
        CipherPolicy, ClientEarlyData, ClientResumption, ServerEarlyData, ServerResumption,
    },
    early_data::{
        EarlyFreshness, EarlyStatus, Quarantine, QuarantineSlot, ReplayStorage, ServerPolicy,
    },
    tls_ticket::{
        self as ticket, Binding, ClientCache, ClientOffer, ClientSlot, ReplayPolicy, TicketKey,
        VerificationContext,
    },
};
use p256::pkcs8::DecodePrivateKey;
use rand_core::OsRng;
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
    assert_eq!(n, 0, "bounded TLS ticket lifecycle allocated");
    value
}

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
    let mut params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let leaf = params.signed_by(&key, &ca, &ca_key).unwrap();
    let der = key.serialize_der();
    let signing = SigningKey::from_pkcs8_der(&der).unwrap();
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
fn now() -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_000))
}
const CLIENT_PARAMS: &[u8] = &[15, 0, 4, 1, 42];
const SERVER_PARAMS: &[u8] = &[0, 0, 15, 0, 4, 2, 0x48, 0, 6, 2, 0x44, 0, 8, 1, 2];
const EARLY_POLICY: ServerPolicy = ServerPolicy::BufferedReplaySafeRequests {
    max_bytes: 2048,
    max_streams: 2,
};
struct Clock(Cell<u64>);
impl ticket::TicketClock for Clock {
    fn now_ms(&self) -> Result<u64, ticket::Error> {
        Ok(self.0.get())
    }
}
const SIZE: usize = 4096;
fn drain(
    from: &mut BoundedTls<'_, '_>,
    to: &mut BoundedTls<'_, '_>,
    fragment: usize,
    pns: &mut [u64; 3],
    certificates: &mut usize,
    tickets: &mut usize,
) -> Result<bool, tls::Error> {
    let mut buffer = [0; 4096 + 16];
    let mut progress = false;
    for _ in 0..10000 {
        let Some(out) = from.transmit(&mut buffer[..fragment])? else {
            return Ok(progress);
        };
        if fragment == 4096 {
            let mut position = 0;
            while position + 4 <= out.len {
                if out.level == Level::Handshake && buffer[position] == 11 {
                    *certificates += 1;
                }
                if out.level == Level::OneRtt && buffer[position] == 4 {
                    *tickets += 1;
                }
                position += 4
                    + ((buffer[position + 1] as usize) << 16)
                    + ((buffer[position + 2] as usize) << 8)
                    + buffer[position + 3] as usize;
            }
        }
        if out.level != Level::Initial {
            let index = if out.level == Level::Handshake { 1 } else { 2 };
            let pn = pns[index];
            pns[index] += 1;
            let n = from.seal(out.level, pn, b"authenticated CRYPTO", &mut buffer, out.len)?;
            let plain = to.open(out.level, pn, b"authenticated CRYPTO", &mut buffer[..n])?;
            assert_eq!(plain, out.len);
        }
        to.receive(out.level, &buffer[..out.len])?;
        progress = true;
    }
    panic!("unbounded output")
}
fn pump(client: &mut BoundedTls<'_, '_>, server: &mut BoundedTls<'_, '_>) {
    let mut cp = [0; 3];
    let mut sp = [0; 3];
    let mut certificates = 0;
    let mut tickets = 0;
    for _ in 0..32 {
        let c = drain(
            client,
            server,
            127,
            &mut cp,
            &mut certificates,
            &mut tickets,
        );
        let s = drain(
            server,
            client,
            127,
            &mut sp,
            &mut certificates,
            &mut tickets,
        );
        if c.is_err() || s.is_err() {
            panic!(
                "client={c:?}/{:?},server={s:?}/{:?}",
                client.last_failure(),
                server.last_failure()
            );
        }
        if !c.unwrap() && !s.unwrap() {
            assert_eq!(client.state(), State::Connected);
            assert_eq!(server.state(), State::Connected);
            return;
        }
    }
    panic!("nonquiescent handshake")
}
fn client_config<'a>(anchors: &'a [TrustAnchor<'a>]) -> ClientConfig<'a> {
    ClientConfig {
        server_name: "localhost",
        trust_anchors: anchors,
        now: now(),
        certificate_limits: Limits::default(),
        transport_parameters: CLIENT_PARAMS,
    }
}
fn issue_ticket(
    id: &Identity,
    anchors: &[TrustAnchor<'_>],
    key: &mut TicketKey<'_>,
    cache: &mut ClientCache<'_, SIZE>,
    clock: &Clock,
    cipher: CipherPolicy,
) {
    let mut cb = Buffers::new();
    let mut sb = Buffers::new();
    let chain = [id.leaf.as_ref()];
    let mut entropy = OsRng;
    let slots = [QuarantineSlot::<1024>::EMPTY, QuarantineSlot::EMPTY];
    let admission = ServerEarlyData::buffered(
        1,
        EARLY_POLICY,
        SERVER_PARAMS,
        &slots,
        EarlyFreshness::new(1000).unwrap(),
    )
    .unwrap();
    let mut client = BoundedTls::client_with_tickets_and_policy(
        client_config(anchors),
        cb.storage(),
        &mut OsRng,
        ClientResumption {
            store: cache,
            clock,
        },
        cipher,
    )
    .unwrap();
    let mut server = BoundedTls::server_with_early_data_and_policy(
        ServerConfig {
            certificate_chain: &chain,
            signing_key: &id.signing,
            transport_parameters: SERVER_PARAMS,
        },
        sb.storage(),
        &mut OsRng,
        ServerResumption {
            store: key,
            entropy: &mut entropy,
            clock,
            policy: b"early GET v1",
            lifetime_seconds: 60,
            max_age_skew_ms: 1000,
        },
        admission,
        cipher,
    )
    .unwrap();
    pump(&mut client, &mut server);
    assert_eq!(client.early_status(), EarlyStatus::Disabled);
    assert_eq!(server.early_status(), EarlyStatus::Disabled);
    assert!(!client.has_early_keys() && !server.has_early_keys());
}
fn offer(
    cache: &mut ClientCache<'_, SIZE>,
    anchors: &[TrustAnchor<'_>],
    suite: u16,
) -> ClientOffer<SIZE> {
    let offer = cache
        .take_verified_for_origin(
            1000,
            &Binding::new("localhost", b"hq-interop", &[]).unwrap(),
            suite,
            VerificationContext::new(anchors, Limits::default()).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert!(offer.remembered_early_limits().is_some());
    offer
}
#[test]
fn real_early_packet_keys_and_finished_quarantine_allocate_zero_both_suites() {
    for (cipher, suite) in [
        (CipherPolicy::Aes128Only, 0x1301),
        (CipherPolicy::ChaCha20Only, 0x1303),
    ] {
        let id = identity();
        let anchors = [trust_anchor_from_der(&id.root).unwrap()];
        let chain = [id.leaf.as_ref()];
        let clock = Clock(Cell::new(1000));
        let mut ordinary = [];
        let mut replay = ReplayStorage::<4>::new();
        let mut cache_slots = [ClientSlot::<SIZE>::empty()];
        let mut cb = Buffers::new();
        let mut sb = Buffers::new();
        let mut held = [QuarantineSlot::<1024>::EMPTY, QuarantineSlot::EMPTY];
        measured(|| {
            let mut cache = ClientCache::new(&mut cache_slots);
            let mut key = TicketKey::generate_with_early_replay(
                &mut OsRng,
                ReplayPolicy::ReusableOneRtt,
                &mut ordinary,
                &mut replay,
            )
            .unwrap();
            issue_ticket(&id, &anchors, &mut key, &mut cache, &clock, cipher);
            let cached = offer(&mut cache, &anchors, suite);
            let mut client = BoundedTls::client_resuming_early_with_policy(
                client_config(&anchors),
                cb.storage(),
                &mut OsRng,
                ClientResumption {
                    store: &mut cache,
                    clock: &clock,
                },
                cached,
                ClientEarlyData::replay_safe_requests(2),
                cipher,
            )
            .unwrap();
            let mut entropy = OsRng;
            let admission = ServerEarlyData::buffered(
                2,
                EARLY_POLICY,
                SERVER_PARAMS,
                &held,
                EarlyFreshness::new(1000).unwrap(),
            )
            .unwrap();
            let mut server = BoundedTls::server_with_early_data_and_policy(
                ServerConfig {
                    certificate_chain: &chain,
                    signing_key: &id.signing,
                    transport_parameters: SERVER_PARAMS,
                },
                sb.storage(),
                &mut OsRng,
                ServerResumption {
                    store: &mut key,
                    entropy: &mut entropy,
                    clock: &clock,
                    policy: b"early GET v1",
                    lifetime_seconds: 60,
                    max_age_skew_ms: 1000,
                },
                admission,
                cipher,
            )
            .unwrap();
            let mut hello = [0; 4096];
            let ch = client.transmit(&mut hello).unwrap().unwrap();
            server.receive(ch.level, &hello[..ch.len]).unwrap();
            assert_eq!(server.early_status(), EarlyStatus::AcceptedPendingFinished);
            assert_eq!(server.early_generation(), Some(2));
            assert!(server.has_early_keys() && client.has_early_keys());
            let remembered = server.remembered_early_limits().unwrap();
            let claim = server.take_early_replay_claim().unwrap();
            assert!(server.take_early_replay_claim().is_none());
            let mut quarantine =
                Quarantine::new(EARLY_POLICY, remembered, claim, &mut held).unwrap();
            let request = b"GET /early\r\n";
            let mut first = [0; 64];
            first[..request.len()].copy_from_slice(request);
            let n = client
                .seal_early(0, b"header", &mut first, request.len())
                .unwrap();
            let mut late = first; // protect the delayed retransmission with a fresh PN
            late[..request.len()].copy_from_slice(request);
            let late_n = client
                .seal_early(1, b"header", &mut late, request.len())
                .unwrap();
            assert_eq!(
                client.early_header_mask(true, &[0; 16]).unwrap(),
                server.early_header_mask(false, &[0; 16]).unwrap()
            );
            assert_eq!(
                server.seal_early(0, b"header", &mut first, 0),
                Err(tls::Error::InvalidInput)
            );
            assert_eq!(
                client.open_early(0, b"header", &mut first[..n]),
                Err(tls::Error::InvalidInput)
            );
            let mut bad = first;
            bad[n - 1] ^= 1;
            assert_eq!(
                server.open_early(0, b"header", &mut bad[..n]),
                Err(tls::Error::Authentication)
            );
            assert!(bad[..n].iter().all(|b| *b == 0));
            assert!(server.has_early_keys());
            let plain = server.open_early(0, b"header", &mut first[..n]).unwrap();
            quarantine
                .buffer_authenticated_stream(2, 0, 0, &first[..plain], true)
                .unwrap();
            assert!(quarantine.next_release().is_err());
            pump(&mut client, &mut server);
            assert!(client.is_resumed() && server.is_resumed());
            assert_eq!(client.early_status(), EarlyStatus::Accepted);
            assert_eq!(server.early_status(), EarlyStatus::Accepted);
            assert!(!client.has_early_keys());
            assert_eq!(
                client.seal_early(2, b"header", &mut first, 0),
                Err(tls::Error::KeysUnavailable)
            );
            quarantine.finish_after_verified_handshake(2).unwrap();
            let view = quarantine.next_release().unwrap().unwrap();
            assert_eq!(view.bytes, request);
            let release = view.ticket;
            quarantine.complete_release(release).unwrap();
            let plain = server
                .open_early(1, b"header", &mut late[..late_n])
                .unwrap();
            quarantine
                .buffer_authenticated_stream(2, 0, 0, &late[..plain], true)
                .unwrap();
            assert!(quarantine.next_release().unwrap().is_none());
            assert_eq!(quarantine.charged(), request.len() as u64);
            server.discard_early_keys();
            assert!(!server.has_early_keys());
            assert_eq!(
                server.open_early(1, b"header", &mut late[..late_n]),
                Err(tls::Error::KeysUnavailable)
            );
        });
    }
}
#[test]
fn explicit_server_decline_keeps_real_one_rtt_resumption() {
    let id = identity();
    let anchors = [trust_anchor_from_der(&id.root).unwrap()];
    let chain = [id.leaf.as_ref()];
    let clock = Clock(Cell::new(1000));
    let mut ordinary = [];
    let mut replay = ReplayStorage::<1>::new();
    let mut cache_slots = [ClientSlot::<SIZE>::empty()];
    let mut cache = ClientCache::new(&mut cache_slots);
    let mut key = TicketKey::generate_with_early_replay(
        &mut OsRng,
        ReplayPolicy::ReusableOneRtt,
        &mut ordinary,
        &mut replay,
    )
    .unwrap();
    issue_ticket(
        &id,
        &anchors,
        &mut key,
        &mut cache,
        &clock,
        CipherPolicy::Default,
    );
    let cached = offer(&mut cache, &anchors, 0x1301);
    let mut cb = Buffers::new();
    let mut sb = Buffers::new();
    let mut entropy = OsRng;
    let mut client = BoundedTls::client_resuming_early(
        client_config(&anchors),
        cb.storage(),
        &mut OsRng,
        ClientResumption {
            store: &mut cache,
            clock: &clock,
        },
        cached,
        ClientEarlyData::replay_safe_requests(2),
    )
    .unwrap();
    let mut server = BoundedTls::server_with_tickets(
        ServerConfig {
            certificate_chain: &chain,
            signing_key: &id.signing,
            transport_parameters: SERVER_PARAMS,
        },
        sb.storage(),
        &mut OsRng,
        ServerResumption {
            store: &mut key,
            entropy: &mut entropy,
            clock: &clock,
            policy: b"early GET v1",
            lifetime_seconds: 60,
            max_age_skew_ms: 1000,
        },
    )
    .unwrap();
    pump(&mut client, &mut server);
    assert!(client.is_resumed() && server.is_resumed());
    assert_eq!(client.early_status(), EarlyStatus::Rejected);
    assert_eq!(server.early_status(), EarlyStatus::Rejected);
    assert!(!client.has_early_keys() && !server.has_early_keys());
    assert!(server.take_early_replay_claim().is_none());
}
#[test]
fn replayed_clienthello_cannot_admit_early_after_first_owner_aborts() {
    let id = identity();
    let anchors = [trust_anchor_from_der(&id.root).unwrap()];
    let chain = [id.leaf.as_ref()];
    let clock = Clock(Cell::new(1000));
    let mut ordinary = [];
    let mut replay = ReplayStorage::<1>::new();
    let mut cache_slots = [ClientSlot::<SIZE>::empty()];
    let mut cache = ClientCache::new(&mut cache_slots);
    let mut key = TicketKey::generate_with_early_replay(
        &mut OsRng,
        ReplayPolicy::ReusableOneRtt,
        &mut ordinary,
        &mut replay,
    )
    .unwrap();
    issue_ticket(
        &id,
        &anchors,
        &mut key,
        &mut cache,
        &clock,
        CipherPolicy::Default,
    );
    let cached = offer(&mut cache, &anchors, 0x1301);
    let mut cb = Buffers::new();
    let mut client = BoundedTls::client_resuming_early(
        client_config(&anchors),
        cb.storage(),
        &mut OsRng,
        ClientResumption {
            store: &mut cache,
            clock: &clock,
        },
        cached,
        ClientEarlyData::replay_safe_requests(2),
    )
    .unwrap();
    let mut hello = [0; 4096];
    let out = client.transmit(&mut hello).unwrap().unwrap();
    for generation in [2, 3] {
        let mut buffers = Buffers::new();
        let held = [QuarantineSlot::<1024>::EMPTY, QuarantineSlot::EMPTY];
        let mut entropy = OsRng;
        let admission = ServerEarlyData::buffered(
            generation,
            EARLY_POLICY,
            SERVER_PARAMS,
            &held,
            EarlyFreshness::new(1000).unwrap(),
        )
        .unwrap();
        let mut server = BoundedTls::server_with_early_data(
            ServerConfig {
                certificate_chain: &chain,
                signing_key: &id.signing,
                transport_parameters: SERVER_PARAMS,
            },
            buffers.storage(),
            &mut OsRng,
            ServerResumption {
                store: &mut key,
                entropy: &mut entropy,
                clock: &clock,
                policy: b"early GET v1",
                lifetime_seconds: 60,
                max_age_skew_ms: 1000,
            },
            admission,
        )
        .unwrap();
        server.receive(Level::Initial, &hello[..out.len]).unwrap();
        assert_eq!(
            server.early_status(),
            if generation == 2 {
                EarlyStatus::AcceptedPendingFinished
            } else {
                EarlyStatus::Rejected
            }
        );
        assert_eq!(server.has_early_keys(), generation == 2);
        assert_eq!(server.take_early_replay_claim().is_some(), generation == 2);
    }
}

#[test]
fn broad_one_rtt_tolerance_cannot_silently_authorize_stale_early_data() {
    for (delay, accept) in [(999, true), (1000, true), (1001, false)] {
        let id = identity();
        let anchors = [trust_anchor_from_der(&id.root).unwrap()];
        let chain = [id.leaf.as_ref()];
        let client_clock = Clock(Cell::new(1000));
        let server_clock = Clock(Cell::new(1000 + delay));
        let mut ordinary = [];
        let mut replay = ReplayStorage::<2>::new();
        let mut cache_slots = [ClientSlot::<SIZE>::empty()];
        let mut cache = ClientCache::new(&mut cache_slots);
        let mut key = TicketKey::generate_with_early_replay(
            &mut OsRng,
            ReplayPolicy::ReusableOneRtt,
            &mut ordinary,
            &mut replay,
        )
        .unwrap();
        issue_ticket(
            &id,
            &anchors,
            &mut key,
            &mut cache,
            &client_clock,
            CipherPolicy::Default,
        );
        let cached = offer(&mut cache, &anchors, 0x1301);
        let mut cb = Buffers::new();
        let mut sb = Buffers::new();
        let held = [QuarantineSlot::<1024>::EMPTY, QuarantineSlot::EMPTY];
        let mut entropy = OsRng;
        let mut client = BoundedTls::client_resuming_early(
            client_config(&anchors),
            cb.storage(),
            &mut OsRng,
            ClientResumption {
                store: &mut cache,
                clock: &client_clock,
            },
            cached,
            ClientEarlyData::replay_safe_requests(2),
        )
        .unwrap();
        let admission = ServerEarlyData::buffered(
            2,
            EARLY_POLICY,
            SERVER_PARAMS,
            &held,
            EarlyFreshness::new(1000).unwrap(),
        )
        .unwrap();
        let mut server = BoundedTls::server_with_early_data(
            ServerConfig {
                certificate_chain: &chain,
                signing_key: &id.signing,
                transport_parameters: SERVER_PARAMS,
            },
            sb.storage(),
            &mut OsRng,
            ServerResumption {
                store: &mut key,
                entropy: &mut entropy,
                clock: &server_clock,
                policy: b"early GET v1",
                lifetime_seconds: 60,
                max_age_skew_ms: 10_000,
            },
            admission,
        )
        .unwrap();
        pump(&mut client, &mut server);
        assert!(client.is_resumed() && server.is_resumed());
        assert_eq!(
            client.early_status(),
            if accept {
                EarlyStatus::Accepted
            } else {
                EarlyStatus::Rejected
            }
        );
        assert_eq!(server.early_status(), client.early_status());
        assert_eq!(server.take_early_replay_claim().is_some(), accept);
    }
}
