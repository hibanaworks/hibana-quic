#[path = "../../tests/support/async_tls_fixture.rs"]
mod async_fixture;
// Real two-connection PSK_DHE resumption. Fixture setup is host-only; measured
// constructors, encrypted TLS flights, issuance, cache and resumption allocate zero.
use hibana_quic::{
    tls::certificate::{CertificateDer, Limits, TrustAnchor, UnixTime, trust_anchor_from_der},
    tls::handshake::{BoundedTls, ClientConfig, ServerConfig, SigningKey, State, Storage},
    tls::{self, Level, Provider},
};
use hibana_quic::{
    tls::handshake::{ClientResumption, Failure, ServerResumption},
    tls::ticket::{
        self as ticket, Binding, ClientCache, ClientOffer, ClientSlot, ReplayPolicy, ReplaySlot,
        TicketKey, VerificationContext,
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
const SERVER_PARAMS: &[u8] = &[0, 0, 15, 0, 4, 1, 63];
struct Clock(Cell<u64>);
impl ticket::TicketClock for Clock {
    fn now_ms(&self) -> Result<u64, ticket::Error> {
        Ok(self.0.get())
    }
}
const SIZE: usize = 4096;
struct Outcome {
    resumed: bool,
    mask: [u8; 5],
    certificate_messages: usize,
    tickets: usize,
}
#[allow(clippy::too_many_arguments)]
fn connect(
    id: &Identity,
    anchors: &[TrustAnchor<'_>],
    cache: &mut ClientCache<'_, SIZE>,
    key: &mut TicketKey<'_>,
    clock: &Clock,
    offer: Option<ClientOffer<SIZE>>,
    policy: &[u8],
    params: &[u8],
    fragment: usize,
) -> Outcome {
    connect_clocks(
        id, anchors, cache, key, clock, clock, offer, policy, params, fragment,
    )
}
#[allow(clippy::too_many_arguments)]
fn connect_clocks(
    id: &Identity,
    anchors: &[TrustAnchor<'_>],
    cache: &mut ClientCache<'_, SIZE>,
    key: &mut TicketKey<'_>,
    clock: &Clock,
    server_clock: &Clock,
    offer: Option<ClientOffer<SIZE>>,
    policy: &[u8],
    params: &[u8],
    fragment: usize,
) -> Outcome {
    connect_clocks_with_cipher(
        id,
        anchors,
        cache,
        key,
        clock,
        server_clock,
        offer,
        policy,
        params,
        fragment,
        hibana_quic::tls::handshake::CipherPolicy::Default,
    )
}
#[allow(clippy::too_many_arguments)]
fn connect_clocks_with_cipher(
    id: &Identity,
    anchors: &[TrustAnchor<'_>],
    cache: &mut ClientCache<'_, SIZE>,
    key: &mut TicketKey<'_>,
    clock: &Clock,
    server_clock: &Clock,
    offer: Option<ClientOffer<SIZE>>,
    policy: &[u8],
    params: &[u8],
    fragment: usize,
    cipher: hibana_quic::tls::handshake::CipherPolicy,
) -> Outcome {
    let mut cb = Buffers::new();
    let mut sb = Buffers::new();
    let chain = [id.leaf.as_ref()];
    let mut rng = OsRng;
    let mut entropy = OsRng;
    let cfg = ClientConfig {
        protocol: Default::default(),
        version: hibana_quic::version::Version::V1,
        server_name: "localhost",
        trust_anchors: anchors,
        now: now(),
        certificate_limits: Limits::default(),
        transport_parameters: CLIENT_PARAMS,
    };
    let session = ClientResumption {
        store: cache,
        clock,
    };
    let mut client = match offer {
        Some(offer) => BoundedTls::client_resuming_with_policy(
            cfg,
            cb.storage(),
            &mut rng,
            session,
            offer,
            cipher,
        ),
        None => {
            BoundedTls::client_with_tickets_and_policy(cfg, cb.storage(), &mut rng, session, cipher)
        }
    }
    .unwrap();
    let mut server = BoundedTls::server_with_tickets_and_policy(
        ServerConfig {
            protocol: Default::default(),
            version: hibana_quic::version::Version::V1,
            certificate_chain: &chain,
            signing_key: &id.signing,
            transport_parameters: params,
        },
        sb.storage(),
        &mut rng,
        ServerResumption {
            store: key,
            entropy: &mut entropy,
            clock: server_clock,
            policy,
            lifetime_seconds: 60,
            max_age_skew_ms: 1000,
        },
        cipher,
    )
    .unwrap();
    let cp = [0; 3];
    let certs = async_fixture::handshake_with(&mut client, &mut server, fragment, true);
    let tickets = async_fixture::drain_authenticated_tickets(&mut server, &mut client, fragment);
    assert_eq!(client.state(), State::Connected);
    assert_eq!(server.state(), State::Connected);
    assert_eq!(client.is_resumed(), server.is_resumed());
    let mut packet = [0; 30];
    packet[..14].copy_from_slice(b"resumed secret");
    assert_eq!(
        client.seal(Level::OneRtt, cp[2], b"app", &mut packet, 14),
        Ok(30)
    );
    assert_eq!(
        server.open(Level::OneRtt, cp[2], b"app", &mut packet),
        Ok(14)
    );
    assert_eq!(&packet[..14], b"resumed secret");
    Outcome {
        resumed: client.is_resumed(),
        mask: client.header_mask(Level::OneRtt, true, &[0; 16]).unwrap(),
        certificate_messages: certs,
        tickets,
    }
}
fn context(anchors: &[TrustAnchor<'_>]) -> VerificationContext {
    VerificationContext::new(anchors, Limits::default()).unwrap()
}
fn take(
    cache: &mut ClientCache<'_, SIZE>,
    clock: &Clock,
    anchors: &[TrustAnchor<'_>],
) -> ClientOffer<SIZE> {
    cache
        .take_verified_for_origin(
            clock.0.get(),
            &Binding::new("localhost", b"hq-interop", &[]).unwrap(),
            0x1301,
            context(anchors),
        )
        .unwrap()
        .unwrap()
}
#[test]
fn two_connections_fresh_dhe_finished_and_encrypted_nst_allocate_zero() {
    for fragment in [1, 127, 4096] {
        let id = identity();
        let anchors = [trust_anchor_from_der(&id.root).unwrap()];
        let mut slots = [ClientSlot::<SIZE>::empty()];
        let mut replay = [ReplaySlot::empty()];
        let clock = Clock(Cell::new(1000));
        measured(|| {
            let mut cache = ClientCache::new(&mut slots);
            let mut key =
                TicketKey::generate(&mut OsRng, ReplayPolicy::SingleUseOneRtt, &mut replay)
                    .unwrap();
            let first = connect(
                &id,
                &anchors,
                &mut cache,
                &mut key,
                &clock,
                None,
                b"policy",
                SERVER_PARAMS,
                fragment,
            );
            assert!(!first.resumed);
            assert_eq!(cache.len(), 1);
            clock.0.set(1500);
            let offer = take(&mut cache, &clock, &anchors);
            assert!(cache.is_empty());
            let second = connect(
                &id,
                &anchors,
                &mut cache,
                &mut key,
                &clock,
                Some(offer),
                b"policy",
                SERVER_PARAMS,
                fragment,
            );
            assert!(second.resumed);
            assert_ne!(first.mask, second.mask);
            assert_eq!(cache.len(), 1);
            if fragment == 4096 {
                assert!(first.certificate_messages > 0);
                assert_eq!(second.certificate_messages, 0);
                assert_eq!(first.tickets, 1);
                assert_eq!(second.tickets, 1);
            }
        });
    }
}
#[test]
fn changed_server_policy_and_unknown_issuer_fall_back_to_full_authentication() {
    for unknown in [false, true] {
        let id = identity();
        let anchors = [trust_anchor_from_der(&id.root).unwrap()];
        let clock = Clock(Cell::new(1000));
        let mut slots = [ClientSlot::<SIZE>::empty()];
        let mut cache = ClientCache::new(&mut slots);
        let mut replay = [];
        let mut replay2 = [];
        let mut key =
            TicketKey::generate(&mut OsRng, ReplayPolicy::ReusableOneRtt, &mut replay).unwrap();
        connect(
            &id,
            &anchors,
            &mut cache,
            &mut key,
            &clock,
            None,
            b"policy",
            SERVER_PARAMS,
            4096,
        );
        let offer = take(&mut cache, &clock, &anchors);
        let mut key2 =
            TicketKey::generate(&mut OsRng, ReplayPolicy::ReusableOneRtt, &mut replay2).unwrap();
        let result = connect(
            &id,
            &anchors,
            &mut cache,
            if unknown { &mut key2 } else { &mut key },
            &clock,
            Some(offer),
            if unknown { b"policy" } else { b"changed" },
            SERVER_PARAMS,
            4096,
        );
        assert!(!result.resumed);
        assert!(result.certificate_messages > 0);
    }
}
#[test]
fn changed_trust_anchor_or_verification_limits_cannot_reuse_old_offer() {
    for change_root in [true, false] {
        let id = identity();
        let other = identity();
        let anchors = [trust_anchor_from_der(&id.root).unwrap()];
        let other_anchors = [trust_anchor_from_der(&other.root).unwrap()];
        let clock = Clock(Cell::new(1000));
        let mut slots = [ClientSlot::<SIZE>::empty()];
        let mut cache = ClientCache::new(&mut slots);
        let mut replay = [];
        let mut key =
            TicketKey::generate(&mut OsRng, ReplayPolicy::ReusableOneRtt, &mut replay).unwrap();
        connect(
            &id,
            &anchors,
            &mut cache,
            &mut key,
            &clock,
            None,
            b"policy",
            SERVER_PARAMS,
            4096,
        );
        let changed = if change_root {
            &other_anchors
        } else {
            &anchors
        };
        let mut limits = Limits::default();
        if !change_root {
            limits.max_chain_bytes += 1;
        }
        let changed_context = VerificationContext::new(changed, limits).unwrap();
        let origin = Binding::new("localhost", b"hq-interop", &[]).unwrap();
        assert!(
            cache
                .take_verified_for_origin(1000, &origin, 0x1301, changed_context)
                .unwrap()
                .is_none()
        );
        // Even the old generic lookup cannot bypass the constructor check.
        let offer = cache
            .take_for_origin(1000, &origin, 0x1301)
            .unwrap()
            .unwrap();
        let mut buffers = Buffers::new();
        let result = BoundedTls::client_resuming(
            ClientConfig {
                protocol: Default::default(),
                version: hibana_quic::version::Version::V1,
                server_name: "localhost",
                trust_anchors: changed,
                now: now(),
                certificate_limits: limits,
                transport_parameters: CLIENT_PARAMS,
            },
            buffers.storage(),
            &mut OsRng,
            ClientResumption {
                store: &mut cache,
                clock: &clock,
            },
            offer,
        );
        assert!(matches!(
            result,
            Err(Failure::Ticket(ticket::Error::VerificationContext))
        ));
    }
}
#[test]
fn known_ticket_invalid_binder_is_fatal_and_never_selects_application_keys() {
    let id = identity();
    let anchors = [trust_anchor_from_der(&id.root).unwrap()];
    let clock = Clock(Cell::new(1000));
    let chain = [id.leaf.as_ref()];
    let mut slots = [ClientSlot::<SIZE>::empty()];
    let mut cache = ClientCache::new(&mut slots);
    let mut replay = [];
    let mut key =
        TicketKey::generate(&mut OsRng, ReplayPolicy::ReusableOneRtt, &mut replay).unwrap();
    connect(
        &id,
        &anchors,
        &mut cache,
        &mut key,
        &clock,
        None,
        b"policy",
        SERVER_PARAMS,
        4096,
    );
    let offer = take(&mut cache, &clock, &anchors);
    let mut cb = Buffers::new();
    let mut sb = Buffers::new();
    let mut entropy = OsRng;
    let mut client = BoundedTls::client_resuming(
        ClientConfig {
            protocol: Default::default(),
            version: hibana_quic::version::Version::V1,
            server_name: "localhost",
            trust_anchors: &anchors,
            now: now(),
            certificate_limits: Limits::default(),
            transport_parameters: CLIENT_PARAMS,
        },
        cb.storage(),
        &mut OsRng,
        ClientResumption {
            store: &mut cache,
            clock: &clock,
        },
        offer,
    )
    .unwrap();
    let mut server = BoundedTls::server_with_tickets(
        ServerConfig {
            protocol: Default::default(),
            version: hibana_quic::version::Version::V1,
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
            policy: b"policy",
            lifetime_seconds: 60,
            max_age_skew_ms: 1000,
        },
    )
    .unwrap();
    let mut hello = [0; 4096];
    let out = client.transmit(&mut hello).unwrap().unwrap();
    let psk = hibana_quic::tls::wire::parse_client_hello_psk(&hello[..out.len])
        .unwrap()
        .psk
        .unwrap();
    let offset = psk.binder_offset;
    hello[offset] ^= 1;
    let error = async_fixture::reject_server_message(&mut server, &hello[..out.len]);
    assert!(matches!(
        error,
        hibana_quic::tls::handshake::local::Error::Crypto(Failure::Ticket(ticket::Error::Binder))
    ));
    assert_eq!(server.state(), State::Failed);
    assert!(!server.has_keys(Level::OneRtt));
    assert!(!server.has_keys(Level::Handshake));
}

#[test]
fn expired_server_ticket_falls_back_and_bounded_full_cache_discards_new_ticket() {
    let id = identity();
    let anchors = [trust_anchor_from_der(&id.root).unwrap()];
    let clock = Clock(Cell::new(1000));
    let server_clock = Clock(Cell::new(1000));
    let mut slots = [ClientSlot::<SIZE>::empty()];
    let mut cache = ClientCache::new(&mut slots);
    let mut replay = [];
    let mut key =
        TicketKey::generate(&mut OsRng, ReplayPolicy::ReusableOneRtt, &mut replay).unwrap();
    connect(
        &id,
        &anchors,
        &mut cache,
        &mut key,
        &clock,
        None,
        b"policy",
        SERVER_PARAMS,
        4096,
    );
    // A second full connection receives another valid NST while this slot is
    // live. Cache pressure cannot turn successful authentication into failure.
    connect(
        &id,
        &anchors,
        &mut cache,
        &mut key,
        &clock,
        None,
        b"policy",
        SERVER_PARAMS,
        4096,
    );
    assert_eq!(cache.len(), 1);
    let offer = take(&mut cache, &clock, &anchors);
    server_clock.0.set(61000);
    let result = connect_clocks(
        &id,
        &anchors,
        &mut cache,
        &mut key,
        &clock,
        &server_clock,
        Some(offer),
        b"policy",
        SERVER_PARAMS,
        4096,
    );
    assert!(!result.resumed);
    assert!(result.certificate_messages > 0);
}

#[test]
fn transport_binding_is_canonical_excludes_cids_and_rejects_changed_limits() {
    for (params, resumed) in [
        (&[0, 1, 1, 15, 1, 2, 4, 1, 63][..], true),
        (&[4, 2, 0x40, 63, 15, 0, 0, 0][..], true),
        (&[0, 0, 15, 0, 4, 2, 0x40, 0x40][..], false),
    ] {
        let id = identity();
        let anchors = [trust_anchor_from_der(&id.root).unwrap()];
        let clock = Clock(Cell::new(1000));
        let mut slots = [ClientSlot::<SIZE>::empty()];
        let mut cache = ClientCache::new(&mut slots);
        let mut replay = [];
        let mut key =
            TicketKey::generate(&mut OsRng, ReplayPolicy::ReusableOneRtt, &mut replay).unwrap();
        connect(
            &id,
            &anchors,
            &mut cache,
            &mut key,
            &clock,
            None,
            b"policy",
            SERVER_PARAMS,
            4096,
        );
        let offer = take(&mut cache, &clock, &anchors);
        let result = connect(
            &id,
            &anchors,
            &mut cache,
            &mut key,
            &clock,
            Some(offer),
            b"policy",
            params,
            4096,
        );
        assert_eq!(result.resumed, resumed);
    }
}

#[test]
fn strict_chacha_ticket_roundtrip_and_policy_mismatch_before_output() {
    use hibana_quic::tls::handshake::{CipherPolicy, Failure};
    let id = identity();
    let anchors = [trust_anchor_from_der(&id.root).unwrap()];
    let mut slots = [ClientSlot::<SIZE>::empty()];
    let mut replay = [ReplaySlot::empty(), ReplaySlot::empty()];
    let clock = Clock(Cell::new(1000));
    measured(|| {
        let mut cache = ClientCache::new(&mut slots);
        let mut key =
            TicketKey::generate(&mut OsRng, ReplayPolicy::SingleUseOneRtt, &mut replay).unwrap();
        let first = connect_clocks_with_cipher(
            &id,
            &anchors,
            &mut cache,
            &mut key,
            &clock,
            &clock,
            None,
            b"policy",
            SERVER_PARAMS,
            4096,
            CipherPolicy::ChaCha20Only,
        );
        assert!(!first.resumed);
        let origin = Binding::new("localhost", b"hq-interop", &[]).unwrap();
        clock.0.set(1100);
        let offer = cache
            .take_verified_for_origin(clock.0.get(), &origin, 0x1303, context(&anchors))
            .unwrap()
            .unwrap();
        let second = connect_clocks_with_cipher(
            &id,
            &anchors,
            &mut cache,
            &mut key,
            &clock,
            &clock,
            Some(offer),
            b"policy",
            SERVER_PARAMS,
            4096,
            CipherPolicy::ChaCha20Only,
        );
        assert!(second.resumed);
        assert_eq!(second.certificate_messages, 0);
        assert_ne!(first.mask, second.mask);
        let offer = cache
            .take_verified_for_origin(clock.0.get(), &origin, 0x1303, context(&anchors))
            .unwrap()
            .unwrap();
        let mut buffers = Buffers::new();
        let result = BoundedTls::client_resuming_with_policy(
            ClientConfig {
                protocol: Default::default(),
                version: hibana_quic::version::Version::V1,
                server_name: "localhost",
                trust_anchors: &anchors,
                now: now(),
                certificate_limits: Limits::default(),
                transport_parameters: CLIENT_PARAMS,
            },
            buffers.storage(),
            &mut OsRng,
            ClientResumption {
                store: &mut cache,
                clock: &clock,
            },
            offer,
            CipherPolicy::Aes128Only,
        );
        assert!(matches!(result, Err(Failure::UnsupportedSuite)));
    });
}
