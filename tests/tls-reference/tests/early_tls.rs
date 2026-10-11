//! Protected0RTT TLS-provider evidence. This does not qualify QUIC wire routing,
//! congestion/rollback or the external runner; those are engine/host gates.
#[path = "../../support/async_tls_fixture.rs"]
mod async_fixture;
use hibana_quic::quic::early_data::EarlyFreshness;
use hibana_quic::quic::early_data::EarlyStatus;
use hibana_quic::quic::early_data::QuarantineSlot;
use hibana_quic::quic::early_data::ReplayStorage;
use hibana_quic::quic::early_data::ServerPolicy;
use hibana_quic_pal::unix::entropy::KernelEntropy;
use hibana_tls::certificate::CertificateDer;
use hibana_tls::certificate::Limits;
use hibana_tls::certificate::TrustAnchor;
use hibana_tls::certificate::UnixTime;
use hibana_tls::certificate::trust_anchor_from_der;
use hibana_tls::handshake::BoundedTls;
use hibana_tls::handshake::CipherPolicy;
use hibana_tls::handshake::ClientConfig;
use hibana_tls::handshake::ClientEarlyData;
use hibana_tls::handshake::ClientResumption;
use hibana_tls::handshake::ServerConfig;
use hibana_tls::handshake::ServerEarlyData;
use hibana_tls::handshake::ServerResumption;
use hibana_tls::handshake::SigningKey;
use hibana_tls::handshake::Storage;
use hibana_tls::quic::Level;
use hibana_tls::quic::Provider;
use hibana_tls::ticket;
use hibana_tls::ticket::Binding;
use hibana_tls::ticket::ClientCache;
use hibana_tls::ticket::ClientOffer;
use hibana_tls::ticket::ClientSlot;
use hibana_tls::ticket::ReplayPolicy;
use hibana_tls::ticket::TicketKey;
use hibana_tls::ticket::VerificationContext;
#[allow(dead_code)]
#[path = "../../support/tls_actor_fixture.rs"]
mod public_identity;
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
    root: Vec<u8>,
    leaf: Vec<u8>,
    signing: SigningKey,
}
fn identity() -> Identity {
    // Independently generated, public deterministic test credentials. These
    // tests exercise ticket ownership, not a runtime certificate generator.
    Identity {
        root: public_identity::ROOT_DER.to_vec(),
        leaf: public_identity::LEAF_DER.to_vec(),
        signing: public_identity::signing_key(),
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
fn pump(client: &mut BoundedTls<'_, '_>, server: &mut BoundedTls<'_, '_>) {
    async_fixture::handshake_with(client, server, 127, true);
    async_fixture::drain_authenticated_tickets(server, client, 127);
}
fn client_config<'a>(anchors: &'a [TrustAnchor<'a>]) -> ClientConfig<'a> {
    ClientConfig {
        protocol: Default::default(),
        version: hibana_quic::quic::version::Version::V1,
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
    let mut entropy = KernelEntropy;
    let slots = [QuarantineSlot::<1024>::EMPTY, QuarantineSlot::EMPTY];
    let admission = ServerEarlyData::buffered::<1024>(
        1,
        EARLY_POLICY,
        SERVER_PARAMS,
        slots.len(),
        EarlyFreshness::new(1000).unwrap(),
    )
    .unwrap();
    let mut client = BoundedTls::client_with_tickets_and_policy(
        client_config(anchors),
        cb.storage(),
        &mut KernelEntropy,
        ClientResumption {
            store: cache,
            clock,
        },
        cipher,
    )
    .unwrap();
    let mut server = BoundedTls::server_with_early_data_and_policy(
        ServerConfig {
            protocol: Default::default(),
            version: hibana_quic::quic::version::Version::V1,
            certificate_chain: &chain,
            signing_key: &id.signing,
            transport_parameters: SERVER_PARAMS,
        },
        sb.storage(),
        &mut KernelEntropy,
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
            &Binding::new("localhost", b"hibana/1", &[]).unwrap(),
            suite,
            VerificationContext::new(anchors, Limits::default()).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert!(offer.remembered_early_limits().is_some());
    offer
}
#[test]
fn real_early_packet_keys_and_projected_finished_release_allocate_zero_both_suites() {
    for (cipher, suite) in [
        (CipherPolicy::Aes128Only, 0x1301),
        (CipherPolicy::ChaCha20Only, 0x1303),
    ] {
        let id = identity();
        let anchors = [trust_anchor_from_der(&CertificateDer::from(id.root.as_slice())).unwrap()];
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
                &mut KernelEntropy,
                ReplayPolicy::ReusableOneRtt,
                &mut ordinary,
                &mut replay,
            )
            .unwrap();
            issue_ticket(&id, &anchors, &mut key, &mut cache, &clock, cipher);
            let cached = offer(&mut cache, &anchors, suite);
            let client = BoundedTls::client_resuming_early_with_policy(
                client_config(&anchors),
                cb.storage(),
                &mut KernelEntropy,
                ClientResumption {
                    store: &mut cache,
                    clock: &clock,
                },
                cached,
                ClientEarlyData::replay_safe_requests(2),
                cipher,
            )
            .unwrap();
            let mut entropy = KernelEntropy;
            let admission = ServerEarlyData::buffered::<1024>(
                2,
                EARLY_POLICY,
                SERVER_PARAMS,
                held.len(),
                EarlyFreshness::new(1000).unwrap(),
            )
            .unwrap();
            let server = BoundedTls::server_with_early_data_and_policy(
                ServerConfig {
                    protocol: Default::default(),
                    version: hibana_quic::quic::version::Version::V1,
                    certificate_chain: &chain,
                    signing_key: &id.signing,
                    transport_parameters: SERVER_PARAMS,
                },
                sb.storage(),
                &mut KernelEntropy,
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

            let mut client_scope = hibana_quic::crypto::directional::ApplicationKeyScope::new(2300);
            let mut server_scope = hibana_quic::crypto::directional::ApplicationKeyScope::new(2301);
            let mut installation = client_scope.claim().unwrap();
            let mut recovery = hibana_quic::quic::recovery::Recovery::<256>::new(
                installation.take_recovery().unwrap(),
                hibana_quic::quic::Side::Client,
                333_000,
                1200,
                3,
            )
            .unwrap();
            let (mut book, _, _, _, mut retirement) = recovery.split().unwrap();
            let mut client = client.into_key_source(installation).unwrap();
            let mut server = server
                .into_key_source(server_scope.claim().unwrap())
                .unwrap();
            let request = b"GET /early\r\n";
            let mut late = [0; 256];
            let mut late_n = 0;
            let mut plaintext = [0; 64];
            let mut observed = false;
            let (mut cm, mut sm) = async_fixture::handshake_key_sources_observe(
                &mut client,
                &mut server,
                |client, server| {
                    if observed || server.early_status() != EarlyStatus::AcceptedPendingFinished {
                        return;
                    }
                    observed = true;
                    let hibana_tls::handshake::keys::EarlyKeyMaterial::Transmit(mut tx) =
                        client.take_early_key().unwrap()
                    else {
                        panic!("client early key must transmit")
                    };
                    let plain_n = hibana_quic::quic::packet::encode_frame(
                        &hibana_quic::quic::packet::Frame::Stream {
                            id: 0,
                            offset: 0,
                            fin: true,
                            data: request,
                        },
                        &mut plaintext,
                    )
                    .unwrap();
                    let size = hibana_quic::quic::early_wire::encoded_len(
                        b"server01",
                        b"client01",
                        plain_n,
                    )
                    .unwrap();
                    let reservation = book
                        .reserve_early(&tx, &plaintext[..plain_n], size as u64, 0)
                        .unwrap();
                    let sealed = hibana_quic::quic::early_wire::seal::<256>(
                        &mut tx,
                        reservation,
                        b"server01",
                        b"client01",
                        &plaintext[..plain_n],
                    )
                    .unwrap_or_else(|(error, _)| panic!("early seal: {error:?}"));
                    late_n = sealed.bytes().len();
                    late[..late_n].copy_from_slice(sealed.bytes());
                    // Packet-protection fixture only: no UDP acceptance is claimed.
                    book.cancel(sealed.into_reservation()).unwrap();
                    // The actual early transmitter is retired after its finite input.
                    tx.discard();
                },
            );
            assert!(observed);
            let client_finished = cm.finished.take().unwrap().into_receipt();
            assert!(client_finished.resumed());
            assert_eq!(client.early_status(), EarlyStatus::Accepted);
            assert_eq!(server.early_status(), EarlyStatus::Accepted);
            let admission = server.take_early_admission().unwrap();
            assert!(server.take_early_replay_claim().is_none());
            let finished = sm.finished.take().unwrap().into_receipt();
            assert!(finished.resumed());
            let mut budget = server.take_integrity_budget().unwrap();
            let hibana_tls::handshake::keys::EarlyKeyMaterial::Receive(mut key) =
                server.take_early_key().unwrap()
            else {
                panic!("server early key must receive")
            };
            let mut bad = late;
            bad[late_n - 1] ^= 1;
            assert!(
                hibana_quic::quic::early_wire::open::<256>(
                    &key,
                    &mut budget,
                    &bad[..late_n],
                    b"server01",
                    None
                )
                .is_err()
            );
            assert!(
                hibana_quic::quic::early_wire::open::<256>(
                    &key,
                    &mut budget,
                    &late[..late_n],
                    b"wrongcid",
                    None
                )
                .is_err()
            );
            let mut opened = hibana_quic::quic::early_wire::open::<256>(
                &key,
                &mut budget,
                &late[..late_n],
                b"server01",
                None,
            )
            .unwrap();
            let authenticated = opened.take_receipt().unwrap();
            assert!(opened.take_receipt().is_none());
            let input =
                hibana_quic::quic::early_data::AuthenticatedInput::<64>::from_authentication(
                    authenticated,
                    2,
                    opened.plaintext(),
                    None,
                )
                .unwrap();
            projected_early_release(admission, finished, input, &mut held, request);
            key.discard();
            assert!(
                hibana_quic::quic::early_wire::open::<256>(
                    &key,
                    &mut budget,
                    &late[..late_n],
                    b"server01",
                    None
                )
                .is_err()
            );
            retirement.disarm();
        });
    }
}
#[test]
fn explicit_server_decline_keeps_real_one_rtt_resumption() {
    let id = identity();
    let anchors = [trust_anchor_from_der(&CertificateDer::from(id.root.as_slice())).unwrap()];
    let chain = [id.leaf.as_ref()];
    let clock = Clock(Cell::new(1000));
    let mut ordinary = [];
    let mut replay = ReplayStorage::<1>::new();
    let mut cache_slots = [ClientSlot::<SIZE>::empty()];
    let mut cache = ClientCache::new(&mut cache_slots);
    let mut key = TicketKey::generate_with_early_replay(
        &mut KernelEntropy,
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
    let mut entropy = KernelEntropy;
    let mut client = BoundedTls::client_resuming_early(
        client_config(&anchors),
        cb.storage(),
        &mut KernelEntropy,
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
            protocol: Default::default(),
            version: hibana_quic::quic::version::Version::V1,
            certificate_chain: &chain,
            signing_key: &id.signing,
            transport_parameters: SERVER_PARAMS,
        },
        sb.storage(),
        &mut KernelEntropy,
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
    let anchors = [trust_anchor_from_der(&CertificateDer::from(id.root.as_slice())).unwrap()];
    let chain = [id.leaf.as_ref()];
    let clock = Clock(Cell::new(1000));
    let mut ordinary = [];
    let mut replay = ReplayStorage::<1>::new();
    let mut cache_slots = [ClientSlot::<SIZE>::empty()];
    let mut cache = ClientCache::new(&mut cache_slots);
    let mut key = TicketKey::generate_with_early_replay(
        &mut KernelEntropy,
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
        &mut KernelEntropy,
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
        let mut entropy = KernelEntropy;
        let admission = ServerEarlyData::buffered::<1024>(
            generation,
            EARLY_POLICY,
            SERVER_PARAMS,
            held.len(),
            EarlyFreshness::new(1000).unwrap(),
        )
        .unwrap();
        let mut server = BoundedTls::server_with_early_data(
            ServerConfig {
                protocol: Default::default(),
                version: hibana_quic::quic::version::Version::V1,
                certificate_chain: &chain,
                signing_key: &id.signing,
                transport_parameters: SERVER_PARAMS,
            },
            buffers.storage(),
            &mut KernelEntropy,
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
        async_fixture::probe_server_message(&mut server, &hello[..out.len], |server| {
            if !server.has_keys(Level::Handshake) {
                return None;
            }
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
            Some(())
        })
        .unwrap();
        assert!(
            server.last_failure().is_some(),
            "dropping the unfinished async owner fails closed"
        );
        assert!(!server.has_early_keys());
    }
}

#[test]
fn broad_one_rtt_tolerance_cannot_silently_authorize_stale_early_data() {
    for (delay, accept) in [(999, true), (1000, true), (1001, false)] {
        let id = identity();
        let anchors = [trust_anchor_from_der(&CertificateDer::from(id.root.as_slice())).unwrap()];
        let chain = [id.leaf.as_ref()];
        let client_clock = Clock(Cell::new(1000));
        let server_clock = Clock(Cell::new(1000 + delay));
        let mut ordinary = [];
        let mut replay = ReplayStorage::<2>::new();
        let mut cache_slots = [ClientSlot::<SIZE>::empty()];
        let mut cache = ClientCache::new(&mut cache_slots);
        let mut key = TicketKey::generate_with_early_replay(
            &mut KernelEntropy,
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
        let mut entropy = KernelEntropy;
        let mut client = BoundedTls::client_resuming_early(
            client_config(&anchors),
            cb.storage(),
            &mut KernelEntropy,
            ClientResumption {
                store: &mut cache,
                clock: &client_clock,
            },
            cached,
            ClientEarlyData::replay_safe_requests(2),
        )
        .unwrap();
        let admission = ServerEarlyData::buffered::<1024>(
            2,
            EARLY_POLICY,
            SERVER_PARAMS,
            held.len(),
            EarlyFreshness::new(1000).unwrap(),
        )
        .unwrap();
        let mut server = BoundedTls::server_with_early_data(
            ServerConfig {
                protocol: Default::default(),
                version: hibana_quic::quic::version::Version::V1,
                certificate_chain: &chain,
                signing_key: &id.signing,
                transport_parameters: SERVER_PARAMS,
            },
            sb.storage(),
            &mut KernelEntropy,
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

fn projected_early_release<'scope>(
    admission: hibana_quic::quic::early_data::Admission<'scope>,
    finished: hibana_tls::handshake::keys::FinishedAuthenticated<'scope>,
    input: hibana_quic::quic::early_data::AuthenticatedInput<'scope, 64>,
    slots: &mut [QuarantineSlot<1024>],
    expected: &[u8],
) {
    use core::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };
    use hibana::runtime::{
        SessionKitStorage,
        ids::SessionId,
        program::{RoleProgram, project},
    };
    use hibana_quic::quic::early_data::global as p;
    use hibana_quic::quic::early_data::localside;
    use hibana_quic::runtime::TaskSet;
    use hibana_quic::runtime::carrier::CarrierStorage;
    let global = p::choreography();
    let ip: RoleProgram<{ p::INPUT }> = project(&global);
    let op: RoleProgram<{ p::OWNER }> = project(&global);
    let tp: RoleProgram<{ p::TLS }> = project(&global);
    let ap: RoleProgram<{ p::APPLICATION }> = project(&global);
    let carrier = CarrierStorage::<1, 16, 16>::new();
    let mut slab = [0; 65536];
    let mut kit = SessionKitStorage::uninit();
    let sid = SessionId::new(2300);
    let rv = kit
        .init()
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    let mut source = rv.enter(sid, &ip).unwrap();
    let mut owner_ep = rv.enter(sid, &op).unwrap();
    let mut tls = rv.enter(sid, &tp).unwrap();
    let mut app = rv.enter(sid, &ap).unwrap();
    let exchange = hibana_quic::quic::early_data::Exchange::<64>::new();
    let generation = admission.generation();
    let packet_number = input.packet_number();
    {
        let mut input_task = pin!(async {
            exchange.store_input(input)?;
            source.send::<p::Packet>(&packet_number).await?;
            assert_eq!(
                source.offer().await?.recv::<p::PacketStored>().await?,
                packet_number
            );
            assert_eq!(exchange.take_stored()?.packet_number(), packet_number);
            source.send::<p::InputEnd>(&generation).await?;
            assert_eq!(source.recv::<p::InputEnded>().await?, generation);
            source.send::<p::InputRetired>(&generation).await?;
            Ok::<_, hibana_quic::quic::early_data::Failure>(())
        });
        let mut owner_task = pin!(localside::run(
            &mut owner_ep,
            admission,
            EARLY_POLICY,
            slots,
            &exchange
        ));
        let mut tls_task = pin!(async {
            assert_eq!(tls.recv::<p::InputRetired>().await?, generation);
            exchange.store_finished(finished)?;
            tls.send::<p::Verified>(&generation).await?;
            assert_eq!(tls.recv::<p::VerifiedTaken>().await?, generation);
            assert_eq!(tls.recv::<p::Retired>().await?, generation);
            Ok::<_, hibana_quic::quic::early_data::Failure>(())
        });
        let mut app_task = pin!(async {
            assert_eq!(app.offer().await?.recv::<p::Range>().await?, 0);
            let range = exchange.take_range()?;
            assert_eq!(range.bytes(), expected);
            assert_eq!((range.id, range.offset, range.fin), (0, 0, true));
            drop(range);
            app.send::<p::RangeApplied>(&0).await?;
            assert_eq!(app.offer().await?.recv::<p::Released>().await?, generation);
            app.send::<p::ReleaseSeen>(&generation).await?;
            Ok::<_, hibana_quic::quic::early_data::Failure>(())
        });
        let mut all = pin!(TaskSet::new([
            input_task.as_mut(),
            owner_task.as_mut(),
            tls_task.as_mut(),
            app_task.as_mut()
        ]));
        let mut result = None;
        for _ in 0..200 {
            if let Poll::Ready(value) = all.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
                result = Some(value);
                break;
            }
        }
        result
            .expect("projected early transfer must settle")
            .unwrap();
    }
    let returned = exchange.take_finished().unwrap();
    assert_eq!(returned.early_generation(), Some(generation));
}
