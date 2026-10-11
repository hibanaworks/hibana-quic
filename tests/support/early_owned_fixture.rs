#![allow(dead_code)]
//! Genuine ticket/binder/ECDHE/Finished inputs for isolated early-owner tests.
//! Test credentials are public; no production receipt constructor is exposed.
use crate::{scoped_tls_fixture as driver, tls_fixture as fixture};
use hibana_quic::crypto::directional::ApplicationKeyScope;
use hibana_quic::quic::early_data::EarlyFreshness;
use hibana_quic::quic::early_data::EarlyStatus;
use hibana_quic::quic::early_data::ReplayStorage;
use hibana_quic::quic::early_data::ServerPolicy;
use hibana_quic::quic::version::Version;
use hibana_tls::certificate::CertificateDer;
use hibana_tls::certificate::Limits;
use hibana_tls::certificate::trust_anchor_from_der;
use hibana_tls::handshake::BoundedTls;
use hibana_tls::handshake::CipherPolicy;
use hibana_tls::handshake::ClientConfig;
use hibana_tls::handshake::ClientEarlyData;
use hibana_tls::handshake::ClientResumption;
use hibana_tls::handshake::ServerConfig;
use hibana_tls::handshake::ServerEarlyData;
use hibana_tls::handshake::ServerResumption;
use hibana_tls::handshake::keys::Admission;
use hibana_tls::handshake::keys::FinishedAuthenticated;
use hibana_tls::ticket;
use hibana_tls::ticket::Binding;
use hibana_tls::ticket::ClientCache;
use hibana_tls::ticket::ClientSlot;
use hibana_tls::ticket::ReplayPolicy;
use hibana_tls::ticket::TicketKey;
use hibana_tls::ticket::VerificationContext;
struct Clock;
impl ticket::TicketClock for Clock {
    fn now_ms(&self) -> Result<u64, ticket::Error> {
        Ok(1000)
    }
}
pub fn admission_and_finished<'scope>(
    scope: &'scope mut ApplicationKeyScope,
    generation: u64,
    params: &[u8],
    policy: ServerPolicy,
    replay: &mut ReplayStorage<4>,
) -> (
    Admission<'scope>,
    FinishedAuthenticated<'scope>,
    [u8; 16],
    [u8; 12],
) {
    let root = CertificateDer::from(fixture::ROOT_DER);
    let anchors = [trust_anchor_from_der(&root).unwrap()];
    let chain = [fixture::LEAF_DER];
    let signing = fixture::signing_key();
    let clock = Clock;
    let mut cb = fixture::Buffers::new();
    let mut sb = fixture::Buffers::new();
    let mut entropy = fixture::TestRandom(443);
    let mut ordinary = [];
    let mut slots = [ClientSlot::<4096>::empty()];
    let mut cache = ClientCache::new(&mut slots);
    let mut key = TicketKey::generate_with_early_replay(
        &mut entropy,
        ReplayPolicy::ReusableOneRtt,
        &mut ordinary,
        replay,
    )
    .unwrap();
    let client_config = || ClientConfig {
        protocol: Default::default(),
        version: Version::V1,
        server_name: "localhost",
        trust_anchors: &anchors,
        now: fixture::now(),
        certificate_limits: Limits::default(),
        transport_parameters: fixture::CLIENT_PARAMS,
    };
    let server_config = || ServerConfig {
        protocol: Default::default(),
        version: Version::V1,
        certificate_chain: &chain,
        signing_key: &signing,
        transport_parameters: params,
    };
    let configured = ServerEarlyData::buffered::<8>(
        generation,
        policy,
        params,
        1,
        EarlyFreshness::new(1000).unwrap(),
    )
    .unwrap();
    {
        let mut client = BoundedTls::client_with_tickets_and_policy(
            client_config(),
            cb.storage(),
            &mut fixture::TestRandom(500),
            ClientResumption {
                store: &mut cache,
                clock: &clock,
            },
            CipherPolicy::Aes128Only,
        )
        .unwrap();
        let mut server = BoundedTls::server_with_early_data_and_policy(
            server_config(),
            sb.storage(),
            &mut fixture::TestRandom(600),
            ServerResumption {
                store: &mut key,
                entropy: &mut entropy,
                clock: &clock,
                policy: b"early-owner",
                lifetime_seconds: 60,
                max_age_skew_ms: 1000,
            },
            configured,
            CipherPolicy::Aes128Only,
        )
        .unwrap();
        driver::handshake_with(&mut client, &mut server, 127, true);
        assert!(driver::drain_authenticated_tickets(&mut server, &mut client, 4096) > 0);
    }
    let cached = cache
        .take_verified_for_origin(
            1000,
            &Binding::new("localhost", hibana_tls::Protocol::default().alpn(), &[]).unwrap(),
            0x1301,
            VerificationContext::new(&anchors, Limits::default()).unwrap(),
        )
        .unwrap()
        .unwrap();
    let issuer: [u8; 16] = cached.identity()[1..17].try_into().unwrap();
    let nonce: [u8; 12] = cached.identity()[17..29].try_into().unwrap();
    let mut client_scope = ApplicationKeyScope::new(9011);
    let client = BoundedTls::client_resuming_early_with_policy(
        client_config(),
        cb.storage(),
        &mut fixture::TestRandom(700),
        ClientResumption {
            store: &mut cache,
            clock: &clock,
        },
        cached,
        ClientEarlyData::replay_safe_requests(generation),
        CipherPolicy::Aes128Only,
    )
    .unwrap();
    let server = BoundedTls::server_with_early_data_and_policy(
        server_config(),
        sb.storage(),
        &mut fixture::TestRandom(800),
        ServerResumption {
            store: &mut key,
            entropy: &mut entropy,
            clock: &clock,
            policy: b"early-owner",
            lifetime_seconds: 60,
            max_age_skew_ms: 1000,
        },
        configured,
        CipherPolicy::Aes128Only,
    )
    .unwrap();
    let mut client = client
        .into_key_source(client_scope.claim().unwrap())
        .unwrap();
    let mut server = server.into_key_source(scope.claim().unwrap()).unwrap();
    let (_, mut material) =
        driver::handshake_key_sources_observe(&mut client, &mut server, |_, _| {});
    assert_eq!(server.early_status(), EarlyStatus::Accepted);
    let admission = server.take_early_admission().unwrap();
    let finished = material.finished.take().unwrap().into_receipt();
    assert_eq!(admission.generation(), generation);
    assert_eq!(finished.early_generation(), Some(generation));
    (admission, finished, issuer, nonce)
}
