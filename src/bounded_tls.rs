//! Allocation-free TLS 1.3 certificate and optional PSK_DHE profile for QUIC v1.
//!
//! Fresh X25519/P-256 ECDHE, server certificate/hostname/CertificateVerify checks,
//! Finished verification, and negotiated traffic keys. Caller-owned input/output,
//! certificate, transport-parameter and optional ticket/cache storage is mandatory.
//! Resumption offers are bound to the actual client trust/verification context;
//! only authenticated OneRtt NST input can populate the provider's ticket cache.
//! Full and resumed handshakes share strict HRR and Finished state transitions.
//! Explicit early constructors additionally require replay/freshness policy,
//! remembered limits and application retry authorization. Ordinary constructors
//! keep 0-RTT disabled. Client authentication is not enabled; this is not a claim
//! of complete mandatory TLS algorithms or QUIC release conformance.

use crate::{
    crypto::{self, ApplicationKeys, CipherSuite, IntegrityBudget, KeyKind, PacketKey},
    early_data::{
        self as early, EarlyFreshness, EarlyStatus, QuarantineSlot, RememberedLimits, ReplayClaim,
        ServerPolicy,
    },
    tls::{self, Level, Output, Provider},
    tls_certificate::{
        self as certificate, CertificateDer, Limits, ServerName, ServerVerifier, TrustAnchor,
        UnixTime,
    },
    tls_schedule::{self as schedule, KeySchedule, Side, Transcript},
    tls_ticket as ticket, tls_wire as wire,
};
use p256::ecdsa::{Signature, signature::Signer};
use p256::{PublicKey, SecretKey, ecdh::diffie_hellman, elliptic_curve::sec1::ToEncodedPoint};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

pub mod key_source;
mod operations;

pub use crate::tls_wire::CipherPolicy;
pub use p256::ecdsa::SigningKey;
pub const ALPN: &[u8] = b"hq-interop";
const MAX_CHAIN: usize = certificate::MAX_INTERMEDIATES + 1;

/// The four buffers must be distinct borrows. RX holds one complete handshake
/// message; TX holds one complete outbound flight; certificate storage holds the
/// peer's encoded Certificate message (and CH1 during retry); parameters hold
/// the peer's raw extension. Server certificate scratch must also fit CH1 for HRR.
pub struct Storage<'a> {
    pub rx_message: &'a mut [u8],
    pub tx_flight: &'a mut [u8],
    pub peer_certificates: &'a mut [u8],
    pub peer_parameters: &'a mut [u8],
}

pub struct ClientConfig<'a> {
    pub server_name: &'a str,
    pub trust_anchors: &'a [TrustAnchor<'a>],
    pub now: UnixTime,
    pub certificate_limits: Limits,
    pub transport_parameters: &'a [u8],
}
pub struct ServerConfig<'a> {
    /// DER leaf first, then intermediate certificates. Do not include private keys.
    pub certificate_chain: &'a [&'a [u8]],
    pub signing_key: &'a SigningKey,
    pub transport_parameters: &'a [u8],
}

enum Mode<'a> {
    Client(ClientConfig<'a>),
    Server(ServerConfig<'a>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    ClientServerHello,
    ClientServerHelloRetry,
    ClientEncryptedExtensions,
    ClientCertificate,
    ClientCertificateVerify,
    ClientFinished,
    ServerClientHello,
    ServerClientHelloRetry,
    ServerClientFinished,
    Connected,
    Failed,
}

#[derive(Debug)]
pub enum Failure {
    InvalidStorage,
    InvalidConfig,
    Entropy,
    State,
    InvalidKeyShare,
    UnsupportedSuite,
    CertificateKeyMismatch,
    Wire(wire::Error),
    Certificate(certificate::Error),
    Schedule(schedule::Error),
    Crypto(crypto::Error),
    Ticket(ticket::Error),
    Parameters(crate::parameters::Error),
    Early(early::Error),
    Capacity,
}
impl From<wire::Error> for Failure {
    fn from(e: wire::Error) -> Self {
        Self::Wire(e)
    }
}
impl From<certificate::Error> for Failure {
    fn from(e: certificate::Error) -> Self {
        Self::Certificate(e)
    }
}
impl From<schedule::Error> for Failure {
    fn from(e: schedule::Error) -> Self {
        Self::Schedule(e)
    }
}
impl From<crypto::Error> for Failure {
    fn from(e: crypto::Error) -> Self {
        Self::Crypto(e)
    }
}

impl From<ticket::Error> for Failure {
    fn from(e: ticket::Error) -> Self {
        Self::Ticket(e)
    }
}

/// Caller-owned cache and trusted millisecond clock, kept across connections.
pub struct ClientResumption<'a> {
    pub store: &'a mut dyn ticket::ClientTicketStore,
    pub clock: &'a dyn ticket::TicketClock,
}
/// Caller-owned authenticated ticket key/replay policy and entropy. The policy
/// bytes must describe stable server configuration not represented by QUIC limits.
pub struct ServerResumption<'a> {
    pub store: &'a mut dyn ticket::ServerTicketStore,
    pub entropy: &'a mut dyn rand_core::CryptoRngCore,
    pub clock: &'a dyn ticket::TicketClock,
    pub policy: &'a [u8],
    pub lifetime_seconds: u32,
    pub max_age_skew_ms: u32,
}
/// Explicit application opt-in. The application promises replay-tolerant
/// requests; this does not imply network exactly-once semantics. This opt-in
/// also authorizes retransmitting those queued complete requests over 1-RTT
/// after early rejection, under the newly authenticated transport limits.
/// Applications that do not authorize that retry must not enable this mode.
#[derive(Clone, Copy)]
pub struct ClientEarlyData {
    generation: u64,
}
impl ClientEarlyData {
    pub const fn replay_safe_requests(generation: u64) -> Self {
        Self { generation }
    }
}
/// Constructor-time proof of the configured receive storage/parameter geometry.
/// The engine must use those same slots/policy and repeat quarantine admission.
#[derive(Clone, Copy)]
pub struct ServerEarlyData {
    generation: u64,
    limits: RememberedLimits,
    freshness: EarlyFreshness,
}
impl ServerEarlyData {
    pub fn buffered<const BYTES: usize>(
        generation: u64,
        policy: ServerPolicy,
        parameters: &[u8],
        slots: &[QuarantineSlot<BYTES>],
        freshness: EarlyFreshness,
    ) -> Result<Self, Failure> {
        let limits = RememberedLimits::from_authenticated_server_parameters(parameters)
            .map_err(Failure::Early)?;
        policy
            .check_capacity::<BYTES>(limits, slots.len())
            .map_err(Failure::Early)?;
        Ok(Self {
            generation,
            limits,
            freshness,
        })
    }
}

enum Resumption<'a> {
    Client(ClientResumption<'a>),
    Server(ServerResumption<'a>),
}

/// Hash stable parsed transport limits, never connection IDs or reset tokens.
/// This remembers a 1-RTT binding only; it does not authorize early data.
fn transport_profile(bytes: &[u8], policy: &[u8]) -> Result<[u8; 32], Failure> {
    use sha2::{Digest, Sha256};
    if policy.len() > ticket::MAX_BINDING_PROFILE_BYTES {
        return Err(Failure::InvalidConfig);
    }
    let params =
        crate::parameters::Parameters::parse(bytes, crate::parameters::Peer::Server, &mut [0; 64])
            .map_err(Failure::Parameters)?;
    let mut h = Sha256::new();
    h.update(b"hibana-quic stable server limits v1");
    for (id, default) in [
        (1, 0),
        (3, 65527),
        (4, 0),
        (5, 0),
        (6, 0),
        (7, 0),
        (8, 0),
        (9, 0),
        (10, 3),
        (11, 25),
        (14, 2),
    ] {
        let value = params
            .get_integer(id, default)
            .map_err(Failure::Parameters)?;
        h.update(id.to_be_bytes());
        h.update(value.to_be_bytes());
    }
    h.update([u8::from(params.get(12).is_some())]);
    h.update((policy.len() as u32).to_be_bytes());
    h.update(policy);
    Ok(h.finalize().into())
}

struct DirectionalKeys {
    local: PacketKey,
    remote: PacketKey,
}

// Mutually exclusive representations: the handoff path never constructs or
// retains the legacy combined application-key machine.
enum ApplicationMaterial {
    Empty,
    Legacy(ApplicationKeys),
    Handoff(DirectionalKeys),
}
impl ApplicationMaterial {
    fn as_ref(&self) -> Option<&ApplicationKeys> {
        match self {
            Self::Legacy(keys) => Some(keys),
            _ => None,
        }
    }
    fn as_mut(&mut self) -> Option<&mut ApplicationKeys> {
        match self {
            Self::Legacy(keys) => Some(keys),
            _ => None,
        }
    }
    fn is_some(&self) -> bool {
        !matches!(self, Self::Empty)
    }
    fn take_handoff(&mut self) -> Option<DirectionalKeys> {
        if !matches!(self, Self::Handoff(_)) {
            return None;
        }
        match core::mem::replace(self, Self::Empty) {
            Self::Handoff(keys) => Some(keys),
            _ => unreachable!(),
        }
    }
}

/// A single-owner TLS provider. No self-references into owned receive storage;
/// peer certificates are represented by bounded offsets and reborrowed for CV.
pub struct BoundedTls<'cfg, 'buf> {
    mode: Mode<'cfg>,
    state: State,
    last_failure: Option<Failure>,
    rx: Option<&'buf mut [u8]>,
    rx_used: usize,
    rx_target: usize,
    rx_level: Option<Level>,
    tx: &'buf mut [u8],
    tx_len: usize,
    tx_sent: usize,
    tx_initial_end: usize,
    tx_post_handshake: bool,
    certificates: &'buf mut [u8],
    cert_ranges: [wire::DerRange; MAX_CHAIN],
    cert_count: usize,
    first_hello_len: usize,
    retry_suite: Option<u16>,
    retry_group: Option<u16>,
    parameters: &'buf mut [u8],
    parameters_len: usize,
    ephemeral: Option<SecretKey>,
    x25519: Option<crate::key_exchange::X25519Secret>,
    x25519_share: [u8; 32],
    allow_x25519: bool,
    negotiated_group: Option<u16>,
    share: [u8; 65],
    random: [u8; 32],
    transcript: Transcript,
    schedule: KeySchedule,
    suite: Option<CipherSuite>,
    cipher_policy: CipherPolicy,
    handshake: Option<DirectionalKeys>,
    application: ApplicationMaterial,
    key_handoff: bool,
    handshake_created: bool,
    application_created: bool,
    handshake_discarded: bool,
    application_discarded: bool,
    integrity: IntegrityBudget,
    resumption: Option<Resumption<'cfg>>,
    resumption_master: Option<schedule::ResumptionMaster>,
    verification_context: Option<ticket::VerificationContext>,
    ticket_binding: Option<ticket::Binding>,
    offer_age: Option<ticket::OfferAge>,
    offer_suite: Option<u16>,
    resumed: bool,
    peer_wants_tickets: bool,
    early_status: EarlyStatus,
    early_generation: Option<u64>,
    early_limits: Option<RememberedLimits>,
    early_server: Option<ServerEarlyData>,
    early_key: Option<PacketKey>,
    early_claim: Option<ReplayClaim>,
}

impl<'cfg, 'buf> BoundedTls<'cfg, 'buf> {
    pub fn client<R: RngCore + CryptoRng>(
        config: ClientConfig<'cfg>,
        storage: Storage<'buf>,
        rng: &mut R,
    ) -> Result<Self, Failure> {
        Self::client_with_policy(config, storage, rng, CipherPolicy::Default)
    }
    /// Construct with an explicit immutable suite policy, enforced before output.
    pub fn client_with_policy<R: RngCore + CryptoRng>(
        config: ClientConfig<'cfg>,
        storage: Storage<'buf>,
        rng: &mut R,
        policy: CipherPolicy,
    ) -> Result<Self, Failure> {
        let name = ServerName::try_from(config.server_name).map_err(|_| Failure::InvalidConfig)?;
        if !matches!(name, ServerName::DnsName(_)) {
            return Err(Failure::InvalidConfig);
        }
        ServerVerifier::new(config.trust_anchors, config.now, config.certificate_limits)?;
        let mut this = Self::new(Mode::Client(config), storage, rng)?;
        this.cipher_policy = policy;
        let Mode::Client(config) = &this.mode else {
            return Err(Failure::State);
        };
        let n = wire::encode_client_hello_dual_with_policy(
            this.tx,
            &this.random,
            &this.share,
            &this.x25519_share,
            config.server_name,
            ALPN,
            config.transport_parameters,
            policy,
        )?;
        if n > this.certificates.len() {
            return Err(Failure::Capacity);
        }
        this.certificates[..n].copy_from_slice(&this.tx[..n]);
        this.first_hello_len = n;
        this.transcript.append(&this.tx[..n])?;
        this.tx_len = n;
        this.tx_initial_end = n;
        Ok(this)
    }

    pub fn client_with_tickets<R: RngCore + CryptoRng>(
        config: ClientConfig<'cfg>,
        storage: Storage<'buf>,
        rng: &mut R,
        resumption: ClientResumption<'cfg>,
    ) -> Result<Self, Failure> {
        Self::client_with_tickets_and_policy(
            config,
            storage,
            rng,
            resumption,
            CipherPolicy::Default,
        )
    }
    /// Construct with an explicit immutable suite policy, enforced before output.
    pub fn client_with_tickets_and_policy<R: RngCore + CryptoRng>(
        config: ClientConfig<'cfg>,
        storage: Storage<'buf>,
        rng: &mut R,
        resumption: ClientResumption<'cfg>,
        policy: CipherPolicy,
    ) -> Result<Self, Failure> {
        let context =
            ticket::VerificationContext::new(config.trust_anchors, config.certificate_limits)?;
        let mut this = Self::client_with_policy(config, storage, rng, policy)?;
        this.verification_context = Some(context);
        this.resumption = Some(Resumption::Client(resumption));
        this.encode_psk_start(None)?;
        Ok(this)
    }
    pub fn client_resuming<R: RngCore + CryptoRng, const BYTES: usize>(
        config: ClientConfig<'cfg>,
        storage: Storage<'buf>,
        rng: &mut R,
        resumption: ClientResumption<'cfg>,
        offer: ticket::ClientOffer<BYTES>,
    ) -> Result<Self, Failure> {
        Self::client_resuming_with_policy(
            config,
            storage,
            rng,
            resumption,
            offer,
            CipherPolicy::Default,
        )
    }
    /// Construct with an explicit immutable suite policy, enforced before output.
    pub fn client_resuming_with_policy<R: RngCore + CryptoRng, const BYTES: usize>(
        config: ClientConfig<'cfg>,
        storage: Storage<'buf>,
        rng: &mut R,
        resumption: ClientResumption<'cfg>,
        mut offer: ticket::ClientOffer<BYTES>,
        policy: CipherPolicy,
    ) -> Result<Self, Failure> {
        let context =
            ticket::VerificationContext::new(config.trust_anchors, config.certificate_limits)?;
        let origin = ticket::Binding::new(config.server_name, ALPN, &[])?;
        // Independently enforce trust/origin even if caller used an unfiltered lookup.
        offer.verify_context(context, &origin)?;
        if !policy.permits(offer.suite()) {
            return Err(Failure::UnsupportedSuite);
        }
        let age = offer.obfuscated_age(resumption.clock.now_ms()?)?;
        let mut this =
            Self::client_with_tickets_and_policy(config, storage, rng, resumption, policy)?;
        this.schedule = offer.schedule()?;
        this.offer_suite = Some(offer.suite());
        this.offer_age = Some(offer.age_state());
        this.encode_psk_start(Some((offer.identity(), age)))?;
        Ok(this)
    }
    pub fn client_resuming_early<R: RngCore + CryptoRng, const BYTES: usize>(
        config: ClientConfig<'cfg>,
        storage: Storage<'buf>,
        rng: &mut R,
        resumption: ClientResumption<'cfg>,
        offer: ticket::ClientOffer<BYTES>,
        early: ClientEarlyData,
    ) -> Result<Self, Failure> {
        Self::client_resuming_early_with_policy(
            config,
            storage,
            rng,
            resumption,
            offer,
            early,
            CipherPolicy::Default,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn client_resuming_early_with_policy<R: RngCore + CryptoRng, const BYTES: usize>(
        config: ClientConfig<'cfg>,
        storage: Storage<'buf>,
        rng: &mut R,
        resumption: ClientResumption<'cfg>,
        mut offer: ticket::ClientOffer<BYTES>,
        early: ClientEarlyData,
        policy: CipherPolicy,
    ) -> Result<Self, Failure> {
        let context =
            ticket::VerificationContext::new(config.trust_anchors, config.certificate_limits)?;
        offer.verify_context(
            context,
            &ticket::Binding::new(config.server_name, ALPN, &[])?,
        )?;
        let limits = offer
            .remembered_early_limits()
            .ok_or(Failure::Ticket(ticket::Error::EarlyDataUnavailable))?;
        if !policy.permits(offer.suite()) {
            return Err(Failure::UnsupportedSuite);
        }
        let age = offer.obfuscated_age(resumption.clock.now_ms()?)?;
        let mut this =
            Self::client_with_tickets_and_policy(config, storage, rng, resumption, policy)?;
        this.schedule = offer.schedule()?;
        this.offer_suite = Some(offer.suite());
        this.offer_age = Some(offer.age_state());
        this.early_generation = Some(early.generation);
        this.early_limits = Some(limits);
        this.early_status = EarlyStatus::Offered;
        this.encode_psk_start(Some((offer.identity(), age)))?;
        let secret = this.schedule.client_early_traffic(&this.transcript)?;
        this.early_key = Some(PacketKey::from_secret(
            suite_from_wire(offer.suite())?,
            KeyKind::ZeroRtt,
            secret.as_bytes(),
        )?);
        Ok(this)
    }
    fn encode_psk_start(&mut self, offer: Option<(&[u8], u32)>) -> Result<(), Failure> {
        let Mode::Client(config) = &self.mode else {
            return Err(Failure::State);
        };
        let n = wire::encode_client_hello_dual_early_with_policy(
            self.tx,
            &self.random,
            &self.share,
            &self.x25519_share,
            config.server_name,
            ALPN,
            config.transport_parameters,
            offer,
            self.early_status == EarlyStatus::Offered,
            self.cipher_policy,
        )?;
        self.transcript = Transcript::new();
        if let Some(psk) = wire::parse_client_hello_early(&self.tx[..n])?.psk {
            let (prefix, offset) = (psk.binder_prefix, psk.binder_offset);
            let hash = self.transcript.binder_hash(&self.tx[..prefix])?;
            let binder = self.schedule.binder(schedule::PskKind::Resumption, &hash)?;
            self.tx[offset..offset + 32].copy_from_slice(&binder);
        }
        if n > self.certificates.len() {
            return Err(Failure::Capacity);
        }
        self.certificates[..n].copy_from_slice(&self.tx[..n]);
        self.first_hello_len = n;
        self.transcript.append(&self.tx[..n])?;
        self.tx_len = n;
        self.tx_sent = 0;
        self.tx_initial_end = n;
        Ok(())
    }
    pub fn server_with_tickets<R: RngCore + CryptoRng>(
        config: ServerConfig<'cfg>,
        storage: Storage<'buf>,
        rng: &mut R,
        resumption: ServerResumption<'cfg>,
    ) -> Result<Self, Failure> {
        Self::server_with_tickets_and_policy(
            config,
            storage,
            rng,
            resumption,
            CipherPolicy::Default,
        )
    }
    /// Construct with an explicit immutable suite policy, enforced before output.
    pub fn server_with_tickets_and_policy<R: RngCore + CryptoRng>(
        config: ServerConfig<'cfg>,
        storage: Storage<'buf>,
        rng: &mut R,
        resumption: ServerResumption<'cfg>,
        policy: CipherPolicy,
    ) -> Result<Self, Failure> {
        if resumption.lifetime_seconds == 0
            || resumption.lifetime_seconds > ticket::MAX_LIFETIME_SECONDS
            || resumption.max_age_skew_ms > ticket::MAX_AGE_SKEW_MS
            || resumption.policy.len() > ticket::MAX_BINDING_PROFILE_BYTES
        {
            return Err(Failure::InvalidConfig);
        }
        transport_profile(config.transport_parameters, resumption.policy)?;
        let mut this = Self::server_with_policy(config, storage, rng, policy)?;
        this.resumption = Some(Resumption::Server(resumption));
        Ok(this)
    }
    /// Explicit P-256-only group policy with the same bounded ticket services.
    pub fn server_p256_with_tickets<R: RngCore + CryptoRng>(
        config: ServerConfig<'cfg>,
        storage: Storage<'buf>,
        rng: &mut R,
        resumption: ServerResumption<'cfg>,
    ) -> Result<Self, Failure> {
        let mut this = Self::server_with_tickets(config, storage, rng, resumption)?;
        this.allow_x25519 = false;
        this.x25519 = None;
        Ok(this)
    }
    pub fn server_with_early_data<R: RngCore + CryptoRng>(
        config: ServerConfig<'cfg>,
        storage: Storage<'buf>,
        rng: &mut R,
        resumption: ServerResumption<'cfg>,
        early: ServerEarlyData,
    ) -> Result<Self, Failure> {
        Self::server_with_early_data_and_policy(
            config,
            storage,
            rng,
            resumption,
            early,
            CipherPolicy::Default,
        )
    }
    pub fn server_with_early_data_and_policy<R: RngCore + CryptoRng>(
        config: ServerConfig<'cfg>,
        storage: Storage<'buf>,
        rng: &mut R,
        resumption: ServerResumption<'cfg>,
        early: ServerEarlyData,
        policy: CipherPolicy,
    ) -> Result<Self, Failure> {
        if !resumption.store.supports_early()
            || RememberedLimits::from_authenticated_server_parameters(config.transport_parameters)
                .map_err(Failure::Early)?
                != early.limits
        {
            return Err(Failure::InvalidConfig);
        }
        let mut this =
            Self::server_with_tickets_and_policy(config, storage, rng, resumption, policy)?;
        this.early_generation = Some(early.generation);
        this.early_server = Some(early);
        Ok(this)
    }
    pub fn server_p256_with_early_data<R: RngCore + CryptoRng>(
        config: ServerConfig<'cfg>,
        storage: Storage<'buf>,
        rng: &mut R,
        resumption: ServerResumption<'cfg>,
        early: ServerEarlyData,
    ) -> Result<Self, Failure> {
        let mut this = Self::server_with_early_data(config, storage, rng, resumption, early)?;
        this.allow_x25519 = false;
        this.x25519 = None;
        Ok(this)
    }
    fn reject_early(&mut self) {
        if self.early_status != EarlyStatus::Disabled {
            self.early_status = EarlyStatus::Rejected;
        }
        self.early_key = None;
        self.early_claim = None;
    }
    pub fn is_resumed(&self) -> bool {
        self.state == State::Connected && self.resumed
    }

    pub fn server<R: RngCore + CryptoRng>(
        config: ServerConfig<'cfg>,
        storage: Storage<'buf>,
        rng: &mut R,
    ) -> Result<Self, Failure> {
        Self::server_with_policy(config, storage, rng, CipherPolicy::Default)
    }
    /// Construct with an explicit immutable suite policy, enforced before output.
    pub fn server_with_policy<R: RngCore + CryptoRng>(
        config: ServerConfig<'cfg>,
        storage: Storage<'buf>,
        rng: &mut R,
        policy: CipherPolicy,
    ) -> Result<Self, Failure> {
        if config.certificate_chain.is_empty() || config.certificate_chain.len() > MAX_CHAIN {
            return Err(Failure::InvalidConfig);
        }
        // Prove the supplied signing key matches the supplied leaf; neither trust
        // nor peer identity is established by this local configuration check.
        let leaf = CertificateDer::from(config.certificate_chain[0]);
        let cert = webpki::EndEntityCert::try_from(&leaf).map_err(|_| Failure::InvalidConfig)?;
        let signature: Signature = config
            .signing_key
            .sign(b"hibana-quic TLS signing key consistency");
        cert.verify_signature(
            &certificate::P256_SHA256,
            b"hibana-quic TLS signing key consistency",
            signature.to_der().as_bytes(),
        )
        .map_err(|_| Failure::CertificateKeyMismatch)?;
        let mut this = Self::new(Mode::Server(config), storage, rng)?;
        this.cipher_policy = policy;
        Ok(this)
    }

    /// Explicit P-256-only group policy, useful for compatibility and genuine HRR
    /// testing. Certificate verification and all other checks remain unchanged.
    pub fn server_p256<R: RngCore + CryptoRng>(
        config: ServerConfig<'cfg>,
        storage: Storage<'buf>,
        rng: &mut R,
    ) -> Result<Self, Failure> {
        let mut this = Self::server(config, storage, rng)?;
        this.allow_x25519 = false;
        this.x25519 = None;
        Ok(this)
    }

    fn new<R: RngCore + CryptoRng>(
        mode: Mode<'cfg>,
        storage: Storage<'buf>,
        rng: &mut R,
    ) -> Result<Self, Failure> {
        if storage.rx_message.len() < 4
            || storage.tx_flight.len() < 4
            || storage.peer_parameters.is_empty()
        {
            return Err(Failure::InvalidStorage);
        }
        if matches!(mode, Mode::Client(_)) && storage.peer_certificates.is_empty() {
            return Err(Failure::InvalidStorage);
        }
        let mut scalar = zeroize::Zeroizing::new([0u8; 32]);
        let mut ephemeral = None;
        for _ in 0..8 {
            rng.try_fill_bytes(&mut *scalar)
                .map_err(|_| Failure::Entropy)?;
            if let Ok(key) = SecretKey::from_slice(&*scalar) {
                ephemeral = Some(key);
                break;
            }
        }
        let ephemeral = ephemeral.ok_or(Failure::Entropy)?;
        let point = ephemeral.public_key().to_encoded_point(false);
        let mut share = [0; 65];
        share.copy_from_slice(point.as_bytes());
        let mut random = [0; 32];
        rng.try_fill_bytes(&mut random)
            .map_err(|_| Failure::Entropy)?;
        let x25519 =
            crate::key_exchange::X25519Secret::generate(rng).map_err(|_| Failure::Entropy)?;
        let x25519_share = x25519.public_key();
        let state = match mode {
            Mode::Client(_) => State::ClientServerHello,
            Mode::Server(_) => State::ServerClientHello,
        };
        Ok(Self {
            mode,
            state,
            last_failure: None,
            rx: Some(storage.rx_message),
            rx_used: 0,
            rx_target: 0,
            rx_level: None,
            tx: storage.tx_flight,
            tx_len: 0,
            tx_sent: 0,
            tx_initial_end: 0,
            tx_post_handshake: false,
            certificates: storage.peer_certificates,
            cert_ranges: core::array::from_fn(|_| wire::DerRange { offset: 0, len: 0 }),
            cert_count: 0,
            first_hello_len: 0,
            retry_suite: None,
            retry_group: None,
            parameters: storage.peer_parameters,
            parameters_len: 0,
            ephemeral: Some(ephemeral),
            x25519: Some(x25519),
            x25519_share,
            allow_x25519: true,
            negotiated_group: None,
            share,
            random,
            transcript: Transcript::new(),
            schedule: KeySchedule::new(None)?,
            suite: None,
            cipher_policy: CipherPolicy::Default,
            handshake: None,
            application: ApplicationMaterial::Empty,
            key_handoff: false,
            handshake_created: false,
            application_created: false,
            handshake_discarded: false,
            application_discarded: false,
            integrity: IntegrityBudget::new(),
            resumption: None,
            resumption_master: None,
            verification_context: None,
            ticket_binding: None,
            offer_age: None,
            offer_suite: None,
            resumed: false,
            peer_wants_tickets: false,
            early_status: EarlyStatus::Disabled,
            early_generation: None,
            early_limits: None,
            early_server: None,
            early_key: None,
            early_claim: None,
        })
    }

    pub fn state(&self) -> State {
        self.state
    }
    /// Lifetime failed packet authentication count, shared with the endpoint's
    /// Initial keys and all Handshake/application generations. Never resets.
    pub fn failed_authentications(&self) -> u64 {
        self.integrity.failed_packets()
    }
    pub fn last_failure(&self) -> Option<&Failure> {
        self.last_failure.as_ref()
    }
    pub fn negotiated_alpn(&self) -> Option<&'static [u8]> {
        if self.state == State::Connected {
            Some(ALPN)
        } else {
            None
        }
    }
    pub fn negotiated_group(&self) -> Option<u16> {
        self.negotiated_group
    }
    pub fn negotiated_suite(&self) -> Option<CipherSuite> {
        self.suite
    }
    fn side(&self) -> Side {
        match self.mode {
            Mode::Client(_) => Side::Client,
            Mode::Server(_) => Side::Server,
        }
    }

    fn fail(&mut self, failure: Failure) -> tls::Error {
        let error = match &failure {
            Failure::Capacity | Failure::InvalidStorage => tls::Error::Capacity,
            Failure::Certificate(_)
            | Failure::CertificateKeyMismatch
            | Failure::Ticket(ticket::Error::Binder) => tls::Error::Authentication,
            Failure::Wire(wire::Error::InvalidQuicEarlyData) => tls::Error::ProtocolViolation,
            Failure::Crypto(crypto::Error::IntegrityLimit) => tls::Error::IntegrityLimit,
            Failure::Crypto(crypto::Error::KeyUpdateError) => tls::Error::KeyUpdateError,
            Failure::Crypto(crypto::Error::ConfidentialityLimit) => {
                tls::Error::ConfidentialityLimit
            }
            Failure::Crypto(crypto::Error::PacketNumberReuse) => tls::Error::PacketNumberReuse,
            _ => tls::Error::Handshake,
        };
        self.last_failure = Some(failure);
        self.state = State::Failed;
        self.ephemeral = None;
        self.x25519 = None;
        self.schedule.discard();
        self.reject_early();
        self.resumption_master = None;
        self.offer_age = None;
        self.handshake = None;
        self.application = ApplicationMaterial::Empty;
        self.tx_len = 0;
        self.tx_sent = 0;
        error
    }

    fn expected_level(&self) -> Result<Level, Failure> {
        match self.state {
            State::ClientServerHello
            | State::ClientServerHelloRetry
            | State::ServerClientHello
            | State::ServerClientHelloRetry => Ok(Level::Initial),
            State::ClientEncryptedExtensions
            | State::ClientCertificate
            | State::ClientCertificateVerify
            | State::ClientFinished
            | State::ServerClientFinished => Ok(Level::Handshake),
            State::Connected
                if self.side() == Side::Client
                    && self.application_created
                    && !self.application_discarded =>
            {
                Ok(Level::OneRtt)
            }
            _ => Err(Failure::State),
        }
    }

    fn save_parameters(&mut self, bytes: &[u8]) -> Result<(), Failure> {
        if bytes.len() > self.parameters.len() {
            return Err(Failure::Capacity);
        }
        self.parameters[..bytes.len()].copy_from_slice(bytes);
        self.parameters_len = bytes.len();
        Ok(())
    }
    fn begin_flight(&mut self) -> Result<(), Failure> {
        if self.tx_sent != self.tx_len {
            return Err(Failure::State);
        }
        self.tx_len = 0;
        self.tx_sent = 0;
        self.tx_initial_end = 0;
        self.tx_post_handshake = false;
        Ok(())
    }
    fn commit_output(&mut self, n: usize) -> Result<(), Failure> {
        let end = self.tx_len.checked_add(n).ok_or(Failure::Capacity)?;
        let message = self.tx.get(self.tx_len..end).ok_or(Failure::Capacity)?;
        self.transcript.append(message)?;
        self.tx_len = end;
        Ok(())
    }

    fn install_handshake(&mut self, group: u16, share: &[u8], suite: u16) -> Result<(), Failure> {
        if self.handshake_discarded || self.handshake_created {
            return Err(Failure::State);
        }
        let suite = match suite {
            0x1301 => CipherSuite::Aes128GcmSha256,
            0x1303 => CipherSuite::ChaCha20Poly1305Sha256,
            _ => return Err(Failure::UnsupportedSuite),
        };
        match group {
            wire::GROUP_P256 => {
                if share.len() != 65 || share[0] != 4 {
                    return Err(Failure::InvalidKeyShare);
                }
                let peer =
                    PublicKey::from_sec1_bytes(share).map_err(|_| Failure::InvalidKeyShare)?;
                let key = self.ephemeral.take().ok_or(Failure::State)?;
                let shared = diffie_hellman(key.to_nonzero_scalar(), peer.as_affine());
                self.schedule
                    .derive_handshake(shared.raw_secret_bytes(), &self.transcript)?;
            }
            wire::GROUP_X25519 if self.allow_x25519 => {
                let key = self.x25519.take().ok_or(Failure::State)?;
                let shared = key.complete(share).map_err(|_| Failure::InvalidKeyShare)?;
                self.schedule.derive_handshake(&*shared, &self.transcript)?;
            }
            _ => return Err(Failure::InvalidKeyShare),
        }
        // Unselected fresh group secrets are not retained after negotiation.
        self.ephemeral = None;
        self.x25519 = None;
        self.negotiated_group = Some(group);
        self.suite = Some(suite);
        self.handshake = Some(self.packet_keys(KeyKind::Handshake)?);
        self.handshake_created = true;
        Ok(())
    }
    fn packet_keys(&self, kind: KeyKind) -> Result<DirectionalKeys, Failure> {
        if matches!(kind, KeyKind::Handshake) && self.handshake_created
            || matches!(kind, KeyKind::OneRtt) && self.application_created
        {
            return Err(Failure::State);
        }
        let suite = self.suite.ok_or(Failure::State)?;
        let client = match kind {
            KeyKind::Handshake => self.schedule.handshake_traffic(Side::Client)?,
            KeyKind::OneRtt => self.schedule.application_traffic(Side::Client)?,
            _ => return Err(Failure::State),
        };
        let server = match kind {
            KeyKind::Handshake => self.schedule.handshake_traffic(Side::Server)?,
            KeyKind::OneRtt => self.schedule.application_traffic(Side::Server)?,
            _ => return Err(Failure::State),
        };
        let (local, remote) = match self.side() {
            Side::Client => (client, server),
            Side::Server => (server, client),
        };
        Ok(DirectionalKeys {
            local: PacketKey::from_secret(suite, kind, local.as_bytes())?,
            remote: PacketKey::from_secret(suite, kind, remote.as_bytes())?,
        })
    }
    fn install_application(&mut self) -> Result<(), Failure> {
        if self.application_discarded || self.application_created {
            return Err(Failure::State);
        }
        self.schedule.derive_master(&self.transcript)?;
        let keys = self.packet_keys(KeyKind::OneRtt)?;
        self.application = if self.key_handoff {
            ApplicationMaterial::Handoff(keys)
        } else {
            ApplicationMaterial::Legacy(ApplicationKeys::new(keys.local, keys.remote)?)
        };
        self.application_created = true;
        if self.side() == Side::Client {
            self.early_key = None;
        }
        Ok(())
    }

    fn validate_peer_certificate(&self, signature: Option<(u16, &[u8])>) -> Result<(), Failure> {
        let Mode::Client(config) = &self.mode else {
            return Err(Failure::State);
        };
        if self.cert_count == 0 {
            return Err(Failure::State);
        }
        let mut certs: [CertificateDer<'_>; MAX_CHAIN] =
            core::array::from_fn(|_| CertificateDer::from(&[][..]));
        for (slot, range) in certs.iter_mut().zip(&self.cert_ranges[..self.cert_count]) {
            let end = range
                .offset
                .checked_add(range.len)
                .ok_or(Failure::Capacity)?;
            *slot = CertificateDer::from(
                self.certificates
                    .get(range.offset..end)
                    .ok_or(Failure::Capacity)?,
            );
        }
        let verifier =
            ServerVerifier::new(config.trust_anchors, config.now, config.certificate_limits)?;
        let name = ServerName::try_from(config.server_name).map_err(|_| Failure::InvalidConfig)?;
        let verified = verifier.verify_server(&certs[0], &certs[1..self.cert_count], &name)?;
        if let Some((scheme, signature)) = signature {
            verified.verify_certificate_verify(scheme, &self.transcript.hash(), signature)?;
        }
        Ok(())
    }

    fn retain_resumption(&mut self) -> Result<(), Failure> {
        self.schedule.derive_resumption(&self.transcript)?;
        if matches!(self.resumption, Some(Resumption::Client(_)))
            || self.peer_wants_tickets && matches!(self.resumption, Some(Resumption::Server(_)))
        {
            self.resumption_master = Some(self.schedule.take_resumption_master()?);
        }
        self.schedule.discard();
        self.offer_age = None;
        Ok(())
    }
    fn issue_ticket(&mut self) -> Result<(), Failure> {
        if !self.peer_wants_tickets || !matches!(self.resumption, Some(Resumption::Server(_))) {
            return Ok(());
        }
        self.begin_flight()?;
        let Some(Resumption::Server(config)) = &mut self.resumption else {
            return Err(Failure::State);
        };
        let suite = match self.suite.ok_or(Failure::State)? {
            CipherSuite::Aes128GcmSha256 => 0x1301,
            CipherSuite::ChaCha20Poly1305Sha256 => 0x1303,
        };
        let token = if let Some(early) = self.early_server {
            config.store.prepare_early(
                config.entropy,
                config.clock.now_ms()?,
                config.lifetime_seconds,
                suite,
                self.ticket_binding.ok_or(Failure::State)?,
                early.limits,
            )?
        } else {
            config.store.prepare(
                config.entropy,
                config.clock.now_ms()?,
                config.lifetime_seconds,
                suite,
                self.ticket_binding.ok_or(Failure::State)?,
            )?
        };
        let psk = self
            .resumption_master
            .as_ref()
            .ok_or(Failure::State)?
            .derive(token.ticket_nonce())?;
        let mut identity = [0; ticket::SEALED_TICKET_BYTES];
        let issued = config.store.seal(token, psk, &mut identity)?;
        let n = wire::encode_new_session_ticket_early(
            self.tx,
            issued.lifetime_seconds,
            issued.age_add,
            &issued.nonce,
            &identity[..issued.len],
            self.early_server.is_some(),
        )?;
        self.tx_len = n;
        self.tx_post_handshake = true;
        // At most one NST per connection; the server needs no master thereafter.
        self.resumption_master = None;
        Ok(())
    }
    fn cache_ticket(&mut self, message: &[u8]) -> Result<(), Failure> {
        let received = wire::parse_new_session_ticket(message)?;
        let Some(Resumption::Client(config)) = &mut self.resumption else {
            return Ok(());
        };
        if received.lifetime_seconds == 0
            || received.lifetime_seconds > ticket::MAX_LIFETIME_SECONDS
        {
            return Ok(());
        }
        let psk = self
            .resumption_master
            .as_ref()
            .ok_or(Failure::State)?
            .derive(received.nonce)?;
        let Mode::Client(client) = &self.mode else {
            return Err(Failure::State);
        };
        let profile = transport_profile(&self.parameters[..self.parameters_len], &[])?;
        let binding = ticket::Binding::new(client.server_name, ALPN, &profile)?;
        let metadata = ticket::ReceivedTicket {
            ticket: received.ticket,
            lifetime_seconds: received.lifetime_seconds,
            age_add: received.age_add,
            suite: match self.suite.ok_or(Failure::State)? {
                CipherSuite::Aes128GcmSha256 => 0x1301,
                CipherSuite::ChaCha20Poly1305Sha256 => 0x1303,
            },
            binding,
        };
        let context = self.verification_context.ok_or(Failure::State)?;
        let result = if received.early_data {
            let limits = RememberedLimits::from_authenticated_server_parameters(
                &self.parameters[..self.parameters_len],
            )
            .map_err(Failure::Early)?;
            config.store.insert_verified_early(
                config.clock.now_ms()?,
                metadata,
                psk,
                context,
                limits,
            )
        } else {
            config
                .store
                .insert_verified(config.clock.now_ms()?, metadata, psk, context)
        };
        match result {
            Ok(()) | Err(ticket::Error::Capacity | ticket::Error::DuplicateTicket) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn handle_message(&mut self, level: Level, message: &[u8]) -> Result<(), Failure> {
        if level != self.expected_level()? {
            return Err(Failure::State);
        }
        self.state = match self.state {
            State::ClientServerHello | State::ClientServerHelloRetry => {
                if self.client_hello(message, self.state == State::ClientServerHelloRetry)? {
                    State::ClientServerHelloRetry
                } else {
                    State::ClientEncryptedExtensions
                }
            }
            State::ClientEncryptedExtensions => {
                self.client_extensions(message)?;
                if self.resumed {
                    State::ClientFinished
                } else {
                    State::ClientCertificate
                }
            }
            State::ClientCertificate => {
                self.client_certificate(message)?;
                State::ClientCertificateVerify
            }
            State::ClientCertificateVerify => {
                self.client_certificate_verify(message)?;
                State::ClientFinished
            }
            State::ClientFinished => {
                self.client_finished(message)?;
                State::Connected
            }
            State::ServerClientHello | State::ServerClientHelloRetry => {
                if self.server_hello(message, self.state == State::ServerClientHelloRetry)? {
                    State::ServerClientHelloRetry
                } else {
                    State::ServerClientFinished
                }
            }
            State::ServerClientFinished => {
                self.server_finished(message)?;
                State::Connected
            }
            State::Connected if self.side() == Side::Client => {
                self.cache_ticket(message)?;
                State::Connected
            }
            _ => return Err(Failure::State),
        };
        Ok(())
    }

    fn receive_inner(&mut self, level: Level, mut bytes: &[u8]) -> Result<(), Failure> {
        while !bytes.is_empty() {
            if self.rx_used == 0 {
                if level != self.expected_level()? {
                    return Err(Failure::State);
                }
                self.rx_level = Some(level);
                self.rx_target = 4;
            } else if self.rx_level != Some(level) {
                return Err(Failure::State);
            }
            let rx = self.rx.as_deref_mut().ok_or(Failure::State)?;
            let n = (self.rx_target - self.rx_used).min(bytes.len());
            rx[self.rx_used..self.rx_used + n].copy_from_slice(&bytes[..n]);
            self.rx_used += n;
            bytes = &bytes[n..];
            if self.rx_used < self.rx_target {
                continue;
            }
            if self.rx_target == 4 {
                let body = ((rx[1] as usize) << 16) | ((rx[2] as usize) << 8) | rx[3] as usize;
                self.rx_target = 4 + body;
                if self.rx_target > rx.len() {
                    return Err(Failure::Capacity);
                }
                if self.rx_used < self.rx_target {
                    continue;
                }
            }
            let rx = self.rx.take().ok_or(Failure::State)?;
            let post_handshake = self.state == State::Connected;
            let result = self.handle_message(level, &rx[..self.rx_target]);
            if post_handshake {
                rx[..self.rx_target].zeroize();
            }
            self.rx = Some(rx);
            self.rx_used = 0;
            self.rx_target = 0;
            self.rx_level = None;
            result?;
        }
        Ok(())
    }
}

fn suite_from_wire(suite: u16) -> Result<CipherSuite, Failure> {
    match suite {
        0x1301 => Ok(CipherSuite::Aes128GcmSha256),
        0x1303 => Ok(CipherSuite::ChaCha20Poly1305Sha256),
        _ => Err(Failure::UnsupportedSuite),
    }
}

fn map_crypto(error: crypto::Error) -> tls::Error {
    match error {
        crypto::Error::AuthenticationFailed => tls::Error::Authentication,
        crypto::Error::KeyUpdateError => tls::Error::KeyUpdateError,
        crypto::Error::KeyUpdateNotAllowed => tls::Error::KeyUpdateNotAllowed,
        crypto::Error::IntegrityLimit => tls::Error::IntegrityLimit,
        crypto::Error::ConfidentialityLimit => tls::Error::ConfidentialityLimit,
        crypto::Error::PacketNumberReuse => tls::Error::PacketNumberReuse,
        crypto::Error::KeyDiscarded => tls::Error::KeysUnavailable,
        crypto::Error::BufferTooSmall | crypto::Error::PacketTooLarge => tls::Error::Capacity,
        _ => tls::Error::InvalidInput,
    }
}
impl Provider for BoundedTls<'_, '_> {
    fn observations(&self) -> tls::Observations {
        tls::Observations {
            resumed: Some(self.is_resumed()),
            negotiated_suite: self.negotiated_suite().map(|suite| match suite {
                CipherSuite::Aes128GcmSha256 => 0x1301,
                CipherSuite::ChaCha20Poly1305Sha256 => 0x1303,
            }),
            failed_authentications: Some(self.failed_authentications()),
        }
    }
    fn write_failure_diagnostic(&self, out: &mut dyn core::fmt::Write) -> core::fmt::Result {
        if let Some(failure) = self.last_failure() {
            write!(out, "{failure:?}")?;
        }
        Ok(())
    }

    fn early_status(&self) -> EarlyStatus {
        self.early_status
    }
    fn early_generation(&self) -> Option<u64> {
        self.early_generation
    }
    fn remembered_early_limits(&self) -> Option<RememberedLimits> {
        self.early_limits
    }
    fn take_early_replay_claim(&mut self) -> Option<ReplayClaim> {
        self.early_claim.take()
    }
    fn has_early_keys(&self) -> bool {
        !self.key_handoff && self.state != State::Failed && self.early_key.is_some()
    }
    fn seal_early(
        &mut self,
        pn: u64,
        header: &[u8],
        buffer: &mut [u8],
        plaintext_len: usize,
    ) -> Result<usize, tls::Error> {
        if self.key_handoff {
            return Err(tls::Error::KeysUnavailable);
        }
        if self.side() != Side::Client {
            return Err(tls::Error::InvalidInput);
        }
        if self.state == State::Failed
            || self.application.is_some()
            || !matches!(
                self.early_status,
                EarlyStatus::Offered | EarlyStatus::AcceptedPendingFinished
            )
        {
            return Err(tls::Error::KeysUnavailable);
        }
        self.early_key
            .as_mut()
            .ok_or(tls::Error::KeysUnavailable)?
            .seal(pn, header, buffer, plaintext_len)
            .map_err(map_crypto)
    }
    fn open_early(
        &mut self,
        pn: u64,
        header: &[u8],
        buffer: &mut [u8],
    ) -> Result<usize, tls::Error> {
        if self.key_handoff {
            return Err(tls::Error::KeysUnavailable);
        }
        if self.side() != Side::Server {
            return Err(tls::Error::InvalidInput);
        }
        if self.state == State::Failed
            || !matches!(
                self.early_status,
                EarlyStatus::AcceptedPendingFinished | EarlyStatus::Accepted
            )
        {
            return Err(tls::Error::KeysUnavailable);
        }
        let result = self
            .early_key
            .as_ref()
            .ok_or(tls::Error::KeysUnavailable)?
            .open(pn, header, buffer, &mut self.integrity);
        match result {
            Err(crypto::Error::IntegrityLimit) => {
                Err(self.fail(Failure::Crypto(crypto::Error::IntegrityLimit)))
            }
            other => other.map_err(map_crypto),
        }
    }
    fn early_header_mask(&self, local: bool, sample: &[u8; 16]) -> Result<[u8; 5], tls::Error> {
        if self.key_handoff {
            return Err(tls::Error::KeysUnavailable);
        }
        if local != (self.side() == Side::Client) {
            return Err(tls::Error::InvalidInput);
        }
        if self.state == State::Failed {
            return Err(tls::Error::KeysUnavailable);
        }
        self.early_key
            .as_ref()
            .ok_or(tls::Error::KeysUnavailable)?
            .header_mask(sample)
            .map_err(map_crypto)
    }
    fn discard_early_keys(&mut self) {
        self.early_key = None;
    }
    fn negotiated_group(&self) -> Option<u16> {
        self.negotiated_group
    }
    fn key_phase(&self) -> bool {
        self.application
            .as_ref()
            .is_some_and(ApplicationKeys::phase)
    }
    fn integrity_budget(&mut self) -> Option<&mut crate::crypto::IntegrityBudget> {
        if self.key_handoff {
            None
        } else {
            Some(&mut self.integrity)
        }
    }
    fn receive_key_generation(&self) -> u64 {
        self.application
            .as_ref()
            .map_or(0, ApplicationKeys::receive_generation)
    }
    fn key_generation(&self) -> u64 {
        self.application
            .as_ref()
            .map_or(0, ApplicationKeys::generation)
    }
    fn confirm_handshake(&mut self) -> Result<(), tls::Error> {
        if self.key_handoff {
            return Err(tls::Error::KeysUnavailable);
        }
        if self.state != State::Connected {
            return Err(tls::Error::KeysUnavailable);
        }
        self.application
            .as_mut()
            .ok_or(tls::Error::KeysUnavailable)?
            .confirm_handshake()
            .map_err(map_crypto)
    }
    fn maintain_keys(&mut self, now: u64, pto: u64) -> Result<(), tls::Error> {
        if self.key_handoff {
            return Err(tls::Error::KeysUnavailable);
        }
        if self.state == State::Failed {
            return Err(tls::Error::Handshake);
        }
        if self.application_discarded {
            return Err(tls::Error::KeysUnavailable);
        }
        // The transport services timers throughout the handshake, even before
        // it can use application keys. No update preparation is needed yet.
        if self.state != State::Connected {
            return Ok(());
        }
        self.application
            .as_mut()
            .ok_or(tls::Error::KeysUnavailable)?
            .maintain(now, pto)
            .map_err(map_crypto)
    }
    fn initiate_key_update(&mut self, now: u64, pto: u64) -> Result<(), tls::Error> {
        if self.key_handoff {
            return Err(tls::Error::KeysUnavailable);
        }
        if self.state != State::Connected {
            return Err(tls::Error::KeysUnavailable);
        }
        self.application
            .as_mut()
            .ok_or(tls::Error::KeysUnavailable)?
            .initiate(now, pto)
            .map_err(map_crypto)
    }
    fn acknowledge_one_rtt(
        &mut self,
        sent_pn: u64,
        received_generation: u64,
        now: u64,
        pto: u64,
    ) -> Result<(), tls::Error> {
        if self.key_handoff {
            return Err(tls::Error::KeysUnavailable);
        }
        if self.state != State::Connected {
            return Err(tls::Error::KeysUnavailable);
        }
        let result = self
            .application
            .as_mut()
            .ok_or(tls::Error::KeysUnavailable)?
            .acknowledge(sent_pn, received_generation, now, pto);
        match result {
            Err(crypto::Error::KeyUpdateError) => {
                Err(self.fail(Failure::Crypto(crypto::Error::KeyUpdateError)))
            }
            other => other.map_err(map_crypto),
        }
    }
    #[allow(clippy::too_many_arguments)]
    fn open_one_rtt(
        &mut self,
        pn: u64,
        phase: bool,
        header: &[u8],
        buffer: &mut [u8],
        now: u64,
        pto: u64,
    ) -> Result<crypto::Opened, tls::Error> {
        if self.key_handoff {
            return Err(tls::Error::KeysUnavailable);
        }
        if self.state != State::Connected {
            return Err(tls::Error::KeysUnavailable);
        }
        let result = self
            .application
            .as_mut()
            .ok_or(tls::Error::KeysUnavailable)?
            .open(pn, phase, header, buffer, &mut self.integrity, now, pto);
        match result {
            Err(error @ (crypto::Error::IntegrityLimit | crypto::Error::KeyUpdateError)) => {
                Err(self.fail(Failure::Crypto(error)))
            }
            other => other.map_err(map_crypto),
        }
    }
    fn receive(&mut self, level: Level, bytes: &[u8]) -> Result<(), tls::Error> {
        if self.state == State::Failed {
            return Err(tls::Error::Handshake);
        }
        match self.receive_inner(level, bytes) {
            Ok(()) => Ok(()),
            Err(error) => Err(self.fail(error)),
        }
    }
    fn transmit(&mut self, out: &mut [u8]) -> Result<Option<Output>, tls::Error> {
        if self.state == State::Failed {
            return Err(tls::Error::Handshake);
        }
        if self.tx_sent == self.tx_len {
            return Ok(None);
        }
        if out.is_empty() {
            return Err(tls::Error::Capacity);
        }
        let (level, end) = if self.tx_post_handshake {
            (Level::OneRtt, self.tx_len)
        } else if self.tx_sent < self.tx_initial_end {
            (Level::Initial, self.tx_initial_end)
        } else {
            (Level::Handshake, self.tx_len)
        };
        let n = out.len().min(end - self.tx_sent);
        out[..n].copy_from_slice(&self.tx[self.tx_sent..self.tx_sent + n]);
        self.tx_sent += n;
        Ok(Some(Output { level, len: n }))
    }
    fn has_keys(&self, level: Level) -> bool {
        if self.key_handoff || self.state == State::Failed {
            return false;
        }
        match level {
            Level::Initial => false,
            Level::Handshake => self.handshake.is_some(),
            Level::OneRtt => self.application.is_some(),
        }
    }
    fn discard_keys(&mut self, level: Level) {
        match level {
            Level::Initial => {}
            Level::Handshake => {
                self.handshake = None;
                self.handshake_discarded = true
            }
            Level::OneRtt => {
                self.application = ApplicationMaterial::Empty;
                self.early_key = None;
                self.early_claim = None;
                self.resumption_master = None;
                self.application_discarded = true
            }
        }
    }
    fn is_handshaking(&self) -> bool {
        self.state != State::Connected
    }
    fn peer_transport_parameters(&self) -> Option<&[u8]> {
        if self.state == State::Connected {
            Some(&self.parameters[..self.parameters_len])
        } else {
            None
        }
    }
    fn seal(
        &mut self,
        level: Level,
        pn: u64,
        header: &[u8],
        buffer: &mut [u8],
        plaintext_len: usize,
    ) -> Result<usize, tls::Error> {
        if self.key_handoff {
            return Err(tls::Error::KeysUnavailable);
        }
        if self.state == State::Failed {
            return Err(tls::Error::Handshake);
        }
        if level == Level::OneRtt && self.state != State::Connected {
            return Err(tls::Error::KeysUnavailable);
        }
        match level {
            Level::Initial => Err(tls::Error::KeysUnavailable),
            Level::Handshake => self
                .handshake
                .as_mut()
                .ok_or(tls::Error::KeysUnavailable)?
                .local
                .seal(pn, header, buffer, plaintext_len)
                .map_err(map_crypto),
            Level::OneRtt => self
                .application
                .as_mut()
                .ok_or(tls::Error::KeysUnavailable)?
                .seal(pn, header, buffer, plaintext_len)
                .map_err(map_crypto),
        }
    }
    fn open(
        &mut self,
        level: Level,
        pn: u64,
        header: &[u8],
        buffer: &mut [u8],
    ) -> Result<usize, tls::Error> {
        if self.key_handoff {
            return Err(tls::Error::KeysUnavailable);
        }
        if self.state == State::Failed {
            return Err(tls::Error::Handshake);
        }
        if level == Level::OneRtt && self.state != State::Connected {
            return Err(tls::Error::KeysUnavailable);
        }
        // Compatibility entry point is generation-zero only. The phase-aware
        // transport must use open_one_rtt once it supports key updates.
        let result = match level {
            Level::Initial => return Err(tls::Error::KeysUnavailable),
            Level::Handshake => self
                .handshake
                .as_ref()
                .ok_or(tls::Error::KeysUnavailable)?
                .remote
                .open(pn, header, buffer, &mut self.integrity),
            Level::OneRtt => {
                let keys = self
                    .application
                    .as_mut()
                    .ok_or(tls::Error::KeysUnavailable)?;
                if keys.generation() != 0 || keys.receive_generation() != 0 {
                    return Err(tls::Error::InvalidInput);
                }
                keys.open(pn, false, header, buffer, &mut self.integrity, 0, 1)
                    .map(|o| o.len)
            }
        };
        match result {
            Err(crypto::Error::IntegrityLimit) => {
                Err(self.fail(Failure::Crypto(crypto::Error::IntegrityLimit)))
            }
            other => other.map_err(map_crypto),
        }
    }
    fn header_mask(
        &self,
        level: Level,
        local: bool,
        sample: &[u8; 16],
    ) -> Result<[u8; 5], tls::Error> {
        if self.key_handoff {
            return Err(tls::Error::KeysUnavailable);
        }
        if self.state == State::Failed {
            return Err(tls::Error::Handshake);
        }
        match level {
            Level::Initial => Err(tls::Error::KeysUnavailable),
            Level::Handshake => {
                let keys = self.handshake.as_ref().ok_or(tls::Error::KeysUnavailable)?;
                if local {
                    keys.local.header_mask(sample)
                } else {
                    keys.remote.header_mask(sample)
                }
                .map_err(map_crypto)
            }
            Level::OneRtt => self
                .application
                .as_ref()
                .ok_or(tls::Error::KeysUnavailable)?
                .header_mask(local, sample)
                .map_err(map_crypto),
        }
    }
}
