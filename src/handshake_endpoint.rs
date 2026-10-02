//! Experimental, real encrypted QUIC v1 handshake transport.
//!
//! Owns authenticated packet processing, CRYPTO/control recovery, congestion
//! accounting and typed Hibana authority. `TransportEndpoint` adds bounded streams.
//! Initial HP/AEAD/Retry replacement and graceful key retirement use actual
//! actor-owned keys through awaited mailbox capabilities. Provider protection
//! at other levels and the remaining Driver services are not yet migrated to
//! independently scheduled role actors. This is a partial architecture slice.
//! Retry and explicit close/draining are integrated; provider resumption is
//! supported. Migration and automatic fatal-error close reporting remain incomplete. Allocation
//! policy depends on the selected provider; the bounded backend and allocating
//! Rustls reference backend have separate evidence.
mod initial;
pub use initial::{
    INITIAL_PACKET_BYTES, InitialKeyClient, InitialKeyProtection, InitialProtection,
};
mod path;
use path::Reservation as PathReservation;
pub use path::{
    NetworkConfig, NetworkError, NetworkRandom, NetworkReceiveContext, NetworkResources,
    PreferredServer,
};
mod trace;
pub use trace::{TraceSetupError, TraceStatus};
mod early;
pub use early::{EARLY_CONTROL_BYTES, EARLY_REQUEST_BYTES};

use crate::{
    accounting::{self, PacketKind, PacketNumberSpace, SendReservation, SentLedger},
    crypto::{self, IntegrityBudget},
    driver::{Driver, DriverError, TransmitTicket},
    ecn::{self, Codepoint, MarkedPackets, PathEcn, PathIdentity, RxCounts},
    flights::{self, FlightId, FlightStore, Reference},
    handshake::{self, CryptoBuffer},
    idle::{self, IdleTimeout},
    lifecycle::{self, CloseReason, CloseTransmit, Lifecycle, State as ConnectionState},
    packet::{
        self, AckRanges, EncryptionLevel, Frame, FrameIter, Header, LongHeader, LongType,
        PacketIter, ParseLimits, ShortHeader,
    },
    parameters::{Parameters, Peer},
    recovery::{
        self, RecoveryTimer, RttEstimator, RttSample, SpaceTimer, TimeoutAction, TimerContext,
    },
    retry::{self, ClientRetry, ValidatedToken},
    tls::{self, Level, Provider},
    version_negotiation,
};

/// Fits a 1024-byte STREAM chunk plus worst-case base STREAM fields.
pub const MAX_APPLICATION_FRAME_BYTES: usize = 1056;
/// Local Retry-token admission bound. Larger legal opaque tokens are discarded
/// without resetting state. With max-20-byte CIDs, 4-byte PN and a 2-byte token
/// length this leaves 937 plaintext bytes in a 1200-byte Initial, enough for a
/// 900-byte CRYPTO fragment plus its maximum 11-byte frame header. ACKs that do
/// not fit with that fragment remain pending for a separate packet.
pub const MAX_RETRY_TOKEN_BYTES: usize = 192;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Side {
    Client,
    Server,
}
#[derive(Clone, Copy, Debug)]
pub enum KeyStage {
    Install,
    Use,
    Complete,
    Retire,
}
#[derive(Debug)]
pub enum Error {
    EarlyControl(crate::early_control::Error),
    Network(NetworkError),
    InvalidConfig,
    /// Unauthenticated VN omitted the sole supported version. No restart occurs.
    VersionNegotiationNoCommonVersion,
    Early(crate::early_data::Error),
    Lifecycle(lifecycle::Error),
    Idle(idle::Error),
    Ecn(ecn::Error),
    Retired,
    Busy,
    Retry(retry::Error),
    Capacity,
    UnexpectedFrame,
    ProtocolViolation,
    Streams(crate::streams::Error),
    Flight(flights::Error),
    Recovery(recovery::RecoveryError),
    Wire(packet::Error),
    Crypto(crypto::Error),
    /// The key-role service failed. The connection is terminal after this error.
    Protection(crate::roles::client::Error),
    Tls(tls::Error),
    Accounting(accounting::AccountingError),
    Driver(DriverError),
    KeyAuthority {
        stage: KeyStage,
        level: Level,
        error: DriverError,
    },
    Reassembly(handshake::Error),
    Parameters(crate::parameters::Error),
}
impl From<idle::Error> for Error {
    fn from(e: idle::Error) -> Self {
        Self::Idle(e)
    }
}
impl From<NetworkError> for Error {
    fn from(e: NetworkError) -> Self {
        Self::Network(e)
    }
}
impl From<ecn::Error> for Error {
    fn from(e: ecn::Error) -> Self {
        Self::Ecn(e)
    }
}
impl From<lifecycle::Error> for Error {
    fn from(e: lifecycle::Error) -> Self {
        Self::Lifecycle(e)
    }
}
impl From<retry::Error> for Error {
    fn from(e: retry::Error) -> Self {
        Self::Retry(e)
    }
}
impl From<flights::Error> for Error {
    fn from(e: flights::Error) -> Self {
        Self::Flight(e)
    }
}
impl From<recovery::RecoveryError> for Error {
    fn from(e: recovery::RecoveryError) -> Self {
        Self::Recovery(e)
    }
}
impl From<packet::Error> for Error {
    fn from(e: packet::Error) -> Self {
        Self::Wire(e)
    }
}
impl From<crypto::Error> for Error {
    fn from(e: crypto::Error) -> Self {
        Self::Crypto(e)
    }
}
impl From<tls::Error> for Error {
    fn from(e: tls::Error) -> Self {
        Self::Tls(e)
    }
}
impl From<accounting::AccountingError> for Error {
    fn from(e: accounting::AccountingError) -> Self {
        Self::Accounting(e)
    }
}
impl From<DriverError> for Error {
    fn from(e: DriverError) -> Self {
        Self::Driver(e)
    }
}
impl From<handshake::Error> for Error {
    fn from(e: handshake::Error) -> Self {
        Self::Reassembly(e)
    }
}
impl From<crate::parameters::Error> for Error {
    fn from(e: crate::parameters::Error) -> Self {
        Self::Parameters(e)
    }
}

/// Effects are called only inside the authenticated Hibana receive contract.
pub trait ApplicationHandler {
    /// Client-side reconciliation boundary after certificate/Finished and TP
    /// validation, before any coalesced 1-RTT ACK can touch early references.
    fn early_decision(
        &mut self,
        _decision: crate::early_send::Decision,
        _limits: crate::streams::Limits,
        _authority: &mut crate::early_send::ImportAuthority<'_, '_>,
    ) -> Result<(), crate::streams::Error> {
        Ok(())
    }
    fn frame(&mut self, frame: Frame<'_>) -> Result<(), crate::streams::Error>;
    fn acknowledged(&mut self, ranges: AckRanges<'_>) -> Result<(), crate::streams::Error>;
}
struct NoApplication;
impl ApplicationHandler for NoApplication {
    fn frame(&mut self, _: Frame<'_>) -> Result<(), crate::streams::Error> {
        Err(crate::streams::Error::StreamState)
    }
    fn acknowledged(&mut self, _: AckRanges<'_>) -> Result<(), crate::streams::Error> {
        Ok(())
    }
}
#[derive(Clone, Copy)]
struct ApplicationPacket {
    number: u64,
    early: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct Config<'a> {
    pub side: Side,
    pub local_id: &'a [u8],
    pub original_destination_id: &'a [u8],
    /// Must match Driver and remain unique while any old callback descriptor can exist.
    /// Reused connection slots need a checked, monotonically advanced generation.
    pub generation: u64,
}
#[derive(Clone, Copy)]
struct ConnectionId {
    bytes: [u8; 20],
    len: usize,
}
impl ConnectionId {
    fn new(input: &[u8]) -> Result<Self, Error> {
        if input.is_empty() || input.len() > 20 {
            return Err(Error::InvalidConfig);
        }
        let mut bytes = [0; 20];
        bytes[..input.len()].copy_from_slice(input);
        Ok(Self {
            bytes,
            len: input.len(),
        })
    }
    fn peer(input: &[u8]) -> Result<Self, Error> {
        if input.len() > 20 {
            return Err(Error::InvalidConfig);
        }
        let mut bytes = [0; 20];
        bytes[..input.len()].copy_from_slice(input);
        Ok(Self {
            bytes,
            len: input.len(),
        })
    }
    fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
/// A caller must report adapter acceptance or rejection before reusing this slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Transmit {
    // Opaque issued authority survives copying; changing public reporting fields
    // cannot turn an old output into a grant for a new reservation.
    authority: TransmitTicket,
    early: bool,
    pub connection_generation: u64,
    pub id: u64,
    pub len: usize,
    pub level: Level,
    pub packet_number: accounting::PacketNumber,
    pub ecn: Codepoint,
    /// Exact source/destination when opt-in path resources are configured.
    pub address: Option<crate::path::Address>,
}
impl Transmit {
    /// Actual wire protection. `level` identifies the shared CRYPTO/PN family;
    /// early data shares the application family but has distinct packet keys.
    pub fn encryption_level(self) -> EncryptionLevel {
        if self.early {
            EncryptionLevel::ZeroRtt
        } else {
            wire_level(self.level)
        }
    }
    pub fn is_early_data(self) -> bool {
        self.early
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Received {
    pub authenticated: usize,
    pub discarded: usize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerClose {
    pub error_code: u64,
    pub frame_type: Option<u64>,
    pub level: Level,
    pub protection: packet::EncryptionLevel,
}
struct Pending {
    close: Option<CloseTransmit>,
    output: Transmit,
    sent: SendReservation,
    path: PathReservation,
    ticket: TransmitTicket,
    crypto_len: usize,
    reference: Option<Reference>,
    was_probe: bool,
    handshake_done: bool,
    application_slot: Option<usize>,
    ping: bool,
    ack_largest: Option<u64>,
    ack_bits: u64,
    trace_key_generation: Option<u64>,
}
#[derive(Clone, Copy, Default)]
struct Seen {
    largest: Option<u64>,
    bits: u64,
    ack_pending: bool,
}
impl Seen {
    fn insert(&mut self, pn: u64) -> bool {
        match self.largest {
            None => {
                self.largest = Some(pn);
                self.bits = 1;
                true
            }
            Some(largest) if pn > largest => {
                let d = pn - largest;
                self.bits = if d >= 64 { 1 } else { (self.bits << d) | 1 };
                self.largest = Some(pn);
                true
            }
            Some(largest) => {
                let d = largest - pn;
                if d >= 64 {
                    return false;
                }
                let bit = 1u64 << d;
                if self.bits & bit != 0 {
                    false
                } else {
                    self.bits |= bit;
                    true
                }
            }
        }
    }
    fn ranges(&self, out: &mut [packet::AckRange; 32]) -> usize {
        let Some(largest) = self.largest else {
            return 0;
        };
        let mut n = 0;
        let mut bit = 0;
        while bit < 64 {
            if self.bits & (1u64 << bit) == 0 {
                bit += 1;
                continue;
            }
            let top = bit;
            while bit + 1 < 64 && self.bits & (1u64 << (bit + 1)) != 0 {
                bit += 1
            }
            out[n] = packet::AckRange {
                largest: largest - top,
                smallest: largest - bit,
            };
            n += 1;
            bit += 1;
        }
        n
    }
}
fn index(level: Level) -> usize {
    match level {
        Level::Initial => 0,
        Level::Handshake => 1,
        Level::OneRtt => 2,
    }
}
fn kind(level: Level) -> PacketKind {
    match level {
        Level::Initial => PacketKind::Initial,
        Level::Handshake => PacketKind::Handshake,
        Level::OneRtt => PacketKind::OneRtt,
    }
}
fn space(level: Level) -> PacketNumberSpace {
    kind(level).space()
}
fn wire_level(level: Level) -> EncryptionLevel {
    match level {
        Level::Initial => EncryptionLevel::Initial,
        Level::Handshake => EncryptionLevel::Handshake,
        Level::OneRtt => EncryptionLevel::OneRtt,
    }
}

/// Bounded history may no longer retain the ACK-largest exact timestamp.
/// Use an explicitly conservative upper bound for recovery discrimination,
/// never for RTT. Current time is the final upper bound on any prior accepted
/// send if no per-space history remains. Validated congestion is never dropped.
fn ecn_congestion_event<const N: usize>(
    cc: &mut recovery::NewReno,
    sent: &SentLedger<N>,
    largest: accounting::PacketNumber,
    now: u64,
) -> Result<bool, recovery::RecoveryError> {
    let upper_bound = sent.congestion_sent_at_upper_bound(largest).unwrap_or(now);
    cc.on_congestion_event(now, upper_bound)
}

/// One connection owner. All receive storage is borrowed from the caller; inline
/// bounded history and descriptor state are owned by this object. The provider's
/// allocation policy is explicit and is NOT inferred from this no_std core.
pub struct HandshakeEndpoint<
    'r,
    's,
    T: Provider,
    K: InitialKeyProtection = InitialProtection<'r, 's>,
> {
    side: Side,
    early: early::State<'s>,
    trace: Option<trace::State<'s>>,
    local: ConnectionId,
    original: ConnectionId,
    initial_destination: ConnectionId,
    client_retry: ClientRetry<MAX_RETRY_TOKEN_BYTES>,
    version_negotiation: Option<version_negotiation::Client>,
    retry_pending: bool,
    remote: ConnectionId,
    remote_known: bool,
    tls: T,
    initial: K,
    integrity: IntegrityBudget,
    driver: Driver<'r>,
    received: [Seen; 3],
    crypto: [CryptoBuffer<'s>; 3],
    offsets: [u64; 3],
    pending_crypto: [u8; 900],
    pending_tls: Option<tls::Output>,
    queued_flight: Option<FlightId>,
    flights: FlightStore<16, 900, 64>,
    probe: Option<FlightId>,
    now: u64,
    rtt: RttEstimator,
    recovery: RecoveryTimer,
    handshake_ack: bool,
    handshake_confirmed: bool,
    peer_limits: Option<crate::streams::Limits>,
    discarded: [bool; 2],
    discard_requested: [bool; 2],
    largest_acked: [Option<u64>; 3],
    loss_times: [Option<u64>; 3],
    peer_ack_exponent: u8,
    peer_max_ack_delay: u64,
    cc: recovery::NewReno,
    application_packets: [Option<ApplicationPacket>; 64],
    application_probe: bool,
    application_probe_permit: bool,
    crypto_probe_permit: bool,
    lost_application: [Option<u64>; 64],
    lost_head: usize,
    lost_len: usize,
    ping_probe: Option<Level>,
    handshake_done_pending: bool,
    handshake_done_flight: Option<FlightId>,
    pending: Option<Pending>,
    next_id: u64,
    sent: SentLedger<64>,
    path: path::Owner<'s>,
    ecn_enabled: bool,
    ecn_tx: PathEcn,
    ecn_rx: RxCounts,
    ecn_validated_ce: u64,
    ecn_congestion_events: u64,
    retired: bool,
    lifecycle: Lifecycle,
    idle: IdleTimeout,
    idle_configured: bool,
    io_started: bool,
    close_round: Option<(CloseTransmit, u8, bool)>,
    peer_close: Option<PeerClose>,
    parameters_verified: bool,
}
impl<'r, 's, T: Provider, K: InitialKeyProtection> HandshakeEndpoint<'r, 's, T, K> {
    /// The local advertised max_idle_timeout defaults to zero. If TLS advertises
    /// a nonzero value, call configure_idle_timeout with that exact value before
    /// any receive/transmit attempt. Peer parameters are installed after TLS authentication.
    /// `initial` must contain connected RX/TX actors for this side and the
    /// original destination CID. The endpoint never derives or borrows their keys.
    pub fn new(
        config: Config<'_>,
        tls: T,
        driver: Driver<'r>,
        crypto: [CryptoBuffer<'s>; 3],
        initial: K,
    ) -> Result<Self, Error> {
        Self::new_inner(config, tls, driver, crypto, None, initial)
    }
    /// Bootstrap a server only after its dispatcher authenticates and consumes a
    /// Retry token for this peer address and this Initial's source/destination CIDs.
    /// The dispatcher must preserve that peer-address binding on subsequent I/O.
    /// The supplied TLS provider must already advertise ODCID (TP 0), its Initial
    /// SCID (TP 15), and the token's Retry SCID (TP 16). The admission is affine.
    /// Initial actors must already own the keys derived from that Retry SCID.
    pub fn new_after_retry(
        config: Config<'_>,
        tls: T,
        driver: Driver<'r>,
        crypto: [CryptoBuffer<'s>; 3],
        admission: ValidatedToken,
        initial: K,
    ) -> Result<Self, Error> {
        if config.side != Side::Server
            || config.original_destination_id != admission.original_destination_id()
        {
            return Err(Error::InvalidConfig);
        }
        Self::new_inner(config, tls, driver, crypto, Some(admission), initial)
    }
    fn new_inner(
        config: Config<'_>,
        tls: T,
        driver: Driver<'r>,
        crypto: [CryptoBuffer<'s>; 3],
        admission: Option<ValidatedToken>,
        initial: K,
    ) -> Result<Self, Error> {
        if config.generation != driver.generation() || config.generation != initial.generation() {
            return Err(Error::InvalidConfig);
        }
        // RFC 9000 §7.2: only the client's first chosen DCID has this minimum;
        // a server-selected Retry/Initial SCID may be shorter or empty.
        if config.side == Side::Client && config.original_destination_id.len() < 8 {
            return Err(Error::InvalidConfig);
        }
        let local = ConnectionId::peer(config.local_id)?;
        let original = ConnectionId::new(config.original_destination_id)?;
        let initial_destination = ConnectionId::peer(
            admission
                .as_ref()
                .map_or(original.bytes(), ValidatedToken::retry_source_id),
        )?;
        let client_retry = ClientRetry::new(original.bytes(), local.bytes())?;
        let version_negotiation = if config.side == Side::Client {
            Some(
                version_negotiation::Client::new(original.bytes(), local.bytes())
                    .map_err(|_| Error::InvalidConfig)?,
            )
        } else {
            None
        };
        let remote = ConnectionId::peer(
            admission
                .as_ref()
                .map_or(original.bytes(), ValidatedToken::client_source_id),
        )?;
        let mut path = path::Owner::new(0, config.generation);
        if config.side == Side::Client || admission.is_some() {
            path.mark_validated()?;
        }
        Ok(Self {
            side: config.side,
            early: early::State::new(),
            trace: None,
            local,
            original,
            initial_destination,
            client_retry,
            version_negotiation,
            retry_pending: false,
            remote,
            remote_known: admission.is_some(),
            tls,
            initial,
            integrity: IntegrityBudget::new(),
            driver,
            received: [Seen::default(); 3],
            crypto,
            offsets: [0; 3],
            pending_crypto: [0; 900],
            pending_tls: None,
            queued_flight: None,
            flights: FlightStore::new(),
            probe: None,
            now: 0,
            rtt: RttEstimator::new(recovery::INITIAL_RTT_US)?,
            recovery: RecoveryTimer::new(),
            handshake_ack: false,
            handshake_confirmed: false,
            discarded: [false; 2],
            discard_requested: [false; 2],
            largest_acked: [None; 3],
            loss_times: [None; 3],
            peer_ack_exponent: 3,
            peer_max_ack_delay: 25_000,
            cc: recovery::NewReno::new(1200)?,
            peer_limits: None,
            application_packets: [None; 64],
            application_probe: false,
            application_probe_permit: false,
            crypto_probe_permit: false,
            lost_application: [None; 64],
            lost_head: 0,
            lost_len: 0,
            ping_probe: None,
            handshake_done_pending: false,
            handshake_done_flight: None,
            pending: None,
            next_id: 0,
            sent: SentLedger::new(config.generation),
            path,
            ecn_enabled: false,
            ecn_tx: PathEcn::new(PathIdentity {
                connection_generation: config.generation,
                slot: 0,
                path_generation: 0,
            }),
            ecn_rx: RxCounts::new(),
            ecn_validated_ce: 0,
            ecn_congestion_events: 0,
            retired: false,
            lifecycle: Lifecycle::new(config.generation),
            idle: IdleTimeout::new(config.generation, 0, 0, recovery::INITIAL_RTT_US)?,
            idle_configured: false,
            io_started: false,
            close_round: None,
            peer_close: None,
            parameters_verified: false,
        })
    }
    /// Configure the exact local max_idle_timeout advertised by the already-built
    /// TLS provider. Units are milliseconds; this does not rewrite TLS bytes.
    /// This explicit setup is required for nonzero local TP 1 because Provider
    /// exposes only peer parameters. It is one-shot and precedes every I/O attempt.
    pub fn configure_idle_timeout(&mut self, local_timeout_ms: u64) -> Result<(), Error> {
        if self.io_started
            || self.idle_configured
            || self.retired
            || self.lifecycle.state() != ConnectionState::Active
        {
            return Err(Error::InvalidConfig);
        }
        self.idle = IdleTimeout::new(
            self.generation(),
            local_timeout_ms,
            self.now,
            self.idle_pto()?,
        )?;
        self.idle_configured = true;
        Ok(())
    }
    pub fn idle_deadline(&self) -> Option<u64> {
        self.idle.deadline()
    }
    pub fn idle_timeout_ms(&self) -> u64 {
        self.idle.negotiated_timeout_ms()
    }
    pub fn idle_expired(&self) -> bool {
        self.idle.state() == idle::State::Expired
    }
    pub fn idle_deadline_token(&self) -> Option<idle::DeadlineToken> {
        self.idle.deadline_token()
    }
    // RFC 9000 section 10.1 uses the current PTO estimate, not the loss timer's
    // exponential backoff. Otherwise repeated unanswered probes could keep
    // extending their own idle expiry. max_ack_delay applies after confirmation.
    fn idle_pto(&self) -> Result<u64, Error> {
        Ok(self.rtt.pto_duration_us(
            if self.handshake_confirmed {
                self.peer_max_ack_delay
            } else {
                0
            },
            0,
        )?)
    }
    /// Check idle expiry before a wrapper rejects work as Busy. Expiry cancels
    /// any prepared output and silently retires this endpoint. Closing/draining
    /// are governed exclusively by their independent retention timer.
    pub fn poll_idle_timeout(&mut self, now: u64) -> Result<bool, Error> {
        if now < self.now {
            return Err(idle::Error::TimeWentBackwards.into());
        }
        if self.retired {
            return Ok(self.idle_expired());
        }
        if self.lifecycle.state() != ConnectionState::Active {
            return Ok(false);
        }
        let state = self.idle.poll(now, self.idle_pto()?)?;
        self.now = now;
        if state == idle::State::Expired {
            self.retire();
            return Ok(true);
        }
        Ok(false)
    }
    /// Dispatch an opaque queued idle timer. Invalid/early/stale descriptors do
    /// not advance the endpoint clock, send anything, or affect close retention.
    pub fn idle_timeout(&mut self, token: idle::DeadlineToken, now: u64) -> Result<(), Error> {
        let state = self.idle.on_timeout_token(token, now, self.idle_pto()?)?;
        self.now = now;
        if state == idle::State::Expired {
            self.retire();
        }
        Ok(())
    }
    pub fn version_negotiation_state(&self) -> Option<version_negotiation::ClientState> {
        self.version_negotiation
            .as_ref()
            .map(version_negotiation::Client::state)
    }
    pub fn retry_source_id(&self) -> Option<&[u8]> {
        if self.side == Side::Client {
            self.client_retry.retry_source_id()
        } else if self.initial_destination.bytes() != self.original.bytes() {
            Some(self.initial_destination.bytes())
        } else {
            None
        }
    }
    pub fn retry_token(&self) -> &[u8] {
        self.client_retry.token()
    }
    /// True only while a validated Retry awaits the outstanding adapter callback.
    pub const fn retry_is_pending(&self) -> bool {
        self.retry_pending
    }
    async fn apply_client_retry(&mut self) -> Result<(), Error> {
        if !self.retry_pending || self.pending.is_some() {
            return Ok(());
        }
        let source = self
            .client_retry
            .retry_source_id()
            .ok_or(Error::InvalidConfig)?;
        let destination = ConnectionId::peer(source)?;
        self.initial.rekey(source, self.side).await?;
        let rtt = RttEstimator::new(recovery::INITIAL_RTT_US)?;
        let cc = recovery::NewReno::new(1200)?;
        // There is no unreported adapter reference now. Retain CRYPTO and every
        // burned PN; Retry is neither an ACK nor a congestion-loss event.
        self.flights.requeue_space(PacketNumberSpace::Initial)?;
        self.sent.discard_space(PacketNumberSpace::Initial)?;
        self.retry_early_packets()?;
        self.initial_destination = destination;
        self.remote = destination;
        self.remote_known = false;
        self.received = [Seen::default(); 3];
        self.rtt = rtt;
        self.cc = cc;
        self.recovery = RecoveryTimer::new();
        self.largest_acked = [None; 3];
        self.loss_times = [None; 3];
        self.probe = None;
        self.crypto_probe_permit = false;
        self.ping_probe = None;
        self.retry_pending = false;
        Ok(())
    }
    fn key_pto(&self) -> Result<u64, Error> {
        Ok(self.rtt.pto_duration_us(self.peer_max_ack_delay, 0)?)
    }
    /// Request an authenticated QUIC application-key update. Pending adapter output
    /// must complete first so no old-key datagram crosses the local update boundary.
    pub fn initiate_key_update(&mut self) -> Result<(), Error> {
        if self.connection_state() != ConnectionState::Active {
            return Err(Error::Busy);
        }
        if self.is_retired() {
            return Err(Error::Retired);
        }
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        if !self.handshake_confirmed {
            return Err(tls::Error::KeyUpdateNotAllowed.into());
        }
        self.tls.initiate_key_update(self.now, self.key_pto()?)?;
        self.trace_event(crate::trace::Event::ApplicationKeyUpdated {
            owner: self.trace_vantage(),
            generation: self.tls.key_generation(),
            trigger: crate::trace::KeyUpdateTrigger::LocalUpdate,
        });
        Ok(())
    }
    /// Enable ECT probing before any packet is produced or authenticated.
    /// Received metadata feedback is supported independently of local marking.
    pub fn enable_ecn(&mut self) -> Result<(), Error> {
        if self.is_retired() {
            return Err(Error::Retired);
        }
        if self.next_id != 0 || self.received.iter().any(|s| s.largest.is_some()) {
            return Err(Error::InvalidConfig);
        }
        self.ecn_enabled = true;
        Ok(())
    }
    pub fn path_identity(&self) -> PathIdentity {
        self.path.identity()
    }
    pub fn ecn_snapshot(&self) -> ecn::Snapshot {
        let spaces = [
            PacketNumberSpace::Initial,
            PacketNumberSpace::Handshake,
            PacketNumberSpace::ApplicationData,
        ];
        ecn::Snapshot {
            enabled: self.ecn_enabled,
            state: self.ecn_tx.state(),
            failure: self.ecn_tx.failure(),
            sent: spaces.map(|s| self.sent.accepted_ecn_counts(s)),
            received: spaces.map(|s| self.ecn_rx.ack_counts(s)),
            validated_ce: self.ecn_validated_ce,
            congestion_events: self.ecn_congestion_events,
        }
    }
    pub fn tls(&self) -> &T {
        &self.tls
    }
    pub fn handshake_complete(&self) -> bool {
        self.connection_state() == ConnectionState::Active
            && !self.is_retired()
            && !self.tls.is_handshaking()
            && self.parameters_verified
    }
    pub fn congestion_window(&self) -> u64 {
        self.cc.congestion_window()
    }
    pub fn has_rtt_sample(&self) -> bool {
        self.rtt.first_sample_at().is_some()
    }
    pub fn bytes_in_flight(&self) -> u64 {
        self.sent.bytes_in_flight()
    }
    pub fn keys_discarded(&self, level: Level) -> bool {
        match level {
            Level::Initial => self.discarded[0],
            Level::Handshake => self.discarded[1],
            Level::OneRtt => false,
        }
    }
    pub fn side(&self) -> Side {
        self.side
    }
    pub fn generation(&self) -> u64 {
        self.driver.generation()
    }
    pub(crate) fn stream_retired(&mut self, id: u64) -> Result<(), Error> {
        if self.is_retired() {
            return Err(Error::Retired);
        }
        if let Err(error) = self.driver.stream_retired(id) {
            self.retire();
            return Err(error.into());
        }
        Ok(())
    }
    pub fn verified_peer_limits(&self) -> Option<crate::streams::Limits> {
        self.peer_limits
    }
    pub fn take_lost_application_packet(&mut self) -> Option<u64> {
        if self.lost_len == 0 {
            return None;
        }
        let pn = self.lost_application[self.lost_head].take();
        self.lost_head = (self.lost_head + 1) % 64;
        self.lost_len -= 1;
        pn
    }
    fn report_application_loss(&mut self, pn: u64) -> Result<(), Error> {
        if self.lost_len == 64 {
            return Err(Error::Capacity);
        }
        let at = (self.lost_head + self.lost_len) % 64;
        self.lost_application[at] = Some(pn);
        self.lost_len += 1;
        Ok(())
    }
    pub fn take_application_probe(&mut self) -> bool {
        core::mem::take(&mut self.application_probe)
    }
    pub fn peer_close(&self) -> Option<PeerClose> {
        self.peer_close
    }
    pub fn close_deadline(&self) -> Option<u64> {
        self.lifecycle.deadline()
    }
    pub fn connection_state(&self) -> ConnectionState {
        if self.retired {
            ConnectionState::Closed
        } else {
            self.lifecycle.state()
        }
    }
    pub fn close(&mut self, reason: CloseReason) -> Result<(), Error> {
        if self.retired {
            return Err(Error::Retired);
        }
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        if self
            .lifecycle
            .local_close(reason, self.now, self.key_pto()?)?
        {
            self.idle.stop();
            self.stop_ordinary_output()?;
        }
        Ok(())
    }
    fn stop_ordinary_output(&mut self) -> Result<(), Error> {
        if self.driver.is_early_key_installed() {
            self.driver.retire_early_key()?;
        }
        self.clear_early();
        self.close_round = None;
        self.discard_requested = [false; 2];
        self.flights.discard();
        for space in [
            PacketNumberSpace::Initial,
            PacketNumberSpace::Handshake,
            PacketNumberSpace::ApplicationData,
        ] {
            self.sent.discard_space(space)?;
        }
        self.pending_tls = None;
        self.queued_flight = None;
        self.probe = None;
        self.ping_probe = None;
        self.handshake_done_pending = false;
        self.handshake_done_flight = None;
        self.application_packets.fill(None);
        self.lost_application.fill(None);
        self.lost_len = 0;
        self.application_probe = false;
        self.application_probe_permit = false;
        self.crypto_probe_permit = false;
        for seen in &mut self.received {
            seen.ack_pending = false;
        }
        Ok(())
    }
    async fn enter_draining(&mut self) -> Result<(), Error> {
        self.idle.stop();
        self.lifecycle.on_peer_close(self.now, self.key_pto()?)?;
        if let Some(pending) = self.pending.take() {
            self.begin_network_result(&pending, false)?;
            self.sent.cancel(pending.sent)?;
            self.path.cancel(pending.path)?;
            if let Some(reference) = pending.reference {
                self.flights.cancelled(reference)?;
            }
            self.driver.adapter_result(pending.ticket)?;
        }
        self.stop_ordinary_output()?;
        for level in [Level::Handshake, Level::OneRtt] {
            if self.driver.is_key_installed(level) {
                self.driver.retire_key(level)?;
            }
        }
        self.initial.retire().await?;
        self.tls.discard_keys(Level::Handshake);
        self.tls.discard_keys(Level::OneRtt);
        self.discarded = [true; 2];
        self.driver.retire();
        Ok(())
    }
    /// Check immediately before synchronous adapter submission. Serialize this
    /// check/send with receive and timer calls. A result reports submission, not delivery.
    pub fn transmit_permitted(&mut self, output: Transmit, now: u64) -> Result<bool, Error> {
        let Some(pending) = self.pending.as_ref() else {
            return Ok(false);
        };
        if self.retired || pending.output != output {
            return Ok(false);
        }
        if let Some(token) = pending.close {
            let permitted = self.lifecycle.transmit_permitted(token, now)?;
            self.now = self.now.max(now);
            if self.lifecycle.state() == ConnectionState::Closed {
                self.retire();
            }
            return Ok(permitted);
        }
        if self.poll_idle_timeout(now)? {
            return Ok(false);
        }
        Ok(self.lifecycle.state() == ConnectionState::Active)
    }
    pub fn is_retired(&self) -> bool {
        self.retired || self.driver.is_retired()
    }
    pub fn retire(&mut self) {
        self.idle.stop();
        self.pending = None;
        self.pending_tls = None;
        self.close_round = None;
        self.retired = true;
        self.driver.retire();
        self.clear_early();
        self.initial.close();
        self.sent.retire();
        self.path.retire();
        self.flights.discard();
        self.tls.discard_keys(Level::Handshake);
        self.tls.discard_keys(Level::OneRtt);
    }
    /// Advance the injected monotonic clock and arm a bounded fresh-PN CRYPTO
    /// probe on PTO. A PTO does not declare every outstanding packet lost.
    pub fn timer(&mut self, now: u64) -> Result<(), Error> {
        if self.retired {
            return Err(Error::Retired);
        }
        if now < self.now {
            return Err(Error::Recovery(recovery::RecoveryError::TimeWentBackwards));
        }
        if self.lifecycle.state() != ConnectionState::Active {
            self.now = now;
            if self.lifecycle.state() == ConnectionState::Closing {
                self.driver.timer(now)?;
            }
            if self.lifecycle.on_timeout(now)? || self.lifecycle.state() == ConnectionState::Closed
            {
                self.retire();
            }
            return Ok(());
        }
        if self.poll_idle_timeout(now)? {
            return Ok(());
        }
        let timer = self.driver.timer_with_ticket(now)?;
        self.now = now;
        self.network_timeout(timer)?;
        if self.is_retired() {
            return Ok(());
        }
        self.tls.maintain_keys(now, self.key_pto()?)?;
        if let Some(action) = self.recovery.on_timeout(now)? {
            if let TimeoutAction::DetectLoss(_) = action {
                self.detect_losses()?;
            }
            if let TimeoutAction::Probe { space, .. } = action {
                if space == PacketNumberSpace::ApplicationData {
                    self.path.on_pto();
                }
                if self.probe.is_none() {
                    self.probe = self.flights.probe(space);
                    self.crypto_probe_permit = self.probe.is_some();
                }
                if space == PacketNumberSpace::ApplicationData
                    && self.application_packets.iter().any(Option::is_some)
                {
                    self.application_probe = true;
                    self.application_probe_permit = true;
                } else if self.probe.is_none() {
                    self.ping_probe = Some(match space {
                        PacketNumberSpace::Initial => Level::Initial,
                        PacketNumberSpace::Handshake => Level::Handshake,
                        PacketNumberSpace::ApplicationData => Level::OneRtt,
                    });
                }
            }
            self.refresh_timer()?;
        }
        Ok(())
    }
    pub fn next_deadline(&self) -> Option<u64> {
        if self.retired {
            return None;
        }
        if self.lifecycle.state() != ConnectionState::Active {
            return self.lifecycle.next_deadline();
        }
        let network = if self.handshake_confirmed && self.pending.is_none() {
            let can_prepare = self.sent.remaining_capacity() > 0
                && self.cc.can_send(
                    self.network_bytes_in_flight(),
                    self.sent.reserved_in_flight(),
                    50,
                    true,
                    false,
                );
            self.path.network_deadline(can_prepare)
        } else {
            None
        };
        [
            self.recovery.deadline().map(|d| d.at),
            self.idle.deadline(),
            network,
        ]
        .into_iter()
        .flatten()
        .min()
    }
    fn timer_context(&self) -> TimerContext {
        TimerContext {
            is_server: self.side == Side::Server,
            handshake_confirmed: self.handshake_confirmed,
            handshake_ack_received: self.handshake_ack,
            server_amplification_blocked: self.side == Side::Server
                && self.path.available_bytes() == 0,
        }
    }
    fn refresh_timer(&mut self) -> Result<(), Error> {
        if self.poll_idle_timeout(self.now)? {
            return Ok(());
        }
        if self.lifecycle.state() != ConnectionState::Active {
            return Ok(());
        }
        let spaces = core::array::from_fn(|i| {
            let level = [Level::Initial, Level::Handshake, Level::OneRtt][i];
            let at = self
                .sent
                .outstanding_sent()
                .filter(|p| {
                    p.packet.space == space(level)
                        && p.ack_eliciting
                        && self.path.matches_active(p.path)
                })
                .map(|p| p.sent_at)
                .max()
                // An abandoned STREAM original can remain unacknowledged while
                // the replacement path has no in-flight data. Retain a PTO
                // source so its owned bytes can be probed under a fresh PN on
                // the active path, without importing old RTT/CC evidence.
                .or_else(|| {
                    self.sent
                        .outstanding_sent()
                        .filter(|p| p.packet.space == space(level) && p.ack_eliciting)
                        .map(|p| p.sent_at)
                        .max()
                });
            SpaceTimer {
                keys_available: if i == 0 {
                    !self.discarded[0]
                } else {
                    self.tls.has_keys(level)
                },
                loss_time: self.loss_times[i],
                ack_eliciting_in_flight: at.is_some(),
                last_ack_eliciting_sent_at: at,
            }
        });
        self.recovery.update(
            self.now,
            &self.rtt,
            &spaces,
            self.timer_context(),
            self.peer_max_ack_delay,
        )?;
        Ok(())
    }

    fn sync_key_authority(&mut self) -> Result<(), Error> {
        for level in [Level::Handshake, Level::OneRtt] {
            if self.tls.has_keys(level) && !self.driver.is_key_installed(level) {
                self.driver
                    .install_key(level)
                    .map_err(|error| Error::KeyAuthority {
                        stage: KeyStage::Install,
                        level,
                        error,
                    })?;
                if level == Level::OneRtt {
                    self.trace_event(crate::trace::Event::ApplicationKeyUpdated {
                        owner: self.trace_vantage(),
                        generation: self.tls.key_generation(),
                        trigger: crate::trace::KeyUpdateTrigger::Tls,
                    });
                    self.trace_event(crate::trace::Event::ApplicationKeyUpdated {
                        owner: self.trace_peer_vantage(),
                        generation: self.tls.receive_key_generation(),
                        trigger: crate::trace::KeyUpdateTrigger::Tls,
                    });
                }
            }
        }
        self.sync_early_authority()
    }
    async fn apply_key_discards(&mut self) -> Result<(), Error> {
        if self.lifecycle.state() != ConnectionState::Active {
            return Ok(());
        }
        for i in 0..2 {
            let level = if i == 0 {
                Level::Initial
            } else {
                Level::Handshake
            };
            if !self.discard_requested[i]
                || self.discarded[i]
                || self
                    .pending
                    .as_ref()
                    .is_some_and(|p| p.output.level == level)
            {
                continue;
            }
            self.sent.discard_space(space(level))?;
            self.flights.discard_space(space(level))?;
            self.recovery.on_keys_discarded(space(level))?;
            if i == 0 {
                self.initial.retire().await?;
            } else {
                self.driver
                    .retire_key(level)
                    .map_err(|error| Error::KeyAuthority {
                        stage: KeyStage::Retire,
                        level,
                        error,
                    })?;
                self.tls.discard_keys(level);
            }
            self.received[i].ack_pending = false;
            self.loss_times[i] = None;
            if self.probe.is_some_and(|p| self.flights.data(p).is_err()) {
                self.probe = None;
            }
            if self.ping_probe == Some(level) {
                self.ping_probe = None;
            }
            self.discarded[i] = true;
        }
        Ok(())
    }
    fn detect_losses(&mut self) -> Result<(), Error> {
        self.loss_times = [None; 3];
        let mut records = [None; 64];
        for (i, p) in self.sent.outstanding_sent().enumerate() {
            records[i] = Some(p);
        }
        for packet in records.into_iter().flatten() {
            let i = packet.packet.space as usize;
            let largest_on_path = self
                .path
                .largest_ack_on_path(&packet, self.largest_acked[i]);
            let decision = recovery::loss_decision(
                &self.rtt,
                recovery::LossCandidate {
                    packet_number: packet.packet.value,
                    sent_at: packet.sent_at,
                    newer_sent_packets: largest_on_path.map_or(0, |n| {
                        if self.path.managed() {
                            packet.path.map_or(0, |path| {
                                self.sent.count_later_sent_on_path(packet.packet, n, path)
                            })
                        } else {
                            self.sent.count_later_sent(packet.packet, n)
                        }
                    }),
                },
                largest_on_path,
                self.now,
            )?;
            match decision {
                recovery::LossDecision::Lost => {
                    if let accounting::LossOutcome::NewlyLost {
                        bytes_removed_from_flight,
                    } = self.sent.declare_lost(packet.packet)?
                    {
                        if let Some(kind) = self.sent.sent_kind(packet.packet) {
                            self.trace_event(crate::trace::Event::PacketLost {
                                header: crate::trace::PacketHeader {
                                    packet_type: match kind {
                                        PacketKind::Initial => crate::trace::PacketType::Initial,
                                        PacketKind::Handshake => {
                                            crate::trace::PacketType::Handshake
                                        }
                                        PacketKind::ZeroRtt => crate::trace::PacketType::ZeroRtt,
                                        PacketKind::OneRtt => crate::trace::PacketType::OneRtt,
                                    },
                                    packet_number: Some(packet.packet.value),
                                    key_phase: None,
                                },
                                // loss_decision does not expose its winning cause.
                                trigger: None,
                            });
                        } else if let Some(trace) = self.trace.as_mut() {
                            trace.observation_lost(crate::trace::Error::InvalidHeader);
                        }
                        if matches!(packet.ecn, Codepoint::Ect0 | Codepoint::Ect1)
                            && packet.path == Some(self.ecn_tx.identity())
                        {
                            self.ecn_tx.lost(self.ecn_tx.identity(), 1)?;
                        }
                        if bytes_removed_from_flight > 0 && self.path.matches_active(packet.path) {
                            self.cc.on_congestion_event(self.now, packet.sent_at)?;
                        }
                        self.flights.mark_lost(packet.packet);
                        self.path.on_lost(packet.packet);
                        if packet.packet.space == PacketNumberSpace::ApplicationData {
                            let mut found = false;
                            for r in &mut self.application_packets {
                                if r.is_some_and(|r| r.number == packet.packet.value) {
                                    *r = None;
                                    found = true;
                                }
                            }
                            if found {
                                self.report_application_loss(packet.packet.value)?;
                            }
                        }
                    }
                }
                recovery::LossDecision::WaitUntil(at) => {
                    self.loss_times[i] = Some(self.loss_times[i].map_or(at, |old| old.min(at)));
                }
                recovery::LossDecision::NotEligible => {}
            }
        }
        for space in [
            PacketNumberSpace::Initial,
            PacketNumberSpace::Handshake,
            PacketNumberSpace::ApplicationData,
        ] {
            self.sent.reclaim_completed_prefix(space)?;
        }
        Ok(())
    }

    /// Process bounded packets. Corruption/unknown keys/duplicates are discarded,
    /// not Hibana faults. Authenticated protocol errors retire this connection.
    pub async fn receive(
        &mut self,
        datagram: &[u8],
        scratch: &mut [u8],
    ) -> Result<Received, Error> {
        if self.retired {
            return Err(Error::Retired);
        }
        self.receive_with(datagram, scratch, &mut NoApplication)
            .await
    }
    pub async fn receive_with<A: ApplicationHandler>(
        &mut self,
        datagram: &[u8],
        scratch: &mut [u8],
        handler: &mut A,
    ) -> Result<Received, Error> {
        self.receive_with_metadata(
            datagram,
            scratch,
            ecn::Metadata {
                path: self.path_identity(),
                codepoint: None,
            },
            handler,
        )
        .await
    }
    async fn receive_with_metadata_impl<A: ApplicationHandler>(
        &mut self,
        datagram: &[u8],
        scratch: &mut [u8],
        metadata: ecn::Metadata,
        handler: &mut A,
    ) -> Result<Received, Error> {
        if !self.path.ready_ingress() {
            return Err(Error::InvalidConfig);
        }
        if self.retired {
            return Err(Error::Retired);
        }
        if self.poll_idle_timeout(self.now)? {
            return Err(Error::Retired);
        }
        self.io_started = true;
        if self.lifecycle.state() == ConnectionState::Draining {
            return Ok(Received {
                authenticated: 0,
                discarded: 1,
            });
        }
        if metadata.path != self.path_identity() {
            return Ok(Received {
                authenticated: 0,
                discarded: 1,
            });
        }
        // Application output owns the current write-key generation until the
        // adapter reports acceptance or rejection. Defer input (without mutation
        // or retirement) so an authenticated peer update cannot invalidate bytes
        // prepared but not yet submitted. The caller retains and retries input.
        if self
            .pending
            .as_ref()
            .is_some_and(|p| p.output.level == Level::OneRtt)
        {
            return Err(Error::Busy);
        }
        if self.retry_pending {
            // The already-validated Retry is retained. Old-key peer data cannot
            // overtake the adapter completion and restart boundary.
            return Ok(Received {
                authenticated: 0,
                discarded: 1,
            });
        }
        let result = self
            .receive_inner(datagram, scratch, metadata.codepoint, handler)
            .await;
        if result.is_err() {
            self.retire();
        } else if !self.retired {
            self.refresh_timer()?;
        }
        result
    }
    async fn receive_inner<A: ApplicationHandler>(
        &mut self,
        datagram: &[u8],
        scratch: &mut [u8],
        received_ecn: Option<Codepoint>,
        handler: &mut A,
    ) -> Result<Received, Error> {
        self.tls.maintain_keys(self.now, self.key_pto()?)?;
        self.path.record_received(datagram.len() as u64)?;
        let mut report = Received::default();
        let packets = match PacketIter::new(datagram, self.local.len, 8) {
            Ok(p) => p,
            Err(_) => {
                report.discarded += 1;
                return Ok(report);
            }
        };
        for packet in packets {
            // Preserve the estimate at packet arrival while ACK processing may
            // change RTT. A valid packet renews activity before applying that
            // updated floor, so an RTT decrease cannot retroactively expire it.
            let receive_pto = self.idle_pto()?;
            let packet = match packet {
                Ok(p) => p,
                Err(_) => {
                    report.discarded += 1;
                    break;
                }
            };
            if matches!(packet.header, Header::VersionNegotiation { .. }) {
                if self.lifecycle.state() == ConnectionState::Active
                    && let Some(client) = &mut self.version_negotiation
                    && client.on_packet(packet.bytes) == version_negotiation::ClientAction::Abandon
                {
                    // The wrapper retires on this explicit unprotected indication.
                    // It is not a TLS alert, authenticated peer error or retry.
                    return Err(Error::VersionNegotiationNoCommonVersion);
                }
                report.discarded += 1;
                continue;
            }
            if matches!(packet.header, Header::Retry { .. }) {
                if self.side != Side::Client {
                    report.discarded += 1;
                    continue;
                }
                if self.lifecycle.state() != ConnectionState::Active {
                    report.discarded += 1;
                    continue;
                }
                match self.client_retry.validate(packet.bytes, scratch) {
                    Ok(checked) => {
                        self.client_retry.commit(checked)?;
                        if let Some(client) = &mut self.version_negotiation {
                            client.on_peer_processed();
                        }
                        self.retry_pending = true;
                        self.apply_client_retry().await?;
                    }
                    Err(_) => report.discarded += 1,
                }
                continue;
            }
            if matches!(
                packet.header,
                Header::Long {
                    kind: LongType::ZeroRtt,
                    ..
                }
            ) {
                let receive_pto = self.idle_pto()?;
                if self
                    .receive_early(packet, scratch, received_ecn, handler)
                    .await?
                {
                    self.idle.on_processed_receive(self.now, receive_pto)?;
                    report.authenticated += 1;
                } else {
                    report.discarded += 1;
                }
                continue;
            }
            let (level, pn_offset, source, destination) = match packet.header {
                Header::Long {
                    kind: LongType::Initial,
                    packet_number_offset,
                    source_id,
                    destination_id,
                    ..
                } => {
                    if self.side == Side::Server && datagram.len() < 1200 {
                        report.discarded += 1;
                        continue;
                    }
                    (
                        Level::Initial,
                        packet_number_offset,
                        Some(source_id),
                        destination_id,
                    )
                }
                Header::Long {
                    kind: LongType::Handshake,
                    packet_number_offset,
                    source_id,
                    destination_id,
                    ..
                } => (
                    Level::Handshake,
                    packet_number_offset,
                    Some(source_id),
                    destination_id,
                ),
                Header::Short {
                    packet_number_offset,
                    destination_id,
                } => (Level::OneRtt, packet_number_offset, None, destination_id),
                _ => {
                    report.discarded += 1;
                    continue;
                }
            };
            if (if self.path.managed() {
                !self.path.accepts_destination(destination)
            } else {
                destination != self.local.bytes()
            }) && !(self.side == Side::Server
                && level == Level::Initial
                && destination == self.initial_destination.bytes())
            {
                report.discarded += 1;
                continue;
            }
            if packet.bytes.len() > scratch.len()
                || (level == Level::Initial && packet.bytes.len() > INITIAL_PACKET_BYTES)
            {
                report.discarded += 1;
                continue;
            }
            if (level == Level::Initial && self.discarded[0])
                || (level == Level::OneRtt && self.tls.is_handshaking())
                || (level != Level::Initial && !self.tls.has_keys(level))
            {
                report.discarded += 1;
                continue;
            }
            let bytes = &mut scratch[..packet.bytes.len()];
            bytes.copy_from_slice(packet.bytes);
            let sample_start = pn_offset.checked_add(4).ok_or(Error::Capacity)?;
            let Some(sample) = bytes.get(sample_start..sample_start + 16) else {
                report.discarded += 1;
                continue;
            };
            let sample: &[u8; 16] = sample.try_into().map_err(|_| Error::Capacity)?;
            self.sync_key_authority()?;
            let key_use = if level == Level::Initial {
                None
            } else {
                Some(
                    self.driver
                        .begin_key_use(level)
                        .map_err(|error| Error::KeyAuthority {
                            stage: KeyStage::Use,
                            level,
                            error,
                        })?,
                )
            };
            let mask = if level == Level::Initial {
                self.initial.receive_mask(*sample).await?
            } else {
                self.tls.header_mask(level, false, sample)?
            };
            bytes[0] ^= mask[0] & if bytes[0] & 0x80 != 0 { 0x0f } else { 0x1f };
            let pn_len = usize::from((bytes[0] & 3) + 1);
            if pn_offset + pn_len > bytes.len() {
                self.finish_provider_key_use(key_use)
                    .map_err(|error| Error::KeyAuthority {
                        stage: KeyStage::Complete,
                        level,
                        error,
                    })?;
                report.discarded += 1;
                continue;
            }
            for i in 0..pn_len {
                bytes[pn_offset + i] ^= mask[i + 1];
            }
            let (truncated, _) =
                packet::decode_truncated_packet_number(bytes[0], &bytes[pn_offset..])?;
            let pn = match packet::restore_packet_number(
                truncated,
                pn_len as u8,
                self.received[index(level)].largest,
            ) {
                Ok(pn) => pn,
                Err(_) => {
                    self.finish_provider_key_use(key_use)
                        .map_err(|error| Error::KeyAuthority {
                            stage: KeyStage::Complete,
                            level,
                            error,
                        })?;
                    report.discarded += 1;
                    continue;
                }
            };
            let first = bytes[0];
            let (header, body) = bytes.split_at_mut(pn_offset + pn_len);
            let previous_receive_generation = self.tls.receive_key_generation();
            let previous_write_generation = self.tls.key_generation();
            let mut received_key_generation = 0;
            let plaintext = if level == Level::Initial {
                match self.open_initial(pn, header, body).await {
                    Ok(n) => n,
                    Err(Error::Crypto(crypto::Error::AuthenticationFailed)) => {
                        self.finish_provider_key_use(key_use).map_err(|error| {
                            Error::KeyAuthority {
                                stage: KeyStage::Complete,
                                level,
                                error,
                            }
                        })?;
                        report.discarded += 1;
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            } else {
                let opened = if level == Level::OneRtt {
                    self.tls
                        .open_one_rtt(
                            pn,
                            first & 0x04 != 0,
                            header,
                            body,
                            self.now,
                            self.key_pto()?,
                        )
                        .map(|opened| {
                            received_key_generation = opened.generation;
                            opened.len
                        })
                } else {
                    self.tls.open(level, pn, header, body)
                };
                match opened {
                    Ok(n) => n,
                    Err(tls::Error::Authentication | tls::Error::KeysUnavailable) => {
                        self.finish_provider_key_use(key_use).map_err(|error| {
                            Error::KeyAuthority {
                                stage: KeyStage::Complete,
                                level,
                                error,
                            }
                        })?;
                        report.discarded += 1;
                        continue;
                    }
                    Err(e) => return Err(e.into()),
                }
            };
            self.finish_provider_key_use(key_use)
                .map_err(|error| Error::KeyAuthority {
                    stage: KeyStage::Complete,
                    level,
                    error,
                })?;
            if level == Level::OneRtt
                && self.tls.receive_key_generation() > previous_receive_generation
            {
                self.trace_event(crate::trace::Event::ApplicationKeyUpdated {
                    owner: self.trace_peer_vantage(),
                    generation: self.tls.receive_key_generation(),
                    trigger: crate::trace::KeyUpdateTrigger::RemoteUpdate,
                });
            }
            if level == Level::OneRtt && self.tls.key_generation() > previous_write_generation {
                self.trace_event(crate::trace::Event::ApplicationKeyUpdated {
                    owner: self.trace_vantage(),
                    generation: self.tls.key_generation(),
                    trigger: crate::trace::KeyUpdateTrigger::RemoteUpdate,
                });
            }
            self.trace_event(crate::trace::Event::Packet {
                direction: crate::trace::Direction::Received,
                header: crate::trace::PacketHeader {
                    packet_type: match level {
                        Level::Initial => crate::trace::PacketType::Initial,
                        Level::Handshake => crate::trace::PacketType::Handshake,
                        Level::OneRtt => crate::trace::PacketType::OneRtt,
                    },
                    packet_number: Some(pn),
                    key_phase: (level == Level::OneRtt).then_some(received_key_generation),
                },
                datagram_id: None,
            });
            // RFC 9000 §12.4: a successfully authenticated packet must contain
            // at least one frame. Reject before CID/replay/receive authority state.
            if plaintext == 0 {
                if self.lifecycle.state() == ConnectionState::Closing {
                    self.lifecycle.on_attributed_packet(self.now)?;
                    report.discarded += 1;
                    continue;
                }
                return Err(Error::ProtocolViolation);
            }
            if level == Level::OneRtt && !self.parameters_verified {
                report.discarded += 1;
                continue;
            }
            if let Err(error) = packet::validate_reserved_bits(first) {
                if self.lifecycle.state() == ConnectionState::Closing {
                    self.lifecycle.on_attributed_packet(self.now)?;
                    report.discarded += 1;
                    continue;
                }
                return Err(error.into());
            }
            if let Some(source) = source {
                if source.len() > 20 {
                    return Err(Error::InvalidConfig);
                }
                if self.remote_known && source != self.remote.bytes() {
                    report.discarded += 1;
                    continue;
                }
                self.remote = ConnectionId::peer(source)?;
                self.remote_known = true;
            }
            if !self
                .path
                .source_allowed(self.side, self.handshake_confirmed)
            {
                report.discarded += 1;
                continue;
            }
            // Authentication precedes both duplicate state and the typed contract.
            let payload = &body[..plaintext];
            let limits = ParseLimits {
                max_bytes: 65535,
                max_frames: 128,
                max_ack_ranges: 32,
            };
            if self.lifecycle.state() == ConnectionState::Closing {
                let mut peer_close = None;
                let mut malformed = false;
                match FrameIter::new(payload, wire_level(level), limits) {
                    Ok(frames) => {
                        for frame in frames {
                            match frame {
                                Ok(Frame::ConnectionClose {
                                    error_code,
                                    frame_type,
                                    ..
                                }) => {
                                    peer_close.get_or_insert(PeerClose {
                                        error_code,
                                        frame_type,
                                        level,
                                        protection: wire_level(level),
                                    });
                                }
                                Err(_) => {
                                    malformed = true;
                                    break;
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(_) => malformed = true,
                }
                if peer_close.is_some() && !malformed {
                    self.peer_close = peer_close;
                    self.enter_draining().await?;
                } else {
                    self.lifecycle.on_attributed_packet(self.now)?;
                }
                report.authenticated += 1;
                return Ok(report);
            }
            let mut eliciting = false;
            let mut non_probing = false;
            for frame in FrameIter::new(payload, wire_level(level), limits)? {
                let frame = frame?;
                eliciting |= frame.ack_eliciting();
                non_probing |= !frame.probing();
            }
            if !self.received[index(level)].insert(pn) {
                if eliciting {
                    self.received[index(level)].ack_pending = true;
                }
                report.discarded += 1;
                continue;
            }
            let ticket = self.driver.begin_receive()?;
            let path_pto = self.key_pto()?;
            self.path.ensure_probe_pto(path_pto)?;
            let network_context = if self.path.managed() {
                Some(self.path.admit_packet(
                    destination,
                    pn,
                    non_probing,
                    datagram.len() as u64,
                    self.now,
                )?)
            } else {
                None
            };
            self.finish_network_admission(ticket)?;
            for frame in FrameIter::new(payload, wire_level(level), limits)? {
                let frame = frame?;
                if let Some(context) = network_context
                    && self.process_network_frame(ticket, frame, context)?
                {
                    continue;
                }
                match frame {
                    Frame::Crypto { offset, data } => {
                        self.crypto[index(level)].insert(offset, data)?;
                        loop {
                            let (a, b) = self.crypto[index(level)].ready();
                            let bytes = if !a.is_empty() { a } else { b };
                            if bytes.is_empty() {
                                break;
                            }
                            let n = bytes.len();
                            self.tls.receive(level, bytes)?;
                            self.crypto[index(level)].consume(n)?;
                            self.sync_key_authority()?;
                        }
                    }
                    Frame::Ack { ranges, delay, ecn } => {
                        let mut converted = [accounting::AckRange { start: 0, end: 0 }; 32];
                        let n = ranges.len();
                        for (i, r) in ranges.iter().enumerate() {
                            converted[n - 1 - i] = accounting::AckRange {
                                start: r.smallest,
                                end: r.largest,
                            };
                        }
                        let largest = converted[n - 1].end;
                        let largest_packet = accounting::PacketNumber {
                            space: space(level),
                            value: largest,
                        };
                        let largest_new = self.sent.is_new_ack(largest_packet);
                        let sent_at = self.sent.sent_at(largest_packet);
                        let largest_on_active_path = self
                            .path
                            .matches_active(self.sent.sent_path(largest_packet))
                            && (!self.path.managed()
                                || network_context.is_none_or(|context| {
                                    context.path == self.path.active_identity()
                                }));
                        let mut newly_flight = [None; 64];
                        let mut added = 0;
                        for p in self.sent.unacknowledged_sent() {
                            if p.packet.space == space(level)
                                && ranges.iter().any(|r| {
                                    r.smallest <= p.packet.value && p.packet.value <= r.largest
                                })
                            {
                                newly_flight[added] = Some(p);
                                added += 1;
                            }
                        }
                        let any_eliciting = newly_flight.iter().flatten().any(|p| p.ack_eliciting);
                        self.sent.validate_ack(space(level), &converted[..n])?;
                        let ack_authority = self.driver.begin_ack_release(ticket)?;
                        for packet in newly_flight.iter().flatten() {
                            self.path.observe_ack(packet);
                        }
                        let newly_active = newly_flight
                            .iter()
                            .flatten()
                            .any(|p| self.path.matches_active(p.path));
                        if level == Level::OneRtt {
                            self.path.on_ack(ranges)?;
                        }
                        if level == Level::OneRtt {
                            for sent in newly_flight.iter().flatten() {
                                // A 1-RTT ACK can acknowledge shared-space 0-RTT
                                // packets, which must not authorize a key update.
                                if self.sent.sent_kind(sent.packet) != Some(PacketKind::OneRtt) {
                                    continue;
                                }
                                self.tls.acknowledge_one_rtt(
                                    sent.packet.value,
                                    received_key_generation,
                                    self.now,
                                    self.key_pto()?,
                                )?;
                            }
                        }
                        let mut marked = MarkedPackets::default();
                        for p in newly_flight.iter().flatten() {
                            match p.ecn {
                                Codepoint::Ect0 => marked.ect0 += 1,
                                Codepoint::Ect1 => marked.ect1 += 1,
                                _ => {}
                            }
                        }
                        if self.ecn_enabled
                            && self.path.active_identity() == self.ecn_tx.identity()
                            && let ecn::Feedback::Validated { ce_increase } =
                                self.ecn_tx.acknowledged(
                                    self.path_identity(),
                                    space(level),
                                    largest,
                                    marked,
                                    ecn,
                                )?
                        {
                            self.ecn_validated_ce = self
                                .ecn_validated_ce
                                .checked_add(ce_increase)
                                .ok_or(Error::Capacity)?;
                            if ce_increase > 0
                                && ecn_congestion_event(
                                    &mut self.cc,
                                    &self.sent,
                                    largest_packet,
                                    self.now,
                                )?
                            {
                                self.ecn_congestion_events = self
                                    .ecn_congestion_events
                                    .checked_add(1)
                                    .ok_or(Error::Capacity)?;
                            }
                        }
                        let summary = self.sent.acknowledge(space(level), &converted[..n])?;
                        if level == Level::OneRtt {
                            handler.acknowledged(ranges).map_err(Error::Streams)?;
                            for record in &mut self.application_packets {
                                if record.is_some_and(|r| {
                                    ranges
                                        .iter()
                                        .any(|a| a.smallest <= r.number && r.number <= a.largest)
                                }) {
                                    *record = None;
                                }
                            }
                        }
                        if let Some(sent_at) = sent_at
                            && largest_new
                            && largest_on_active_path
                            && any_eliciting
                        {
                            self.rtt.on_ack(RttSample {
                                now: self.now,
                                sent_at,
                                ack_delay_us: delay.saturating_mul(1u64 << self.peer_ack_exponent),
                                max_ack_delay_us: self.peer_max_ack_delay,
                                space: space(level),
                                handshake_confirmed: self.handshake_confirmed,
                                largest_newly_acknowledged: true,
                                any_newly_acknowledged_ack_eliciting: true,
                                local_decryption_delay_us: 0,
                            })?;
                        }
                        for p in newly_flight.into_iter().flatten() {
                            if p.in_flight && self.path.matches_active(p.path) {
                                self.cc.on_ack(self.now, p.sent_at, p.bytes, false)?;
                            }
                        }
                        self.largest_acked[index(level)] = Some(
                            self.largest_acked[index(level)]
                                .map_or(largest, |old| old.max(largest)),
                        );
                        self.flights.acknowledge(space(level), &converted[..n]);
                        self.detect_losses()?;
                        if level == Level::Handshake && summary.newly_acknowledged > 0 {
                            self.handshake_ack = true;
                        }
                        self.recovery.on_new_ack(
                            summary.newly_acknowledged > 0 && newly_active,
                            self.timer_context().peer_completed_address_validation(),
                        );
                        self.sent.reclaim_completed_prefix(space(level))?;
                        self.driver.finish_ack_release(ack_authority)?;
                    }
                    Frame::Padding { .. } | Frame::Ping => {}
                    Frame::HandshakeDone if self.side == Side::Client && level == Level::OneRtt => {
                        self.handshake_confirmed = true;
                        self.tls.confirm_handshake()?;
                        self.discard_requested[1] = true;
                    }
                    // These optional post-handshake frames require no immediate
                    // effect for the handshake-only endpoint. No stream API exists.
                    Frame::NewConnectionId { .. } if level == Level::OneRtt => {}
                    Frame::NewToken { .. }
                        if level == Level::OneRtt && self.side == Side::Client => {}
                    Frame::ConnectionClose {
                        error_code,
                        frame_type,
                        ..
                    } => {
                        self.peer_close = Some(PeerClose {
                            error_code,
                            frame_type,
                            level,
                            protection: wire_level(level),
                        });
                        self.driver.finish_receive(ticket)?;
                        self.enter_draining().await?;
                        report.authenticated += 1;
                        return Ok(report);
                    }
                    other @ (Frame::Stream { id, .. } | Frame::ResetStream { id, .. })
                        if level == Level::OneRtt =>
                    {
                        let delivery = self.driver.begin_stream_delivery(ticket, id)?;
                        handler.frame(other).map_err(Error::Streams)?;
                        self.driver.finish_stream_delivery(delivery)?;
                    }
                    other if level == Level::OneRtt => {
                        handler.frame(other).map_err(Error::Streams)?
                    }
                    _ => return Err(Error::UnexpectedFrame),
                }
            }
            self.ecn_rx.processed(space(level), received_ecn)?;
            if level == Level::OneRtt
                && let Some(context) = network_context
            {
                self.network_packet_processed(ticket, context, pn, non_probing)?;
            }
            self.driver.finish_receive(ticket)?;
            if eliciting {
                self.received[index(level)].ack_pending = true;
            }
            if self.side == Side::Server && level == Level::Handshake {
                self.path.mark_validated()?;
                self.discard_requested[0] = true;
            }
            if self.side == Side::Client && level == Level::Initial {
                self.client_retry.on_server_initial_processed();
            }
            report.authenticated += 1;
            if let Some(client) = &mut self.version_negotiation {
                client.on_peer_processed();
            }
            self.idle.on_processed_receive(self.now, receive_pto)?;
            self.validate_parameters()?;
            self.reconcile_early_client(handler)?;
            self.release_early(handler)?;
            if level == Level::OneRtt && self.side == Side::Server && self.tls.has_early_keys() {
                self.tls.discard_early_keys();
                if self.driver.is_early_key_installed() {
                    self.driver.retire_early_key()?;
                }
            }
            self.apply_key_discards().await?;
        }
        Ok(report)
    }
    fn validate_parameters(&mut self) -> Result<(), Error> {
        if self.tls.is_handshaking() || self.parameters_verified {
            return Ok(());
        }
        let raw = self
            .tls
            .peer_transport_parameters()
            .ok_or(Error::InvalidConfig)?;
        let peer = if self.side == Side::Client {
            Peer::Server
        } else {
            Peer::Client
        };
        let p = Parameters::parse(raw, peer, &mut [0; 64])?;
        let original = if self.side == Side::Client {
            Some(self.original.bytes())
        } else {
            None
        };
        let retry = if self.side == Side::Client {
            self.client_retry.retry_source_id()
        } else {
            None
        };
        p.verify_connection_ids(self.remote.bytes(), original, retry)?;
        self.path
            .install_parameters(&p, self.remote.bytes(), self.side)?;
        self.peer_ack_exponent = p.get_integer(10, 3)? as u8;
        self.peer_max_ack_delay = p
            .get_integer(11, 25)?
            .checked_mul(1000)
            .ok_or(Error::InvalidConfig)?;
        self.peer_limits = Some(crate::streams::Limits {
            max_data: p.get_integer(4, 0)?,
            stream_data_bidi_local: p.get_integer(5, 0)?,
            stream_data_bidi_remote: p.get_integer(6, 0)?,
            stream_data_uni: p.get_integer(7, 0)?,
            max_streams_bidi: p.get_integer(8, 0)?,
            max_streams_uni: p.get_integer(9, 0)?,
        });
        let peer_idle_timeout = p.get_integer(1, 0)?;
        self.idle
            .negotiate_peer(peer_idle_timeout, self.now, self.idle_pto()?)?;
        self.parameters_verified = true;
        if self.side == Side::Server {
            self.handshake_confirmed = true;
            self.tls.confirm_handshake()?;
            self.handshake_done_pending = true;
            self.discard_requested[1] = true;
        }
        Ok(())
    }

    /// Produce one standard protected QUIC datagram. At most one unreported
    /// transmission exists. Failed adapter submission retains TLS bytes for retry
    /// under a new PN; accepted packets are never rolled back.
    async fn transmit_impl(&mut self, out: &mut [u8]) -> Result<Option<Transmit>, Error> {
        if self.poll_idle_timeout(self.now)? {
            return Err(Error::Retired);
        }
        self.io_started = true;
        if self.retired {
            return Err(Error::Retired);
        }
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        if out.len() < 1200 {
            return Err(Error::Capacity);
        }
        if self.lifecycle.state() == ConnectionState::Draining {
            return Ok(None);
        }
        let result = if self.lifecycle.state() == ConnectionState::Closing {
            self.transmit_close(out).await
        } else {
            match self.transmit_inner(out, None, None).await {
                Ok(None) => self.transmit_network_control(out).await,
                result => result,
            }
        };
        if result.is_err() {
            self.retire();
        }
        result
    }
    /// Encoded application frames still pass normal key, reservation, path and
    /// Hibana publication gates. Drain transmit() handshake/control output first.
    async fn transmit_application_impl(
        &mut self,
        encoded_frames: &[u8],
        out: &mut [u8],
    ) -> Result<Option<Transmit>, Error> {
        if self.retired {
            return Err(Error::Retired);
        }
        if self.poll_idle_timeout(self.now)? {
            return Err(Error::Retired);
        }
        self.io_started = true;
        if !self.handshake_complete()
            || self.pending.is_some()
            || self.pending_tls.is_some()
            || self.probe.is_some()
            || self.lost_len > 0
        {
            return Err(Error::Busy);
        }
        if out.len() < 1200
            || encoded_frames.is_empty()
            || encoded_frames.len() > MAX_APPLICATION_FRAME_BYTES
        {
            return Err(Error::Capacity);
        }
        for frame in FrameIter::new(
            encoded_frames,
            EncryptionLevel::OneRtt,
            ParseLimits::default(),
        )? {
            match frame? {
                Frame::Stream { .. }
                | Frame::ResetStream { .. }
                | Frame::StopSending { .. }
                | Frame::MaxData { .. }
                | Frame::MaxStreamData { .. }
                | Frame::MaxStreams { .. }
                | Frame::DataBlocked { .. }
                | Frame::StreamDataBlocked { .. }
                | Frame::StreamsBlocked { .. } => {}
                _ => return Err(Error::UnexpectedFrame),
            }
        }
        let result = self.transmit_inner(out, Some(encoded_frames), None).await;
        if result.is_err() {
            self.retire();
        }
        result
    }
    async fn transmit_close(&mut self, out: &mut [u8]) -> Result<Option<Transmit>, Error> {
        if self.close_round.is_none() {
            let mut levels = 0_u8;
            if self.tls.has_keys(Level::OneRtt) && !self.tls.is_handshaking() {
                levels |= 4;
            }
            if !self.handshake_confirmed {
                if self.tls.has_keys(Level::Handshake) {
                    levels |= 2;
                }
                if !self.discarded[0] && (self.side == Side::Server || levels == 0) {
                    levels |= 1;
                }
            }
            if levels == 0 {
                self.retire();
                return Ok(None);
            }
            let Some(token) = self.lifecycle.poll_transmit(self.now)? else {
                if self.lifecycle.state() == ConnectionState::Closed {
                    self.retire();
                }
                return Ok(None);
            };
            self.close_round = Some((token, levels, false));
        }
        let (token, levels, accepted) = self.close_round.ok_or(Error::InvalidConfig)?;
        let level = if levels & 4 != 0 {
            Level::OneRtt
        } else if levels & 2 != 0 {
            Level::Handshake
        } else {
            Level::Initial
        };
        let mut encoded = [0; 160];
        let frame = self
            .lifecycle
            .reason()
            .ok_or(Error::InvalidConfig)?
            .frame(level);
        let len = packet::encode_frame(&frame, &mut encoded)?;
        let result = self
            .transmit_inner(out, None, Some((level, &encoded[..len])))
            .await?;
        if result.is_some() {
            self.pending.as_mut().ok_or(Error::InvalidConfig)?.close = Some(token);
        } else {
            self.close_round = None;
            self.lifecycle.adapter_result(token, accepted, self.now)?;
        }
        Ok(result)
    }
    async fn transmit_inner(
        &mut self,
        out: &mut [u8],
        application: Option<&[u8]>,
        closing: Option<(Level, &[u8])>,
    ) -> Result<Option<Transmit>, Error> {
        self.path.reset_staged_advertisement();
        if self.probe.is_none() {
            self.probe = self.flights.next_lost();
        }
        if self.probe.is_some_and(|id| self.flights.data(id).is_err()) {
            self.probe = None;
        }
        if closing.is_none()
            && application.is_none()
            && self.pending_tls.is_none()
            && self.probe.is_none()
        {
            self.pending_tls = self.tls.transmit(&mut self.pending_crypto)?;
        }
        if let Some(output) = self.pending_tls
            && self.queued_flight.is_none()
        {
            if output.len == 0 || output.len > self.pending_crypto.len() {
                return Err(Error::InvalidConfig);
            }
            match self.flights.append(
                output.level,
                self.offsets[index(output.level)],
                &self.pending_crypto[..output.len],
            ) {
                Ok(id) => self.queued_flight = Some(id),
                Err(flights::Error::Full) => {}
                Err(e) => return Err(e.into()),
            }
        }
        if self.handshake_done_pending && self.handshake_done_flight.is_none() {
            match self.flights.append_handshake_done() {
                Ok(id) => self.handshake_done_flight = Some(id),
                Err(flights::Error::Full) => {}
                Err(e) => return Err(e.into()),
            }
        }
        let selected = if closing.is_some() {
            None
        } else {
            self.probe
                .or(self.queued_flight)
                .or(if self.handshake_done_pending {
                    self.handshake_done_flight
                } else {
                    None
                })
        };
        let was_probe = closing.is_none() && self.probe.is_some();
        let level = if let Some((level, _)) = closing {
            level
        } else if application.is_some() {
            Level::OneRtt
        } else if let Some(id) = selected {
            self.flights.data(id)?.0
        } else if let Some(level) = self.ping_probe {
            level
        } else {
            let Some(i) = self.received.iter().enumerate().find_map(|(i, s)| {
                if s.ack_pending
                    && ((i == 0 && !self.discarded[0])
                        || self.tls.has_keys(if i == 1 {
                            Level::Handshake
                        } else {
                            Level::OneRtt
                        }))
                {
                    Some(i)
                } else {
                    None
                }
            }) else {
                return Ok(None);
            };
            [Level::Initial, Level::Handshake, Level::OneRtt][i]
        };
        if closing.is_none() && level == Level::OneRtt && self.tls.is_handshaking() {
            return Ok(None);
        }
        let mut plaintext = [0_u8; 1200];
        let mut len = 0;
        let mut ack_largest = None;
        let mut ack_bits = 0;
        let seen = &self.received[index(level)];
        if closing.is_none() && seen.ack_pending {
            let mut ranges = [packet::AckRange {
                smallest: 0,
                largest: 0,
            }; 32];
            let n = seen.ranges(&mut ranges);
            if n > 0 {
                len += packet::encode_frame(
                    &Frame::Ack {
                        delay: 0,
                        ranges: AckRanges::new(&ranges[..n])?,
                        ecn: self.ecn_rx.ack_counts(space(level)),
                    },
                    &mut plaintext[len..],
                )?;
                ack_largest = seen.largest;
                ack_bits = seen.bits;
            }
        }
        let ack_len = len;
        let handshake_done =
            selected.is_some_and(|id| self.flights.is_handshake_done(id).unwrap_or(false));
        let crypto_len = if let Some(id) = selected {
            let (_, offset, data) = self.flights.data(id)?;
            if handshake_done {
                len += packet::encode_frame(&Frame::HandshakeDone, &mut plaintext[len..])?;
                0
            } else {
                self.path.stage_crypto_advertisement(level, offset, data)?;
                len +=
                    packet::encode_frame(&Frame::Crypto { offset, data }, &mut plaintext[len..])?;
                if Some(id) == self.queued_flight {
                    data.len()
                } else {
                    0
                }
            }
        } else {
            0
        };
        let ping = closing.is_none()
            && application.is_none()
            && selected.is_none()
            && self.ping_probe == Some(level);
        if ping {
            len += packet::encode_frame(&Frame::Ping, &mut plaintext[len..])?;
        }
        let application_slot = if let Some(encoded) = application {
            let Some(slot) = self.application_packets.iter().position(Option::is_none) else {
                return Ok(None);
            };
            if len + encoded.len() > plaintext.len() {
                return Err(Error::Capacity);
            }
            plaintext[len..len + encoded.len()].copy_from_slice(encoded);
            len += encoded.len();
            Some(slot)
        } else {
            None
        };
        if let Some((_, encoded)) = closing {
            plaintext[..encoded.len()].copy_from_slice(encoded);
            len = encoded.len();
        }
        let pn = self
            .sent
            .next_packet_number(space(level))
            .ok_or(Error::Capacity)?;
        // A zero-length peer CID is a legal wire destination on its fixed
        // address-bound path; it is not a member of the nonzero CID table.
        let selected_destination = self.path.selected_destination();
        let destination = selected_destination
            .as_ref()
            .map_or(self.remote.bytes(), |cid| cid.as_bytes());
        let hlen = if level == Level::OneRtt {
            packet::encode_short_header(
                &ShortHeader {
                    destination_id: destination,
                    packet_number: pn,
                    packet_number_len: 4,
                    spin: false,
                    key_phase: self.tls.key_phase(),
                },
                out,
            )?
        } else {
            let header = LongHeader {
                kind: if level == Level::Initial {
                    LongType::Initial
                } else {
                    LongType::Handshake
                },
                destination_id: destination,
                source_id: self.local.bytes(),
                token: if level == Level::Initial && self.side == Side::Client {
                    self.client_retry.token()
                } else {
                    &[]
                },
                packet_number: pn,
                packet_number_len: 4,
            };
            let mut hlen = packet::encode_long_header(&header, len + 16, out)?;
            if level == Level::Initial {
                hlen = packet::encode_long_header(&header, 1200 - hlen, out)?;
                hlen = packet::encode_long_header(&header, 1200 - hlen, out)?;
            }
            hlen
        };
        if level == Level::Initial {
            let padded = 1200usize.checked_sub(hlen + 16).ok_or(Error::Capacity)?;
            if len > padded && ack_len > 0 && len - ack_len <= padded {
                // Keep the whole CRYPTO fragment and defer the ACK; never trim a
                // frame or fail a previously admitted Retry on ACK overhead.
                plaintext.copy_within(ack_len..len, 0);
                len -= ack_len;
                ack_largest = None;
                ack_bits = 0;
            }
            if len > padded {
                return Err(Error::Capacity);
            }
            plaintext[len..padded].fill(0);
            len = padded;
        }
        if hlen + len + 16 > out.len() || len > plaintext.len() {
            return Err(Error::Capacity);
        }
        if let Some(total) = self.path.control_padding() {
            let padded = total.checked_sub(hlen + 16).ok_or(Error::Capacity)?;
            if len > padded || padded > plaintext.len() {
                return Err(Error::Capacity);
            }
            plaintext[len..padded].fill(0);
            len = padded;
        }
        let internal_eliciting = if let Some((level, bytes)) = closing {
            let mut eliciting = false;
            for frame in FrameIter::new(bytes, wire_level(level), ParseLimits::default())? {
                eliciting |= frame?.ack_eliciting();
            }
            eliciting
        } else {
            false
        };
        let total = hlen + len + 16;
        let in_flight = internal_eliciting
            || selected.is_some()
            || handshake_done
            || application.is_some()
            || ping
            || level == Level::Initial;
        if !self.cc.can_send(
            self.network_bytes_in_flight(),
            self.sent.reserved_in_flight(),
            total as u64,
            in_flight,
            (was_probe && self.crypto_probe_permit)
                || ping
                || (application.is_some() && self.application_probe_permit),
        ) {
            return Ok(None);
        }
        let path = match self.path.reserve(total as u64) {
            Ok(p) => p,
            Err(accounting::AccountingError::AmplificationLimited) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let reservation = match self.sent.reserve_classified(
            kind(level),
            total as u64,
            internal_eliciting
                || selected.is_some()
                || handshake_done
                || application.is_some()
                || ping
                || level == Level::Initial,
            internal_eliciting
                || selected.is_some()
                || handshake_done
                || application.is_some()
                || ping,
        ) {
            Ok(r) => r,
            Err(accounting::AccountingError::Full) => {
                self.path.cancel(path)?;
                return Ok(None);
            }
            Err(e) => {
                self.path.cancel(path)?;
                return Err(e.into());
            }
        };
        let reference = if let Some(id) = selected {
            match self.flights.reserve(id, reservation.packet()) {
                Ok(r) => Some(r),
                Err(flights::Error::Full) => {
                    self.sent.cancel(reservation)?;
                    self.sent.reclaim_completed_prefix(space(level))?;
                    self.path.cancel(path)?;
                    return Ok(None);
                }
                Err(e) => return Err(e.into()),
            }
        } else {
            None
        };
        let ticket = self.driver.reserve_transmit()?;
        self.bind_network_transmit(ticket, path)?;
        self.sync_key_authority()?;
        let key_use = if level == Level::Initial {
            None
        } else {
            Some(
                self.driver
                    .begin_key_use(level)
                    .map_err(|error| Error::KeyAuthority {
                        stage: KeyStage::Use,
                        level,
                        error,
                    })?,
            )
        };
        out[hlen..hlen + len].copy_from_slice(&plaintext[..len]);
        let (header, body) = out[..total].split_at_mut(hlen);
        if level == Level::Initial {
            self.initial.seal(pn, header, body, len).await?;
        } else {
            self.tls.seal(level, pn, header, body, len)?;
        }
        let pn_offset = hlen - 4;
        let sample: &[u8; 16] = out[pn_offset + 4..pn_offset + 20]
            .try_into()
            .map_err(|_| Error::Capacity)?;
        let mask = if level == Level::Initial {
            self.initial.transmit_mask(*sample).await?
        } else {
            self.tls.header_mask(level, true, sample)?
        };
        out[0] ^= mask[0] & if out[0] & 0x80 != 0 { 0x0f } else { 0x1f };
        for i in 0..4 {
            out[pn_offset + i] ^= mask[i + 1];
        }
        self.finish_provider_key_use(key_use)
            .map_err(|error| Error::KeyAuthority {
                stage: KeyStage::Complete,
                level,
                error,
            })?;
        let output = Transmit {
            authority: ticket,
            early: false,
            address: self.transmit_address(),
            connection_generation: self.generation(),
            id: self.next_id,
            len: total,
            level,
            packet_number: reservation.packet(),
            ecn: self.transmit_ecn()?,
        };
        self.next_id = self.next_id.checked_add(1).ok_or(Error::Capacity)?;
        let trace_key_generation = (level == Level::OneRtt).then(|| self.tls.key_generation());
        self.pending = Some(Pending {
            trace_key_generation,
            close: None,
            output,
            sent: reservation,
            path,
            ticket,
            crypto_len,
            reference,
            was_probe,
            handshake_done,
            application_slot,
            ping,
            ack_largest,
            ack_bits,
        });
        Ok(Some(output))
    }
    async fn adapter_result_impl(
        &mut self,
        output: Transmit,
        accepted: bool,
        now: u64,
    ) -> Result<(), Error> {
        if self.retired {
            return Err(Error::Retired);
        }
        let pending = self.pending.as_ref().ok_or(Error::InvalidConfig)?;
        if pending.output.authority != output.authority || pending.output != output {
            return Err(Error::InvalidConfig);
        }
        let trace_key_generation = pending.trace_key_generation;
        if accepted {
            self.trace_event_at(
                now,
                crate::trace::Event::Packet {
                    direction: crate::trace::Direction::Sent,
                    header: crate::trace::PacketHeader {
                        packet_type: match output.encryption_level() {
                            EncryptionLevel::Initial => crate::trace::PacketType::Initial,
                            EncryptionLevel::Handshake => crate::trace::PacketType::Handshake,
                            EncryptionLevel::ZeroRtt => crate::trace::PacketType::ZeroRtt,
                            EncryptionLevel::OneRtt => crate::trace::PacketType::OneRtt,
                        },
                        packet_number: Some(output.packet_number.value),
                        key_phase: trace_key_generation,
                    },
                    datagram_id: None,
                },
            );
        }
        if self.poll_idle_timeout(now)? {
            return Err(Error::Retired);
        }
        let pending = self.pending.take().ok_or(Error::InvalidConfig)?;
        let outcome = async {
            let network_accepted = self.begin_network_result(&pending, accepted)?;
            if accepted {
                let sent_path = self.path.reservation_identity(pending.path);
                self.sent
                    .adapter_accepted_on_path(pending.sent, now, output.ecn, sent_path)?;
                if output.level == Level::Initial
                    && !output.early
                    && let Some(client) = &mut self.version_negotiation
                {
                    client.on_initial_accepted();
                }
                let ack_eliciting = self
                    .sent
                    .sent_packet(output.packet_number)
                    .ok_or(Error::InvalidConfig)?
                    .ack_eliciting;
                self.idle
                    .on_accepted_send(ack_eliciting, now, self.idle_pto()?)?;
                if sent_path == self.ecn_tx.identity() {
                    self.ecn_tx.accepted(
                        sent_path,
                        output.packet_number,
                        output.ecn,
                        now,
                        self.key_pto()?,
                    )?;
                }
                self.path.adapter_accepted(pending.path, now)?;
                if let Some(slot) = pending.application_slot {
                    self.application_packets[slot] = Some(ApplicationPacket {
                        number: output.packet_number.value,
                        early: output.early,
                    });
                    self.application_probe_permit = false;
                }
                if pending.ping {
                    self.ping_probe = None;
                }
                if let Some(reference) = pending.reference {
                    self.flights.accepted(reference, now)?;
                }
                if pending.was_probe {
                    self.probe = None;
                    self.crypto_probe_permit = false;
                }
                if pending.handshake_done {
                    self.handshake_done_pending = false;
                }
                if pending.crypto_len > 0 {
                    self.offsets[index(output.level)] = self.offsets[index(output.level)]
                        .checked_add(pending.crypto_len as u64)
                        .filter(|n| *n <= packet::MAX_VARINT)
                        .ok_or(Error::Capacity)?;
                    self.pending_tls = None;
                    self.queued_flight = None;
                }
                let seen = &mut self.received[index(output.level)];
                if pending.ack_largest == seen.largest && pending.ack_bits == seen.bits {
                    seen.ack_pending = false;
                }
            } else {
                self.sent.cancel(pending.sent)?;
                self.path.cancel(pending.path)?;
                if let Some(reference) = pending.reference {
                    self.flights.cancelled(reference)?;
                }
            }
            self.finish_network_result(&pending, network_accepted)?;
            self.driver.adapter_result(pending.ticket)?;
            if let Some(token) = pending.close {
                let (round, mut levels, prior_accepted) =
                    self.close_round.take().ok_or(Error::InvalidConfig)?;
                if round != token {
                    return Err(Error::InvalidConfig);
                }
                if accepted {
                    levels &= !(1 << index(output.level));
                }
                if accepted && levels != 0 {
                    self.close_round = Some((token, levels, true));
                } else {
                    self.lifecycle
                        .adapter_result(token, accepted || prior_accepted, now)?;
                }
            }
            self.sent.reclaim_completed_prefix(space(output.level))?;
            self.now = self.now.max(now);
            if accepted && self.side == Side::Client && output.level == Level::Handshake {
                self.discard_requested[0] = true;
            }
            self.apply_client_retry().await?;
            self.apply_key_discards().await?;
            self.refresh_timer()?;
            Ok(())
        }
        .await;
        if outcome.is_err() {
            self.retire();
        }
        outcome
    }
}

#[cfg(test)]
mod ecn_history_tests {
    use super::*;
    const APP: PacketNumberSpace = PacketNumberSpace::ApplicationData;
    const PATH: PathIdentity = PathIdentity {
        connection_generation: 7,
        slot: 0,
        path_generation: 0,
    };
    fn counts(ect0: u64, ce: u64) -> Option<packet::EcnCounts> {
        Some(packet::EcnCounts { ect0, ect1: 0, ce })
    }
    fn accept(
        ledger: &mut SentLedger<4>,
        path: &mut PathEcn,
        at: u64,
        in_flight: bool,
    ) -> accounting::PacketNumber {
        let reserved = ledger.reserve(PacketKind::OneRtt, 40, in_flight).unwrap();
        ledger
            .adapter_accepted_ecn(reserved, at, Codepoint::Ect0)
            .unwrap();
        path.accepted(PATH, reserved.packet(), Codepoint::Ect0, at, 100)
            .unwrap();
        reserved.packet()
    }
    #[test]
    fn reclaimed_ack_only_and_lost_ce_react_without_fabricated_exact_time() {
        let mut ledger = SentLedger::<4>::new(7);
        let mut path = PathEcn::new(PATH);
        let mut cc = recovery::NewReno::new(1200).unwrap();
        let initial = accept(&mut ledger, &mut path, 1, true);
        path.acknowledged(
            PATH,
            APP,
            initial.value,
            MarkedPackets { ect0: 1, ect1: 0 },
            counts(1, 0),
        )
        .unwrap();
        ledger
            .acknowledge(
                APP,
                &[accounting::AckRange {
                    start: initial.value,
                    end: initial.value,
                }],
            )
            .unwrap();
        ledger.reclaim_completed_prefix(APP).unwrap();
        let ack_only = accept(&mut ledger, &mut path, 10, false);
        ledger.reclaim_completed_prefix(APP).unwrap();
        assert_eq!(ledger.sent_at(ack_only), None);
        assert_eq!(ledger.congestion_sent_at_upper_bound(ack_only), Some(10));
        assert_eq!(
            path.acknowledged(
                PATH,
                APP,
                ack_only.value,
                MarkedPackets::default(),
                counts(1, 1)
            )
            .unwrap(),
            ecn::Feedback::Validated { ce_increase: 1 }
        );
        assert!(ecn_congestion_event(&mut cc, &ledger, ack_only, 20).unwrap());
        let reduced = cc.congestion_window();
        assert_eq!(
            path.acknowledged(
                PATH,
                APP,
                ack_only.value,
                MarkedPackets::default(),
                counts(1, 1)
            )
            .unwrap(),
            ecn::Feedback::Reordered
        );
        assert!(!ecn_congestion_event(&mut cc, &ledger, ack_only, 21).unwrap());
        assert_eq!(cc.congestion_window(), reduced);

        let later = accept(&mut ledger, &mut path, 30, false);
        ledger.reclaim_completed_prefix(APP).unwrap();
        assert_eq!(
            path.acknowledged(
                PATH,
                APP,
                later.value,
                MarkedPackets::default(),
                counts(1, 2)
            )
            .unwrap(),
            ecn::Feedback::Validated { ce_increase: 1 }
        );
        assert!(ecn_congestion_event(&mut cc, &ledger, later, 40).unwrap());
        assert!(cc.congestion_window() < reduced);

        let lost = accept(&mut ledger, &mut path, 50, true);
        ledger.declare_lost(lost).unwrap();
        cc.on_congestion_event(60, 50).unwrap();
        ledger.reclaim_completed_prefix(APP).unwrap();
        assert_eq!(ledger.sent_at(lost), None);
        assert_eq!(
            path.acknowledged(
                PATH,
                APP,
                lost.value,
                MarkedPackets::default(),
                counts(1, 3)
            )
            .unwrap(),
            ecn::Feedback::Validated { ce_increase: 1 }
        );
        // This congestion was already covered by the actual loss response.
        assert!(!ecn_congestion_event(&mut cc, &ledger, lost, 70).unwrap());
    }
    #[test]
    fn unknown_history_uses_explicit_conservative_now_bound() {
        let ledger = SentLedger::<1>::new(7);
        let mut cc = recovery::NewReno::new(1200).unwrap();
        let unknown = accounting::PacketNumber {
            space: APP,
            value: 0,
        };
        assert!(ecn_congestion_event(&mut cc, &ledger, unknown, 10).unwrap());
        assert_eq!(cc.recovery_started(), Some(10));
        assert_eq!(ledger.sent_at(unknown), None);
    }
}
