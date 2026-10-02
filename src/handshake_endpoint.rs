//! Experimental, real encrypted QUIC v1 handshake transport.
//!
//! Owns authenticated packet processing, CRYPTO/control recovery, congestion
//! accounting and typed Hibana authority. `TransportEndpoint` adds bounded streams.
//! Initial keys and the whole TLS Provider are owned by separate projected
//! async roles. Packet protection, CRYPTO processing, key maintenance and key
//! retirement are genuinely awaited; no Provider or key handle lives here.
//! Recovery, streams and Path/CID state live in independent projected owners;
//! this coordinator retains only affine clients, bounded packets and observations.
//! Retry and explicit close/draining are integrated; provider resumption is
//! supported. Migration and automatic fatal-error close reporting remain incomplete. Allocation
//! policy depends on the selected provider; the bounded backend and allocating
//! Rustls reference backend have separate evidence.
mod recovery_actor;
pub use recovery_actor::{
    PacketAuthority, RecoveryClient, RecoveryExchange, RecoveryOwner, RecoverySnapshot,
};
mod stream_actor;
pub use stream_actor::{STREAM_FRAME_BYTES, StreamClient, StreamCommand, StreamOutcome};
mod tls_actor;
mod tx_actor;
pub use tls_actor::{TLS_PACKET_BYTES, TLS_PARAMETER_BYTES, TlsClient, TlsSnapshot};
mod initial;
pub use initial::{
    INITIAL_PACKET_BYTES, InitialKeyClient, InitialKeyProtection, InitialProtection,
};
mod path;
pub use path::{
    NetworkConfig, NetworkError, NetworkRandom, NetworkReceiveContext, NetworkResources,
    PreferredServer,
};
mod trace;
pub use trace::{TraceSetupError, TraceStatus};
mod early;
pub use early::{
    EARLY_COMMAND_BYTES, EARLY_CONTROL_BYTES, EARLY_REQUEST_BYTES, EarlyClient, EarlyExchange,
    EarlyStarter, EarlyStorage,
};

use crate::{
    accounting::{self, PacketKind, PacketNumberSpace},
    crypto::{self},
    ecn::{self, Codepoint, PathIdentity, RxCounts},
    flights::{self, FlightId},
    handshake::{self, CryptoBuffer},
    idle::{self, IdleTimeout},
    lifecycle::{self, CloseReason, CloseTransmit, Lifecycle, State as ConnectionState},
    packet::{
        self, AckRanges, EncryptionLevel, Frame, FrameIter, Header, LongHeader, LongType,
        PacketIter, ParseLimits, ShortHeader,
    },
    parameters::{Parameters, Peer},
    recovery::{self, TimeoutAction, TimerContext},
    retry::{self, ClientRetry, ValidatedToken},
    tls::{self, Level},
    version_negotiation,
};

#[cfg(test)]
use crate::{
    accounting::SentLedger,
    ecn::{MarkedPackets, PathEcn},
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
#[derive(Debug)]
pub enum Error {
    EarlyControl(crate::early_control::Error),
    Network(NetworkError),
    InvalidConfig,
    /// Unauthenticated VN omitted the sole supported version. No restart occurs.
    VersionNegotiationNoCommonVersion,
    Early(crate::early_data::Error),
    EarlyOwner(crate::roles::early_owner::ServiceError),
    EarlyOwnerFault(crate::roles::early_owner::Fault),
    ConnectionAuthority(crate::roles::connection_authority::Error),
    Lifecycle(lifecycle::Error),
    Idle(idle::Error),
    Ecn(ecn::Error),
    Retired,
    Busy,
    Retry(retry::Error),
    Capacity,
    Datagram(crate::roles::datagram::Error),
    UdpSubmission(crate::roles::path_owner::SubmitError),
    UnexpectedFrame,
    ProtocolViolation,
    Streams(crate::streams::Error),
    StreamOwner(crate::roles::stream_owner::ClientError),
    Flight(flights::Error),
    Recovery(recovery::RecoveryError),
    RecoveryOwner(crate::roles::recovery_owner::ClientError),
    RecoveryRejected(crate::roles::recovery_owner::Rejection),
    PacketAuthority(crate::roles::packet_authority::Error),
    Wire(packet::Error),
    Crypto(crypto::Error),
    /// The key-role service failed. The connection is terminal after this error.
    Protection(crate::roles::client::Error),
    TlsOwner(crate::roles::tls_owner::ClientError),
    IntegrityLoanUnavailable,
    Tls(tls::Error),
    Accounting(accounting::AccountingError),
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
impl From<crate::roles::recovery_owner::ClientError> for Error {
    fn from(error: crate::roles::recovery_owner::ClientError) -> Self {
        Self::RecoveryOwner(error)
    }
}
impl From<crate::roles::packet_authority::Error> for Error {
    fn from(error: crate::roles::packet_authority::Error) -> Self {
        Self::PacketAuthority(error)
    }
}
impl From<crate::roles::stream_owner::ClientError> for Error {
    fn from(error: crate::roles::stream_owner::ClientError) -> Self {
        Self::StreamOwner(error)
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
impl From<crate::roles::tls_owner::ClientError> for Error {
    fn from(error: crate::roles::tls_owner::ClientError) -> Self {
        Self::TlsOwner(error)
    }
}
impl From<accounting::AccountingError> for Error {
    fn from(e: accounting::AccountingError) -> Self {
        Self::Accounting(e)
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

#[derive(Clone, Copy, Debug)]
pub struct Config<'a> {
    pub side: Side,
    pub local_id: &'a [u8],
    pub original_destination_id: &'a [u8],
    /// Must match every connected owner and remain unique while old callbacks can exist.
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
/// Observation returned after actual adapter submission and every owner settlement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Transmit {
    early: bool,
    pub connection_generation: u64,
    pub id: u64,
    pub len: usize,
    pub level: Level,
    pub packet_number: accounting::PacketNumber,
    pub ecn: Codepoint,
    pub accepted_at: Option<u64>,
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
#[cfg(test)]
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
pub struct HandshakeEndpoint<'r, 's, 'tc, 'ts, K: InitialKeyProtection = InitialProtection<'r, 's>>
{
    side: Side,
    early: Option<early::EarlyClient<'tc, 'ts>>,
    early_starter: Option<early::EarlyStarter<'tc, 'ts>>,
    early_last: Option<crate::roles::early_owner::Snapshot>,
    trace: Option<trace::State<'s>>,
    local: ConnectionId,
    original: ConnectionId,
    initial_destination: ConnectionId,
    client_retry: ClientRetry<MAX_RETRY_TOKEN_BYTES>,
    version_negotiation: Option<version_negotiation::Client>,
    retry_grants: Option<crate::roles::packet_authority::RetryGrants>,
    retry_admission: Option<ValidatedToken>,
    remote: ConnectionId,
    remote_known: bool,
    tls: Option<TlsClient<'tc, 'ts>>,
    tls_last: TlsSnapshot,
    stream: Option<StreamClient<'tc, 'ts>>,
    stream_last: crate::roles::stream_owner::Snapshot,
    finished_receipt: Option<crate::roles::tls_owner::FinishedReceipt>,
    initial: K,
    initial_lifetime: core::marker::PhantomData<&'r ()>,
    received: [Seen; 3],
    crypto: [CryptoBuffer<'s>; 3],
    offsets: [u64; 3],
    pending_crypto: [u8; 900],
    pending_tls: Option<tls::Output>,
    queued_flight: Option<FlightId>,
    probe: Option<FlightId>,
    now: u64,
    recovery: Option<RecoveryClient<'tc, 'ts>>,
    recovery_last: RecoverySnapshot,
    authority: &'tc PacketAuthority,
    early_rejection: Option<crate::roles::tls_owner::EarlyRejectedGrant>,
    early_ready: Option<crate::roles::connection_authority::EarlyReady>,
    handshake_ack: bool,
    handshake_confirmed: bool,
    peer_limits: Option<crate::streams::Limits>,
    discarded: [bool; 2],
    discard_requested: [bool; 2],
    peer_ack_exponent: u8,
    peer_max_ack_delay: u64,
    ping_probe: Option<Level>,
    handshake_done_pending: bool,
    handshake_done_flight: Option<FlightId>,
    next_id: u64,
    path: Option<path::PathClient<'tc, 'ts>>,
    path_last: crate::roles::path_owner::Snapshot,
    ingress_address: Option<crate::path::Address>,
    path_datagram_id: u64,
    ecn_enabled: bool,
    ecn_rx: RxCounts,
    retired: bool,
    lifecycle: Lifecycle,
    idle: IdleTimeout,
    idle_configured: bool,
    io_started: bool,
    close_round: Option<(CloseTransmit, u8, bool)>,
    peer_close: Option<PeerClose>,
    parameters_verified: bool,
}
impl<'r, 's, 'tc, 'ts, K: InitialKeyProtection> HandshakeEndpoint<'r, 's, 'tc, 'ts, K> {
    /// The local advertised max_idle_timeout defaults to zero. If TLS advertises
    /// a nonzero value, call configure_idle_timeout with that exact value before
    /// any receive/transmit attempt. Peer parameters are installed after TLS authentication.
    /// `initial` must contain connected RX/TX actors for this side and the
    /// original destination CID. The endpoint never derives or borrows their keys.
    pub fn new(
        config: Config<'_>,
        tls: TlsClient<'tc, 'ts>,
        recovery: RecoveryClient<'tc, 'ts>,
        authority: &'tc PacketAuthority,
        path: path::PathClient<'tc, 'ts>,
        stream: StreamClient<'tc, 'ts>,
        crypto: [CryptoBuffer<'s>; 3],
        initial: K,
    ) -> Result<Self, Error> {
        Self::new_inner(
            config, tls, recovery, authority, path, stream, crypto, None, initial,
        )
    }
    /// Bootstrap a server only after its dispatcher authenticates and consumes a
    /// Retry token for this peer address and this Initial's source/destination CIDs.
    /// The dispatcher must preserve that peer-address binding on subsequent I/O.
    /// The supplied TLS provider must already advertise ODCID (TP 0), its Initial
    /// SCID (TP 15), and the token's Retry SCID (TP 16). The admission is affine.
    /// Initial actors must already own the keys derived from that Retry SCID.
    pub fn new_after_retry(
        config: Config<'_>,
        tls: TlsClient<'tc, 'ts>,
        recovery: RecoveryClient<'tc, 'ts>,
        authority: &'tc PacketAuthority,
        path: path::PathClient<'tc, 'ts>,
        stream: StreamClient<'tc, 'ts>,
        crypto: [CryptoBuffer<'s>; 3],
        admission: ValidatedToken,
        initial: K,
    ) -> Result<Self, Error> {
        if config.side != Side::Server
            || config.original_destination_id != admission.original_destination_id()
        {
            return Err(Error::InvalidConfig);
        }
        Self::new_inner(
            config,
            tls,
            recovery,
            authority,
            path,
            stream,
            crypto,
            Some(admission),
            initial,
        )
    }
    fn new_inner(
        config: Config<'_>,
        tls: TlsClient<'tc, 'ts>,
        recovery: RecoveryClient<'tc, 'ts>,
        authority: &'tc PacketAuthority,
        path: path::PathClient<'tc, 'ts>,
        stream: StreamClient<'tc, 'ts>,
        crypto: [CryptoBuffer<'s>; 3],
        admission: Option<ValidatedToken>,
        initial: K,
    ) -> Result<Self, Error> {
        if config.generation != initial.generation()
            || config.generation != tls.generation()
            || config.generation != recovery.snapshot().generation
            || config.generation != authority.generation()
            || config.generation != stream.generation()
            || stream.snapshot().role
                != match config.side {
                    Side::Client => crate::streams::Role::Client,
                    Side::Server => crate::streams::Role::Server,
                }
        {
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
        let path_last = path.snapshot();
        if path_last.active.connection_generation != config.generation
            || path_last.local_cid.as_bytes() != config.local_id
            || path_last.role
                != match config.side {
                    Side::Client => crate::migration::Role::Client,
                    Side::Server => crate::migration::Role::Server,
                }
            || recovery.snapshot().active_path != Some(path_last.active)
        {
            return Err(Error::InvalidConfig);
        }
        let tls_last = *tls.snapshot();
        let recovery_last = recovery.snapshot();
        let stream_last = *stream.snapshot();
        Ok(Self {
            side: config.side,
            early: None,
            early_starter: None,
            early_last: None,
            trace: None,
            local,
            original,
            initial_destination,
            client_retry,
            version_negotiation,
            retry_grants: None,
            remote,
            remote_known: admission.is_some(),
            retry_admission: admission,
            tls: Some(tls),
            tls_last,
            stream: Some(stream),
            stream_last,
            finished_receipt: None,
            initial,
            initial_lifetime: core::marker::PhantomData,
            received: [Seen::default(); 3],
            crypto,
            offsets: [0; 3],
            pending_crypto: [0; 900],
            pending_tls: None,
            queued_flight: None,
            probe: None,
            now: 0,
            recovery: Some(recovery),
            recovery_last,
            authority,
            early_rejection: None,
            early_ready: None,
            handshake_ack: false,
            handshake_confirmed: false,
            discarded: [false; 2],
            discard_requested: [false; 2],
            peer_ack_exponent: 3,
            peer_max_ack_delay: 25_000,
            peer_limits: None,
            ping_probe: None,
            handshake_done_pending: false,
            handshake_done_flight: None,
            next_id: 0,
            path: Some(path),
            path_last,
            ingress_address: None,
            path_datagram_id: 0,
            ecn_enabled: false,
            ecn_rx: RxCounts::new(),
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
        self.recovery_snapshot()
            .base_pto_us?
            .checked_add(if self.handshake_confirmed {
                self.peer_max_ack_delay
            } else {
                0
            })
            .ok_or(Error::Recovery(recovery::RecoveryError::Overflow))
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
        self.retry_grants.is_some()
    }
    async fn apply_client_retry(&mut self) -> Result<(), Error> {
        use crate::roles::{
            packet_authority::RetryGrants,
            recovery_owner::{Command, Outcome},
        };
        let Some(RetryGrants {
            path,
            recovery,
            stream,
        }) = self.retry_grants.take()
        else {
            return Ok(());
        };
        match self.recovery_request(Command::RetryReset(recovery)).await? {
            Outcome::RetryReset { .. } => {}
            Outcome::RetryDeferred { grant, error } => {
                self.retry_grants = Some(RetryGrants {
                    path,
                    recovery: grant,
                    stream,
                });
                return Err(Error::RecoveryRejected(error));
            }
            _ => return Err(Error::InvalidConfig),
        }
        let destination = ConnectionId::peer(path.source_cid())?;
        self.initial.rekey(destination.bytes(), self.side).await?;
        self.stream_retry(stream).await?;
        self.path_apply_retry(path).await?;
        self.initial_destination = destination;
        self.remote = destination;
        self.remote_known = false;
        self.received = [Seen::default(); 3];
        self.probe = None;
        self.ping_probe = None;
        Ok(())
    }
    fn key_pto(&self) -> Result<u64, Error> {
        self.recovery_snapshot()
            .base_pto_us?
            .checked_add(self.peer_max_ack_delay)
            .ok_or(Error::Recovery(recovery::RecoveryError::Overflow))
    }
    /// Request an authenticated QUIC application-key update. Pending adapter output
    /// must complete first so no old-key datagram crosses the local update boundary.
    async fn initiate_key_update_impl(&mut self) -> Result<(), Error> {
        if self.connection_state() != ConnectionState::Active {
            return Err(Error::Busy);
        }
        if self.is_retired() {
            return Err(Error::Retired);
        }
        if !self.handshake_confirmed {
            return Err(tls::Error::KeyUpdateNotAllowed.into());
        }
        self.tls_initiate_key_update(self.now, self.key_pto()?)
            .await?;
        self.trace_event(crate::trace::Event::ApplicationKeyUpdated {
            owner: self.trace_vantage(),
            generation: self.tls_snapshot().send_generation,
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
        if self.next_id != 0
            || self.received.iter().any(|s| s.largest.is_some())
            || !self.recovery_snapshot().ecn.is_some_and(|ecn| ecn.active)
        {
            return Err(Error::InvalidConfig);
        }
        // The actual owner must have been configured for ECN at bootstrap.
        self.ecn_enabled = true;
        Ok(())
    }
    pub fn path_identity(&self) -> PathIdentity {
        self.path_snapshot().active
    }
    pub fn ecn_snapshot(&self) -> ecn::Snapshot {
        let snapshot = self.recovery_snapshot();
        let state = snapshot.ecn;
        ecn::Snapshot {
            enabled: self.ecn_enabled && state.is_some(),
            state: state.map_or(ecn::State::Testing, |s| s.state),
            failure: state.and_then(|s| s.failure),
            sent: snapshot.accepted_ecn,
            received: [
                PacketNumberSpace::Initial,
                PacketNumberSpace::Handshake,
                PacketNumberSpace::ApplicationData,
            ]
            .map(|space| self.ecn_rx.ack_counts(space)),
            validated_ce: state.map_or(0, |s| s.validated_ce),
            congestion_events: state.map_or(0, |s| s.congestion_events),
        }
    }
    pub fn handshake_complete(&self) -> bool {
        self.connection_state() == ConnectionState::Active
            && !self.is_retired()
            && !self.tls_snapshot().handshaking
            && self.parameters_verified
    }
    pub fn congestion_window(&self) -> u64 {
        self.recovery_snapshot().congestion_window
    }
    pub fn has_rtt_sample(&self) -> bool {
        self.recovery_snapshot().min_rtt_us.is_some()
    }
    pub fn bytes_in_flight(&self) -> u64 {
        self.recovery_snapshot().bytes_in_flight
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
        self.recovery_last.generation
    }
    pub fn verified_peer_limits(&self) -> Option<crate::streams::Limits> {
        self.peer_limits
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
    async fn close_impl(&mut self, reason: CloseReason) -> Result<(), Error> {
        if self.retired {
            return Err(Error::Retired);
        }
        if self
            .lifecycle
            .local_close(reason, self.now, self.key_pto()?)?
        {
            self.idle.stop();
            self.stop_ordinary_output().await?;
        }
        Ok(())
    }
    async fn stop_ordinary_output(&mut self) -> Result<(), Error> {
        if self.tls_snapshot().early_keys {
            self.tls_discard_early().await?;
        }
        self.retire_early_owner().await?;
        self.close_round = None;
        self.discard_requested = [false; 2];
        self.pending_tls = None;
        self.queued_flight = None;
        self.probe = None;
        self.ping_probe = None;
        self.handshake_done_pending = false;
        self.handshake_done_flight = None;
        for seen in &mut self.received {
            seen.ack_pending = false;
        }
        Ok(())
    }
    async fn enter_draining(&mut self) -> Result<(), Error> {
        self.idle.stop();
        self.lifecycle.on_peer_close(self.now, self.key_pto()?)?;
        self.stop_ordinary_output().await?;
        self.initial.retire().await?;
        self.retire_tls().await?;
        self.retire_recovery().await?;
        self.retire_stream_owner().await?;
        self.retire_path_owner().await?;
        self.discarded = [true; 2];
        Ok(())
    }
    pub fn is_retired(&self) -> bool {
        self.retired
    }
    pub fn retire(&mut self) {
        self.retire_data_plane();
        self.initial.close();
        self.abort_tls();
    }
    /// Revoke numerical admission without replacing an awaited owner retirement
    /// with mailbox cancellation. Only the synchronous Closing-expiry check
    /// leaves owner capabilities retained for the explicit async finalizer.
    fn retire_data_plane(&mut self) {
        self.idle.stop();
        self.pending_tls = None;
        self.close_round = None;
        self.retired = true;
        self.clear_early();
        self.abort_recovery();
        self.abort_path();
        self.abort_stream();
    }
    /// Advance the injected monotonic clock and arm a bounded fresh-PN CRYPTO
    /// probe on PTO. A PTO does not declare every outstanding packet lost.
    async fn timer_impl(&mut self, now: u64) -> Result<(), Error> {
        use crate::roles::recovery_owner::{Command, Outcome, TimerCommand};
        if self.retired {
            return Err(Error::Retired);
        }
        if now < self.now {
            return Err(recovery::RecoveryError::TimeWentBackwards.into());
        }
        if self.lifecycle.state() != ConnectionState::Active {
            self.now = now;
            if self.lifecycle.on_timeout(now)? || self.lifecycle.state() == ConnectionState::Closed
            {
                self.retire_owned().await?;
            }
            return Ok(());
        }
        if self.poll_idle_timeout(now)? {
            return Ok(());
        }
        self.now = now;
        self.path_timeout().await?;
        if self.is_retired() {
            return Ok(());
        }
        self.tls_maintain(now, self.key_pto()?).await?;
        let Outcome::Timeout(timeout) = self
            .recovery_request(Command::Timer(TimerCommand::Expire { now }))
            .await?
        else {
            return Err(Error::InvalidConfig);
        };
        if let Some(grant) = timeout.path {
            self.path_pto(grant).await?;
        }
        if let Some(grant) = timeout.stream {
            self.stream_pto(grant).await?;
        }
        if let Some(action) = timeout.action {
            match action {
                TimeoutAction::DetectLoss(_) => self.detect_losses().await?,
                TimeoutAction::Probe { space, .. } => {
                    if self.probe.is_none() {
                        self.probe = self.recovery_snapshot().probe_flights[space as usize];
                    }
                    if self.probe.is_none() && self.stream_snapshot().probe_budget == 0 {
                        self.ping_probe = Some(match space {
                            PacketNumberSpace::Initial => Level::Initial,
                            PacketNumberSpace::Handshake => Level::Handshake,
                            PacketNumberSpace::ApplicationData => Level::OneRtt,
                        });
                    }
                }
            }
            self.refresh_timer().await?;
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
        let snapshot = self.recovery_snapshot();
        let network = if self.handshake_confirmed {
            let can_prepare = snapshot.remaining_capacity > 0
                && snapshot
                    .active_bytes_in_flight
                    .saturating_add(snapshot.reserved_in_flight)
                    .saturating_add(50)
                    <= snapshot.congestion_window;
            self.network_deadline(can_prepare)
        } else {
            None
        };
        [
            snapshot.timer.map(|deadline| deadline.at),
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
                && self.path_available_bytes() == 0,
        }
    }
    async fn refresh_timer(&mut self) -> Result<(), Error> {
        if self.poll_idle_timeout(self.now)? || self.lifecycle.state() != ConnectionState::Active {
            return Ok(());
        }
        let command = crate::roles::recovery_owner::TimerCommand::Update {
            now: self.now,
            keys_available: [
                !self.discarded[0],
                self.tls_has_keys(Level::Handshake),
                self.tls_has_keys(Level::OneRtt),
            ],
            context: self.timer_context(),
            max_ack_delay_us: self.peer_max_ack_delay,
        };
        match self
            .recovery_request(crate::roles::recovery_owner::Command::Timer(command))
            .await?
        {
            crate::roles::recovery_owner::Outcome::TimerUpdated(grant) => {
                self.path_probe_timeout(grant).await
            }
            _ => Err(Error::InvalidConfig),
        }
    }

    async fn sync_tls_effects(&mut self) -> Result<(), Error> {
        self.sync_early_state().await
    }
    async fn apply_key_discards(&mut self) -> Result<(), Error> {
        use crate::roles::recovery_owner::{Command, FlightCommand, Outcome};
        if self.lifecycle.state() != ConnectionState::Active {
            return Ok(());
        }
        for i in 0..2 {
            let level = if i == 0 {
                Level::Initial
            } else {
                Level::Handshake
            };
            if !self.discard_requested[i] || self.discarded[i] {
                continue;
            }
            match self
                .recovery_request(Command::DiscardSpace(space(level)))
                .await?
            {
                Outcome::SpaceDiscarded { .. } => {}
                _ => return Err(Error::InvalidConfig),
            }
            if i == 0 {
                self.initial.retire().await?;
            } else {
                self.tls_discard_handshake().await?;
            }
            self.received[i].ack_pending = false;
            if let Some(probe) = self.probe {
                match self.recovery_flight(FlightCommand::Read(probe)).await {
                    Ok(Outcome::FlightData { .. }) => {}
                    Err(Error::RecoveryRejected(
                        crate::roles::recovery_owner::Rejection::Flight(flights::Error::Invalid),
                    )) => self.probe = None,
                    Err(error) => return Err(error),
                    Ok(_) => return Err(Error::InvalidConfig),
                }
            }
            if self.ping_probe == Some(level) {
                self.ping_probe = None;
            }
            self.discarded[i] = true;
        }
        Ok(())
    }
    async fn detect_losses(&mut self) -> Result<(), Error> {
        use crate::roles::recovery_owner::{Command, Outcome};
        let Outcome::Losses(losses) = self
            .recovery_request(Command::DetectLoss { now: self.now })
            .await?
        else {
            return Err(Error::InvalidConfig);
        };
        for packet in losses.newly.into_iter().flatten() {
            self.trace_event(crate::trace::Event::PacketLost {
                header: crate::trace::PacketHeader {
                    packet_type: match packet.kind {
                        PacketKind::Initial => crate::trace::PacketType::Initial,
                        PacketKind::Handshake => crate::trace::PacketType::Handshake,
                        PacketKind::ZeroRtt => crate::trace::PacketType::ZeroRtt,
                        PacketKind::OneRtt => crate::trace::PacketType::OneRtt,
                    },
                    packet_number: Some(packet.sent.packet.value),
                    key_phase: None,
                },
                trigger: None,
            });
        }
        for grant in losses.path.into_iter().flatten() {
            self.path_loss(grant).await?;
        }
        for grant in losses.stream.into_iter().flatten() {
            if grant.packet().space == PacketNumberSpace::ApplicationData {
                self.stream_loss(grant).await?;
            }
        }
        // Downstream owners now retain every reliable reference. Explicitly
        // release completed numeric history only after those real effects.
        for space in [
            PacketNumberSpace::Initial,
            PacketNumberSpace::Handshake,
            PacketNumberSpace::ApplicationData,
        ] {
            self.recovery_reclaim(space).await?;
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
        self.receive_with_metadata(
            datagram,
            scratch,
            ecn::Metadata {
                path: self.path_identity(),
                codepoint: None,
            },
        )
        .await
    }
    async fn receive_with_metadata_impl(
        &mut self,
        datagram: &[u8],
        scratch: &mut [u8],
        metadata: ecn::Metadata,
    ) -> Result<Received, Error> {
        if self.retired {
            return Err(Error::Retired);
        }
        self.path_prepare().await?;
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
        if self.retry_grants.is_some() {
            // The already-validated Retry is retained. Old-key peer data cannot
            // overtake the adapter completion and restart boundary.
            return Ok(Received {
                authenticated: 0,
                discarded: 1,
            });
        }
        let result = self
            .receive_inner(datagram, scratch, metadata.codepoint)
            .await;
        if result.is_err() {
            self.retire();
        } else if !self.retired {
            self.refresh_timer().await?;
        }
        result
    }
    async fn receive_inner(
        &mut self,
        datagram: &[u8],
        scratch: &mut [u8],
        received_ecn: Option<Codepoint>,
    ) -> Result<Received, Error> {
        self.tls_maintain(self.now, self.key_pto()?).await?;
        self.path_begin_datagram()?;
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
                        let committed = self.client_retry.commit_with_receipt(checked)?;
                        self.retry_grants = Some(crate::roles::packet_authority::split_retry(
                            self.generation(),
                            committed,
                        ));
                        if let Some(client) = &mut self.version_negotiation {
                            client.on_peer_processed();
                        }
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
                    .receive_early(packet, scratch, received_ecn, datagram.len())
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
            if !self.path_accepts_destination(destination, level) {
                report.discarded += 1;
                continue;
            }
            if packet.bytes.len() > scratch.len() || packet.bytes.len() > TLS_PACKET_BYTES {
                report.discarded += 1;
                continue;
            }
            if (level == Level::Initial && self.discarded[0])
                || (level == Level::OneRtt && self.tls_snapshot().handshaking)
                || (level != Level::Initial && !self.tls_has_keys(level))
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
            self.sync_tls_effects().await?;
            let mask = if level == Level::Initial {
                self.initial.receive_mask(*sample).await?
            } else {
                self.tls_mask(level, false, *sample).await?
            };
            bytes[0] ^= mask[0] & if bytes[0] & 0x80 != 0 { 0x0f } else { 0x1f };
            let pn_len = usize::from((bytes[0] & 3) + 1);
            if pn_offset + pn_len > bytes.len() {
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
                    report.discarded += 1;
                    continue;
                }
            };
            let first = bytes[0];
            let (header, body) = bytes.split_at_mut(pn_offset + pn_len);
            let previous_receive_generation = self.tls_snapshot().receive_generation;
            let previous_write_generation = self.tls_snapshot().send_generation;
            let mut received_key_generation = 0;
            let (plaintext, receive_evidence) = if level == Level::Initial {
                match self.open_initial(pn, header, body).await {
                    Ok((n, receipt)) => (
                        n,
                        crate::roles::packet_authority::ReceiveEvidence::Initial(receipt),
                    ),
                    Err(Error::Crypto(crypto::Error::AuthenticationFailed)) => {
                        report.discarded += 1;
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            } else {
                let opened = if level == Level::OneRtt {
                    self.tls_open_one_rtt(
                        pn,
                        first & 0x04 != 0,
                        header,
                        body,
                        self.now,
                        self.key_pto()?,
                    )
                    .await
                    .map(|(opened, receipt)| {
                        received_key_generation = opened.generation;
                        (opened.len, receipt)
                    })
                } else {
                    self.tls_open(level, pn, header, body).await
                };
                match opened {
                    Ok((n, receipt)) => (
                        n,
                        crate::roles::packet_authority::ReceiveEvidence::Tls(receipt),
                    ),
                    Err(Error::Tls(tls::Error::Authentication | tls::Error::KeysUnavailable)) => {
                        report.discarded += 1;
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            };

            if level == Level::OneRtt
                && self.tls_snapshot().receive_generation > previous_receive_generation
            {
                self.trace_event(crate::trace::Event::ApplicationKeyUpdated {
                    owner: self.trace_peer_vantage(),
                    generation: self.tls_snapshot().receive_generation,
                    trigger: crate::trace::KeyUpdateTrigger::RemoteUpdate,
                });
            }
            if level == Level::OneRtt
                && self.tls_snapshot().send_generation > previous_write_generation
            {
                self.trace_event(crate::trace::Event::ApplicationKeyUpdated {
                    owner: self.trace_vantage(),
                    generation: self.tls_snapshot().send_generation,
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
            let packet_scope =
                recovery_actor::PacketScope::admit(self.authority, receive_evidence, payload)?;
            let ticket = packet_scope.ticket();
            if level == Level::Initial {
                self.path_learn_initial(ticket, header).await?;
            }
            let network_context = self.path_receive_context(destination, datagram.len())?;
            let received_path = self
                .path_received_packet(ticket, network_context, non_probing)
                .await?;
            for (ordinal, frame) in FrameIter::new(payload, wire_level(level), limits)?.enumerate()
            {
                let frame = frame?;
                if self
                    .path_received_frame(ticket, ordinal as u32, frame, network_context)
                    .await?
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
                            let n = bytes.len().min(TLS_PACKET_BYTES);
                            let mut input = [0; TLS_PACKET_BYTES];
                            input[..n].copy_from_slice(&bytes[..n]);
                            self.tls_receive_crypto(level, &input[..n]).await?;
                            self.crypto[index(level)].consume(n)?;
                            self.sync_tls_effects().await?;
                        }
                    }
                    Frame::Ack { ranges, delay, ecn } => {
                        let grant =
                            self.authority
                                .grant_ack(ticket, ordinal as u32, ranges, delay, ecn)?;
                        let ack = self.recovery_ack(grant, Some(received_path)).await?;
                        if level == Level::Handshake && ack.summary.newly_acknowledged != 0 {
                            self.handshake_ack = true;
                        }
                        let (stream, path) = ack.validated.split();
                        self.path_ack(path).await?;
                        if level == Level::OneRtt {
                            self.stream_ack(stream).await?;
                        }
                        for grant in ack.keys.into_iter().flatten() {
                            self.tls_acknowledge(grant, self.now, self.key_pto()?)
                                .await?;
                        }
                        self.detect_losses().await?;
                        self.recovery_reclaim(space(level)).await?;
                    }
                    Frame::Padding { .. } | Frame::Ping => {}
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
                        packet_scope.finish()?;
                        self.enter_draining().await?;
                        report.authenticated += 1;
                        return Ok(report);
                    }
                    other if level == Level::OneRtt => {
                        let grant = self.authority.grant_delivery::<STREAM_FRAME_BYTES>(
                            ticket,
                            ordinal as u32,
                            other,
                        )?;
                        self.stream_deliver(grant).await?;
                    }
                    _ => return Err(Error::UnexpectedFrame),
                }
            }
            self.ecn_rx.processed(space(level), received_ecn)?;
            packet_scope.finish()?;
            if eliciting {
                self.received[index(level)].ack_pending = true;
            }
            if self.side == Side::Server && level == Level::Handshake {
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
            self.validate_parameters().await?;
            self.release_early().await?;
            if level == Level::OneRtt && self.side == Side::Server && self.tls_snapshot().early_keys
            {
                self.tls_discard_early().await?;
            }
            self.apply_key_discards().await?;
        }
        Ok(report)
    }
    async fn validate_parameters(&mut self) -> Result<(), Error> {
        if self.tls_snapshot().handshaking || self.parameters_verified {
            return Ok(());
        }
        let observed = *self.tls_snapshot();
        let raw = observed.peer_parameters().ok_or(Error::InvalidConfig)?;
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
        let receipt = self.finished_receipt.take().ok_or(Error::InvalidConfig)?;
        let grants = crate::roles::connection_authority::verify_and_split(
            receipt,
            raw,
            peer,
            self.remote.bytes(),
            original,
            retry,
        )
        .map_err(Error::ConnectionAuthority)?;
        self.path_install_ready(grants.path).await?;
        self.stream_install_early_send().await?;
        self.stream_ready(grants.application).await?;
        if self.side == Side::Client {
            if self.stream_snapshot().early_import_required {
                self.stream_early_ready(grants.early).await?;
            }
        } else {
            self.early_ready = Some(grants.early);
        }
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
        if self.side == Side::Server {
            // PathReady consumed the actual server Finished confirmation.
            self.handshake_done_pending = true;
            self.discard_requested[1] = true;
        }
        self.parameters_verified = true;
        Ok(())
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
