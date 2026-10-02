//! A projected owner for address validation, anti-amplification and CID history.
//!
//! The owner retains every mutable kernel. Requests move affine authenticated
//! frame grants and adapter completions, never a caller-supplied authenticated
//! boolean. Observed path IDs and timer IDs are checked against live generations.
//! Datagram reservations survive while the adapter is pending; cancellation or
//! owner retirement releases them without counting a send.
use super::{packet_authority as authority, packet_protection::Descriptor, protocol_path as p};
use crate::{
    accounting::{PacketNumber, PacketNumberSpace},
    connection_id::{
        Cid, CidError, LocalCidHandle, LocalCidSlot, LocalCidTable, PeerCidHandle, PeerCidSlot,
        PeerCidTable, ResetToken,
    },
    mailbox::{Receiver, Sender},
    migration::{self, Decision, Migration, Role},
    path::{self, Address, InitialValidation, PathIdentity, PathSlot, Paths},
    runtime,
};
use core::{cell::RefCell, future::Future};
use hibana::{Endpoint, EndpointError};
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;

pub const PATHS: usize = 2;
pub const LOCAL_CIDS: usize = 8;
pub const PEER_CIDS: usize = 16;
const CONTROLS: usize = LOCAL_CIDS + PEER_CIDS;

/// A wire CID including the fixed zero-length form, which never enters a
/// nonzero CID table and can never migrate away from its original exact tuple.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Destination {
    bytes: [u8; 20],
    len: u8,
}
impl Destination {
    pub fn new(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 20 {
            return Err(Error::InvalidConfig);
        }
        let mut result = Self {
            bytes: [0; 20],
            len: bytes.len() as u8,
        };
        result.bytes[..bytes.len()].copy_from_slice(bytes);
        Ok(result)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
    pub const fn is_zero(self) -> bool {
        self.len == 0
    }
}
impl From<Cid> for Destination {
    fn from(cid: Cid) -> Self {
        Self::new(cid.as_bytes()).expect("CID kernel bounds")
    }
}
/// Immutable receive facts copied only by the authenticated packet parser.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathContext {
    pub address: Address,
    pub destination: Destination,
    pub datagram_id: u64,
    pub datagram_bytes: u64,
    pub now: u64,
}
/// The actual parsed frame is inside the affine grant; no command can replace it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathFrame {
    Challenge([u8; 8]),
    Response([u8; 8]),
    NewConnectionId {
        sequence: u64,
        retire_prior_to: u64,
        id: Cid,
        reset_token: ResetToken,
    },
    RetireConnectionId {
        sequence: u64,
    },
    PacketProcessed {
        non_probing: bool,
    },
    HandshakeDone,
}
#[derive(Clone, Copy, Debug)]
pub struct PreferredPeer {
    pub address: Address,
    pub cid: Cid,
    pub reset_token: ResetToken,
}
/// This copied data is not authority. Only an owner-minted PathReady capability
/// can install it into the state below.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedParameters {
    pub peer_cid: Destination,
    pub peer_active_limit: u64,
    pub disable_active_migration: bool,
    pub initial_reset_token: Option<ResetToken>,
    pub preferred: Option<PreferredPeer>,
}
#[derive(Clone, Copy, Debug)]
pub struct PreferredLocal {
    pub address: core::net::SocketAddr,
    pub cid: Cid,
    pub reset_token: ResetToken,
}
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub generation: u64,
    pub role: Role,
    pub initial: Address,
    pub local_cid: Destination,
    pub bootstrap_destination: Destination,
    pub local_active_limit: u64,
    pub local_reset_token: Option<ResetToken>,
    pub preferred_server: Option<PreferredLocal>,
    pub now: u64,
    pub pto: u64,
}
pub struct Resources<'a> {
    pub paths: &'a mut [PathSlot<1, 3>; PATHS],
    pub local_cids: &'a mut [LocalCidSlot; LOCAL_CIDS],
    pub peer_cids: &'a mut [PeerCidSlot<2>; PEER_CIDS],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidConfig,
    Capacity,
    Entropy,
    WrongGeneration,
    WrongLevel,
    WrongDestination,
    FixedZeroCid,
    StaleIngress,
    StaleTimer,
    TimerNotDue,
    InvalidDescriptor,
    AdapterPayload,
    SequenceExhausted,
    HandshakeNotInstalled,
    AlreadyInstalled,
    PreferredAdvertisementRequired,
    PeerInitialNotLearned,
    PeerCidMismatch,
    RetryNotAllowed,
    Path(path::Error),
    Cid(CidError),
    Migration(migration::Error),
    Authority(authority::Error),
    Packet(crate::packet::Error),
}
impl From<path::Error> for Error {
    fn from(e: path::Error) -> Self {
        Self::Path(e)
    }
}
impl From<CidError> for Error {
    fn from(e: CidError) -> Self {
        Self::Cid(e)
    }
}
impl From<migration::Error> for Error {
    fn from(e: migration::Error) -> Self {
        Self::Migration(e)
    }
}
impl From<authority::Error> for Error {
    fn from(e: authority::Error) -> Self {
        Self::Authority(e)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Control {
    Challenge([u8; 8]),
    Response([u8; 8]),
    NewConnectionId {
        sequence: u64,
        retire_prior_to: u64,
        cid: Cid,
        reset_token: ResetToken,
    },
    RetireConnectionId {
        sequence: u64,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReliableControl {
    Advertise(LocalCidHandle),
    Retire(PeerCidHandle),
}
#[derive(Clone, Copy)]
struct ControlRecord {
    kind: ReliableControl,
    ready: bool,
    acknowledged: bool,
    sent: [Option<u64>; 4],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingRecord {
    descriptor: Descriptor,
    reservation: path::Transmit,
    address: Address,
    destination: Destination,
    peer: Option<PeerCidHandle>,
    control: Option<Control>,
    reliable: Option<usize>,
    packet: PacketNumber,
}
/// The adapter owns this non-Clone capability while a send is pending. Getters
/// expose observations only. No public constructor can create an accepted send.
#[derive(Debug)]
pub struct PendingTransmit {
    record: PendingRecord,
    local_cid: Destination,
}
impl PendingTransmit {
    pub const fn descriptor(&self) -> Descriptor {
        self.record.descriptor
    }
    pub const fn packet(&self) -> PacketNumber {
        self.record.packet
    }
    pub fn path(&self) -> PathIdentity {
        self.record.reservation.path()
    }
    pub fn bytes(&self) -> u64 {
        self.record.reservation.bytes()
    }
    pub const fn address(&self) -> Address {
        self.record.address
    }
    pub const fn destination(&self) -> Destination {
        self.record.destination
    }
    pub const fn control(&self) -> Option<Control> {
        self.record.control
    }
    /// Explicit rejection never calls the adapter and never counts a send.
    pub fn reject(self) -> AdapterCompletion {
        AdapterCompletion {
            record: self.record,
            accepted_at: None,
            initial_advertised: false,
        }
    }
    /// Calls the real adapter with the reserved exact tuple and byte count.
    /// The adapter reports the monotonic acceptance timestamp only after the
    /// entire datagram was accepted. Invalid buffers return rejection evidence.
    pub(crate) async fn submit<A: UdpAdapter, const N: usize>(
        self,
        adapter: &mut A,
        protected: super::datagram::ProtectedDatagram<N>,
    ) -> Result<super::datagram::Completions, super::datagram::Error> {
        if !protected.matches(&self) {
            return Err(super::datagram::Error::Binding);
        }
        let bytes = protected.bytes();
        let mut initial_advertised = false;
        let valid = (|| {
            if bytes.len() as u64 != self.bytes() {
                return false;
            }
            let Ok(packets) =
                crate::packet::PacketIter::new(bytes, self.destination().as_bytes().len(), 16)
            else {
                return false;
            };
            let mut count = 0;
            for packet in packets {
                let Ok(packet) = packet else {
                    return false;
                };
                count += 1;
                let dcid = match packet.header {
                    crate::packet::Header::Long {
                        destination_id,
                        source_id,
                        ..
                    } => {
                        if source_id != self.local_cid.as_bytes() {
                            return false;
                        }
                        initial_advertised = true;
                        destination_id
                    }
                    crate::packet::Header::Short { destination_id, .. } => destination_id,
                    _ => return false,
                };
                if dcid != self.destination().as_bytes() {
                    return false;
                }
            }
            count != 0
        })();
        let accepted_at = if valid {
            adapter
                .send(Datagram {
                    bytes,
                    path: self.path(),
                    address: self.address(),
                    ecn: protected.ecn(),
                })
                .await
                .ok()
        } else {
            None
        };
        super::datagram::complete(self, protected, accepted_at, initial_advertised)
    }
}
pub struct Datagram<'a> {
    pub bytes: &'a [u8],
    pub path: PathIdentity,
    pub address: Address,
    pub ecn: crate::ecn::Codepoint,
}
/// Trusted UDP boundary: Ok(time) means actual complete datagram acceptance.
/// An implementation must not report planned, partial, rejected or blocked sends.
pub trait UdpAdapter {
    fn send(&mut self, datagram: Datagram<'_>) -> impl Future<Output = Result<u64, ()>>;
}
#[derive(Debug)]
pub struct AdapterCompletion {
    record: PendingRecord,
    accepted_at: Option<u64>,
    initial_advertised: bool,
}
impl From<super::datagram::PathCompletion> for AdapterCompletion {
    fn from(completion: super::datagram::PathCompletion) -> Self {
        let (pending, accepted_at, initial_advertised) = completion.into_parts();
        Self {
            record: pending.record,
            accepted_at,
            initial_advertised,
        }
    }
}

/// An original datagram's length and trailing reset candidate. Header bits are
/// irrelevant to RFC 9000 reset detection. This contains no authentication flag.
pub struct ResetCandidate {
    address: Address,
    tail: [u8; 21],
    long_enough: bool,
}
impl ResetCandidate {
    pub fn new(address: Address, original_datagram: &[u8]) -> Self {
        let mut tail = [0; 21];
        let long_enough = original_datagram.len() >= tail.len();
        if long_enough {
            tail.copy_from_slice(&original_datagram[original_datagram.len() - 21..]);
        }
        Self {
            address,
            tail,
            long_enough,
        }
    }
}
/// Actual QUIC confirmation, not a copied handshake-status flag. Servers
/// obtain it from verified client Finished; clients from authenticated 1-RTT
/// HANDSHAKE_DONE. The TLS/key owner consumes it before enabling key updates.
#[derive(Debug)]
pub struct HandshakeConfirmation {
    generation: u64,
}
impl HandshakeConfirmation {
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

/// Affine permission minted only by an actual path-policy switch that requires
/// fresh congestion/RTT state. A copied Decision or PathIdentity is observation.
#[derive(Debug)]
pub struct RecoveryResetGrant {
    generation: u64,
    previous: PathIdentity,
    active: PathIdentity,
}
impl RecoveryResetGrant {
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub const fn previous(&self) -> PathIdentity {
        self.previous
    }
    pub const fn active(&self) -> PathIdentity {
        self.active
    }
}
/// Opaque current-deadline observation, minted only by the owner. A mutation
/// invalidates earlier observations, including ones whose numeric deadline
/// happens to be unchanged. Time passage alone does not grant mutation authority.
#[derive(Debug)]
pub struct TimerObservation {
    generation: u64,
    revision: u64,
    deadline: u64,
}
impl TimerObservation {
    pub const fn deadline(&self) -> u64 {
        self.deadline
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Snapshot {
    pub active: PathIdentity,
    pub paths: [Option<(PathIdentity, path::Snapshot)>; PATHS],
    pub installed: bool,
    pub peer_initial_cid: Option<Destination>,
    pub initial_destination_cid: Option<Destination>,
    pub pending_transmits: usize,
    pub local_routing_count: usize,
    pub pending_controls: usize,
    pub preferred_advertisement_pending: bool,
    pub next_control_path: Option<PathIdentity>,
}

#[derive(Clone, Copy)]
enum IngressKind {
    Initial,
    Ordinary,
    Early,
}

/// Construct once, then move into run_borrowed. There are deliberately no
/// public mutable-kernel getters or public effect methods on this object.
pub struct State<'s, R> {
    config: Config,
    paths: Paths<'s, 1, 3>,
    local: LocalCidTable<'s>,
    local_initial: Option<LocalCidHandle>,
    preferred_local: Option<LocalCidHandle>,
    preferred_advertised: bool,
    peer_slots: Option<&'s mut [PeerCidSlot<2>; PEER_CIDS]>,
    peer: Option<PeerCidTable<'s, 2>>,
    learned_peer_initial: Option<Destination>,
    initial_received_destination: Option<Destination>,
    original_bootstrap: Destination,
    retry_seen: bool,
    zero_peer: bool,
    zero_peer_token: Option<ResetToken>,
    zero_peer_used: bool,
    bootstrap_used: Option<(Destination, Address)>,
    installed: bool,
    confirmed: bool,
    tls_confirmation: Option<HandshakeConfirmation>,
    original: PathIdentity,
    migration: Migration,
    recovery_reset: Option<RecoveryResetGrant>,
    bindings: [Option<PeerCidHandle>; PATHS],
    inbound: [Option<Destination>; PATHS],
    preferred: Option<(Address, PeerCidHandle)>,
    preferred_started: bool,
    pending: [Option<PendingRecord>; PATHS],
    controls: [Option<ControlRecord>; CONTROLS],
    rng: R,
    last_datagram: Option<(u64, Address, u64, PathIdentity)>,
    revision: u64,
    now: u64,
}
impl<'s, R: RngCore + CryptoRng> State<'s, R> {
    /// Read-only bootstrap identity for the connection's owner configuration.
    /// This never authorizes a later recovery reset or path mutation.
    pub const fn initial_path(&self) -> PathIdentity {
        self.original
    }

    pub fn new(config: Config, resources: Resources<'s>, rng: R) -> Result<Self, Error> {
        if config.initial.local.port() == 0
            || config.initial.remote.port() == 0
            || config.initial.local.ip().is_unspecified()
            || config.initial.remote.ip().is_unspecified()
            || config.pto == 0
            || !(2..=4).contains(&config.local_active_limit)
            || (config.role == Role::Client
                && (config.local_reset_token.is_some() || config.preferred_server.is_some()))
            || config.preferred_server.is_some_and(|preferred| {
                config.local_cid.is_zero()
                    || preferred.cid.as_bytes().len() != config.local_cid.as_bytes().len()
                    || preferred.address.port() == 0
                    || preferred.address.ip().is_unspecified()
            })
        {
            return Err(Error::InvalidConfig);
        }
        let mut local = LocalCidTable::new(0, config.generation, resources.local_cids, 2)?;
        let local_initial = if config.local_cid.is_zero() {
            None
        } else {
            Some(
                local
                    .issue_initial(
                        Cid::new(config.local_cid.as_bytes())?,
                        config.local_reset_token,
                    )?
                    .handle,
            )
        };
        let preferred_local = config
            .preferred_server
            .map(|preferred| {
                local
                    .issue_preferred(preferred.cid, preferred.reset_token)
                    .map(|cid| cid.handle)
            })
            .transpose()?;
        let mut paths = Paths::new(
            resources.paths,
            config.generation,
            path::Config {
                probe_interval_us: config.pto,
                validation_timeout_us: config.pto.checked_mul(3).ok_or(Error::Capacity)?,
                max_attempts: 3,
            },
        )?;
        let original = paths.insert(
            config.initial,
            if config.role == Role::Client {
                InitialValidation::ClientUnvalidated
            } else {
                InitialValidation::Unvalidated
            },
            config.now,
        )?;
        let migration = Migration::new(config.role, original, &paths)?;
        Ok(Self {
            config,
            paths,
            local,
            local_initial,
            preferred_local,
            preferred_advertised: false,
            peer_slots: Some(resources.peer_cids),
            peer: None,
            learned_peer_initial: None,
            initial_received_destination: None,
            original_bootstrap: config.bootstrap_destination,
            retry_seen: false,
            zero_peer: false,
            zero_peer_token: None,
            zero_peer_used: false,
            bootstrap_used: None,
            installed: false,
            confirmed: false,
            tls_confirmation: None,
            original,
            migration,
            recovery_reset: None,
            bindings: [None; PATHS],
            inbound: [None; PATHS],
            preferred: None,
            preferred_started: false,
            pending: [None; PATHS],
            controls: [None; CONTROLS],
            rng,
            last_datagram: None,
            revision: 0,
            now: config.now,
        })
    }
    fn snapshot(&self) -> Snapshot {
        let mut paths = [None; PATHS];
        for path in self.paths.identities() {
            paths[usize::from(path.slot)] =
                self.paths.snapshot(path).ok().map(|state| (path, state));
        }
        Snapshot {
            active: self.migration.active(),
            paths,
            installed: self.installed,
            peer_initial_cid: self.learned_peer_initial,
            initial_destination_cid: self.initial_received_destination,
            pending_transmits: self.pending.iter().flatten().count(),
            local_routing_count: if self.config.local_cid.is_zero() {
                1
            } else {
                self.local.routing_count()
            },
            pending_controls: self
                .controls
                .iter()
                .flatten()
                .filter(|r| !r.acknowledged)
                .count(),
            preferred_advertisement_pending: self.preferred_local.is_some()
                && !self.preferred_advertised,
            next_control_path: self.next_control_path(),
        }
    }
    fn clock(&mut self, now: u64) -> Result<(), Error> {
        if now < self.now {
            return Err(path::Error::ClockRegression.into());
        }
        self.now = now;
        Ok(())
    }
    fn queue(&mut self, kind: ReliableControl) -> Result<(), Error> {
        if self.controls.iter().flatten().any(|r| r.kind == kind) {
            return Ok(());
        }
        let index = self
            .controls
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        self.controls[index] = Some(ControlRecord {
            kind,
            ready: true,
            acknowledged: false,
            sent: [None; 4],
        });
        Ok(())
    }
    fn queue_retirements(&mut self) -> Result<(), Error> {
        let mut handles = [None; PEER_CIDS];
        if let Some(peer) = &self.peer {
            for (i, handle) in peer.pending_retirements().enumerate() {
                handles[i] = Some(handle);
            }
        }
        for handle in handles.into_iter().flatten() {
            self.queue(ReliableControl::Retire(handle))?;
        }
        Ok(())
    }
    fn destination(
        &self,
        path: PathIdentity,
    ) -> Result<(Destination, Option<PeerCidHandle>), Error> {
        let address = self.paths.snapshot(path)?.address;
        if self.zero_peer || !self.installed {
            if path != self.original || address != self.config.initial {
                return Err(Error::FixedZeroCid);
            }
            return Ok((
                self.learned_peer_initial
                    .unwrap_or(self.config.bootstrap_destination),
                None,
            ));
        }
        let handle = self
            .bindings
            .get(usize::from(path.slot))
            .copied()
            .flatten()
            .ok_or(Error::Capacity)?;
        let peer = self.peer.as_ref().ok_or(Error::HandshakeNotInstalled)?;
        peer.check_send(handle, address.local, address.remote)?;
        Ok((peer.get(handle)?.cid.into(), Some(handle)))
    }
    fn bind_peer(
        &mut self,
        path: PathIdentity,
        rebind_from: Option<PathIdentity>,
    ) -> Result<(), Error> {
        let address = self.paths.snapshot(path)?.address;
        if self.zero_peer || !self.installed {
            return if path == self.original && address == self.config.initial {
                Ok(())
            } else {
                Err(Error::FixedZeroCid)
            };
        }
        let index = usize::from(path.slot);
        let peer = self.peer.as_mut().ok_or(Error::HandshakeNotInstalled)?;
        if self.bindings[index].is_some_and(|handle| {
            peer.check_send(handle, address.local, address.remote)
                .is_ok()
        }) {
            return Ok(());
        }
        if let Some(old) = rebind_from {
            let old_index = usize::from(old.slot);
            if self.inbound[index].is_some()
                && self.inbound[index] == self.inbound[old_index]
                && self.paths.snapshot(old)?.address.local == address.local
                && let Some(handle) = self.bindings[old_index]
            {
                match peer.authorize_remote_rebinding_authenticated(
                    handle,
                    address.local,
                    address.remote,
                ) {
                    Ok(()) => {
                        self.bindings[index] = Some(handle);
                        return Ok(());
                    }
                    Err(
                        CidError::UnusedConnectionId
                        | CidError::AddressHistoryFull
                        | CidError::Retired,
                    ) => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        let candidate = peer
            .active()
            .find(|cid| {
                !self
                    .bindings
                    .iter()
                    .enumerate()
                    .any(|(other, handle)| other != index && *handle == Some(cid.handle))
                    && peer
                        .check_send(cid.handle, address.local, address.remote)
                        .is_ok()
            })
            .map(|cid| cid.handle)
            .ok_or(Error::Capacity)?;
        self.bindings[index] = Some(candidate);
        Ok(())
    }
    fn install(&mut self, parameters: VerifiedParameters) -> Result<(), Error> {
        if self.installed {
            return Err(Error::AlreadyInstalled);
        }
        let learned = self
            .learned_peer_initial
            .ok_or(Error::PeerInitialNotLearned)?;
        if learned != parameters.peer_cid {
            return Err(Error::PeerCidMismatch);
        }
        if parameters.peer_cid.is_zero() && parameters.preferred.is_some() {
            return Err(Error::FixedZeroCid);
        }
        self.local
            .set_peer_limit_verified(parameters.peer_active_limit)?;
        if parameters.peer_cid.is_zero() {
            self.zero_peer = true;
            self.zero_peer_token = parameters.initial_reset_token;
        } else {
            let mut peer = PeerCidTable::new(
                1,
                self.config.generation,
                self.peer_slots.take().ok_or(Error::AlreadyInstalled)?,
                self.config.local_active_limit,
                Cid::new(parameters.peer_cid.as_bytes())?,
            )?;
            if let Some(token) = parameters.initial_reset_token {
                peer.install_initial_token_verified(token)?;
            }
            let initial = peer.initial()?.handle;
            if self.bootstrap_used == Some((parameters.peer_cid, self.config.initial)) {
                peer.record_sent(
                    initial,
                    self.config.initial.local,
                    self.config.initial.remote,
                )?;
            }
            self.bindings[usize::from(self.original.slot)] = Some(initial);
            if let Some(preferred) = parameters.preferred {
                if self.config.role != Role::Client
                    || preferred.address.local != self.config.initial.local
                {
                    return Err(Error::InvalidConfig);
                }
                let cid = peer
                    .accept_preferred_verified(preferred.cid, preferred.reset_token)?
                    .handle;
                self.preferred = Some((preferred.address, cid));
            }
            self.peer = Some(peer);
            self.zero_peer = false;
        }
        self.paths.handshake_validated(self.original)?;
        self.migration.validated(self.original, &self.paths)?;
        self.migration.verified_parameters(
            parameters.disable_active_migration,
            if self.config.role == Role::Server {
                self.config.preferred_server.map(|p| p.address)
            } else {
                parameters.preferred.map(|p| p.address.remote)
            },
        )?;
        self.installed = true;
        Ok(())
    }
    fn apply_decision(&mut self, decision: Decision) -> Result<(), Error> {
        match decision {
            Decision::Switched(switch) => {
                self.bind_peer(switch.active, Some(switch.previous))?;
                if switch.reprobe_previous {
                    self.paths.restart_validation(switch.previous, self.now)?;
                }
                if switch.reset_recovery {
                    let previous = if let Some(prior) = self.recovery_reset.take() {
                        // Reclaiming an unvalidated candidate can briefly select
                        // the validated fallback before the replacement tuple.
                        // No send can interleave this owner operation; Recovery
                        // needs one reset from its old path to the final path.
                        if prior.active != switch.previous {
                            return Err(Error::InvalidDescriptor);
                        }
                        prior.previous
                    } else {
                        switch.previous
                    };
                    self.recovery_reset = Some(RecoveryResetGrant {
                        generation: self.config.generation,
                        previous,
                        active: switch.active,
                    });
                }
            }
            Decision::Validate(path) => self.bind_peer(path, Some(self.migration.active()))?,
            _ => {}
        }
        Ok(())
    }
    fn retire_path(&mut self, path: PathIdentity) -> Result<(), Error> {
        self.paths.snapshot(path)?;
        if path == self.migration.active() {
            return Err(Error::InvalidConfig);
        }
        let index = usize::from(path.slot);
        if let Some(pending) = self.pending[index].take() {
            let _ = self.paths.adapter_rejected(pending.reservation);
        }
        self.paths.retire(path)?;
        if let Some(handle) = self.bindings[index].take()
            && !self.bindings.contains(&Some(handle))
        {
            self.peer
                .as_mut()
                .ok_or(Error::HandshakeNotInstalled)?
                .retire(handle)?;
            self.queue_retirements()?;
        }
        self.inbound[index] = None;
        Ok(())
    }
    fn issue_cid(&mut self) -> Result<Option<Control>, Error> {
        if self.config.local_cid.is_zero() {
            return Err(Error::FixedZeroCid);
        }
        if !self.installed {
            return Err(Error::HandshakeNotInstalled);
        }
        if !self.local.can_issue() {
            return Ok(None);
        }
        if self.controls.iter().all(Option::is_some) {
            return Err(Error::Capacity);
        }
        for _ in 0..8 {
            let mut bytes = [0; 20];
            let mut token = [0; 16];
            let len = self.config.local_cid.as_bytes().len();
            self.rng
                .try_fill_bytes(&mut bytes[..len])
                .map_err(|_| Error::Entropy)?;
            self.rng
                .try_fill_bytes(&mut token)
                .map_err(|_| Error::Entropy)?;
            match self.local.issue(
                Cid::new(&bytes[..len])?,
                ResetToken::new(token),
                self.local.retire_prior_to(),
            ) {
                Ok(cid) => {
                    self.queue(ReliableControl::Advertise(cid.handle))?;
                    return Ok(Some(Control::NewConnectionId {
                        sequence: cid.sequence,
                        retire_prior_to: cid.retire_prior_to,
                        cid: cid.cid,
                        reset_token: cid.token.ok_or(Error::InvalidConfig)?,
                    }));
                }
                Err(CidError::ConnectionIdReused | CidError::ResetTokenReused) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(Error::Entropy)
    }
    fn next_control_path(&self) -> Option<PathIdentity> {
        if !self.confirmed || self.pending.iter().any(Option::is_some) {
            return None;
        }
        for path in self.paths.identities() {
            if self.paths.pending_response(path).ok().flatten().is_some()
                && self.destination(path).is_ok()
            {
                return Some(path);
            }
        }
        let active = self.migration.active();
        if self.destination(active).is_ok()
            && self
                .controls
                .iter()
                .flatten()
                .any(|record| record.ready && !record.acknowledged)
        {
            return Some(active);
        }
        self.paths.identities().find(|path| {
            self.paths
                .probe_deadline(*path)
                .ok()
                .flatten()
                .is_some_and(|deadline| self.now >= deadline)
                && self.destination(*path).is_ok()
        })
    }
    fn reserve(
        &mut self,
        descriptor: Descriptor,
        path: PathIdentity,
        bytes: u64,
        packet: PacketNumber,
        control: bool,
        now: u64,
    ) -> Result<PendingTransmit, Error> {
        self.clock(now)?;
        if descriptor.generation != self.config.generation {
            return Err(Error::WrongGeneration);
        }
        let index = usize::from(path.slot);
        if index >= PATHS || self.pending[index].is_some() {
            return Err(Error::Capacity);
        }
        let address = self.paths.snapshot(path)?.address;
        let (destination, peer) = self.destination(path)?;
        let mut reliable = None;
        let (reservation, wire_control) = if control {
            if let Some(response) = self.paths.pending_response(path)? {
                let reservation = self.paths.reserve_response(response, bytes)?;
                let Some(path::Control::Response(data)) = reservation.control() else {
                    return Err(Error::InvalidDescriptor);
                };
                (reservation, Some(Control::Response(data)))
            } else if self
                .paths
                .probe_deadline(path)?
                .is_some_and(|deadline| now >= deadline)
            {
                let reservation = self.paths.reserve_probe(path, bytes, now, &mut self.rng)?;
                let Some(path::Control::Challenge(data)) = reservation.control() else {
                    return Err(Error::InvalidDescriptor);
                };
                (reservation, Some(Control::Challenge(data)))
            } else {
                let slot = self
                    .controls
                    .iter()
                    .position(|r| r.is_some_and(|r| r.ready && !r.acknowledged))
                    .ok_or(Error::Capacity)?;
                let record = self.controls[slot].ok_or(Error::InvalidDescriptor)?;
                if record.sent.iter().all(Option::is_some) {
                    return Err(Error::Capacity);
                }
                let value = match record.kind {
                    ReliableControl::Advertise(handle) => {
                        let cid = self.local.get(handle)?;
                        Control::NewConnectionId {
                            sequence: cid.sequence,
                            retire_prior_to: cid.retire_prior_to,
                            cid: cid.cid,
                            reset_token: cid.token.ok_or(Error::InvalidConfig)?,
                        }
                    }
                    ReliableControl::Retire(handle) => Control::RetireConnectionId {
                        sequence: self
                            .peer
                            .as_ref()
                            .ok_or(Error::HandshakeNotInstalled)?
                            .retirement_sequence(handle, Cid::new(destination.as_bytes())?)?,
                    },
                };
                reliable = Some(slot);
                (self.paths.reserve_datagram(path, bytes)?, Some(value))
            }
        } else {
            (self.paths.reserve_datagram(path, bytes)?, None)
        };
        let record = PendingRecord {
            descriptor,
            reservation,
            address,
            destination,
            peer,
            control: wire_control,
            reliable,
            packet,
        };
        self.pending[index] = Some(record);
        Ok(PendingTransmit {
            record,
            local_cid: self.config.local_cid,
        })
    }
    fn complete(&mut self, completion: AdapterCompletion) -> Result<(), Error> {
        let record = completion.record;
        let index = usize::from(record.reservation.path().slot);
        if self.pending.get(index).copied().flatten() != Some(record) {
            return Err(Error::InvalidDescriptor);
        }
        if self.paths.snapshot(record.reservation.path())?.address != record.address {
            return Err(Error::InvalidDescriptor);
        }
        // Nothing can mutate CIDs between reservation and completion. Admission
        // cancels affected records first, so these checks precede every commit.
        if let Some(peer) = record.peer {
            self.peer
                .as_ref()
                .ok_or(Error::HandshakeNotInstalled)?
                .check_send(peer, record.address.local, record.address.remote)?;
        }
        if let Some(now) = completion.accepted_at {
            self.clock(now)?;
            self.paths.adapter_accepted(record.reservation, now)?;
            if let Some(peer) = record.peer {
                self.peer
                    .as_mut()
                    .ok_or(Error::HandshakeNotInstalled)?
                    .record_sent(peer, record.address.local, record.address.remote)?;
            } else if self.zero_peer {
                self.zero_peer_used = true;
            } else {
                self.bootstrap_used = Some((record.destination, record.address));
            }
            if completion.initial_advertised
                && let Some(local) = self.local_initial
            {
                self.local.mark_advertised(local)?;
            }
            if let Some(slot) = record.reliable {
                let control = self.controls[slot]
                    .as_mut()
                    .ok_or(Error::InvalidDescriptor)?;
                let sent = control
                    .sent
                    .iter_mut()
                    .find(|pn| pn.is_none())
                    .ok_or(Error::Capacity)?;
                *sent = Some(record.packet.value);
                control.ready = false;
                if let ReliableControl::Advertise(handle) = control.kind {
                    self.local.mark_advertised(handle)?;
                }
            }
        } else {
            self.paths.adapter_rejected(record.reservation)?;
        }
        self.pending[index] = None;
        Ok(())
    }
    fn reset(&self, candidate: ResetCandidate) -> bool {
        if !candidate.long_enough {
            return false;
        }
        if self.zero_peer {
            return self.zero_peer_used
                && candidate.address == self.config.initial
                && self
                    .zero_peer_token
                    .is_some_and(|token| bool::from(token.as_bytes().ct_eq(&candidate.tail[5..])));
        }
        self.peer.as_ref().is_some_and(|peer| {
            peer.detect_stateless_reset(&candidate.tail, candidate.address.remote)
        })
    }
    fn timer(&self) -> Option<TimerObservation> {
        let mut deadline = None;
        for path in self.paths.identities() {
            let probe = if self.confirmed
                && self
                    .paths
                    .snapshot(path)
                    .ok()
                    .is_some_and(|snapshot| snapshot.available_bytes >= 50)
                && self.destination(path).is_ok()
            {
                self.paths.probe_deadline(path).ok().flatten()
            } else {
                None
            };
            for observed in [self.paths.validation_deadline(path).ok().flatten(), probe]
                .into_iter()
                .flatten()
            {
                deadline = Some(deadline.map_or(observed, |old: u64| old.min(observed)));
            }
        }
        Some(TimerObservation {
            generation: self.config.generation,
            revision: self.revision,
            deadline: deadline?,
        })
    }
    fn timeout(&mut self, timer: TimerObservation, now: u64) -> Result<Option<Decision>, Error> {
        if timer.generation != self.config.generation
            || timer.revision != self.revision
            || self
                .timer()
                .is_none_or(|current| current.deadline != timer.deadline)
        {
            return Err(Error::StaleTimer);
        }
        if now < timer.deadline {
            return Err(Error::TimerNotDue);
        }
        self.clock(now)?;
        let mut result = None;
        while let Some(path) = self.paths.expire(now)? {
            self.pending[usize::from(path.slot)] = None;
            let decision = self.migration.failed(path, &self.paths)?;
            self.apply_decision(decision)?;
            result = Some(decision);
        }
        Ok(result)
    }
}
impl<R> Drop for State<'_, R> {
    fn drop(&mut self) {
        self.pending.fill(None);
        self.paths.retire_all();
    }
}

impl<R: RngCore + CryptoRng> State<'_, R> {
    fn learn_peer_cid<const P: usize, const E: usize>(
        &mut self,
        arena: &authority::Arena<P, E>,
        grant: authority::InitialPeerCid,
    ) -> Result<(), Error> {
        let (facts, source, destination) = arena.consume_initial_peer_cid(grant)?;
        if facts.generation() != self.config.generation {
            return Err(Error::WrongGeneration);
        }
        if facts.space() != PacketNumberSpace::Initial {
            return Err(Error::WrongLevel);
        }
        if self.config.role == Role::Client {
            if destination != self.config.local_cid {
                return Err(Error::WrongDestination);
            }
        } else if let Some(original) = self.initial_received_destination
            && destination != original
            && destination != self.config.local_cid
        {
            return Err(Error::WrongDestination);
        }
        if let Some(previous) = self.learned_peer_initial {
            if previous != source {
                return Err(Error::PeerCidMismatch);
            }
            return Ok(());
        }
        if self.installed {
            return Err(Error::AlreadyInstalled);
        }
        self.learned_peer_initial = Some(source);
        self.initial_received_destination = Some(destination);
        self.zero_peer = source.is_zero();
        self.zero_peer_used =
            self.zero_peer && self.bootstrap_used == Some((source, self.config.initial));
        Ok(())
    }
    fn apply_retry(&mut self, grant: authority::RetryPeerCid) -> Result<(), Error> {
        if grant.generation() != self.config.generation {
            return Err(Error::WrongGeneration);
        }
        if self.config.role != Role::Client
            || self.retry_seen
            || self.learned_peer_initial.is_some()
            || self.installed
        {
            return Err(Error::RetryNotAllowed);
        }
        if grant.original_destination_cid() != self.original_bootstrap.as_bytes()
            || grant.client_source_cid() != self.config.local_cid.as_bytes()
        {
            return Err(Error::WrongDestination);
        }
        let destination = Destination::new(grant.source_cid())?;
        self.config.bootstrap_destination = destination;
        self.bootstrap_used = self
            .bootstrap_used
            .filter(|(cid, address)| *cid == destination && *address == self.config.initial);
        self.retry_seen = true;
        Ok(())
    }
    fn destination_allowed(&self, destination: Destination, kind: IngressKind) -> bool {
        let routed = if self.config.local_cid.is_zero() {
            destination.is_zero()
        } else {
            self.local.route(destination.as_bytes()).is_some()
        };
        routed
            || (self.config.role == Role::Server
                && matches!(kind, IngressKind::Initial | IngressKind::Early)
                && self.initial_received_destination == Some(destination))
    }
    fn confirm_handshake(&mut self) {
        if !self.confirmed {
            self.confirmed = true;
            self.migration.handshake_confirmed();
            self.tls_confirmation = Some(HandshakeConfirmation {
                generation: self.config.generation,
            });
        }
    }
    fn handshake(&mut self, ready: super::connection_authority::PathReady) -> Result<(), Error> {
        if ready.generation() != self.config.generation {
            return Err(Error::WrongGeneration);
        }
        let expected = if self.config.role == Role::Client {
            crate::parameters::Peer::Server
        } else {
            crate::parameters::Peer::Client
        };
        if ready.peer_role() != expected {
            return Err(Error::InvalidConfig);
        }
        let parameters = ready.peer_parameters().map_err(|_| Error::InvalidConfig)?;
        let preferred = if let Some(bytes) = parameters.get(13) {
            let preferred = migration::PreferredAddress::parse(bytes)?;
            let address = if self.config.initial.local.is_ipv4() {
                preferred.ipv4
            } else {
                preferred.ipv6
            };
            address
                .map(|remote| {
                    Ok::<_, Error>(PreferredPeer {
                        address: Address {
                            local: self.config.initial.local,
                            remote,
                        },
                        cid: Cid::new(preferred.connection_id)?,
                        reset_token: ResetToken::new(*preferred.reset_token),
                    })
                })
                .transpose()?
        } else {
            None
        };
        self.install(VerifiedParameters {
            peer_cid: Destination::new(ready.peer_initial_cid())?,
            peer_active_limit: parameters
                .get_integer(14, 2)
                .map_err(|_| Error::InvalidConfig)?,
            disable_active_migration: parameters.get(12).is_some(),
            initial_reset_token: parameters
                .get(2)
                .map(|bytes| {
                    bytes
                        .try_into()
                        .map(ResetToken::new)
                        .map_err(|_| Error::InvalidConfig)
                })
                .transpose()?,
            preferred,
        })?;
        if ready.server_handshake_confirmed() {
            self.confirm_handshake();
        }
        Ok(())
    }
    #[cfg(test)]
    fn ingress(&mut self, context: PathContext) -> Result<PathIdentity, Error> {
        self.ingress_packet(context, None, IngressKind::Ordinary)
    }
    fn ingress_packet(
        &mut self,
        context: PathContext,
        packet: Option<(u64, bool)>,
        kind: IngressKind,
    ) -> Result<PathIdentity, Error> {
        // An authenticated receive can wait in a mailbox while another
        // operation advances the owner clock. Its observed arrival timestamp
        // is immutable, but processing must never rewind numerical timers.
        self.clock(self.now.max(context.now))?;
        if context.datagram_bytes == 0 {
            return Err(Error::InvalidConfig);
        }
        if !self.destination_allowed(context.destination, kind) {
            return Err(Error::WrongDestination);
        }
        if (self.zero_peer || self.config.local_cid.is_zero())
            && context.address != self.config.initial
        {
            return Err(Error::FixedZeroCid);
        }
        if context.address != self.config.initial {
            if !self.confirmed {
                return Err(Error::HandshakeNotInstalled);
            }
            match self.config.role {
                Role::Client => {
                    if self.paths.find(context.address).is_none()
                        || (context.address.remote != self.config.initial.remote
                            && self.preferred.is_none_or(|p| p.0 != context.address))
                    {
                        return Err(Error::InvalidConfig);
                    }
                }
                Role::Server if context.address.local != self.config.initial.local => {
                    if self
                        .config
                        .preferred_server
                        .is_none_or(|p| p.address != context.address.local)
                    {
                        return Err(Error::InvalidConfig);
                    }
                    if !self.preferred_advertised {
                        return Err(Error::PreferredAdvertisementRequired);
                    }
                }
                _ => {}
            }
        }
        if let Some((id, address, bytes, path)) = self.last_datagram {
            if context.datagram_id < id {
                return Err(Error::StaleIngress);
            }
            if context.datagram_id == id {
                if address != context.address
                    || bytes != context.datagram_bytes
                    || self.paths.snapshot(path)?.address != address
                {
                    return Err(Error::StaleIngress);
                }
                self.inbound[usize::from(path.slot)] = Some(context.destination);
                return Ok(path);
            }
        }
        let path = if let Some(path) = self.paths.find(context.address) {
            path
        } else {
            let active = self.migration.active();
            let fallback = self.migration.fallback();
            let mut reclaim = self
                .paths
                .identities()
                .find(|path| *path != active && Some(*path) != fallback);
            if reclaim.is_none()
                && packet.is_some_and(|(pn, non_probing)| {
                    non_probing
                        && self
                            .migration
                            .largest_non_probing()
                            .is_none_or(|old| pn > old)
                })
                && !self.paths.snapshot(active)?.address_validated
                && fallback != Some(active)
            {
                let decision = self.migration.failed(active, &self.paths)?;
                self.apply_decision(decision)?;
                reclaim = Some(active);
            }
            if let Some(path) = reclaim {
                self.retire_path(path)?;
            }
            self.paths
                .insert(context.address, InitialValidation::Unvalidated, self.now)?
        };
        self.paths.received(path, context.datagram_bytes)?;
        self.inbound[usize::from(path.slot)] = Some(context.destination);
        self.last_datagram = Some((
            context.datagram_id,
            context.address,
            context.datagram_bytes,
            path,
        ));
        Ok(path)
    }
    fn new_cid(
        &mut self,
        sequence: u64,
        retire_prior_to: u64,
        id: Cid,
        reset_token: ResetToken,
    ) -> Result<(), Error> {
        if self.zero_peer {
            return Err(Error::FixedZeroCid);
        }
        self.peer
            .as_mut()
            .ok_or(Error::HandshakeNotInstalled)?
            .accept_new_authenticated(sequence, retire_prior_to, id, reset_token)?;
        self.queue_retirements()?;
        self.bind_peer(self.migration.active(), None)?;
        Ok(())
    }
    fn retire_cid(&mut self, sequence: u64, destination: Destination) -> Result<(), Error> {
        if self.config.local_cid.is_zero() {
            return Err(Error::FixedZeroCid);
        }
        self.local
            .retire_authenticated(sequence, destination.as_bytes())?;
        for record in self.controls.iter_mut().flatten() {
            if let ReliableControl::Advertise(handle) = record.kind
                && self.local.get(handle).is_err()
            {
                record.ready = false;
                record.acknowledged = true;
            }
        }
        Ok(())
    }
    fn frame<const P: usize, const E: usize>(
        &mut self,
        arena: &authority::Arena<P, E>,
        grant: authority::PathGrant,
    ) -> Result<Outcome, Error> {
        let (packet, frame, context) = arena.consume_path(grant)?;
        if packet.generation() != self.config.generation {
            return Err(Error::WrongGeneration);
        }
        if !matches!(frame, PathFrame::PacketProcessed { .. })
            && packet.space() != PacketNumberSpace::ApplicationData
        {
            return Err(Error::WrongLevel);
        }
        let census = match frame {
            PathFrame::PacketProcessed { non_probing } => {
                Some((packet.packet_number(), non_probing))
            }
            _ => None,
        };
        let kind = if packet.space() == PacketNumberSpace::Initial {
            IngressKind::Initial
        } else {
            IngressKind::Ordinary
        };
        let path = self.ingress_packet(context, census, kind)?;
        let mut decision = Decision::Unchanged;
        let mut validated = None;
        match frame {
            PathFrame::Challenge(data) => {
                self.paths.queue_response(path, data)?;
            }
            PathFrame::Response(data) => {
                validated = self.paths.response(data, self.now)?;
                if let Some(validated) = validated {
                    decision = self.migration.validated(validated.path, &self.paths)?;
                    self.apply_decision(decision)?;
                }
            }
            PathFrame::NewConnectionId {
                sequence,
                retire_prior_to,
                id,
                reset_token,
            } => {
                self.new_cid(sequence, retire_prior_to, id, reset_token)?;
            }
            PathFrame::RetireConnectionId { sequence } => {
                self.retire_cid(sequence, context.destination)?;
            }
            PathFrame::HandshakeDone => {
                if self.config.role != Role::Client || !self.installed {
                    return Err(Error::InvalidConfig);
                }
                self.confirm_handshake();
                if !self.preferred_started
                    && let Some((address, cid)) = self.preferred
                    && self.paths.find(address).is_none()
                {
                    let path = self.paths.insert(
                        address,
                        InitialValidation::ClientUnvalidated,
                        self.now,
                    )?;
                    self.bindings[usize::from(path.slot)] = Some(cid);
                    decision = self.migration.initiate_client(path, true, &self.paths)?;
                    self.apply_decision(decision)?;
                    self.preferred_started = true;
                }
            }
            PathFrame::PacketProcessed { non_probing } => {
                if packet.space() == PacketNumberSpace::ApplicationData {
                    self.bind_peer(path, Some(self.migration.active()))?;
                    decision = self.migration.packet(
                        path,
                        packet.packet_number(),
                        non_probing,
                        &self.paths,
                    )?;
                    self.apply_decision(decision)?;
                }
            }
        }
        Ok(Outcome::Frame {
            path,
            decision,
            validated,
            recovery_reset: self.recovery_reset.take(),
            tls_confirmation: self.tls_confirmation.take(),
        })
    }
    fn acknowledge(&mut self, ack: super::recovery_owner::PathAck) -> Result<(), Error> {
        if ack.authentication().generation() != self.config.generation {
            return Err(Error::WrongGeneration);
        }
        if ack.authentication().space() != PacketNumberSpace::ApplicationData {
            return Ok(());
        }
        for record in self.controls.iter_mut().flatten() {
            if !record.acknowledged
                && record.sent.iter().flatten().any(|pn| {
                    ack.ranges()
                        .iter()
                        .any(|range| range.start <= *pn && *pn <= range.end)
                })
            {
                if let ReliableControl::Retire(handle) = record.kind {
                    self.peer
                        .as_mut()
                        .ok_or(Error::HandshakeNotInstalled)?
                        .acknowledge_retirement(handle)?;
                }
                record.acknowledged = true;
                record.ready = false;
            }
        }
        Ok(())
    }
    fn pto(&mut self, grant: super::recovery_owner::PathPtoGrant) -> Result<(), Error> {
        if grant.generation() != self.config.generation {
            return Err(Error::WrongGeneration);
        }
        if grant.space() == PacketNumberSpace::ApplicationData
            && let Some(record) = self
                .controls
                .iter_mut()
                .flatten()
                .find(|record| !record.acknowledged && record.sent.iter().any(Option::is_some))
        {
            record.ready = true;
        }
        Ok(())
    }
    fn lost(&mut self, packet: super::recovery_owner::PathLostPacket) -> Result<(), Error> {
        if packet.generation() != self.config.generation {
            return Err(Error::WrongGeneration);
        }
        if packet.packet().space != PacketNumberSpace::ApplicationData {
            return Ok(());
        }
        for record in self.controls.iter_mut().flatten() {
            if record.acknowledged {
                continue;
            }
            for sent in &mut record.sent {
                if *sent == Some(packet.packet().value) {
                    *sent = None;
                    record.ready = true;
                }
            }
        }
        Ok(())
    }
}

pub enum Command {
    LearnPeerCid(authority::InitialPeerCid),
    ApplyRetry(authority::RetryPeerCid),
    EarlyPreflight(super::early_owner::PathCheck),
    EarlyAdmission(super::early_owner::EarlyAdmission),
    EarlyRelease(super::early_owner::PathRelease<64>),
    Frame(authority::PathGrant),
    Ack(super::recovery_owner::PathAck),
    Lost(super::recovery_owner::PathLostPacket),
    Pto(super::recovery_owner::PathPtoGrant),
    Reserve {
        path: PathIdentity,
        bytes: u64,
        packet: PacketNumber,
        now: u64,
    },
    ReserveControl {
        path: PathIdentity,
        bytes: u64,
        packet: PacketNumber,
        now: u64,
    },
    AdapterComplete(AdapterCompletion),
    CheckReset(ResetCandidate),
    ObserveTimer,
    Timeout {
        timer: TimerObservation,
        now: u64,
    },
    IssueCid,
    Handshake(super::connection_authority::PathReady),
    RetirePath(PathIdentity),
    Inspect,
    Retire,
}
pub enum Outcome {
    PeerCidLearned,
    RetryApplied,
    EarlyChecked(super::early_owner::PathChecked),
    EarlyCheckRejected {
        check: super::early_owner::PathCheck,
        error: Error,
    },
    EarlyAdmitted {
        path: PathIdentity,
    },
    EarlyAdmissionRejected {
        admission: super::early_owner::EarlyAdmission,
        error: Error,
    },
    EarlyReleased(super::early_owner::ReleaseCompletion),
    EarlyReleaseRejected {
        release: super::early_owner::PathRelease<64>,
        error: Error,
    },
    Installed,
    Frame {
        path: PathIdentity,
        decision: Decision,
        validated: Option<path::Validated>,
        recovery_reset: Option<RecoveryResetGrant>,
        tls_confirmation: Option<HandshakeConfirmation>,
    },
    AckApplied,
    LossApplied,
    PtoApplied,
    Reserved(PendingTransmit),
    AdapterCompleted,
    Reset(bool),
    Timer(Option<TimerObservation>),
    Expired {
        decision: Option<Decision>,
        recovery_reset: Option<RecoveryResetGrant>,
    },
    Issued(Option<Control>),
    HandshakeInstalled {
        tls_confirmation: Option<HandshakeConfirmation>,
    },
    PathRetired,
    Snapshot,
    Rejected(Error),
    Retired,
}
impl Outcome {
    fn is_rejected(&self) -> bool {
        matches!(
            self,
            Self::Rejected(_)
                | Self::EarlyCheckRejected { .. }
                | Self::EarlyAdmissionRejected { .. }
                | Self::EarlyReleaseRejected { .. }
        )
    }
}
pub struct Reply {
    pub descriptor: Descriptor,
    pub snapshot: Snapshot,
    pub outcome: Outcome,
}
struct Request {
    descriptor: Descriptor,
    command: Command,
}
/// Caller-owned one-request exchange, not a mutable state-owner escape hatch.
pub struct Exchange {
    request: RefCell<Option<Request>>,
    reply: RefCell<Option<Reply>>,
}
impl Exchange {
    pub const fn new() -> Self {
        Self {
            request: RefCell::new(None),
            reply: RefCell::new(None),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.request.borrow().is_none() && self.reply.borrow().is_none()
    }
    fn put(&self, request: Request) -> Result<(), ServiceError> {
        if !self.is_empty() {
            return Err(ServiceError::OccupiedSlot);
        }
        *self.request.borrow_mut() = Some(request);
        Ok(())
    }
    fn take(&self, wire: [u8; 16]) -> Result<Request, ServiceError> {
        let request = self
            .request
            .borrow_mut()
            .take()
            .ok_or(ServiceError::MissingSlot)?;
        same(encode(request.descriptor), wire)?;
        Ok(request)
    }
    fn reply(&self, reply: Reply) -> Result<(), ServiceError> {
        let mut slot = self.reply.borrow_mut();
        if slot.is_some() {
            return Err(ServiceError::OccupiedSlot);
        }
        *slot = Some(reply);
        Ok(())
    }
    fn take_reply(&self, descriptor: Descriptor) -> Result<Reply, ServiceError> {
        let reply = self
            .reply
            .borrow_mut()
            .take()
            .ok_or(ServiceError::MissingSlot)?;
        if reply.descriptor != descriptor {
            return Err(ServiceError::Correlation);
        }
        Ok(reply)
    }
}
impl Default for Exchange {
    fn default() -> Self {
        Self::new()
    }
}
struct Clear<'a>(&'a Exchange);
impl Drop for Clear<'_> {
    fn drop(&mut self) {
        self.0.request.borrow_mut().take();
        self.0.reply.borrow_mut().take();
    }
}
#[derive(Debug)]
pub enum ServiceError {
    Hibana(EndpointError),
    CommandsClosed,
    RepliesClosed,
    OccupiedSlot,
    MissingSlot,
    Correlation,
    UnexpectedCommand,
    UnexpectedLabel(u8),
    SequenceExhausted,
}
impl From<EndpointError> for ServiceError {
    fn from(e: EndpointError) -> Self {
        Self::Hibana(e)
    }
}
fn encode(d: Descriptor) -> [u8; 16] {
    let mut wire = [0; 16];
    wire[..8].copy_from_slice(&d.generation.to_be_bytes());
    wire[8..].copy_from_slice(&d.sequence.to_be_bytes());
    wire
}
fn same(left: [u8; 16], right: [u8; 16]) -> Result<(), ServiceError> {
    if left == right {
        Ok(())
    } else {
        Err(ServiceError::Correlation)
    }
}
/// Distinct client and owner endpoint values remain borrowed from the outer
/// composed global session. No actor recreates or synchronously polls endpoints.
pub async fn run_borrowed<
    R: RngCore + CryptoRng,
    const C: u8,
    const O: u8,
    const P: usize,
    const E: usize,
    const Q: usize,
    const S: usize,
>(
    client: &mut Endpoint<'_, C>,
    owner: &mut Endpoint<'_, O>,
    state: State<'_, R>,
    arena: &authority::Arena<P, E>,
    commands: Receiver<'_, '_, Command, Q>,
    replies: Sender<'_, '_, Reply, S>,
    exchange: &mut Exchange,
) -> Result<(), ServiceError> {
    if !exchange.is_empty() {
        return Err(ServiceError::OccupiedSlot);
    }
    let generation = state.config.generation;
    let exchange = &*exchange;
    let _clear = Clear(exchange);
    let mut command = core::pin::pin!(command_role(
        client, generation, commands, replies, exchange
    ));
    let mut owner = core::pin::pin!(owner_role(owner, state, arena, exchange));
    runtime::TaskSet::new([command.as_mut(), owner.as_mut()]).await
}

async fn command_role<const C: u8, const Q: usize, const S: usize>(
    endpoint: &mut Endpoint<'_, C>,
    generation: u64,
    mut commands: Receiver<'_, '_, Command, Q>,
    mut replies: Sender<'_, '_, Reply, S>,
    exchange: &Exchange,
) -> Result<(), ServiceError> {
    let installed = Descriptor {
        generation,
        sequence: 0,
    };
    let wire = encode(installed);
    endpoint.send::<p::Install>(&wire).await?;
    same(endpoint.recv::<p::Installed>().await?, wire)?;
    replies
        .send(exchange.take_reply(installed)?)
        .await
        .map_err(|_| ServiceError::RepliesClosed)?;
    let mut sequence = 1u64;
    loop {
        let command = commands
            .recv()
            .await
            .map_err(|_| ServiceError::CommandsClosed)?;
        let descriptor = Descriptor {
            generation,
            sequence,
        };
        let wire = encode(descriptor);
        let reservation = matches!(
            command,
            Command::Reserve { .. } | Command::ReserveControl { .. }
        );
        match command {
            command @ Command::LearnPeerCid(_) => {
                exchange.put(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::LearnPeerCid>(&wire).await?;
            }
            command @ Command::ApplyRetry(_) => {
                exchange.put(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::ApplyRetry>(&wire).await?;
            }
            command @ Command::EarlyPreflight(_) => {
                exchange.put(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::EarlyPreflight>(&wire).await?;
            }
            command @ Command::EarlyAdmission(_) => {
                exchange.put(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::EarlyAdmission>(&wire).await?;
            }
            command @ Command::EarlyRelease(_) => {
                exchange.put(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::EarlyRelease>(&wire).await?;
            }
            command @ Command::Frame(_) => {
                exchange.put(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::Frame>(&wire).await?;
            }
            command @ Command::Ack(_) => {
                exchange.put(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::Ack>(&wire).await?;
            }
            command @ Command::Lost(_) => {
                exchange.put(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::Lost>(&wire).await?;
            }
            command @ Command::Pto(_) => {
                exchange.put(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::Pto>(&wire).await?;
            }
            command @ Command::CheckReset(_) => {
                exchange.put(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::CheckReset>(&wire).await?;
            }
            command @ Command::ObserveTimer => {
                exchange.put(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::ObserveTimer>(&wire).await?;
            }
            command @ Command::Timeout { .. } => {
                exchange.put(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::Timeout>(&wire).await?;
            }
            command @ Command::IssueCid => {
                exchange.put(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::IssueCid>(&wire).await?;
            }
            command @ Command::Handshake(_) => {
                exchange.put(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::Handshake>(&wire).await?;
            }
            command @ Command::RetirePath(_) => {
                exchange.put(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::RetirePath>(&wire).await?;
            }
            command @ Command::Inspect => {
                exchange.put(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::Inspect>(&wire).await?;
            }
            command @ Command::Reserve { .. } => {
                exchange.put(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::Reserve>(&wire).await?;
            }
            command @ Command::ReserveControl { .. } => {
                exchange.put(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::ReserveControl>(&wire).await?;
            }
            command @ Command::Retire => {
                exchange.put(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::RetireRequested>(&wire).await?;
                same(endpoint.recv::<p::Retired>().await?, wire)?;
                replies
                    .send(exchange.take_reply(descriptor)?)
                    .await
                    .map_err(|_| ServiceError::RepliesClosed)?;
                endpoint.send::<p::RetirementAcknowledged>(&wire).await?;
                return Ok(());
            }
            Command::AdapterComplete(_) => return Err(ServiceError::UnexpectedCommand),
        }
        let branch = endpoint.offer().await?;
        let (observed, reserved) = match branch.label() {
            p::APPLIED if !reservation => (branch.recv::<p::Applied>().await?, false),
            p::RESERVED if reservation => (branch.recv::<p::Reserved>().await?, true),
            p::REJECTED => (branch.recv::<p::Rejected>().await?, false),
            label => return Err(ServiceError::UnexpectedLabel(label)),
        };
        same(observed, wire)?;
        replies
            .send(exchange.take_reply(descriptor)?)
            .await
            .map_err(|_| ServiceError::RepliesClosed)?;
        endpoint.send::<p::ResultTaken>(&wire).await?;
        sequence = sequence
            .checked_add(1)
            .ok_or(ServiceError::SequenceExhausted)?;
        if reserved {
            let command = commands
                .recv()
                .await
                .map_err(|_| ServiceError::CommandsClosed)?;
            if !matches!(command, Command::AdapterComplete(_)) {
                return Err(ServiceError::UnexpectedCommand);
            }
            let descriptor = Descriptor {
                generation,
                sequence,
            };
            let wire = encode(descriptor);
            exchange.put(Request {
                descriptor,
                command,
            })?;
            endpoint.send::<p::AdapterComplete>(&wire).await?;
            let branch = endpoint.offer().await?;
            let observed = match branch.label() {
                p::APPLIED => branch.recv::<p::Applied>().await?,
                p::REJECTED => branch.recv::<p::Rejected>().await?,
                label => return Err(ServiceError::UnexpectedLabel(label)),
            };
            same(observed, wire)?;
            replies
                .send(exchange.take_reply(descriptor)?)
                .await
                .map_err(|_| ServiceError::RepliesClosed)?;
            endpoint.send::<p::ResultTaken>(&wire).await?;
            sequence = sequence
                .checked_add(1)
                .ok_or(ServiceError::SequenceExhausted)?;
        }
        runtime::yield_now().await;
    }
}

async fn owner_role<R: RngCore + CryptoRng, const O: u8, const P: usize, const E: usize>(
    endpoint: &mut Endpoint<'_, O>,
    mut state: State<'_, R>,
    arena: &authority::Arena<P, E>,
    exchange: &Exchange,
) -> Result<(), ServiceError> {
    let generation = state.config.generation;
    let installed = Descriptor {
        generation,
        sequence: 0,
    };
    let wire = endpoint.recv::<p::Install>().await?;
    same(wire, encode(installed))?;
    exchange.reply(Reply {
        descriptor: installed,
        snapshot: state.snapshot(),
        outcome: Outcome::Installed,
    })?;
    endpoint.send::<p::Installed>(&wire).await?;
    let mut sequence = 1u64;
    loop {
        let branch = endpoint.offer().await?;
        let label = branch.label();
        let wire = match label {
            p::LEARN_PEER_CID => branch.recv::<p::LearnPeerCid>().await?,
            p::APPLY_RETRY => branch.recv::<p::ApplyRetry>().await?,
            p::EARLY_PREFLIGHT => branch.recv::<p::EarlyPreflight>().await?,
            p::EARLY_ADMISSION => branch.recv::<p::EarlyAdmission>().await?,
            p::EARLY_RELEASE => branch.recv::<p::EarlyRelease>().await?,
            p::FRAME => branch.recv::<p::Frame>().await?,
            p::ACK => branch.recv::<p::Ack>().await?,
            p::LOST => branch.recv::<p::Lost>().await?,
            p::PTO => branch.recv::<p::Pto>().await?,
            p::CHECK_RESET => branch.recv::<p::CheckReset>().await?,
            p::OBSERVE_TIMER => branch.recv::<p::ObserveTimer>().await?,
            p::TIMEOUT => branch.recv::<p::Timeout>().await?,
            p::ISSUE_CID => branch.recv::<p::IssueCid>().await?,
            p::HANDSHAKE => branch.recv::<p::Handshake>().await?,
            p::RETIRE_PATH => branch.recv::<p::RetirePath>().await?,
            p::INSPECT => branch.recv::<p::Inspect>().await?,
            p::RESERVE => branch.recv::<p::Reserve>().await?,
            p::RESERVE_CONTROL => branch.recv::<p::ReserveControl>().await?,
            p::RETIRE_REQUESTED => branch.recv::<p::RetireRequested>().await?,
            label => return Err(ServiceError::UnexpectedLabel(label)),
        };
        let request = exchange.take(wire)?;
        let descriptor = Descriptor {
            generation,
            sequence,
        };
        same(encode(request.descriptor), encode(descriptor))?;
        if label == p::RETIRE_REQUESTED {
            if !matches!(request.command, Command::Retire) {
                return Err(ServiceError::UnexpectedCommand);
            }
            state.pending.fill(None);
            state.paths.retire_all();
            exchange.reply(Reply {
                descriptor,
                snapshot: state.snapshot(),
                outcome: Outcome::Retired,
            })?;
            endpoint.send::<p::Retired>(&wire).await?;
            same(endpoint.recv::<p::RetirementAcknowledged>().await?, wire)?;
            return Ok(());
        }
        let reservation = matches!(label, p::RESERVE | p::RESERVE_CONTROL);
        let outcome = state.execute(label, descriptor, request.command, arena)?;
        let reserved = matches!(outcome, Outcome::Reserved(_));
        let rejected = outcome.is_rejected();
        exchange.reply(Reply {
            descriptor,
            snapshot: state.snapshot(),
            outcome,
        })?;
        if reserved {
            endpoint.send::<p::Reserved>(&wire).await?;
        } else if rejected {
            endpoint.send::<p::Rejected>(&wire).await?;
        } else if !reservation {
            endpoint.send::<p::Applied>(&wire).await?;
        } else {
            return Err(ServiceError::UnexpectedCommand);
        }
        same(endpoint.recv::<p::ResultTaken>().await?, wire)?;
        sequence = sequence
            .checked_add(1)
            .ok_or(ServiceError::SequenceExhausted)?;
        if reserved {
            // The successful reserve branch cannot roll back into unrelated
            // work until this exact adapter callback is consumed.
            let wire = endpoint.recv::<p::AdapterComplete>().await?;
            let request = exchange.take(wire)?;
            let descriptor = Descriptor {
                generation,
                sequence,
            };
            same(encode(request.descriptor), encode(descriptor))?;
            let outcome = state.execute(p::ADAPTER_COMPLETE, descriptor, request.command, arena)?;
            let rejected = outcome.is_rejected();
            exchange.reply(Reply {
                descriptor,
                snapshot: state.snapshot(),
                outcome,
            })?;
            if rejected {
                endpoint.send::<p::Rejected>(&wire).await?;
            } else {
                endpoint.send::<p::Applied>(&wire).await?;
            }
            same(endpoint.recv::<p::ResultTaken>().await?, wire)?;
            sequence = sequence
                .checked_add(1)
                .ok_or(ServiceError::SequenceExhausted)?;
        }
        runtime::yield_now().await;
    }
}
impl<R: RngCore + CryptoRng> State<'_, R> {
    fn execute<const P: usize, const E: usize>(
        &mut self,
        label: u8,
        descriptor: Descriptor,
        command: Command,
        arena: &authority::Arena<P, E>,
    ) -> Result<Outcome, ServiceError> {
        let mutable = !matches!(
            command,
            Command::Inspect
                | Command::ObserveTimer
                | Command::CheckReset(_)
                | Command::EarlyPreflight(_)
        );
        let revision = if mutable {
            self.revision.checked_add(1)
        } else {
            Some(self.revision)
        };
        let Some(revision) = revision else {
            return Ok(Outcome::Rejected(Error::SequenceExhausted));
        };
        let result = match (label, command) {
            (p::LEARN_PEER_CID, Command::LearnPeerCid(grant)) => self
                .learn_peer_cid(arena, grant)
                .map(|()| Outcome::PeerCidLearned),
            (p::APPLY_RETRY, Command::ApplyRetry(grant)) => {
                self.apply_retry(grant).map(|()| Outcome::RetryApplied)
            }
            (p::EARLY_PREFLIGHT, Command::EarlyPreflight(check)) => Ok(self.early_check(check)),
            (p::EARLY_ADMISSION, Command::EarlyAdmission(admission)) => {
                Ok(self.early_admit(admission))
            }
            (p::EARLY_RELEASE, Command::EarlyRelease(release)) => Ok(self.early_release(release)),
            (p::FRAME, Command::Frame(grant)) => self.frame(arena, grant),
            (p::ACK, Command::Ack(ack)) => self.acknowledge(ack).map(|()| Outcome::AckApplied),
            (p::LOST, Command::Lost(packet)) => self.lost(packet).map(|()| Outcome::LossApplied),
            (
                p::RESERVE,
                Command::Reserve {
                    path,
                    bytes,
                    packet,
                    now,
                },
            ) => self
                .reserve(descriptor, path, bytes, packet, false, now)
                .map(Outcome::Reserved),
            (
                p::RESERVE_CONTROL,
                Command::ReserveControl {
                    path,
                    bytes,
                    packet,
                    now,
                },
            ) => {
                if !self.confirmed {
                    Err(Error::HandshakeNotInstalled)
                } else {
                    self.reserve(descriptor, path, bytes, packet, true, now)
                        .map(Outcome::Reserved)
                }
            }
            (p::ADAPTER_COMPLETE, Command::AdapterComplete(completion)) => self
                .complete(completion)
                .map(|()| Outcome::AdapterCompleted),
            (p::PTO, Command::Pto(grant)) => self.pto(grant).map(|()| Outcome::PtoApplied),
            (p::CHECK_RESET, Command::CheckReset(candidate)) => {
                Ok(Outcome::Reset(self.reset(candidate)))
            }
            (p::OBSERVE_TIMER, Command::ObserveTimer) => Ok(Outcome::Timer(self.timer())),
            (p::TIMEOUT, Command::Timeout { timer, now }) => {
                self.timeout(timer, now).map(|decision| Outcome::Expired {
                    decision,
                    recovery_reset: self.recovery_reset.take(),
                })
            }
            (p::ISSUE_CID, Command::IssueCid) => self.issue_cid().map(Outcome::Issued),
            (p::HANDSHAKE, Command::Handshake(ready)) => {
                self.handshake(ready).map(|()| Outcome::HandshakeInstalled {
                    tls_confirmation: self.tls_confirmation.take(),
                })
            }
            (p::RETIRE_PATH, Command::RetirePath(path)) => {
                self.retire_path(path).map(|()| Outcome::PathRetired)
            }
            (p::INSPECT, Command::Inspect) => Ok(Outcome::Snapshot),
            _ => return Err(ServiceError::UnexpectedCommand),
        };
        self.revision = revision;
        Ok(result.unwrap_or_else(Outcome::Rejected))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientError {
    Closed,
    Correlation,
    UnexpectedReply,
    PendingAdapter,
    SequenceExhausted,
}
#[derive(Debug)]
pub enum SubmitError {
    Client(ClientError),
    Datagram(super::datagram::Error),
}
pub struct Client<'c, 's, const Q: usize, const S: usize> {
    commands: Sender<'c, 's, Command, Q>,
    replies: Receiver<'c, 's, Reply, S>,
    generation: u64,
    next_sequence: u64,
    awaiting_adapter: bool,
    snapshot: Snapshot,
}
struct PendingCall<'a, 'c, 's, const Q: usize, const S: usize> {
    commands: &'a mut Sender<'c, 's, Command, Q>,
    replies: &'a mut Receiver<'c, 's, Reply, S>,
    completed: bool,
}
impl<const Q: usize, const S: usize> Drop for PendingCall<'_, '_, '_, Q, S> {
    fn drop(&mut self) {
        if !self.completed {
            self.commands.close();
            self.replies.close();
        }
    }
}
impl<'c, 's, const Q: usize, const S: usize> Client<'c, 's, Q, S> {
    pub async fn connect(
        commands: Sender<'c, 's, Command, Q>,
        mut replies: Receiver<'c, 's, Reply, S>,
        generation: u64,
    ) -> Result<Self, ClientError> {
        let reply = replies.recv().await.map_err(|_| ClientError::Closed)?;
        if reply.descriptor
            != (Descriptor {
                generation,
                sequence: 0,
            })
        {
            return Err(ClientError::Correlation);
        }
        if !matches!(reply.outcome, Outcome::Installed) {
            return Err(ClientError::UnexpectedReply);
        }
        Ok(Self {
            commands,
            replies,
            generation,
            next_sequence: 1,
            awaiting_adapter: false,
            snapshot: reply.snapshot,
        })
    }
    pub const fn snapshot(&self) -> Snapshot {
        self.snapshot
    }
    pub async fn request(&mut self, command: Command) -> Result<Outcome, ClientError> {
        if self.awaiting_adapter != matches!(command, Command::AdapterComplete(_)) {
            self.close();
            return Err(ClientError::PendingAdapter);
        }
        let next = self
            .next_sequence
            .checked_add(1)
            .ok_or(ClientError::SequenceExhausted)?;
        let mut pending = PendingCall {
            commands: &mut self.commands,
            replies: &mut self.replies,
            completed: false,
        };
        pending
            .commands
            .send(command)
            .await
            .map_err(|_| ClientError::Closed)?;
        let reply = pending
            .replies
            .recv()
            .await
            .map_err(|_| ClientError::Closed)?;
        if reply.descriptor
            != (Descriptor {
                generation: self.generation,
                sequence: self.next_sequence,
            })
        {
            return Err(ClientError::Correlation);
        }
        self.awaiting_adapter = matches!(reply.outcome, Outcome::Reserved(_));
        self.next_sequence = next;
        self.snapshot = reply.snapshot;
        pending.completed = true;
        Ok(reply.outcome)
    }
    /// A cancelled adapter future closes this service. Its owner then drops
    /// every reservation; a later copied completion cannot revive the session.
    /// After success the coordinator must distribute all returned completions,
    /// with AdapterComplete as this client's next command.
    pub async fn submit<A: UdpAdapter, const N: usize>(
        &mut self,
        pending: PendingTransmit,
        adapter: &mut A,
        protected: super::datagram::ProtectedDatagram<N>,
    ) -> Result<super::datagram::Completions, SubmitError> {
        if !self.awaiting_adapter {
            self.close();
            return Err(SubmitError::Client(ClientError::PendingAdapter));
        }
        let mut call = PendingCall {
            commands: &mut self.commands,
            replies: &mut self.replies,
            completed: false,
        };
        let completed = pending
            .submit(adapter, protected)
            .await
            .map_err(SubmitError::Datagram)?;
        call.completed = true;
        Ok(completed)
    }
    pub async fn reject(&mut self, pending: PendingTransmit) -> Result<Outcome, ClientError> {
        self.request(Command::AdapterComplete(pending.reject()))
            .await
    }
    pub async fn retire(mut self) -> Result<Snapshot, ClientError> {
        match self.request(Command::Retire).await? {
            Outcome::Retired => Ok(self.snapshot),
            _ => Err(ClientError::UnexpectedReply),
        }
    }
    pub fn close(&mut self) {
        self.commands.close();
        self.replies.close();
    }
}
impl<const Q: usize, const S: usize> Drop for Client<'_, '_, Q, S> {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
pub(crate) mod tests;

#[cfg(test)]
mod test_auth;

mod early;
