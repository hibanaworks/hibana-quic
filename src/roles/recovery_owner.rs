//! Real single-owner recovery/accounting role. SentLedger, RTT, NewReno and
//! CRYPTO flight storage move into the actor and never escape as mutable aliases.
//! The client facet exchanges copied descriptor IDs; bounded owned command and
//! reply slots carry payloads. ACK contents originate in packet_authority, not
//! an asserted authentication flag or caller-replaceable range list.
use super::{
    packet_authority::{self, AckFrame, AckGrant, Arena, AuthenticatedPacket},
    packet_protection::Descriptor,
    protocol_recovery as p,
};
use crate::{
    accounting::{
        self, AckSummary, PacketKind, PacketNumber, PacketNumberSpace, SendReservation, SentLedger,
        SentPacket,
    },
    ecn::{Codepoint, MarkedPackets, PathIdentity},
    flights::{self, FlightId, FlightStore, Reference},
    mailbox::{Receiver, Sender},
    recovery::{
        self, NewReno, RecoveryTimer, RttEstimator, RttSample, SpaceTimer, TimeoutAction,
        TimerContext, TimerDeadline,
    },
    runtime,
    tls::Level,
};
use core::cell::RefCell;
use hibana::{Endpoint, EndpointError};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

const SPACES: [PacketNumberSpace; 3] = [
    PacketNumberSpace::Initial,
    PacketNumberSpace::Handshake,
    PacketNumberSpace::ApplicationData,
];
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rejection {
    Accounting(accounting::AccountingError),
    Recovery(recovery::RecoveryError),
    Flight(flights::Error),
    Ecn(crate::ecn::Error),
    Authority(packet_authority::Error),
    CongestionLimited,
    ProbeUnavailable,
    InvalidTicket,
    Capacity,
    WrongPath,
    ClockWentBackwards,
}
impl From<accounting::AccountingError> for Rejection {
    fn from(e: accounting::AccountingError) -> Self {
        Self::Accounting(e)
    }
}
impl From<recovery::RecoveryError> for Rejection {
    fn from(e: recovery::RecoveryError) -> Self {
        Self::Recovery(e)
    }
}
impl From<flights::Error> for Rejection {
    fn from(e: flights::Error) -> Self {
        Self::Flight(e)
    }
}
impl From<crate::ecn::Error> for Rejection {
    fn from(e: crate::ecn::Error) -> Self {
        Self::Ecn(e)
    }
}
impl From<packet_authority::Error> for Rejection {
    fn from(e: packet_authority::Error) -> Self {
        Self::Authority(e)
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub generation: u64,
    pub initial_rtt_us: u64,
    pub max_datagram_size: u64,
    pub active_path: Option<PathIdentity>,
    pub ecn: Option<PathIdentity>,
    pub max_ack_delay_us: u64,
}
#[derive(Clone, Copy, Debug)]
pub struct SendPlan {
    pub kind: PacketKind,
    pub bytes: u64,
    pub in_flight: bool,
    pub ack_eliciting: bool,
    pub pto_probe: bool,
    pub flight: Option<FlightId>,
}
/// Exact retained CRYPTO/control contents, minted only by the flight owner.
/// It is copied for encoder verification, never used to authorize mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlightBinding {
    level: Level,
    offset: u64,
    len: usize,
    digest: [u8; 32],
    handshake_done: bool,
}
impl FlightBinding {
    pub const fn level(self) -> Level {
        self.level
    }
    pub const fn is_handshake_done(self) -> bool {
        self.handshake_done
    }
    pub fn matches_crypto(self, offset: u64, data: &[u8]) -> bool {
        !self.handshake_done
            && self.offset == offset
            && self.len == data.len()
            && self.digest == flight_digest(data)
    }
}
fn flight_digest(data: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"hibana-quic:retained-crypto-flight:v1\0");
    digest.update((data.len() as u64).to_be_bytes());
    digest.update(data);
    digest.finalize().into()
}
/// A copied callback ID is always checked against the one live reservation.
/// It is not an adapter-acceptance capability.
/// ```compile_fail
/// use hibana_quic::roles::recovery_owner::SendTicket;
/// let invented = SendTicket { descriptor: todo!(), packet: todo!(), bytes: 1200, kind: todo!() };
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendTicket {
    descriptor: Descriptor,
    packet: PacketNumber,
    bytes: u64,
    kind: PacketKind,
    flight: Option<FlightBinding>,
    in_flight: bool,
    ack_eliciting: bool,
    pto_probe: bool,
}
impl SendTicket {
    pub const fn is_pto_probe(self) -> bool {
        self.pto_probe
    }
    pub const fn in_flight(self) -> bool {
        self.in_flight
    }
    pub const fn ack_eliciting(self) -> bool {
        self.ack_eliciting
    }
    pub const fn flight(self) -> Option<FlightBinding> {
        self.flight
    }
    pub const fn bytes(self) -> u64 {
        self.bytes
    }
    pub const fn kind(self) -> PacketKind {
        self.kind
    }
    pub const fn packet(self) -> PacketNumber {
        self.packet
    }
    pub const fn descriptor(self) -> Descriptor {
        self.descriptor
    }
}
#[derive(Clone, Copy, Debug)]
struct Pending {
    ticket: SendTicket,
    reservation: SendReservation,
    flight: Option<Reference>,
    probe_epoch: Option<u64>,
}
#[derive(Clone, Copy, Debug)]
pub struct AckContext {
    pub ack_delay_exponent: u8,
    pub max_ack_delay_us: u64,
    pub handshake_confirmed: bool,
    pub peer_address_validated: bool,
    pub received_path: Option<PathIdentity>,
    pub local_decryption_delay_us: u64,
    pub app_or_flow_limited: bool,
}
/// Plain copied recovery metadata cannot authorize App/Path mutations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketMetadata {
    pub sent: SentPacket,
    pub kind: PacketKind,
}
/// Affine evidence that the real owner validated and applied these exact ranges.
/// Stream-data release consumes this value; snapshots cannot be substituted.
/// ```compile_fail
/// use hibana_quic::roles::recovery_owner::ValidatedAck;
/// fn duplicate(ack: ValidatedAck) { let first = ack.split(); let second = ack.split(); }
/// ```
#[derive(Debug)]
pub struct ValidatedAck {
    authentication: AuthenticatedPacket,
    frame: AckFrame,
}
#[derive(Debug)]
pub struct AckRelease<const DOMAIN: u8> {
    authentication: AuthenticatedPacket,
    frame: AckFrame,
}
pub type StreamAck = AckRelease<0>;
pub type PathAck = AckRelease<1>;
impl<const D: u8> AckRelease<D> {
    pub fn ranges(&self) -> &[accounting::AckRange] {
        self.frame.ranges()
    }
    pub const fn authentication(&self) -> AuthenticatedPacket {
        self.authentication
    }
}
impl ValidatedAck {
    pub fn split(self) -> (StreamAck, PathAck) {
        let path_frame = self.frame.duplicate_for_domain();
        (
            AckRelease {
                authentication: self.authentication,
                frame: self.frame,
            },
            AckRelease {
                authentication: self.authentication,
                frame: path_frame,
            },
        )
    }
    pub fn ranges(&self) -> &[accounting::AckRange] {
        self.frame.ranges()
    }
    pub const fn authentication(&self) -> AuthenticatedPacket {
        self.authentication
    }
    pub const fn ecn(&self) -> Option<crate::packet::EcnCounts> {
        self.frame.ecn()
    }
}
/// Real sent-ledger evidence for one newly acknowledged 1-RTT packet. A
/// shared-space 0-RTT ACK or duplicate cannot manufacture key-update authority.
#[derive(Debug)]
pub struct KeyAckGrant {
    generation: u64,
    sent_packet_number: u64,
    received_key_generation: u64,
}
impl KeyAckGrant {
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub const fn sent_packet_number(&self) -> u64 {
        self.sent_packet_number
    }
    pub const fn received_key_generation(&self) -> u64 {
        self.received_key_generation
    }
}
pub struct AckResult<const L: usize> {
    pub validated: ValidatedAck,
    pub summary: AckSummary,
    pub newly: [Option<PacketMetadata>; L],
    pub keys: [Option<KeyAckGrant>; L],
    pub ecn: Option<crate::ecn::Feedback>,
}
#[derive(Debug)]
pub struct LossGrant<const DOMAIN: u8> {
    generation: u64,
    metadata: PacketMetadata,
}
pub type LostPacket = LossGrant<0>;
pub type PathLostPacket = LossGrant<1>;
impl<const D: u8> LossGrant<D> {
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub const fn packet(&self) -> PacketNumber {
        self.metadata.sent.packet
    }
    pub const fn metadata(&self) -> PacketMetadata {
        self.metadata
    }
}
#[derive(Debug)]
pub struct LossResult<const L: usize> {
    pub newly: [Option<PacketMetadata>; L],
    pub loss_times: [Option<u64>; 3],
    pub stream: [Option<LostPacket>; L],
    pub path: [Option<PathLostPacket>; L],
}
#[derive(Debug)]
pub struct FlightBytes<const B: usize> {
    bytes: [u8; B],
    len: usize,
}
impl<const B: usize> FlightBytes<B> {
    pub fn new(input: &[u8]) -> Result<Self, Rejection> {
        if input.len() > B {
            return Err(Rejection::Capacity);
        }
        let mut result = Self {
            bytes: [0; B],
            len: input.len(),
        };
        result.bytes[..input.len()].copy_from_slice(input);
        Ok(result)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
impl<const B: usize> Drop for FlightBytes<B> {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}
pub enum FlightCommand<const B: usize> {
    Store {
        level: Level,
        offset: u64,
        bytes: FlightBytes<B>,
    },
    StoreHandshakeDone,
    Read(FlightId),
}
/// Affine instruction to make retained data available for an actual PTO probe.
/// This never declares loss or subtracts bytes in flight.
#[derive(Debug)]
pub struct PtoGrant<const DOMAIN: u8> {
    generation: u64,
    space: PacketNumberSpace,
    packets: u8,
}
pub type StreamPtoGrant = PtoGrant<0>;
pub type PathPtoGrant = PtoGrant<1>;
impl<const D: u8> PtoGrant<D> {
    pub const fn packets(&self) -> u8 {
        self.packets
    }
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub const fn space(&self) -> PacketNumberSpace {
        self.space
    }
}
#[derive(Debug)]
pub struct TimeoutResult {
    pub action: Option<TimeoutAction>,
    pub stream: Option<StreamPtoGrant>,
    pub path: Option<PathPtoGrant>,
}
pub enum TimerCommand {
    Update {
        now: u64,
        keys_available: [bool; 3],
        context: TimerContext,
        max_ack_delay_us: u64,
    },
    Expire {
        now: u64,
    },
}
pub enum Command<const B: usize> {
    Reserve(SendPlan),
    AdapterComplete(super::datagram::RecoveryCompletion),
    Cancel(super::datagram::RecoveryCancellation),
    Ack {
        grant: AckGrant,
        now: u64,
        context: AckContext,
    },
    DetectLoss {
        now: u64,
    },
    Flight(FlightCommand<B>),
    DiscardSpace(PacketNumberSpace),
    RequeueSpace(PacketNumberSpace),
    Reclaim(PacketNumberSpace),
    ResetPath(super::path_owner::RecoveryResetGrant),
    Timer(TimerCommand),
    KeyPto {
        max_ack_delay_us: u64,
    },
    RejectZeroRtt(super::tls_owner::EarlyRejectedGrant),
    EcnMarking {
        path: PathIdentity,
        now: u64,
    },
    Inspect,
    Retire,
}
#[derive(Clone, Copy, Debug)]
pub struct EcnSnapshot {
    pub identity: PathIdentity,
    pub state: crate::ecn::State,
    pub failure: Option<crate::ecn::Failure>,
    pub disabled_error: Option<crate::ecn::Error>,
    pub active: bool,
    pub sent: [MarkedPackets; 3],
    pub validated_ce: u64,
    pub congestion_events: u64,
}
#[derive(Clone, Copy, Debug)]
pub struct Snapshot {
    pub generation: u64,
    pub bytes_in_flight: u64,
    pub active_bytes_in_flight: u64,
    pub reserved_in_flight: u64,
    pub retained_records: usize,
    pub remaining_capacity: usize,
    pub next_packet_number: [Option<u64>; 3],
    pub congestion_window: u64,
    pub latest_rtt_us: u64,
    pub smoothed_rtt_us: u64,
    pub min_rtt_us: Option<u64>,
    pub variation_us: u64,
    pub active_flights: usize,
    pub next_lost_flight: Option<FlightId>,
    pub probe_flights: [Option<FlightId>; 3],
    pub loss_times: [Option<u64>; 3],
    pub largest_acked: [Option<u64>; 3],
    pub accepted_ecn: [MarkedPackets; 3],
    pub timer: Option<TimerDeadline>,
    pub pto_count: u32,
    pub pto_probe_space: Option<PacketNumberSpace>,
    pub pto_probe_credits: u8,
    pub ecn: Option<EcnSnapshot>,
}
pub enum Outcome<const L: usize, const B: usize> {
    Installed,
    Reserved(SendTicket),
    AdapterAccepted(PacketNumber),
    AdapterRejected(PacketNumber),
    Acknowledged(AckResult<L>),
    Losses(LossResult<L>),
    FlightStored(FlightId),
    FlightData {
        id: FlightId,
        level: Level,
        offset: u64,
        bytes: FlightBytes<B>,
        handshake_done: bool,
    },
    SpaceDiscarded {
        space: PacketNumberSpace,
        bytes_removed: u64,
    },
    SpaceRequeued {
        space: PacketNumberSpace,
        bytes_removed: u64,
    },
    Reclaimed {
        space: PacketNumberSpace,
        floor: u64,
    },
    PathReset,
    TimerUpdated,
    KeyPto(u64),
    ZeroRttRejected {
        bytes_removed: u64,
    },
    /// The Rejected route preserves the actual affine TLS grant for retry after
    /// every outstanding adapter submission has an irreversible outcome.
    ZeroRttPending(super::tls_owner::EarlyRejectedGrant),
    EcnMarking(Codepoint),
    Timeout(TimeoutResult),
    Inspected,
    Rejected(Rejection),
    Retired,
}
pub struct Reply<const L: usize, const B: usize> {
    pub descriptor: Descriptor,
    pub snapshot: Snapshot,
    pub outcome: Outcome<L, B>,
}
#[derive(Clone, Copy)]
struct PathAckHigh {
    path: Option<PathIdentity>,
    largest: [Option<u64>; 3],
}
/// Move into run_borrowed. Only the owner role calls private mutation methods.
pub struct RecoveryOwner<const L: usize, const F: usize, const B: usize, const R: usize> {
    config: Config,
    sent: SentLedger<L>,
    rtt: RttEstimator,
    cc: NewReno,
    flights: FlightStore<F, B, R>,
    timer: RecoveryTimer,
    pending: [Option<Pending>; L],
    largest_acked: [Option<u64>; 3],
    path_acks: [Option<PathAckHigh>; L],
    loss_times: [Option<u64>; 3],
    last_now: Option<u64>,
    probe_epoch: u64,
    probe_space: Option<PacketNumberSpace>,
    probe_credits: u8,
    ecn: Option<crate::ecn::PathEcn>,
    ecn_disabled_error: Option<crate::ecn::Error>,
    ecn_validated_ce: u64,
    ecn_congestion_events: u64,
    max_ack_delay_us: u64,
}
impl<const L: usize, const F: usize, const B: usize, const R: usize> RecoveryOwner<L, F, B, R> {
    pub fn new(config: Config) -> Result<Self, Rejection> {
        if config
            .active_path
            .is_some_and(|p| p.connection_generation != config.generation)
        {
            return Err(Rejection::WrongPath);
        }
        if config.ecn.is_some_and(|p| {
            p.connection_generation != config.generation || config.active_path != Some(p)
        }) {
            return Err(Rejection::WrongPath);
        }
        Ok(Self {
            ecn: config.ecn.map(crate::ecn::PathEcn::new),
            ecn_disabled_error: None,
            ecn_validated_ce: 0,
            ecn_congestion_events: 0,
            max_ack_delay_us: config.max_ack_delay_us,
            sent: SentLedger::new(config.generation),
            rtt: RttEstimator::new(config.initial_rtt_us)?,
            cc: NewReno::new(config.max_datagram_size)?,
            flights: FlightStore::new(),
            timer: RecoveryTimer::new(),
            pending: [None; L],
            largest_acked: [None; 3],
            path_acks: [None; L],
            loss_times: [None; 3],
            last_now: None,
            probe_epoch: 0,
            probe_space: None,
            probe_credits: 0,
            config,
        })
    }
    fn active(&self, path: Option<PathIdentity>) -> bool {
        self.config
            .active_path
            .is_none_or(|active| path == Some(active))
    }
    fn active_flight(&self) -> u64 {
        self.config.active_path.map_or_else(
            || self.sent.bytes_in_flight(),
            |p| self.sent.bytes_in_flight_on_path(p),
        )
    }
    fn check_time(&self, now: u64) -> Result<(), Rejection> {
        if self.last_now.is_some_and(|old| now < old) {
            Err(Rejection::ClockWentBackwards)
        } else {
            Ok(())
        }
    }
    fn snapshot(&self) -> Snapshot {
        Snapshot {
            generation: self.config.generation,
            bytes_in_flight: self.sent.bytes_in_flight(),
            active_bytes_in_flight: self.active_flight(),
            reserved_in_flight: self.sent.reserved_in_flight(),
            retained_records: self.sent.retained_records(),
            remaining_capacity: self.sent.remaining_capacity(),
            next_packet_number: SPACES.map(|s| self.sent.next_packet_number(s)),
            congestion_window: self.cc.congestion_window(),
            latest_rtt_us: self.rtt.latest_us(),
            smoothed_rtt_us: self.rtt.smoothed_us(),
            min_rtt_us: self.rtt.min_us(),
            variation_us: self.rtt.variation_us(),
            active_flights: self.flights.active_flights(),
            next_lost_flight: self.flights.next_lost(),
            probe_flights: SPACES.map(|s| self.flights.probe(s)),
            loss_times: self.loss_times,
            largest_acked: self.largest_acked,
            accepted_ecn: SPACES.map(|s| self.sent.accepted_ecn_counts(s)),
            timer: self.timer.deadline(),
            pto_count: self.timer.pto_count(),
            pto_probe_space: self.probe_space,
            pto_probe_credits: self.probe_credits,
            ecn: self.ecn.as_ref().map(|ecn| EcnSnapshot {
                identity: ecn.identity(),
                state: ecn.state(),
                failure: ecn.failure(),
                disabled_error: self.ecn_disabled_error,
                active: self.ecn_disabled_error.is_none()
                    && self.config.active_path == Some(ecn.identity()),
                sent: SPACES.map(|space| ecn.sent(space)),
                validated_ce: self.ecn_validated_ce,
                congestion_events: self.ecn_congestion_events,
            }),
        }
    }
    fn reserve(&mut self, descriptor: Descriptor, plan: SendPlan) -> Result<SendTicket, Rejection> {
        if plan.pto_probe
            && (self.probe_space != Some(plan.kind.space()) || self.probe_credits == 0)
        {
            return Err(Rejection::ProbeUnavailable);
        }
        if plan.pto_probe && (!plan.in_flight || !plan.ack_eliciting) {
            return Err(accounting::AccountingError::InvalidClassification.into());
        }
        if !self.cc.can_send(
            self.active_flight(),
            self.sent.reserved_in_flight(),
            plan.bytes,
            plan.in_flight,
            plan.pto_probe,
        ) {
            return Err(Rejection::CongestionLimited);
        }
        let slot = self
            .pending
            .iter()
            .position(Option::is_none)
            .ok_or(Rejection::Capacity)?;
        // Validate a flight before allocating; reference capacity may still fail,
        // in which case cancel the reservation but never rewind its burned PN.
        let binding = if let Some(flight) = plan.flight {
            let (level, offset, data) = self.flights.data(flight)?;
            if level_space(level) != plan.kind.space()
                || plan.kind == PacketKind::ZeroRtt
                || !plan.ack_eliciting
            {
                return Err(Rejection::Flight(flights::Error::Invalid));
            }
            Some(FlightBinding {
                level,
                offset,
                len: data.len(),
                digest: flight_digest(data),
                handshake_done: self.flights.is_handshake_done(flight)?,
            })
        } else {
            None
        };
        let reservation = self.sent.reserve_classified(
            plan.kind,
            plan.bytes,
            plan.in_flight,
            plan.ack_eliciting,
        )?;
        let flight = match plan
            .flight
            .map(|id| self.flights.reserve(id, reservation.packet()))
            .transpose()
        {
            Ok(flight) => flight,
            Err(e) => {
                self.sent.cancel(reservation)?;
                return Err(e.into());
            }
        };
        let ticket = SendTicket {
            descriptor,
            packet: reservation.packet(),
            bytes: plan.bytes,
            kind: plan.kind,
            flight: binding,
            in_flight: plan.in_flight,
            ack_eliciting: plan.ack_eliciting,
            pto_probe: plan.pto_probe,
        };
        self.pending[slot] = Some(Pending {
            ticket,
            reservation,
            flight,
            probe_epoch: plan.pto_probe.then_some(self.probe_epoch),
        });
        if plan.pto_probe {
            self.probe_credits -= 1;
        }
        Ok(ticket)
    }
    fn pending(&self, ticket: SendTicket) -> Result<(usize, Pending), Rejection> {
        self.pending
            .iter()
            .enumerate()
            .find_map(|(i, p)| p.filter(|p| p.ticket == ticket).map(|p| (i, p)))
            .ok_or(Rejection::InvalidTicket)
    }
    fn accepted(
        &mut self,
        ticket: SendTicket,
        now: u64,
        ecn: Codepoint,
        path: Option<PathIdentity>,
    ) -> Result<(), Rejection> {
        self.check_time(now)?;
        let (slot, pending) = self.pending(ticket)?;
        match path {
            Some(path) => {
                self.sent
                    .adapter_accepted_on_path(pending.reservation, now, ecn, path)?
            }
            None => self
                .sent
                .adapter_accepted_ecn(pending.reservation, now, ecn)?,
        }
        if let Some(reference) = pending.flight {
            self.flights.accepted(reference, now)?;
        }
        if self.ecn_disabled_error.is_none() {
            let pto = self.rtt.pto_duration_us(self.max_ack_delay_us, 0);
            if let Some(state) = self
                .ecn
                .as_mut()
                .filter(|state| path == Some(state.identity()))
            {
                let result = pto
                    .map_err(|_| crate::ecn::Error::CounterLimit)
                    .and_then(|pto| state.accepted(state.identity(), ticket.packet, ecn, now, pto));
                if let Err(error) = result {
                    self.ecn_disabled_error = Some(error);
                }
            }
        }
        self.pending[slot] = None;
        self.last_now = Some(now);
        Ok(())
    }
    fn rejected(&mut self, ticket: SendTicket) -> Result<(), Rejection> {
        let (slot, pending) = self.pending(ticket)?;
        self.sent.cancel(pending.reservation)?;
        if let Some(reference) = pending.flight {
            self.flights.cancelled(reference)?;
        }
        if pending.probe_epoch == Some(self.probe_epoch)
            && self.probe_space == Some(ticket.packet.space)
        {
            self.probe_credits = self.probe_credits.saturating_add(1);
        }
        self.pending[slot] = None;
        Ok(())
    }
    fn observe_ack(&mut self, packet: SentPacket) {
        let existing = self
            .path_acks
            .iter()
            .position(|p| p.is_some_and(|p| p.path == packet.path));
        let slot = existing.or_else(|| self.path_acks.iter().position(Option::is_none));
        // A full path-history table undercounts loss evidence conservatively.
        if let Some(slot) = slot {
            let p = self.path_acks[slot].get_or_insert(PathAckHigh {
                path: packet.path,
                largest: [None; 3],
            });
            let largest = &mut p.largest[packet.packet.space as usize];
            *largest =
                Some(largest.map_or(packet.packet.value, |old| old.max(packet.packet.value)));
        }
    }
    fn ack<const P: usize, const E: usize>(
        &mut self,
        authority: &Arena<P, E>,
        grant: AckGrant,
        now: u64,
        context: AckContext,
    ) -> Result<AckResult<L>, Rejection> {
        self.check_time(now)?;
        let (authentication, frame) = authority.consume_ack(grant)?;
        if authentication.generation() != self.config.generation {
            return Err(Rejection::Authority(
                packet_authority::Error::WrongGeneration,
            ));
        }
        if context.ack_delay_exponent > 20 {
            return Err(Rejection::Recovery(
                recovery::RecoveryError::InvalidConfiguration,
            ));
        }
        let space = authentication.space();
        self.sent.validate_ack(space, frame.ranges())?;
        let largest = frame
            .ranges()
            .last()
            .ok_or(accounting::AccountingError::InvalidAckRange)?
            .end;
        let largest_packet = PacketNumber {
            space,
            value: largest,
        };
        let largest_new = self.sent.is_new_ack(largest_packet);
        let largest_sent = self.sent.sent_packet(largest_packet);
        let mut newly = [None; L];
        let mut len = 0;
        for sent in self.sent.unacknowledged_sent() {
            if sent.packet.space == space
                && frame
                    .ranges()
                    .iter()
                    .any(|r| r.start <= sent.packet.value && sent.packet.value <= r.end)
            {
                let kind = self
                    .sent
                    .sent_kind(sent.packet)
                    .ok_or(Rejection::InvalidTicket)?;
                if sent.sent_at > now {
                    return Err(Rejection::ClockWentBackwards);
                }
                newly[len] = Some(PacketMetadata { sent, kind });
                len += 1;
            }
        }
        let any_eliciting = newly.iter().flatten().any(|p| p.sent.ack_eliciting);
        let sample = largest_sent.filter(|p| {
            largest_new
                && any_eliciting
                && self.active(p.path)
                && self.active(context.received_path)
        });
        // Preflight every fallible RTT input before touching the sent ledger.
        if let Some(packet) = sample {
            let elapsed = now
                .checked_sub(packet.sent_at)
                .ok_or(Rejection::ClockWentBackwards)?;
            if !context.handshake_confirmed && elapsed < context.local_decryption_delay_us {
                return Err(recovery::RecoveryError::InvalidSample.into());
            }
        }
        let mut ecn_feedback = None;
        if self.ecn_disabled_error.is_none() {
            if let Some(state) = self
                .ecn
                .as_mut()
                .filter(|state| self.config.active_path == Some(state.identity()))
            {
                let mut marked = MarkedPackets::default();
                for packet in newly
                    .iter()
                    .flatten()
                    .filter(|p| p.sent.path == Some(state.identity()))
                {
                    match packet.sent.ecn {
                        Codepoint::Ect0 => marked.ect0 += 1,
                        Codepoint::Ect1 => marked.ect1 += 1,
                        _ => {}
                    }
                }
                match state.acknowledged(state.identity(), space, largest, marked, frame.ecn()) {
                    Ok(feedback) => ecn_feedback = Some(feedback),
                    Err(error) => self.ecn_disabled_error = Some(error),
                }
            }
        }
        if let Some(crate::ecn::Feedback::Validated { ce_increase }) = ecn_feedback {
            self.ecn_validated_ce = self
                .ecn_validated_ce
                .checked_add(ce_increase)
                .ok_or(crate::ecn::Error::CounterLimit)?;
            if ce_increase != 0 {
                let sent_at = self
                    .sent
                    .congestion_sent_at_upper_bound(largest_packet)
                    .unwrap_or(now);
                if self.cc.on_congestion_event(now, sent_at)? {
                    self.ecn_congestion_events = self
                        .ecn_congestion_events
                        .checked_add(1)
                        .ok_or(crate::ecn::Error::CounterLimit)?;
                }
            }
        }
        let summary = self.sent.acknowledge(space, frame.ranges())?;
        self.max_ack_delay_us = context.max_ack_delay_us;
        if let Some(packet) = sample {
            self.rtt.on_ack(RttSample {
                now,
                sent_at: packet.sent_at,
                ack_delay_us: frame
                    .delay()
                    .saturating_mul(1u64 << context.ack_delay_exponent),
                max_ack_delay_us: context.max_ack_delay_us,
                space,
                handshake_confirmed: context.handshake_confirmed,
                largest_newly_acknowledged: true,
                any_newly_acknowledged_ack_eliciting: true,
                local_decryption_delay_us: context.local_decryption_delay_us,
            })?;
        }
        let mut newly_active = false;
        for packet in newly.iter().flatten() {
            self.observe_ack(packet.sent);
            if self.active(packet.sent.path) {
                newly_active = true;
                if packet.sent.in_flight {
                    self.cc.on_ack(
                        now,
                        packet.sent.sent_at,
                        packet.sent.bytes,
                        context.app_or_flow_limited,
                    )?;
                }
            }
        }
        self.flights.acknowledge(space, frame.ranges());
        let high = &mut self.largest_acked[space as usize];
        *high = Some(high.map_or(largest, |old| old.max(largest)));
        self.timer.on_new_ack(
            summary.newly_acknowledged != 0 && newly_active,
            context.peer_address_validated,
        );
        if summary.newly_acknowledged != 0 && newly_active {
            self.probe_space = None;
            self.probe_credits = 0;
        }
        self.last_now = Some(now);
        let keys = newly.map(|p| {
            p.filter(|p| p.kind == PacketKind::OneRtt)
                .map(|p| KeyAckGrant {
                    generation: self.config.generation,
                    sent_packet_number: p.sent.packet.value,
                    received_key_generation: authentication.key_generation(),
                })
        });
        Ok(AckResult {
            ecn: ecn_feedback,
            keys,
            validated: ValidatedAck {
                authentication,
                frame,
            },
            summary,
            newly,
        })
    }
    fn detect_loss(&mut self, now: u64) -> Result<LossResult<L>, Rejection> {
        self.check_time(now)?;
        let mut candidates = [None; L];
        let mut loss_times: [Option<u64>; 3] = [None; 3];
        // Compute all decisions before any mutation so overflow cannot half-apply a sweep.
        for (index, sent) in self.sent.outstanding_sent().enumerate() {
            let largest = self
                .path_acks
                .iter()
                .flatten()
                .find(|p| p.path == sent.path)
                .and_then(|p| p.largest[sent.packet.space as usize]);
            let newer_sent_packets = largest.map_or(0, |largest| {
                sent.path.map_or_else(
                    || self.sent.count_later_sent(sent.packet, largest),
                    |path| {
                        self.sent
                            .count_later_sent_on_path(sent.packet, largest, path)
                    },
                )
            });
            match recovery::loss_decision(
                &self.rtt,
                recovery::LossCandidate {
                    packet_number: sent.packet.value,
                    sent_at: sent.sent_at,
                    newer_sent_packets,
                },
                largest,
                now,
            )? {
                recovery::LossDecision::Lost => {
                    candidates[index] = Some(PacketMetadata {
                        sent,
                        kind: self
                            .sent
                            .sent_kind(sent.packet)
                            .ok_or(Rejection::InvalidTicket)?,
                    })
                }
                recovery::LossDecision::WaitUntil(at) => {
                    let t = &mut loss_times[sent.packet.space as usize];
                    *t = Some(t.map_or(at, |old| old.min(at)));
                }
                recovery::LossDecision::NotEligible => {}
            }
        }
        for p in candidates.iter().flatten() {
            if let accounting::LossOutcome::NewlyLost {
                bytes_removed_from_flight,
            } = self.sent.declare_lost(p.sent.packet)?
            {
                if bytes_removed_from_flight != 0 && self.active(p.sent.path) {
                    self.cc.on_congestion_event(now, p.sent.sent_at)?;
                }
                self.flights.mark_lost(p.sent.packet);
                if self.ecn_disabled_error.is_none()
                    && matches!(p.sent.ecn, Codepoint::Ect0 | Codepoint::Ect1)
                {
                    if let Some(state) = self
                        .ecn
                        .as_mut()
                        .filter(|state| p.sent.path == Some(state.identity()))
                    {
                        if let Err(error) = state.lost(state.identity(), 1) {
                            self.ecn_disabled_error = Some(error);
                        }
                    }
                }
            }
        }
        self.loss_times = loss_times;
        self.last_now = Some(now);
        Ok(LossResult {
            newly: candidates,
            loss_times,
            stream: candidates.map(|metadata| {
                metadata.map(|metadata| LossGrant {
                    generation: self.config.generation,
                    metadata,
                })
            }),
            path: candidates.map(|metadata| {
                metadata.map(|metadata| LossGrant {
                    generation: self.config.generation,
                    metadata,
                })
            }),
        })
    }
    fn space_change(&mut self, space: PacketNumberSpace, requeue: bool) -> Result<u64, Rejection> {
        if space == PacketNumberSpace::ApplicationData {
            return Err(recovery::RecoveryError::InvalidConfiguration.into());
        }
        if self
            .pending
            .iter()
            .flatten()
            .any(|p| p.ticket.packet.space == space)
        {
            return Err(accounting::AccountingError::OutstandingPackets.into());
        }
        if requeue {
            self.flights.requeue_space(space)?;
        } else {
            self.flights.discard_space(space)?;
        }
        let removed = self.sent.discard_space(space)?;
        self.timer.on_keys_discarded(space)?;
        if self.probe_space == Some(space) {
            self.probe_space = None;
            self.probe_credits = 0;
        }
        self.loss_times[space as usize] = None;
        self.largest_acked[space as usize] = None;
        for p in self.path_acks.iter_mut().flatten() {
            p.largest[space as usize] = None;
        }
        Ok(removed)
    }
    fn timer(&mut self, command: TimerCommand) -> Result<Outcome<L, B>, Rejection> {
        match command {
            TimerCommand::Update {
                now,
                keys_available,
                context,
                max_ack_delay_us,
            } => {
                self.check_time(now)?;
                let spaces = core::array::from_fn(|index| {
                    let at = self
                        .sent
                        .outstanding_sent()
                        .filter(|p| {
                            p.packet.space == SPACES[index]
                                && p.ack_eliciting
                                && self.active(p.path)
                        })
                        .map(|p| p.sent_at)
                        .max();
                    // Migration can leave retained data only on the retired
                    // path. Keep PTO live so the new path can send a probe;
                    // this does not attribute old bytes to its congestion window.
                    let at = at.or_else(|| {
                        self.sent
                            .outstanding_sent()
                            .filter(|p| p.packet.space == SPACES[index] && p.ack_eliciting)
                            .map(|p| p.sent_at)
                            .max()
                    });
                    SpaceTimer {
                        keys_available: keys_available[index],
                        loss_time: self.loss_times[index],
                        ack_eliciting_in_flight: at.is_some(),
                        last_ack_eliciting_sent_at: at,
                    }
                });
                self.timer
                    .update(now, &self.rtt, &spaces, context, max_ack_delay_us)?;
                self.last_now = Some(now);
                self.max_ack_delay_us = max_ack_delay_us;
                Ok(Outcome::TimerUpdated)
            }
            TimerCommand::Expire { now } => {
                self.check_time(now)?;
                let due_probe = self.timer.deadline().is_some_and(|d| {
                    d.at <= now && matches!(d.kind, recovery::TimerKind::Probe { .. })
                });
                let next_epoch = if due_probe {
                    self.probe_epoch
                        .checked_add(1)
                        .ok_or(recovery::RecoveryError::Overflow)?
                } else {
                    self.probe_epoch
                };
                let action = self.timer.on_timeout(now)?;
                let (stream, path) = if let Some(TimeoutAction::Probe {
                    space,
                    max_datagrams,
                    ..
                }) = action
                {
                    self.probe_epoch = next_epoch;
                    self.probe_space = Some(space);
                    self.probe_credits = max_datagrams;
                    if space == PacketNumberSpace::ApplicationData {
                        (
                            Some(PtoGrant {
                                generation: self.config.generation,
                                space,
                                packets: max_datagrams,
                            }),
                            Some(PtoGrant {
                                generation: self.config.generation,
                                space,
                                packets: max_datagrams,
                            }),
                        )
                    } else {
                        (None, None)
                    }
                } else {
                    (None, None)
                };
                self.last_now = Some(now);
                Ok(Outcome::Timeout(TimeoutResult {
                    action,
                    stream,
                    path,
                }))
            }
        }
    }
    fn reject_zero_rtt(
        &mut self,
        grant: super::tls_owner::EarlyRejectedGrant,
    ) -> Result<Outcome<L, B>, Rejection> {
        if grant.generation() != self.config.generation {
            return Err(Rejection::Authority(
                packet_authority::Error::WrongGeneration,
            ));
        }
        match self.sent.reject_zero_rtt() {
            Err(accounting::AccountingError::OutstandingPackets) => {
                Ok(Outcome::ZeroRttPending(grant))
            }
            Err(error) => Err(error.into()),
            Ok(bytes_removed) => {
                if self.probe_space == Some(PacketNumberSpace::ApplicationData) {
                    self.probe_space = None;
                    self.probe_credits = 0;
                }
                Ok(Outcome::ZeroRttRejected { bytes_removed })
            }
        }
    }
    fn reset_path(&mut self, path: Option<PathIdentity>) -> Result<(), Rejection> {
        if path.is_some_and(|p| p.connection_generation != self.config.generation) {
            return Err(Rejection::WrongPath);
        }
        let rtt = RttEstimator::new(self.config.initial_rtt_us)?;
        let cc = NewReno::new(self.config.max_datagram_size)?;
        self.config.active_path = path;
        self.rtt = rtt;
        self.cc = cc;
        self.timer = RecoveryTimer::new();
        self.probe_space = None;
        self.probe_credits = 0;
        self.loss_times = [None; 3];
        Ok(())
    }
    fn apply<const P: usize, const E: usize>(
        &mut self,
        authority: &Arena<P, E>,
        descriptor: Descriptor,
        command: Command<B>,
    ) -> Result<Outcome<L, B>, Rejection> {
        match command {
            Command::Reserve(plan) => self.reserve(descriptor, plan).map(Outcome::Reserved),
            Command::AdapterComplete(completion) => {
                let ticket = completion.ticket();
                if let Some(sent_at) = completion.accepted_at() {
                    self.accepted(ticket, sent_at, completion.ecn(), completion.path())?;
                    Ok(Outcome::AdapterAccepted(ticket.packet))
                } else {
                    self.rejected(ticket)?;
                    Ok(Outcome::AdapterRejected(ticket.packet))
                }
            }
            Command::Cancel(cancellation) => {
                let ticket = cancellation.ticket();
                self.rejected(ticket)?;
                Ok(Outcome::AdapterRejected(ticket.packet))
            }
            Command::Ack {
                grant,
                now,
                context,
            } => self
                .ack(authority, grant, now, context)
                .map(Outcome::Acknowledged),
            Command::DetectLoss { now } => self.detect_loss(now).map(Outcome::Losses),
            Command::Flight(FlightCommand::Store {
                level,
                offset,
                bytes,
            }) => self
                .flights
                .append(level, offset, bytes.as_bytes())
                .map(Outcome::FlightStored)
                .map_err(Into::into),
            Command::Flight(FlightCommand::StoreHandshakeDone) => self
                .flights
                .append_handshake_done()
                .map(Outcome::FlightStored)
                .map_err(Into::into),
            Command::Flight(FlightCommand::Read(id)) => {
                let (level, offset, data) = self.flights.data(id)?;
                Ok(Outcome::FlightData {
                    id,
                    level,
                    offset,
                    bytes: FlightBytes::new(data)?,
                    handshake_done: self.flights.is_handshake_done(id)?,
                })
            }
            Command::DiscardSpace(space) => Ok(Outcome::SpaceDiscarded {
                space,
                bytes_removed: self.space_change(space, false)?,
            }),
            Command::RequeueSpace(space) => Ok(Outcome::SpaceRequeued {
                space,
                bytes_removed: self.space_change(space, true)?,
            }),
            Command::Reclaim(space) => Ok(Outcome::Reclaimed {
                space,
                floor: self.sent.reclaim_completed_prefix(space)?,
            }),
            Command::ResetPath(grant) => {
                if grant.generation() != self.config.generation
                    || Some(grant.previous()) != self.config.active_path
                {
                    return Err(Rejection::WrongPath);
                }
                self.reset_path(Some(grant.active()))?;
                Ok(Outcome::PathReset)
            }
            Command::Timer(command) => self.timer(command),
            Command::RejectZeroRtt(grant) => self.reject_zero_rtt(grant),
            Command::KeyPto { max_ack_delay_us } => Ok(Outcome::KeyPto(
                self.rtt.pto_duration_us(max_ack_delay_us, 0)?,
            )),
            Command::EcnMarking { path, now } => {
                self.check_time(now)?;
                if path.connection_generation != self.config.generation {
                    return Err(Rejection::WrongPath);
                }
                let mark =
                    if self.ecn_disabled_error.is_none() && self.config.active_path == Some(path) {
                        if let Some(ecn) = self.ecn.as_mut().filter(|ecn| ecn.identity() == path) {
                            ecn.marking(path, now)?
                        } else {
                            Codepoint::NotEct
                        }
                    } else {
                        Codepoint::NotEct
                    };
                self.last_now = Some(now);
                Ok(Outcome::EcnMarking(mark))
            }
            Command::Inspect => Ok(Outcome::Inspected),
            Command::Retire => {
                self.sent.retire();
                self.flights.discard();
                self.pending.fill(None);
                Ok(Outcome::Retired)
            }
        }
    }
}
fn level_space(level: Level) -> PacketNumberSpace {
    match level {
        Level::Initial => PacketNumberSpace::Initial,
        Level::Handshake => PacketNumberSpace::Handshake,
        Level::OneRtt => PacketNumberSpace::ApplicationData,
    }
}
impl<const L: usize, const F: usize, const B: usize, const R: usize> Drop
    for RecoveryOwner<L, F, B, R>
{
    fn drop(&mut self) {
        self.flights.discard();
        self.sent.retire();
        self.pending.fill(None);
    }
}
impl<const B: usize> Command<B> {
    fn label(&self) -> u8 {
        match self {
            Self::Reserve(_) => p::RESERVE,
            Self::AdapterComplete(_) => p::ADAPTER_COMPLETE,
            Self::Cancel(_) => p::CANCEL,
            Self::Ack { .. } => p::ACK,
            Self::DetectLoss { .. } => p::DETECT_LOSS,
            Self::Flight(_) => p::FLIGHT,
            Self::DiscardSpace(_) => p::DISCARD_SPACE,
            Self::RequeueSpace(_) => p::REQUEUE_SPACE,
            Self::Reclaim(_) => p::RECLAIM,
            Self::ResetPath(_) => p::RESET_PATH,
            Self::Timer(_) => p::TIMER,
            Self::KeyPto { .. } => p::KEY_PTO,
            Self::RejectZeroRtt(_) => p::REJECT_ZERO_RTT,
            Self::EcnMarking { .. } => p::ECN_MARKING,
            Self::Inspect => p::INSPECT,
            Self::Retire => p::RETIRE_REQUESTED,
        }
    }
}
struct Request<const B: usize> {
    descriptor: Descriptor,
    command: Command<B>,
}
pub struct Exchange<const L: usize, const B: usize> {
    request: RefCell<Option<Request<B>>>,
    reply: RefCell<Option<Reply<L, B>>>,
}
impl<const L: usize, const B: usize> Default for Exchange<L, B> {
    fn default() -> Self {
        Self::new()
    }
}
impl<const L: usize, const B: usize> Exchange<L, B> {
    pub const fn new() -> Self {
        Self {
            request: RefCell::new(None),
            reply: RefCell::new(None),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.request.borrow().is_none() && self.reply.borrow().is_none()
    }
    fn put_request(&self, request: Request<B>) -> Result<(), Error> {
        let mut slot = self.request.borrow_mut();
        if slot.is_some() || self.reply.borrow().is_some() {
            return Err(Error::OccupiedSlot);
        }
        *slot = Some(request);
        Ok(())
    }
    fn take_request(&self, wire: [u8; 16]) -> Result<Request<B>, Error> {
        let request = self.request.borrow_mut().take().ok_or(Error::MissingSlot)?;
        same(encode(request.descriptor), wire)?;
        Ok(request)
    }
    fn put_reply(&self, reply: Reply<L, B>) -> Result<(), Error> {
        let mut slot = self.reply.borrow_mut();
        if slot.is_some() {
            return Err(Error::OccupiedSlot);
        }
        *slot = Some(reply);
        Ok(())
    }
    fn take_reply(&self, descriptor: Descriptor) -> Result<Reply<L, B>, Error> {
        let reply = self.reply.borrow_mut().take().ok_or(Error::MissingSlot)?;
        if reply.descriptor != descriptor {
            return Err(Error::Correlation);
        }
        Ok(reply)
    }
}
struct Clear<'a, const L: usize, const B: usize>(&'a Exchange<L, B>);
impl<const L: usize, const B: usize> Drop for Clear<'_, L, B> {
    fn drop(&mut self) {
        self.0.request.borrow_mut().take();
        self.0.reply.borrow_mut().take();
    }
}
#[derive(Debug)]
pub enum Error {
    Hibana(EndpointError),
    CommandsClosed,
    RepliesClosed,
    OccupiedSlot,
    MissingSlot,
    Correlation,
    UnexpectedLabel(u8),
    SequenceExhausted,
}
impl From<EndpointError> for Error {
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
fn same(actual: [u8; 16], expected: [u8; 16]) -> Result<(), Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(Error::Correlation)
    }
}
/// Endpoints belong to the encompassing session. Cancellation destroys this
/// numerical owner and closes mailbox admission; it never invents adapter
/// rejection merely because a waiting caller was dropped.
pub async fn run_borrowed<
    const C: u8,
    const O: u8,
    const L: usize,
    const F: usize,
    const B: usize,
    const R: usize,
    const P: usize,
    const E: usize,
    const Q: usize,
    const S: usize,
>(
    client: &mut Endpoint<'_, C>,
    owner_endpoint: &mut Endpoint<'_, O>,
    owner: RecoveryOwner<L, F, B, R>,
    authority: &Arena<P, E>,
    commands: Receiver<'_, '_, Command<B>, Q>,
    replies: Sender<'_, '_, Reply<L, B>, S>,
    exchange: &mut Exchange<L, B>,
) -> Result<(), Error> {
    if !exchange.is_empty() {
        return Err(Error::OccupiedSlot);
    }
    let generation = owner.config.generation;
    let exchange = &*exchange;
    let _clear = Clear(exchange);
    let mut command = core::pin::pin!(command_role(
        client, generation, commands, replies, exchange
    ));
    let mut owned = core::pin::pin!(owner_role(owner_endpoint, owner, authority, exchange));
    runtime::TaskSet::new([command.as_mut(), owned.as_mut()]).await
}
async fn command_role<
    const C: u8,
    const L: usize,
    const B: usize,
    const Q: usize,
    const S: usize,
>(
    endpoint: &mut Endpoint<'_, C>,
    generation: u64,
    mut commands: Receiver<'_, '_, Command<B>, Q>,
    mut replies: Sender<'_, '_, Reply<L, B>, S>,
    exchange: &Exchange<L, B>,
) -> Result<(), Error> {
    let install = Descriptor {
        generation,
        sequence: 0,
    };
    let wire = encode(install);
    endpoint.send::<p::Install>(&wire).await?;
    same(endpoint.recv::<p::Installed>().await?, wire)?;
    replies
        .send(exchange.take_reply(install)?)
        .await
        .map_err(|_| Error::RepliesClosed)?;
    let mut sequence = 1u64;
    loop {
        let command = commands.recv().await.map_err(|_| Error::CommandsClosed)?;
        let label = command.label();
        let descriptor = Descriptor {
            generation,
            sequence,
        };
        let wire = encode(descriptor);
        exchange.put_request(Request {
            descriptor,
            command,
        })?;
        match label {
            p::RESERVE => endpoint.send::<p::Reserve>(&wire).await?,
            p::ADAPTER_COMPLETE => endpoint.send::<p::AdapterComplete>(&wire).await?,
            p::CANCEL => endpoint.send::<p::Cancel>(&wire).await?,
            p::ACK => endpoint.send::<p::Ack>(&wire).await?,
            p::DETECT_LOSS => endpoint.send::<p::DetectLoss>(&wire).await?,
            p::FLIGHT => endpoint.send::<p::Flight>(&wire).await?,
            p::DISCARD_SPACE => endpoint.send::<p::DiscardSpace>(&wire).await?,
            p::REQUEUE_SPACE => endpoint.send::<p::RequeueSpace>(&wire).await?,
            p::RECLAIM => endpoint.send::<p::Reclaim>(&wire).await?,
            p::RESET_PATH => endpoint.send::<p::ResetPath>(&wire).await?,
            p::TIMER => endpoint.send::<p::Timer>(&wire).await?,
            p::KEY_PTO => endpoint.send::<p::KeyPto>(&wire).await?,
            p::REJECT_ZERO_RTT => endpoint.send::<p::RejectZeroRtt>(&wire).await?,
            p::ECN_MARKING => endpoint.send::<p::EcnMarking>(&wire).await?,
            p::INSPECT => endpoint.send::<p::Inspect>(&wire).await?,
            p::RETIRE_REQUESTED => {
                commands.close();
                endpoint.send::<p::RetireRequested>(&wire).await?;
                same(endpoint.recv::<p::Retired>().await?, wire)?;
                endpoint.send::<p::RetirementAcknowledged>(&wire).await?;
                replies
                    .send(exchange.take_reply(descriptor)?)
                    .await
                    .map_err(|_| Error::RepliesClosed)?;
                return Ok(());
            }
            _ => return Err(Error::UnexpectedLabel(label)),
        }
        let branch = endpoint.offer().await?;
        let observed = match branch.label() {
            p::APPLIED => branch.recv::<p::Applied>().await?,
            p::REJECTED => branch.recv::<p::Rejected>().await?,
            label => return Err(Error::UnexpectedLabel(label)),
        };
        same(observed, wire)?;
        let reply = exchange.take_reply(descriptor)?;
        endpoint.send::<p::ResultTaken>(&wire).await?;
        replies
            .send(reply)
            .await
            .map_err(|_| Error::RepliesClosed)?;
        sequence = sequence.checked_add(1).ok_or(Error::SequenceExhausted)?;
        runtime::yield_now().await;
    }
}
async fn owner_role<
    const O: u8,
    const L: usize,
    const F: usize,
    const B: usize,
    const R: usize,
    const P: usize,
    const E: usize,
>(
    endpoint: &mut Endpoint<'_, O>,
    mut owner: RecoveryOwner<L, F, B, R>,
    authority: &Arena<P, E>,
    exchange: &Exchange<L, B>,
) -> Result<(), Error> {
    let generation = owner.config.generation;
    let install = Descriptor {
        generation,
        sequence: 0,
    };
    let wire = encode(install);
    same(endpoint.recv::<p::Install>().await?, wire)?;
    exchange.put_reply(Reply {
        descriptor: install,
        snapshot: owner.snapshot(),
        outcome: Outcome::Installed,
    })?;
    endpoint.send::<p::Installed>(&wire).await?;
    loop {
        let branch = endpoint.offer().await?;
        let label = branch.label();
        let wire = match label {
            p::RESERVE => branch.recv::<p::Reserve>().await?,
            p::ADAPTER_COMPLETE => branch.recv::<p::AdapterComplete>().await?,
            p::CANCEL => branch.recv::<p::Cancel>().await?,
            p::ACK => branch.recv::<p::Ack>().await?,
            p::DETECT_LOSS => branch.recv::<p::DetectLoss>().await?,
            p::FLIGHT => branch.recv::<p::Flight>().await?,
            p::DISCARD_SPACE => branch.recv::<p::DiscardSpace>().await?,
            p::REQUEUE_SPACE => branch.recv::<p::RequeueSpace>().await?,
            p::RECLAIM => branch.recv::<p::Reclaim>().await?,
            p::RESET_PATH => branch.recv::<p::ResetPath>().await?,
            p::TIMER => branch.recv::<p::Timer>().await?,
            p::KEY_PTO => branch.recv::<p::KeyPto>().await?,
            p::REJECT_ZERO_RTT => branch.recv::<p::RejectZeroRtt>().await?,
            p::ECN_MARKING => branch.recv::<p::EcnMarking>().await?,
            p::INSPECT => branch.recv::<p::Inspect>().await?,
            p::RETIRE_REQUESTED => branch.recv::<p::RetireRequested>().await?,
            _ => return Err(Error::UnexpectedLabel(label)),
        };
        // No interior borrow or externally mutable numeric state crosses awaits.
        let succeeded = {
            let Request {
                descriptor,
                command,
            } = exchange.take_request(wire)?;
            if descriptor.generation != generation || command.label() != label {
                return Err(Error::Correlation);
            }
            let outcome = match owner.apply(authority, descriptor, command) {
                Ok(outcome) => outcome,
                Err(error) => Outcome::Rejected(error),
            };
            let succeeded = !matches!(outcome, Outcome::Rejected(_) | Outcome::ZeroRttPending(_));
            exchange.put_reply(Reply {
                descriptor,
                snapshot: owner.snapshot(),
                outcome,
            })?;
            succeeded
        };
        if label == p::RETIRE_REQUESTED {
            endpoint.send::<p::Retired>(&wire).await?;
            same(endpoint.recv::<p::RetirementAcknowledged>().await?, wire)?;
            return Ok(());
        }
        if succeeded {
            endpoint.send::<p::Applied>(&wire).await?;
        } else {
            endpoint.send::<p::Rejected>(&wire).await?;
        }
        same(endpoint.recv::<p::ResultTaken>().await?, wire)?;
        runtime::yield_now().await;
    }
}

#[cfg(test)]
mod tests;

/// Mailbox-facing recovery client. It does not hold any numeric kernel. An
/// abandoned request closes its channels, so a later request cannot accidentally
/// consume an earlier outcome or reinterpret a pending adapter reservation.
pub struct Client<
    'channel,
    'storage,
    const L: usize,
    const B: usize,
    const Q: usize,
    const S: usize,
> {
    generation: u64,
    commands: Sender<'channel, 'storage, Command<B>, Q>,
    replies: Receiver<'channel, 'storage, Reply<L, B>, S>,
    snapshot: Snapshot,
    expected_sequence: u64,
}
#[derive(Debug)]
pub enum ClientError {
    CommandsClosed,
    RepliesClosed,
    Correlation,
    UnexpectedReply,
    SequenceExhausted,
}
impl<'channel, 'storage, const L: usize, const B: usize, const Q: usize, const S: usize>
    Client<'channel, 'storage, L, B, Q, S>
{
    pub async fn connect(
        generation: u64,
        commands: Sender<'channel, 'storage, Command<B>, Q>,
        mut replies: Receiver<'channel, 'storage, Reply<L, B>, S>,
    ) -> Result<Self, ClientError> {
        let reply = replies
            .recv()
            .await
            .map_err(|_| ClientError::RepliesClosed)?;
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
            generation,
            commands,
            replies,
            snapshot: reply.snapshot,
            expected_sequence: 1,
        })
    }
    pub const fn snapshot(&self) -> Snapshot {
        self.snapshot
    }
    pub async fn request(&mut self, command: Command<B>) -> Result<Outcome<L, B>, ClientError> {
        let mut request = PendingRequest {
            client: self,
            complete: false,
        };
        let expected = Descriptor {
            generation: request.client.generation,
            sequence: request.client.expected_sequence,
        };
        request
            .client
            .commands
            .send(command)
            .await
            .map_err(|_| ClientError::CommandsClosed)?;
        let reply = request
            .client
            .replies
            .recv()
            .await
            .map_err(|_| ClientError::RepliesClosed)?;
        if reply.descriptor != expected {
            return Err(ClientError::Correlation);
        }
        request.client.expected_sequence = expected
            .sequence
            .checked_add(1)
            .ok_or(ClientError::SequenceExhausted)?;
        request.client.snapshot = reply.snapshot;
        request.complete = true;
        Ok(reply.outcome)
    }
    pub async fn retire(mut self) -> Result<Snapshot, ClientError> {
        if !matches!(self.request(Command::Retire).await?, Outcome::Retired) {
            return Err(ClientError::UnexpectedReply);
        }
        Ok(self.snapshot)
    }
    pub fn close(&mut self) {
        self.commands.close();
        self.replies.close();
    }
}
impl<const L: usize, const B: usize, const Q: usize, const S: usize> Drop
    for Client<'_, '_, L, B, Q, S>
{
    fn drop(&mut self) {
        self.close();
    }
}
struct PendingRequest<'a, 'c, 's, const L: usize, const B: usize, const Q: usize, const S: usize> {
    client: &'a mut Client<'c, 's, L, B, Q, S>,
    complete: bool,
}
impl<const L: usize, const B: usize, const Q: usize, const S: usize> Drop
    for PendingRequest<'_, '_, '_, L, B, Q, S>
{
    fn drop(&mut self) {
        if !self.complete {
            self.client.close();
        }
    }
}
