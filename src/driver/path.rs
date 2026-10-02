//! Path/CID authorities in the real service choreography. External owners prove
//! AEAD, CID rules, address validation and budget arithmetic. These opaque tickets
//! bind those effects to the exact live authenticated receive or accepted send;
//! path acceptance alone never authenticates a peer address.
use super::*;
use crate::{
    connection_id::{Cid, LocalCidHandle, PeerCidHandle},
    path::{PathIdentity, Transmit as PathTransmit},
    protocol::*,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathEffect {
    ChallengeReceived,
    ResponseValidated,
    ActivePathChanged,
    ValidationExpired,
}
/// Single-use owner of one completed typed timer event. Equal clock values
/// carry different checked descriptor identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimerTicket {
    descriptor: Descriptor,
    now: u64,
}
impl TimerTicket {
    pub const fn now(self) -> u64 {
        self.now
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReceiveSource {
    Ordinary(ReceiveTicket),
    EarlyControl(EarlyControlReleaseTicket),
    Timer(TimerTicket),
}
impl ReceiveSource {
    fn descriptor(self) -> Descriptor {
        match self {
            Self::Ordinary(ticket) => ticket.0,
            Self::EarlyControl(ticket) => Descriptor {
                generation: ticket.generation(),
                id: ticket.descriptor_id(),
            },
            Self::Timer(ticket) => ticket.descriptor,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathEffectTicket {
    descriptor: Descriptor,
    receive: ReceiveSource,
    path: PathIdentity,
    effect: PathEffect,
}
impl PathEffectTicket {
    pub const fn path(self) -> PathIdentity {
        self.path
    }
    pub const fn effect(self) -> PathEffect {
        self.effect
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CidInstallTicket {
    descriptor: Descriptor,
    receive: ReceiveSource,
    sequence: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CidRetirementTicket {
    descriptor: Descriptor,
    receive: ReceiveSource,
    sequence: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PeerTarget {
    FixedZero,
    Bootstrap(Cid),
    Verified(PeerCidHandle),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathReservationTicket {
    descriptor: Descriptor,
    transmit: TransmitTicket,
    path: PathTransmit,
    cid: PeerTarget,
}
impl PathReservationTicket {
    pub const fn transmit(self) -> TransmitTicket {
        self.transmit
    }
    pub fn path(self) -> PathIdentity {
        self.path.path()
    }
    pub const fn peer_cid(self) -> Option<PeerCidHandle> {
        match self.cid {
            PeerTarget::Bootstrap(_) | PeerTarget::FixedZero => None,
            PeerTarget::Verified(cid) => Some(cid),
        }
    }
    pub const fn bootstrap_cid(self) -> Option<Cid> {
        match self.cid {
            PeerTarget::Bootstrap(cid) => Some(cid),
            PeerTarget::Verified(_) | PeerTarget::FixedZero => None,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathAcceptedTicket {
    descriptor: Descriptor,
    reservation: PathReservationTicket,
}
impl PathAcceptedTicket {
    pub const fn reservation(self) -> PathReservationTicket {
        self.reservation
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CidAdvertisementTicket {
    descriptor: Descriptor,
    accepted: Descriptor,
    cid: LocalCidHandle,
}
impl CidAdvertisementTicket {
    pub const fn local_cid(self) -> LocalCidHandle {
        self.cid
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SendState {
    Reserved(PathReservationTicket),
    Accepted {
        ticket: PathAcceptedTicket,
        advertisement: Option<CidAdvertisementTicket>,
    },
}
pub(super) struct State {
    send: Option<SendState>,
    timer: Option<TimerTicket>,
    timer_effect: bool,
}
impl State {
    pub(super) const fn new() -> Self {
        Self {
            send: None,
            timer: None,
            timer_effect: false,
        }
    }
    pub(super) const fn retired() -> Self {
        Self::new()
    }
    pub(super) fn supersede_timer(&mut self) -> Result<(), DriverError> {
        if self.timer_effect {
            return Err(DriverError::ReceiveEffectBusy);
        }
        self.timer = None;
        Ok(())
    }
    pub(super) fn transmitting(&self) -> bool {
        self.send.is_some()
    }
}

impl Driver<'_> {
    fn validate_path_source(&self, source: ReceiveSource) -> Result<(), DriverError> {
        match source {
            ReceiveSource::Ordinary(ticket) => self.validate_receive(ticket),
            ReceiveSource::EarlyControl(ticket) => self.validate_early_control_release(ticket),
            ReceiveSource::Timer(ticket) => {
                self.ensure_live()?;
                if self.path.timer != Some(ticket)
                    || ticket.descriptor.generation != self.generation
                {
                    return Err(DriverError::InvalidTicket);
                }
                Ok(())
            }
        }
    }

    /// Preserve ordinary timer progress while optionally granting one explicit
    /// timer-driven path transition. Any newer timer event invalidates the grant.
    pub fn timer_with_ticket(&mut self, now: u64) -> Result<TimerTicket, DriverError> {
        let descriptor = self.issue_descriptor()?;
        self.timer(now)?;
        let ticket = TimerTicket { descriptor, now };
        self.path.timer = Some(ticket);
        Ok(ticket)
    }
    pub fn begin_timer_path_effect(
        &mut self,
        timer: TimerTicket,
        path: PathIdentity,
        effect: PathEffect,
    ) -> Result<PathEffectTicket, DriverError> {
        if !matches!(
            effect,
            PathEffect::ValidationExpired | PathEffect::ActivePathChanged
        ) {
            return Err(DriverError::InvalidTicket);
        }
        self.begin_path_effect_from(ReceiveSource::Timer(timer), path, effect)
    }
    pub fn begin_path_effect(
        &mut self,
        receive: ReceiveTicket,
        path: PathIdentity,
        effect: PathEffect,
    ) -> Result<PathEffectTicket, DriverError> {
        self.begin_path_effect_from(ReceiveSource::Ordinary(receive), path, effect)
    }
    pub fn begin_early_path_effect(
        &mut self,
        release: EarlyControlReleaseTicket,
        path: PathIdentity,
        effect: PathEffect,
    ) -> Result<PathEffectTicket, DriverError> {
        self.begin_path_effect_from(ReceiveSource::EarlyControl(release), path, effect)
    }
    fn begin_path_effect_from(
        &mut self,
        receive: ReceiveSource,
        path: PathIdentity,
        effect: PathEffect,
    ) -> Result<PathEffectTicket, DriverError> {
        self.validate_path_source(receive)?;
        if self.receive_effect.is_some() {
            return Err(DriverError::ReceiveEffectBusy);
        }
        if path.connection_generation != self.generation {
            return Err(DriverError::InvalidTicket);
        }
        let ticket = PathEffectTicket {
            descriptor: self.issue_descriptor()?,
            receive,
            path,
            effect,
        };
        let wire = path_wire(
            receive.descriptor(),
            ticket.descriptor,
            path.path_generation,
        );
        self.execute(|roles| rx_request::<PathEffectRequest>(roles, wire))?;
        self.receive_effect = Some(ReceiveEffect::Path(ticket));
        if matches!(receive, ReceiveSource::Timer(_)) {
            self.path.timer_effect = true;
        }
        Ok(ticket)
    }
    pub fn finish_path_effect(&mut self, ticket: PathEffectTicket) -> Result<(), DriverError> {
        self.validate_path_source(ticket.receive)?;
        if self.receive_effect != Some(ReceiveEffect::Path(ticket)) {
            return Err(DriverError::InvalidTicket);
        }
        let wire = path_wire(
            ticket.receive.descriptor(),
            ticket.descriptor,
            ticket.path.path_generation,
        );
        self.execute(|roles| rx_complete::<PathEffectCompleted>(roles, wire))?;
        self.receive_effect = None;
        if matches!(ticket.receive, ReceiveSource::Timer(_)) {
            self.path.timer = None;
            self.path.timer_effect = false;
        }
        Ok(())
    }
    pub fn begin_cid_install(
        &mut self,
        receive: ReceiveTicket,
        sequence: u64,
    ) -> Result<CidInstallTicket, DriverError> {
        self.begin_cid_install_from(ReceiveSource::Ordinary(receive), sequence)
    }
    pub fn begin_early_cid_install(
        &mut self,
        release: EarlyControlReleaseTicket,
        sequence: u64,
    ) -> Result<CidInstallTicket, DriverError> {
        self.begin_cid_install_from(ReceiveSource::EarlyControl(release), sequence)
    }
    fn begin_cid_install_from(
        &mut self,
        receive: ReceiveSource,
        sequence: u64,
    ) -> Result<CidInstallTicket, DriverError> {
        self.validate_path_source(receive)?;
        if self.receive_effect.is_some() {
            return Err(DriverError::ReceiveEffectBusy);
        }
        if sequence > crate::packet::MAX_VARINT {
            return Err(DriverError::InvalidTicket);
        }
        let ticket = CidInstallTicket {
            descriptor: self.issue_descriptor()?,
            receive,
            sequence,
        };
        let wire = path_wire(receive.descriptor(), ticket.descriptor, sequence);
        self.execute(|roles| rx_request::<CidInstallRequest>(roles, wire))?;
        self.receive_effect = Some(ReceiveEffect::CidInstall(ticket));
        Ok(ticket)
    }
    pub fn finish_cid_install(&mut self, ticket: CidInstallTicket) -> Result<(), DriverError> {
        self.validate_path_source(ticket.receive)?;
        if self.receive_effect != Some(ReceiveEffect::CidInstall(ticket)) {
            return Err(DriverError::InvalidTicket);
        }
        let wire = path_wire(
            ticket.receive.descriptor(),
            ticket.descriptor,
            ticket.sequence,
        );
        self.execute(|roles| rx_complete::<CidInstallCompleted>(roles, wire))?;
        self.receive_effect = None;
        Ok(())
    }
    pub fn begin_cid_retirement(
        &mut self,
        receive: ReceiveTicket,
        sequence: u64,
    ) -> Result<CidRetirementTicket, DriverError> {
        self.begin_cid_retirement_from(ReceiveSource::Ordinary(receive), sequence)
    }
    pub fn begin_early_cid_retirement(
        &mut self,
        release: EarlyControlReleaseTicket,
        sequence: u64,
    ) -> Result<CidRetirementTicket, DriverError> {
        self.begin_cid_retirement_from(ReceiveSource::EarlyControl(release), sequence)
    }
    fn begin_cid_retirement_from(
        &mut self,
        receive: ReceiveSource,
        sequence: u64,
    ) -> Result<CidRetirementTicket, DriverError> {
        self.validate_path_source(receive)?;
        if self.receive_effect.is_some() {
            return Err(DriverError::ReceiveEffectBusy);
        }
        if sequence > crate::packet::MAX_VARINT {
            return Err(DriverError::InvalidTicket);
        }
        let ticket = CidRetirementTicket {
            descriptor: self.issue_descriptor()?,
            receive,
            sequence,
        };
        let wire = path_wire(receive.descriptor(), ticket.descriptor, sequence);
        self.execute(|roles| rx_request::<CidRetirementRequest>(roles, wire))?;
        self.receive_effect = Some(ReceiveEffect::CidRetirement(ticket));
        Ok(ticket)
    }
    pub fn finish_cid_retirement(
        &mut self,
        ticket: CidRetirementTicket,
    ) -> Result<(), DriverError> {
        self.validate_path_source(ticket.receive)?;
        if self.receive_effect != Some(ReceiveEffect::CidRetirement(ticket)) {
            return Err(DriverError::InvalidTicket);
        }
        let wire = path_wire(
            ticket.receive.descriptor(),
            ticket.descriptor,
            ticket.sequence,
        );
        self.execute(|roles| rx_complete::<CidRetirementCompleted>(roles, wire))?;
        self.receive_effect = None;
        Ok(())
    }
    /// Call after both real sent-ledger/path reservations and peer-CID preflight,
    /// but before publishing bytes to the adapter. The full descriptors remain
    /// in checked local state; the protocol carries their unique grant ID.
    pub fn bind_path_transmit(
        &mut self,
        transmit: TransmitTicket,
        path: PathTransmit,
        cid: PeerCidHandle,
    ) -> Result<PathReservationTicket, DriverError> {
        self.bind_path_target(transmit, path, PeerTarget::Verified(cid))
    }
    /// Before the peer's final initial source CID is verified, keep the actual
    /// bootstrap wire DCID in the reservation. It grants no reset-token usage.
    pub fn bind_bootstrap_path_transmit(
        &mut self,
        transmit: TransmitTicket,
        path: PathTransmit,
        destination: Cid,
    ) -> Result<PathReservationTicket, DriverError> {
        self.bind_path_target(transmit, path, PeerTarget::Bootstrap(destination))
    }
    /// Zero-length peer CIDs use only the original address-bound path. The
    /// connection owner checks its exact tuple; no synthetic CID is introduced.
    pub(crate) fn bind_zero_cid_path_transmit(
        &mut self,
        transmit: TransmitTicket,
        path: PathTransmit,
        original: PathIdentity,
    ) -> Result<PathReservationTicket, DriverError> {
        if path.path() != original {
            return Err(DriverError::InvalidTicket);
        }
        self.bind_path_target(transmit, path, PeerTarget::FixedZero)
    }
    fn bind_path_target(
        &mut self,
        transmit: TransmitTicket,
        path: PathTransmit,
        cid: PeerTarget,
    ) -> Result<PathReservationTicket, DriverError> {
        self.ensure_live()?;
        if self.path.transmitting() {
            return Err(DriverError::TransmitBusy);
        }
        if self.transmit != Some(transmit)
            || transmit.generation() != self.generation
            || path.path().connection_generation != self.generation
            || matches!(cid, PeerTarget::Verified(handle) if handle.connection_generation() != self.generation)
        {
            return Err(DriverError::InvalidTicket);
        }
        let ticket = PathReservationTicket {
            descriptor: self.issue_descriptor()?,
            transmit,
            path,
            cid,
        };
        let wire = path_wire(transmit.0, ticket.descriptor, path.path().path_generation);
        self.execute(|roles| {
            poll_ready(roles.recovery.send::<PathReserved>(&wire))?;
            match_bytes(poll_ready(roles.adapter.recv::<PathReserved>())?, wire)
        })?;
        self.path.send = Some(SendState::Reserved(ticket));
        Ok(ticket)
    }
    /// Supply the actual adapter outcome. Rejection grants no advertisement or
    /// accepted-send authority; acceptance must be completed exactly once after
    /// the path/CID/sent owners apply the matching committed effects.
    pub fn begin_path_result(
        &mut self,
        reservation: PathReservationTicket,
        accepted: bool,
    ) -> Result<Option<PathAcceptedTicket>, DriverError> {
        self.ensure_live()?;
        if self.path.send != Some(SendState::Reserved(reservation))
            || self.transmit != Some(reservation.transmit)
            || reservation.descriptor.generation != self.generation
        {
            return Err(DriverError::InvalidTicket);
        }
        if !accepted {
            let wire = path_wire(
                reservation.transmit.0,
                reservation.descriptor,
                reservation.path.path().path_generation,
            );
            self.execute(|roles| {
                poll_ready(roles.adapter.send::<PathRejected>(&wire))?;
                match_bytes(poll_ready(roles.recovery.recv::<PathRejected>())?, wire)
            })?;
            self.path.send = None;
            return Ok(None);
        }
        let ticket = PathAcceptedTicket {
            descriptor: self.issue_descriptor()?,
            reservation,
        };
        let wire = path_wire(
            reservation.descriptor,
            ticket.descriptor,
            reservation.path.path().path_generation,
        );
        self.execute(|roles| {
            poll_ready(roles.adapter.send::<PathAccepted>(&wire))?;
            match_bytes(poll_ready(roles.recovery.recv::<PathAccepted>())?, wire)
        })?;
        self.path.send = Some(SendState::Accepted {
            ticket,
            advertisement: None,
        });
        Ok(Some(ticket))
    }
    /// A CID advertisement is committed only for an accepted datagram that
    /// actually carried that CID's NEW frame (or corresponding handshake data).
    /// The endpoint's retained frame references establish that association.
    pub fn begin_cid_advertisement(
        &mut self,
        accepted: PathAcceptedTicket,
        cid: LocalCidHandle,
    ) -> Result<CidAdvertisementTicket, DriverError> {
        self.ensure_live()?;
        if cid.connection_generation() != self.generation
            || self.path.send
                != Some(SendState::Accepted {
                    ticket: accepted,
                    advertisement: None,
                })
        {
            return Err(DriverError::InvalidTicket);
        }
        let ticket = CidAdvertisementTicket {
            descriptor: self.issue_descriptor()?,
            accepted: accepted.descriptor,
            cid,
        };
        let wire = path_wire(
            accepted.descriptor,
            ticket.descriptor,
            accepted.reservation.path.path().path_generation,
        );
        self.execute(|roles| {
            poll_ready(roles.recovery.send::<CidAdvertisementRequest>(&wire))?;
            match_bytes(
                poll_ready(roles.packet.recv::<CidAdvertisementRequest>())?,
                wire,
            )
        })?;
        self.path.send = Some(SendState::Accepted {
            ticket: accepted,
            advertisement: Some(ticket),
        });
        Ok(ticket)
    }
    pub fn finish_cid_advertisement(
        &mut self,
        ticket: CidAdvertisementTicket,
    ) -> Result<(), DriverError> {
        self.ensure_live()?;
        let Some(SendState::Accepted {
            ticket: accepted,
            advertisement: Some(current),
        }) = self.path.send
        else {
            return Err(DriverError::InvalidTicket);
        };
        if current != ticket || ticket.accepted != accepted.descriptor {
            return Err(DriverError::InvalidTicket);
        }
        let wire = path_wire(
            accepted.descriptor,
            ticket.descriptor,
            accepted.reservation.path.path().path_generation,
        );
        self.execute(|roles| {
            poll_ready(roles.packet.send::<CidAdvertisementCompleted>(&wire))?;
            match_bytes(
                poll_ready(roles.recovery.recv::<CidAdvertisementCompleted>())?,
                wire,
            )
        })?;
        self.path.send = Some(SendState::Accepted {
            ticket: accepted,
            advertisement: None,
        });
        Ok(())
    }
    pub fn finish_path_result(&mut self, ticket: PathAcceptedTicket) -> Result<(), DriverError> {
        self.ensure_live()?;
        if self.path.send
            != Some(SendState::Accepted {
                ticket,
                advertisement: None,
            })
        {
            return Err(DriverError::InvalidTicket);
        }
        let wire = path_wire(
            ticket.reservation.descriptor,
            ticket.descriptor,
            ticket.reservation.path.path().path_generation,
        );
        self.execute(|roles| {
            poll_ready(roles.recovery.send::<PathCommitted>(&wire))?;
            match_bytes(poll_ready(roles.adapter.recv::<PathCommitted>())?, wire)
        })?;
        self.path.send = None;
        Ok(())
    }
}
fn path_wire(parent: Descriptor, effect: Descriptor, value: u64) -> [u8; 16] {
    let mut wire = [0; 16];
    wire[..4].copy_from_slice(&parent.id.to_be_bytes());
    wire[4..8].copy_from_slice(&effect.id.to_be_bytes());
    wire[8..].copy_from_slice(&value.to_be_bytes());
    wire
}
fn rx_request<M: hibana::g::Message<Payload = [u8; 16]>>(
    roles: &mut Roles<'_>,
    wire: [u8; 16],
) -> Result<(), DriverError> {
    poll_ready(roles.packet.send::<M>(&wire))?;
    match_bytes(poll_ready(roles.recovery.recv::<M>())?, wire)
}
fn rx_complete<M: hibana::g::Message<Payload = [u8; 16]>>(
    roles: &mut Roles<'_>,
    wire: [u8; 16],
) -> Result<(), DriverError> {
    poll_ready(roles.recovery.send::<M>(&wire))?;
    match_bytes(poll_ready(roles.packet.recv::<M>())?, wire)
}

#[cfg(test)]
mod tests {
    use super::super::tests::with_driver;
    use super::*;
    use crate::{
        connection_id::{Cid, LocalCidSlot, LocalCidTable, PeerCidSlot, PeerCidTable},
        path::{Address, Config, InitialValidation, PathSlot, Paths},
    };
    use core::net::{IpAddr, Ipv4Addr, SocketAddr};
    fn address() -> Address {
        Address {
            local: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
            remote: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2),
        }
    }
    fn identity(generation: u64) -> PathIdentity {
        PathIdentity {
            connection_generation: generation,
            slot: 2,
            path_generation: 7,
        }
    }
    const CONFIG: Config = Config {
        probe_interval_us: 100,
        validation_timeout_us: 300,
        max_attempts: 3,
    };

    #[test]
    fn timer_path_grants_are_exact_single_use_and_cannot_be_superseded_mid_effect() {
        with_driver::<16, _>(7, |driver, _| {
            let old = driver.timer_with_ticket(10).unwrap();
            let current = driver.timer_with_ticket(10).unwrap();
            assert_ne!(old, current);
            assert!(matches!(
                driver.begin_timer_path_effect(old, identity(7), PathEffect::ValidationExpired),
                Err(DriverError::InvalidTicket)
            ));
            let mut foreign = current;
            foreign.descriptor.generation = 8;
            assert!(matches!(
                driver.begin_timer_path_effect(foreign, identity(7), PathEffect::ValidationExpired),
                Err(DriverError::InvalidTicket)
            ));
            let effect = driver
                .begin_timer_path_effect(current, identity(7), PathEffect::ValidationExpired)
                .unwrap();
            assert!(matches!(
                driver.timer(11),
                Err(DriverError::ReceiveEffectBusy)
            ));
            driver.finish_path_effect(effect).unwrap();
            assert!(matches!(
                driver.finish_path_effect(effect),
                Err(DriverError::InvalidTicket)
            ));
            assert!(matches!(
                driver.begin_timer_path_effect(current, identity(7), PathEffect::ValidationExpired),
                Err(DriverError::InvalidTicket)
            ));
            let receive = driver.begin_receive().unwrap();
            let effect = driver
                .begin_path_effect(receive, identity(7), PathEffect::ActivePathChanged)
                .unwrap();
            driver.timer(11).unwrap();
            driver.finish_path_effect(effect).unwrap();
            driver.finish_receive(receive).unwrap();
            let tx = driver.reserve_transmit().unwrap();
            let timer = driver.timer_with_ticket(11).unwrap();
            let effect = driver
                .begin_timer_path_effect(timer, identity(7), PathEffect::ValidationExpired)
                .unwrap();
            driver.finish_path_effect(effect).unwrap();
            driver.adapter_result(tx).unwrap();
        });
    }

    #[test]
    fn complete_service_graph_supports_timer_as_the_first_action() {
        with_driver::<16, _>(7, |driver, queues| {
            driver.timer(0).unwrap();
            driver.install_key(Level::Initial).unwrap();
            driver.install_key(Level::Handshake).unwrap();
            driver.install_key(Level::OneRtt).unwrap();
            driver.install_early_key().unwrap();
            let receive = driver.begin_receive().unwrap();
            let path = driver
                .begin_path_effect(receive, identity(7), PathEffect::ActivePathChanged)
                .unwrap();
            driver.finish_path_effect(path).unwrap();
            driver.finish_receive(receive).unwrap();
            driver.timer(1).unwrap();
            assert_eq!(queues.queued(), 0);
            assert!(!queues.is_closed());
        });
    }
    #[test]
    fn path_and_cid_effects_require_exact_live_ordinary_receive_and_exclude_other_effects() {
        with_driver::<16, _>(7, |driver, _| {
            let missing = ReceiveTicket(Descriptor {
                generation: 7,
                id: 0,
            });
            assert!(matches!(
                driver.begin_path_effect(missing, identity(7), PathEffect::ResponseValidated),
                Err(DriverError::InvalidTicket)
            ));
            let receive = driver.begin_receive().unwrap();
            assert!(matches!(
                driver.begin_path_effect(receive, identity(8), PathEffect::ResponseValidated),
                Err(DriverError::InvalidTicket)
            ));
            let ticket = driver
                .begin_path_effect(receive, identity(7), PathEffect::ChallengeReceived)
                .unwrap();
            assert!(matches!(
                driver.finish_receive(receive),
                Err(DriverError::ReceiveEffectBusy)
            ));
            assert!(matches!(
                driver.begin_ack_release(receive),
                Err(DriverError::ReceiveEffectBusy)
            ));
            assert!(matches!(
                driver.begin_cid_retirement(receive, 1),
                Err(DriverError::ReceiveEffectBusy)
            ));
            let mut forged = ticket;
            forged.path.path_generation += 1;
            assert!(matches!(
                driver.finish_path_effect(forged),
                Err(DriverError::InvalidTicket)
            ));
            driver.finish_path_effect(ticket).unwrap();
            assert!(matches!(
                driver.finish_path_effect(ticket),
                Err(DriverError::InvalidTicket)
            ));
            let install = driver.begin_cid_install(receive, 1).unwrap();
            assert!(matches!(
                driver.begin_path_effect(receive, identity(7), PathEffect::ActivePathChanged),
                Err(DriverError::ReceiveEffectBusy)
            ));
            driver.finish_cid_install(install).unwrap();
            let retire = driver.begin_cid_retirement(receive, 1).unwrap();
            assert!(matches!(
                driver.finish_cid_install(install),
                Err(DriverError::InvalidTicket)
            ));
            driver.finish_cid_retirement(retire).unwrap();
            driver.finish_receive(receive).unwrap();
            assert!(matches!(
                driver.begin_cid_install(receive, 2),
                Err(DriverError::InvalidTicket)
            ));
            let next = driver.begin_receive().unwrap();
            assert!(matches!(
                driver.finish_cid_retirement(retire),
                Err(DriverError::InvalidTicket)
            ));
            assert!(matches!(
                driver.begin_cid_retirement(next, u64::MAX),
                Err(DriverError::InvalidTicket)
            ));
            driver.finish_receive(next).unwrap();
        });
    }
    #[test]
    fn accepted_path_has_distinct_single_use_advertisement_authority_without_address_validation() {
        with_driver::<16, _>(7, |driver, _| {
            let mut slots = [PathSlot::<2, 3>::empty()];
            let mut paths = Paths::new(&mut slots, 7, CONFIG).unwrap();
            let id = paths
                .insert(address(), InitialValidation::Unvalidated, 0)
                .unwrap();
            paths.received(id, 400).unwrap();
            let mut peer_slots = [PeerCidSlot::<2>::EMPTY; 4];
            let mut peer =
                PeerCidTable::new(0, 7, &mut peer_slots, 2, Cid::new(&[3; 8]).unwrap()).unwrap();
            let peer_cid = peer.initial().unwrap().handle;
            let mut local_slots = [LocalCidSlot::EMPTY; 4];
            let mut local = LocalCidTable::new(1, 7, &mut local_slots, 2).unwrap();
            let cid = local
                .issue_initial(Cid::new(&[4; 8]).unwrap(), None)
                .unwrap();
            let path_send = paths.reserve_datagram(id, 1200).unwrap();
            peer.check_send(peer_cid, address().local, address().remote)
                .unwrap();
            let tx = driver.reserve_transmit().unwrap();
            let reserved = driver.bind_path_transmit(tx, path_send, peer_cid).unwrap();
            assert!(matches!(
                driver.adapter_result(tx),
                Err(DriverError::TransmitBusy)
            ));
            let accepted = driver.begin_path_result(reserved, true).unwrap().unwrap();
            assert!(matches!(
                driver.begin_path_result(reserved, true),
                Err(DriverError::InvalidTicket)
            ));
            paths.adapter_accepted(path_send, 0).unwrap();
            peer.record_sent(peer_cid, address().local, address().remote)
                .unwrap();
            assert!(!paths.snapshot(id).unwrap().address_validated);
            let ad = driver
                .begin_cid_advertisement(accepted, cid.handle)
                .unwrap();
            assert!(matches!(
                driver.finish_path_result(accepted),
                Err(DriverError::InvalidTicket)
            ));
            assert!(local.mark_advertised(ad.local_cid()).unwrap());
            driver.finish_cid_advertisement(ad).unwrap();
            assert!(matches!(
                driver.finish_cid_advertisement(ad),
                Err(DriverError::InvalidTicket)
            ));
            driver.finish_path_result(accepted).unwrap();
            assert!(matches!(
                driver.begin_cid_advertisement(accepted, cid.handle),
                Err(DriverError::InvalidTicket)
            ));
            driver.adapter_result(tx).unwrap();
            assert_eq!(local.highest_advertised_sequence(), Some(0));
            assert_eq!(paths.snapshot(id).unwrap().sent, 1200);
        });
    }
    #[test]
    fn rejected_send_cannot_mint_acceptance_or_reuse_a_previous_accepted_ticket() {
        with_driver::<16, _>(7, |driver, _| {
            let mut slots = [PathSlot::<2, 3>::empty()];
            let mut paths = Paths::new(&mut slots, 7, CONFIG).unwrap();
            let id = paths
                .insert(address(), InitialValidation::AddressValidated, 0)
                .unwrap();
            let mut peer_slots = [PeerCidSlot::<1>::EMPTY; 2];
            let peer =
                PeerCidTable::new(0, 7, &mut peer_slots, 2, Cid::new(&[3]).unwrap()).unwrap();
            let peer = peer.initial().unwrap().handle;
            let first = paths.reserve_datagram(id, 100).unwrap();
            let tx = driver.reserve_transmit().unwrap();
            let reservation = driver.bind_path_transmit(tx, first, peer).unwrap();
            let accepted = driver
                .begin_path_result(reservation, true)
                .unwrap()
                .unwrap();
            paths.adapter_accepted(first, 0).unwrap();
            driver.finish_path_result(accepted).unwrap();
            driver.adapter_result(tx).unwrap();
            let rejected = paths.reserve_datagram(id, 100).unwrap();
            let tx = driver.reserve_transmit().unwrap();
            let reservation = driver.bind_path_transmit(tx, rejected, peer).unwrap();
            assert_eq!(driver.begin_path_result(reservation, false).unwrap(), None);
            paths.adapter_rejected(rejected).unwrap();
            assert!(matches!(
                driver.begin_path_result(reservation, true),
                Err(DriverError::InvalidTicket)
            ));
            assert!(matches!(
                driver.finish_path_result(accepted),
                Err(DriverError::InvalidTicket)
            ));
            driver.adapter_result(tx).unwrap();
            assert_eq!(paths.snapshot(id).unwrap().sent, 100);
            // Early/default engine sends that never bind a path remain legal.
            let ordinary = driver.reserve_transmit().unwrap();
            driver.adapter_result(ordinary).unwrap();
        });
    }
    #[test]
    fn stale_path_and_cid_generations_cannot_bind_current_transmit() {
        with_driver::<16, _>(7, |driver, _| {
            let mut slots = [PathSlot::<2, 3>::empty()];
            let mut paths = Paths::new(&mut slots, 8, CONFIG).unwrap();
            let id = paths
                .insert(address(), InitialValidation::AddressValidated, 0)
                .unwrap();
            let send = paths.reserve_datagram(id, 100).unwrap();
            let mut peers = [PeerCidSlot::<1>::EMPTY; 2];
            let peer = PeerCidTable::new(0, 7, &mut peers, 2, Cid::new(&[3]).unwrap())
                .unwrap()
                .initial()
                .unwrap()
                .handle;
            let tx = driver.reserve_transmit().unwrap();
            assert!(matches!(
                driver.bind_path_transmit(tx, send, peer),
                Err(DriverError::InvalidTicket)
            ));
            driver.adapter_result(tx).unwrap();
            let mut slots = [PathSlot::<2, 3>::empty()];
            let mut paths = Paths::new(&mut slots, 7, CONFIG).unwrap();
            let id = paths
                .insert(address(), InitialValidation::AddressValidated, 0)
                .unwrap();
            let send = paths.reserve_datagram(id, 100).unwrap();
            let mut peers = [PeerCidSlot::<1>::EMPTY; 2];
            let stale_peer = PeerCidTable::new(0, 8, &mut peers, 2, Cid::new(&[3]).unwrap())
                .unwrap()
                .initial()
                .unwrap()
                .handle;
            let tx = driver.reserve_transmit().unwrap();
            assert!(matches!(
                driver.bind_path_transmit(tx, send, stale_peer),
                Err(DriverError::InvalidTicket)
            ));
            let reserved = driver.bind_path_transmit(tx, send, peer).unwrap();
            driver.retire();
            assert!(matches!(
                driver.begin_path_result(reserved, true),
                Err(DriverError::Retired)
            ));
        });
    }
    #[test]
    fn path_effect_and_timer_progress_do_not_authorize_early_or_completed_receives() {
        with_driver::<16, _>(7, |driver, _| {
            driver.install_early_key().unwrap();
            let early_id = driver.next_descriptor.unwrap();
            let early = driver.begin_early_receive().unwrap();
            // Even equal numeric IDs have different ledger/type authority.
            let forged_ordinary = ReceiveTicket(Descriptor {
                generation: driver.generation(),
                id: early_id,
            });
            assert!(matches!(
                driver.begin_path_effect(
                    forged_ordinary,
                    identity(7),
                    PathEffect::ActivePathChanged
                ),
                Err(DriverError::InvalidTicket)
            ));
            driver.finish_early_receive(early).unwrap();
            let receive = driver.begin_receive().unwrap();
            let path = driver
                .begin_path_effect(receive, identity(7), PathEffect::ResponseValidated)
                .unwrap();
            driver.timer(1).unwrap();
            driver.finish_path_effect(path).unwrap();
            driver.finish_receive(receive).unwrap();
        });
    }
}
