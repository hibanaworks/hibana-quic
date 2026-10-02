//! Caller-owned QUIC path validation and anti-amplification state (RFC 9000 §8/9).
//!
//! The owner admits authenticated frames, counts each attributed UDP datagram
//! once, and supplies monotonic microseconds and a cryptographic RNG. This module
//! does not authenticate packets, choose a migration policy, or reset recovery.
//! A response received on ANY path validates only the original challenge's path
//! (§8.2.3). Its arrival address must never select the path being validated.
//! Every accepted send, including padding and ACK-only sends, uses this budget.
//! Descriptor acceptance is the actual UDP adapter acceptance boundary.
//!
//! The only MTU established here is QUIC's 1200-byte minimum. Caller storage
//! bounds simultaneous paths, outstanding sends, probes and queued responses.
//! Failed paths are retained until explicitly retired; retiring invalidates all
//! descriptors. Reconstructing a connection must use a new connection generation.

use crate::accounting::{AccountingError, PathBudget, PathReservation};
pub use crate::ecn::PathIdentity;
use core::net::SocketAddr;
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;

pub const MINIMUM_MTU: u64 = 1200;
const RANDOM_ATTEMPTS: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Address {
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidConfig,
    StorageInUse,
    Capacity,
    DuplicatePath,
    StalePath,
    PathFailed,
    GenerationExhausted,
    ClockRegression,
    DeadlineOverflow,
    Entropy,
    ChallengeCollision,
    AlreadyValidated,
    ProbeNotDue,
    ProbeLimit,
    PendingProbe,
    InvalidDescriptor,
    InvalidDatagramSize,
    ExpansionRequired,
    Accounting(AccountingError),
}
impl From<AccountingError> for Error {
    fn from(value: AccountingError) -> Self {
        Self::Accounting(value)
    }
}

/// `probe_interval_us` is the new path's probe timeout; the owner supplies a
/// validation timeout of at least three times the larger current/new-path PTO.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    pub probe_interval_us: u64,
    pub validation_timeout_us: u64,
    pub max_attempts: usize,
}

/// Initial trusted protocol evidence. Merely authenticating a packet from a new
/// source does not establish ownership of that source address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitialValidation {
    Unvalidated,
    /// The peer's address is already validated by handshake/token processing.
    /// A changed path still requires a full-sized challenge before `mtu` is true.
    AddressValidated,
    /// Bootstrap an existing path whose handshake established both properties.
    AddressAndMtuValidated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Control {
    Challenge([u8; 8]),
    Response([u8; 8]),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Content {
    Data,
    Probe { serial: u64, data: [u8; 8] },
    Response { serial: u64, data: [u8; 8] },
}

/// Opaque, generation-bound permission for exactly one adapter callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Transmit {
    path: PathIdentity,
    reservation: PathReservation,
    content: Content,
}
impl Transmit {
    pub fn path(self) -> PathIdentity {
        self.path
    }
    pub fn bytes(self) -> u64 {
        self.reservation.bytes()
    }
    pub fn control(self) -> Option<Control> {
        match self.content {
            Content::Data => None,
            Content::Probe { data, .. } => Some(Control::Challenge(data)),
            Content::Response { data, .. } => Some(Control::Response(data)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResponseHandle {
    path: PathIdentity,
    serial: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Validated {
    pub path: PathIdentity,
    pub address: Address,
    pub mtu_validated: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub address: Address,
    pub address_validated: bool,
    pub mtu_validated: bool,
    pub failed: bool,
    pub received: u64,
    pub sent: u64,
    pub reserved: u64,
    pub attempts: usize,
    pub deadline_us: u64,
}

#[derive(Clone, Copy)]
struct Probe {
    serial: u64,
    data: [u8; 8],
    pending: Option<PathReservation>,
    sent: bool,
    expanded: bool,
}
#[derive(Clone, Copy)]
struct Response {
    serial: u64,
    data: [u8; 8],
    pending: Option<PathReservation>,
}
struct Record<const SENDS: usize, const CONTROLS: usize> {
    id: PathIdentity,
    address: Address,
    budget: PathBudget<SENDS>,
    probes: [Option<Probe>; CONTROLS],
    responses: [Option<Response>; CONTROLS],
    next_serial: u64,
    attempts: usize,
    next_probe_us: u64,
    deadline_us: u64,
    mtu_validated: bool,
    validating: bool,
    failed: bool,
}

/// Initialize with `PathSlot::empty()`. Epochs remain after retirement so that
/// reusing caller storage cannot revive a descriptor from an earlier occupant.
pub struct PathSlot<const SENDS: usize, const CONTROLS: usize> {
    epoch: u64,
    record: Option<Record<SENDS, CONTROLS>>,
}
impl<const S: usize, const C: usize> PathSlot<S, C> {
    pub const fn empty() -> Self {
        Self {
            epoch: 0,
            record: None,
        }
    }
}

pub struct Paths<'a, const SENDS: usize, const CONTROLS: usize> {
    slots: &'a mut [PathSlot<SENDS, CONTROLS>],
    connection_generation: u64,
    config: Config,
    last_now: u64,
}
impl<'a, const S: usize, const C: usize> Paths<'a, S, C> {
    pub fn new(
        slots: &'a mut [PathSlot<S, C>],
        connection_generation: u64,
        config: Config,
    ) -> Result<Self, Error> {
        if slots.is_empty()
            || slots.len() > usize::from(u16::MAX) + 1
            || S == 0
            || C == 0
            || config.max_attempts == 0
            || config.max_attempts > C
            || config.max_attempts > 64
            || config.probe_interval_us == 0
            || config
                .probe_interval_us
                .checked_mul(3)
                .is_none_or(|n| n > config.validation_timeout_us)
        {
            return Err(Error::InvalidConfig);
        }
        if slots.iter().any(|s| s.record.is_some()) {
            return Err(Error::StorageInUse);
        }
        Ok(Self {
            slots,
            connection_generation,
            config,
            last_now: 0,
        })
    }
    pub fn insert(
        &mut self,
        address: Address,
        validation: InitialValidation,
        now: u64,
    ) -> Result<PathIdentity, Error> {
        self.clock(now)?;
        if self
            .slots
            .iter()
            .filter_map(|s| s.record.as_ref())
            .any(|r| r.address == address)
        {
            return Err(Error::DuplicatePath);
        }
        let index = self
            .slots
            .iter()
            .position(|s| s.record.is_none())
            .ok_or(Error::Capacity)?;
        let epoch = self.slots[index]
            .epoch
            .checked_add(1)
            .ok_or(Error::GenerationExhausted)?;
        let deadline_us = now
            .checked_add(self.config.validation_timeout_us)
            .ok_or(Error::DeadlineOverflow)?;
        let id = PathIdentity {
            connection_generation: self.connection_generation,
            slot: index as u16,
            path_generation: epoch,
        };
        let mut budget = PathBudget::new(u64::from(id.slot), epoch);
        if validation != InitialValidation::Unvalidated {
            budget.mark_validated()?;
        }
        self.slots[index].epoch = epoch;
        self.slots[index].record = Some(Record {
            id,
            address,
            budget,
            probes: [None; C],
            responses: [None; C],
            next_serial: 0,
            attempts: 0,
            next_probe_us: now,
            deadline_us,
            mtu_validated: validation == InitialValidation::AddressAndMtuValidated,
            validating: validation != InitialValidation::AddressAndMtuValidated,
            failed: false,
        });
        Ok(id)
    }
    pub fn find(&self, address: Address) -> Option<PathIdentity> {
        self.slots
            .iter()
            .filter_map(|s| s.record.as_ref())
            .find(|r| r.address == address)
            .map(|r| r.id)
    }
    pub fn snapshot(&self, path: PathIdentity) -> Result<Snapshot, Error> {
        let r = self.record(path)?;
        Ok(Snapshot {
            address: r.address,
            address_validated: r.budget.is_validated(),
            mtu_validated: r.mtu_validated,
            failed: r.failed,
            received: r.budget.received_bytes(),
            sent: r.budget.accepted_bytes(),
            reserved: r.budget.reserved_bytes(),
            attempts: r.attempts,
            deadline_us: r.deadline_us,
        })
    }
    /// Count actual UDP bytes once after attribution to this exact address pair.
    /// The adapter must not substitute a different path's receive credit.
    pub fn received(&mut self, path: PathIdentity, bytes: u64) -> Result<(), Error> {
        self.active_mut(path)?.budget.record_received(bytes)?;
        Ok(())
    }
    pub fn reserve_datagram(&mut self, path: PathIdentity, bytes: u64) -> Result<Transmit, Error> {
        size(bytes)?;
        let reservation = self.active_mut(path)?.budget.reserve(bytes)?;
        Ok(Transmit {
            path,
            reservation,
            content: Content::Data,
        })
    }
    pub fn reserve_probe(
        &mut self,
        path: PathIdentity,
        bytes: u64,
        now: u64,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Transmit, Error> {
        self.clock(now)?;
        let config = self.config;
        let r = self.active(path)?;
        if !r.validating {
            return Err(Error::AlreadyValidated);
        }
        if now >= r.deadline_us {
            return Err(Error::PathFailed);
        }
        if r.attempts >= config.max_attempts {
            return Err(Error::ProbeLimit);
        }
        if r.probes.iter().flatten().any(|p| p.pending.is_some()) {
            return Err(Error::PendingProbe);
        }
        if now < r.next_probe_us {
            return Err(Error::ProbeNotDue);
        }
        expansion(&r.budget, bytes)?;
        now.checked_add(probe_delay(config, r.attempts)?)
            .ok_or(Error::DeadlineOverflow)?;
        let serial = r
            .next_serial
            .checked_add(1)
            .ok_or(Error::GenerationExhausted)?;
        let index = r
            .probes
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let mut data = [0; 8];
        let mut fresh = false;
        for _ in 0..RANDOM_ATTEMPTS {
            rng.try_fill_bytes(&mut data).map_err(|_| Error::Entropy)?;
            if !self
                .slots
                .iter()
                .filter_map(|s| s.record.as_ref())
                .flat_map(|r| r.probes.iter().flatten())
                .any(|p| bool::from(p.data.ct_eq(&data)))
            {
                fresh = true;
                break;
            }
        }
        if !fresh {
            return Err(Error::ChallengeCollision);
        }
        let r = self.active_mut(path)?;
        let reservation = r.budget.reserve(bytes)?;
        r.next_serial = serial;
        r.probes[index] = Some(Probe {
            serial,
            data,
            pending: Some(reservation),
            sent: false,
            expanded: bytes >= MINIMUM_MTU,
        });
        Ok(Transmit {
            path,
            reservation,
            content: Content::Probe { serial, data },
        })
    }
    /// Invoke once per newly processed authenticated PATH_CHALLENGE frame.
    /// The handle retains the exact receipt path; do not route it via an active
    /// migration destination instead. Payload values are not replay identifiers.
    pub fn queue_response(
        &mut self,
        path: PathIdentity,
        data: [u8; 8],
    ) -> Result<ResponseHandle, Error> {
        let r = self.active_mut(path)?;
        let index = r
            .responses
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let serial = r
            .next_serial
            .checked_add(1)
            .ok_or(Error::GenerationExhausted)?;
        r.next_serial = serial;
        r.responses[index] = Some(Response {
            serial,
            data,
            pending: None,
        });
        Ok(ResponseHandle { path, serial })
    }
    pub fn pending_response(&self, path: PathIdentity) -> Result<Option<ResponseHandle>, Error> {
        Ok(self
            .active(path)?
            .responses
            .iter()
            .flatten()
            .find(|r| r.pending.is_none())
            .map(|r| ResponseHandle {
                path,
                serial: r.serial,
            }))
    }
    pub fn reserve_response(
        &mut self,
        response: ResponseHandle,
        bytes: u64,
    ) -> Result<Transmit, Error> {
        let r = self.active_mut(response.path)?;
        expansion(&r.budget, bytes)?;
        let index = r
            .responses
            .iter()
            .position(|v| v.is_some_and(|v| v.serial == response.serial && v.pending.is_none()))
            .ok_or(Error::InvalidDescriptor)?;
        let reservation = r.budget.reserve(bytes)?;
        let value = r.responses[index]
            .as_mut()
            .ok_or(Error::InvalidDescriptor)?;
        value.pending = Some(reservation);
        Ok(Transmit {
            path: response.path,
            reservation,
            content: Content::Response {
                serial: value.serial,
                data: value.data,
            },
        })
    }
    /// Actual adapter acceptance commits bytes even when the network later loses
    /// the datagram. No response is considered until its challenge is accepted.
    pub fn adapter_accepted(&mut self, transmit: Transmit, now: u64) -> Result<(), Error> {
        self.clock(now)?;
        let next_probe = if matches!(transmit.content, Content::Probe { .. }) {
            now.checked_add(probe_delay(
                self.config,
                self.active(transmit.path)?.attempts,
            )?)
            .ok_or(Error::DeadlineOverflow)?
        } else {
            now
        };
        let r = self.active_mut(transmit.path)?;
        let index = control_index(r, transmit)?;
        r.budget.adapter_accepted(transmit.reservation)?;
        match transmit.content {
            Content::Data => {}
            Content::Probe { .. } => {
                let p = r.probes[index].as_mut().ok_or(Error::InvalidDescriptor)?;
                p.pending = None;
                p.sent = true;
                r.attempts += 1;
                r.next_probe_us = next_probe;
            }
            Content::Response { .. } => r.responses[index] = None,
        }
        Ok(())
    }
    pub fn adapter_rejected(&mut self, transmit: Transmit) -> Result<(), Error> {
        let r = self.active_mut(transmit.path)?;
        let index = control_index(r, transmit)?;
        r.budget.cancel(transmit.reservation)?;
        match transmit.content {
            Content::Data => {}
            Content::Probe { .. } => r.probes[index] = None,
            Content::Response { .. } => {
                r.responses[index]
                    .as_mut()
                    .ok_or(Error::InvalidDescriptor)?
                    .pending = None
            }
        }
        Ok(())
    }
    /// Call only with an authenticated PATH_RESPONSE. Per RFC9000 §8.2.3 the
    /// arrival path is intentionally not an input. Return the original target.
    /// Unknown, replayed, unsent and expired challenges have no effect.
    pub fn response(&mut self, data: [u8; 8], now: u64) -> Result<Option<Validated>, Error> {
        self.clock(now)?;
        let timeout = self.config.validation_timeout_us;
        for slot in self.slots.iter_mut() {
            let Some(r) = slot.record.as_mut() else {
                continue;
            };
            if r.failed || now >= r.deadline_us {
                continue;
            }
            let Some(probe) = r
                .probes
                .iter()
                .flatten()
                .find(|p| p.sent && bool::from(p.data.ct_eq(&data)))
                .copied()
            else {
                continue;
            };
            let new_deadline = if probe.expanded {
                r.deadline_us
            } else {
                now.checked_add(timeout).ok_or(Error::DeadlineOverflow)?
            };
            // Retire all outstanding challenges after success; any pending send
            // reservation is cancelled so it cannot later revive old evidence.
            for probe in r.probes.iter().flatten() {
                if let Some(pending) = probe.pending {
                    r.budget.cancel(pending)?;
                }
            }
            r.budget.mark_validated()?;
            r.probes.fill(None);
            r.mtu_validated |= probe.expanded;
            r.validating = !r.mtu_validated;
            r.attempts = 0;
            r.next_probe_us = now;
            r.deadline_us = new_deadline;
            return Ok(Some(Validated {
                path: r.id,
                address: r.address,
                mtu_validated: r.mtu_validated,
            }));
        }
        Ok(None)
    }
    /// Returns one newly failed path at a time. Failure does not close another
    /// usable path or silently migrate traffic. Owner selects fallback policy.
    pub fn expire(&mut self, now: u64) -> Result<Option<PathIdentity>, Error> {
        self.clock(now)?;
        for slot in self.slots.iter_mut() {
            let Some(r) = slot.record.as_mut() else {
                continue;
            };
            if !r.failed && r.validating && now >= r.deadline_us {
                r.failed = true;
                r.budget.retire();
                r.probes.fill(None);
                r.responses.fill(None);
                return Ok(Some(r.id));
            }
        }
        Ok(None)
    }
    /// Reprobe a previously validated path to counter off-path forwarding
    /// (RFC9000 §9.3.3). Existing validation evidence is preserved while probing.
    /// Pending probes make this a caller sequencing error rather than silently
    /// cancelling a datagram that might be about to reach the adapter.
    pub fn restart_validation(&mut self, path: PathIdentity, now: u64) -> Result<(), Error> {
        self.clock(now)?;
        let deadline = now
            .checked_add(self.config.validation_timeout_us)
            .ok_or(Error::DeadlineOverflow)?;
        let r = self.active_mut(path)?;
        if r.probes.iter().flatten().any(|p| p.pending.is_some()) {
            return Err(Error::PendingProbe);
        }
        r.probes.fill(None);
        r.attempts = 0;
        r.next_probe_us = now;
        r.deadline_us = deadline;
        r.validating = true;
        Ok(())
    }
    pub fn retire(&mut self, path: PathIdentity) -> Result<(), Error> {
        self.record(path)?;
        self.slots[usize::from(path.slot)].record = None;
        Ok(())
    }
    fn clock(&mut self, now: u64) -> Result<(), Error> {
        if now < self.last_now {
            return Err(Error::ClockRegression);
        }
        self.last_now = now;
        Ok(())
    }
    fn record(&self, path: PathIdentity) -> Result<&Record<S, C>, Error> {
        self.slots
            .get(usize::from(path.slot))
            .and_then(|s| s.record.as_ref())
            .filter(|r| r.id == path)
            .ok_or(Error::StalePath)
    }
    fn active(&self, path: PathIdentity) -> Result<&Record<S, C>, Error> {
        let r = self.record(path)?;
        if r.failed {
            Err(Error::PathFailed)
        } else {
            Ok(r)
        }
    }
    fn active_mut(&mut self, path: PathIdentity) -> Result<&mut Record<S, C>, Error> {
        let r = self
            .slots
            .get_mut(usize::from(path.slot))
            .and_then(|s| s.record.as_mut())
            .filter(|r| r.id == path)
            .ok_or(Error::StalePath)?;
        if r.failed {
            Err(Error::PathFailed)
        } else {
            Ok(r)
        }
    }
}
fn probe_delay(config: Config, attempts: usize) -> Result<u64, Error> {
    1u64.checked_shl(attempts as u32)
        .and_then(|n| n.checked_mul(config.probe_interval_us))
        .ok_or(Error::DeadlineOverflow)
}
fn size(bytes: u64) -> Result<(), Error> {
    if bytes == 0 || bytes > MINIMUM_MTU {
        Err(Error::InvalidDatagramSize)
    } else {
        Ok(())
    }
}
fn expansion<const S: usize>(budget: &PathBudget<S>, bytes: u64) -> Result<(), Error> {
    size(bytes)?;
    if bytes < MINIMUM_MTU && budget.available_bytes() >= MINIMUM_MTU {
        return Err(Error::ExpansionRequired);
    }
    Ok(())
}
fn control_index<const S: usize, const C: usize>(
    r: &Record<S, C>,
    tx: Transmit,
) -> Result<usize, Error> {
    match tx.content {
        Content::Data => Ok(0),
        Content::Probe { serial, data } => r
            .probes
            .iter()
            .position(|v| {
                v.is_some_and(|v| {
                    v.serial == serial && v.data == data && v.pending == Some(tx.reservation)
                })
            })
            .ok_or(Error::InvalidDescriptor),
        Content::Response { serial, data } => r
            .responses
            .iter()
            .position(|v| {
                v.is_some_and(|v| {
                    v.serial == serial && v.data == data && v.pending == Some(tx.reservation)
                })
            })
            .ok_or(Error::InvalidDescriptor),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::{
        net::{IpAddr, Ipv4Addr},
        num::NonZeroU32,
    };
    const CONFIG: Config = Config {
        probe_interval_us: 100,
        validation_timeout_us: 300,
        max_attempts: 3,
    };
    fn address(port: u16) -> Address {
        Address {
            local: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
            remote: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        }
    }
    #[derive(Default)]
    struct Random {
        value: u64,
        fail: bool,
        stuck: bool,
    }
    impl RngCore for Random {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn next_u64(&mut self) -> u64 {
            if !self.stuck {
                self.value += 1;
            }
            self.value
        }
        fn fill_bytes(&mut self, out: &mut [u8]) {
            self.try_fill_bytes(out).unwrap();
        }
        fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
            if self.fail {
                return Err(rand_core::Error::from(NonZeroU32::new(1).unwrap()));
            }
            for chunk in out.chunks_mut(8) {
                let bytes = self.next_u64().to_be_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
            Ok(())
        }
    }
    impl CryptoRng for Random {}
    fn challenge(tx: Transmit) -> [u8; 8] {
        match tx.control() {
            Some(Control::Challenge(v)) => v,
            _ => panic!(),
        }
    }

    #[test]
    fn unvalidated_paths_have_independent_actual_three_times_budgets() {
        let mut slots = [const { PathSlot::<3, 3>::empty() }; 2];
        let mut p = Paths::new(&mut slots, 7, CONFIG).unwrap();
        let a = p
            .insert(address(1), InitialValidation::Unvalidated, 0)
            .unwrap();
        let b = p
            .insert(address(2), InitialValidation::Unvalidated, 0)
            .unwrap();
        p.received(a, 100).unwrap();
        assert_eq!(
            p.reserve_datagram(b, 1),
            Err(Error::Accounting(AccountingError::AmplificationLimited))
        );
        let tx = p.reserve_datagram(a, 200).unwrap();
        let second = p.reserve_datagram(a, 100).unwrap();
        assert_eq!(
            p.reserve_datagram(a, 1),
            Err(Error::Accounting(AccountingError::AmplificationLimited))
        );
        p.adapter_rejected(second).unwrap();
        p.adapter_accepted(tx, 1).unwrap();
        assert_eq!(p.snapshot(a).unwrap().sent, 200);
        assert_eq!(p.snapshot(a).unwrap().reserved, 0);
        assert_eq!(
            p.reserve_datagram(a, 101),
            Err(Error::Accounting(AccountingError::AmplificationLimited))
        );
        assert_eq!(
            p.adapter_accepted(tx, 2),
            Err(Error::Accounting(AccountingError::InvalidReservation))
        );
    }
    #[test]
    fn rejected_probe_is_not_validation_evidence_and_does_not_spend_attempt() {
        let mut slots = [PathSlot::<2, 3>::empty()];
        let mut p = Paths::new(&mut slots, 1, CONFIG).unwrap();
        let a = p
            .insert(address(1), InitialValidation::Unvalidated, 0)
            .unwrap();
        p.received(a, 400).unwrap();
        let tx = p.reserve_probe(a, 1200, 0, &mut Random::default()).unwrap();
        assert_eq!(p.response(challenge(tx), 0).unwrap(), None);
        p.adapter_rejected(tx).unwrap();
        assert_eq!(p.response(challenge(tx), 0).unwrap(), None);
        assert_eq!(p.snapshot(a).unwrap().attempts, 0);
        assert_eq!(p.snapshot(a).unwrap().reserved, 0);
    }
    #[test]
    fn cross_path_response_validates_only_the_original_target_once() {
        let mut slots = [const { PathSlot::<2, 3>::empty() }; 2];
        let mut p = Paths::new(&mut slots, 1, CONFIG).unwrap();
        let a = p
            .insert(address(1), InitialValidation::Unvalidated, 0)
            .unwrap();
        let b = p
            .insert(address(2), InitialValidation::Unvalidated, 0)
            .unwrap();
        p.received(a, 400).unwrap();
        let tx = p.reserve_probe(a, 1200, 0, &mut Random::default()).unwrap();
        p.adapter_accepted(tx, 0).unwrap();
        // The authenticated response may have arrived on B. RFC9000 §8.2.3
        // still validates A; there is intentionally no arrival-path argument.
        let validated = p.response(challenge(tx), 1).unwrap().unwrap();
        assert_eq!(validated.path, a);
        assert_eq!(validated.address, address(1));
        assert!(validated.mtu_validated);
        assert!(!p.snapshot(b).unwrap().address_validated);
        assert_eq!(p.response(challenge(tx), 2).unwrap(), None);
        assert_eq!(p.response([42; 8], 2).unwrap(), None);
    }
    #[test]
    fn short_probe_only_validates_address_then_requires_fresh_expanded_probe() {
        let mut slots = [PathSlot::<2, 3>::empty()];
        let mut p = Paths::new(&mut slots, 1, CONFIG).unwrap();
        let a = p
            .insert(address(1), InitialValidation::Unvalidated, 0)
            .unwrap();
        p.received(a, 100).unwrap();
        let mut rng = Random::default();
        let short = p.reserve_probe(a, 300, 0, &mut rng).unwrap();
        p.adapter_accepted(short, 0).unwrap();
        let result = p.response(challenge(short), 1).unwrap().unwrap();
        assert!(!result.mtu_validated);
        assert!(p.snapshot(a).unwrap().address_validated);
        assert_eq!(
            p.reserve_probe(a, 300, 1, &mut rng),
            Err(Error::ExpansionRequired)
        );
        let expanded = p.reserve_probe(a, 1200, 1, &mut rng).unwrap();
        assert_ne!(challenge(short), challenge(expanded));
        p.adapter_accepted(expanded, 1).unwrap();
        assert!(
            p.response(challenge(expanded), 2)
                .unwrap()
                .unwrap()
                .mtu_validated
        );
        assert_eq!(
            p.reserve_probe(a, 1200, 2, &mut rng),
            Err(Error::AlreadyValidated)
        );
    }
    #[test]
    fn probe_expansion_is_required_whenever_budget_allows() {
        let mut slots = [PathSlot::<2, 3>::empty()];
        let mut p = Paths::new(&mut slots, 1, CONFIG).unwrap();
        let a = p
            .insert(address(1), InitialValidation::Unvalidated, 0)
            .unwrap();
        p.received(a, 400).unwrap();
        let mut rng = Random::default();
        assert_eq!(
            p.reserve_probe(a, 1199, 0, &mut rng),
            Err(Error::ExpansionRequired)
        );
        assert_eq!(
            p.reserve_probe(a, 1201, 0, &mut rng),
            Err(Error::InvalidDatagramSize)
        );
        assert_eq!(p.reserve_datagram(a, 0), Err(Error::InvalidDatagramSize));
    }
    #[test]
    fn retry_schedule_freshness_and_attempt_limit_are_bounded() {
        let mut slots = [PathSlot::<2, 3>::empty()];
        let mut p = Paths::new(
            &mut slots,
            1,
            Config {
                validation_timeout_us: 500,
                ..CONFIG
            },
        )
        .unwrap();
        let a = p
            .insert(address(1), InitialValidation::AddressValidated, 0)
            .unwrap();
        let mut rng = Random::default();
        let first = p.reserve_probe(a, 1200, 0, &mut rng).unwrap();
        assert_eq!(
            p.reserve_probe(a, 1200, 0, &mut rng),
            Err(Error::PendingProbe)
        );
        p.adapter_accepted(first, 0).unwrap();
        assert_eq!(
            p.reserve_probe(a, 1200, 99, &mut rng),
            Err(Error::ProbeNotDue)
        );
        let second = p.reserve_probe(a, 1200, 100, &mut rng).unwrap();
        p.adapter_accepted(second, 100).unwrap();
        assert_eq!(
            p.reserve_probe(a, 1200, 299, &mut rng),
            Err(Error::ProbeNotDue)
        );
        let third = p.reserve_probe(a, 1200, 300, &mut rng).unwrap();
        p.adapter_accepted(third, 300).unwrap();
        assert_ne!(challenge(first), challenge(second));
        assert_ne!(challenge(second), challenge(third));
        assert_eq!(
            p.reserve_probe(a, 1200, 300, &mut rng),
            Err(Error::ProbeLimit)
        );
        // A delayed response to the first, still-live attempt is sufficient.
        assert!(p.response(challenge(first), 301).unwrap().is_some());
    }
    #[test]
    fn expired_and_forged_responses_cannot_create_validation() {
        let mut slots = [PathSlot::<2, 3>::empty()];
        let mut p = Paths::new(&mut slots, 1, CONFIG).unwrap();
        let a = p
            .insert(address(1), InitialValidation::Unvalidated, 0)
            .unwrap();
        p.received(a, 400).unwrap();
        let tx = p.reserve_probe(a, 1200, 0, &mut Random::default()).unwrap();
        p.adapter_accepted(tx, 0).unwrap();
        let mut forged = challenge(tx);
        forged[0] ^= 1;
        assert_eq!(p.response(forged, 299).unwrap(), None);
        assert_eq!(p.response(challenge(tx), 300).unwrap(), None);
        assert_eq!(p.expire(300).unwrap(), Some(a));
        assert_eq!(p.expire(300).unwrap(), None);
        assert!(p.snapshot(a).unwrap().failed);
        assert!(!p.snapshot(a).unwrap().address_validated);
        assert_eq!(p.reserve_datagram(a, 1), Err(Error::PathFailed));
    }
    #[test]
    fn failure_keeps_alternative_valid_path_and_credit_independent() {
        let mut slots = [const { PathSlot::<2, 3>::empty() }; 2];
        let mut p = Paths::new(&mut slots, 1, CONFIG).unwrap();
        let old = p
            .insert(address(1), InitialValidation::AddressAndMtuValidated, 0)
            .unwrap();
        let new = p
            .insert(address(2), InitialValidation::Unvalidated, 0)
            .unwrap();
        assert_eq!(p.expire(300).unwrap(), Some(new));
        assert_eq!(p.expire(300).unwrap(), None);
        let tx = p.reserve_datagram(old, 1200).unwrap();
        p.adapter_accepted(tx, 300).unwrap();
    }
    #[test]
    fn response_queue_routes_to_receipt_path_and_commits_once() {
        let mut slots = [const { PathSlot::<2, 3>::empty() }; 2];
        let mut p = Paths::new(&mut slots, 1, CONFIG).unwrap();
        let a = p
            .insert(address(1), InitialValidation::Unvalidated, 0)
            .unwrap();
        let b = p
            .insert(address(2), InitialValidation::AddressAndMtuValidated, 0)
            .unwrap();
        p.received(a, 400).unwrap();
        let h = p.queue_response(a, [7; 8]).unwrap();
        assert_eq!(p.pending_response(a).unwrap(), Some(h));
        assert_eq!(p.reserve_response(h, 100), Err(Error::ExpansionRequired));
        let tx = p.reserve_response(h, 1200).unwrap();
        assert_eq!(tx.path(), a);
        assert_eq!(tx.control(), Some(Control::Response([7; 8])));
        assert_eq!(p.pending_response(a).unwrap(), None);
        assert_eq!(p.pending_response(b).unwrap(), None);
        p.adapter_rejected(tx).unwrap();
        assert_eq!(p.pending_response(a).unwrap(), Some(h));
        let tx = p.reserve_response(h, 1200).unwrap();
        p.adapter_accepted(tx, 1).unwrap();
        assert_eq!(p.reserve_response(h, 1), Err(Error::InvalidDescriptor));
        assert_eq!(p.adapter_accepted(tx, 1), Err(Error::InvalidDescriptor));
        assert_eq!(p.snapshot(a).unwrap().sent, 1200);
    }
    #[test]
    fn constrained_response_may_be_short_but_never_exceeds_credit() {
        let mut slots = [PathSlot::<2, 3>::empty()];
        let mut p = Paths::new(&mut slots, 1, CONFIG).unwrap();
        let a = p
            .insert(address(1), InitialValidation::Unvalidated, 0)
            .unwrap();
        p.received(a, 100).unwrap();
        let h = p.queue_response(a, [7; 8]).unwrap();
        assert_eq!(
            p.reserve_response(h, 301),
            Err(Error::Accounting(AccountingError::AmplificationLimited))
        );
        let tx = p.reserve_response(h, 300).unwrap();
        p.adapter_accepted(tx, 0).unwrap();
        assert_eq!(p.snapshot(a).unwrap().sent, 300);
    }
    #[test]
    fn path_storage_and_response_storage_exhaustion_are_explicit() {
        let mut slots = [PathSlot::<2, 3>::empty()];
        let mut p = Paths::new(&mut slots, 1, CONFIG).unwrap();
        let a = p
            .insert(address(1), InitialValidation::Unvalidated, 0)
            .unwrap();
        assert_eq!(
            p.insert(address(1), InitialValidation::Unvalidated, 0),
            Err(Error::DuplicatePath)
        );
        assert_eq!(
            p.insert(address(2), InitialValidation::Unvalidated, 0),
            Err(Error::Capacity)
        );
        for n in 0..3 {
            p.queue_response(a, [n; 8]).unwrap();
        }
        assert_eq!(p.queue_response(a, [8; 8]), Err(Error::Capacity));
    }
    #[test]
    fn reused_slot_and_new_connection_reject_stale_descriptors_and_responses() {
        let mut slots = [PathSlot::<2, 3>::empty()];
        let mut p = Paths::new(&mut slots, 1, CONFIG).unwrap();
        let old = p
            .insert(address(1), InitialValidation::AddressValidated, 0)
            .unwrap();
        let tx = p
            .reserve_probe(old, 1200, 0, &mut Random::default())
            .unwrap();
        p.adapter_accepted(tx, 0).unwrap();
        let data = p.reserve_datagram(old, 100).unwrap();
        p.retire(old).unwrap();
        let new = p
            .insert(address(1), InitialValidation::AddressValidated, 0)
            .unwrap();
        assert_ne!(old, new);
        assert_eq!(p.adapter_accepted(data, 0), Err(Error::StalePath));
        assert_eq!(p.response(challenge(tx), 0).unwrap(), None);
        p.retire(new).unwrap();
        let mut p = Paths::new(&mut slots, 2, CONFIG).unwrap();
        let newer = p
            .insert(address(1), InitialValidation::AddressValidated, 0)
            .unwrap();
        assert_eq!(p.adapter_rejected(data), Err(Error::StalePath));
        assert_ne!(newer.path_generation, old.path_generation);
    }
    #[test]
    fn entropy_failure_and_repeated_entropy_leave_reservations_unchanged() {
        let mut slots = [const { PathSlot::<2, 3>::empty() }; 2];
        let mut p = Paths::new(&mut slots, 1, CONFIG).unwrap();
        let a = p
            .insert(address(1), InitialValidation::AddressValidated, 0)
            .unwrap();
        let b = p
            .insert(address(2), InitialValidation::AddressValidated, 0)
            .unwrap();
        let mut failing = Random {
            fail: true,
            ..Random::default()
        };
        assert_eq!(
            p.reserve_probe(a, 1200, 0, &mut failing),
            Err(Error::Entropy)
        );
        assert_eq!(p.snapshot(a).unwrap().reserved, 0);
        let mut repeated = Random {
            stuck: true,
            ..Random::default()
        };
        let tx = p.reserve_probe(a, 1200, 0, &mut repeated).unwrap();
        p.adapter_accepted(tx, 0).unwrap();
        assert_eq!(
            p.reserve_probe(b, 1200, 0, &mut repeated),
            Err(Error::ChallengeCollision)
        );
        assert_eq!(p.snapshot(b).unwrap().reserved, 0);
    }
    #[test]
    fn success_invalidates_other_outstanding_challenges() {
        let mut slots = [PathSlot::<3, 3>::empty()];
        let mut p = Paths::new(&mut slots, 1, CONFIG).unwrap();
        let a = p
            .insert(address(1), InitialValidation::AddressValidated, 0)
            .unwrap();
        let mut rng = Random::default();
        let first = p.reserve_probe(a, 1200, 0, &mut rng).unwrap();
        p.adapter_accepted(first, 0).unwrap();
        let pending = p.reserve_probe(a, 1200, 100, &mut rng).unwrap();
        assert!(p.response(challenge(first), 100).unwrap().is_some());
        assert_eq!(p.snapshot(a).unwrap().reserved, 0);
        assert_eq!(
            p.adapter_accepted(pending, 100),
            Err(Error::InvalidDescriptor)
        );
        assert_eq!(p.response(challenge(pending), 100).unwrap(), None);
    }
    #[test]
    fn invalid_config_clock_and_counter_boundaries_fail_closed() {
        let mut slots = [PathSlot::<1, 3>::empty()];
        assert!(matches!(
            Paths::new(
                &mut slots,
                1,
                Config {
                    validation_timeout_us: 299,
                    ..CONFIG
                }
            ),
            Err(Error::InvalidConfig)
        ));
        let mut p = Paths::new(&mut slots, 1, CONFIG).unwrap();
        assert_eq!(
            p.insert(address(1), InitialValidation::Unvalidated, u64::MAX),
            Err(Error::DeadlineOverflow)
        );
        assert_eq!(
            p.insert(address(1), InitialValidation::Unvalidated, 0),
            Err(Error::ClockRegression)
        );
        let mut slots = [PathSlot::<1, 3>::empty()];
        slots[0].epoch = u64::MAX;
        let mut p = Paths::new(&mut slots, 1, CONFIG).unwrap();
        assert_eq!(
            p.insert(address(1), InitialValidation::Unvalidated, 0),
            Err(Error::GenerationExhausted)
        );
    }
}
