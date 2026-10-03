//! Bounded migration selection policy, separate from packet authentication.
//!
//! The endpoint calls `packet` only after authenticating a fresh 1-RTT packet,
//! checking its active destination CID, and classifying every frame. It must
//! honor every returned validation/reprobe action and reserve a legal peer CID
//! before transmitting on the selected address. This policy never authenticates
//! an address merely because a packet arrived there. One preferred candidate
//! and the last validated fallback are retained; no heap or sockets are used.
//!
//! A switch requires independent per-path amplification/recovery state. Old-path
//! sent packets must not update the new path's RTT/congestion/ECN validation.

use crate::path::{self, Address, PathIdentity, Paths};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Client,
    Server,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Path(path::Error),
    HandshakeUnconfirmed,
    ActiveMigrationDisabled,
    UnknownServerAddress,
    InvalidPreferredAddress,
    WrongRole,
    InvalidPacketNumber,
    NoViablePath,
}
impl From<path::Error> for Error {
    fn from(e: path::Error) -> Self {
        Self::Path(e)
    }
}

/// Borrowed preferred_address syntax. Parsing does not authenticate this value;
/// use only the current connection's verified server transport parameters.
pub struct PreferredAddress<'a> {
    pub ipv4: Option<SocketAddr>,
    pub ipv6: Option<SocketAddr>,
    pub connection_id: &'a [u8],
    pub reset_token: &'a [u8; 16],
}
impl<'a> PreferredAddress<'a> {
    pub fn parse(value: &'a [u8]) -> Result<Self, Error> {
        if value.len() < 42 {
            return Err(Error::InvalidPreferredAddress);
        }
        let n = usize::from(value[24]);
        if !(1..=20).contains(&n) || value.len() != 41 + n {
            return Err(Error::InvalidPreferredAddress);
        }
        let v4 = Ipv4Addr::new(value[0], value[1], value[2], value[3]);
        let p4 = u16::from_be_bytes([value[4], value[5]]);
        let v6 = Ipv6Addr::from(
            <[u8; 16]>::try_from(&value[6..22]).map_err(|_| Error::InvalidPreferredAddress)?,
        );
        let p6 = u16::from_be_bytes([value[22], value[23]]);
        Ok(Self {
            ipv4: (!v4.is_unspecified() && p4 != 0).then_some(SocketAddr::new(IpAddr::V4(v4), p4)),
            ipv6: (!v6.is_unspecified() && p6 != 0).then_some(SocketAddr::new(IpAddr::V6(v6), p6)),
            connection_id: &value[25..25 + n],
            reset_token: value[25 + n..]
                .try_into()
                .map_err(|_| Error::InvalidPreferredAddress)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Switch {
    pub previous: PathIdentity,
    pub active: PathIdentity,
    /// New/changed peer addresses must be challenged while 3x credit is enforced.
    pub validate_active: bool,
    /// RFC9000 §9.3.3 requires probing the old path on apparent peer migration.
    pub reprobe_previous: bool,
    /// This conservative policy resets even for a port-only change (permitted).
    pub reset_recovery: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    Unchanged,
    /// Silently ignore this address for migration; never generate a reset solely
    /// because it differs or because active migration was disabled.
    Discard,
    Validate(PathIdentity),
    Switched(Switch),
}
#[derive(Clone, Copy)]
struct PreferredCandidate {
    path: PathIdentity,
    packet_number: Option<u64>,
}

pub struct Migration {
    role: Role,
    original: Address,
    active: PathIdentity,
    last_validated: Option<PathIdentity>,
    confirmed: bool,
    peer_disabled_active_migration: bool,
    preferred_server: Option<SocketAddr>,
    preferred: Option<PreferredCandidate>,
    largest_non_probing: Option<u64>,
}
impl Migration {
    pub fn new<const S: usize, const C: usize>(
        role: Role,
        initial: PathIdentity,
        paths: &Paths<'_, S, C>,
    ) -> Result<Self, Error> {
        let state = paths.snapshot(initial)?;
        Ok(Self {
            role,
            original: state.address,
            active: initial,
            last_validated: (state.address_validated && state.mtu_validated && !state.failed)
                .then_some(initial),
            confirmed: false,
            peer_disabled_active_migration: false,
            preferred_server: None,
            preferred: None,
            largest_non_probing: None,
        })
    }
    /// Apply only after TLS peer parameters are authenticated. For a server,
    /// `preferred_server` is its own address advertised in this handshake; for
    /// a client it is one address selected from the verified server parameter.
    /// A resumed connection starts with a new policy and cannot inherit it.
    pub fn verified_parameters(
        &mut self,
        disable_active_migration: bool,
        preferred_server: Option<SocketAddr>,
    ) -> Result<(), Error> {
        if preferred_server.is_some_and(|a| a.port() == 0 || a.ip().is_unspecified()) {
            return Err(Error::InvalidPreferredAddress);
        }
        self.peer_disabled_active_migration = disable_active_migration;
        self.preferred_server = preferred_server;
        Ok(())
    }
    /// Call at actual TLS/QUIC handshake confirmation, not merely key availability.
    pub fn handshake_confirmed(&mut self) {
        self.confirmed = true;
    }
    pub fn largest_non_probing(&self) -> Option<u64> { self.largest_non_probing }
    pub fn active(&self) -> PathIdentity {
        self.active
    }
    pub fn fallback(&self) -> Option<PathIdentity> {
        self.last_validated
    }

    /// Client-initiated migration. The caller first obtains an unused peer CID
    /// appropriate for the new address, then carries out the returned action.
    /// Preferred-address cutover always waits for completed path/MTU validation.
    pub fn initiate_client<const S: usize, const C: usize>(
        &mut self,
        candidate: PathIdentity,
        preferred: bool,
        paths: &Paths<'_, S, C>,
    ) -> Result<Decision, Error> {
        if self.role != Role::Client {
            return Err(Error::WrongRole);
        }
        if !self.confirmed {
            return Err(Error::HandshakeUnconfirmed);
        }
        let state = paths.snapshot(candidate)?;
        if state.failed {
            return Err(Error::NoViablePath);
        }
        if preferred {
            if Some(state.address.remote) != self.preferred_server {
                return Err(Error::InvalidPreferredAddress);
            }
            self.preferred = Some(PreferredCandidate {
                path: candidate,
                packet_number: None,
            });
            if state.address_validated && state.mtu_validated {
                return self.validated(candidate, paths);
            }
            return Ok(Decision::Validate(candidate));
        }
        let current = paths.snapshot(self.active)?;
        if state.address.remote != current.address.remote {
            return Err(Error::UnknownServerAddress);
        }
        if self.peer_disabled_active_migration
            && state.address.local != current.address.local
            && state.address.remote == self.original.remote
        {
            return Err(Error::ActiveMigrationDisabled);
        }
        if candidate == self.active {
            return Ok(Decision::Unchanged);
        }
        self.select(candidate, false, paths)
    }

    /// Observe one authenticated, replay-checked 1-RTT packet. `non_probing` means
    /// it contains any frame other than PADDING, NEW_CONNECTION_ID,
    /// PATH_CHALLENGE or PATH_RESPONSE; use Frame::probing for the census.
    pub fn packet<const S: usize, const C: usize>(
        &mut self,
        path: PathIdentity,
        packet_number: u64,
        non_probing: bool,
        paths: &Paths<'_, S, C>,
    ) -> Result<Decision, Error> {
        if packet_number > crate::packet::MAX_VARINT {
            return Err(Error::InvalidPacketNumber);
        }
        let state = paths.snapshot(path)?;
        if state.failed {
            return Ok(Decision::Discard);
        }
        if self.role == Role::Client {
            let current = paths.snapshot(self.active)?;
            if state.address.remote != self.original.remote
                && state.address.remote != current.address.remote
                && !self.preferred.is_some_and(|p| p.path == path)
            {
                return Ok(Decision::Discard);
            }
        } else if state.address.local != self.original.local
            && Some(state.address.local) != self.preferred_server
        {
            return Ok(Decision::Discard);
        }
        if path != self.active && !self.confirmed {
            return Ok(Decision::Discard);
        }
        if !non_probing {
            return Ok(Decision::Unchanged);
        }
        if self.largest_non_probing.is_some_and(|n| packet_number <= n) {
            return Ok(Decision::Unchanged);
        }
        if self.role == Role::Server
            && paths.snapshot(self.active)?.address.local != self.original.local
            && state.address.local == self.original.local
        {
            // Once cut over to our preferred address, decline new old-address
            // traffic (§9.6.2); reordered old packets were handled above.
            return Ok(Decision::Discard);
        }
        self.largest_non_probing = Some(packet_number);
        if path == self.active || self.role == Role::Client {
            return Ok(Decision::Unchanged);
        }
        if state.address.local != self.original.local {
            self.preferred = Some(PreferredCandidate {
                path,
                packet_number: Some(packet_number),
            });
            if !state.address_validated || !state.mtu_validated {
                return Ok(Decision::Validate(path));
            }
        }
        // A server may accept an observed NAT rebinding even when migration was
        // disabled; treating a changed source as fatal enables spoofed closure.
        self.select(path, true, paths)
    }

    pub fn validated<const S: usize, const C: usize>(
        &mut self,
        path: PathIdentity,
        paths: &Paths<'_, S, C>,
    ) -> Result<Decision, Error> {
        let state = paths.snapshot(path)?;
        if state.failed || !state.address_validated || !state.mtu_validated {
            return Ok(Decision::Unchanged);
        }
        if path == self.active {
            self.last_validated = Some(path);
            return Ok(Decision::Unchanged);
        }
        if !self.confirmed {
            return Err(Error::HandshakeUnconfirmed);
        }
        if let Some(candidate) = self.preferred
            && candidate.path == path
        {
            if self.role == Role::Server && candidate.packet_number != self.largest_non_probing {
                return Ok(Decision::Unchanged);
            }
            self.preferred = None;
            return self.select(path, self.role == Role::Server, paths);
        }
        Ok(Decision::Unchanged)
    }
    /// On a failed apparent migration, revert to the still-live validated path.
    /// No viable fallback is an explicit signal for silent connection retirement.
    pub fn failed<const S: usize, const C: usize>(
        &mut self,
        path: PathIdentity,
        paths: &Paths<'_, S, C>,
    ) -> Result<Decision, Error> {
        if self.preferred.is_some_and(|p| p.path == path) {
            self.preferred = None;
        }
        if path != self.active {
            return Ok(Decision::Unchanged);
        }
        let fallback = self
            .last_validated
            .filter(|id| *id != path)
            .ok_or(Error::NoViablePath)?;
        let state = paths.snapshot(fallback).map_err(|_| Error::NoViablePath)?;
        if state.failed || !state.address_validated || !state.mtu_validated {
            return Err(Error::NoViablePath);
        }
        self.select(fallback, false, paths)
    }
    fn select<const S: usize, const C: usize>(
        &mut self,
        next: PathIdentity,
        reprobe_previous: bool,
        paths: &Paths<'_, S, C>,
    ) -> Result<Decision, Error> {
        let state = paths.snapshot(next)?;
        if state.failed {
            return Err(Error::NoViablePath);
        }
        let old = self.active;
        let validate_active = !state.address_validated || !state.mtu_validated;
        self.active = next;
        if !validate_active {
            self.last_validated = Some(next);
        }
        Ok(Decision::Switched(Switch {
            previous: old,
            active: next,
            validate_active,
            reprobe_previous,
            reset_recovery: true,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path::{Config, Control, InitialValidation, PathSlot};
    use rand_core::{CryptoRng, RngCore};
    const CONFIG: Config = Config {
        probe_interval_us: 100,
        validation_timeout_us: 300,
        max_attempts: 3,
    };
    fn addr(local: u16, remote: u16) -> Address {
        Address {
            local: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), local),
            remote: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), remote),
        }
    }
    fn setup(
        slots: &mut [PathSlot<2, 3>],
        role: Role,
    ) -> (Paths<'_, 2, 3>, Migration, PathIdentity) {
        let mut paths = Paths::new(slots, 99, CONFIG).unwrap();
        let initial = paths
            .insert(
                addr(443, 9000),
                InitialValidation::AddressAndMtuValidated,
                0,
            )
            .unwrap();
        let migration = Migration::new(role, initial, &paths).unwrap();
        (paths, migration, initial)
    }
    struct TestRandom(u64);
    impl RngCore for TestRandom {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn next_u64(&mut self) -> u64 {
            self.0 += 1;
            self.0
        }
        fn fill_bytes(&mut self, out: &mut [u8]) {
            for chunk in out.chunks_mut(8) {
                let b = self.next_u64().to_be_bytes();
                chunk.copy_from_slice(&b[..chunk.len()]);
            }
        }
        fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(out);
            Ok(())
        }
    }
    impl CryptoRng for TestRandom {}
    fn validate(paths: &mut Paths<'_, 2, 3>, path: PathIdentity) {
        paths.received(path, 400).unwrap();
        let tx = paths
            .reserve_probe(path, 1200, 0, &mut TestRandom(u64::from(path.slot)))
            .unwrap();
        let Some(Control::Challenge(data)) = tx.control() else {
            panic!()
        };
        paths.adapter_accepted(tx, 0).unwrap();
        assert!(paths.response(data, 0).unwrap().unwrap().mtu_validated);
    }
    #[test]
    fn highest_non_probing_packet_selects_server_rebinding_and_requests_both_probes() {
        let mut slots = [const { PathSlot::<2, 3>::empty() }; 3];
        let (mut p, mut m, old) = setup(&mut slots, Role::Server);
        m.handshake_confirmed();
        let new = p
            .insert(addr(443, 9001), InitialValidation::Unvalidated, 0)
            .unwrap();
        assert_eq!(m.packet(old, 10, true, &p).unwrap(), Decision::Unchanged);
        assert_eq!(m.packet(new, 11, false, &p).unwrap(), Decision::Unchanged);
        assert_eq!(m.active(), old);
        assert_eq!(m.packet(new, 9, true, &p).unwrap(), Decision::Unchanged);
        let Decision::Switched(s) = m.packet(new, 11, true, &p).unwrap() else {
            panic!()
        };
        assert!(s.validate_active && s.reprobe_previous && s.reset_recovery);
        assert_eq!(m.active(), new);
        assert_eq!(m.fallback(), Some(old));
        assert_eq!(m.packet(old, 10, true, &p).unwrap(), Decision::Unchanged);
        assert_eq!(m.active(), new);
        assert!(matches!(
            m.packet(old, 12, true, &p).unwrap(),
            Decision::Switched(_)
        ));
        assert_eq!(m.active(), old);
    }
    #[test]
    fn failed_spoofed_address_returns_to_live_validated_fallback() {
        let mut slots = [const { PathSlot::<2, 3>::empty() }; 2];
        let (mut p, mut m, old) = setup(&mut slots, Role::Server);
        m.handshake_confirmed();
        let new = p
            .insert(addr(443, 9001), InitialValidation::Unvalidated, 0)
            .unwrap();
        m.packet(new, 1, true, &p).unwrap();
        p.expire(300).unwrap();
        assert!(matches!(m.failed(new, &p).unwrap(), Decision::Switched(_)));
        assert_eq!(m.active(), old);
    }
    #[test]
    fn absent_or_retired_fallback_never_silently_selects_unvalidated_address() {
        let mut slots = [const { PathSlot::<2, 3>::empty() }; 2];
        let (mut p, mut m, old) = setup(&mut slots, Role::Server);
        m.handshake_confirmed();
        let new = p
            .insert(addr(443, 9001), InitialValidation::Unvalidated, 0)
            .unwrap();
        m.packet(new, 1, true, &p).unwrap();
        p.retire(old).unwrap();
        assert_eq!(m.failed(new, &p), Err(Error::NoViablePath));
    }
    #[test]
    fn client_preferred_waits_for_confirmed_handshake_and_real_challenge_validation() {
        let mut slots = [const { PathSlot::<2, 3>::empty() }; 2];
        let (mut p, mut m, old) = setup(&mut slots, Role::Client);
        let preferred = addr(443, 9001);
        m.verified_parameters(true, Some(preferred.remote)).unwrap();
        let new = p
            .insert(preferred, InitialValidation::Unvalidated, 0)
            .unwrap();
        assert_eq!(
            m.initiate_client(new, true, &p),
            Err(Error::HandshakeUnconfirmed)
        );
        m.handshake_confirmed();
        assert_eq!(
            m.initiate_client(new, true, &p).unwrap(),
            Decision::Validate(new)
        );
        assert_eq!(m.active(), old);
        assert_eq!(m.validated(new, &p).unwrap(), Decision::Unchanged);
        assert_eq!(m.active(), old);
        validate(&mut p, new);
        assert!(matches!(
            m.validated(new, &p).unwrap(),
            Decision::Switched(_)
        ));
        assert_eq!(m.active(), new);
    }
    #[test]
    fn preferred_failure_keeps_original_server_and_does_not_leak_across_connections() {
        let mut slots = [const { PathSlot::<2, 3>::empty() }; 2];
        let (mut p, mut m, old) = setup(&mut slots, Role::Client);
        m.handshake_confirmed();
        let new = p
            .insert(addr(443, 9001), InitialValidation::Unvalidated, 0)
            .unwrap();
        m.verified_parameters(false, Some(addr(443, 9001).remote))
            .unwrap();
        m.initiate_client(new, true, &p).unwrap();
        p.expire(300).unwrap();
        assert_eq!(m.failed(new, &p).unwrap(), Decision::Unchanged);
        assert_eq!(m.active(), old);
        let mut fresh = Migration::new(Role::Client, old, &p).unwrap();
        fresh.handshake_confirmed();
        assert_eq!(
            fresh.initiate_client(new, true, &p),
            Err(Error::NoViablePath)
        );
        assert_eq!(fresh.preferred_server, None);
    }
    #[test]
    fn server_preferred_needs_validation_and_current_highest_non_probing_packet() {
        let mut slots = [const { PathSlot::<2, 3>::empty() }; 2];
        let (mut p, mut m, old) = setup(&mut slots, Role::Server);
        m.handshake_confirmed();
        let target = addr(444, 9000);
        m.verified_parameters(false, Some(target.local)).unwrap();
        let new = p.insert(target, InitialValidation::Unvalidated, 0).unwrap();
        assert_eq!(m.packet(new, 10, false, &p).unwrap(), Decision::Unchanged);
        assert_eq!(
            m.packet(new, 11, true, &p).unwrap(),
            Decision::Validate(new)
        );
        assert_eq!(m.active(), old);
        m.packet(old, 12, true, &p).unwrap();
        validate(&mut p, new);
        assert_eq!(m.validated(new, &p).unwrap(), Decision::Unchanged);
        assert_eq!(m.active(), old);
        assert!(matches!(
            m.packet(new, 13, true, &p).unwrap(),
            Decision::Switched(_)
        ));
        assert_eq!(m.active(), new);
        assert_eq!(m.packet(old, 14, true, &p).unwrap(), Decision::Discard);
        assert_eq!(m.active(), new);
    }
    #[test]
    fn peer_disable_blocks_client_local_migration_but_server_can_validate_nat_rebinding() {
        let mut slots = [const { PathSlot::<2, 3>::empty() }; 3];
        let (mut p, mut client, old) = setup(&mut slots, Role::Client);
        client.handshake_confirmed();
        client.verified_parameters(true, None).unwrap();
        let local = p
            .insert(addr(444, 9000), InitialValidation::AddressValidated, 0)
            .unwrap();
        assert_eq!(
            client.initiate_client(local, false, &p),
            Err(Error::ActiveMigrationDisabled)
        );
        assert_eq!(client.active(), old);
        let mut server = Migration::new(Role::Server, old, &p).unwrap();
        server.handshake_confirmed();
        server.verified_parameters(true, None).unwrap();
        let peer = p
            .insert(addr(443, 9001), InitialValidation::Unvalidated, 0)
            .unwrap();
        assert!(matches!(
            server.packet(peer, 1, true, &p).unwrap(),
            Decision::Switched(_)
        ));
    }
    #[test]
    fn unknown_server_and_unconfigured_server_local_addresses_are_discarded() {
        let mut slots = [const { PathSlot::<2, 3>::empty() }; 3];
        let (mut p, mut client, old) = setup(&mut slots, Role::Client);
        client.handshake_confirmed();
        let unknown = p
            .insert(addr(443, 9999), InitialValidation::Unvalidated, 0)
            .unwrap();
        assert_eq!(
            client.packet(unknown, 1, true, &p).unwrap(),
            Decision::Discard
        );
        assert_eq!(
            client.initiate_client(unknown, false, &p),
            Err(Error::UnknownServerAddress)
        );
        let local = p
            .insert(addr(444, 9000), InitialValidation::Unvalidated, 0)
            .unwrap();
        let mut server = Migration::new(Role::Server, old, &p).unwrap();
        server.handshake_confirmed();
        assert_eq!(
            server.packet(local, 1, true, &p).unwrap(),
            Decision::Discard
        );
    }
    #[test]
    fn preconfirmation_peer_change_is_not_a_migration_and_probe_only_is_not_selection() {
        let mut slots = [const { PathSlot::<2, 3>::empty() }; 2];
        let (mut p, mut m, old) = setup(&mut slots, Role::Server);
        let new = p
            .insert(addr(443, 9001), InitialValidation::Unvalidated, 0)
            .unwrap();
        assert_eq!(m.packet(new, 1, true, &p).unwrap(), Decision::Discard);
        assert_eq!(m.active(), old);
        m.handshake_confirmed();
        assert_eq!(m.packet(new, 2, false, &p).unwrap(), Decision::Unchanged);
        assert_eq!(m.active(), old);
    }
    #[test]
    fn preferred_address_parser_preserves_borrowed_cid_token_and_rejects_truncation() {
        let mut bytes = [0u8; 49];
        bytes[..4].copy_from_slice(&[127, 0, 0, 1]);
        bytes[4..6].copy_from_slice(&443u16.to_be_bytes());
        bytes[24] = 8;
        bytes[25..33].fill(7);
        bytes[33..].fill(9);
        let p = PreferredAddress::parse(&bytes).unwrap();
        assert_eq!(p.ipv4, Some(addr(443, 443).remote));
        assert_eq!(p.ipv6, None);
        assert_eq!(p.connection_id, &[7; 8]);
        assert_eq!(p.reset_token, &[9; 16]);
        for n in 0..bytes.len() {
            assert!(PreferredAddress::parse(&bytes[..n]).is_err());
        }
        bytes[24] = 0;
        assert!(PreferredAddress::parse(&bytes).is_err());
        bytes[24] = 21;
        assert!(PreferredAddress::parse(&bytes).is_err());
    }
}
