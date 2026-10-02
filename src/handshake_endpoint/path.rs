//! Opt-in address-aware endpoint integration. The default endpoint keeps its
//! original single-path surface; configured resources are caller-owned.
use super::*;
use crate::driver;
use crate::{
    connection_id::{
        Cid, CidError, LocalCidHandle, LocalCidSlot, LocalCidTable, PeerCidHandle, PeerCidSlot,
        PeerCidTable, ResetToken,
    },
    migration::{Migration, Role},
    path::{Address, InitialValidation, PathSlot, Paths},
};
use core::net::SocketAddr;
use rand_core::{CryptoRng, RngCore};

pub const NETWORK_PATHS: usize = 2;
pub const LOCAL_CID_HISTORY: usize = 8;
pub const PEER_CID_HISTORY: usize = 16;
pub trait NetworkRandom: RngCore + CryptoRng {}
impl<T: RngCore + CryptoRng> NetworkRandom for T {}

#[derive(Clone, Copy, Debug)]
pub struct PreferredServer {
    pub address: SocketAddr,
    pub connection_id: Cid,
    pub reset_token: ResetToken,
}
#[derive(Clone, Copy, Debug)]
pub struct NetworkConfig {
    pub initial: Address,
    /// Must match the local active_connection_id_limit TP (default2).
    pub active_connection_id_limit: u64,
    /// Server-only, and must match the local authenticated transport parameter.
    pub initial_reset_token: Option<ResetToken>,
    /// Server-only, with the exact CID/token/address encoded in local TLS TPs.
    pub preferred_server: Option<PreferredServer>,
}
impl NetworkConfig {
    pub fn new(initial: Address) -> Self {
        Self {
            initial,
            active_connection_id_limit: 2,
            initial_reset_token: None,
            preferred_server: None,
        }
    }
}
pub struct NetworkResources<'s> {
    pub paths: &'s mut [PathSlot<1, 3>; NETWORK_PATHS],
    pub local_cids: &'s mut [LocalCidSlot; LOCAL_CID_HISTORY],
    pub peer_cids: &'s mut [PeerCidSlot<2>; PEER_CID_HISTORY],
    /// Server preferred-address profiles retain the exact outgoing TLS EE
    /// prefix until accepted. Must fit that entire message; otherwise None.
    pub preferred_advertisement: Option<&'s mut [u8]>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkError {
    InvalidConfig,
    Capacity,
    Entropy,
    Cid(CidError),
    Path(crate::path::Error),
    Migration(crate::migration::Error),
}
impl From<CidError> for NetworkError {
    fn from(e: CidError) -> Self {
        Self::Cid(e)
    }
}
impl From<crate::path::Error> for NetworkError {
    fn from(e: crate::path::Error) -> Self {
        Self::Path(e)
    }
}
impl From<crate::migration::Error> for NetworkError {
    fn from(e: crate::migration::Error) -> Self {
        Self::Migration(e)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Reservation {
    Legacy(accounting::PathReservation),
    Managed(crate::path::Transmit),
}
struct Timing {
    now: u64,
    pto: u64,
}
pub(super) struct Owner<'s> {
    legacy: accounting::PathBudget<1>,
    legacy_id: PathIdentity,
    network: Option<Network<'s>>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkReceiveContext {
    pub path: PathIdentity,
    pub destination: Cid,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CidControl {
    Advertise(LocalCidHandle),
    Retire(PeerCidHandle),
}
#[derive(Clone, Copy)]
struct ControlRecord {
    kind: CidControl,
    ready: bool,
    acknowledged: bool,
    sent: [Option<u64>; 4],
}
#[derive(Clone, Copy)]
enum Plan {
    Cid { slot: usize, path: PathIdentity },
    Challenge(PathIdentity),
    Response(crate::path::ResponseHandle),
}
struct Network<'s> {
    config: NetworkConfig,
    local_cid_len: usize,
    paths: Paths<'s, 1, 3>,
    local: LocalCidTable<'s>,
    local_initial: LocalCidHandle,
    preferred_local: Option<LocalCidHandle>,
    preferred_advertisement: Option<&'s mut [u8]>,
    ee_committed: usize,
    ee_pending: Option<usize>,
    ee_complete: bool,
    peer_slots: Option<&'s mut [PeerCidSlot<2>; PEER_CID_HISTORY]>,
    peer: Option<PeerCidTable<'s, 2>>,
    /// A real zero-length peer CID has no entry in the nonzero CID table.
    /// It remains bound to the original exact address tuple for its lifetime.
    zero_peer: bool,
    zero_peer_token: Option<ResetToken>,
    zero_peer_used: bool,
    peer_selected: Option<PeerCidHandle>,
    bootstrap_used: Option<(Cid, Address)>,
    peers_by_path: [Option<PeerCidHandle>; 2],
    inbound_cids: [Option<LocalCidHandle>; 2],
    ack_history: [Option<(PathIdentity, [Option<u64>; 3])>; 2],
    preferred_peer: Option<(Address, PeerCidHandle)>,
    preferred_started: bool,
    migration: Migration,
    rng: &'s mut dyn NetworkRandom,
    original: PathIdentity,
    selected: PathIdentity,
    ingress: Option<Address>,
    ingress_path: Option<PathIdentity>,
    credited: bool,
    datagram_bytes: u64,
    pending_driver: Option<driver::PathReservationTicket>,
    controls: [Option<ControlRecord>; 24],
    pending_control: Option<Plan>,
    prepared: Option<crate::path::Transmit>,
    padded_total: Option<usize>,
    abandoned: Option<PathIdentity>,
}
impl<'s> Owner<'s> {
    pub(super) fn new(path: u64, generation: u64) -> Self {
        Self {
            legacy: accounting::PathBudget::new(path, generation),
            legacy_id: PathIdentity {
                connection_generation: generation,
                slot: 0,
                path_generation: 0,
            },
            network: None,
        }
    }
    fn enable(
        &mut self,
        config: NetworkConfig,
        resources: NetworkResources<'s>,
        rng: &'s mut dyn NetworkRandom,
        side: Side,
        local: &[u8],
        timing: Timing,
    ) -> Result<(), NetworkError> {
        let Timing { now, pto } = timing;
        if self.network.is_some()
            || config.initial.local.port() == 0
            || config.initial.remote.port() == 0
            || config.initial.local.ip().is_unspecified()
            || config.initial.remote.ip().is_unspecified()
            || !(2..=4).contains(&config.active_connection_id_limit)
            || (side == Side::Client
                && (config.initial_reset_token.is_some() || config.preferred_server.is_some()))
        {
            return Err(NetworkError::InvalidConfig);
        }
        if config.preferred_server.is_some()
            && resources
                .preferred_advertisement
                .as_ref()
                .is_none_or(|b| b.len() < 4)
        {
            return Err(NetworkError::InvalidConfig);
        }
        let cid = Cid::new(local)?;
        if config.preferred_server.is_some_and(|p| {
            p.connection_id.as_bytes().len() != local.len()
                || p.address.port() == 0
                || p.address.ip().is_unspecified()
        }) {
            return Err(NetworkError::InvalidConfig);
        }
        let mut local = LocalCidTable::new(
            0,
            self.legacy_id.connection_generation,
            resources.local_cids,
            2,
        )?;
        let local_initial = local.issue_initial(cid, config.initial_reset_token)?.handle;
        let preferred_local = if let Some(p) = config.preferred_server {
            Some(
                local
                    .issue_preferred(p.connection_id, p.reset_token)?
                    .handle,
            )
        } else {
            None
        };
        let mut paths = Paths::new(
            resources.paths,
            self.legacy_id.connection_generation,
            crate::path::Config {
                probe_interval_us: pto.max(1),
                validation_timeout_us: pto.max(1).checked_mul(3).ok_or(NetworkError::Capacity)?,
                max_attempts: 3,
            },
        )?;
        let original = paths.insert(
            config.initial,
            if side == Side::Client {
                InitialValidation::ClientUnvalidated
            } else if self.legacy.is_validated() {
                InitialValidation::AddressValidated
            } else {
                InitialValidation::Unvalidated
            },
            now,
        )?;
        let migration = Migration::new(
            if side == Side::Client {
                Role::Client
            } else {
                Role::Server
            },
            original,
            &paths,
        )?;
        self.network = Some(Network {
            config,
            local_cid_len: cid.as_bytes().len(),
            paths,
            local,
            local_initial,
            preferred_local,
            preferred_advertisement: resources.preferred_advertisement,
            ee_committed: 0,
            ee_pending: None,
            ee_complete: false,
            peer_slots: Some(resources.peer_cids),
            peer: None,
            zero_peer: false,
            zero_peer_token: None,
            zero_peer_used: false,
            peer_selected: None,
            bootstrap_used: None,
            peers_by_path: [None; 2],
            inbound_cids: [None; 2],
            ack_history: [None; 2],
            preferred_peer: None,
            preferred_started: false,
            migration,
            rng,
            original,
            selected: original,
            ingress: None,
            ingress_path: None,
            credited: false,
            datagram_bytes: 0,
            pending_driver: None,
            controls: [None; 24],
            pending_control: None,
            prepared: None,
            padded_total: None,
            abandoned: None,
        });
        Ok(())
    }
    pub(super) fn identity(&self) -> PathIdentity {
        self.network.as_ref().map_or(self.legacy_id, |n| n.selected)
    }
    pub(super) fn address(&self) -> Option<Address> {
        self.network
            .as_ref()
            .and_then(|n| n.paths.snapshot(n.selected).ok().map(|s| s.address))
    }
    pub(super) fn reserve(
        &mut self,
        bytes: u64,
    ) -> Result<Reservation, accounting::AccountingError> {
        match &mut self.network {
            Some(n) => {
                if let Some(prepared) = n.prepared.take() {
                    if prepared.bytes() != bytes {
                        return Err(accounting::AccountingError::InvalidReservation);
                    }
                    return Ok(Reservation::Managed(prepared));
                }
                n.paths
                    .reserve_datagram(n.selected, bytes)
                    .map(Reservation::Managed)
                    .map_err(budget_error)
            }
            None => self.legacy.reserve(bytes).map(Reservation::Legacy),
        }
    }
    pub(super) fn cancel(&mut self, r: Reservation) -> Result<(), accounting::AccountingError> {
        match r {
            Reservation::Legacy(r) => self.legacy.cancel(r),
            Reservation::Managed(r) => self
                .network
                .as_mut()
                .ok_or(accounting::AccountingError::InvalidReservation)?
                .paths
                .adapter_rejected(r)
                .map_err(budget_error),
        }
    }
    pub(super) fn adapter_accepted(
        &mut self,
        r: Reservation,
        now: u64,
    ) -> Result<(), accounting::AccountingError> {
        match r {
            Reservation::Legacy(r) => self.legacy.adapter_accepted(r),
            Reservation::Managed(r) => self
                .network
                .as_mut()
                .ok_or(accounting::AccountingError::InvalidReservation)?
                .paths
                .adapter_accepted(r, now)
                .map_err(budget_error),
        }
    }
    pub(super) fn record_received(
        &mut self,
        bytes: u64,
    ) -> Result<(), accounting::AccountingError> {
        if let Some(n) = &mut self.network {
            n.datagram_bytes = bytes;
            Ok(())
        } else {
            self.legacy.record_received(bytes)
        }
    }
    pub(super) fn mark_validated(&mut self) -> Result<(), accounting::AccountingError> {
        self.legacy.mark_validated()?;
        if let Some(n) = &mut self.network {
            n.paths
                .handshake_validated(n.original)
                .map_err(budget_error)?;
        }
        Ok(())
    }
    pub(super) fn available_bytes(&self) -> u64 {
        self.network.as_ref().map_or_else(
            || self.legacy.available_bytes(),
            |n| {
                n.paths
                    .snapshot(n.selected)
                    .map_or(0, |s| s.available_bytes)
            },
        )
    }
    pub(super) fn retire(&mut self) {
        self.legacy.retire();
        if let Some(n) = &mut self.network {
            n.paths.retire_all();
        }
        self.network.take();
    }
}
impl Drop for Owner<'_> {
    fn drop(&mut self) {
        self.retire();
    }
}
fn budget_error(error: crate::path::Error) -> accounting::AccountingError {
    match error {
        crate::path::Error::Accounting(e) => e,
        crate::path::Error::Capacity => accounting::AccountingError::Full,
        crate::path::Error::StalePath => accounting::AccountingError::InvalidReservation,
        _ => accounting::AccountingError::InvalidState,
    }
}
impl<'r, 's, T: Provider, K: InitialKeyProtection> HandshakeEndpoint<'r, 's, T, K> {
    /// Configure exact socket identities and bounded resources before any I/O.
    /// Local CID length remains fixed. Local token/preferred values must be the
    /// same values supplied to the TLS provider's transport parameters.
    pub fn enable_network(
        &mut self,
        config: NetworkConfig,
        resources: NetworkResources<'s>,
        rng: &'s mut dyn NetworkRandom,
    ) -> Result<(), Error> {
        if self.io_started || self.pending.is_some() || self.retired {
            return Err(Error::InvalidConfig);
        }
        self.path
            .enable(
                config,
                resources,
                rng,
                self.side,
                self.local.bytes(),
                Timing {
                    now: self.now,
                    pto: self.key_pto()?,
                },
            )
            .map_err(Error::Network)?;
        self.ecn_tx = PathEcn::new(self.path.identity());
        Ok(())
    }
    pub(super) fn network_bytes_in_flight(&self) -> u64 {
        if self.path.managed() {
            self.sent.bytes_in_flight_on_path(self.path_identity())
        } else {
            self.sent.bytes_in_flight()
        }
    }
    pub fn issued_local_cids(&self) -> impl Iterator<Item = Cid> + '_ {
        self.path.network.iter().flat_map(|n| n.local.issued_ids())
    }
    /// Exact active tuple and validation evidence for adapter routing/diagnostics.
    pub fn network_path_state(&self) -> Option<(PathIdentity, crate::path::Snapshot)> {
        let n = self.path.network.as_ref()?;
        let id = n.migration.active();
        n.paths.snapshot(id).ok().map(|s| (id, s))
    }
    pub(super) fn transmit_address(&self) -> Option<Address> {
        self.path.address()
    }
    pub(super) fn bind_network_transmit(
        &mut self,
        ticket: TransmitTicket,
        reservation: Reservation,
    ) -> Result<(), Error> {
        let Reservation::Managed(path) = reservation else {
            return Ok(());
        };
        let n = self.path.network.as_mut().ok_or(Error::InvalidConfig)?;
        if n.pending_driver.is_some() {
            return Err(Error::Busy);
        }
        let grant = if self.remote.bytes().is_empty() {
            if n.peer.is_some()
                || n.peer_selected.is_some()
                || path.path() != n.original
                || n.paths
                    .snapshot(path.path())
                    .map_err(NetworkError::from)?
                    .address
                    != n.config.initial
            {
                return Err(Error::InvalidConfig);
            }
            self.driver
                .bind_zero_cid_path_transmit(ticket, path, n.original)?
        } else if let Some(peer) = n.peer_selected {
            let address = n
                .paths
                .snapshot(path.path())
                .map_err(NetworkError::from)?
                .address;
            n.peer
                .as_ref()
                .ok_or(Error::InvalidConfig)?
                .check_send(peer, address.local, address.remote)
                .map_err(NetworkError::from)?;
            self.driver.bind_path_transmit(ticket, path, peer)?
        } else {
            // Once authenticated peer CID state exists, exhaustion cannot fall
            // back to a raw handshake DCID or bypass address/CID ownership.
            if n.peer.is_some() {
                return Err(NetworkError::Capacity.into());
            }
            self.driver.bind_bootstrap_path_transmit(
                ticket,
                path,
                Cid::new(self.remote.bytes()).map_err(NetworkError::from)?,
            )?
        };
        n.pending_driver = Some(grant);
        Ok(())
    }
}

impl Owner<'_> {
    pub(super) fn reservation_identity(&self, r: Reservation) -> PathIdentity {
        match r {
            Reservation::Legacy(_) => self.legacy_id,
            Reservation::Managed(r) => r.path(),
        }
    }
    pub(super) fn begin_ingress(&mut self, address: Address) -> Result<(), NetworkError> {
        let n = self.network.as_mut().ok_or(NetworkError::InvalidConfig)?;
        n.ingress = Some(address);
        n.ingress_path = n.paths.find(address);
        n.credited = false;
        n.datagram_bytes = 0;
        Ok(())
    }
    pub(super) fn end_ingress(&mut self) {
        if let Some(n) = &mut self.network {
            n.ingress = None;
            n.ingress_path = None;
            n.credited = false;
            n.datagram_bytes = 0;
        }
    }
    pub(super) fn active_identity(&self) -> PathIdentity {
        self.network
            .as_ref()
            .map_or(self.legacy_id, |n| n.migration.active())
    }
    pub(super) fn matches_active(&self, path: Option<PathIdentity>) -> bool {
        self.network.is_none() || path == Some(self.active_identity())
    }
    pub(super) fn observe_ack(&mut self, packet: &accounting::SentPacket) {
        let Some(n) = &mut self.network else {
            return;
        };
        let Some(path) = packet.path else {
            return;
        };
        // The table owner checks generation before attributing an ACK. A stale
        // slot number cannot populate its replacement's packet history.
        if n.paths.snapshot(path).is_err() {
            return;
        }
        let history = &mut n.ack_history[usize::from(path.slot)];
        if history.is_none_or(|(old, _)| old != path) {
            *history = Some((path, [None; 3]));
        }
        let values = &mut history.as_mut().expect("assigned above").1;
        let largest = &mut values[packet.packet.space as usize];
        *largest = Some(largest.map_or(packet.packet.value, |old| old.max(packet.packet.value)));
    }
    pub(super) fn largest_ack_on_path(
        &self,
        packet: &accounting::SentPacket,
        legacy: Option<u64>,
    ) -> Option<u64> {
        let Some(n) = &self.network else {
            return legacy;
        };
        let path = packet.path?;
        n.ack_history
            .get(usize::from(path.slot))
            .and_then(|h| *h)
            .filter(|(identity, _)| *identity == path)
            .and_then(|(_, h)| h[packet.packet.space as usize])
    }
    pub(super) fn ensure_probe_pto(&mut self, pto: u64) -> Result<(), NetworkError> {
        if let Some(n) = &mut self.network {
            n.paths.ensure_probe_timeout(pto)?;
        }
        Ok(())
    }
    pub(super) fn managed(&self) -> bool {
        self.network.is_some()
    }
    pub(super) fn ready_ingress(&self) -> bool {
        self.network.as_ref().is_none_or(|n| n.ingress.is_some())
    }
}
impl<'r, 's, T: Provider, K: InitialKeyProtection> HandshakeEndpoint<'r, 's, T, K> {
    /// Exact receive tuple from an unconnected adapter. A previously unseen
    /// address does not itself create a path or authenticate its ownership.
    pub(super) async fn receive_from_impl<A: ApplicationHandler>(
        &mut self,
        datagram: &[u8],
        scratch: &mut [u8],
        address: Address,
        codepoint: Option<Codepoint>,
        handler: &mut A,
    ) -> Result<Received, Error> {
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        self.path.begin_ingress(address)?;
        if self.path.network.as_ref().is_some_and(|n| {
            n.peer
                .as_ref()
                .is_some_and(|p| p.detect_stateless_reset(datagram, address.remote))
                || (n.zero_peer
                    && n.zero_peer_used
                    && address == n.config.initial
                    && datagram.len() >= 21
                    && n.zero_peer_token.is_some_and(|token| {
                        let mut tail = [0; 16];
                        tail.copy_from_slice(&datagram[datagram.len() - 16..]);
                        token == ResetToken::new(tail)
                    }))
        }) {
            self.enter_draining().await?;
            self.path.end_ingress();
            return Ok(Received {
                authenticated: 0,
                discarded: 1,
            });
        }
        if !self
            .path
            .source_allowed(self.side, self.handshake_confirmed)
        {
            self.path.end_ingress();
            return Ok(Received {
                authenticated: 0,
                discarded: 1,
            });
        }
        let result = self
            .receive_with_metadata(
                datagram,
                scratch,
                ecn::Metadata {
                    path: self.path_identity(),
                    codepoint,
                },
                handler,
            )
            .await;
        self.path.end_ingress();
        result
    }
    pub(super) fn begin_network_result(
        &mut self,
        pending: &Pending,
        accepted: bool,
    ) -> Result<Option<driver::PathAcceptedTicket>, Error> {
        let Reservation::Managed(path) = pending.path else {
            return Ok(None);
        };
        let n = self.path.network.as_mut().ok_or(Error::InvalidConfig)?;
        let grant = n.pending_driver.ok_or(Error::InvalidConfig)?;
        if grant.transmit() != pending.ticket || grant.path() != path.path() {
            return Err(Error::InvalidConfig);
        }
        let result = self.driver.begin_path_result(grant, accepted)?;
        if !accepted {
            n.pending_driver = None;
        }
        Ok(result)
    }
    pub(super) fn finish_network_result(
        &mut self,
        pending: &Pending,
        accepted: Option<driver::PathAcceptedTicket>,
    ) -> Result<(), Error> {
        let Some(accepted) = accepted else {
            if let Some(n) = &mut self.path.network {
                n.pending_control = None;
                n.padded_total = None;
                n.prepared = None;
                n.ee_pending = None;
                n.selected = n.migration.active();
                n.peer_selected = n.peers_by_path[usize::from(n.selected.slot)];
            }
            return Ok(());
        };
        let n = self.path.network.as_mut().ok_or(Error::InvalidConfig)?;
        let grant = accepted.reservation();
        let address = n
            .paths
            .snapshot(grant.path())
            .map_err(NetworkError::from)?
            .address;
        if let Some(peer) = grant.peer_cid() {
            n.peer
                .as_mut()
                .ok_or(Error::InvalidConfig)?
                .record_sent(peer, address.local, address.remote)
                .map_err(NetworkError::from)?;
        } else if let Some(cid) = grant.bootstrap_cid() {
            n.bootstrap_used = Some((cid, address));
        } else {
            n.zero_peer_used = true;
        }

        if pending.output.level != Level::OneRtt || pending.output.early {
            let advertisement = self
                .driver
                .begin_cid_advertisement(accepted, n.local_initial)?;
            n.local
                .mark_advertised(advertisement.local_cid())
                .map_err(NetworkError::from)?;
            self.driver.finish_cid_advertisement(advertisement)?;
        }
        if let Some(end) = n.ee_pending.take() {
            n.ee_committed = n.ee_committed.max(end);
            let evidence = n
                .preferred_advertisement
                .as_ref()
                .ok_or(Error::InvalidConfig)?;
            if n.ee_committed >= 4 {
                let total = 4
                    + usize::from(evidence[1]) * 65536
                    + usize::from(evidence[2]) * 256
                    + usize::from(evidence[3]);
                if n.ee_committed == total && !n.ee_complete {
                    let extensions =
                        crate::tls_wire::parse_encrypted_extensions_early(&evidence[..total])
                            .map_err(|_| Error::InvalidConfig)?;
                    let parameters =
                        Parameters::parse(extensions.params, Peer::Server, &mut [0; 64])?;
                    let preferred = crate::migration::PreferredAddress::parse(
                        parameters.get(13).ok_or(Error::InvalidConfig)?,
                    )
                    .map_err(NetworkError::from)?;
                    let expected = n.config.preferred_server.ok_or(Error::InvalidConfig)?;
                    if preferred.connection_id != expected.connection_id.as_bytes()
                        || preferred.reset_token != expected.reset_token.as_bytes()
                        || ![preferred.ipv4, preferred.ipv6].contains(&Some(expected.address))
                    {
                        return Err(Error::InvalidConfig);
                    }
                    let cid = n.preferred_local.ok_or(Error::InvalidConfig)?;
                    let advertisement = self.driver.begin_cid_advertisement(accepted, cid)?;
                    n.local.mark_advertised(cid).map_err(NetworkError::from)?;
                    self.driver.finish_cid_advertisement(advertisement)?;
                    n.ee_complete = true;
                }
            }
        }
        if let Some(Plan::Cid { slot, .. }) = n.pending_control {
            let record = n.controls[slot].as_mut().ok_or(Error::InvalidConfig)?;
            if let CidControl::Advertise(cid) = record.kind {
                let advertisement = self.driver.begin_cid_advertisement(accepted, cid)?;
                n.local.mark_advertised(cid).map_err(NetworkError::from)?;
                self.driver.finish_cid_advertisement(advertisement)?;
            }
            let index = record
                .sent
                .iter()
                .position(Option::is_none)
                .unwrap_or_else(|| {
                    record
                        .sent
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, n)| **n)
                        .map_or(0, |(i, _)| i)
                });
            record.sent[index] = Some(pending.output.packet_number.value);
            record.ready = false;
        }
        self.driver.finish_path_result(accepted)?;
        n.pending_driver = None;
        n.pending_control = None;
        n.padded_total = None;
        n.prepared = None;
        n.selected = n.migration.active();
        n.peer_selected = n.peers_by_path[usize::from(n.selected.slot)];
        Ok(())
    }
    pub(super) fn transmit_ecn(&mut self) -> Result<Codepoint, Error> {
        if self.ecn_enabled && self.path_identity() == self.ecn_tx.identity() {
            Ok(self.ecn_tx.marking(self.path_identity(), self.now)?)
        } else {
            Ok(Codepoint::NotEct)
        }
    }
}

impl Owner<'_> {
    pub(super) fn install_parameters(
        &mut self,
        p: &crate::parameters::Parameters<'_>,
        remote: &[u8],
        side: Side,
    ) -> Result<(), NetworkError> {
        let Some(n) = &mut self.network else {
            return Ok(());
        };
        if n.peer.is_some() || n.zero_peer {
            return Ok(());
        }
        n.local.set_peer_limit_verified(
            p.get_integer(14, 2)
                .map_err(|_| NetworkError::InvalidConfig)?,
        )?;
        if remote.is_empty() {
            // RFC9000§5.1.1/18.2: the zero-length initial peer CID stays zero;
            // neither NEW_CONNECTION_ID nor a preferred address may replace it.
            if p.get(13).is_some() {
                return Err(NetworkError::InvalidConfig);
            }
            n.zero_peer_token = p
                .get(2)
                .map(|token| {
                    token
                        .try_into()
                        .map(ResetToken::new)
                        .map_err(|_| NetworkError::InvalidConfig)
                })
                .transpose()?;
            n.paths.handshake_validated(n.original)?;
            n.migration.validated(n.original, &n.paths)?;
            n.migration.verified_parameters(p.get(12).is_some(), None)?;
            n.zero_peer = true;
            return Ok(());
        }
        let slots = n.peer_slots.take().ok_or(NetworkError::InvalidConfig)?;
        let mut peer = PeerCidTable::new(
            1,
            n.original.connection_generation,
            slots,
            n.config.active_connection_id_limit,
            Cid::new(remote)?,
        )?;
        if let Some(token) = p.get(2) {
            peer.install_initial_token_verified(ResetToken::new(
                token.try_into().map_err(|_| NetworkError::InvalidConfig)?,
            ))?;
        }
        let mut preferred_address = n.config.preferred_server.map(|p| p.address);
        if side == Side::Client
            && let Some(value) = p.get(13)
        {
            let value = crate::migration::PreferredAddress::parse(value)?;
            let cid = peer
                .accept_preferred_verified(
                    Cid::new(value.connection_id)?,
                    ResetToken::new(*value.reset_token),
                )?
                .handle;
            let remote = if n.config.initial.local.is_ipv4() {
                value.ipv4
            } else {
                value.ipv6
            };
            if let Some(remote) = remote {
                n.preferred_peer = Some((
                    Address {
                        local: n.config.initial.local,
                        remote,
                    },
                    cid,
                ));
                preferred_address = Some(remote);
            }
        }
        let initial = peer.initial()?.handle;
        if let Some((cid, address)) = n.bootstrap_used
            && cid.as_bytes() == remote
        {
            peer.record_sent(initial, address.local, address.remote)?;
        }
        n.peer_selected = Some(initial);
        n.peers_by_path[usize::from(n.original.slot)] = Some(initial);
        n.paths.handshake_validated(n.original)?;
        n.migration.validated(n.original, &n.paths)?;
        n.migration
            .verified_parameters(p.get(12).is_some(), preferred_address)?;
        n.peer = Some(peer);
        Ok(())
    }
    pub(super) fn accepts_destination(&self, cid: &[u8]) -> bool {
        self.network
            .as_ref()
            .is_some_and(|n| n.local.route(cid).is_some())
    }
    pub(super) fn source_allowed(&self, side: Side, confirmed: bool) -> bool {
        let Some(n) = &self.network else {
            return true;
        };
        let Some(address) = n.ingress else {
            return false;
        };
        if address == n.config.initial {
            return true;
        }
        if n.zero_peer || !confirmed {
            return false;
        }
        match side {
            Side::Client => {
                n.paths.find(address).is_some()
                    && (address.remote == n.config.initial.remote
                        || n.preferred_peer.is_some_and(|p| p.0 == address))
            }
            Side::Server => {
                address.local == n.config.initial.local
                    || n.config
                        .preferred_server
                        .is_some_and(|p| p.address == address.local)
            }
        }
    }
    pub(super) fn selected_destination(&self) -> Option<Cid> {
        let n = self.network.as_ref()?;
        let peer = n.peer.as_ref()?;
        peer.get(n.peers_by_path[usize::from(n.selected.slot)]?)
            .ok()
            .map(|p| p.cid)
    }
}

impl Network<'_> {
    fn queue(&mut self, kind: CidControl) -> Result<(), NetworkError> {
        if self.controls.iter().flatten().any(|r| r.kind == kind) {
            return Ok(());
        }
        let index = self
            .controls
            .iter()
            .position(Option::is_none)
            .ok_or(NetworkError::Capacity)?;
        self.controls[index] = Some(ControlRecord {
            kind,
            ready: true,
            acknowledged: false,
            sent: [None; 4],
        });
        Ok(())
    }
    fn queue_retirements(&mut self) -> Result<(), NetworkError> {
        let mut handles = [None; PEER_CID_HISTORY];
        if let Some(peer) = &self.peer {
            for (i, h) in peer.pending_retirements().enumerate() {
                handles[i] = Some(h);
            }
        }
        for h in handles.into_iter().flatten() {
            self.queue(CidControl::Retire(h))?;
        }
        Ok(())
    }
    fn bind_peer(
        &mut self,
        path: PathIdentity,
        rebind_from: Option<PathIdentity>,
    ) -> Result<bool, NetworkError> {
        let address = self.paths.snapshot(path)?.address;
        if self.zero_peer {
            return Ok(path == self.original && address == self.config.initial);
        }
        let peer = self.peer.as_mut().ok_or(NetworkError::InvalidConfig)?;
        let i = usize::from(path.slot);
        if let Some(h) = self.peers_by_path[i]
            && peer.get(h).is_ok()
            && peer.check_send(h, address.local, address.remote).is_ok()
        {
            return Ok(true);
        }
        if let Some(old) = rebind_from {
            let j = usize::from(old.slot);
            if self.inbound_cids[i].is_some()
                && self.inbound_cids[i] == self.inbound_cids[j]
                && let Some(h) = self.peers_by_path[j]
                && peer.get(h).is_ok()
                && self.paths.snapshot(old)?.address.local == address.local
            {
                match peer.authorize_remote_rebinding_authenticated(
                    h,
                    address.local,
                    address.remote,
                ) {
                    Ok(()) => {
                        self.peers_by_path[i] = Some(h);
                        return Ok(true);
                    }
                    Err(CidError::AddressHistoryFull | CidError::UnusedConnectionId) => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
        let available = peer
            .active()
            .find(|cid| {
                !self
                    .peers_by_path
                    .iter()
                    .enumerate()
                    .any(|(j, h)| j != i && *h == Some(cid.handle))
                    && peer
                        .check_send(cid.handle, address.local, address.remote)
                        .is_ok()
            })
            .map(|cid| cid.handle);
        self.peers_by_path[i] = available;
        Ok(available.is_some())
    }
}
impl Owner<'_> {
    pub(super) fn admit_packet(
        &mut self,
        destination: &[u8],
        pn: u64,
        non_probing: bool,
        bytes: u64,
        now: u64,
    ) -> Result<NetworkReceiveContext, NetworkError> {
        let cid = Cid::new(destination)?;
        let Some(n) = &mut self.network else {
            return Ok(NetworkReceiveContext {
                path: self.legacy_id,
                destination: cid,
            });
        };
        let address = n.ingress.ok_or(NetworkError::InvalidConfig)?;
        if n.zero_peer && address != n.config.initial {
            return Err(NetworkError::InvalidConfig);
        }
        let path = if let Some(path) = n.paths.find(address) {
            path
        } else {
            let active = n.migration.active();
            let fallback = n.migration.fallback();
            let mut reclaim = n
                .paths
                .identities()
                .find(|p| *p != active && Some(*p) != fallback);
            if reclaim.is_none()
                && non_probing
                && n.migration.largest_non_probing().is_none_or(|old| pn > old)
                && !n.paths.snapshot(active)?.address_validated
                && fallback != Some(active)
            {
                n.migration.failed(active, &n.paths)?;
                reclaim = Some(active);
            }
            if let Some(old) = reclaim {
                if n.abandoned.is_some() {
                    return Err(NetworkError::Capacity);
                }
                n.abandoned = Some(old);
                n.paths.retire(old)?;
                let peer = n.peers_by_path[usize::from(old.slot)].take();
                if let Some(peer) = peer
                    && !n.peers_by_path.contains(&Some(peer))
                {
                    n.peer
                        .as_mut()
                        .ok_or(NetworkError::InvalidConfig)?
                        .retire(peer)?;
                    n.queue_retirements()?;
                }
                n.ack_history[usize::from(old.slot)] = None;
                n.inbound_cids[usize::from(old.slot)] = None;
            }
            n.paths
                .insert(address, InitialValidation::Unvalidated, now)?
        };
        n.ingress_path = Some(path);
        if !n.credited {
            n.paths.received(path, bytes)?;
            n.credited = true;
        }
        if let Some(cid) = n.local.route(destination) {
            n.inbound_cids[usize::from(path.slot)] = Some(cid);
        }
        Ok(NetworkReceiveContext {
            path,
            destination: cid,
        })
    }
}
impl<'r, 's, T: Provider, K: InitialKeyProtection> HandshakeEndpoint<'r, 's, T, K> {
    /// Retain this exact context with deferred 0-RTT controls. No active-path or
    /// later-CID substitution is valid when those controls are released.
    pub(super) fn network_receive_context(
        &self,
        destination: &[u8],
    ) -> Result<NetworkReceiveContext, Error> {
        let path = if let Some(n) = &self.path.network {
            n.ingress_path.ok_or(Error::InvalidConfig)?
        } else {
            self.path.legacy_id
        };
        Ok(NetworkReceiveContext {
            path,
            destination: Cid::new(destination).map_err(NetworkError::from)?,
        })
    }
    /// Packet-wide, read-only early admission. `held` is the FIFO of retained
    /// controls, and `remembered_limit` is authenticated ticket state. Simulation
    /// includes the live CID history and every queued NEW frame, so independently
    /// legal frames cannot collectively exceed the old active CID limit. This
    /// call must precede control-store commit and packet Seen insertion.
    pub(super) fn preflight_early_network_controls<'a>(
        &self,
        held: impl IntoIterator<
            Item = Result<(Frame<'a>, NetworkReceiveContext), crate::early_control::Error>,
        >,
        payload: &[u8],
        context: NetworkReceiveContext,
        remembered_limit: u64,
    ) -> Result<(), Error> {
        if let Some(n) = &self.path.network {
            n.paths.snapshot(context.path).map_err(NetworkError::from)?;
        } else if context.path != self.path.legacy_id {
            return Err(Error::InvalidConfig);
        }
        let mut slots = [PeerCidSlot::<2>::EMPTY; PEER_CID_HISTORY];
        let mut peer = if self.remote.bytes().is_empty() {
            None
        } else {
            Some(
                if let Some(n) = &self.path.network {
                    n.paths.snapshot(context.path).map_err(NetworkError::from)?;
                    if let Some(peer) = &n.peer {
                        peer.admission_copy(&mut slots, remembered_limit)
                    } else {
                        PeerCidTable::new(
                            1,
                            self.generation(),
                            &mut slots,
                            remembered_limit,
                            Cid::new(self.remote.bytes()).map_err(NetworkError::from)?,
                        )
                    }
                } else {
                    if context.path != self.path.legacy_id {
                        return Err(Error::InvalidConfig);
                    }
                    PeerCidTable::new(
                        1,
                        self.generation(),
                        &mut slots,
                        remembered_limit,
                        Cid::new(self.remote.bytes()).map_err(NetworkError::from)?,
                    )
                }
                .map_err(NetworkError::from)?,
            )
        };
        let validate = |peer: &mut Option<PeerCidTable<'_, 2>>,
                        frame: Frame<'_>,
                        context: NetworkReceiveContext|
         -> Result<(), Error> {
            match frame {
                Frame::NewConnectionId {
                    sequence,
                    retire_prior_to,
                    id,
                    reset_token,
                } => {
                    peer.as_mut()
                        .ok_or(Error::ProtocolViolation)?
                        .accept_new_authenticated(
                            sequence,
                            retire_prior_to,
                            Cid::new(id).map_err(NetworkError::from)?,
                            ResetToken::new(*reset_token),
                        )
                        .map_err(NetworkError::from)?;
                }
                Frame::RetireConnectionId { sequence } => {
                    if let Some(n) = &self.path.network {
                        n.local
                            .check_retirement(sequence, context.destination.as_bytes())
                            .map_err(NetworkError::from)?;
                    } else if sequence != 0 {
                        return Err(NetworkError::Cid(CidError::UnknownSequence).into());
                    } else if context.destination.as_bytes() == self.local.bytes() {
                        return Err(NetworkError::Cid(CidError::CurrentDestinationCid).into());
                    }
                }
                Frame::PathChallenge { .. } => {}
                Frame::PathResponse { .. } => return Err(Error::ProtocolViolation),
                _ => {}
            }
            Ok(())
        };
        for prior in held {
            let (frame, context) = prior.map_err(Error::EarlyControl)?;
            validate(&mut peer, frame, context)?;
        }
        for frame in FrameIter::new(payload, EncryptionLevel::ZeroRtt, ParseLimits::default())? {
            validate(&mut peer, frame?, context)?;
        }
        Ok(())
    }
    /// Shared ordinary/deferred-control dispatch. The ordinary receive ticket
    /// must be obtained from authenticated packet or checked Finished-release
    /// authority. A true result means the frame was handled internally.
    pub(super) fn process_network_frame(
        &mut self,
        receive: crate::driver::ReceiveTicket,
        frame: Frame<'_>,
        context: NetworkReceiveContext,
    ) -> Result<bool, Error> {
        self.process_network_frame_from(NetworkAuthority::Ordinary(receive), frame, context)
    }
    pub(super) fn process_early_network_frame(
        &mut self,
        release: crate::driver::EarlyControlReleaseTicket,
        frame: Frame<'_>,
        context: NetworkReceiveContext,
    ) -> Result<bool, Error> {
        self.process_network_frame_from(NetworkAuthority::Early(release), frame, context)
    }
    fn process_network_frame_from(
        &mut self,
        authority: NetworkAuthority,
        frame: Frame<'_>,
        context: NetworkReceiveContext,
    ) -> Result<bool, Error> {
        let Some(n) = &mut self.path.network else {
            return Ok(false);
        };
        n.paths.snapshot(context.path).map_err(NetworkError::from)?;
        match frame {
            Frame::NewConnectionId {
                sequence,
                retire_prior_to,
                id,
                reset_token,
            } => {
                if n.zero_peer {
                    return Err(Error::ProtocolViolation);
                }
                let ticket = authority.install(&mut self.driver, sequence)?;
                n.peer
                    .as_mut()
                    .ok_or(Error::InvalidConfig)?
                    .accept_new_authenticated(
                        sequence,
                        retire_prior_to,
                        Cid::new(id).map_err(NetworkError::from)?,
                        ResetToken::new(*reset_token),
                    )
                    .map_err(NetworkError::from)?;
                n.queue_retirements()?;
                let active = n.migration.active();
                if !n.bind_peer(active, None)? {
                    return Err(NetworkError::Capacity.into());
                }
                n.selected = active;
                n.peer_selected = n.peers_by_path[usize::from(active.slot)];
                self.driver.finish_cid_install(ticket)?;
            }
            Frame::RetireConnectionId { sequence } => {
                let ticket = authority.retire(&mut self.driver, sequence)?;
                n.local
                    .retire_authenticated(sequence, context.destination.as_bytes())
                    .map_err(NetworkError::from)?;
                self.driver.finish_cid_retirement(ticket)?;
            }
            Frame::PathChallenge { data } => {
                let ticket = authority.path(
                    &mut self.driver,
                    context.path,
                    driver::PathEffect::ChallengeReceived,
                )?;
                n.paths
                    .queue_response(context.path, *data)
                    .map_err(NetworkError::from)?;
                self.driver.finish_path_effect(ticket)?;
            }
            Frame::PathResponse { data } => {
                let ticket = authority.path(
                    &mut self.driver,
                    context.path,
                    driver::PathEffect::ResponseValidated,
                )?;
                if let Some(validated) = n
                    .paths
                    .response(*data, self.now)
                    .map_err(NetworkError::from)?
                {
                    let decision = n
                        .migration
                        .validated(validated.path, &n.paths)
                        .map_err(NetworkError::from)?;
                    self.apply_network_decision(decision)?;
                }
                self.driver.finish_path_effect(ticket)?;
            }
            _ => return Ok(false),
        }
        Ok(true)
    }
    pub(super) fn network_packet_processed(
        &mut self,
        receive: crate::driver::ReceiveTicket,
        context: NetworkReceiveContext,
        pn: u64,
        non_probing: bool,
    ) -> Result<(), Error> {
        let Some(n) = &mut self.path.network else {
            return Ok(());
        };
        if self.handshake_confirmed {
            n.migration.handshake_confirmed();
        }
        let old = n.migration.active();
        n.bind_peer(context.path, Some(old))?;
        let ticket = self.driver.begin_path_effect(
            receive,
            context.path,
            driver::PathEffect::ActivePathChanged,
        )?;
        let decision = n
            .migration
            .packet(context.path, pn, non_probing, &n.paths)
            .map_err(NetworkError::from)?;
        self.apply_network_decision(decision)?;
        self.driver.finish_path_effect(ticket)?;
        self.start_preferred_path(receive)?;
        Ok(())
    }
    fn start_preferred_path(&mut self, receive: driver::ReceiveTicket) -> Result<(), Error> {
        if self.side != Side::Client || !self.handshake_confirmed {
            return Ok(());
        }
        let Some(n) = &mut self.path.network else {
            return Ok(());
        };
        if n.preferred_started {
            return Ok(());
        }
        let Some((address, cid)) = n.preferred_peer else {
            return Ok(());
        };
        let candidate = n
            .paths
            .insert(address, InitialValidation::ClientUnvalidated, self.now)
            .map_err(NetworkError::from)?;
        n.peers_by_path[usize::from(candidate.slot)] = Some(cid);
        let ticket = self.driver.begin_path_effect(
            receive,
            candidate,
            driver::PathEffect::ActivePathChanged,
        )?;
        n.migration.handshake_confirmed();
        let decision = n
            .migration
            .initiate_client(candidate, true, &n.paths)
            .map_err(NetworkError::from)?;
        n.preferred_started = true;
        self.apply_network_decision(decision)?;
        self.driver.finish_path_effect(ticket)?;
        Ok(())
    }
    fn apply_network_decision(
        &mut self,
        decision: crate::migration::Decision,
    ) -> Result<(), Error> {
        let Some(n) = &mut self.path.network else {
            return Ok(());
        };
        match decision {
            crate::migration::Decision::Switched(s) => {
                n.selected = s.active;
                n.peer_selected = n.peers_by_path[usize::from(s.active.slot)];
                if s.reprobe_previous {
                    n.paths
                        .restart_validation(s.previous, self.now)
                        .map_err(NetworkError::from)?;
                }
                if s.reset_recovery {
                    self.cc = recovery::NewReno::new(1200)?;
                    self.rtt = RttEstimator::new(recovery::INITIAL_RTT_US)?;
                    self.recovery = RecoveryTimer::new();
                    self.loss_times = [None; 3];
                }
            }
            crate::migration::Decision::Validate(path) => {
                n.bind_peer(path, Some(n.migration.active()))?;
            }
            _ => {}
        }
        Ok(())
    }
}

impl<'r, 's, T: Provider, K: InitialKeyProtection> HandshakeEndpoint<'r, 's, T, K> {
    /// Early data cannot establish a migrated path. Check before early key use;
    /// an unexpected source is a silent discard, not a connection error.
    pub(super) fn early_path_allowed(&self) -> bool {
        self.path
            .network
            .as_ref()
            .is_none_or(|n| n.ingress == Some(n.config.initial))
    }
    /// Call once after successful early AEAD, replay check and whole-payload
    /// admission. A coalesced UDP datagram earns credit only once if any packet
    /// was admitted. Failed AEAD or rejected controls do not call this helper.
    pub(super) fn on_authenticated_early_path(
        &mut self,
        destination: &[u8],
        packet_number: u64,
    ) -> Result<NetworkReceiveContext, Error> {
        if !self.early_path_allowed() {
            return Err(Error::InvalidConfig);
        }
        let bytes = self.path.network.as_ref().map_or(0, |n| n.datagram_bytes);
        Ok(self
            .path
            .admit_packet(destination, packet_number, true, bytes, self.now)?)
    }
}

impl Network<'_> {
    fn ensure_spare(&mut self) -> Result<(), NetworkError> {
        if !self.local.can_issue() {
            return Ok(());
        }
        let len = self.local_cid_len;
        for _ in 0..8 {
            let mut cid = [0u8; 20];
            let mut token = [0u8; 16];
            self.rng
                .try_fill_bytes(&mut cid[..len])
                .map_err(|_| NetworkError::Entropy)?;
            self.rng
                .try_fill_bytes(&mut token)
                .map_err(|_| NetworkError::Entropy)?;
            match self.local.issue(
                Cid::new(&cid[..len])?,
                ResetToken::new(token),
                self.local.retire_prior_to(),
            ) {
                Ok(cid) => {
                    self.queue(CidControl::Advertise(cid.handle))?;
                    return Ok(());
                }
                Err(CidError::ActiveLimit | CidError::HistoryFull) => return Ok(()),
                Err(CidError::ConnectionIdReused | CidError::ResetTokenReused) => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Err(NetworkError::Entropy)
    }
    fn next_plan(&mut self, now: u64) -> Result<Option<Plan>, NetworkError> {
        let mut ids = [None; 2];
        for (i, id) in self.paths.identities().enumerate() {
            ids[i] = Some(id);
        }
        for path in ids.into_iter().flatten() {
            if self.paths.snapshot(path)?.failed {
                continue;
            }
            if let Some(response) = self.paths.pending_response(path)?
                && self.bind_peer(path, Some(self.migration.active()))?
            {
                return Ok(Some(Plan::Response(response)));
            }
        }
        if self.bind_peer(self.migration.active(), None)? {
            for (slot, record) in self.controls.iter_mut().enumerate() {
                let Some(record) = record else {
                    continue;
                };
                if !record.ready || record.acknowledged {
                    continue;
                }
                if let CidControl::Advertise(h) = record.kind
                    && self.local.get(h).is_err()
                {
                    record.acknowledged = true;
                    continue;
                }
                return Ok(Some(Plan::Cid {
                    slot,
                    path: self.migration.active(),
                }));
            }
        }
        for path in ids.into_iter().flatten() {
            if self.paths.snapshot(path)?.failed {
                continue;
            }
            if self.paths.probe_deadline(path)?.is_some_and(|at| now >= at)
                && self.bind_peer(path, Some(self.migration.active()))?
            {
                return Ok(Some(Plan::Challenge(path)));
            }
        }
        Ok(None)
    }
}
impl Owner<'_> {
    pub(super) fn reset_staged_advertisement(&mut self) {
        if let Some(n) = &mut self.network {
            n.ee_pending = None;
        }
    }
    pub(super) fn stage_crypto_advertisement(
        &mut self,
        level: Level,
        offset: u64,
        data: &[u8],
    ) -> Result<(), NetworkError> {
        let Some(n) = &mut self.network else {
            return Ok(());
        };
        if level != Level::Handshake || n.preferred_local.is_none() || n.ee_complete {
            return Ok(());
        }
        let offset = usize::try_from(offset).map_err(|_| NetworkError::Capacity)?;
        if offset > n.ee_committed {
            return Err(NetworkError::InvalidConfig);
        }
        let buf = n
            .preferred_advertisement
            .as_mut()
            .ok_or(NetworkError::InvalidConfig)?;
        let mut total = if n.ee_committed >= 4 {
            4 + usize::from(buf[1]) * 65536 + usize::from(buf[2]) * 256 + usize::from(buf[3])
        } else {
            buf.len()
        };
        let end = offset
            .checked_add(data.len())
            .ok_or(NetworkError::Capacity)?
            .min(total);
        if end > buf.len() {
            return Err(NetworkError::Capacity);
        }
        buf[offset..end].copy_from_slice(&data[..end - offset]);
        if end >= 4 {
            if buf[0] != 8 {
                return Err(NetworkError::InvalidConfig);
            }
            total =
                4 + usize::from(buf[1]) * 65536 + usize::from(buf[2]) * 256 + usize::from(buf[3]);
            if total > buf.len() {
                return Err(NetworkError::Capacity);
            }
        }
        n.ee_pending = Some(end.min(total));
        Ok(())
    }
    pub(super) fn control_padding(&self) -> Option<usize> {
        self.network.as_ref().and_then(|n| n.padded_total)
    }
    pub(super) fn on_ack(&mut self, ranges: AckRanges<'_>) -> Result<(), NetworkError> {
        let Some(n) = &mut self.network else {
            return Ok(());
        };
        for record in n.controls.iter_mut().flatten() {
            if !record.acknowledged
                && record
                    .sent
                    .iter()
                    .flatten()
                    .any(|pn| ranges.iter().any(|r| r.smallest <= *pn && *pn <= r.largest))
            {
                record.acknowledged = true;
                record.ready = false;
                record.sent.fill(None);
                if let CidControl::Retire(h) = record.kind {
                    n.peer
                        .as_mut()
                        .ok_or(NetworkError::InvalidConfig)?
                        .acknowledge_retirement(h)?;
                }
            }
        }
        Ok(())
    }
    pub(super) fn on_lost(&mut self, packet: accounting::PacketNumber) {
        if packet.space != PacketNumberSpace::ApplicationData {
            return;
        }
        if let Some(n) = &mut self.network {
            for r in n.controls.iter_mut().flatten() {
                if !r.acknowledged && r.sent.contains(&Some(packet.value)) {
                    r.ready = true;
                    for pn in &mut r.sent {
                        if *pn == Some(packet.value) {
                            *pn = None;
                        }
                    }
                }
            }
        }
    }
    pub(super) fn on_pto(&mut self) {
        if let Some(n) = &mut self.network
            && let Some(r) = n
                .controls
                .iter_mut()
                .flatten()
                .find(|r| !r.acknowledged && r.sent.iter().any(Option::is_some))
        {
            r.ready = true;
        }
    }
}
impl<'r, 's, T: Provider, K: InitialKeyProtection> HandshakeEndpoint<'r, 's, T, K> {
    pub(super) async fn transmit_network_control(
        &mut self,
        out: &mut [u8],
    ) -> Result<Option<Transmit>, Error> {
        if !self.handshake_confirmed || self.tls.is_handshaking() {
            return Ok(None);
        }
        let Some(n) = &mut self.path.network else {
            return Ok(None);
        };
        n.migration.handshake_confirmed();
        n.ensure_spare()?;
        let Some(plan) = n.next_plan(self.now)? else {
            return Ok(None);
        };
        let target = match plan {
            Plan::Cid { path, .. } | Plan::Challenge(path) => path,
            Plan::Response(handle) => handle.path(),
        };
        n.selected = target;
        n.peer_selected = n.peers_by_path[usize::from(target.slot)];
        let peer_cid = if n.zero_peer {
            None
        } else {
            Some(
                n.peer
                    .as_ref()
                    .ok_or(Error::InvalidConfig)?
                    .get(n.peer_selected.ok_or(Error::InvalidConfig)?)
                    .map_err(NetworkError::from)?
                    .cid,
            )
        };
        let header = 1 + peer_cid.map_or(0, |cid| cid.as_bytes().len()) + 4 + 16;
        let mut encoded = [0u8; 96];
        let len = match plan {
            Plan::Cid { slot, .. } => match n.controls[slot].ok_or(Error::InvalidConfig)?.kind {
                CidControl::Advertise(h) => {
                    let cid = n.local.get(h).map_err(NetworkError::from)?;
                    packet::encode_frame(
                        &Frame::NewConnectionId {
                            sequence: cid.sequence,
                            retire_prior_to: cid.retire_prior_to,
                            id: cid.cid.as_bytes(),
                            reset_token: cid.token.ok_or(Error::InvalidConfig)?.as_bytes(),
                        },
                        &mut encoded,
                    )?
                }
                CidControl::Retire(h) => {
                    let sequence = n
                        .peer
                        .as_ref()
                        .ok_or(Error::InvalidConfig)?
                        .retirement_sequence(h, peer_cid.ok_or(Error::ProtocolViolation)?)
                        .map_err(NetworkError::from)?;
                    packet::encode_frame(&Frame::RetireConnectionId { sequence }, &mut encoded)?
                }
            },
            Plan::Challenge(_) | Plan::Response(_) => {
                let state = n.paths.snapshot(target).map_err(NetworkError::from)?;
                let available = state.available_bytes;
                let total = available.min(1200) as usize;
                if total < header + 9 {
                    n.selected = n.migration.active();
                    n.peer_selected = n.peers_by_path[usize::from(n.selected.slot)];
                    return Ok(None);
                }
                let reserved = match plan {
                    Plan::Challenge(path) => {
                        n.paths
                            .reserve_probe(path, total as u64, self.now, &mut n.rng)
                    }
                    Plan::Response(h) => n.paths.reserve_response(h, total as u64),
                    _ => unreachable!(),
                }
                .map_err(NetworkError::from)?;
                let len = match reserved.control().ok_or(Error::InvalidConfig)? {
                    crate::path::Control::Challenge(data) => {
                        packet::encode_frame(&Frame::PathChallenge { data: &data }, &mut encoded)?
                    }
                    crate::path::Control::Response(data) => {
                        packet::encode_frame(&Frame::PathResponse { data: &data }, &mut encoded)?
                    }
                };
                n.prepared = Some(reserved);
                n.padded_total = Some(total);
                len
            }
        };
        n.pending_control = Some(plan);
        let result = self
            .transmit_inner(out, None, Some((Level::OneRtt, &encoded[..len])))
            .await;
        if !matches!(result, Ok(Some(_)))
            && let Some(n) = &mut self.path.network
        {
            if let Some(prepared) = n.prepared.take() {
                n.paths
                    .adapter_rejected(prepared)
                    .map_err(NetworkError::from)?;
            }
            n.pending_control = None;
            n.padded_total = None;
            n.selected = n.migration.active();
            n.peer_selected = n.peers_by_path[usize::from(n.selected.slot)];
        }
        result
    }
}

#[derive(Clone, Copy)]
enum NetworkAuthority {
    Ordinary(crate::driver::ReceiveTicket),
    Early(crate::driver::EarlyControlReleaseTicket),
}
impl NetworkAuthority {
    fn install(
        self,
        driver: &mut Driver<'_>,
        sequence: u64,
    ) -> Result<crate::driver::CidInstallTicket, DriverError> {
        match self {
            Self::Ordinary(r) => driver.begin_cid_install(r, sequence),
            Self::Early(r) => driver.begin_early_cid_install(r, sequence),
        }
    }
    fn retire(
        self,
        driver: &mut Driver<'_>,
        sequence: u64,
    ) -> Result<crate::driver::CidRetirementTicket, DriverError> {
        match self {
            Self::Ordinary(r) => driver.begin_cid_retirement(r, sequence),
            Self::Early(r) => driver.begin_early_cid_retirement(r, sequence),
        }
    }
    fn path(
        self,
        driver: &mut Driver<'_>,
        path: PathIdentity,
        effect: crate::driver::PathEffect,
    ) -> Result<crate::driver::PathEffectTicket, DriverError> {
        match self {
            Self::Ordinary(r) => driver.begin_path_effect(r, path, effect),
            Self::Early(r) => driver.begin_early_path_effect(r, path, effect),
        }
    }
}

impl Owner<'_> {
    pub(super) fn network_deadline(&self, can_prepare: bool) -> Option<u64> {
        let n = self.network.as_ref()?;
        let mut deadline = None;
        for path in n.paths.identities() {
            let state = n.paths.snapshot(path).ok()?;
            if state.failed {
                continue;
            }
            let validation = n.paths.validation_deadline(path).ok().flatten();
            // No busy loop for a probe blocked by its actual amplification budget.
            let available = state.available_bytes;
            let probe = if can_prepare && available >= 50 {
                n.paths.probe_deadline(path).ok().flatten()
            } else {
                None
            };
            for at in [validation, probe].into_iter().flatten() {
                deadline = Some(deadline.map_or(at, |old: u64| old.min(at)));
            }
        }
        deadline
    }
}
impl<'r, 's, T: Provider, K: InitialKeyProtection> HandshakeEndpoint<'r, 's, T, K> {
    fn abandon_network_packets(&mut self, path: PathIdentity) -> Result<(), Error> {
        // Validation failure abandons this exact path. Outstanding originals
        // remain ACKable as Lost; their data is requeued on the surviving path.
        // Their loss never reduces the replacement path's congestion window.
        let mut abandoned = [None; 64];
        for (i, p) in self
            .sent
            .outstanding_sent()
            .filter(|p| p.path == Some(path))
            .enumerate()
        {
            abandoned[i] = Some(p);
        }
        for p in abandoned.into_iter().flatten() {
            self.sent.declare_lost(p.packet)?;
            self.flights.mark_lost(p.packet);
            self.path.on_lost(p.packet);
            if p.packet.space == PacketNumberSpace::ApplicationData {
                let mut found = false;
                for record in &mut self.application_packets {
                    if record.is_some_and(|r| r.number == p.packet.value) {
                        *record = None;
                        found = true;
                    }
                }
                if found {
                    self.report_application_loss(p.packet.value)?;
                }
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
    pub(super) fn finish_network_admission(
        &mut self,
        receive: driver::ReceiveTicket,
    ) -> Result<(), Error> {
        let abandoned = self.path.network.as_mut().and_then(|n| n.abandoned.take());
        if let Some(path) = abandoned {
            let ticket = self.driver.begin_path_effect(
                receive,
                path,
                driver::PathEffect::ActivePathChanged,
            )?;
            self.abandon_network_packets(path)?;
            self.driver.finish_path_effect(ticket)?;
        }
        Ok(())
    }
    pub(super) fn network_timeout(&mut self, timer: driver::TimerTicket) -> Result<(), Error> {
        if !self.handshake_confirmed || self.pending.is_some() {
            return Ok(());
        }
        let Some(n) = &self.path.network else {
            return Ok(());
        };
        let Some(expiring) = n.paths.identities().find(|path| {
            n.paths
                .validation_deadline(*path)
                .ok()
                .flatten()
                .is_some_and(|at| self.now >= at)
        }) else {
            return Ok(());
        };
        let grant = self.driver.begin_timer_path_effect(
            timer,
            expiring,
            driver::PathEffect::ValidationExpired,
        )?;
        let decision = {
            let n = self.path.network.as_mut().ok_or(Error::InvalidConfig)?;
            if n.paths.expire(self.now).map_err(NetworkError::from)? != Some(expiring) {
                return Err(Error::InvalidConfig);
            }
            n.migration.failed(expiring, &n.paths)
        };
        match decision {
            Ok(decision) => self.apply_network_decision(decision)?,
            Err(crate::migration::Error::NoViablePath) => {
                self.driver.finish_path_effect(grant)?;
                self.retire();
                return Ok(());
            }
            Err(e) => return Err(NetworkError::Migration(e).into()),
        }
        self.abandon_network_packets(expiring)?;
        let n = self.path.network.as_mut().ok_or(Error::InvalidConfig)?;
        n.paths.retire(expiring).map_err(NetworkError::from)?;
        let old_peer = n.peers_by_path[usize::from(expiring.slot)].take();
        n.inbound_cids[usize::from(expiring.slot)] = None;
        n.ack_history[usize::from(expiring.slot)] = None;
        if let Some(peer) = old_peer
            && !n.peers_by_path.contains(&Some(peer))
        {
            n.peer
                .as_mut()
                .ok_or(Error::InvalidConfig)?
                .retire(peer)
                .map_err(NetworkError::from)?;
            n.queue_retirements()?;
        }
        self.driver.finish_path_effect(grant)?;
        Ok(())
    }
}
