//! Endpoint plumbing for the actual projected Path/CID owner. This module owns
//! mailbox capabilities and copied observations only; there is no second path,
//! anti-amplification, CID, migration or reliable-control kernel here.
use super::*;
use crate::{
    connection_id::{Cid, CidError, LocalCidSlot, PeerCidSlot, ResetToken},
    path::{Address, PathSlot},
    roles::{connection_authority, packet_authority, path_owner, recovery_owner},
};
use core::net::SocketAddr;
use rand_core::{CryptoRng, RngCore};

pub const NETWORK_PATHS: usize = path_owner::PATHS;
pub const LOCAL_CID_HISTORY: usize = path_owner::LOCAL_CIDS;
pub const PEER_CID_HISTORY: usize = path_owner::PEER_CIDS;
pub type PathClient<'channel, 'storage> = path_owner::Client<'channel, 'storage, 1, 1>;
pub(super) type Reservation = path_owner::PendingTransmit;
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
    pub active_connection_id_limit: u64,
    pub initial_reset_token: Option<ResetToken>,
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
/// Caller-owned storage is moved into path_owner::State before spawning the
/// Path roles. It is never installed into a live endpoint as a mutable alias.
pub struct NetworkResources<'s> {
    pub paths: &'s mut [PathSlot<1, 3>; NETWORK_PATHS],
    pub local_cids: &'s mut [LocalCidSlot; LOCAL_CID_HISTORY],
    pub peer_cids: &'s mut [PeerCidSlot<2>; PEER_CID_HISTORY],
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
    Owner(path_owner::Error),
    Client(path_owner::ClientError),
}
impl From<CidError> for NetworkError {
    fn from(error: CidError) -> Self {
        Self::Cid(error)
    }
}
impl From<crate::path::Error> for NetworkError {
    fn from(error: crate::path::Error) -> Self {
        Self::Path(error)
    }
}
impl From<crate::migration::Error> for NetworkError {
    fn from(error: crate::migration::Error) -> Self {
        Self::Migration(error)
    }
}
impl From<path_owner::Error> for NetworkError {
    fn from(error: path_owner::Error) -> Self {
        Self::Owner(error)
    }
}
impl From<path_owner::ClientError> for NetworkError {
    fn from(error: path_owner::ClientError) -> Self {
        Self::Client(error)
    }
}
/// Kept for the standalone historical early-control numerical kernel. Production
/// admission uses PathContext (including zero CID) and affine Early owner grants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkReceiveContext {
    pub path: PathIdentity,
    pub destination: Cid,
}

impl<'r, 's, 'tc, 'ts, K: InitialKeyProtection> HandshakeEndpoint<'r, 's, 'tc, 'ts, K> {
    pub fn path_snapshot(&self) -> path_owner::Snapshot {
        self.path
            .as_ref()
            .map_or(self.path_last, PathClient::snapshot)
    }
    pub(super) async fn path_request(
        &mut self,
        command: path_owner::Command,
    ) -> Result<path_owner::Outcome, Error> {
        let owner = self.path.as_mut().ok_or(Error::Retired)?;
        let outcome = match owner.request(command).await {
            Ok(outcome) => outcome,
            Err(error) => {
                self.retire();
                return Err(NetworkError::Client(error).into());
            }
        };
        self.path_last = owner.snapshot();
        match outcome {
            path_owner::Outcome::Rejected(error) => Err(NetworkError::Owner(error).into()),
            outcome => Ok(outcome),
        }
    }
    pub(super) fn active_path_identity(&self) -> PathIdentity {
        self.path_snapshot().active
    }
    pub(super) fn path_available_bytes(&self) -> u64 {
        self.network_path_state()
            .map_or(0, |(_, state)| state.available_bytes)
    }
    pub fn network_path_state(&self) -> Option<(PathIdentity, crate::path::Snapshot)> {
        let snapshot = self.path_snapshot();
        snapshot
            .paths
            .get(usize::from(snapshot.active.slot))
            .copied()
            .flatten()
            .filter(|(identity, _)| *identity == snapshot.active)
    }
    pub fn issued_local_cids(&self) -> impl Iterator<Item = Cid> + '_ {
        self.path_snapshot()
            .issued_cids
            .into_iter()
            .flatten()
            .filter_map(|cid| Cid::new(cid.as_bytes()).ok())
    }
    pub(super) fn transmit_address(&self) -> Option<Address> {
        self.network_path_state().map(|(_, p)| p.address)
    }
    pub(super) fn network_deadline(&self, can_prepare: bool) -> Option<u64> {
        let snapshot = self.path_snapshot();
        if !snapshot.confirmed {
            return None;
        }
        if can_prepare {
            snapshot.deadline
        } else {
            snapshot.validation_deadline
        }
    }
    fn path_accepts_source(&self, address: Address) -> bool {
        let snapshot = self.path_snapshot();
        // Initial protection is public-key-derived, not peer authentication.
        // An off-path Initial must not turn a different unconfirmed source into
        // a fatal owner rejection against the existing connection.
        if !snapshot.confirmed
            || snapshot.local_cid.is_zero()
            || snapshot.peer_initial_cid.is_some_and(|cid| cid.is_zero())
        {
            return address == snapshot.initial_address;
        }
        match snapshot.role {
            crate::migration::Role::Client => snapshot
                .paths
                .into_iter()
                .flatten()
                .any(|(_, state)| state.address == address && !state.failed),
            crate::migration::Role::Server => true, // authenticated owner checks migration/local policy
        }
    }
    pub(super) fn path_accepts_destination(&self, destination: &[u8], level: Level) -> bool {
        let snapshot = self.path_snapshot();
        snapshot.routable_cids.into_iter().flatten().any(|cid| cid.as_bytes() == destination)
            || (level == Level::Initial && self.side == Side::Server && snapshot.initial_destination_cid.is_some_and(|cid| cid.as_bytes() == destination))
            // Before the first authenticated Initial, the dispatcher selected
            // this connection using its ODCID. The owner learns that alias only
            // from the actual integrity-checked Initial header.
            || (level == Level::Initial && self.side == Side::Server && snapshot.initial_destination_cid.is_none() && destination == self.initial_destination.bytes())
    }
    pub(super) fn abort_path(&mut self) {
        if let Some(mut owner) = self.path.take() {
            self.path_last = owner.snapshot();
            owner.close();
        }
    }
    pub(super) async fn retire_path_owner(&mut self) -> Result<(), Error> {
        if let Some(owner) = self.path.take() {
            self.path_last = owner.retire().await.map_err(NetworkError::from)?;
        }
        Ok(())
    }
    pub(super) async fn path_ack(&mut self, grant: recovery_owner::PathAck) -> Result<(), Error> {
        match self.path_request(path_owner::Command::Ack(grant)).await? {
            path_owner::Outcome::AckApplied => Ok(()),
            _ => Err(Error::InvalidConfig),
        }
    }
    pub(super) async fn path_loss(
        &mut self,
        grant: recovery_owner::PathLostPacket,
    ) -> Result<Option<recovery_owner::PathLossSettled>, Error> {
        match self.path_request(path_owner::Command::Lost(grant)).await? {
            path_owner::Outcome::LossApplied(proof) => Ok(proof),
            _ => Err(Error::InvalidConfig),
        }
    }
    pub(super) async fn path_probe_timeout(
        &mut self,
        grant: recovery_owner::PathProbeTimeoutGrant,
    ) -> Result<(), Error> {
        match self
            .path_request(path_owner::Command::ProbeTimeout(grant))
            .await?
        {
            path_owner::Outcome::ProbeTimeoutUpdated => Ok(()),
            _ => Err(Error::InvalidConfig),
        }
    }
    pub(super) async fn path_pto(
        &mut self,
        grant: recovery_owner::PathPtoGrant,
    ) -> Result<(), Error> {
        match self.path_request(path_owner::Command::Pto(grant)).await? {
            path_owner::Outcome::PtoApplied => Ok(()),
            _ => Err(Error::InvalidConfig),
        }
    }
    pub(super) fn path_begin_datagram(&mut self) -> Result<(), Error> {
        self.path_datagram_id = self
            .path_datagram_id
            .checked_add(1)
            .ok_or(Error::Capacity)?;
        Ok(())
    }
    pub(super) fn path_receive_context(
        &self,
        destination: &[u8],
        datagram_bytes: usize,
    ) -> Result<path_owner::PathContext, Error> {
        Ok(path_owner::PathContext {
            address: self
                .ingress_address
                .unwrap_or(self.path_snapshot().initial_address),
            destination: path_owner::Destination::new(destination).map_err(NetworkError::from)?,
            datagram_id: self.path_datagram_id,
            datagram_bytes: u64::try_from(datagram_bytes).map_err(|_| Error::Capacity)?,
            now: self.now,
        })
    }
    pub(super) async fn path_prepare(&mut self) -> Result<(), Error> {
        if let Some(token) = self.retry_admission.take() {
            match self
                .path_request(path_owner::Command::ServerRetry(token))
                .await?
            {
                path_owner::Outcome::ServerRetryValidated => {}
                _ => {
                    self.retire();
                    return Err(Error::InvalidConfig);
                }
            }
        }
        Ok(())
    }
    pub(super) async fn path_learn_initial(
        &mut self,
        ticket: packet_authority::PacketTicket,
        header: &[u8],
    ) -> Result<(), Error> {
        let grant = self.authority.grant_initial_peer_cid(ticket, header)?;
        match self
            .path_request(path_owner::Command::LearnPeerCid(grant))
            .await?
        {
            path_owner::Outcome::PeerCidLearned => Ok(()),
            _ => Err(Error::InvalidConfig),
        }
    }
    pub(super) async fn path_apply_retry(
        &mut self,
        grant: packet_authority::RetryPeerCid,
    ) -> Result<(), Error> {
        match self
            .path_request(path_owner::Command::ApplyRetry(grant))
            .await?
        {
            path_owner::Outcome::RetryApplied => Ok(()),
            _ => Err(Error::InvalidConfig),
        }
    }
    pub(super) async fn path_received_packet(
        &mut self,
        ticket: packet_authority::PacketTicket,
        context: path_owner::PathContext,
        non_probing: bool,
    ) -> Result<PathIdentity, Error> {
        self.authority.bind_path_context(ticket, context)?;
        let grant = self.authority.grant_path(
            ticket,
            0,
            path_owner::PathFrame::PacketProcessed { non_probing },
            context,
        )?;
        let outcome = self.path_request(path_owner::Command::Frame(grant)).await?;
        self.path_apply_outcome(outcome)
            .await?
            .ok_or(Error::InvalidConfig)
    }
    pub(super) async fn path_received_frame(
        &mut self,
        ticket: packet_authority::PacketTicket,
        ordinal: u32,
        frame: Frame<'_>,
        context: path_owner::PathContext,
    ) -> Result<bool, Error> {
        let frame = match frame {
            Frame::PathChallenge { data } => path_owner::PathFrame::Challenge(*data),
            Frame::PathResponse { data } => path_owner::PathFrame::Response(*data),
            Frame::NewConnectionId {
                sequence,
                retire_prior_to,
                id,
                reset_token,
            } => path_owner::PathFrame::NewConnectionId {
                sequence,
                retire_prior_to,
                id: Cid::new(id).map_err(NetworkError::from)?,
                reset_token: ResetToken::new(*reset_token),
            },
            Frame::RetireConnectionId { sequence } => {
                path_owner::PathFrame::RetireConnectionId { sequence }
            }
            Frame::HandshakeDone => path_owner::PathFrame::HandshakeDone,
            _ => return Ok(false),
        };
        let grant = self.authority.grant_path(ticket, ordinal, frame, context)?;
        let outcome = self.path_request(path_owner::Command::Frame(grant)).await?;
        self.path_apply_outcome(outcome).await?;
        Ok(true)
    }
    pub(super) async fn path_install_ready(
        &mut self,
        grant: connection_authority::PathReady,
    ) -> Result<(), Error> {
        let outcome = self
            .path_request(path_owner::Command::Handshake(grant))
            .await?;
        self.path_apply_outcome(outcome).await?;
        Ok(())
    }
    pub(super) async fn path_timeout(&mut self) -> Result<(), Error> {
        // Initial-path validation follows the handshake; an unconfirmed
        // connection still uses Recovery's handshake retransmission timers.
        if !self.path_snapshot().confirmed {
            return Ok(());
        }
        let path_owner::Outcome::Timer(timer) =
            self.path_request(path_owner::Command::ObserveTimer).await?
        else {
            return Err(Error::InvalidConfig);
        };
        if let Some(timer) = timer
            && self.now >= timer.deadline()
        {
            let outcome = self
                .path_request(path_owner::Command::Timeout {
                    timer,
                    now: self.now,
                })
                .await?;
            self.path_apply_outcome(outcome).await?;
        }
        Ok(())
    }
    async fn path_apply_outcome(
        &mut self,
        outcome: path_owner::Outcome,
    ) -> Result<Option<PathIdentity>, Error> {
        let result = self.path_apply_outcome_inner(outcome).await;
        if result.is_err() {
            self.retire();
        }
        result
    }
    async fn path_apply_outcome_inner(
        &mut self,
        mut outcome: path_owner::Outcome,
    ) -> Result<Option<PathIdentity>, Error> {
        loop {
            let (path, reset, confirmation) = match outcome {
                path_owner::Outcome::Frame {
                    path,
                    recovery_reset,
                    tls_confirmation,
                    ..
                } => (Some(path), recovery_reset, tls_confirmation),
                path_owner::Outcome::Expired { recovery_reset, .. } => (None, recovery_reset, None),
                path_owner::Outcome::HandshakeInstalled { tls_confirmation } => {
                    (None, None, tls_confirmation)
                }
                path_owner::Outcome::PathRetired => return Ok(None),
                path_owner::Outcome::PathUnavailable => {
                    self.retire_owned().await?;
                    return Ok(None);
                }
                path_owner::Outcome::AbandonmentRequired(grant) => {
                    let recovery_owner::Outcome::AbandonmentStarted(mut losses) = self
                        .recovery_request(recovery_owner::Command::AbandonPath(grant))
                        .await?
                    else {
                        return Err(Error::Busy);
                    };
                    for grant in losses.stream.iter_mut().filter_map(Option::take) {
                        let proof = self.stream_loss(grant).await?.ok_or(Error::InvalidConfig)?;
                        match self
                            .recovery_request(recovery_owner::Command::SettleAbandonment(
                                recovery_owner::AbandonmentSettlement::Stream(proof),
                            ))
                            .await?
                        {
                            recovery_owner::Outcome::AbandonmentSettled => {}
                            _ => return Err(Error::InvalidConfig),
                        }
                    }
                    for grant in losses.path.iter_mut().filter_map(Option::take) {
                        let proof = self.path_loss(grant).await?.ok_or(Error::InvalidConfig)?;
                        match self
                            .recovery_request(recovery_owner::Command::SettleAbandonment(
                                recovery_owner::AbandonmentSettlement::Path(proof),
                            ))
                            .await?
                        {
                            recovery_owner::Outcome::AbandonmentSettled => {}
                            _ => return Err(Error::InvalidConfig),
                        }
                    }
                    let recovery_owner::Outcome::PathAbandoned(completion) = self
                        .recovery_request(recovery_owner::Command::FinishAbandonment)
                        .await?
                    else {
                        return Err(Error::InvalidConfig);
                    };
                    outcome = self
                        .path_request(path_owner::Command::AbandonComplete(completion))
                        .await?;
                    continue;
                }
                _ => return Err(Error::InvalidConfig),
            };
            if let Some(grant) = reset {
                match self
                    .recovery_request(recovery_owner::Command::ResetPath(grant))
                    .await?
                {
                    recovery_owner::Outcome::PathReset => {}
                    _ => return Err(Error::InvalidConfig),
                }
            }
            if let Some(grant) = confirmation {
                self.tls_confirm(grant).await?;
                self.handshake_confirmed = true;
                self.discard_requested[1] = true;
            }
            return Ok(path);
        }
    }
    pub(super) async fn receive_from_impl(
        &mut self,
        datagram: &[u8],
        scratch: &mut [u8],
        address: Address,
        codepoint: Option<Codepoint>,
    ) -> Result<Received, Error> {
        if self.retired {
            return Err(Error::Retired);
        }
        if self.lifecycle.state() == ConnectionState::Draining {
            return Ok(Received {
                authenticated: 0,
                discarded: 1,
            });
        }
        if self.ingress_address.is_some() {
            return Err(Error::Busy);
        }
        self.ingress_address = Some(address);
        let reset = self
            .path_request(path_owner::Command::CheckReset(
                path_owner::ResetCandidate::new(address, datagram),
            ))
            .await;
        match reset {
            Ok(path_owner::Outcome::Reset(true)) => {
                self.ingress_address = None;
                self.enter_draining().await?;
                return Ok(Received {
                    authenticated: 0,
                    discarded: 1,
                });
            }
            Ok(path_owner::Outcome::Reset(false)) => {}
            Ok(_) => {
                self.ingress_address = None;
                return Err(Error::InvalidConfig);
            }
            Err(error) => {
                self.ingress_address = None;
                return Err(error);
            }
        }
        if !self.path_accepts_source(address) {
            self.ingress_address = None;
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
                    path: self.path_snapshot().active,
                    codepoint,
                },
            )
            .await;
        self.ingress_address = None;
        result
    }
}
