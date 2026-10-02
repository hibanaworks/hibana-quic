//! Actual 0-RTT role capabilities at the packet boundary.
//!
//! The endpoint never owns quarantine bytes, replay history, deferred controls,
//! or substitute Finished flags. It moves the real TLS claim at Install, then
//! awaits Early/Path/Stream owners and settles their affine handoffs.
use super::*;
use crate::early_data::EarlyStatus;
use crate::roles::{early_owner, path_owner, stream_owner};

pub const EARLY_REQUEST_BYTES: usize = 1024;
pub const EARLY_CONTROL_BYTES: usize = 128;
pub const EARLY_COMMAND_BYTES: usize = 1568;
pub type EarlyClient<'channel, 'storage> =
    early_owner::Client<'channel, 'storage, EARLY_COMMAND_BYTES, 1, 1>;
pub type EarlyStarter<'channel, 'storage> =
    early_owner::Starter<'channel, 'storage, EARLY_COMMAND_BYTES, 1, 1>;
pub type EarlyStorage<'storage> =
    early_owner::Storage<'storage, EARLY_REQUEST_BYTES, EARLY_CONTROL_BYTES>;
pub type EarlyExchange = early_owner::Exchange<EARLY_COMMAND_BYTES>;

/// A cancelled multi-owner operation cannot leave a PathCheck or release
/// continuation live while ordinary packet input resumes. Closing the whole
/// connection also closes the downstream consumers of any transferred grant.
struct PendingCall<'a, 'r, 's, 'tc, 'ts, K: InitialKeyProtection> {
    endpoint: &'a mut HandshakeEndpoint<'r, 's, 'tc, 'ts, K>,
    completed: bool,
}
impl<K: InitialKeyProtection> Drop for PendingCall<'_, '_, '_, '_, '_, K> {
    fn drop(&mut self) {
        if !self.completed {
            self.endpoint.retire();
        }
    }
}

impl<'r, 's, 'tc, 'ts, K: InitialKeyProtection> HandshakeEndpoint<'r, 's, 'tc, 'ts, K> {
    /// Configure only the affine startup channel. Caller storage already belongs
    /// to run_unclaimed_borrowed, before the TLS offer is admitted.
    pub fn configure_early_receive(
        &mut self,
        starter: EarlyStarter<'tc, 'ts>,
    ) -> Result<(), Error> {
        if self.side != Side::Server
            || self.io_started
            || self.retired
            || self.early.is_some()
            || self.early_starter.is_some()
            || self.early_last.is_some()
            || starter.generation() != self.generation()
        {
            return Err(Error::InvalidConfig);
        }
        self.early_starter = Some(starter);
        Ok(())
    }
    pub fn early_snapshot(&self) -> Option<early_owner::Snapshot> {
        self.early
            .as_ref()
            .map(EarlyClient::snapshot)
            .or(self.early_last)
    }
    pub fn admitted_early_packets(&self) -> u64 {
        self.early_snapshot()
            .map_or(0, |snapshot| snapshot.admitted_packets)
    }
    pub fn has_pending_early_release(&self) -> bool {
        self.early
            .as_ref()
            .is_some_and(|owner| owner.snapshot().has_releasable)
    }
    /// Local cancellation is deliberately distinct from projected retirement.
    /// This also releases an unused startup service if TLS never accepted 0-RTT.
    pub(super) fn clear_early(&mut self) {
        if let Some(mut owner) = self.early.take() {
            self.early_last = Some(owner.snapshot());
            owner.close();
        }
        if let Some(mut starter) = self.early_starter.take() {
            starter.close();
        }
        self.early_ready.take();
    }
    pub(super) async fn retire_early_owner(&mut self) -> Result<(), Error> {
        let mut pending = PendingCall {
            endpoint: self,
            completed: false,
        };
        let result = pending.endpoint.retire_early_inner().await;
        pending.completed = result.is_ok();
        result
    }
    async fn retire_early_inner(&mut self) -> Result<(), Error> {
        if let Some(owner) = self.early.take() {
            self.early_last = Some(owner.snapshot());
            // Propagate the known projected send100 failure; cancellation is not
            // substituted for a successfully completed Retired exchange.
            self.early_last = Some(owner.retire_snapshot().await.map_err(Error::EarlyOwner)?);
        }
        // An unactivated optional service has no claimed quarantine or active
        // projected session. Closing it is explicitly local resource teardown.
        if let Some(mut starter) = self.early_starter.take() {
            starter.close();
        }
        self.early_ready.take();
        Ok(())
    }
    async fn early_request(
        &mut self,
        command: early_owner::Command<EARLY_COMMAND_BYTES>,
    ) -> Result<early_owner::Outcome<EARLY_COMMAND_BYTES>, Error> {
        let mut pending = PendingCall {
            endpoint: self,
            completed: false,
        };
        let owner = pending
            .endpoint
            .early
            .as_mut()
            .ok_or(Error::InvalidConfig)?;
        let outcome = owner.request(command).await.map_err(Error::EarlyOwner)?;
        pending.endpoint.early_last = Some(owner.snapshot());
        pending.completed = true;
        match outcome {
            early_owner::Outcome::Rejected(error) => Err(Error::EarlyOwnerFault(error)),
            outcome => Ok(outcome),
        }
    }
    async fn settle_early(
        &mut self,
        completion: early_owner::ReleaseCompletion,
    ) -> Result<(), Error> {
        match self
            .early_request(early_owner::Command::Settle(completion))
            .await?
        {
            early_owner::Outcome::Settled => Ok(()),
            _ => Err(Error::InvalidConfig),
        }
    }
    async fn cancel_early_check(&mut self, check: early_owner::PathCheck) -> Result<(), Error> {
        match self
            .early_request(early_owner::Command::Checked(check.cancel()))
            .await?
        {
            early_owner::Outcome::Admission(early_owner::Admission::Cancelled) => Ok(()),
            _ => Err(Error::InvalidConfig),
        }
    }
    pub(super) async fn sync_early_state(&mut self) -> Result<(), Error> {
        if self.lifecycle.state() != ConnectionState::Active || self.retired {
            return Ok(());
        }
        if self.tls_snapshot().early_keys
            && self.tls_snapshot().early_generation != Some(self.generation())
        {
            return Err(Error::InvalidConfig);
        }
        if self.side == Side::Client {
            // A copied rejection status cannot mint recovery authority. Move
            // the actual TLS transition receipt once, including pre-Finished EE.
            if self.early_rejection.is_none() {
                self.early_rejection = self
                    .tls
                    .as_mut()
                    .and_then(|owner| owner.take_early_rejected());
            }
            if self.early_rejection.is_some() {
                self.reject_early_packets_impl().await?;
            }
            return Ok(());
        }
        if self.early.is_some()
            || !matches!(
                self.tls_snapshot().early_status,
                EarlyStatus::AcceptedPendingFinished | EarlyStatus::Accepted
            )
        {
            return Ok(());
        }
        let mut pending = PendingCall {
            endpoint: self,
            completed: false,
        };
        let starter = pending
            .endpoint
            .early_starter
            .take()
            .ok_or(Error::InvalidConfig)?;
        let grant = pending
            .endpoint
            .tls
            .as_mut()
            .ok_or(Error::Retired)?
            .take_early_replay_grant()
            .await?
            .ok_or(Error::InvalidConfig)?;
        let owner = starter.activate(grant).await.map_err(Error::EarlyOwner)?;
        pending.endpoint.early_last = Some(owner.snapshot());
        pending.endpoint.early = Some(owner);
        pending.completed = true;
        Ok(())
    }
    /// The server consumes the genuine Finished+TP+Accepted grant once. Each
    /// target either commits the exact frame or returns its grant for cancellation;
    /// the source retains bytes until that settlement has been acknowledged.
    pub(crate) async fn release_early(&mut self) -> Result<(), Error> {
        if self.side != Side::Server || self.early.is_none() {
            return Ok(());
        }
        let mut pending = PendingCall {
            endpoint: self,
            completed: false,
        };
        let result = pending.endpoint.release_early_inner().await;
        pending.completed = result.is_ok();
        result
    }
    async fn release_early_inner(&mut self) -> Result<(), Error> {
        if let Some(ready) = self.early_ready.take() {
            match self
                .early_request(early_owner::Command::Finish(ready))
                .await?
            {
                early_owner::Outcome::Ready => {}
                _ => return Err(Error::InvalidConfig),
            }
        }
        if !self
            .early
            .as_ref()
            .ok_or(Error::InvalidConfig)?
            .snapshot()
            .release_ready
        {
            return Ok(());
        }
        for _ in 0..128 {
            let release = match self.early_request(early_owner::Command::Release).await? {
                early_owner::Outcome::Release(Some(release)) => release,
                early_owner::Outcome::Release(None) => return Ok(()),
                _ => return Err(Error::InvalidConfig),
            };
            match release {
                early_owner::Release::Application(grant) => {
                    match self.stream_deliver_early(grant).await? {
                        Ok(completion) => self.settle_early(completion).await?,
                        Err((error, grant)) => {
                            self.settle_early(grant.cancel()).await?;
                            if matches!(
                                error,
                                stream_owner::Fault::Capacity
                                    | stream_owner::Fault::Streams(crate::streams::Error::Capacity)
                            ) {
                                return Ok(());
                            }
                            return Err(Error::StreamOwner(stream_owner::ClientError::Rejected(
                                error,
                            )));
                        }
                    }
                }
                early_owner::Release::Path(grant) => match self
                    .path_request(path_owner::Command::EarlyRelease(grant))
                    .await?
                {
                    path_owner::Outcome::EarlyReleased(completion) => {
                        self.settle_early(completion).await?
                    }
                    path_owner::Outcome::EarlyReleaseRejected { release, error } => {
                        self.settle_early(release.cancel()).await?;
                        if matches!(
                            error,
                            path_owner::Error::Capacity
                                | path_owner::Error::Path(crate::path::Error::Capacity)
                        ) {
                            return Ok(());
                        }
                        return Err(NetworkError::Owner(error).into());
                    }
                    _ => return Err(Error::InvalidConfig),
                },
            }
        }
        Ok(())
    }
    pub(super) async fn receive_early(
        &mut self,
        packet: packet::Packet<'_>,
        scratch: &mut [u8],
        received_ecn: Option<Codepoint>,
        datagram_bytes: usize,
    ) -> Result<bool, Error> {
        let mut pending = PendingCall {
            endpoint: self,
            completed: false,
        };
        let result = pending
            .endpoint
            .receive_early_inner(packet, scratch, received_ecn, datagram_bytes)
            .await;
        pending.completed = result.is_ok();
        result
    }
    async fn receive_early_inner(
        &mut self,
        packet: packet::Packet<'_>,
        scratch: &mut [u8],
        received_ecn: Option<Codepoint>,
        datagram_bytes: usize,
    ) -> Result<bool, Error> {
        let Header::Long {
            kind: LongType::ZeroRtt,
            packet_number_offset: pn_offset,
            source_id,
            destination_id,
            ..
        } = packet.header
        else {
            return Ok(false);
        };
        let path = self.path_snapshot();
        let address = self.ingress_address.unwrap_or(path.initial_address);
        if self.side != Side::Server
            || address != path.initial_address
            || self.lifecycle.state() != ConnectionState::Active
            || !self.tls_snapshot().early_keys
            || !matches!(
                self.tls_snapshot().early_status,
                EarlyStatus::AcceptedPendingFinished | EarlyStatus::Accepted
            )
            || packet.bytes.len() > scratch.len()
            || packet.bytes.len() > TLS_PACKET_BYTES
            || (self.remote_known && source_id != self.remote.bytes())
        {
            return Ok(false);
        }
        // The original Initial DCID is admitted by Path's distinct Early route;
        // ordinary one-RTT packets never gain this alias.
        let destination_allowed = path
            .routable_cids
            .into_iter()
            .flatten()
            .any(|cid| cid.as_bytes() == destination_id)
            || path
                .initial_destination_cid
                .is_some_and(|cid| cid.as_bytes() == destination_id);
        if !destination_allowed {
            return Ok(false);
        }
        self.sync_early_state().await?;
        if self.early.is_none() {
            return Err(Error::InvalidConfig);
        }
        let bytes = &mut scratch[..packet.bytes.len()];
        bytes.copy_from_slice(packet.bytes);
        let Some(sample) = bytes.get(pn_offset + 4..pn_offset + 20) else {
            return Ok(false);
        };
        let sample: [u8; 16] = sample.try_into().map_err(|_| Error::Capacity)?;
        let mask = self.tls_early_mask(false, sample).await?;
        bytes[0] ^= mask[0] & 0x0f;
        let pn_len = usize::from((bytes[0] & 3) + 1);
        if pn_offset + pn_len > bytes.len() {
            return Ok(false);
        }
        for i in 0..pn_len {
            bytes[pn_offset + i] ^= mask[i + 1];
        }
        let (truncated, _) = packet::decode_truncated_packet_number(bytes[0], &bytes[pn_offset..])?;
        let pn = match packet::restore_packet_number(
            truncated,
            pn_len as u8,
            self.received[2].largest,
        ) {
            Ok(pn) => pn,
            Err(_) => return Ok(false),
        };
        let first = bytes[0];
        let (header, body) = bytes.split_at_mut(pn_offset + pn_len);
        let (len, receipt) = match self.tls_open_early(pn, header, body).await {
            Ok(opened) => opened,
            Err(Error::Tls(tls::Error::Authentication | tls::Error::KeysUnavailable)) => {
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        packet::validate_reserved_bits(first)?;
        if len == 0 {
            return Err(Error::ProtocolViolation);
        }
        let payload = body.get(..len).ok_or(Error::Capacity)?;
        let mut eliciting = false;
        for frame in FrameIter::new(payload, EncryptionLevel::ZeroRtt, ParseLimits::default())? {
            match frame {
                Ok(frame) => eliciting |= frame.ack_eliciting(),
                Err(packet::Error::LimitExceeded(_)) => return Ok(false),
                Err(error) => return Err(error.into()),
            }
        }
        self.trace_event(crate::trace::Event::Packet {
            direction: crate::trace::Direction::Received,
            header: crate::trace::PacketHeader {
                packet_type: crate::trace::PacketType::ZeroRtt,
                packet_number: Some(pn),
                key_phase: None,
            },
            datagram_id: u32::try_from(self.path_datagram_id).ok(),
        });
        let mut seen = self.received[2];
        if !seen.insert(pn) {
            if eliciting {
                self.received[2].ack_pending = true;
            }
            return Ok(false);
        }
        let context = self.path_receive_context(destination_id, datagram_bytes)?;
        let admitted =
            early_owner::AuthenticatedPacket::new(receipt, payload, context, path.original_path)
                .map_err(Error::EarlyOwnerFault)?;
        let check = match self
            .early_request(early_owner::Command::Receive(admitted))
            .await?
        {
            early_owner::Outcome::Check(check) => check,
            early_owner::Outcome::Dropped => return Ok(false),
            _ => return Err(Error::InvalidConfig),
        };
        let checked = match self
            .path_request(path_owner::Command::EarlyPreflight(check))
            .await?
        {
            path_owner::Outcome::EarlyChecked(checked) => checked,
            path_owner::Outcome::EarlyCheckRejected { check, error } => {
                self.cancel_early_check(check).await?;
                if matches!(error, path_owner::Error::Capacity) {
                    return Ok(false);
                }
                return Err(NetworkError::Owner(error).into());
            }
            _ => return Err(Error::InvalidConfig),
        };
        match self
            .early_request(early_owner::Command::Checked(checked))
            .await?
        {
            early_owner::Outcome::Admission(early_owner::Admission::Admitted(grant)) => {
                match self
                    .path_request(path_owner::Command::EarlyAdmission(grant))
                    .await?
                {
                    path_owner::Outcome::EarlyAdmitted {
                        path: admitted_path,
                    } if admitted_path == path.original_path => {}
                    path_owner::Outcome::EarlyAdmissionRejected { error, .. } => {
                        return Err(NetworkError::Owner(error).into());
                    }
                    _ => return Err(Error::InvalidConfig),
                }
                self.received[2] = seen;
                self.ecn_rx
                    .processed(PacketNumberSpace::ApplicationData, received_ecn)?;
                if eliciting {
                    self.received[2].ack_pending = true;
                }
                self.release_early().await?;
                Ok(true)
            }
            early_owner::Outcome::Admission(early_owner::Admission::PeerClose(close)) => {
                let Frame::ConnectionClose {
                    error_code,
                    frame_type,
                    ..
                } = close.frame()?
                else {
                    return Err(Error::InvalidConfig);
                };
                self.peer_close = Some(PeerClose {
                    error_code,
                    frame_type,
                    level: Level::OneRtt,
                    protection: EncryptionLevel::ZeroRtt,
                });
                self.enter_draining().await?;
                Ok(true)
            }
            _ => Err(Error::InvalidConfig),
        }
    }
}
