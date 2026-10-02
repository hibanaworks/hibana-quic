//! Capabilities for the independently scheduled stream/application owner.
//!
//! Only the role owns stream tables, send queues, reliable controls and early
//! intent. This module transfers affine grants and copied command/reply data;
//! it never borrows that state or interprets a snapshot as permission.
use super::*;
use crate::roles::{
    connection_authority, datagram, early_owner, packet_authority, recovery_owner, stream_owner,
};

/// A received 1536-byte packet plus the canonical frame envelope. Read replies
/// copy at most this many bytes even when the receive ring is much larger.
pub const STREAM_FRAME_BYTES: usize = 1568;
pub type StreamClient<'channel, 'storage> =
    stream_owner::Client<'channel, 'storage, STREAM_FRAME_BYTES, 1, 1>;
pub type StreamOutcome = stream_owner::Outcome<STREAM_FRAME_BYTES>;
pub type StreamCommand = stream_owner::Command<STREAM_FRAME_BYTES>;

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
    /// Last copied observation. After abort, this describes the last completed
    /// role exchange; it does not imply that its closed mailbox is usable.
    pub fn stream_snapshot(&self) -> stream_owner::Snapshot {
        self.stream
            .as_ref()
            .map_or(self.stream_last, |owner| *owner.snapshot())
    }

    pub(super) fn abort_stream(&mut self) {
        if let Some(mut owner) = self.stream.take() {
            self.stream_last = *owner.snapshot();
            owner.close();
        }
    }

    pub(super) async fn retire_stream_owner(&mut self) -> Result<(), Error> {
        if let Some(owner) = self.stream.take() {
            self.stream_last = *owner.snapshot();
            owner.retire().await.map_err(Error::StreamOwner)?;
        }
        Ok(())
    }

    /// Every operation awaits the live role. A cancelled request closes the
    /// whole connection because its outcome can no longer be reconciled.
    pub(crate) async fn stream_request(
        &mut self,
        command: StreamCommand,
    ) -> Result<StreamOutcome, Error> {
        let mut pending = PendingCall {
            endpoint: self,
            completed: false,
        };
        let owner = pending.endpoint.stream.as_mut().ok_or(Error::Retired)?;
        let outcome = owner.request(command).await.map_err(Error::StreamOwner)?;
        pending.endpoint.stream_last = *owner.snapshot();
        pending.completed = true;
        match outcome {
            stream_owner::Outcome::Rejected(error) => Err(Error::StreamOwner(
                stream_owner::ClientError::Rejected(error),
            )),
            outcome => Ok(outcome),
        }
    }

    pub(crate) async fn stream_apply(&mut self, command: StreamCommand) -> Result<(), Error> {
        match self.stream_request(command).await? {
            stream_owner::Outcome::Applied => Ok(()),
            _ => {
                self.retire();
                Err(Error::InvalidConfig)
            }
        }
    }

    /// Consumes the real TLS-install grant once, before an early request can be
    /// enqueued. A caller-provided remembered-limit snapshot cannot enter here.
    pub(crate) async fn stream_install_early_send(&mut self) -> Result<(), Error> {
        if !self.stream_snapshot().early_send_configured {
            return Ok(());
        }
        let grant = self
            .tls
            .as_mut()
            .ok_or(Error::Retired)?
            .take_early_send_ready();
        if let Some(grant) = grant {
            self.stream_apply(StreamCommand::EarlySendReady(grant))
                .await?;
        }
        Ok(())
    }

    pub(super) async fn stream_retry(
        &mut self,
        grant: packet_authority::StreamRetryGrant,
    ) -> Result<(), Error> {
        self.stream_apply(StreamCommand::Retry(grant)).await
    }
    pub(super) async fn stream_ready(
        &mut self,
        grant: connection_authority::AppReady,
    ) -> Result<(), Error> {
        self.stream_apply(StreamCommand::PeerReady(grant)).await
    }
    pub(super) async fn stream_early_ready(
        &mut self,
        grant: connection_authority::EarlyReady,
    ) -> Result<(), Error> {
        self.stream_apply(StreamCommand::EarlyReady(grant)).await
    }
    pub(super) async fn stream_deliver(
        &mut self,
        grant: packet_authority::DeliveryGrant<STREAM_FRAME_BYTES>,
    ) -> Result<(), Error> {
        self.stream_apply(StreamCommand::Deliver(grant)).await
    }
    pub(super) async fn stream_ack(
        &mut self,
        grant: recovery_owner::StreamAck,
    ) -> Result<(), Error> {
        self.stream_apply(StreamCommand::Acknowledge(grant)).await
    }
    pub(super) async fn stream_pto(
        &mut self,
        grant: recovery_owner::StreamPtoGrant,
    ) -> Result<(), Error> {
        self.stream_apply(StreamCommand::Probe(grant)).await
    }
    pub(super) async fn stream_loss(
        &mut self,
        grant: recovery_owner::LostPacket,
    ) -> Result<Option<recovery_owner::StreamLossSettled>, Error> {
        match self.stream_request(StreamCommand::Lost(grant)).await? {
            stream_owner::Outcome::LossApplied(settlement) => Ok(settlement),
            _ => {
                self.retire();
                Err(Error::InvalidConfig)
            }
        }
    }
    pub(super) async fn stream_deliver_early(
        &mut self,
        grant: early_owner::AppRelease<STREAM_FRAME_BYTES>,
    ) -> Result<
        Result<
            early_owner::ReleaseCompletion,
            (
                stream_owner::Fault,
                early_owner::AppRelease<STREAM_FRAME_BYTES>,
            ),
        >,
        Error,
    > {
        match self
            .stream_request(StreamCommand::DeliverEarly(grant))
            .await?
        {
            stream_owner::Outcome::EarlyDelivered(settlement) => Ok(Ok(settlement)),
            stream_owner::Outcome::EarlyRejected { error, grant } => Ok(Err((error, grant))),
            _ => {
                self.retire();
                Err(Error::InvalidConfig)
            }
        }
    }
    pub(crate) async fn stream_prepare(
        &mut self,
        early: bool,
    ) -> Result<Option<stream_owner::PreparedFrame<STREAM_FRAME_BYTES>>, Error> {
        let probe = self.stream_snapshot().probe_budget != 0;
        let command = if early {
            StreamCommand::PrepareEarly { probe }
        } else {
            StreamCommand::Prepare { probe }
        };
        match self.stream_request(command).await? {
            stream_owner::Outcome::Prepared(frame) => Ok(frame),
            _ => {
                self.retire();
                Err(Error::InvalidConfig)
            }
        }
    }
    pub(super) async fn stream_reserve(
        &mut self,
        prepared: stream_owner::PreparedId,
        packet: u64,
    ) -> Result<stream_owner::TransmissionId, Error> {
        match self
            .stream_request(StreamCommand::Reserve { prepared, packet })
            .await?
        {
            stream_owner::Outcome::Reserved(id) => Ok(id),
            _ => {
                self.retire();
                Err(Error::InvalidConfig)
            }
        }
    }
    pub(super) async fn stream_cancel_prepared(
        &mut self,
        prepared: stream_owner::PreparedId,
    ) -> Result<(), Error> {
        self.stream_apply(StreamCommand::CancelPrepared(prepared))
            .await
    }
    pub(super) async fn stream_complete(
        &mut self,
        completion: datagram::StreamCompletion,
    ) -> Result<(), Error> {
        self.stream_apply(StreamCommand::AdapterComplete(completion))
            .await
    }
    pub(super) async fn stream_cancel(
        &mut self,
        cancellation: datagram::StreamCancellation,
    ) -> Result<(), Error> {
        self.stream_apply(StreamCommand::CancelTransmission(cancellation))
            .await
    }
}
