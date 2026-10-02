//! Application operations over the connection's independently scheduled stream owner.
//!
//! The caller gives stream slots, chunks, references and optional early slots to
//! Stream State, then gives its connected Client to HandshakeEndpoint. This
//! facade owns only that connection. Each operation awaits the actual role;
//! reads copy bounded data and no mutable owner reference escapes.
pub use crate::handshake_endpoint::{Error, STREAM_FRAME_BYTES, StreamClient};
use crate::{
    handshake_endpoint::{
        self, HandshakeEndpoint, InitialKeyProtection, InitialProtection, Received, Transmit,
    },
    roles::{
        path_owner::UdpAdapter,
        stream_owner::{self, Bytes, Command, Outcome},
    },
    streams::StreamHandle,
};

pub struct TransportEndpoint<'r, 's, 'tc, 'ts, K: InitialKeyProtection = InitialProtection<'r, 's>>
{
    engine: HandshakeEndpoint<'r, 's, 'tc, 'ts, K>,
}
impl<'r, 's, 'tc, 'ts, K: InitialKeyProtection> TransportEndpoint<'r, 's, 'tc, 'ts, K> {
    /// Complete optional early-send admission using the actual TLS install
    /// grant. All stream storage already belongs to the connected role.
    pub async fn new(mut engine: HandshakeEndpoint<'r, 's, 'tc, 'ts, K>) -> Result<Self, Error> {
        engine.stream_install_early_send().await?;
        Ok(Self { engine })
    }
    fn active(&self) -> Result<(), Error> {
        if self.is_retired() || self.connection_state() != crate::lifecycle::State::Active {
            return Err(Error::Retired);
        }
        Ok(())
    }
    fn not_ready() -> Error {
        Error::StreamOwner(stream_owner::ClientError::Rejected(
            stream_owner::Fault::NotReady,
        ))
    }
    fn ready(&self) -> Result<(), Error> {
        self.active()?;
        if !self.stream_snapshot().ready {
            return Err(Self::not_ready());
        }
        Ok(())
    }
    async fn request(
        &mut self,
        command: Command<STREAM_FRAME_BYTES>,
    ) -> Result<Outcome<STREAM_FRAME_BYTES>, Error> {
        self.ready()?;
        self.engine.stream_request(command).await
    }
    fn unexpected<T>(&mut self) -> Result<T, Error> {
        self.engine.retire();
        Err(Error::InvalidConfig)
    }
    fn bytes(input: &[u8]) -> Result<Bytes<STREAM_FRAME_BYTES>, Error> {
        Bytes::new(input).map_err(|e| Error::StreamOwner(stream_owner::ClientError::Rejected(e)))
    }
    /// Last completed role observation; this does not authorize mutation.
    pub fn stream_snapshot(&self) -> stream_owner::Snapshot {
        self.engine.stream_snapshot()
    }
    pub async fn open(&mut self, bidirectional: bool) -> Result<StreamHandle, Error> {
        match self.request(Command::Open { bidirectional }).await? {
            Outcome::Opened(stream) => Ok(stream),
            _ => self.unexpected(),
        }
    }
    pub async fn send(
        &mut self,
        stream: StreamHandle,
        bytes: &[u8],
        fin: bool,
    ) -> Result<(), Error> {
        self.ready()?;
        self.engine
            .stream_apply(Command::Send {
                stream,
                bytes: Self::bytes(bytes)?,
                fin,
            })
            .await
    }
    pub async fn read(
        &mut self,
        stream: StreamHandle,
    ) -> Result<stream_owner::ReadResult<STREAM_FRAME_BYTES>, Error> {
        self.read_up_to(stream, STREAM_FRAME_BYTES).await
    }
    /// Copy at most maximum bytes, including across ring wrap. Consume only the
    /// returned bytes; remaining describes additional ready bytes in the owner.
    pub async fn read_up_to(
        &mut self,
        stream: StreamHandle,
        maximum: usize,
    ) -> Result<stream_owner::ReadResult<STREAM_FRAME_BYTES>, Error> {
        match self.request(Command::Read { stream, maximum }).await? {
            Outcome::Read(view) => Ok(view),
            _ => self.unexpected(),
        }
    }
    pub async fn consume(&mut self, stream: StreamHandle, count: usize) -> Result<(), Error> {
        self.ready()?;
        self.engine
            .stream_apply(Command::Consume { stream, count })
            .await
    }
    pub async fn acknowledge_reset(&mut self, stream: StreamHandle) -> Result<u64, Error> {
        match self.request(Command::AcknowledgeReset(stream)).await? {
            Outcome::ResetAcknowledged(code) => Ok(code),
            _ => self.unexpected(),
        }
    }
    pub async fn reset(&mut self, stream: StreamHandle, error_code: u64) -> Result<(), Error> {
        self.ready()?;
        self.engine
            .stream_apply(Command::Reset { stream, error_code })
            .await
    }
    pub async fn stop(&mut self, stream: StreamHandle, error_code: u64) -> Result<(), Error> {
        self.ready()?;
        self.engine
            .stream_apply(Command::Stop { stream, error_code })
            .await
    }
    pub async fn retire_stream(&mut self, stream: StreamHandle) -> Result<(), Error> {
        match self.request(Command::RetireStream(stream)).await? {
            Outcome::StreamRetired(_) => Ok(()),
            _ => return self.unexpected(),
        }
    }
    pub async fn lookup(&mut self, id: u64) -> Result<StreamHandle, Error> {
        match self.request(Command::Lookup { id }).await? {
            Outcome::Found(stream) => Ok(stream),
            _ => self.unexpected(),
        }
    }
    pub async fn inspect(
        &mut self,
        stream: StreamHandle,
    ) -> Result<stream_owner::StreamStatus, Error> {
        match self
            .request(Command::Inspect {
                stream: Some(stream),
            })
            .await?
        {
            Outcome::Inspected(Some(status)) => Ok(status),
            _ => self.unexpected(),
        }
    }
    pub async fn handles_after(
        &mut self,
        after_id: Option<u64>,
    ) -> Result<stream_owner::HandlePage, Error> {
        match self.request(Command::Handles { after_id }).await? {
            Outcome::Handles(page) => Ok(page),
            _ => self.unexpected(),
        }
    }
    /// Authorize a replay-safe complete request and retain its intent for the
    /// real Finished-gated acceptance/rejection reconciliation.
    pub async fn enqueue_early_request(
        &mut self,
        bytes: &[u8],
    ) -> Result<crate::early_send::Handle, Error> {
        self.active()?;
        if self.stream_snapshot().ready || !self.stream_snapshot().early_send_installed {
            return Err(Self::not_ready());
        }
        match self
            .engine
            .stream_request(Command::EnqueueEarly(Self::bytes(bytes)?))
            .await?
        {
            Outcome::EarlyEnqueued(handle) => Ok(handle),
            _ => self.unexpected(),
        }
    }
    pub async fn early_stream_id(
        &mut self,
        handle: crate::early_send::Handle,
    ) -> Result<u64, Error> {
        self.active()?;
        if self.stream_snapshot().ready || !self.stream_snapshot().early_send_installed {
            return Err(Self::not_ready());
        }
        match self
            .engine
            .stream_request(Command::InspectEarly(handle))
            .await?
        {
            Outcome::EarlyStreamId(id) => Ok(id),
            _ => self.unexpected(),
        }
    }
    /// Configure the actual Early owner's startup capability before input. Its
    /// caller-owned quarantine and replay storage stay with that role.
    pub fn configure_early_receive(
        &mut self,
        starter: handshake_endpoint::EarlyStarter<'tc, 'ts>,
    ) -> Result<(), Error> {
        self.engine.configure_early_receive(starter)
    }
    pub async fn receive(
        &mut self,
        datagram: &[u8],
        scratch: &mut [u8],
    ) -> Result<Received, Error> {
        self.engine.receive(datagram, scratch).await
    }
    pub async fn receive_from(
        &mut self,
        datagram: &[u8],
        scratch: &mut [u8],
        address: crate::path::Address,
        codepoint: Option<crate::ecn::Codepoint>,
    ) -> Result<Received, Error> {
        self.engine
            .receive_from(datagram, scratch, address, codepoint)
            .await
    }
    pub async fn receive_with_metadata(
        &mut self,
        datagram: &[u8],
        scratch: &mut [u8],
        metadata: crate::ecn::Metadata,
    ) -> Result<Received, Error> {
        self.engine
            .receive_with_metadata(datagram, scratch, metadata)
            .await
    }
    pub async fn timer(&mut self, now: u64) -> Result<(), Error> {
        self.engine.timer(now).await
    }
    /// Drain protocol output first. Tx then reserves the exact prepared frame
    /// and settles every actual adapter completion before returning.
    pub async fn transmit_with<A: UdpAdapter>(
        &mut self,
        adapter: &mut A,
    ) -> Result<Option<Transmit>, Error> {
        self.drain_early_data().await?;
        if let Some(output) = self.engine.transmit_with(adapter).await? {
            return Ok(Some(output));
        }
        if self.connection_state() != crate::lifecycle::State::Active || self.is_retired() {
            return Ok(None);
        }
        let early = !self.stream_snapshot().ready;
        if early
            && (!self.stream_snapshot().early_send_installed
                || !self.tls_snapshot().early_keys
                || self.tls_snapshot().one_rtt_keys)
        {
            return Ok(None);
        }
        let Some(frame) = self.engine.stream_prepare(early).await? else {
            return Ok(None);
        };
        self.engine.transmit_application_with(frame, adapter).await
    }
    pub async fn drain_early_data(&mut self) -> Result<bool, Error> {
        if self.connection_state() != crate::lifecycle::State::Active || self.is_retired() {
            return Ok(false);
        }
        self.engine.release_early().await?;
        Ok(self.engine.has_pending_early_release())
    }
    pub fn pending_application_work(&self) -> bool {
        let s = self.stream_snapshot();
        self.connection_state() == crate::lifecycle::State::Active
            && !self.is_retired()
            && (s.pending_transmission
                || s.early_intent
                || s.queued_chunks != 0
                || s.control_count != 0
                || self.engine.has_pending_early_release())
    }
    pub async fn initiate_key_update(&mut self) -> Result<(), Error> {
        self.engine.initiate_key_update().await
    }
    pub async fn initiate_close(
        &mut self,
        reason: crate::lifecycle::CloseReason,
    ) -> Result<(), Error> {
        self.engine.close(reason).await
    }
    pub async fn retire_owned(&mut self) -> Result<(), Error> {
        self.engine.retire_owned().await
    }
    pub fn close(&mut self) {
        self.engine.retire();
    }
    pub fn handshake_complete(&self) -> bool {
        self.engine.handshake_complete()
    }
    pub fn is_retired(&self) -> bool {
        self.engine.is_retired()
    }
    pub fn connection_state(&self) -> crate::lifecycle::State {
        self.engine.connection_state()
    }
    pub fn idle_deadline(&self) -> Option<u64> {
        self.engine.idle_deadline()
    }
    pub fn close_deadline(&self) -> Option<u64> {
        self.engine.close_deadline()
    }
    pub fn next_deadline(&self) -> Option<u64> {
        self.engine.next_deadline()
    }
    pub fn peer_close(&self) -> Option<handshake_endpoint::PeerClose> {
        self.engine.peer_close()
    }
    pub fn tls_snapshot(&self) -> &crate::roles::tls_owner::Snapshot<512> {
        self.engine.tls_snapshot()
    }
    pub fn key_generation(&self) -> u64 {
        self.tls_snapshot().send_generation
    }
    pub fn receive_key_generation(&self) -> u64 {
        self.tls_snapshot().receive_generation
    }
    pub fn negotiated_group(&self) -> Option<u16> {
        self.tls_snapshot().negotiated_group
    }
    pub fn admitted_early_packets(&self) -> u64 {
        self.engine.admitted_early_packets()
    }
    pub fn path_identity(&self) -> crate::ecn::PathIdentity {
        self.engine.path_identity()
    }
    pub fn ecn_snapshot(&self) -> crate::ecn::Snapshot {
        self.engine.ecn_snapshot()
    }
    pub fn enable_ecn(&mut self) -> Result<(), Error> {
        self.engine.enable_ecn()
    }
    pub fn issued_local_cids(&self) -> impl Iterator<Item = crate::connection_id::Cid> + '_ {
        self.engine.issued_local_cids()
    }
    pub fn network_path_state(&self) -> Option<(crate::ecn::PathIdentity, crate::path::Snapshot)> {
        self.engine.network_path_state()
    }
    pub fn enable_trace(
        &mut self,
        buffer: &'s mut [u8],
    ) -> Result<(), handshake_endpoint::TraceSetupError> {
        self.engine.enable_trace(buffer)
    }
    pub fn trace_status(&self) -> Option<handshake_endpoint::TraceStatus> {
        self.engine.trace_status()
    }
    pub fn trace_pending(&self) -> &[u8] {
        self.engine.trace_pending()
    }
    pub fn consume_trace(&mut self, bytes: usize) -> Result<(), crate::trace::Error> {
        self.engine.consume_trace(bytes)
    }
    pub fn mark_trace_sink_failed(&mut self) {
        self.engine.mark_trace_sink_failed();
    }
}
