//! Direct projected locals for the early-byte lifetime. No phase discriminator.
use super::global as p;
use super::imp::{EarlyStatus, Error, HeldBytes, QuarantineSlot, ServerPolicy};
use crate::crypto::directional::ApplicationKeyScope;
use crate::quic::imp::kernel::packet::EncryptionLevel;
use crate::quic::imp::kernel::packet::Frame;
use crate::quic::imp::kernel::packet::FrameIter;
use crate::quic::imp::kernel::packet::ParseLimits;
use crate::quic::imp::tls::Inbox;
use hibana::Endpoint;
use hibana_tls::handshake::local::keys::FinishedAuthenticated;
use hibana_tls::schedule::Side;
use hibana_tls::secret::Erase;

#[derive(Debug)]
pub enum Failure {
    Endpoint(hibana::EndpointError),
    Bytes(Error),
    Binding,
}
impl From<hibana::EndpointError> for Failure {
    fn from(e: hibana::EndpointError) -> Self {
        Self::Endpoint(e)
    }
}
impl From<Error> for Failure {
    fn from(e: Error) -> Self {
        Self::Bytes(e)
    }
}

/// Created only by the authenticated receive boundary, never by a wire label.
pub struct AuthenticatedInput<'scope, const N: usize> {
    pub(crate) scope: &'scope ApplicationKeyScope,
    pub(crate) generation: u64,
    pub(crate) packet: u64,
    pub(crate) bytes: [u8; N],
    pub(crate) len: usize,
    pub(crate) ecn: Option<crate::quic::ecn::imp::Codepoint>,
}
impl<const N: usize> Drop for AuthenticatedInput<'_, N> {
    fn drop(&mut self) {
        self.bytes.erase();
    }
}
/// Proof that every authenticated frame in this packet was retained by the
/// quarantine owner. This authorizes ACK accounting only after real Finished.
#[must_use]
pub struct StoredPacket<'scope> {
    scope: &'scope ApplicationKeyScope,
    generation: u64,
    packet: u64,
    ack_eliciting: bool,
    ecn: Option<crate::quic::ecn::imp::Codepoint>,
}
impl<'scope> StoredPacket<'scope> {
    pub(crate) fn ecn(&self) -> Option<crate::quic::ecn::imp::Codepoint> {
        self.ecn
    }
    pub(crate) fn scope(&self) -> &'scope ApplicationKeyScope {
        self.scope
    }
    pub fn packet_number(&self) -> u64 {
        self.packet
    }
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
    pub(crate) fn ack_eliciting(&self) -> bool {
        self.ack_eliciting
    }
}

pub struct Range<const N: usize> {
    pub id: u64,
    pub offset: u64,
    pub fin: bool,
    pub(crate) bytes: [u8; N],
    pub(crate) len: usize,
}
impl<const N: usize> Drop for Range<N> {
    fn drop(&mut self) {
        self.bytes.erase();
    }
}
pub struct ControlBlock<const N: usize> {
    pub(crate) bytes: [u8; N],
    pub(crate) len: usize,
}
impl<const N: usize> Drop for ControlBlock<N> {
    fn drop(&mut self) {
        self.bytes.erase();
    }
}
pub struct Exchange<'scope, const N: usize> {
    pub(crate) input: Inbox<AuthenticatedInput<'scope, N>>,
    stored: Inbox<StoredPacket<'scope>>,
    pub(crate) finished: Inbox<FinishedAuthenticated<'scope>>,
    pub(crate) returned_finished: Inbox<FinishedAuthenticated<'scope>>,
    pub(crate) output: Inbox<Range<N>>,
    pub(crate) controls: Inbox<ControlBlock<N>>,
}
impl<const N: usize> Exchange<'_, N> {
    pub const fn new() -> Self {
        Self {
            input: Inbox::new(),
            stored: Inbox::new(),
            finished: Inbox::new(),
            returned_finished: Inbox::new(),
            output: Inbox::new(),
            controls: Inbox::new(),
        }
    }
}

impl<const N: usize> Default for Exchange<'_, N> {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run<'scope, const BYTES: usize, const PACKET: usize>(
    endpoint: &mut Endpoint<'_, { p::OWNER }>,
    admission: Admission<'scope>,
    policy: ServerPolicy,
    slots: &mut [QuarantineSlot<BYTES>],
    exchange: &Exchange<'scope, PACKET>,
) -> Result<(), Failure> {
    let (scope, limits, claim) = admission.into_parts();
    let generation = claim.generation();
    let mut held = HeldBytes::new(policy, limits, claim, slots)?;
    let mut deferred = hibana_tls::secret::Secret::new([0u8; PACKET]);
    let mut deferred_len = 0usize;
    loop {
        let offered = endpoint.offer().await?;
        match offered.label() {
            0 => {
                let packet = offered.recv::<p::Packet>().await?;
                let input = exchange.input.take().map_err(|_| Failure::Binding)?;
                if !core::ptr::eq(input.scope, scope)
                    || input.generation != generation
                    || input.packet != packet
                    || input.len > PACKET
                {
                    return Err(Failure::Binding);
                }
                match held.preflight_authenticated_packet(generation, &input.bytes[..input.len]) {
                    Ok(()) => {}
                    Err(Error::Capacity) => {
                        endpoint.send::<p::PacketDropped>(&packet).await?;
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                }
                // Retain every non-data control before committing either ledger.
                // Capacity pressure drops the complete packet without admitting it.
                let mut extra = hibana_tls::secret::Secret::new([0u8; PACKET]);
                let mut extra_len = 0usize;
                let mut fits = true;
                for frame in FrameIter::new(
                    &input.bytes[..input.len],
                    EncryptionLevel::ZeroRtt,
                    ParseLimits {
                        max_frames: 128,
                        ..ParseLimits::default()
                    },
                )
                .map_err(Error::Packet)?
                {
                    let frame = frame.map_err(Error::Packet)?;
                    if matches!(
                        frame,
                        Frame::Stream { .. } | Frame::Ping | Frame::Padding { .. }
                    ) {
                        continue;
                    }
                    match crate::quic::imp::kernel::packet::encode_frame(
                        &frame,
                        &mut extra[extra_len..],
                    ) {
                        Ok(n) => extra_len += n,
                        Err(crate::quic::imp::kernel::packet::Error::BufferTooShort) => {
                            fits = false;
                            break;
                        }
                        Err(error) => return Err(Error::Packet(error).into()),
                    }
                }
                if !fits || extra_len > PACKET - deferred_len {
                    endpoint.send::<p::PacketDropped>(&packet).await?;
                    continue;
                }
                let mut ack_eliciting = false;
                for frame in FrameIter::new(
                    &input.bytes[..input.len],
                    EncryptionLevel::ZeroRtt,
                    ParseLimits {
                        max_frames: 128,
                        ..ParseLimits::default()
                    },
                )
                .map_err(Error::Packet)?
                {
                    let frame = frame.map_err(Error::Packet)?;
                    ack_eliciting |= frame.ack_eliciting();
                    match frame {
                        Frame::Stream {
                            id,
                            offset,
                            fin,
                            data,
                        } => held.buffer_authenticated_stream(generation, id, offset, data, fin)?,
                        other => held.buffer_authenticated_control(generation, other)?,
                    }
                }
                deferred[deferred_len..deferred_len + extra_len]
                    .copy_from_slice(&extra[..extra_len]);
                deferred_len += extra_len;
                exchange
                    .stored
                    .put(StoredPacket {
                        scope: input.scope,
                        generation: input.generation,
                        packet: input.packet,
                        ack_eliciting,
                        ecn: input.ecn,
                    })
                    .map_err(|_| Failure::Binding)?;
                endpoint.send::<p::PacketStored>(&packet).await?;
            }
            3 => {
                let id = offered.recv::<p::InputEnd>().await?;
                if id != generation {
                    return Err(Failure::Binding);
                }
                endpoint.send::<p::InputEnded>(&generation).await?;
                break;
            }
            _ => return Err(Failure::Binding),
        }
    }
    let offered = endpoint.offer().await?;
    match offered.label() {
        6 => {
            if offered.recv::<p::Verified>().await? != generation {
                return Err(Failure::Binding);
            }
            let finished = exchange.finished.take().map_err(|_| Failure::Binding)?;
            if !core::ptr::eq(finished.scope(), scope)
                || finished.side() != Side::Server
                || finished.early_status() != EarlyStatus::Accepted
                || finished.early_generation() != Some(generation)
            {
                return Err(Failure::Binding);
            }
            exchange
                .returned_finished
                .put(finished)
                .map_err(|_| Failure::Binding)?;
            endpoint.send::<p::VerifiedTaken>(&generation).await?;
            if deferred_len != 0 {
                let mut bytes = [0; PACKET];
                bytes[..deferred_len].copy_from_slice(&deferred[..deferred_len]);
                exchange
                    .controls
                    .put(ControlBlock {
                        bytes,
                        len: deferred_len,
                    })
                    .map_err(|_| Failure::Binding)?;
                endpoint.send::<p::Controls>(&generation).await?;
                if endpoint.recv::<p::ControlsApplied>().await? != generation
                    || !exchange.controls.is_empty()
                {
                    return Err(Failure::Binding);
                }
                deferred.erase();
            }

            while let Some(view) = held.next_release()? {
                if view.bytes.len() > PACKET {
                    return Err(Error::Capacity.into());
                }
                let mut bytes = [0; PACKET];
                bytes[..view.bytes.len()].copy_from_slice(view.bytes);
                let id = view.stream_id;
                let ticket = view.ticket;
                exchange
                    .output
                    .put(Range {
                        id,
                        offset: view.offset,
                        fin: view.fin,
                        bytes,
                        len: view.bytes.len(),
                    })
                    .map_err(|_| Failure::Binding)?;
                endpoint.send::<p::Range>(&id).await?;
                if endpoint.recv::<p::RangeApplied>().await? != id || !exchange.output.is_empty() {
                    return Err(Failure::Binding);
                }
                held.complete_release(ticket)?;
            }
            endpoint.send::<p::Released>(&generation).await?;
            if endpoint.recv::<p::ReleaseSeen>().await? != generation {
                return Err(Failure::Binding);
            }
            drop(held);
        }
        8 => {
            if offered.recv::<p::Reject>().await? != generation {
                return Err(Failure::Binding);
            }
            drop(held);
            endpoint.send::<p::Discarded>(&generation).await?;
            if endpoint.recv::<p::DiscardSeen>().await? != generation {
                return Err(Failure::Binding);
            }
        }
        9 => {
            if offered.recv::<p::Cancel>().await? != generation {
                return Err(Failure::Binding);
            }
            drop(held);
            endpoint.send::<p::Discarded>(&generation).await?;
            if endpoint.recv::<p::DiscardSeen>().await? != generation {
                return Err(Failure::Binding);
            }
        }
        _ => return Err(Failure::Binding),
    }
    endpoint.send::<p::Retired>(&generation).await?;
    Ok(())
}

pub use hibana_tls::handshake::local::keys::Admission;
impl<'scope, const N: usize> AuthenticatedInput<'scope, N> {
    pub fn packet_number(&self) -> u64 {
        self.packet
    }
    pub fn from_authentication(
        receipt: hibana_tls::handshake::local::keys::AuthenticatedEarlyRead<'scope>,
        generation: u64,
        plaintext: &[u8],
        ecn: Option<crate::quic::ecn::imp::Codepoint>,
    ) -> Result<Self, Failure> {
        if plaintext.len() > N || !receipt.authenticates_plaintext(plaintext) {
            return Err(Failure::Binding);
        }
        let mut bytes = [0; N];
        bytes[..plaintext.len()].copy_from_slice(plaintext);
        Ok(Self {
            scope: receipt.scope(),
            generation,
            packet: receipt.packet_number(),
            bytes,
            len: plaintext.len(),
            ecn,
        })
    }
}
impl<const N: usize> Range<N> {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
impl<const N: usize> ControlBlock<N> {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
impl<'scope, const N: usize> Exchange<'scope, N> {
    pub fn take_stored(&self) -> Result<StoredPacket<'scope>, Failure> {
        self.stored.take().map_err(|_| Failure::Binding)
    }
    pub fn store_input(&self, value: AuthenticatedInput<'scope, N>) -> Result<(), Failure> {
        self.input.put(value).map_err(|_| Failure::Binding)
    }
    pub fn store_finished(&self, value: FinishedAuthenticated<'scope>) -> Result<(), Failure> {
        self.finished.put(value).map_err(|_| Failure::Binding)
    }
    pub fn take_finished(&self) -> Result<FinishedAuthenticated<'scope>, Failure> {
        self.returned_finished.take().map_err(|_| Failure::Binding)
    }
    pub fn take_range(&self) -> Result<Range<N>, Failure> {
        self.output.take().map_err(|_| Failure::Binding)
    }
    pub fn take_controls(&self) -> Result<ControlBlock<N>, Failure> {
        self.controls.take().map_err(|_| Failure::Binding)
    }
}
