//! Protected output and affine evidence of the real UDP adapter's result.
//! Only the Tx encoder constructs a protected datagram, from an actual key
//! owner's sealed packet and the immutable frame selected by its data owner.
//! Planned publication or a copied reservation ID is never acceptance.
use super::{
    packet_protection::Descriptor,
    path_owner::{Control, Destination, PREFERRED_ADVERTISEMENT_BYTES, PendingTransmit},
    recovery_owner::SendTicket,
    sealed_packet::SealedPacket,
    stream_owner::{PreparedFrame, TransmissionId},
};
use crate::{
    accounting::{PacketNumber, PacketNumberSpace},
    crypto::KeyKind,
    ecn::Codepoint,
    packet::{EncryptionLevel, Frame, FrameIter, ParseLimits},
    path::{Address, PathIdentity},
};
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Binding,
    Capacity,
    Frame,
    Header,
}

/// Immutable, owner-protected wire bytes. There is no public constructor or
/// mutable byte access, and storage is wiped when its submission scope ends.
pub struct ProtectedDatagram<const N: usize> {
    bytes: [u8; N],
    len: usize,
    path_descriptor: Descriptor,
    path: PathIdentity,
    address: Address,
    destination: Destination,
    control: Option<Control>,
    recovery: SendTicket,
    stream: Option<TransmissionId>,
    ecn: Codepoint,
    source_cid: Option<Destination>,
    handshake_crypto: Option<HandshakeFragment>,
}
impl<const N: usize> Drop for ProtectedDatagram<N> {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}
impl<const N: usize> ProtectedDatagram<N> {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
    pub const fn packet(&self) -> PacketNumber {
        self.recovery.packet()
    }
    pub const fn ecn(&self) -> Codepoint {
        self.ecn
    }
    pub(crate) fn matches(&self, pending: &PendingTransmit) -> bool {
        self.path_descriptor == pending.descriptor()
            && self.path == pending.path()
            && self.address == pending.address()
            && self.destination == pending.destination()
            && self.control == pending.control()
            && self.len as u64 == pending.bytes()
            && self.packet() == pending.packet()
    }
    /// The encoder passes its exact pre-AEAD plaintext, not a claimed control
    /// flag. The owning key has independently bound these bytes in SealedPacket.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_sealed<const M: usize>(
        pending: &PendingTransmit,
        recovery: SendTicket,
        application: Option<(TransmissionId, &PreparedFrame<M>)>,
        ecn: Codepoint,
        sealed: SealedPacket<N>,
        plaintext: &[u8],
        pn_offset: usize,
        mask: [u8; 5],
    ) -> Result<Self, Error> {
        if sealed.generation() != pending.descriptor().generation
            || sealed.generation() != recovery.descriptor().generation
            || sealed.packet_number() != recovery.packet().value
            || pending.packet() != recovery.packet()
            || !sealed.authenticates_plaintext(plaintext)
            || sealed.bytes().len() as u64 != pending.bytes()
        {
            return Err(Error::Binding);
        }
        let level = match sealed.kind() {
            KeyKind::Initial => EncryptionLevel::Initial,
            KeyKind::Handshake => EncryptionLevel::Handshake,
            KeyKind::ZeroRtt => EncryptionLevel::ZeroRtt,
            KeyKind::OneRtt => EncryptionLevel::OneRtt,
        };
        let kind = match sealed.kind() {
            KeyKind::Initial => crate::accounting::PacketKind::Initial,
            KeyKind::Handshake => crate::accounting::PacketKind::Handshake,
            KeyKind::ZeroRtt => crate::accounting::PacketKind::ZeroRtt,
            KeyKind::OneRtt => crate::accounting::PacketKind::OneRtt,
        };
        if recovery.kind() != kind || recovery.bytes() != sealed.bytes().len() as u64 {
            return Err(Error::Binding);
        }
        let mut packets = crate::packet::PacketIter::new(
            sealed.bytes(),
            pending.destination().as_bytes().len(),
            1,
        )
        .map_err(|_| Error::Header)?;
        let packet = packets
            .next()
            .ok_or(Error::Header)?
            .map_err(|_| Error::Header)?;
        if packets.next().is_some() {
            return Err(Error::Header);
        }
        let source_cid = match packet.header {
            crate::packet::Header::Long { source_id, .. } => {
                if source_id != pending.source_cid().as_bytes() {
                    return Err(Error::Binding);
                }
                Some(pending.source_cid())
            }
            _ => None,
        };
        let destination_id = match packet.header {
            crate::packet::Header::Long { destination_id, .. }
            | crate::packet::Header::Short { destination_id, .. } => destination_id,
            _ => return Err(Error::Header),
        };
        if destination_id != pending.destination().as_bytes() {
            return Err(Error::Binding);
        }
        let wire_kind = match packet.header {
            crate::packet::Header::Long {
                kind: crate::packet::LongType::Initial,
                packet_number_offset,
                ..
            } if packet_number_offset == pn_offset => crate::accounting::PacketKind::Initial,
            crate::packet::Header::Long {
                kind: crate::packet::LongType::Handshake,
                packet_number_offset,
                ..
            } if packet_number_offset == pn_offset => crate::accounting::PacketKind::Handshake,
            crate::packet::Header::Long {
                kind: crate::packet::LongType::ZeroRtt,
                packet_number_offset,
                ..
            } if packet_number_offset == pn_offset => crate::accounting::PacketKind::ZeroRtt,
            crate::packet::Header::Short {
                packet_number_offset,
                ..
            } if packet_number_offset == pn_offset => crate::accounting::PacketKind::OneRtt,
            _ => return Err(Error::Header),
        };
        if wire_kind != kind {
            return Err(Error::Binding);
        }
        let space = match sealed.kind() {
            KeyKind::Initial => PacketNumberSpace::Initial,
            KeyKind::Handshake => PacketNumberSpace::Handshake,
            _ => PacketNumberSpace::ApplicationData,
        };
        if recovery.packet().space != space {
            return Err(Error::Binding);
        }
        let expected_app = if let Some((id, prepared)) = application {
            if id.generation() != sealed.generation()
                || id.packet_number() != recovery.packet().value
                || id.prepared_id() != prepared.id()
                || prepared.is_early() != matches!(sealed.kind(), KeyKind::ZeroRtt)
                || prepared.is_probe() != recovery.is_pto_probe()
            {
                return Err(Error::Binding);
            }
            let mut frames = FrameIter::new(prepared.bytes(), level, ParseLimits::default())
                .map_err(|_| Error::Frame)?;
            let frame = frames
                .next()
                .ok_or(Error::Frame)?
                .map_err(|_| Error::Frame)?;
            if frames.next().is_some() {
                return Err(Error::Frame);
            }
            Some(frame)
        } else {
            None
        };
        let mut control_count = 0usize;
        let mut app_count = 0usize;
        let mut flight_count = 0usize;
        let mut handshake_crypto = None;
        let mut ack_eliciting = false;
        let mut padded = false;
        for frame in
            FrameIter::new(plaintext, level, ParseLimits::default()).map_err(|_| Error::Frame)?
        {
            let frame = frame.map_err(|_| Error::Frame)?;
            ack_eliciting |= frame.ack_eliciting();
            padded |= matches!(frame, Frame::Padding { .. });
            match frame {
                Frame::Crypto { offset, data } => {
                    let binding = recovery.flight().ok_or(Error::Binding)?;
                    let tls_level = match level {
                        EncryptionLevel::Initial => crate::tls::Level::Initial,
                        EncryptionLevel::Handshake => crate::tls::Level::Handshake,
                        _ => crate::tls::Level::OneRtt,
                    };
                    if binding.is_handshake_done()
                        || binding.level() != tls_level
                        || !binding.matches_crypto(offset, data)
                    {
                        return Err(Error::Binding);
                    }
                    if level == EncryptionLevel::Handshake {
                        handshake_crypto = HandshakeFragment::prefix(offset, data);
                    }
                    flight_count += 1;
                }
                Frame::HandshakeDone => {
                    if !recovery
                        .flight()
                        .is_some_and(|binding| binding.is_handshake_done())
                    {
                        return Err(Error::Binding);
                    }
                    flight_count += 1;
                }
                _ => {}
            }
            let path_control = match frame {
                Frame::PathChallenge { data } => Some(Control::Challenge(*data)),
                Frame::PathResponse { data } => Some(Control::Response(*data)),
                Frame::NewConnectionId {
                    sequence,
                    retire_prior_to,
                    id,
                    reset_token,
                } => Some(Control::NewConnectionId {
                    sequence,
                    retire_prior_to,
                    cid: crate::connection_id::Cid::new(id).map_err(|_| Error::Frame)?,
                    reset_token: crate::connection_id::ResetToken::new(*reset_token),
                }),
                Frame::RetireConnectionId { sequence } => {
                    Some(Control::RetireConnectionId { sequence })
                }
                _ => None,
            };
            if let Some(control) = path_control {
                if Some(control) != pending.control() {
                    return Err(Error::Binding);
                }
                control_count += 1;
            }
            if Some(frame) == expected_app {
                app_count += 1;
            }
            if managed_application_frame(frame) && Some(frame) != expected_app {
                return Err(Error::Binding);
            }
        }
        if control_count != usize::from(pending.control().is_some())
            || app_count != usize::from(application.is_some())
            || flight_count != usize::from(recovery.flight().is_some())
            || ack_eliciting != recovery.ack_eliciting()
            || (ack_eliciting || padded) != recovery.in_flight()
        {
            return Err(Error::Binding);
        }
        let pn_len = usize::from(sealed.header().first().ok_or(Error::Header)? & 3) + 1;
        if pn_offset.checked_add(pn_len) != Some(sealed.header().len())
            || pn_offset
                .checked_add(4 + 16)
                .is_none_or(|n| n > sealed.bytes().len())
        {
            return Err(Error::Header);
        }
        let encoded_pn = sealed.header()[pn_offset..]
            .iter()
            .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
        let pn_mask = (1u64 << (pn_len * 8)) - 1;
        if encoded_pn != (recovery.packet().value & pn_mask) {
            return Err(Error::Binding);
        }
        let mut bytes = [0; N];
        let len = sealed.bytes().len();
        bytes[..len].copy_from_slice(sealed.bytes());
        bytes[0] ^= mask[0] & if bytes[0] & 0x80 != 0 { 0x0f } else { 0x1f };
        for n in 0..pn_len {
            bytes[pn_offset + n] ^= mask[1 + n];
        }
        Ok(Self {
            bytes,
            len,
            path_descriptor: pending.descriptor(),
            path: pending.path(),
            address: pending.address(),
            destination: pending.destination(),
            control: pending.control(),
            recovery,
            stream: application.map(|a| a.0),
            ecn,
            source_cid,
            handshake_crypto,
        })
    }
}
fn managed_application_frame(frame: Frame<'_>) -> bool {
    matches!(
        frame,
        Frame::Stream { .. }
            | Frame::ResetStream { .. }
            | Frame::StopSending { .. }
            | Frame::MaxData { .. }
            | Frame::MaxStreamData { .. }
            | Frame::MaxStreams { .. }
            | Frame::DataBlocked { .. }
            | Frame::StreamDataBlocked { .. }
            | Frame::StreamsBlocked { .. }
    )
}

#[derive(Debug)]
pub struct RecoveryCompletion {
    ticket: SendTicket,
    accepted_at: Option<u64>,
    ecn: Codepoint,
    path: PathIdentity,
}
impl RecoveryCompletion {
    pub const fn ticket(&self) -> SendTicket {
        self.ticket
    }
    pub const fn accepted_at(&self) -> Option<u64> {
        self.accepted_at
    }
    pub const fn ecn(&self) -> Codepoint {
        self.ecn
    }
    pub const fn path(&self) -> Option<PathIdentity> {
        Some(self.path)
    }
}
#[derive(Debug)]
pub struct StreamCompletion {
    transmission: TransmissionId,
    accepted: bool,
}
impl StreamCompletion {
    pub const fn transmission(&self) -> TransmissionId {
        self.transmission
    }
    pub const fn accepted(&self) -> bool {
        self.accepted
    }
}
/// Bounded outgoing EE prefix retained only from exact flight-bound CRYPTO
/// bytes authenticated by the sealing owner. The engine currently supplies
/// FlightCommand::Store bytes, so this proves actual transmitted bytes, not a
/// separate theorem that the TLS Provider originally emitted them.
const ADVERTISEMENT_BYTES: usize = PREFERRED_ADVERTISEMENT_BYTES;
struct HandshakeFragment {
    offset: usize,
    len: usize,
    bytes: [u8; ADVERTISEMENT_BYTES],
}
impl HandshakeFragment {
    fn prefix(offset: u64, data: &[u8]) -> Option<Self> {
        let offset = usize::try_from(offset).ok()?;
        if offset >= ADVERTISEMENT_BYTES || data.is_empty() {
            return None;
        }
        let len = data.len().min(ADVERTISEMENT_BYTES - offset);
        let mut result = Self {
            offset,
            len,
            bytes: [0; ADVERTISEMENT_BYTES],
        };
        result.bytes[..len].copy_from_slice(&data[..len]);
        Some(result)
    }
}
impl Drop for HandshakeFragment {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}
/// Affine evidence minted at the actual successful UDP boundary. Constructors
/// and fragment storage stay private to this module; Path can only inspect it.
pub(crate) struct AcceptedAdvertisement {
    generation: u64,
    source_cid: Option<Destination>,
    handshake_crypto: Option<HandshakeFragment>,
}
impl core::fmt::Debug for AcceptedAdvertisement {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AcceptedAdvertisement")
            .field("generation", &self.generation)
            .field("source_cid", &self.source_cid)
            .field(
                "crypto_range",
                &self.handshake_crypto.as_ref().map(|p| (p.offset, p.len)),
            )
            .finish_non_exhaustive()
    }
}
impl AcceptedAdvertisement {
    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }
    pub(crate) const fn source_cid(&self) -> Option<Destination> {
        self.source_cid
    }
    pub(crate) fn handshake_crypto(&self) -> Option<(usize, &[u8])> {
        self.handshake_crypto
            .as_ref()
            .map(|p| (p.offset, &p.bytes[..p.len]))
    }
}
#[derive(Debug)]
pub struct PathCompletion {
    pending: PendingTransmit,
    accepted_at: Option<u64>,
    advertisement: Option<AcceptedAdvertisement>,
}
impl PathCompletion {
    pub(crate) fn into_parts(
        self,
    ) -> (PendingTransmit, Option<u64>, Option<AcceptedAdvertisement>) {
        (self.pending, self.accepted_at, self.advertisement)
    }
}
#[must_use = "every actual adapter outcome must reach each owning domain"]
pub struct Completions {
    pub recovery: RecoveryCompletion,
    pub stream: Option<StreamCompletion>,
    pub path: PathCompletion,
}

/// Called only at the real adapter return boundary, under its cancellation
/// guard. It is not exposed to external callers as an acceptance constructor.
pub(crate) fn complete<const N: usize>(
    pending: PendingTransmit,
    mut protected: ProtectedDatagram<N>,
    accepted_at: Option<u64>,
) -> Result<Completions, Error> {
    if !protected.matches(&pending) {
        return Err(Error::Binding);
    }
    let advertisement = accepted_at.map(|_| AcceptedAdvertisement {
        generation: protected.path_descriptor.generation,
        source_cid: protected.source_cid,
        handshake_crypto: protected.handshake_crypto.take(),
    });
    Ok(Completions {
        recovery: RecoveryCompletion {
            ticket: protected.recovery,
            accepted_at,
            ecn: protected.ecn,
            path: protected.path,
        },
        stream: protected.stream.map(|transmission| StreamCompletion {
            transmission,
            accepted: accepted_at.is_some(),
        }),
        path: PathCompletion {
            pending,
            accepted_at,
            advertisement,
        },
    })
}
#[derive(Debug)]
pub struct RecoveryCancellation {
    ticket: SendTicket,
}
impl RecoveryCancellation {
    pub const fn ticket(&self) -> SendTicket {
        self.ticket
    }
}
#[derive(Debug)]
pub struct StreamCancellation {
    transmission: TransmissionId,
}
impl StreamCancellation {
    pub const fn transmission(&self) -> TransmissionId {
        self.transmission
    }
}
#[must_use]
pub struct Cancellations {
    pub recovery: RecoveryCancellation,
    pub stream: Option<StreamCancellation>,
    pub path: PathCompletion,
}
/// Consumes the still-unsubmitted affine path reservation. A retained copied
/// send ID alone cannot cancel a publication already owned by its UDP future.
pub(crate) fn cancel_before_publication(
    pending: PendingTransmit,
    recovery: SendTicket,
    stream: Option<TransmissionId>,
) -> Result<Cancellations, Error> {
    if pending.packet() != recovery.packet()
        || pending.descriptor().generation != recovery.descriptor().generation
        || stream.is_some_and(|s| {
            s.packet_number() != recovery.packet().value
                || s.generation() != recovery.descriptor().generation
        })
    {
        return Err(Error::Binding);
    }
    Ok(Cancellations {
        recovery: RecoveryCancellation { ticket: recovery },
        stream: stream.map(|transmission| StreamCancellation { transmission }),
        path: PathCompletion {
            pending,
            accepted_at: None,
            advertisement: None,
        },
    })
}
