//! RECONSTRUCTED AFTER EXECUTOR RESET; UNVERIFIED.
//! Bounded packet-scoped authority shared by independently owned effect domains.
//!
//! The arena retains the actual affine receipt minted by a key owner. Wire IDs
//! are observations, not authentication: every grant is checked against live
//! packet/effect records. This is a numeric authority table, not a replacement
//! for the projected roles' ordering. Interior borrows never cross an await.
use crate::{accounting::PacketNumberSpace, crypto::KeyKind, tls::Level};
use core::cell::RefCell;
use zeroize::Zeroize;
pub const AUTHENTICATED_PAYLOAD_CAPACITY: usize = 1536;

pub mod scoped;
pub use scoped::{
    RecoveryBinding, ScopedAckGrant, ScopedArena, ScopedDeliveryGrant, ScopedPacketTicket,
    ScopedReceiveEvidence,
};

/// Only successful ordinary packet opens can enter this arena. Early data has
/// a separate quarantine and cannot authorize ordinary ACK/STREAM/path effects.
pub enum ReceiveEvidence {
    Initial(super::packet_protection::OpenReceipt),
    Tls(super::tls_owner::OpenReceipt),
    /// Opaque evidence consumed from the actual scoped directional RX owner.
    Directional(scoped::DirectionalReceiveEvidence),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    WrongGeneration,
    UnsupportedProtection,
    PacketCapacity,
    EffectCapacity,
    InvalidPacket,
    InvalidGrant,
    OutstandingEffects,
    SequenceExhausted,
    InvalidFrame,
    AckCapacity,
    FrameCapacity,
}

/// A copied observation returned only after checking live authentication.
/// No mutation API accepts this value as authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedPacket {
    generation: u64,
    operation_id: u64,
    space: PacketNumberSpace,
    packet_number: u64,
    key_generation: u64,
}
impl AuthenticatedPacket {
    pub const fn generation(self) -> u64 {
        self.generation
    }
    pub const fn operation_id(self) -> u64 {
        self.operation_id
    }
    pub const fn space(self) -> PacketNumberSpace {
        self.space
    }
    pub const fn packet_number(self) -> u64 {
        self.packet_number
    }
    pub const fn key_generation(self) -> u64 {
        self.key_generation
    }
}
impl ReceiveEvidence {
    fn facts(&self) -> Result<AuthenticatedPacket, Error> {
        let (generation, operation_id, space, packet_number, key_generation) = match self {
            Self::Initial(opened) if opened.kind() == KeyKind::Initial => (
                opened.generation(),
                opened.operation_id(),
                PacketNumberSpace::Initial,
                opened.packet_number(),
                0,
            ),
            Self::Tls(opened) => (
                opened.generation(),
                opened.operation_id(),
                match opened.level() {
                    Level::Handshake => PacketNumberSpace::Handshake,
                    Level::OneRtt => PacketNumberSpace::ApplicationData,
                    Level::Initial => return Err(Error::UnsupportedProtection),
                },
                opened.packet_number(),
                opened.key_generation(),
            ),
            Self::Directional(opened) => return Ok(opened.facts()),
            _ => return Err(Error::UnsupportedProtection),
        };
        Ok(AuthenticatedPacket {
            generation,
            operation_id,
            space,
            packet_number,
            key_generation,
        })
    }
}

/// Exact SCID/DCID from a successfully opened Initial's AEAD header. Initial
/// protection is public-key-derived integrity, not TLS peer identity.
pub struct InitialPeerCid {
    id: EffectId,
    generation: u64,
    source: super::path_owner::Destination,
    destination: super::path_owner::Destination,
}
impl InitialPeerCid {
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub fn source_cid(&self) -> &[u8] {
        self.source.as_bytes()
    }
    pub fn destination_cid(&self) -> &[u8] {
        self.destination.as_bytes()
    }
}
/// One committed transport Retry, separate from ordinary peer-SCID learning.
pub struct RetryPeerCid {
    generation: u64,
    retry: crate::retry::CommittedRetry,
}
impl RetryPeerCid {
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub fn source_cid(&self) -> &[u8] {
        self.retry.source_id()
    }
    pub fn original_destination_cid(&self) -> &[u8] {
        self.retry.original_destination_id()
    }
    pub fn client_source_cid(&self) -> &[u8] {
        self.retry.client_source_id()
    }
    pub(crate) fn from_committed(generation: u64, retry: crate::retry::CommittedRetry) -> Self {
        Self { generation, retry }
    }
}

/// Distinct domain permissions split from one actual committed Retry.
/// CommittedRetry and all three public grants are affine: a domain cannot
/// recreate another domain's permission from copied identity observations.
pub struct RetryGrants {
    pub path: RetryPeerCid,
    pub recovery: RecoveryRetryGrant,
    pub stream: StreamRetryGrant,
}
#[derive(Clone, Copy, Debug)]
struct RetryIdentity {
    generation: u64,
    source: super::path_owner::Destination,
    original: super::path_owner::Destination,
    client: super::path_owner::Destination,
}
/// Permission for Recovery to reset only this committed Retry's state.
#[derive(Debug)]
pub struct RecoveryRetryGrant {
    identity: RetryIdentity,
}
/// Permission for Stream to requeue its own accepted early references.
#[derive(Debug)]
pub struct StreamRetryGrant {
    identity: RetryIdentity,
}
macro_rules! retry_identity_accessors {
    ($grant:ident) => {
        impl $grant {
            pub const fn generation(&self) -> u64 {
                self.identity.generation
            }
            pub fn source_cid(&self) -> &[u8] {
                self.identity.source.as_bytes()
            }
            pub fn original_destination_cid(&self) -> &[u8] {
                self.identity.original.as_bytes()
            }
            pub fn client_source_cid(&self) -> &[u8] {
                self.identity.client.as_bytes()
            }
        }
    };
}
retry_identity_accessors!(RecoveryRetryGrant);
retry_identity_accessors!(StreamRetryGrant);
/// The RX coordinator calls this immediately after ClientRetry's integrity and
/// local-policy commit. No status boolean or parsed-but-unchecked Retry enters.
pub(crate) fn split_retry(generation: u64, retry: crate::retry::CommittedRetry) -> RetryGrants {
    use super::path_owner::Destination;
    let identity = RetryIdentity {
        generation,
        source: Destination::new(retry.source_id()).expect("committed Retry CID bound"),
        original: Destination::new(retry.original_destination_id())
            .expect("committed Retry CID bound"),
        client: Destination::new(retry.client_source_id()).expect("committed Retry CID bound"),
    };
    RetryGrants {
        path: RetryPeerCid::from_committed(generation, retry),
        recovery: RecoveryRetryGrant { identity },
        stream: StreamRetryGrant { identity },
    }
}

/// Copying an ID cannot reopen a finished packet or duplicate an effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketTicket {
    generation: u64,
    sequence: u64,
}
impl PacketTicket {
    pub const fn generation(self) -> u64 {
        self.generation
    }
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EffectId {
    packet: PacketTicket,
    sequence: u64,
    frame_ordinal: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Domain {
    Ack,
    Delivery,
    Path,
    PathAdmission,
    InitialPeerCid,
}

/// Affine grants have no public constructor and deliberately implement neither
/// Clone nor Copy. Cancelling their packet also invalidates queued grants.
/// ```compile_fail
/// use hibana_quic::roles::packet_authority::AckGrant;
/// fn duplicate(grant: AckGrant) { let first = grant; let second = grant; }
/// ```
#[derive(Debug)]
pub struct AckGrant {
    id: EffectId,
    frame: AckFrame,
}
#[derive(Debug)]
pub struct DeliveryGrant<const N: usize> {
    id: EffectId,
    frame: DeliveryFrame<N>,
}
#[derive(Debug)]
pub struct PathGrant {
    id: EffectId,
    frame: super::path_owner::PathFrame,
    context: super::path_owner::PathContext,
}

pub const MAX_ACK_RANGES: usize = 32;
/// Immutable copied ACK contents supplied only by the authenticated parser.
#[derive(Debug)]
pub struct AckFrame {
    ranges: [crate::accounting::AckRange; MAX_ACK_RANGES],
    len: usize,
    delay: u64,
    ecn: Option<crate::packet::EcnCounts>,
}
impl AckFrame {
    pub fn ranges(&self) -> &[crate::accounting::AckRange] {
        &self.ranges[..self.len]
    }
    pub const fn delay(&self) -> u64 {
        self.delay
    }
    pub const fn ecn(&self) -> Option<crate::packet::EcnCounts> {
        self.ecn
    }
    pub(crate) fn duplicate_for_domain(&self) -> Self {
        Self {
            ranges: self.ranges,
            len: self.len,
            delay: self.delay,
            ecn: self.ecn,
        }
    }
}
/// Owned bytes copied from an authenticated STREAM frame, wiped on drop.
#[derive(Debug)]
pub struct FrameBytes<const N: usize> {
    bytes: [u8; N],
    len: usize,
}
impl<const N: usize> FrameBytes<N> {
    fn new(input: &[u8]) -> Result<Self, Error> {
        if input.len() > N {
            return Err(Error::FrameCapacity);
        }
        let mut result = Self {
            bytes: [0; N],
            len: input.len(),
        };
        result.bytes[..input.len()].copy_from_slice(input);
        Ok(result)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
impl<const N: usize> Drop for FrameBytes<N> {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.bytes);
    }
}
#[derive(Debug)]
pub enum DeliveryFrame<const N: usize> {
    Stream {
        id: u64,
        offset: u64,
        fin: bool,
        data: FrameBytes<N>,
    },
    ResetStream {
        id: u64,
        error_code: u64,
        final_size: u64,
    },
    StopSending {
        id: u64,
        error_code: u64,
    },
    MaxData {
        maximum: u64,
    },
    MaxStreamData {
        id: u64,
        maximum: u64,
    },
    MaxStreams {
        bidirectional: bool,
        maximum: u64,
    },
    DataBlocked {
        limit: u64,
    },
    StreamDataBlocked {
        id: u64,
        limit: u64,
    },
    StreamsBlocked {
        bidirectional: bool,
        limit: u64,
    },
}
impl<const N: usize> DeliveryFrame<N> {
    pub fn as_frame(&self) -> crate::packet::Frame<'_> {
        use crate::packet::Frame;
        match self {
            Self::Stream {
                id,
                offset,
                fin,
                data,
            } => Frame::Stream {
                id: *id,
                offset: *offset,
                fin: *fin,
                data: data.as_bytes(),
            },
            Self::ResetStream {
                id,
                error_code,
                final_size,
            } => Frame::ResetStream {
                id: *id,
                error_code: *error_code,
                final_size: *final_size,
            },
            Self::StopSending { id, error_code } => Frame::StopSending {
                id: *id,
                error_code: *error_code,
            },
            Self::MaxData { maximum } => Frame::MaxData { maximum: *maximum },
            Self::MaxStreamData { id, maximum } => Frame::MaxStreamData {
                id: *id,
                maximum: *maximum,
            },
            Self::MaxStreams {
                bidirectional,
                maximum,
            } => Frame::MaxStreams {
                bidirectional: *bidirectional,
                maximum: *maximum,
            },
            Self::DataBlocked { limit } => Frame::DataBlocked { limit: *limit },
            Self::StreamDataBlocked { id, limit } => Frame::StreamDataBlocked {
                id: *id,
                limit: *limit,
            },
            Self::StreamsBlocked {
                bidirectional,
                limit,
            } => Frame::StreamsBlocked {
                bidirectional: *bidirectional,
                limit: *limit,
            },
        }
    }
    fn from_frame(frame: crate::packet::Frame<'_>) -> Result<Self, Error> {
        use crate::packet::Frame;
        Ok(match frame {
            Frame::Stream {
                id,
                offset,
                fin,
                data,
            } => Self::Stream {
                id,
                offset,
                fin,
                data: FrameBytes::new(data)?,
            },
            Frame::ResetStream {
                id,
                error_code,
                final_size,
            } => Self::ResetStream {
                id,
                error_code,
                final_size,
            },
            Frame::StopSending { id, error_code } => Self::StopSending { id, error_code },
            Frame::MaxData { maximum } => Self::MaxData { maximum },
            Frame::MaxStreamData { id, maximum } => Self::MaxStreamData { id, maximum },
            Frame::MaxStreams {
                bidirectional,
                maximum,
            } => Self::MaxStreams {
                bidirectional,
                maximum,
            },
            Frame::DataBlocked { limit } => Self::DataBlocked { limit },
            Frame::StreamDataBlocked { id, limit } => Self::StreamDataBlocked { id, limit },
            Frame::StreamsBlocked {
                bidirectional,
                limit,
            } => Self::StreamsBlocked {
                bidirectional,
                limit,
            },
            _ => return Err(Error::InvalidFrame),
        })
    }
}
struct PacketRecord {
    ticket: PacketTicket,
    evidence: ReceiveEvidence,
    last_frame: [Option<u32>; 5],
    plaintext: [u8; AUTHENTICATED_PAYLOAD_CAPACITY],
    plaintext_len: usize,
    context: Option<super::path_owner::PathContext>,
}
impl Drop for PacketRecord {
    fn drop(&mut self) {
        self.plaintext.zeroize();
    }
}
#[derive(Clone, Copy)]
struct EffectRecord {
    id: EffectId,
    domain: Domain,
}
struct State<const P: usize, const E: usize> {
    packets: [Option<PacketRecord>; P],
    effects: [Option<EffectRecord>; E],
    next_packet: u64,
    next_effect: u64,
}
/// Caller-owned storage. `generation` must not be reused while callbacks from
/// another connection can arrive. One arena covers all ordinary packet domains.
pub struct Arena<const P: usize, const E: usize> {
    generation: u64,
    state: RefCell<State<P, E>>,
}
impl<const P: usize, const E: usize> Arena<P, E> {
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub const fn new(generation: u64) -> Self {
        Self {
            generation,
            state: RefCell::new(State {
                packets: [const { None }; P],
                effects: [None; E],
                next_packet: 0,
                next_effect: 0,
            }),
        }
    }
    /// Moves the real key-owner receipt into a bounded live packet record.
    pub(crate) fn admit(
        &self,
        evidence: ReceiveEvidence,
        plaintext: &[u8],
    ) -> Result<PacketTicket, Error> {
        if plaintext.len() > AUTHENTICATED_PAYLOAD_CAPACITY {
            return Err(Error::FrameCapacity);
        }
        let binds = match &evidence {
            ReceiveEvidence::Initial(receipt) => receipt.authenticates_plaintext(plaintext),
            ReceiveEvidence::Tls(receipt) => receipt.authenticates_plaintext(plaintext),
            ReceiveEvidence::Directional(receipt) => receipt.authenticates_plaintext(plaintext),
        };
        if !binds {
            return Err(Error::InvalidFrame);
        }
        let level = match evidence.facts()?.space {
            PacketNumberSpace::Initial => crate::packet::EncryptionLevel::Initial,
            PacketNumberSpace::Handshake => crate::packet::EncryptionLevel::Handshake,
            PacketNumberSpace::ApplicationData => crate::packet::EncryptionLevel::OneRtt,
        };
        let mut count = 0;
        for frame in
            crate::packet::FrameIter::new(plaintext, level, crate::packet::ParseLimits::default())
                .map_err(|_| Error::InvalidFrame)?
        {
            frame.map_err(|_| Error::InvalidFrame)?;
            count += 1;
        }
        if count == 0 {
            return Err(Error::InvalidFrame);
        }
        if evidence.facts()?.generation != self.generation {
            return Err(Error::WrongGeneration);
        }
        let mut state = self.state.borrow_mut();
        let slot = state
            .packets
            .iter()
            .position(Option::is_none)
            .ok_or(Error::PacketCapacity)?;
        let next = state
            .next_packet
            .checked_add(1)
            .ok_or(Error::SequenceExhausted)?;
        let ticket = PacketTicket {
            generation: self.generation,
            sequence: state.next_packet,
        };
        state.next_packet = next;
        let mut stored = [0; AUTHENTICATED_PAYLOAD_CAPACITY];
        stored[..plaintext.len()].copy_from_slice(plaintext);
        state.packets[slot] = Some(PacketRecord {
            ticket,
            evidence,
            last_frame: [None; 5],
            plaintext: stored,
            plaintext_len: plaintext.len(),
            context: None,
        });
        Ok(ticket)
    }
    pub fn inspect(&self, ticket: PacketTicket) -> Result<AuthenticatedPacket, Error> {
        let state = self.state.borrow();
        state
            .packets
            .iter()
            .flatten()
            .find(|p| p.ticket == ticket)
            .ok_or(Error::InvalidPacket)?
            .evidence
            .facts()
    }
    fn grant(
        &self,
        packet: PacketTicket,
        frame_ordinal: u32,
        domain: Domain,
    ) -> Result<EffectId, Error> {
        let mut state = self.state.borrow_mut();
        let packet_slot = state
            .packets
            .iter()
            .position(|p| p.as_ref().is_some_and(|p| p.ticket == packet))
            .ok_or(Error::InvalidPacket)?;
        if state.packets[packet_slot]
            .as_ref()
            .ok_or(Error::InvalidPacket)?
            .last_frame[domain as usize]
            .is_some_and(|old| frame_ordinal <= old)
        {
            return Err(Error::InvalidFrame);
        }
        let slot = state
            .effects
            .iter()
            .position(Option::is_none)
            .ok_or(Error::EffectCapacity)?;
        let next = state
            .next_effect
            .checked_add(1)
            .ok_or(Error::SequenceExhausted)?;
        let id = EffectId {
            packet,
            sequence: state.next_effect,
            frame_ordinal,
        };
        state.next_effect = next;
        state.packets[packet_slot]
            .as_mut()
            .ok_or(Error::InvalidPacket)?
            .last_frame[domain as usize] = Some(frame_ordinal);
        state.effects[slot] = Some(EffectRecord { id, domain });
        Ok(id)
    }
    pub(crate) fn grant_initial_peer_cid(
        &self,
        ticket: PacketTicket,
        header: &[u8],
    ) -> Result<InitialPeerCid, Error> {
        let state = self.state.borrow();
        let record = state
            .packets
            .iter()
            .flatten()
            .find(|p| p.ticket == ticket)
            .ok_or(Error::InvalidPacket)?;
        let ReceiveEvidence::Initial(receipt) = &record.evidence else {
            return Err(Error::UnsupportedProtection);
        };
        if !receipt.authenticates_header(header)
            || header.len() < 7
            || header[0] & 0xf0 != 0xc0
            || header[1..5] != crate::packet::QUIC_V1.to_be_bytes()
        {
            return Err(Error::InvalidFrame);
        }
        let dlen = usize::from(header[5]);
        let d = header.get(6..6 + dlen).ok_or(Error::InvalidFrame)?;
        let slen = usize::from(*header.get(6 + dlen).ok_or(Error::InvalidFrame)?);
        let source = header
            .get(7 + dlen..7 + dlen + slen)
            .ok_or(Error::InvalidFrame)?;
        let generation = receipt.generation();
        let source =
            super::path_owner::Destination::new(source).map_err(|_| Error::InvalidFrame)?;
        let destination =
            super::path_owner::Destination::new(d).map_err(|_| Error::InvalidFrame)?;
        drop(state);
        Ok(InitialPeerCid {
            id: self.grant(ticket, 0, Domain::InitialPeerCid)?,
            generation,
            source,
            destination,
        })
    }
    /// Binds the actual UDP receive context once; later frame grants cannot
    /// substitute another tuple, destination CID, datagram identity or size.
    pub(crate) fn bind_path_context(
        &self,
        ticket: PacketTicket,
        context: super::path_owner::PathContext,
    ) -> Result<(), Error> {
        let mut state = self.state.borrow_mut();
        let record = state
            .packets
            .iter_mut()
            .flatten()
            .find(|p| p.ticket == ticket)
            .ok_or(Error::InvalidPacket)?;
        if record.context.is_some() {
            return Err(Error::InvalidGrant);
        }
        record.context = Some(context);
        Ok(())
    }
    fn with_frame<R>(
        &self,
        ticket: PacketTicket,
        ordinal: u32,
        make: impl for<'a> FnOnce(crate::packet::Frame<'a>) -> Result<R, Error>,
    ) -> Result<R, Error> {
        let state = self.state.borrow();
        let record = state
            .packets
            .iter()
            .flatten()
            .find(|p| p.ticket == ticket)
            .ok_or(Error::InvalidPacket)?;
        let level = match record.evidence.facts()?.space {
            PacketNumberSpace::Initial => crate::packet::EncryptionLevel::Initial,
            PacketNumberSpace::Handshake => crate::packet::EncryptionLevel::Handshake,
            PacketNumberSpace::ApplicationData => crate::packet::EncryptionLevel::OneRtt,
        };
        let frame = crate::packet::FrameIter::new(
            &record.plaintext[..record.plaintext_len],
            level,
            crate::packet::ParseLimits::default(),
        )
        .map_err(|_| Error::InvalidFrame)?
        .nth(ordinal as usize)
        .ok_or(Error::InvalidFrame)?
        .map_err(|_| Error::InvalidFrame)?;
        make(frame)
    }
    pub(crate) fn grant_ack(
        &self,
        packet: PacketTicket,
        frame_ordinal: u32,
        ranges: crate::packet::AckRanges<'_>,
        delay: u64,
        ecn: Option<crate::packet::EcnCounts>,
    ) -> Result<AckGrant, Error> {
        let frame = self.with_frame(packet, frame_ordinal, |actual| {
            let crate::packet::Frame::Ack {
                ranges: actual_ranges,
                delay: actual_delay,
                ecn: actual_ecn,
            } = actual
            else {
                return Err(Error::InvalidFrame);
            };
            if delay != actual_delay || ecn != actual_ecn || !ranges.iter().eq(actual_ranges.iter())
            {
                return Err(Error::InvalidFrame);
            }
            let len = actual_ranges.len();
            if len == 0 || len > MAX_ACK_RANGES {
                return Err(Error::AckCapacity);
            }
            let mut frame = AckFrame {
                ranges: [crate::accounting::AckRange { start: 0, end: 0 }; MAX_ACK_RANGES],
                len,
                delay: actual_delay,
                ecn: actual_ecn,
            };
            for (index, range) in actual_ranges.iter().enumerate() {
                frame.ranges[len - index - 1] = crate::accounting::AckRange {
                    start: range.smallest,
                    end: range.largest,
                };
            }
            Ok(frame)
        })?;
        Ok(AckGrant {
            id: self.grant(packet, frame_ordinal, Domain::Ack)?,
            frame,
        })
    }
    pub(crate) fn grant_delivery<const N: usize>(
        &self,
        packet: PacketTicket,
        frame_ordinal: u32,
        frame: crate::packet::Frame<'_>,
    ) -> Result<DeliveryGrant<N>, Error> {
        let frame = self.with_frame(packet, frame_ordinal, |actual| {
            if actual != frame {
                return Err(Error::InvalidFrame);
            }
            DeliveryFrame::from_frame(actual)
        })?;
        Ok(DeliveryGrant {
            id: self.grant(packet, frame_ordinal, Domain::Delivery)?,
            frame,
        })
    }
    pub(crate) fn grant_path(
        &self,
        packet: PacketTicket,
        frame_ordinal: u32,
        frame: super::path_owner::PathFrame,
        context: super::path_owner::PathContext,
    ) -> Result<PathGrant, Error> {
        use super::path_owner::PathFrame;
        {
            let state = self.state.borrow();
            let record = state
                .packets
                .iter()
                .flatten()
                .find(|p| p.ticket == packet)
                .ok_or(Error::InvalidPacket)?;
            if record.context != Some(context) {
                return Err(Error::InvalidFrame);
            }
        }
        let domain = if let PathFrame::PacketProcessed { non_probing } = frame {
            let state = self.state.borrow();
            let record = state
                .packets
                .iter()
                .flatten()
                .find(|p| p.ticket == packet)
                .ok_or(Error::InvalidPacket)?;
            let level = match record.evidence.facts()?.space {
                PacketNumberSpace::Initial => crate::packet::EncryptionLevel::Initial,
                PacketNumberSpace::Handshake => crate::packet::EncryptionLevel::Handshake,
                PacketNumberSpace::ApplicationData => crate::packet::EncryptionLevel::OneRtt,
            };
            let mut actual = false;
            for value in crate::packet::FrameIter::new(
                &record.plaintext[..record.plaintext_len],
                level,
                crate::packet::ParseLimits::default(),
            )
            .map_err(|_| Error::InvalidFrame)?
            {
                actual |= !value.map_err(|_| Error::InvalidFrame)?.probing();
            }
            if frame_ordinal != 0 || non_probing != actual {
                return Err(Error::InvalidFrame);
            }
            Domain::PathAdmission
        } else {
            self.with_frame(packet, frame_ordinal, |actual| {
                use crate::packet::Frame;
                let actual = match actual {
                    Frame::PathChallenge { data } => PathFrame::Challenge(*data),
                    Frame::PathResponse { data } => PathFrame::Response(*data),
                    Frame::NewConnectionId {
                        sequence,
                        retire_prior_to,
                        id,
                        reset_token,
                    } => PathFrame::NewConnectionId {
                        sequence,
                        retire_prior_to,
                        id: crate::connection_id::Cid::new(id).map_err(|_| Error::InvalidFrame)?,
                        reset_token: crate::connection_id::ResetToken::new(*reset_token),
                    },
                    Frame::RetireConnectionId { sequence } => {
                        PathFrame::RetireConnectionId { sequence }
                    }
                    Frame::HandshakeDone => PathFrame::HandshakeDone,
                    _ => return Err(Error::InvalidFrame),
                };
                if actual != frame {
                    return Err(Error::InvalidFrame);
                }
                Ok(())
            })?;
            Domain::Path
        };
        Ok(PathGrant {
            id: self.grant(packet, frame_ordinal, domain)?,
            frame,
            context,
        })
    }
    fn consume(&self, id: EffectId, domain: Domain) -> Result<AuthenticatedPacket, Error> {
        let mut state = self.state.borrow_mut();
        let slot = state
            .effects
            .iter()
            .position(|e| e.is_some_and(|e| e.id == id && e.domain == domain))
            .ok_or(Error::InvalidGrant)?;
        let facts = state
            .packets
            .iter()
            .flatten()
            .find(|p| p.ticket == id.packet)
            .ok_or(Error::InvalidGrant)?
            .evidence
            .facts()?;
        state.effects[slot] = None;
        Ok(facts)
    }
    pub fn consume_initial_peer_cid(
        &self,
        grant: InitialPeerCid,
    ) -> Result<
        (
            AuthenticatedPacket,
            super::path_owner::Destination,
            super::path_owner::Destination,
        ),
        Error,
    > {
        let facts = self.consume(grant.id, Domain::InitialPeerCid)?;
        Ok((facts, grant.source, grant.destination))
    }
    pub fn consume_ack(&self, grant: AckGrant) -> Result<(AuthenticatedPacket, AckFrame), Error> {
        let facts = self.consume(grant.id, Domain::Ack)?;
        Ok((facts, grant.frame))
    }
    pub fn consume_delivery<const N: usize>(
        &self,
        grant: DeliveryGrant<N>,
    ) -> Result<(AuthenticatedPacket, DeliveryFrame<N>), Error> {
        let facts = self.consume(grant.id, Domain::Delivery)?;
        Ok((facts, grant.frame))
    }
    pub fn consume_path(
        &self,
        grant: PathGrant,
    ) -> Result<
        (
            AuthenticatedPacket,
            super::path_owner::PathFrame,
            super::path_owner::PathContext,
        ),
        Error,
    > {
        let domain = if matches!(
            grant.frame,
            super::path_owner::PathFrame::PacketProcessed { .. }
        ) {
            Domain::PathAdmission
        } else {
            Domain::Path
        };
        let facts = self.consume(grant.id, domain)?;
        Ok((facts, grant.frame, grant.context))
    }
    /// A completed scope destroys its original receipt; it cannot be readmitted.
    /// Outstanding grants must be consumed, or explicitly revoked by cancel.
    pub fn finish(&self, ticket: PacketTicket) -> Result<AuthenticatedPacket, Error> {
        let mut state = self.state.borrow_mut();
        let slot = state
            .packets
            .iter()
            .position(|p| p.as_ref().is_some_and(|p| p.ticket == ticket))
            .ok_or(Error::InvalidPacket)?;
        if state
            .effects
            .iter()
            .flatten()
            .any(|e| e.id.packet == ticket)
        {
            return Err(Error::OutstandingEffects);
        }
        let record = state.packets[slot].take().ok_or(Error::InvalidPacket)?;
        record.evidence.facts()
    }
    pub fn cancel(&self, ticket: PacketTicket) -> Result<(), Error> {
        let mut state = self.state.borrow_mut();
        let slot = state
            .packets
            .iter()
            .position(|p| p.as_ref().is_some_and(|p| p.ticket == ticket))
            .ok_or(Error::InvalidPacket)?;
        state.packets[slot] = None;
        for effect in &mut state.effects {
            if effect.is_some_and(|e| e.id.packet == ticket) {
                *effect = None;
            }
        }
        Ok(())
    }
    pub fn live_packets(&self) -> usize {
        self.state.borrow().packets.iter().flatten().count()
    }
    pub fn live_effects(&self) -> usize {
        self.state.borrow().effects.iter().flatten().count()
    }
}
