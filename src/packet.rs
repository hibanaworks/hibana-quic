//! Allocation-free QUIC v1 wire syntax (RFC 9000 §§12, 16, 17, 19).
//!
//! This module does **not** authenticate packets. `PacketIter` only finds packet
//! boundaries before header protection removal. Pass decrypted, authenticated
//! payloads to `FrameIter`; validate reserved bits only after authentication.
//! Packet number spaces, duplicate detection, endpoint role/stream-state rules,
//! same-DCID coalescing policy, Retry integrity, transport parameters and packet
//! protection belong to their respective owners. Unknown versions are returned
//! opaquely; extensions (including DATAGRAM and QUIC v2) are not decoded.
//! Header emitters cover Initial, 0-RTT, Handshake and 1-RTT only; Retry and
//! Version Negotiation are currently parsed but not generated. Stateless Reset
//! recognition is a separate post-decryption-failure operation, not header parsing.
//!
//! All variable-length inputs borrow caller storage. Work is bounded by input
//! length and explicit local limits. `LimitExceeded` is local resource exhaustion,
//! not evidence of a peer protocol violation. No heap or unsafe code is used.
//! Normative reference: <https://www.rfc-editor.org/rfc/rfc9000>.

/// Largest QUIC variable-length integer, offset or packet number.
pub const MAX_VARINT: u64 = (1u64 << 62) - 1;
pub const QUIC_V1: u32 = 1;
pub const MAX_CONNECTION_ID_LEN: usize = 20;
pub const MAX_STREAM_COUNT: u64 = 1u64 << 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceLimit {
    Bytes,
    Packets,
    Frames,
    AckRanges,
}

/// Wire syntax errors only; the caller selects discard versus transport error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Truncated,
    BufferTooShort,
    VarIntTooLarge,
    InvalidVarIntWidth,
    InvalidPacketNumber,
    InvalidConnectionIdLength,
    InvalidFixedBit,
    InvalidLength,
    InvalidVersionNegotiation,
    EmptyToken,
    ReservedBits,
    UnknownFrameType(u64),
    NonMinimalFrameType,
    InvalidAckRange,
    InvalidOffset,
    InvalidStreamCount,
    InvalidRetirePriorTo,
    FrameNotAllowed {
        frame_type: u64,
        level: EncryptionLevel,
    },
    EmptyPayload,
    LimitExceeded(ResourceLimit),
}

/// Returns the integer and number of input bytes consumed. Non-minimal encodings
/// are deliberately accepted (RFC 9000 §16).
pub fn decode_varint(input: &[u8]) -> Result<(u64, usize), Error> {
    let first = *input.first().ok_or(Error::Truncated)?;
    let width = 1usize << (first >> 6);
    let bytes = input.get(..width).ok_or(Error::Truncated)?;
    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    Ok((value, width))
}

pub fn varint_len(value: u64) -> Result<usize, Error> {
    match value {
        0..=63 => Ok(1),
        64..=16383 => Ok(2),
        16384..=1073741823 => Ok(4),
        1073741824..=MAX_VARINT => Ok(8),
        _ => Err(Error::VarIntTooLarge),
    }
}

/// Encodes using the shortest legal width. Output is unchanged on error.
pub fn encode_varint(value: u64, output: &mut [u8]) -> Result<usize, Error> {
    encode_varint_with_len(value, varint_len(value)?, output)
}

/// Explicit-width encoding is useful for length fields reserved before sealing.
/// Non-minimal widths are legal except when encoding a frame type.
pub fn encode_varint_with_len(value: u64, width: usize, output: &mut [u8]) -> Result<usize, Error> {
    let tag = match width {
        1 => 0,
        2 => 0x40,
        4 => 0x80,
        8 => 0xc0,
        _ => return Err(Error::InvalidVarIntWidth),
    };
    if varint_len(value)? > width {
        return Err(Error::InvalidVarIntWidth);
    }
    let out = output.get_mut(..width).ok_or(Error::BufferTooShort)?;
    let bytes = value.to_be_bytes();
    out.copy_from_slice(&bytes[8 - width..]);
    out[0] |= tag;
    Ok(width)
}

/// Restores a PN after header protection removal (RFC 9000 §17.1/A.3).
/// `largest_authenticated` is from this PN space; `None` means no PN received.
/// This result must not update the receive high-water mark before authentication.
pub fn restore_packet_number(
    truncated: u64,
    encoded_bytes: u8,
    largest_authenticated: Option<u64>,
) -> Result<u64, Error> {
    if !(1..=4).contains(&encoded_bytes) {
        return Err(Error::InvalidPacketNumber);
    }
    let expected = match largest_authenticated {
        Some(largest) if largest <= MAX_VARINT => largest + 1,
        Some(_) => return Err(Error::InvalidPacketNumber),
        None => 0,
    };
    let window = 1u64 << (u32::from(encoded_bytes) * 8);
    if truncated >= window {
        return Err(Error::InvalidPacketNumber);
    }
    let half = window / 2;
    let mut candidate = (expected & !(window - 1)) | truncated;
    if expected >= half && candidate <= expected - half && candidate < (1u64 << 62) - window {
        candidate += window;
    } else if candidate > expected + half && candidate >= window {
        candidate -= window;
    }
    if candidate > MAX_VARINT {
        return Err(Error::InvalidPacketNumber);
    }
    Ok(candidate)
}

#[derive(Clone, Copy, Debug)]
struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.position..]
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(Error::InvalidLength)?;
        let result = self.bytes.get(self.position..end).ok_or(Error::Truncated)?;
        self.position = end;
        Ok(result)
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn varint(&mut self) -> Result<u64, Error> {
        let (value, length) = decode_varint(self.remaining())?;
        self.position += length;
        Ok(value)
    }
    fn length_prefixed(&mut self) -> Result<&'a [u8], Error> {
        let length = self.varint()?;
        let length = usize::try_from(length).map_err(|_| Error::InvalidLength)?;
        self.take(length)
    }
    fn rest(&mut self) -> &'a [u8] {
        let result = self.remaining();
        self.position = self.bytes.len();
        result
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncryptionLevel {
    Initial,
    Handshake,
    ZeroRtt,
    OneRtt,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LongType {
    Initial,
    ZeroRtt,
    Handshake,
}

impl LongType {
    pub fn encryption_level(self) -> EncryptionLevel {
        match self {
            Self::Initial => EncryptionLevel::Initial,
            Self::ZeroRtt => EncryptionLevel::ZeroRtt,
            Self::Handshake => EncryptionLevel::Handshake,
        }
    }
}

/// Version-independent CIDs may be longer than 20 bytes in unsupported versions
/// and Version Negotiation packets. The 20-byte limit is enforced for v1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Header<'a> {
    Long {
        kind: LongType,
        destination_id: &'a [u8],
        source_id: &'a [u8],
        token: &'a [u8],
        packet_number_offset: usize,
    },
    Short {
        destination_id: &'a [u8],
        packet_number_offset: usize,
    },
    Retry {
        destination_id: &'a [u8],
        source_id: &'a [u8],
        token: &'a [u8],
        integrity_tag: &'a [u8; 16],
    },
    VersionNegotiation {
        destination_id: &'a [u8],
        source_id: &'a [u8],
        versions: Versions<'a>,
    },
    UnsupportedVersion {
        version: u32,
        destination_id: &'a [u8],
        source_id: &'a [u8],
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Versions<'a> {
    bytes: &'a [u8],
}

impl<'a> Versions<'a> {
    pub fn iter(self) -> impl Iterator<Item = u32> + 'a {
        self.bytes
            .chunks_exact(4)
            .map(|v| u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
    }
    pub fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }
}

/// An untrusted view. `bytes` includes the entire individual packet (not the
/// remainder of the UDP datagram); PN offsets are relative to this slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Packet<'a> {
    pub header: Header<'a>,
    pub bytes: &'a [u8],
}

/// Bounded, fused iterator over coalesced packets (RFC 9000 §12.2).
/// Short, Retry, Version Negotiation and unsupported-version packets consume the
/// remaining datagram because their formats expose no usable packet length.
/// The caller must apply connection/role/DCID policy and minimum datagram sizes.
pub struct PacketIter<'a> {
    remaining: &'a [u8],
    short_destination_id_len: usize,
    budget: usize,
    failed: bool,
}

impl<'a> PacketIter<'a> {
    pub fn new(
        datagram: &'a [u8],
        short_destination_id_len: usize,
        max_packets: usize,
    ) -> Result<Self, Error> {
        if short_destination_id_len > MAX_CONNECTION_ID_LEN {
            return Err(Error::InvalidConnectionIdLength);
        }
        Ok(Self {
            remaining: datagram,
            short_destination_id_len,
            budget: max_packets,
            failed: false,
        })
    }
}

impl<'a> Iterator for PacketIter<'a> {
    type Item = Result<Packet<'a>, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.remaining.is_empty() {
            return None;
        }
        if self.budget == 0 {
            self.failed = true;
            return Some(Err(Error::LimitExceeded(ResourceLimit::Packets)));
        }
        self.budget -= 1;
        match parse_packet(self.remaining, self.short_destination_id_len) {
            Ok(packet) => {
                self.remaining = &self.remaining[packet.bytes.len()..];
                Some(Ok(packet))
            }
            Err(error) => {
                self.failed = true;
                Some(Err(error))
            }
        }
    }
}
impl core::iter::FusedIterator for PacketIter<'_> {}

fn parse_packet(datagram: &[u8], short_id_len: usize) -> Result<Packet<'_>, Error> {
    let mut cursor = Cursor::new(datagram);
    let first = cursor.byte()?;
    if first & 0x80 == 0 {
        if first & 0x40 == 0 {
            return Err(Error::InvalidFixedBit);
        }
        let destination_id = cursor.take(short_id_len)?;
        // Even protected packets need at least a PN byte. AEAD and HP sample
        // length checks are the crypto owner's responsibility.
        if cursor.remaining().is_empty() {
            return Err(Error::Truncated);
        }
        return Ok(Packet {
            header: Header::Short {
                destination_id,
                packet_number_offset: cursor.position,
            },
            bytes: datagram,
        });
    }
    let version_bytes = cursor.take(4)?;
    let version = u32::from_be_bytes([
        version_bytes[0],
        version_bytes[1],
        version_bytes[2],
        version_bytes[3],
    ]);
    let destination_len = usize::from(cursor.byte()?);
    if version == QUIC_V1 && destination_len > MAX_CONNECTION_ID_LEN {
        return Err(Error::InvalidConnectionIdLength);
    }
    let destination_id = cursor.take(destination_len)?;
    let source_len = usize::from(cursor.byte()?);
    if version == QUIC_V1 && source_len > MAX_CONNECTION_ID_LEN {
        return Err(Error::InvalidConnectionIdLength);
    }
    let source_id = cursor.take(source_len)?;
    if version == 0 {
        let bytes = cursor.rest();
        if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
            return Err(Error::InvalidVersionNegotiation);
        }
        return Ok(Packet {
            header: Header::VersionNegotiation {
                destination_id,
                source_id,
                versions: Versions { bytes },
            },
            bytes: datagram,
        });
    }
    if version != QUIC_V1 {
        return Ok(Packet {
            header: Header::UnsupportedVersion {
                version,
                destination_id,
                source_id,
            },
            bytes: datagram,
        });
    }
    if first & 0x40 == 0 {
        return Err(Error::InvalidFixedBit);
    }
    let kind = match (first >> 4) & 3 {
        0 => LongType::Initial,
        1 => LongType::ZeroRtt,
        2 => LongType::Handshake,
        _ => {
            let remaining = cursor.rest();
            if remaining.len() < 16 {
                return Err(Error::Truncated);
            }
            let split = remaining.len() - 16;
            if split == 0 {
                return Err(Error::EmptyToken);
            }
            let (token, tag) = remaining.split_at(split);
            let integrity_tag = <&[u8; 16]>::try_from(tag).map_err(|_| Error::Truncated)?;
            return Ok(Packet {
                header: Header::Retry {
                    destination_id,
                    source_id,
                    token,
                    integrity_tag,
                },
                bytes: datagram,
            });
        }
    };
    let token = if kind == LongType::Initial {
        cursor.length_prefixed()?
    } else {
        &[]
    };
    let length = usize::try_from(cursor.varint()?).map_err(|_| Error::InvalidLength)?;
    if length == 0 {
        return Err(Error::InvalidLength);
    }
    let packet_number_offset = cursor.position;
    cursor.take(length)?;
    Ok(Packet {
        header: Header::Long {
            kind,
            destination_id,
            source_id,
            token,
            packet_number_offset,
        },
        bytes: &datagram[..cursor.position],
    })
}

/// Read PN bytes only after header protection has been removed. Does not
/// authenticate, restore the full PN, or check reserved bits.
pub fn decode_truncated_packet_number(first: u8, input: &[u8]) -> Result<(u64, usize), Error> {
    let length = usize::from((first & 3) + 1);
    let bytes = input.get(..length).ok_or(Error::Truncated)?;
    let mut value = 0u64;
    for byte in bytes {
        value = (value << 8) | u64::from(*byte);
    }
    Ok((value, length))
}

/// Invoke only after successful AEAD authentication and HP removal. Rejecting
/// protected or unauthenticated reserved bits as a connection error is unsafe.
pub fn validate_reserved_bits(authenticated_first: u8) -> Result<(), Error> {
    let mask = if authenticated_first & 0x80 != 0 {
        0x0c
    } else {
        0x18
    };
    if authenticated_first & mask != 0 {
        Err(Error::ReservedBits)
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseLimits {
    pub max_bytes: usize,
    /// Maximum decoded entries; one contiguous PADDING run is one entry.
    pub max_frames: usize,
    /// Includes the first ACK range (the wire count excludes it).
    pub max_ack_ranges: usize,
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            max_bytes: 65535,
            max_frames: 256,
            max_ack_ranges: 64,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AckRange {
    /// Inclusive lower bound.
    pub smallest: u64,
    /// Inclusive upper bound.
    pub largest: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AckRangeStorage<'a> {
    Slice(&'a [AckRange]),
    Wire {
        first: AckRange,
        additional: &'a [u8],
        count: usize,
    },
}

/// Validated, descending, disjoint, non-adjacent ranges. Borrowed storage is
/// immutable; neither parsing nor iteration allocates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AckRanges<'a> {
    storage: AckRangeStorage<'a>,
}

impl<'a> AckRanges<'a> {
    pub fn new(ranges: &'a [AckRange]) -> Result<Self, Error> {
        if ranges.is_empty() {
            return Err(Error::InvalidAckRange);
        }
        let mut previous: Option<AckRange> = None;
        for range in ranges {
            if range.smallest > range.largest || range.largest > MAX_VARINT {
                return Err(Error::InvalidAckRange);
            }
            if let Some(previous) = previous
                && previous
                    .smallest
                    .checked_sub(2)
                    .filter(|v| *v >= range.largest)
                    .is_none()
            {
                return Err(Error::InvalidAckRange);
            }
            previous = Some(*range);
        }
        Ok(Self {
            storage: AckRangeStorage::Slice(ranges),
        })
    }
    pub fn len(self) -> usize {
        match self.storage {
            AckRangeStorage::Slice(ranges) => ranges.len(),
            AckRangeStorage::Wire { count, .. } => count + 1,
        }
    }
    pub fn is_empty(self) -> bool {
        false
    }
    pub fn iter(self) -> AckRangeIter<'a> {
        AckRangeIter {
            ranges: self,
            index: 0,
            cursor: match self.storage {
                AckRangeStorage::Wire { additional, .. } => Cursor::new(additional),
                AckRangeStorage::Slice(_) => Cursor::new(&[]),
            },
            previous_smallest: 0,
        }
    }
}

pub struct AckRangeIter<'a> {
    ranges: AckRanges<'a>,
    index: usize,
    cursor: Cursor<'a>,
    previous_smallest: u64,
}

impl Iterator for AckRangeIter<'_> {
    type Item = AckRange;
    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.ranges.len() {
            return None;
        }
        let range = match self.ranges.storage {
            AckRangeStorage::Slice(ranges) => ranges[self.index],
            AckRangeStorage::Wire { first, .. } if self.index == 0 => first,
            AckRangeStorage::Wire { .. } => {
                // The private constructor validates every encoded range first.
                let gap = self.cursor.varint().ok()?;
                let length = self.cursor.varint().ok()?;
                let largest = self.previous_smallest.checked_sub(gap)?.checked_sub(2)?;
                AckRange {
                    smallest: largest.checked_sub(length)?,
                    largest,
                }
            }
        };
        self.index += 1;
        self.previous_smallest = range.smallest;
        Some(range)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.ranges.len() - self.index;
        (remaining, Some(remaining))
    }
}
impl ExactSizeIterator for AckRangeIter<'_> {}
impl core::iter::FusedIterator for AckRangeIter<'_> {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EcnCounts {
    pub ect0: u64,
    pub ect1: u64,
    pub ce: u64,
}

/// Every base QUIC v1 frame shape. Per-connection meaning (stream direction,
/// final size consistency, unsent ACKs, CID issuance and endpoint role) is not
/// determined by wire syntax and must be checked by the appropriate owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Frame<'a> {
    Padding {
        length: usize,
    },
    Ping,
    Ack {
        delay: u64,
        ranges: AckRanges<'a>,
        ecn: Option<EcnCounts>,
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
    Crypto {
        offset: u64,
        data: &'a [u8],
    },
    NewToken {
        token: &'a [u8],
    },
    Stream {
        id: u64,
        offset: u64,
        fin: bool,
        data: &'a [u8],
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
    NewConnectionId {
        sequence: u64,
        retire_prior_to: u64,
        id: &'a [u8],
        reset_token: &'a [u8; 16],
    },
    RetireConnectionId {
        sequence: u64,
    },
    PathChallenge {
        data: &'a [u8; 8],
    },
    PathResponse {
        data: &'a [u8; 8],
    },
    /// `frame_type: None` denotes the application-error (0x1d) variant.
    ConnectionClose {
        error_code: u64,
        frame_type: Option<u64>,
        reason: &'a [u8],
    },
    HandshakeDone,
}

impl Frame<'_> {
    pub fn ack_eliciting(&self) -> bool {
        !matches!(
            self,
            Self::Padding { .. } | Self::Ack { .. } | Self::ConnectionClose { .. }
        )
    }
    pub fn probing(&self) -> bool {
        matches!(
            self,
            Self::Padding { .. }
                | Self::NewConnectionId { .. }
                | Self::PathChallenge { .. }
                | Self::PathResponse { .. }
        )
    }
    /// Canonical wire type used by the encoder. STREAM always carries length.
    pub fn frame_type(&self) -> u64 {
        match self {
            Self::Padding { .. } => 0,
            Self::Ping => 1,
            Self::Ack { ecn, .. } => {
                if ecn.is_some() {
                    3
                } else {
                    2
                }
            }
            Self::ResetStream { .. } => 4,
            Self::StopSending { .. } => 5,
            Self::Crypto { .. } => 6,
            Self::NewToken { .. } => 7,
            Self::Stream { offset, fin, .. } => {
                0x0a | if *offset != 0 { 4 } else { 0 } | u64::from(*fin)
            }
            Self::MaxData { .. } => 0x10,
            Self::MaxStreamData { .. } => 0x11,
            Self::MaxStreams { bidirectional, .. } => {
                if *bidirectional {
                    0x12
                } else {
                    0x13
                }
            }
            Self::DataBlocked { .. } => 0x14,
            Self::StreamDataBlocked { .. } => 0x15,
            Self::StreamsBlocked { bidirectional, .. } => {
                if *bidirectional {
                    0x16
                } else {
                    0x17
                }
            }
            Self::NewConnectionId { .. } => 0x18,
            Self::RetireConnectionId { .. } => 0x19,
            Self::PathChallenge { .. } => 0x1a,
            Self::PathResponse { .. } => 0x1b,
            Self::ConnectionClose { frame_type, .. } => {
                if frame_type.is_some() {
                    0x1c
                } else {
                    0x1d
                }
            }
            Self::HandshakeDone => 0x1e,
        }
    }
}

/// RFC 9000 §12.4 Table 3. Does not enforce sender-role restrictions (e.g.
/// HANDSHAKE_DONE/NEW_TOKEN must be sent by a server).
pub fn frame_allowed(frame_type: u64, level: EncryptionLevel) -> bool {
    if frame_type > 0x1e {
        return false;
    }
    match level {
        EncryptionLevel::OneRtt => true,
        EncryptionLevel::Initial | EncryptionLevel::Handshake => {
            matches!(frame_type, 0..=3 | 6 | 0x1c)
        }
        EncryptionLevel::ZeroRtt => !matches!(frame_type, 2 | 3 | 6 | 7 | 0x1b | 0x1e),
    }
}

/// Consumes one authenticated packet payload. After an error it is fused; no
/// later frame from a malformed packet is exposed. An earlier returned frame is
/// not proof that the entire packet is valid: stage effects if atomic validation
/// is required by the caller.
pub struct FrameIter<'a> {
    cursor: Cursor<'a>,
    level: EncryptionLevel,
    limits: ParseLimits,
    emitted: usize,
    failed: bool,
}

impl<'a> FrameIter<'a> {
    pub fn new(
        payload: &'a [u8],
        level: EncryptionLevel,
        limits: ParseLimits,
    ) -> Result<Self, Error> {
        if payload.is_empty() {
            return Err(Error::EmptyPayload);
        }
        if payload.len() > limits.max_bytes {
            return Err(Error::LimitExceeded(ResourceLimit::Bytes));
        }
        Ok(Self {
            cursor: Cursor::new(payload),
            level,
            limits,
            emitted: 0,
            failed: false,
        })
    }
}

impl<'a> Iterator for FrameIter<'a> {
    type Item = Result<Frame<'a>, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.cursor.remaining().is_empty() {
            return None;
        }
        if self.emitted >= self.limits.max_frames {
            self.failed = true;
            return Some(Err(Error::LimitExceeded(ResourceLimit::Frames)));
        }
        let mut cursor = self.cursor;
        let result = parse_frame(&mut cursor, self.level, self.limits.max_ack_ranges);
        match result {
            Ok(frame) => {
                self.cursor = cursor;
                self.emitted += 1;
                Some(Ok(frame))
            }
            Err(error) => {
                self.failed = true;
                Some(Err(error))
            }
        }
    }
}
impl core::iter::FusedIterator for FrameIter<'_> {}

fn validate_offset(offset: u64, length: usize) -> Result<(), Error> {
    let length = u64::try_from(length).map_err(|_| Error::InvalidOffset)?;
    if offset
        .checked_add(length)
        .filter(|v| *v <= MAX_VARINT)
        .is_none()
    {
        return Err(Error::InvalidOffset);
    }
    Ok(())
}

fn parse_frame<'a>(
    cursor: &mut Cursor<'a>,
    level: EncryptionLevel,
    max_ack_ranges: usize,
) -> Result<Frame<'a>, Error> {
    let (ty, width) = decode_varint(cursor.remaining())?;
    if varint_len(ty)? != width {
        return Err(Error::NonMinimalFrameType);
    }
    cursor.take(width)?;
    if ty > 0x1e {
        return Err(Error::UnknownFrameType(ty));
    }
    if !frame_allowed(ty, level) {
        return Err(Error::FrameNotAllowed {
            frame_type: ty,
            level,
        });
    }
    Ok(match ty {
        0 => {
            let zeros = cursor.remaining().iter().take_while(|b| **b == 0).count();
            cursor.take(zeros)?;
            Frame::Padding { length: zeros + 1 }
        }
        1 => Frame::Ping,
        2 | 3 => {
            let largest = cursor.varint()?;
            let delay = cursor.varint()?;
            let count = usize::try_from(cursor.varint()?)
                .map_err(|_| Error::LimitExceeded(ResourceLimit::AckRanges))?;
            if count >= max_ack_ranges {
                return Err(Error::LimitExceeded(ResourceLimit::AckRanges));
            }
            let first_length = cursor.varint()?;
            let smallest = largest
                .checked_sub(first_length)
                .ok_or(Error::InvalidAckRange)?;
            let first = AckRange { smallest, largest };
            let start = cursor.position;
            let mut previous_smallest = smallest;
            // Each range consumes at least two bytes, bounding work even if a
            // caller supplies an excessively permissive range limit.
            if count > cursor.remaining().len() / 2 {
                return Err(Error::Truncated);
            }
            for _ in 0..count {
                let gap = cursor.varint()?;
                let length = cursor.varint()?;
                let largest = previous_smallest
                    .checked_sub(gap)
                    .and_then(|v| v.checked_sub(2))
                    .ok_or(Error::InvalidAckRange)?;
                previous_smallest = largest.checked_sub(length).ok_or(Error::InvalidAckRange)?;
            }
            let additional = &cursor.bytes[start..cursor.position];
            let ranges = AckRanges {
                storage: AckRangeStorage::Wire {
                    first,
                    additional,
                    count,
                },
            };
            let ecn = if ty == 3 {
                Some(EcnCounts {
                    ect0: cursor.varint()?,
                    ect1: cursor.varint()?,
                    ce: cursor.varint()?,
                })
            } else {
                None
            };
            Frame::Ack { delay, ranges, ecn }
        }
        4 => Frame::ResetStream {
            id: cursor.varint()?,
            error_code: cursor.varint()?,
            final_size: cursor.varint()?,
        },
        5 => Frame::StopSending {
            id: cursor.varint()?,
            error_code: cursor.varint()?,
        },
        6 => {
            let offset = cursor.varint()?;
            let data = cursor.length_prefixed()?;
            validate_offset(offset, data.len())?;
            Frame::Crypto { offset, data }
        }
        7 => {
            let token = cursor.length_prefixed()?;
            if token.is_empty() {
                return Err(Error::EmptyToken);
            }
            Frame::NewToken { token }
        }
        8..=15 => {
            let id = cursor.varint()?;
            let offset = if ty & 4 != 0 { cursor.varint()? } else { 0 };
            let data = if ty & 2 != 0 {
                cursor.length_prefixed()?
            } else {
                cursor.rest()
            };
            validate_offset(offset, data.len())?;
            Frame::Stream {
                id,
                offset,
                fin: ty & 1 != 0,
                data,
            }
        }
        0x10 => Frame::MaxData {
            maximum: cursor.varint()?,
        },
        0x11 => Frame::MaxStreamData {
            id: cursor.varint()?,
            maximum: cursor.varint()?,
        },
        0x12 | 0x13 => {
            let maximum = cursor.varint()?;
            if maximum > MAX_STREAM_COUNT {
                return Err(Error::InvalidStreamCount);
            }
            Frame::MaxStreams {
                bidirectional: ty == 0x12,
                maximum,
            }
        }
        0x14 => Frame::DataBlocked {
            limit: cursor.varint()?,
        },
        0x15 => Frame::StreamDataBlocked {
            id: cursor.varint()?,
            limit: cursor.varint()?,
        },
        0x16 | 0x17 => {
            let limit = cursor.varint()?;
            if limit > MAX_STREAM_COUNT {
                return Err(Error::InvalidStreamCount);
            }
            Frame::StreamsBlocked {
                bidirectional: ty == 0x16,
                limit,
            }
        }
        0x18 => {
            let sequence = cursor.varint()?;
            let retire_prior_to = cursor.varint()?;
            if retire_prior_to > sequence {
                return Err(Error::InvalidRetirePriorTo);
            }
            let length = usize::from(cursor.byte()?);
            if !(1..=MAX_CONNECTION_ID_LEN).contains(&length) {
                return Err(Error::InvalidConnectionIdLength);
            }
            let id = cursor.take(length)?;
            let reset_token =
                <&[u8; 16]>::try_from(cursor.take(16)?).map_err(|_| Error::Truncated)?;
            Frame::NewConnectionId {
                sequence,
                retire_prior_to,
                id,
                reset_token,
            }
        }
        0x19 => Frame::RetireConnectionId {
            sequence: cursor.varint()?,
        },
        0x1a => Frame::PathChallenge {
            data: <&[u8; 8]>::try_from(cursor.take(8)?).map_err(|_| Error::Truncated)?,
        },
        0x1b => Frame::PathResponse {
            data: <&[u8; 8]>::try_from(cursor.take(8)?).map_err(|_| Error::Truncated)?,
        },
        0x1c | 0x1d => {
            let error_code = cursor.varint()?;
            let frame_type = if ty == 0x1c {
                Some(cursor.varint()?)
            } else {
                None
            };
            let reason = cursor.length_prefixed()?;
            Frame::ConnectionClose {
                error_code,
                frame_type,
                reason,
            }
        }
        0x1e => Frame::HandshakeDone,
        _ => return Err(Error::UnknownFrameType(ty)),
    })
}

/// Counting/writing sink; preflight prevents any output modification on errors.
struct Writer<'a> {
    output: Option<&'a mut [u8]>,
    position: usize,
}
impl Writer<'_> {
    fn bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let end = self
            .position
            .checked_add(bytes.len())
            .ok_or(Error::InvalidLength)?;
        if let Some(output) = self.output.as_deref_mut() {
            output
                .get_mut(self.position..end)
                .ok_or(Error::BufferTooShort)?
                .copy_from_slice(bytes);
        }
        self.position = end;
        Ok(())
    }
    fn zeros(&mut self, count: usize) -> Result<(), Error> {
        let end = self
            .position
            .checked_add(count)
            .ok_or(Error::InvalidLength)?;
        if let Some(output) = self.output.as_deref_mut() {
            output
                .get_mut(self.position..end)
                .ok_or(Error::BufferTooShort)?
                .fill(0);
        }
        self.position = end;
        Ok(())
    }
    fn byte(&mut self, value: u8) -> Result<(), Error> {
        self.bytes(&[value])
    }
    fn varint(&mut self, value: u64) -> Result<(), Error> {
        let mut encoded = [0u8; 8];
        let length = encode_varint(value, &mut encoded)?;
        self.bytes(&encoded[..length])
    }
    fn length_prefixed(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.varint(u64::try_from(bytes.len()).map_err(|_| Error::InvalidLength)?)?;
        self.bytes(bytes)
    }
}

/// Required encoded length, with full outbound syntax validation.
pub fn frame_encoded_len(frame: &Frame<'_>) -> Result<usize, Error> {
    let mut writer = Writer {
        output: None,
        position: 0,
    };
    write_frame(frame, &mut writer)?;
    Ok(writer.position)
}

/// Encodes any base v1 frame, using shortest integers and explicit STREAM length.
/// The output is unchanged if the frame is invalid or the output is too small.
/// Check `frame_allowed` and sender-role/state rules before transmitting.
pub fn encode_frame(frame: &Frame<'_>, output: &mut [u8]) -> Result<usize, Error> {
    let length = frame_encoded_len(frame)?;
    if output.len() < length {
        return Err(Error::BufferTooShort);
    }
    let mut writer = Writer {
        output: Some(output),
        position: 0,
    };
    write_frame(frame, &mut writer)?;
    Ok(writer.position)
}

fn write_frame(frame: &Frame<'_>, writer: &mut Writer<'_>) -> Result<(), Error> {
    if let Frame::Padding { length } = frame {
        if *length == 0 {
            return Err(Error::InvalidLength);
        }
        return writer.zeros(*length);
    }
    writer.varint(frame.frame_type())?;
    match frame {
        Frame::Padding { .. } | Frame::Ping | Frame::HandshakeDone => {}
        Frame::Ack { delay, ranges, ecn } => {
            let mut iter = ranges.iter();
            let first = iter.next().ok_or(Error::InvalidAckRange)?;
            writer.varint(first.largest)?;
            writer.varint(*delay)?;
            writer.varint(u64::try_from(ranges.len() - 1).map_err(|_| Error::InvalidLength)?)?;
            writer.varint(first.largest - first.smallest)?;
            let mut previous = first;
            for range in iter {
                writer.varint(previous.smallest - range.largest - 2)?;
                writer.varint(range.largest - range.smallest)?;
                previous = range;
            }
            if let Some(counts) = ecn {
                writer.varint(counts.ect0)?;
                writer.varint(counts.ect1)?;
                writer.varint(counts.ce)?;
            }
        }
        Frame::ResetStream {
            id,
            error_code,
            final_size,
        } => {
            writer.varint(*id)?;
            writer.varint(*error_code)?;
            writer.varint(*final_size)?;
        }
        Frame::StopSending { id, error_code } => {
            writer.varint(*id)?;
            writer.varint(*error_code)?;
        }
        Frame::Crypto { offset, data } => {
            validate_offset(*offset, data.len())?;
            writer.varint(*offset)?;
            writer.length_prefixed(data)?;
        }
        Frame::NewToken { token } => {
            if token.is_empty() {
                return Err(Error::EmptyToken);
            }
            writer.length_prefixed(token)?;
        }
        Frame::Stream {
            id, offset, data, ..
        } => {
            validate_offset(*offset, data.len())?;
            writer.varint(*id)?;
            if *offset != 0 {
                writer.varint(*offset)?;
            }
            writer.length_prefixed(data)?;
        }
        Frame::MaxData { maximum } => writer.varint(*maximum)?,
        Frame::MaxStreamData { id, maximum } => {
            writer.varint(*id)?;
            writer.varint(*maximum)?;
        }
        Frame::MaxStreams { maximum, .. } => {
            if *maximum > MAX_STREAM_COUNT {
                return Err(Error::InvalidStreamCount);
            }
            writer.varint(*maximum)?;
        }
        Frame::DataBlocked { limit } => writer.varint(*limit)?,
        Frame::StreamDataBlocked { id, limit } => {
            writer.varint(*id)?;
            writer.varint(*limit)?;
        }
        Frame::StreamsBlocked { limit, .. } => {
            if *limit > MAX_STREAM_COUNT {
                return Err(Error::InvalidStreamCount);
            }
            writer.varint(*limit)?;
        }
        Frame::NewConnectionId {
            sequence,
            retire_prior_to,
            id,
            reset_token,
        } => {
            if retire_prior_to > sequence {
                return Err(Error::InvalidRetirePriorTo);
            }
            if !(1..=MAX_CONNECTION_ID_LEN).contains(&id.len()) {
                return Err(Error::InvalidConnectionIdLength);
            }
            writer.varint(*sequence)?;
            writer.varint(*retire_prior_to)?;
            writer.byte(id.len() as u8)?;
            writer.bytes(id)?;
            writer.bytes(*reset_token)?;
        }
        Frame::RetireConnectionId { sequence } => writer.varint(*sequence)?,
        Frame::PathChallenge { data } | Frame::PathResponse { data } => writer.bytes(*data)?,
        Frame::ConnectionClose {
            error_code,
            frame_type,
            reason,
        } => {
            writer.varint(*error_code)?;
            if let Some(ty) = frame_type {
                writer.varint(*ty)?;
            }
            writer.length_prefixed(reason)?;
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub struct LongHeader<'a> {
    pub kind: LongType,
    pub destination_id: &'a [u8],
    pub source_id: &'a [u8],
    /// Must be empty for Handshake and 0-RTT.
    pub token: &'a [u8],
    pub packet_number: u64,
    pub packet_number_len: u8,
}

#[derive(Clone, Copy, Debug)]
pub struct ShortHeader<'a> {
    pub destination_id: &'a [u8],
    pub packet_number: u64,
    pub packet_number_len: u8,
    pub spin: bool,
    pub key_phase: bool,
}

/// Emits a plaintext v1 header including the truncated PN. `protected_payload_len`
/// includes the future AEAD tag, excludes the PN. Caller must seal and apply HP;
/// this does not create an authenticated packet or permit PN reuse.
pub fn encode_long_header(
    header: &LongHeader<'_>,
    protected_payload_len: usize,
    output: &mut [u8],
) -> Result<usize, Error> {
    let mut counter = Writer {
        output: None,
        position: 0,
    };
    write_long_header(header, protected_payload_len, &mut counter)?;
    if output.len() < counter.position {
        return Err(Error::BufferTooShort);
    }
    let mut writer = Writer {
        output: Some(output),
        position: 0,
    };
    write_long_header(header, protected_payload_len, &mut writer)?;
    Ok(writer.position)
}

fn write_long_header(
    header: &LongHeader<'_>,
    payload_len: usize,
    writer: &mut Writer<'_>,
) -> Result<(), Error> {
    validate_header_fields(
        header.destination_id,
        header.packet_number,
        header.packet_number_len,
    )?;
    if header.source_id.len() > MAX_CONNECTION_ID_LEN {
        return Err(Error::InvalidConnectionIdLength);
    }
    if header.kind != LongType::Initial && !header.token.is_empty() {
        return Err(Error::InvalidLength);
    }
    let ty = match header.kind {
        LongType::Initial => 0,
        LongType::ZeroRtt => 0x10,
        LongType::Handshake => 0x20,
    };
    writer.byte(0xc0 | ty | (header.packet_number_len - 1))?;
    writer.bytes(&QUIC_V1.to_be_bytes())?;
    writer.byte(header.destination_id.len() as u8)?;
    writer.bytes(header.destination_id)?;
    writer.byte(header.source_id.len() as u8)?;
    writer.bytes(header.source_id)?;
    if header.kind == LongType::Initial {
        writer.length_prefixed(header.token)?;
    }
    let length = u64::try_from(payload_len)
        .map_err(|_| Error::InvalidLength)?
        .checked_add(u64::from(header.packet_number_len))
        .ok_or(Error::InvalidLength)?;
    writer.varint(length)?;
    writer.bytes(&header.packet_number.to_be_bytes()[8 - usize::from(header.packet_number_len)..])
}

/// Emits a plaintext short header including truncated PN; sealing/HP is separate.
pub fn encode_short_header(header: &ShortHeader<'_>, output: &mut [u8]) -> Result<usize, Error> {
    validate_header_fields(
        header.destination_id,
        header.packet_number,
        header.packet_number_len,
    )?;
    let length = 1 + header.destination_id.len() + usize::from(header.packet_number_len);
    if output.len() < length {
        return Err(Error::BufferTooShort);
    }
    let mut writer = Writer {
        output: Some(output),
        position: 0,
    };
    writer.byte(
        0x40 | if header.spin { 0x20 } else { 0 }
            | if header.key_phase { 4 } else { 0 }
            | (header.packet_number_len - 1),
    )?;
    writer.bytes(header.destination_id)?;
    writer
        .bytes(&header.packet_number.to_be_bytes()[8 - usize::from(header.packet_number_len)..])?;
    Ok(writer.position)
}

fn validate_header_fields(id: &[u8], pn: u64, pn_len: u8) -> Result<(), Error> {
    if id.len() > MAX_CONNECTION_ID_LEN {
        return Err(Error::InvalidConnectionIdLength);
    }
    if pn > MAX_VARINT || !(1..=4).contains(&pn_len) {
        return Err(Error::InvalidPacketNumber);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn first_frame(bytes: &[u8]) -> Result<Frame<'_>, Error> {
        FrameIter::new(bytes, EncryptionLevel::OneRtt, ParseLimits::default())?
            .next()
            .ok_or(Error::EmptyPayload)?
    }

    fn put(value: u64, out: &mut [u8], at: &mut usize) {
        *at += encode_varint(value, &mut out[*at..]).unwrap();
    }

    #[test]
    fn rfc_varint_vectors_and_non_minimal_encoding() {
        for (wire, value) in [
            (
                &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c][..],
                151288809941952652,
            ),
            (&[0x9d, 0x7f, 0x3e, 0x7d][..], 494878333),
            (&[0x7b, 0xbd][..], 15293),
            (&[0x25][..], 37),
            (&[0x40, 0x25][..], 37),
        ] {
            assert_eq!(decode_varint(wire), Ok((value, wire.len())));
            for length in 0..wire.len() {
                assert_eq!(decode_varint(&wire[..length]), Err(Error::Truncated));
            }
        }
        for width in [1, 2, 4, 8] {
            let mut out = [0xff; 8];
            assert_eq!(encode_varint_with_len(37, width, &mut out), Ok(width));
            assert_eq!(decode_varint(&out), Ok((37, width)));
        }
    }

    #[test]
    fn varint_boundaries_and_atomic_errors() {
        let values = [
            0,
            1,
            63,
            64,
            16383,
            16384,
            (1 << 30) - 1,
            1 << 30,
            MAX_VARINT,
        ];
        for value in values {
            let mut out = [0xa5; 8];
            let length = encode_varint(value, &mut out).unwrap();
            assert_eq!(decode_varint(&out[..length]), Ok((value, length)));
            let mut short = [0xa5; 8];
            assert_eq!(
                encode_varint(value, &mut short[..length - 1]),
                Err(Error::BufferTooShort)
            );
            assert_eq!(short, [0xa5; 8]);
        }
        let mut out = [0x55; 8];
        assert_eq!(
            encode_varint(MAX_VARINT + 1, &mut out),
            Err(Error::VarIntTooLarge)
        );
        assert_eq!(
            encode_varint_with_len(64, 1, &mut out),
            Err(Error::InvalidVarIntWidth)
        );
        assert_eq!(
            encode_varint_with_len(1, 3, &mut out),
            Err(Error::InvalidVarIntWidth)
        );
        assert_eq!(out, [0x55; 8]);
    }

    #[test]
    fn packet_number_rfc_vector_and_wraps() {
        assert_eq!(
            restore_packet_number(0x9b32, 2, Some(0xa82f30ea)),
            Ok(0xa82f9b32)
        );
        assert_eq!(restore_packet_number(0, 1, None), Ok(0));
        assert_eq!(restore_packet_number(0, 1, Some(255)), Ok(256));
        assert_eq!(restore_packet_number(255, 1, Some(256)), Ok(255));
        assert_eq!(restore_packet_number(0, 1, Some(127)), Ok(256)); // Ties choose higher.
        assert_eq!(
            restore_packet_number(0, 0, None),
            Err(Error::InvalidPacketNumber)
        );
        assert_eq!(
            restore_packet_number(0, 5, None),
            Err(Error::InvalidPacketNumber)
        );
        assert_eq!(
            restore_packet_number(256, 1, None),
            Err(Error::InvalidPacketNumber)
        );
        assert_eq!(
            restore_packet_number(0, 1, Some(MAX_VARINT + 1)),
            Err(Error::InvalidPacketNumber)
        );
        assert_eq!(
            restore_packet_number(255, 1, Some(MAX_VARINT - 1)),
            Ok(MAX_VARINT)
        );
        assert_eq!(
            restore_packet_number(0, 1, Some(MAX_VARINT)),
            Err(Error::InvalidPacketNumber)
        );
    }

    #[test]
    fn packet_number_exhaustive_small_window_nearest_oracle() {
        // Independent candidate enumeration, not a copy of the decoding formula.
        for largest in 0..512u64 {
            let expected = largest + 1;
            for truncated in 0..256u64 {
                let mut nearest = truncated;
                for candidate in (truncated..1024).step_by(256) {
                    if candidate.abs_diff(expected) <= nearest.abs_diff(expected) {
                        nearest = candidate;
                    }
                }
                assert_eq!(
                    restore_packet_number(truncated, 1, Some(largest)),
                    Ok(nearest)
                );
            }
        }
    }

    #[test]
    fn packet_number_decodes_full_four_byte_field() {
        assert_eq!(
            decode_truncated_packet_number(0x43, &[0xfe, 0xdc, 0xba, 0x98]),
            Ok((0xfedcba98, 4))
        );
        assert_eq!(
            decode_truncated_packet_number(0x43, &[0, 1, 2]),
            Err(Error::Truncated)
        );
        assert_eq!(validate_reserved_bits(0xc0), Ok(()));
        assert_eq!(validate_reserved_bits(0xcc), Err(Error::ReservedBits));
        assert_eq!(validate_reserved_bits(0x64), Ok(())); // Spin/key phase are not reserved.
        assert_eq!(validate_reserved_bits(0x58), Err(Error::ReservedBits));
    }

    fn append_long(output: &mut [u8], kind: LongType) -> usize {
        let header = LongHeader {
            kind,
            destination_id: &[1, 2],
            source_id: &[3, 4],
            token: if kind == LongType::Initial {
                &[5, 6]
            } else {
                &[]
            },
            packet_number: 0x1234,
            packet_number_len: 2,
        };
        let length = encode_long_header(&header, 17, output).unwrap();
        output[length..length + 17].fill(0xab);
        length + 17
    }

    #[test]
    fn coalesced_long_and_short_packets_have_correct_boundaries() {
        let mut datagram = [0; 256];
        let mut lengths = [0; 4];
        let mut at = 0;
        for (i, kind) in [LongType::Initial, LongType::ZeroRtt, LongType::Handshake]
            .into_iter()
            .enumerate()
        {
            lengths[i] = append_long(&mut datagram[at..], kind);
            at += lengths[i];
        }
        let h = ShortHeader {
            destination_id: &[1, 2],
            packet_number: 0x99,
            packet_number_len: 1,
            spin: true,
            key_phase: true,
        };
        let n = encode_short_header(&h, &mut datagram[at..]).unwrap();
        datagram[at + n..at + n + 17].fill(0x66);
        lengths[3] = n + 17;
        at += lengths[3];
        let mut packets = PacketIter::new(&datagram[..at], 2, 4).unwrap();
        let first = packets.next().unwrap().unwrap();
        assert_eq!(first.bytes.len(), lengths[0]);
        match first.header {
            Header::Long {
                kind,
                destination_id,
                source_id,
                token,
                packet_number_offset,
            } => {
                assert_eq!(kind, LongType::Initial);
                assert_eq!(destination_id, &[1, 2]);
                assert_eq!(source_id, &[3, 4]);
                assert_eq!(token, &[5, 6]);
                assert_eq!(
                    &first.bytes[packet_number_offset..packet_number_offset + 2],
                    &[0x12, 0x34]
                );
            }
            _ => panic!("wrong header"),
        }
        assert_eq!(packets.next().unwrap().unwrap().bytes.len(), lengths[1]);
        assert_eq!(packets.next().unwrap().unwrap().bytes.len(), lengths[2]);
        assert!(matches!(
            packets.next().unwrap().unwrap().header,
            Header::Short {
                packet_number_offset: 3,
                ..
            }
        ));
        assert!(packets.next().is_none());
        assert!(packets.next().is_none());
        let mut limited = PacketIter::new(&datagram[..at], 2, 1).unwrap();
        assert!(limited.next().unwrap().is_ok());
        assert_eq!(
            limited.next(),
            Some(Err(Error::LimitExceeded(ResourceLimit::Packets)))
        );
        assert_eq!(limited.next(), None);
    }

    #[test]
    fn packet_truncation_lengths_and_fixed_bit_are_checked() {
        let mut packet = [0; 128];
        let length = append_long(&mut packet, LongType::Initial);
        for n in 1..length {
            assert!(
                PacketIter::new(&packet[..n], 2, 1)
                    .unwrap()
                    .next()
                    .unwrap()
                    .is_err(),
                "accepted prefix {n}"
            );
        }
        packet[0] &= !0x40;
        assert_eq!(
            PacketIter::new(&packet[..length], 2, 1).unwrap().next(),
            Some(Err(Error::InvalidFixedBit))
        );
        assert_eq!(
            PacketIter::new(&[0x40, 1, 2], 2, 1).unwrap().next(),
            Some(Err(Error::Truncated))
        );
        assert_eq!(
            PacketIter::new(&[0, 1], 0, 1).unwrap().next(),
            Some(Err(Error::InvalidFixedBit))
        );
        // Long Handshake Length=0.
        assert_eq!(
            PacketIter::new(&[0xe0, 0, 0, 0, 1, 0, 0, 0], 0, 1)
                .unwrap()
                .next(),
            Some(Err(Error::InvalidLength))
        );
        // Protected low bits are not interpreted by the boundary parser.
        let mut protected = [0; 128];
        let length = append_long(&mut protected, LongType::Handshake);
        protected[0] |= 0x0f;
        assert!(
            PacketIter::new(&protected[..length], 0, 1)
                .unwrap()
                .next()
                .unwrap()
                .is_ok()
        );
    }

    #[test]
    fn non_minimal_header_lengths_are_accepted() {
        // Initial: empty CIDs, token length=1 encoded in two bytes, one token
        // byte, packet length=2 encoded in four bytes, then two protected bytes.
        let wire = [
            0xc0, 0, 0, 0, 1, 0, 0, 0x40, 1, 0x55, 0x80, 0, 0, 2, 0x44, 0xaa,
        ];
        let packet = PacketIter::new(&wire, 0, 1)
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(packet.bytes.len(), wire.len());
        assert!(matches!(
            packet.header,
            Header::Long {
                token: [0x55],
                packet_number_offset: 14,
                ..
            }
        ));
    }

    #[test]
    fn unknown_version_and_version_negotiation_are_version_independent() {
        let packet = [0x80, 0, 0, 0, 2, 0, 0, 0xaa];
        assert!(matches!(
            PacketIter::new(&packet, 0, 1)
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .header,
            Header::UnsupportedVersion { version: 2, .. }
        ));
        let mut vn = [0u8; 64];
        vn[0] = 0x80; // Fixed bit is deliberately zero.
        vn[5] = 21;
        vn[27] = 0;
        vn[31] = 1;
        vn[35] = 2;
        let packet = PacketIter::new(&vn[..36], 0, 1)
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        match packet.header {
            Header::VersionNegotiation {
                destination_id,
                versions,
                ..
            } => {
                assert_eq!(destination_id.len(), 21);
                let mut iter = versions.iter();
                assert_eq!(iter.next(), Some(1));
                assert_eq!(iter.next(), Some(2));
                assert_eq!(iter.next(), None);
            }
            _ => panic!("wrong header"),
        }
        assert_eq!(
            PacketIter::new(&vn[..35], 0, 1).unwrap().next(),
            Some(Err(Error::InvalidVersionNegotiation))
        );
        assert_eq!(
            PacketIter::new(&vn[..28], 0, 1).unwrap().next(),
            Some(Err(Error::InvalidVersionNegotiation))
        );
        vn[4] = 1;
        assert_eq!(
            PacketIter::new(&vn[..36], 0, 1).unwrap().next(),
            Some(Err(Error::InvalidConnectionIdLength))
        );
    }

    #[test]
    fn retry_requires_token_and_full_tag() {
        let mut retry = [0u8; 25];
        retry[0] = 0xf0;
        retry[4] = 1;
        retry[7] = 0x77;
        retry[8..].fill(0xaa);
        match PacketIter::new(&retry, 0, 1)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .header
        {
            Header::Retry {
                token,
                integrity_tag,
                ..
            } => {
                assert_eq!(token, &[0x77, 0xaa]);
                assert_eq!(integrity_tag, &[0xaa; 16]);
            }
            _ => panic!("wrong header"),
        }
        assert_eq!(
            PacketIter::new(&retry[..23], 0, 1).unwrap().next(),
            Some(Err(Error::EmptyToken))
        );
        assert_eq!(
            PacketIter::new(&retry[..22], 0, 1).unwrap().next(),
            Some(Err(Error::Truncated))
        );
    }

    #[test]
    fn header_encoding_errors_do_not_modify_output() {
        let mut out = [0x55; 64];
        let mut h = LongHeader {
            kind: LongType::Handshake,
            destination_id: &[],
            source_id: &[],
            token: &[1],
            packet_number: 0,
            packet_number_len: 1,
        };
        assert_eq!(
            encode_long_header(&h, 16, &mut out),
            Err(Error::InvalidLength)
        );
        h.token = &[];
        h.packet_number_len = 0;
        assert_eq!(
            encode_long_header(&h, 16, &mut out),
            Err(Error::InvalidPacketNumber)
        );
        h.packet_number_len = 4;
        h.packet_number = MAX_VARINT + 1;
        assert_eq!(
            encode_long_header(&h, 16, &mut out),
            Err(Error::InvalidPacketNumber)
        );
        h.packet_number = MAX_VARINT;
        assert_eq!(
            encode_long_header(&h, 16, &mut out[..2]),
            Err(Error::BufferTooShort)
        );
        assert_eq!(out, [0x55; 64]);
        let short = ShortHeader {
            destination_id: &[1; 21],
            packet_number: 0,
            packet_number_len: 1,
            spin: false,
            key_phase: false,
        };
        assert_eq!(
            encode_short_header(&short, &mut out),
            Err(Error::InvalidConnectionIdLength)
        );
        assert_eq!(out, [0x55; 64]);
    }

    #[test]
    fn all_v1_frame_shapes_roundtrip_without_allocation() {
        let ack_ranges = [
            AckRange {
                smallest: 90,
                largest: 100,
            },
            AckRange {
                smallest: 1,
                largest: 3,
            },
        ];
        let ranges = AckRanges::new(&ack_ranges).unwrap();
        let token = [0x55; 16];
        let path = [0xaa; 8];
        let frames = [
            Frame::Padding { length: 12 },
            Frame::Ping,
            Frame::Ack {
                delay: 3,
                ranges,
                ecn: None,
            },
            Frame::Ack {
                delay: 3,
                ranges,
                ecn: Some(EcnCounts {
                    ect0: 7,
                    ect1: 8,
                    ce: 9,
                }),
            },
            Frame::ResetStream {
                id: 9,
                error_code: 99,
                final_size: 1234,
            },
            Frame::StopSending {
                id: 9,
                error_code: 99,
            },
            Frame::Crypto {
                offset: 100,
                data: b"crypto",
            },
            Frame::NewToken { token: b"token" },
            Frame::Stream {
                id: 1,
                offset: 0,
                fin: false,
                data: b"abc",
            },
            Frame::Stream {
                id: 1,
                offset: 99,
                fin: true,
                data: b"def",
            },
            Frame::Stream {
                id: 1,
                offset: 0,
                fin: true,
                data: b"",
            },
            Frame::MaxData {
                maximum: MAX_VARINT,
            },
            Frame::MaxStreamData {
                id: 9,
                maximum: MAX_VARINT,
            },
            Frame::MaxStreams {
                bidirectional: true,
                maximum: MAX_STREAM_COUNT,
            },
            Frame::MaxStreams {
                bidirectional: false,
                maximum: 1,
            },
            Frame::DataBlocked { limit: 100 },
            Frame::StreamDataBlocked { id: 9, limit: 200 },
            Frame::StreamsBlocked {
                bidirectional: true,
                limit: MAX_STREAM_COUNT,
            },
            Frame::StreamsBlocked {
                bidirectional: false,
                limit: 1,
            },
            Frame::NewConnectionId {
                sequence: 9,
                retire_prior_to: 8,
                id: &[1, 2, 3],
                reset_token: &token,
            },
            Frame::RetireConnectionId { sequence: 9 },
            Frame::PathChallenge { data: &path },
            Frame::PathResponse { data: &path },
            Frame::ConnectionClose {
                error_code: 7,
                frame_type: Some(6),
                reason: b"why",
            },
            Frame::ConnectionClose {
                error_code: 7,
                frame_type: None,
                reason: b"why",
            },
            Frame::HandshakeDone,
        ];
        for frame in frames {
            let mut wire = [0xcc; 256];
            let length = encode_frame(&frame, &mut wire).unwrap();
            assert_eq!(frame_encoded_len(&frame), Ok(length));
            let parsed = first_frame(&wire[..length]).unwrap();
            if let Frame::Ack {
                ranges: parsed_ranges,
                delay,
                ecn,
            } = parsed
            {
                assert_eq!(parsed_ranges.len(), 2);
                assert_eq!(parsed_ranges.iter().next(), Some(ack_ranges[0]));
                assert_eq!(parsed_ranges.iter().nth(1), Some(ack_ranges[1]));
                assert_eq!(delay, 3);
                if let Frame::Ack { ecn: expected, .. } = frame {
                    assert_eq!(ecn, expected);
                }
            } else {
                assert_eq!(parsed, frame);
            }
            let mut roundtrip = [0; 256];
            assert_eq!(encode_frame(&parsed, &mut roundtrip), Ok(length));
            assert_eq!(&roundtrip[..length], &wire[..length]);
            let mut too_short = [0xcc; 256];
            assert_eq!(
                encode_frame(&frame, &mut too_short[..length - 1]),
                Err(Error::BufferTooShort)
            );
            assert_eq!(too_short, [0xcc; 256]);
        }
    }

    #[test]
    fn non_minimal_frame_type_rejected_other_fields_accepted() {
        assert_eq!(first_frame(&[0x40, 1]), Err(Error::NonMinimalFrameType));
        assert_eq!(first_frame(&[0x40, 0x40]), Err(Error::UnknownFrameType(64)));
        assert_eq!(first_frame(&[0x1f]), Err(Error::UnknownFrameType(31)));
        assert_eq!(
            first_frame(&[0x10, 0x40, 1]),
            Ok(Frame::MaxData { maximum: 1 })
        );
        assert_eq!(
            first_frame(&[0x08, 0x40, 1, 0xaa]),
            Ok(Frame::Stream {
                id: 1,
                offset: 0,
                fin: false,
                data: &[0xaa]
            })
        );
    }

    #[test]
    fn all_stream_type_bits_and_no_length_consumes_remainder() {
        for ty in 8..=15u8 {
            let mut bytes = [0; 32];
            bytes[0] = ty;
            bytes[1] = 1;
            let mut at = 2;
            let offset = if ty & 4 != 0 {
                bytes[at] = 9;
                at += 1;
                9
            } else {
                0
            };
            if ty & 2 != 0 {
                bytes[at] = 2;
                at += 1;
            }
            bytes[at..at + 2].copy_from_slice(&[0xff, 0x01]);
            at += 2;
            assert_eq!(
                first_frame(&bytes[..at]),
                Ok(Frame::Stream {
                    id: 1,
                    offset,
                    fin: ty & 1 != 0,
                    data: &[0xff, 1]
                })
            );
            let mut it = FrameIter::new(
                &bytes[..at],
                EncryptionLevel::OneRtt,
                ParseLimits::default(),
            )
            .unwrap();
            assert!(it.next().unwrap().is_ok());
            assert!(it.next().is_none());
        }
    }

    #[test]
    fn ack_ranges_have_inclusive_bounds_and_validate_underflow() {
        // 10..=12 then 5..=7, with two missing packets (8 and 9).
        let bytes = [2, 12, 0, 1, 2, 1, 2];
        match first_frame(&bytes).unwrap() {
            Frame::Ack { ranges, .. } => {
                let mut iter = ranges.iter();
                assert_eq!(iter.len(), 2);
                assert_eq!(
                    iter.next(),
                    Some(AckRange {
                        smallest: 10,
                        largest: 12
                    })
                );
                assert_eq!(
                    iter.next(),
                    Some(AckRange {
                        smallest: 5,
                        largest: 7
                    })
                );
                assert_eq!(iter.next(), None);
                assert_eq!(iter.len(), 0);
            }
            _ => panic!("wrong frame"),
        }
        for invalid in [
            &[2, 0, 0, 0, 1][..],       // First range exceeds largest.
            &[2, 1, 0, 1, 0, 0, 0][..], // Gap needs subtraction of at least 2.
            &[2, 5, 0, 1, 0, 4, 0][..], // Gap exceeds preceding smallest.
            &[2, 5, 0, 1, 0, 0, 4][..], // Later range exceeds computed largest.
        ] {
            assert_eq!(first_frame(invalid), Err(Error::InvalidAckRange));
        }
        let mut huge = [0; 32];
        huge[0] = 2;
        let mut at = 1;
        for value in [MAX_VARINT, 0, MAX_VARINT, 0] {
            put(value, &mut huge, &mut at);
        }
        assert_eq!(
            first_frame(&huge[..at]),
            Err(Error::LimitExceeded(ResourceLimit::AckRanges))
        );
    }

    #[test]
    fn ack_range_constructor_rejects_empty_adjacent_overlapping_and_overflow() {
        assert!(AckRanges::new(&[]).is_err());
        assert!(
            AckRanges::new(&[AckRange {
                smallest: 4,
                largest: 3
            }])
            .is_err()
        );
        assert!(
            AckRanges::new(&[AckRange {
                smallest: 0,
                largest: MAX_VARINT + 1
            }])
            .is_err()
        );
        for lower_largest in [9, 10, 11] {
            assert!(
                AckRanges::new(&[
                    AckRange {
                        smallest: 10,
                        largest: 20
                    },
                    AckRange {
                        smallest: 1,
                        largest: lower_largest
                    }
                ])
                .is_err()
            );
        }
        assert!(
            AckRanges::new(&[
                AckRange {
                    smallest: 10,
                    largest: 20
                },
                AckRange {
                    smallest: 1,
                    largest: 8
                }
            ])
            .is_ok()
        );
    }

    #[test]
    fn truncated_frames_and_ack_ecn_fields_fail() {
        for bytes in [
            &[2][..],
            &[2, 10, 0, 1, 0][..],
            &[3, 0, 0, 0, 0, 0, 0][..],
            &[4, 1, 2][..],
            &[5, 1][..],
            &[6, 0, 2, 0][..],
            &[7, 2, 0][..],
            &[0x0e, 1, 0, 2, 0][..],
            &[0x1a, 0, 0, 0, 0, 0, 0, 0][..],
            &[0x1c, 1, 1, 2, 0][..],
        ] {
            assert_eq!(first_frame(bytes), Err(Error::Truncated), "{bytes:?}");
        }
    }

    #[test]
    fn stream_and_crypto_offsets_cannot_exceed_sixty_two_bits() {
        for ty in [0x06, 0x0e] {
            let mut bytes = [0u8; 32];
            bytes[0] = ty;
            let mut at = 1;
            if ty == 0x0e {
                put(0, &mut bytes, &mut at);
            }
            put(MAX_VARINT, &mut bytes, &mut at);
            put(1, &mut bytes, &mut at);
            bytes[at] = 1;
            at += 1;
            assert_eq!(first_frame(&bytes[..at]), Err(Error::InvalidOffset));
        }
        assert!(
            frame_encoded_len(&Frame::Stream {
                id: 0,
                offset: MAX_VARINT,
                fin: true,
                data: &[]
            })
            .is_ok()
        );
        assert_eq!(
            frame_encoded_len(&Frame::Crypto {
                offset: MAX_VARINT,
                data: &[1]
            }),
            Err(Error::InvalidOffset)
        );
    }

    #[test]
    fn cid_token_and_stream_count_constraints() {
        assert_eq!(first_frame(&[7, 0]), Err(Error::EmptyToken));
        assert_eq!(
            first_frame(&[0x18, 0, 1, 1]),
            Err(Error::InvalidRetirePriorTo)
        );
        assert_eq!(
            first_frame(&[0x18, 1, 0, 0]),
            Err(Error::InvalidConnectionIdLength)
        );
        assert_eq!(
            first_frame(&[0x18, 1, 0, 21]),
            Err(Error::InvalidConnectionIdLength)
        );
        for ty in [0x12, 0x13, 0x16, 0x17] {
            let mut bytes = [0; 9];
            bytes[0] = ty;
            encode_varint(MAX_STREAM_COUNT + 1, &mut bytes[1..]).unwrap();
            assert_eq!(first_frame(&bytes), Err(Error::InvalidStreamCount));
        }
    }

    #[test]
    fn level_permissions_match_rfc_table_three() {
        for ty in 0..=0x1e {
            assert!(frame_allowed(ty, EncryptionLevel::OneRtt));
            assert_eq!(
                frame_allowed(ty, EncryptionLevel::Initial),
                [0, 1, 2, 3, 6, 0x1c].contains(&ty)
            );
            assert_eq!(
                frame_allowed(ty, EncryptionLevel::Handshake),
                [0, 1, 2, 3, 6, 0x1c].contains(&ty)
            );
            assert_eq!(
                frame_allowed(ty, EncryptionLevel::ZeroRtt),
                ![2, 3, 6, 7, 0x1b, 0x1e].contains(&ty)
            );
        }
        let mut iter =
            FrameIter::new(&[8, 0], EncryptionLevel::Handshake, ParseLimits::default()).unwrap();
        assert_eq!(
            iter.next(),
            Some(Err(Error::FrameNotAllowed {
                frame_type: 8,
                level: EncryptionLevel::Handshake
            }))
        );
        assert_eq!(iter.next(), None);
        assert!(!frame_allowed(0x1f, EncryptionLevel::OneRtt));
    }

    #[test]
    fn local_limits_are_distinct_fused_errors() {
        let limits = ParseLimits {
            max_bytes: 3,
            max_frames: 2,
            max_ack_ranges: 1,
        };
        assert!(matches!(
            FrameIter::new(&[1; 4], EncryptionLevel::OneRtt, limits),
            Err(Error::LimitExceeded(ResourceLimit::Bytes))
        ));
        assert!(matches!(
            FrameIter::new(&[], EncryptionLevel::OneRtt, limits),
            Err(Error::EmptyPayload)
        ));
        let mut iter = FrameIter::new(&[1, 1, 1], EncryptionLevel::OneRtt, limits).unwrap();
        assert_eq!(iter.next(), Some(Ok(Frame::Ping)));
        assert_eq!(iter.next(), Some(Ok(Frame::Ping)));
        assert_eq!(
            iter.next(),
            Some(Err(Error::LimitExceeded(ResourceLimit::Frames)))
        );
        assert_eq!(iter.next(), None);
        let mut malformed = FrameIter::new(&[0x1f, 1], EncryptionLevel::OneRtt, limits).unwrap();
        assert_eq!(malformed.next(), Some(Err(Error::UnknownFrameType(31))));
        assert_eq!(malformed.next(), None);
        let limits = ParseLimits {
            max_bytes: 100,
            ..limits
        };
        let mut ack =
            FrameIter::new(&[2, 10, 0, 1, 0, 0, 0], EncryptionLevel::OneRtt, limits).unwrap();
        assert_eq!(
            ack.next(),
            Some(Err(Error::LimitExceeded(ResourceLimit::AckRanges)))
        );
    }

    #[test]
    fn padding_runs_are_bounded_and_frame_flags_are_classified() {
        let mut iter = FrameIter::new(
            &[0, 0, 0, 1],
            EncryptionLevel::OneRtt,
            ParseLimits::default(),
        )
        .unwrap();
        assert_eq!(iter.next(), Some(Ok(Frame::Padding { length: 3 })));
        assert_eq!(iter.next(), Some(Ok(Frame::Ping)));
        assert_eq!(iter.next(), None);
        assert!(!Frame::Padding { length: 3 }.ack_eliciting());
        assert!(Frame::Padding { length: 3 }.probing());
        assert!(Frame::Ping.ack_eliciting());
        assert!(!Frame::Ping.probing());
        assert!(
            !Frame::ConnectionClose {
                error_code: 0,
                frame_type: Some(0),
                reason: &[]
            }
            .ack_eliciting()
        );
    }

    #[test]
    fn invalid_outbound_frames_do_not_modify_output() {
        let token = [0; 16];
        let invalid = [
            Frame::Padding { length: 0 },
            Frame::NewToken { token: &[] },
            Frame::Crypto {
                offset: MAX_VARINT,
                data: &[1],
            },
            Frame::Stream {
                id: MAX_VARINT + 1,
                offset: 0,
                fin: false,
                data: &[],
            },
            Frame::MaxStreams {
                bidirectional: true,
                maximum: MAX_STREAM_COUNT + 1,
            },
            Frame::StreamsBlocked {
                bidirectional: false,
                limit: MAX_STREAM_COUNT + 1,
            },
            Frame::NewConnectionId {
                sequence: 0,
                retire_prior_to: 1,
                id: &[1],
                reset_token: &token,
            },
            Frame::NewConnectionId {
                sequence: 1,
                retire_prior_to: 0,
                id: &[],
                reset_token: &token,
            },
        ];
        for frame in invalid {
            let mut out = [0xa5; 256];
            assert!(encode_frame(&frame, &mut out).is_err());
            assert_eq!(out, [0xa5; 256]);
        }
    }

    #[test]
    fn borrowed_payload_refers_to_original_input() {
        let wire = [0x0a, 1, 3, 7, 8, 9];
        match first_frame(&wire).unwrap() {
            Frame::Stream { data, .. } => assert_eq!(data.as_ptr(), wire[3..].as_ptr()),
            _ => panic!("wrong frame"),
        }
    }

    #[test]
    fn deterministic_malformed_input_smoke_has_no_panics_or_unbounded_iteration() {
        let mut state = 0x9e3779b97f4a7c15u64;
        let mut input = [0u8; 96];
        for case in 0..20000usize {
            for byte in &mut input {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            let length = case % input.len() + 1;
            let bytes = &input[..length];
            let limits = ParseLimits {
                max_bytes: 96,
                max_frames: 16,
                max_ack_ranges: 8,
            };
            for level in [
                EncryptionLevel::Initial,
                EncryptionLevel::Handshake,
                EncryptionLevel::ZeroRtt,
                EncryptionLevel::OneRtt,
            ] {
                let iter = FrameIter::new(bytes, level, limits).unwrap();
                let mut count = 0;
                for frame in iter {
                    count += 1;
                    assert!(count <= 17);
                    if let Ok(Frame::Ack { ranges, .. }) = frame {
                        assert!(ranges.iter().count() <= 8);
                    }
                }
            }
            let mut count = 0;
            for packet in PacketIter::new(bytes, case % 21, 8).unwrap() {
                count += 1;
                assert!(count <= 9);
                if let Ok(packet) = packet {
                    assert!(!packet.bytes.is_empty());
                }
            }
        }
    }
}
