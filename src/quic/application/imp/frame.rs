//! Authenticated packet effects, frame bounds and QUIC error-code classification.
use crate::quic::application::{Error, imp::stream};
use crate::quic::imp::kernel::packet::{Frame, Header, LongType};
use crate::quic::imp::tls::Transcript;
use crate::quic::imp::{
    kernel::{
        accounting::AccountingError,
        packet::{self, FrameIter, ParseLimits},
        streams,
    },
    recovery,
};
use crate::quic::{Config, ReceiveMaterial, Side};
use crate::{crypto, quic};
use hibana_tls::{quic::Level, secret::Secret};

/// Keep the effect pass bounded identically to recovery's complete preflight.
/// The caller retains the exact authenticated plaintext throughout both passes;
/// no copied packet number or frame alone grants application delivery.
pub(in crate::quic::application) fn received_frames(
    plaintext: &[u8],
    level: packet::EncryptionLevel,
) -> Result<FrameIter<'_>, Error> {
    Ok(FrameIter::new(
        plaintext,
        level,
        ParseLimits {
            max_bytes: plaintext.len(),
            max_frames: 256,
            max_ack_ranges: recovery::ACK_CAPACITY,
        },
    )?)
}

pub(in crate::quic::application) fn discard_before_authentication(error: &quic::Error) -> bool {
    matches!(
        error,
        quic::Error::Binding
            | quic::Error::Capacity
            | quic::Error::Crypto(
                crypto::Error::AuthenticationFailed
                    | crypto::Error::InvalidPacketNumber
                    | crypto::Error::InvalidHeader
                    | crypto::Error::BufferTooSmall
                    | crypto::Error::PacketTooLarge
            )
            | quic::Error::Packet(
                packet::Error::Truncated
                    | packet::Error::BufferTooShort
                    | packet::Error::InvalidPacketNumber
                    | packet::Error::InvalidFixedBit
                    | packet::Error::InvalidLength
                    | packet::Error::InvalidConnectionIdLength
            )
    )
}

pub(in crate::quic::application) fn protocol_code(error: &Error) -> u64 {
    match error {
        Error::Streams(stream::Error::Streams(streams::Error::FlowControl)) => 0x3,
        Error::Streams(stream::Error::Streams(streams::Error::StreamLimit)) => 0x4,
        Error::Streams(stream::Error::Streams(streams::Error::FinalSize)) => 0x6,
        Error::Streams(_) => 0x5,
        Error::Crypto(crypto::Error::KeyUpdateError)
        | Error::Connection(quic::Error::Crypto(crypto::Error::KeyUpdateError)) => 0xe,
        Error::Crypto(crypto::Error::IntegrityLimit | crypto::Error::ConfidentialityLimit)
        | Error::Connection(quic::Error::Crypto(
            crypto::Error::IntegrityLimit | crypto::Error::ConfidentialityLimit,
        )) => 0xf,
        Error::Packet(packet::Error::ReservedBits | packet::Error::EmptyPayload)
        | Error::Connection(quic::Error::Packet(
            packet::Error::ReservedBits | packet::Error::EmptyPayload,
        )) => 0xa,
        Error::Packet(_) | Error::Recovery(recovery::Error::Packet(_)) => 0x7,
        Error::Recovery(recovery::Error::Accounting(AccountingError::UnsentPacket)) => 0xa,
        _ => 0xa,
    }
}

/// Authenticate late Initial/Handshake traffic against the retained keys.
/// This synchronous effect pass cannot advance a Hibana endpoint or re-enter TLS.
#[allow(clippy::too_many_arguments)]
pub(in crate::quic::application) fn receive_handshake_packet<'book, 'scope, const N: usize>(
    material: &mut ReceiveMaterial<'scope>,
    packet: packet::Packet<'_>,
    datagram_len: usize,
    config: Config<'_>,
    transcript: &Transcript<'scope, '_, '_>,
    book: &mut recovery::Rx<'book, 'scope, N>,
    now: u64,
    ecn: Option<crate::io::Codepoint>,
) -> Result<Option<(bool, u64)>, Error> {
    let Header::Long {
        version,
        kind,
        destination_id,
        source_id,
        packet_number_offset,
        ..
    } = packet.header
    else {
        return Ok(None);
    };
    if kind == LongType::Handshake && version != config.version {
        return Ok(None);
    }
    if destination_id != config.local_connection_id
        && !(config.side == Side::Server
            && kind == LongType::Initial
            && destination_id
                == config
                    .retry_source_id
                    .unwrap_or(config.original_destination_id))
    {
        return Ok(None);
    }
    let (index, level, encryption) = match kind {
        LongType::Initial if config.side != Side::Server || datagram_len >= 1200 => {
            (0, Level::Initial, packet::EncryptionLevel::Initial)
        }
        LongType::Handshake => (1, Level::Handshake, packet::EncryptionLevel::Handshake),
        _ => return Ok(None),
    };
    if packet.bytes.len() > N {
        return Ok(None);
    }
    let key = if index == 0 {
        // Initial retirement has its own finite projected lane in the prefix.
        // Once that lane consumes the key, late Initial packets are discarded.
        let Some(initial) = material.initial.as_ref() else {
            return Ok(None);
        };
        initial
    } else {
        &material.handshake
    };
    let mut opened = Secret::new([0u8; N]);
    opened[..packet.bytes.len()].copy_from_slice(packet.bytes);
    let bytes = &mut opened[..packet.bytes.len()];
    let pn_len = match key.unprotect_header(bytes, packet_number_offset) {
        Ok(len) => len,
        Err(_) => return Ok(None),
    };
    let truncated =
        match packet::decode_truncated_packet_number(bytes[0], &bytes[packet_number_offset..]) {
            Ok((truncated, _)) => truncated,
            Err(_) => return Ok(None),
        };
    let pn = match packet::restore_packet_number(
        truncated,
        pn_len as u8,
        material.largest_received[index],
    ) {
        Ok(pn) => pn,
        Err(_) => return Ok(None),
    };
    let (header, payload) = bytes.split_at_mut(packet_number_offset + pn_len);
    let receipt = match key.open_authenticated(pn, header, payload, &mut material.integrity) {
        Ok(receipt) => receipt,
        Err(crypto::Error::AuthenticationFailed) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    packet::validate_reserved_bits(header[0])?;
    if source_id != material.peer_connection_id() {
        return Err(Error::Binding);
    }
    let plaintext = &payload[..receipt.len()];
    if plaintext.is_empty() {
        return Err(packet::Error::EmptyPayload.into());
    }
    material.largest_received[index] =
        Some(material.largest_received[index].map_or(pn, |last| last.max(pn)));
    let outcome = match book.apply_packet(receipt, plaintext, now, now, ecn) {
        Ok(outcome) => outcome,
        Err(recovery::Error::Accounting(AccountingError::HistoryUnavailable)) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !outcome.duplicate {
        for frame in received_frames(plaintext, encryption)? {
            match frame? {
                Frame::Crypto { offset, data } => {
                    let end = offset
                        .checked_add(data.len() as u64)
                        .ok_or(Error::Capacity)?;
                    if end > transcript.received_offset(level) {
                        // Finished is a finite boundary. New Initial/Handshake
                        // transcript bytes cannot re-enter completed TLS.
                        return Err(quic::Error::UnsupportedFrame.into());
                    }
                }
                Frame::ConnectionClose {
                    error_code,
                    frame_type,
                    ..
                } => return Ok(Some((frame_type.is_none(), error_code))),
                Frame::Padding { .. } | Frame::Ping | Frame::Ack { .. } => {}
                _ => return Err(quic::Error::UnsupportedFrame.into()),
            }
        }
    }
    Ok(None)
}
