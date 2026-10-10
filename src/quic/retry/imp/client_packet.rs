//! Bounded Retry response bytes and authenticated packet inspection.
use crate::quic::imp::kernel::packet::{self, Header, LongType, PacketIter};
use crate::quic::*;
pub(in crate::quic) const TOKEN_CAPACITY: usize = 512;
pub(in crate::quic) struct RetryData {
    pub source: ConnectionId,
    pub(in crate::quic::retry) token: [u8; TOKEN_CAPACITY],
    pub(in crate::quic::retry) len: usize,
}
impl RetryData {
    pub fn token(&self) -> &[u8] {
        &self.token[..self.len]
    }
}
pub(in crate::quic) struct Response<const N: usize> {
    pub bytes: [u8; N],
    pub received: ReceivedDatagram,
    pub retry: Option<RetryData>,
}

// Retained ciphertext has no authenticated protocol effects. The same bounded
// owner moves from the Retry prefix into the ordinary receive continuation.
pub(in crate::quic) fn retain_handshake<const N: usize>(
    pending: &mut Option<([u8; N], ReceivedDatagram, u64)>,
    bytes: &[u8],
    received: ReceivedDatagram,
    config: Config<'_>,
    received_at: u64,
) {
    if pending.is_some() {
        return;
    }
    let Ok(packets) = PacketIter::new(bytes, config.local_connection_id.len(), 16) else {
        return;
    };
    for packet in packets {
        let Ok(packet) = packet else {
            break;
        };
        if let Header::Long {
            version,
            kind: LongType::Handshake,
            destination_id,
            ..
        } = packet.header
            && version == config.version
            && destination_id == config.local_connection_id
            && packet.bytes.len() <= N
        {
            let mut retained = [0; N];
            retained[..packet.bytes.len()].copy_from_slice(packet.bytes);
            *pending = Some((
                retained,
                ReceivedDatagram {
                    len: packet.bytes.len(),
                    ..received
                },
                received_at,
            ));
            break;
        }
    }
}

// Packet validation only. No progression or communication is hidden here.
pub(in crate::quic::retry) fn authenticated_initial<const N: usize>(
    bytes: &[u8],
    config: Config<'_>,
    keys: &crate::quic::imp::initial::Keys<'_>,
    integrity: &mut IntegrityBudget,
) -> Result<bool, Error> {
    let Some(Ok(packet)) = PacketIter::new(bytes, config.local_connection_id.len(), 1)
        .ok()
        .and_then(|mut packets| packets.next())
    else {
        return Ok(false);
    };
    let Header::Long {
        version,
        kind: LongType::Initial,
        destination_id,
        packet_number_offset,
        ..
    } = packet.header
    else {
        return Ok(false);
    };
    if (version != config.version && version != crate::quic::imp::kernel::version::Version::V1)
        || destination_id != config.local_connection_id
        || packet.bytes.len() > N
    {
        return Ok(false);
    }
    let mut opened = [0; N];
    opened[..packet.bytes.len()].copy_from_slice(packet.bytes);
    let bytes = &mut opened[..packet.bytes.len()];
    let guard = keys.read_version(version);
    let key = guard.as_ref().ok_or(Error::Binding)?;
    let pn_len = match key.unprotect_header(bytes, packet_number_offset) {
        Ok(n) => n,
        Err(_) => return Ok(false),
    };
    let (truncated, _) =
        packet::decode_truncated_packet_number(bytes[0], &bytes[packet_number_offset..])?;
    let pn = packet::restore_packet_number(truncated, pn_len as u8, None)?;
    let (header, payload) = bytes.split_at_mut(packet_number_offset + pn_len);
    match key.open_authenticated(pn, header, payload, integrity) {
        Ok(_) => Ok(packet::validate_reserved_bits(header[0]).is_ok()),
        Err(crypto::Error::AuthenticationFailed) => Ok(false),
        Err(e) => Err(e.into()),
    }
}
