//! Stateless Initial integrity arithmetic before allocating a connection.
use hibana_quic::quic::imp::kernel::packet::Header;
use hibana_quic::quic::imp::kernel::packet::LongType;
/// Stateless integrity check before committing routing identities or a worker.
/// Initial keys are public: this is not TLS peer authentication. The untouched
/// datagram still enters the ordinary Hibana receive/authentication contract.
pub fn initial_integrity(
    packet: &hibana_quic::quic::imp::kernel::packet::Packet<'_>,
) -> Option<()> {
    let Header::Long {
        kind: LongType::Initial,
        destination_id,
        packet_number_offset,
        ..
    } = packet.header
    else {
        return None;
    };
    if packet.bytes.len() > crate::connection::DATAGRAM {
        return None;
    }
    let key = hibana_quic::crypto::initial_keys(destination_id)
        .ok()?
        .client;
    let mut bytes = packet.bytes.to_vec();
    let pn_len = key
        .unprotect_header(&mut bytes, packet_number_offset)
        .ok()?;
    let (truncated, _) = hibana_quic::quic::imp::kernel::packet::decode_truncated_packet_number(
        bytes[0],
        bytes.get(packet_number_offset..packet_number_offset.checked_add(pn_len)?)?,
    )
    .ok()?;
    let pn = hibana_quic::quic::imp::kernel::packet::restore_packet_number(
        truncated,
        pn_len as u8,
        None,
    )
    .ok()?;
    let first = bytes[0];
    let (aad, ciphertext) = bytes.split_at_mut(packet_number_offset + pn_len);
    key.open(
        pn,
        aad,
        ciphertext,
        &mut hibana_quic::crypto::IntegrityBudget::new(),
    )
    .ok()?;
    hibana_quic::quic::imp::kernel::packet::validate_reserved_bits(first).ok()?;
    Some(())
}
