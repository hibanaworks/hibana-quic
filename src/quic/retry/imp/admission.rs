//! Stateless Initial integrity arithmetic before allocating a connection.
use crate::quic::imp::kernel::packet::Header;
use crate::quic::imp::kernel::packet::LongType;
/// Stateless integrity check before committing routing identities or a worker.
/// Initial keys are public: this is not TLS peer authentication. The untouched
/// datagram still enters the ordinary Hibana receive/authentication contract.
pub fn initial_integrity(
    packet: &crate::quic::imp::kernel::packet::Packet<'_>,
    scratch: &mut [u8],
) -> Option<()> {
    let Header::Long {
        kind: LongType::Initial,
        version,
        destination_id,
        packet_number_offset,
        ..
    } = packet.header
    else {
        return None;
    };
    let key = crate::crypto::initial_keys_for_version(version, destination_id)
        .ok()?
        .client;
    let bytes = scratch.get_mut(..packet.bytes.len())?;
    bytes.copy_from_slice(packet.bytes);
    let pn_len = key.unprotect_header(bytes, packet_number_offset).ok()?;
    let (truncated, _) = crate::quic::imp::kernel::packet::decode_truncated_packet_number(
        bytes[0],
        bytes.get(packet_number_offset..packet_number_offset.checked_add(pn_len)?)?,
    )
    .ok()?;
    let pn = crate::quic::imp::kernel::packet::restore_packet_number(truncated, pn_len as u8, None)
        .ok()?;
    let first = bytes[0];
    let (aad, ciphertext) = bytes.split_at_mut(packet_number_offset + pn_len);
    key.open(
        pn,
        aad,
        ciphertext,
        &mut crate::crypto::IntegrityBudget::new(),
    )
    .ok()?;
    crate::quic::imp::kernel::packet::validate_reserved_bits(first).ok()?;
    Some(())
}

/// Encode the version-independent negotiation envelope for a v1 endpoint.
/// CIDs are reversed and the response obeys the threefold datagram budget.
/// The caller supplies entropy for the unused first-byte bits (RFC 9000 §17.2.1).
pub fn version_negotiation(
    destination_id: &[u8],
    source_id: &[u8],
    received_len: usize,
    random: u8,
    output: &mut [u8],
) -> Option<usize> {
    if destination_id.len() > 20 || source_id.len() > 20 {
        return None;
    }
    let len = 11 + source_id.len() + destination_id.len();
    if len > received_len.saturating_mul(3) {
        return None;
    }
    let output = output.get_mut(..len)?;
    output[..5].copy_from_slice(&[0x80 | (random & 0x7f), 0, 0, 0, 0]);
    output[5] = source_id.len() as u8;
    let mut end = 6 + source_id.len();
    output[6..end].copy_from_slice(source_id);
    output[end] = destination_id.len() as u8;
    end += 1;
    output[end..end + destination_id.len()].copy_from_slice(destination_id);
    end += destination_id.len();
    output[end..].copy_from_slice(&crate::quic::imp::kernel::packet::QUIC_V1.to_be_bytes());
    Some(len)
}

/// An owned datagram backed by a compile-time bound, never a heap allocation.
pub struct Datagram<const N: usize> {
    bytes: [u8; N],
    len: usize,
}
impl<const N: usize> Default for Datagram<N> {
    fn default() -> Self {
        Self::new()
    }
}
impl<const N: usize> Datagram<N> {
    pub const fn new() -> Self {
        Self {
            bytes: [0; N],
            len: N,
        }
    }
    pub fn truncate(&mut self, length: usize) {
        self.len = self.len.min(length);
    }
}
impl<const N: usize> core::ops::Deref for Datagram<N> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
impl<const N: usize> core::ops::DerefMut for Datagram<N> {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[..self.len]
    }
}

#[cfg(test)]
mod tests {
    use super::version_negotiation;
    #[test]
    fn version_envelope_reverses_ids_and_clears_version() {
        let mut bytes = [0xff; 51];
        let len = version_negotiation(&[1, 2], &[3], 5, 0x12, &mut bytes).unwrap();
        assert_eq!(len, 14);
        assert_eq!(
            &bytes[..len],
            &[0x92, 0, 0, 0, 0, 1, 3, 2, 1, 2, 0, 0, 0, 1]
        );
    }
    #[test]
    fn version_envelope_rejects_budget_capacity_and_invalid_ids() {
        assert_eq!(version_negotiation(&[], &[], 3, 0, &mut [0; 51]), None);
        assert_eq!(version_negotiation(&[], &[], 4, 0, &mut [0; 10]), None);
        assert_eq!(
            version_negotiation(&[0; 21], &[], 1200, 0, &mut [0; 51]),
            None
        );
        assert_eq!(
            version_negotiation(&[], &[0; 21], 1200, 0, &mut [0; 51]),
            None
        );
        assert_eq!(
            version_negotiation(&[0; 20], &[0; 20], 17, 0xff, &mut [0; 51]),
            Some(51)
        );
    }
}
