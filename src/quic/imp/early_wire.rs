//! Bounded 0-RTT packet protection. Authentication does not authorize delivery:
//! the returned input must still cross the projected quarantine/Finished owner.
use super::{Error, recovery::Reservation};
use crate::crypto::IntegrityBudget;
use crate::crypto::KeyKind;
use crate::quic::imp::kernel::accounting::PacketKind;
use crate::quic::imp::kernel::packet;
use crate::quic::imp::kernel::packet::Header;
use crate::quic::imp::kernel::packet::LongHeader;
use crate::quic::imp::kernel::packet::LongType;
use crate::quic::imp::kernel::packet::PacketIter;
use hibana_tls::handshake::local::keys::AuthenticatedEarlyRead;
use hibana_tls::handshake::local::keys::ReceivePacketKey;
use hibana_tls::handshake::local::keys::TransmitPacketKey;
use hibana_tls::secret::Erase;

pub fn encoded_len(
    destination: &[u8],
    source: &[u8],
    plaintext_len: usize,
) -> Result<usize, Error> {
    let mut header = [0; 64];
    let len = packet::encode_long_header(
        &LongHeader {
            kind: LongType::ZeroRtt,
            destination_id: destination,
            source_id: source,
            token: &[],
            packet_number: 0,
            packet_number_len: 4,
        },
        plaintext_len.checked_add(16).ok_or(Error::Capacity)?,
        &mut header,
    )?;
    len.checked_add(plaintext_len)
        .and_then(|n| n.checked_add(16))
        .ok_or(Error::Capacity)
}

#[must_use = "settle the actual UDP submission or cancel its retained reservation"]
pub struct Sealed<'book, const N: usize> {
    bytes: [u8; N],
    len: usize,
    reservation: Option<Reservation<'book>>,
}
impl<'book, const N: usize> Sealed<'book, N> {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
    pub fn into_reservation(mut self) -> Reservation<'book> {
        self.reservation.take().expect("owned early reservation")
    }
}
impl<const N: usize> Drop for Sealed<'_, N> {
    fn drop(&mut self) {
        self.bytes.erase();
    }
}

pub fn seal<'book, const N: usize>(
    key: &mut TransmitPacketKey<'_>,
    reservation: Reservation<'book>,
    destination: &[u8],
    source: &[u8],
    plaintext: &[u8],
) -> Result<Sealed<'book, N>, (Error, Reservation<'book>)> {
    let mut bytes = [0; N];
    let result = (|| {
        if key.kind() != KeyKind::ZeroRtt
            || reservation.kind() != PacketKind::ZeroRtt
            || !core::ptr::eq(key.scope(), reservation.scope())
            || plaintext.is_empty()
            || !reservation.matches_plaintext(plaintext)?
        {
            return Err(Error::Binding);
        }
        let total = encoded_len(destination, source, plaintext.len())?;
        if total > N || total as u64 != reservation.bytes() {
            return Err(Error::Capacity);
        }
        let hlen = packet::encode_long_header(
            &LongHeader {
                kind: LongType::ZeroRtt,
                destination_id: destination,
                source_id: source,
                token: &[],
                packet_number: reservation.packet().value,
                packet_number_len: 4,
            },
            plaintext.len() + 16,
            &mut bytes,
        )?;
        bytes[hlen..hlen + plaintext.len()].copy_from_slice(plaintext);
        let (header, payload) = bytes[..total].split_at_mut(hlen);
        let sealed = key.seal(reservation.packet().value, header, payload, plaintext.len())?;
        if hlen + sealed != total {
            return Err(Error::Binding);
        }
        let sample: &[u8; 16] = bytes[hlen..hlen + 16]
            .try_into()
            .map_err(|_| Error::Capacity)?;
        let mask = key.header_mask(sample)?;
        bytes[0] ^= mask[0] & 0x0f;
        for i in 0..4 {
            bytes[hlen - 4 + i] ^= mask[i + 1];
        }
        Ok(total)
    })();
    match result {
        Ok(len) => Ok(Sealed {
            bytes,
            len,
            reservation: Some(reservation),
        }),
        Err(error) => {
            bytes.erase();
            Err((error, reservation))
        }
    }
}

#[must_use = "authentication must enter quarantine before any application effects"]
pub struct Opened<'scope, const N: usize> {
    bytes: [u8; N],
    start: usize,
    len: usize,
    receipt: Option<AuthenticatedEarlyRead<'scope>>,
}
impl<'scope, const N: usize> Opened<'scope, N> {
    pub fn plaintext(&self) -> &[u8] {
        &self.bytes[self.start..self.start + self.len]
    }
    pub fn take_receipt(&mut self) -> Option<AuthenticatedEarlyRead<'scope>> {
        self.receipt.take()
    }
}
impl<const N: usize> Drop for Opened<'_, N> {
    fn drop(&mut self) {
        self.bytes.erase();
    }
}
pub fn open<'scope, const N: usize>(
    key: &ReceivePacketKey<'scope>,
    budget: &mut IntegrityBudget,
    datagram: &[u8],
    destination: &[u8],
    largest_authenticated: Option<u64>,
) -> Result<Opened<'scope, N>, Error> {
    if key.kind() != KeyKind::ZeroRtt || datagram.len() > N {
        return Err(Error::Binding);
    }
    let packet = PacketIter::new(datagram, destination.len(), 1)?
        .next()
        .ok_or(packet::Error::Truncated)??;
    let pn_offset = match packet.header {
        Header::Long {
            kind: LongType::ZeroRtt,
            destination_id,
            packet_number_offset,
            ..
        } if destination_id == destination => packet_number_offset,
        _ => return Err(Error::Binding),
    };
    let mut result = Opened {
        bytes: [0; N],
        start: 0,
        len: 0,
        receipt: None,
    };
    result.bytes[..packet.bytes.len()].copy_from_slice(packet.bytes);
    let bytes = &mut result.bytes[..packet.bytes.len()];
    let pn_len = key.unprotect_header(bytes, pn_offset)?;
    let (truncated, _) = packet::decode_truncated_packet_number(bytes[0], &bytes[pn_offset..])?;
    let pn = packet::restore_packet_number(truncated, pn_len as u8, largest_authenticated)?;
    let start = pn_offset.checked_add(pn_len).ok_or(Error::Capacity)?;
    let (header, payload) = bytes.split_at_mut(start);
    let receipt = key.open_early_authenticated(pn, header, payload, budget)?;
    packet::validate_reserved_bits(header[0])?;
    let len = payload.len().checked_sub(16).ok_or(Error::Capacity)?;
    if len == 0 || !receipt.authenticates_plaintext(&payload[..len]) {
        return Err(Error::Binding);
    }
    result.start = start;
    result.len = len;
    result.receipt = Some(receipt);
    Ok(result)
}

/// Caller-backed retention of untrusted packets while the finite TLS prefix
/// runs. Capacity exhaustion drops a whole packet; no authentication is claimed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketEnd {
    end: usize,
    ecn: Option<crate::quic::ecn::imp::Codepoint>,
}
impl PacketEnd {
    pub const EMPTY: Self = Self { end: 0, ecn: None };
}
pub struct PendingPackets<'a> {
    bytes: &'a mut [u8],
    ends: &'a mut [PacketEnd],
    count: usize,
    used: usize,
}
impl<'a> PendingPackets<'a> {
    pub fn new(bytes: &'a mut [u8], ends: &'a mut [PacketEnd]) -> Self {
        bytes.fill(0);
        ends.fill(PacketEnd::EMPTY);
        Self {
            bytes,
            ends,
            count: 0,
            used: 0,
        }
    }
    pub fn len(&self) -> usize {
        self.count
    }
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
    pub fn packet(&self, index: usize) -> Option<&[u8]> {
        if index >= self.count {
            return None;
        }
        let start = if index == 0 {
            0
        } else {
            self.ends[index - 1].end
        };
        Some(&self.bytes[start..self.ends[index].end])
    }
    pub fn ecn(&self, index: usize) -> Option<crate::quic::ecn::imp::Codepoint> {
        self.ends
            .get(index)
            .filter(|_| index < self.count)
            .and_then(|entry| entry.ecn)
    }
    pub(in crate::quic) fn retain(
        &mut self,
        packet: &[u8],
        ecn: Option<crate::quic::ecn::imp::Codepoint>,
    ) -> bool {
        if packet.is_empty()
            || self.count == self.ends.len()
            || packet.len() > self.bytes.len() - self.used
        {
            return false;
        }
        let end = self.used + packet.len();
        self.bytes[self.used..end].copy_from_slice(packet);
        self.ends[self.count] = PacketEnd { end, ecn };
        self.count += 1;
        self.used = end;
        true
    }
}
impl Drop for PendingPackets<'_> {
    fn drop(&mut self) {
        self.bytes.erase();
        self.ends.fill(PacketEnd::EMPTY);
    }
}

pub(in crate::quic) trait RetainPackets {
    fn retain_packet(
        &mut self,
        packet: &[u8],
        ecn: Option<crate::quic::ecn::imp::Codepoint>,
    ) -> bool;
}
impl RetainPackets for PendingPackets<'_> {
    fn retain_packet(
        &mut self,
        packet: &[u8],
        ecn: Option<crate::quic::ecn::imp::Codepoint>,
    ) -> bool {
        self.retain(packet, ecn)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pending_packets_are_bounded_whole_and_wiped() {
        let mut bytes = [7; 9];
        let mut ends = [PacketEnd::EMPTY; 2];
        {
            let mut pending = PendingPackets::new(&mut bytes, &mut ends);
            assert!(pending.retain(b"first", Some(crate::quic::ecn::imp::Codepoint::Ect0)));
            assert!(!pending.retain(b"second", Some(crate::quic::ecn::imp::Codepoint::Ce)));
            assert!(pending.retain(b"next", None));
            assert!(!pending.retain(b"x", Some(crate::quic::ecn::imp::Codepoint::Ce)));
            assert_eq!(pending.packet(0), Some(&b"first"[..]));
            assert_eq!(pending.packet(1), Some(&b"next"[..]));
            assert_eq!(pending.packet(2), None);
            assert_eq!(pending.ecn(0), Some(crate::quic::ecn::imp::Codepoint::Ect0));
            assert_eq!(pending.ecn(1), None);
            assert_eq!(pending.ecn(2), None);
        }
        assert_eq!(bytes, [0; 9]);
        assert_eq!(ends, [PacketEnd::EMPTY; 2]);
    }
}
