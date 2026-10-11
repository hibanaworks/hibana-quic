//! Short-header protection owned by application RX/TX continuations.
use super::{Error, recovery::Reservation};
use crate::crypto::IntegrityBudget;
use crate::crypto::directional::ApplicationReadKeys;
use crate::crypto::directional::ApplicationWriteKeys;
use crate::crypto::directional::AuthenticatedRead;
use crate::quic::imp::kernel::accounting::PacketNumberSpace;
use crate::quic::imp::kernel::packet;
use crate::quic::imp::kernel::packet::Header;
use crate::quic::imp::kernel::packet::PacketIter;
use crate::quic::imp::kernel::packet::ShortHeader;
use hibana_tls::secret::Erase;

#[allow(clippy::too_many_arguments)]
pub fn open<'scope, 'packet, const N: usize>(
    keys: &mut ApplicationReadKeys<'scope>,
    integrity: &mut IntegrityBudget,
    datagram: &'packet mut [u8],
    local_cid: &[u8],
    largest_authenticated: Option<u64>,
    now: u64,
    pto: u64,
) -> Result<AuthenticatedRead<'scope, 'packet>, Error> {
    if datagram.len() > N {
        return Err(Error::Capacity);
    }
    let packet = PacketIter::new(datagram, local_cid.len(), 1)?
        .next()
        .ok_or(packet::Error::Truncated)??;
    let pn_offset = match packet.header {
        Header::Short {
            destination_id,
            packet_number_offset,
        } if destination_id == local_cid => packet_number_offset,
        _ => return Err(Error::Binding),
    };
    let sample_start = pn_offset.checked_add(4).ok_or(Error::Capacity)?;
    let sample: &[u8; 16] = datagram
        .get(sample_start..sample_start + 16)
        .ok_or(packet::Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Capacity)?;
    let mask = keys.header_mask(sample)?;
    let storage = datagram;
    storage[0] ^= mask[0] & 0x1f;
    let pn_len = usize::from(storage[0] & 3) + 1;
    for i in 0..pn_len {
        storage[pn_offset + i] ^= mask[i + 1];
    }
    let (truncated, _) = packet::decode_truncated_packet_number(
        storage[0],
        &storage[pn_offset..pn_offset + pn_len],
    )?;
    let pn = packet::restore_packet_number(truncated, pn_len as u8, largest_authenticated)?;
    let start = pn_offset + pn_len;
    let (header, payload) = storage.split_at_mut(start);
    let receipt = keys.open(pn, header[0] & 4 != 0, header, payload, integrity, now, pto)?;
    packet::validate_reserved_bits(header[0])?;
    let len = receipt.opened().len;
    if len == 0 {
        return Err(packet::Error::EmptyPayload.into());
    }
    Ok(receipt)
}
#[must_use = "retain reservation until actual publication or cancellation"]
pub struct SealedApplicationDatagram<'book, const N: usize> {
    bytes: [u8; N],
    len: usize,
    reservation: Option<Reservation<'book>>,
}
impl<'book, const N: usize> SealedApplicationDatagram<'book, N> {
    pub(in crate::quic) fn reservation(&self) -> &Reservation<'book> {
        self.reservation.as_ref().expect("owned reservation")
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
    pub fn into_reservation(mut self) -> Reservation<'book> {
        self.reservation.take().expect("owned reservation")
    }
}
impl<const N: usize> Drop for SealedApplicationDatagram<'_, N> {
    fn drop(&mut self) {
        self.bytes.erase();
    }
}
pub fn seal<'book, const N: usize>(
    keys: &mut ApplicationWriteKeys<'_>,
    reservation: Reservation<'book>,
    destination_cid: &[u8],
    plaintext: &[u8],
) -> Result<SealedApplicationDatagram<'book, N>, (Error, Reservation<'book>)> {
    let mut bytes = [0u8; N];
    let result = (|| -> Result<usize, Error> {
        if !core::ptr::eq(keys.scope(), reservation.scope())
            || reservation.packet().space != PacketNumberSpace::ApplicationData
            || reservation.kind() != crate::quic::imp::kernel::accounting::PacketKind::OneRtt
            || keys.generation() != reservation.key_generation()
            || plaintext.is_empty()
            || !reservation.matches_plaintext(plaintext)?
        {
            return Err(Error::Binding);
        }
        let header_len = packet::encode_short_header(
            &ShortHeader {
                destination_id: destination_cid,
                packet_number: reservation.packet().value,
                packet_number_len: 4,
                spin: false,
                key_phase: keys.phase(),
            },
            &mut bytes,
        )?;
        let len = header_len
            .checked_add(plaintext.len())
            .and_then(|v| v.checked_add(16))
            .ok_or(Error::Capacity)?;
        if len > N || reservation.bytes() != len as u64 {
            return Err(Error::Binding);
        }
        bytes[header_len..header_len + plaintext.len()].copy_from_slice(plaintext);
        let (header, payload) = bytes[..len].split_at_mut(header_len);
        let sealed = keys.seal(reservation.packet().value, header, payload, plaintext.len())?;
        if header_len + sealed != len {
            return Err(Error::Binding);
        }
        let sample: &[u8; 16] = bytes[header_len..header_len + 16]
            .try_into()
            .map_err(|_| Error::Capacity)?;
        let mask = keys.header_mask(sample)?;
        bytes[0] ^= mask[0] & 0x1f;
        for i in 0..4 {
            bytes[header_len - 4 + i] ^= mask[i + 1];
        }
        Ok(len)
    })();
    match result {
        Ok(len) => Ok(SealedApplicationDatagram {
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
