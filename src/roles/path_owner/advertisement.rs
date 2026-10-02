//! Only accepted, sealed, retained-flight-bound bytes enter this assembler.
//! Coverage is per byte: reordered fragments and retransmissions cannot fill a
//! hole, and overlapping accepted fragments must agree. The bounded prefix is
//! an explicit local EE capacity, independent of the peer's packet sizes.
use super::{Error, PREFERRED_ADVERTISEMENT_BYTES as ADVERTISEMENT_BYTES, PreferredLocal};
use zeroize::Zeroize;

pub(super) struct Evidence {
    bytes: [u8; ADVERTISEMENT_BYTES],
    covered: [u8; ADVERTISEMENT_BYTES / 8],
}
impl Evidence {
    pub(super) const fn new() -> Self {
        Self {
            bytes: [0; ADVERTISEMENT_BYTES],
            covered: [0; ADVERTISEMENT_BYTES / 8],
        }
    }
    fn contains(&self, i: usize) -> bool {
        self.covered[i / 8] & (1 << (i % 8)) != 0
    }
    pub(super) fn clear(&mut self) {
        self.bytes.zeroize();
        self.covered.zeroize();
    }
    pub(super) fn accept(
        &mut self,
        offset: usize,
        bytes: &[u8],
        expected: PreferredLocal,
    ) -> Result<bool, Error> {
        let end = offset
            .checked_add(bytes.len())
            .filter(|end| *end <= ADVERTISEMENT_BYTES)
            .ok_or(Error::Capacity)?;
        // Preflight overlaps so a conflicting fragment does not partially
        // replace the evidence retained from earlier accepted datagrams.
        for (i, byte) in (offset..end).zip(bytes) {
            if self.contains(i) && self.bytes[i] != *byte {
                return Err(Error::InvalidAdvertisement);
            }
        }
        self.bytes[offset..end].copy_from_slice(bytes);
        for i in offset..end {
            self.covered[i / 8] |= 1 << (i % 8);
        }
        if !(0..4).all(|i| self.contains(i)) {
            return Ok(false);
        }
        if self.bytes[0] != 8 {
            return Err(Error::InvalidAdvertisement);
        }
        let total = 4
            + (usize::from(self.bytes[1]) << 16)
            + (usize::from(self.bytes[2]) << 8)
            + usize::from(self.bytes[3]);
        if total > ADVERTISEMENT_BYTES {
            return Err(Error::Capacity);
        }
        if !(0..total).all(|i| self.contains(i)) {
            return Ok(false);
        }
        let extensions = crate::tls_wire::parse_encrypted_extensions_early(&self.bytes[..total])
            .map_err(|_| Error::InvalidAdvertisement)?;
        let parameters = crate::parameters::Parameters::parse(
            extensions.params,
            crate::parameters::Peer::Server,
            &mut [0; 64],
        )
        .map_err(|_| Error::InvalidAdvertisement)?;
        let preferred = crate::migration::PreferredAddress::parse(
            parameters.get(13).ok_or(Error::InvalidAdvertisement)?,
        )
        .map_err(|_| Error::InvalidAdvertisement)?;
        let exact_address = if expected.address.is_ipv4() {
            preferred.ipv4 == Some(expected.address) && preferred.ipv6.is_none()
        } else {
            preferred.ipv6 == Some(expected.address) && preferred.ipv4.is_none()
        };
        if !exact_address
            || preferred.connection_id != expected.cid.as_bytes()
            || !bool::from(subtle::ConstantTimeEq::ct_eq(
                preferred.reset_token.as_slice(),
                expected.reset_token.as_bytes().as_slice(),
            ))
        {
            return Err(Error::InvalidAdvertisement);
        }
        Ok(true)
    }
}
impl Drop for Evidence {
    fn drop(&mut self) {
        self.clear();
    }
}
