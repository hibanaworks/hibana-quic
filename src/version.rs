//! Immutable wire and cryptographic versions, not protocol progression.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Version {
    V1,
    V2,
}
impl Version {
    pub const fn wire(self) -> u32 {
        match self {
            Self::V1 => 1,
            Self::V2 => 0x6b3343cf,
        }
    }
    pub const fn from_wire(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::V1),
            0x6b3343cf => Some(Self::V2),
            _ => None,
        }
    }
    pub(crate) const fn key_label(self) -> &'static [u8] {
        match self {
            Self::V1 => b"quic key",
            Self::V2 => b"quicv2 key",
        }
    }
    pub(crate) const fn iv_label(self) -> &'static [u8] {
        match self {
            Self::V1 => b"quic iv",
            Self::V2 => b"quicv2 iv",
        }
    }
    pub(crate) const fn hp_label(self) -> &'static [u8] {
        match self {
            Self::V1 => b"quic hp",
            Self::V2 => b"quicv2 hp",
        }
    }
    pub(crate) const fn ku_label(self) -> &'static [u8] {
        match self {
            Self::V1 => b"quic ku",
            Self::V2 => b"quicv2 ku",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Information<'a> {
    chosen: u32,
    available: &'a [u8],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Malformed,
    Mismatch,
    Missing,
    Capacity,
}
impl<'a> Information<'a> {
    pub fn parse(b: &'a [u8], from_client: bool) -> Result<Self, Error> {
        if b.len() < 4 || !b.len().is_multiple_of(4) {
            return Err(Error::Malformed);
        }
        let chosen = u32::from_be_bytes(b[..4].try_into().map_err(|_| Error::Malformed)?);
        let this = Self {
            chosen,
            available: &b[4..],
        };
        if chosen == 0
            || this.available().any(|v| v == 0)
            || (from_client && !this.available().any(|v| v == chosen))
        {
            return Err(Error::Malformed);
        }
        Ok(this)
    }
    pub const fn chosen(self) -> u32 {
        self.chosen
    }
    pub fn available(self) -> impl Iterator<Item = u32> + 'a {
        self.available
            .chunks_exact(4)
            .map(|v| u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
    }
    pub fn verify_fixed(self, wire: Version) -> Result<(), Error> {
        if self.chosen != wire.wire() {
            Err(Error::Mismatch)
        } else {
            Ok(())
        }
    }
}
pub fn encode_fixed(version: Version, out: &mut [u8]) -> Result<usize, Error> {
    let dst = out.get_mut(..8).ok_or(Error::Capacity)?;
    dst[..4].copy_from_slice(&version.wire().to_be_bytes());
    dst[4..].copy_from_slice(&version.wire().to_be_bytes());
    Ok(8)
}
pub fn information_from_parameters(
    bytes: &[u8],
    from_client: bool,
) -> Result<Option<Information<'_>>, Error> {
    let mut remaining = bytes;
    let mut found = None;
    while !remaining.is_empty() {
        let (id, a) = crate::packet::decode_varint(remaining).map_err(|_| Error::Malformed)?;
        let (len, b) =
            crate::packet::decode_varint(&remaining[a..]).map_err(|_| Error::Malformed)?;
        let end = (a + b)
            .checked_add(usize::try_from(len).map_err(|_| Error::Malformed)?)
            .ok_or(Error::Malformed)?;
        let value = remaining.get(a + b..end).ok_or(Error::Malformed)?;
        if id == 0x11 {
            if found.is_some() {
                return Err(Error::Malformed);
            }
            found = Some(Information::parse(value, from_client)?);
        }
        remaining = &remaining[end..];
    }
    Ok(found)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_offer_binds_wire_and_rejects_malformed() {
        for v in [Version::V1, Version::V2] {
            let mut b = [0; 8];
            assert_eq!(encode_fixed(v, &mut b), Ok(8));
            let i = Information::parse(&b, true).unwrap();
            assert_eq!(i.verify_fixed(v), Ok(()));
            assert_eq!(i.available().collect::<std::vec::Vec<_>>(), [v.wire()]);
            let other = if v == Version::V1 {
                Version::V2
            } else {
                Version::V1
            };
            assert_eq!(i.verify_fixed(other), Err(Error::Mismatch));
        }
        for b in [
            &[][..],
            &[0, 0, 0][..],
            &[0, 0, 0, 0][..],
            &[0, 0, 0, 1, 0][..],
            &[0, 0, 0, 1, 0, 0, 0, 0][..],
        ] {
            assert!(Information::parse(b, false).is_err());
        }
        assert!(Information::parse(&[0, 0, 0, 1], true).is_err());
        assert!(Information::parse(&[0, 0, 0, 1], false).is_ok());
        assert!(Information::parse(&[0, 0, 0, 1, 0x6b, 0x33, 0x43, 0xcf], true).is_err());
    }
}
