//! Preferred-address value from one authenticated transport-parameter block.
//! Parsing alone grants no permission to migrate; the projected owner waits for
//! confirmed handshake and successful path validation before adopting it.
use crate::connection_id::{Cid, ResetToken};
use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Length,
    Address,
    ConnectionId,
}
#[derive(Clone, Copy, Debug)]
pub struct Preferred {
    pub ipv4: Option<SocketAddrV4>,
    pub ipv6: Option<SocketAddrV6>,
    pub cid: Cid,
    pub token: ResetToken,
}
impl Preferred {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 42 {
            return Err(Error::Length);
        }
        let len = usize::from(bytes[24]);
        if len == 0 || len > 20 || bytes.len() != 41 + len {
            return Err(Error::Length);
        }
        let v4 = Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[..4]).map_err(|_| Error::Length)?);
        let p4 = u16::from_be_bytes([bytes[4], bytes[5]]);
        let v6 = Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[6..22]).map_err(|_| Error::Length)?);
        let p6 = u16::from_be_bytes([bytes[22], bytes[23]]);
        if v4.is_unspecified() != (p4 == 0) || v6.is_unspecified() != (p6 == 0) {
            return Err(Error::Address);
        }
        Ok(Self {
            ipv4: (!v4.is_unspecified()).then_some(SocketAddrV4::new(v4, p4)),
            ipv6: (!v6.is_unspecified()).then_some(SocketAddrV6::new(v6, p6, 0, 0)),
            cid: Cid::new(&bytes[25..25 + len]).map_err(|_| Error::ConnectionId)?,
            token: ResetToken::new(bytes[25 + len..].try_into().map_err(|_| Error::Length)?),
        })
    }
    pub fn encode(&self, bytes: &mut [u8]) -> Result<usize, Error> {
        let len = self.cid.as_bytes().len();
        let total = 41 + len;
        let out = bytes.get_mut(..total).ok_or(Error::Length)?;
        out.fill(0);
        if let Some(a) = self.ipv4 {
            if a.ip().is_unspecified() || a.port() == 0 {
                return Err(Error::Address);
            }
            out[..4].copy_from_slice(&a.ip().octets());
            out[4..6].copy_from_slice(&a.port().to_be_bytes());
        }
        if let Some(a) = self.ipv6 {
            if a.ip().is_unspecified() || a.port() == 0 {
                return Err(Error::Address);
            }
            out[6..22].copy_from_slice(&a.ip().octets());
            out[22..24].copy_from_slice(&a.port().to_be_bytes());
        }
        out[24] = len as u8;
        out[25..25 + len].copy_from_slice(self.cid.as_bytes());
        out[25 + len..].copy_from_slice(self.token.as_bytes());
        Ok(total)
    }
    pub fn same_family(&self, local: SocketAddr) -> Option<SocketAddr> {
        match local {
            SocketAddr::V4(_) => self.ipv4.map(SocketAddr::V4),
            SocketAddr::V6(_) => self.ipv6.map(SocketAddr::V6),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_value_roundtrip_and_no_cross_family_guess() {
        let p = Preferred {
            ipv4: Some("127.0.0.1:4443".parse().unwrap()),
            ipv6: None,
            cid: Cid::new(&[4; 8]).unwrap(),
            token: ResetToken::new([9; 16]),
        };
        let mut bytes = [0; 61];
        let n = p.encode(&mut bytes).unwrap();
        let decoded = Preferred::parse(&bytes[..n]).unwrap();
        assert_eq!(decoded.ipv4, p.ipv4);
        assert_eq!(decoded.cid, p.cid);
        assert_eq!(decoded.token.as_bytes(), p.token.as_bytes());
        assert_eq!(decoded.same_family("[::1]:4000".parse().unwrap()), None);
        assert_eq!(
            Preferred::parse(&bytes[..n - 1]).unwrap_err(),
            Error::Length
        );
        bytes[4..6].fill(0);
        assert_eq!(Preferred::parse(&bytes[..n]).unwrap_err(), Error::Address);
    }
}
