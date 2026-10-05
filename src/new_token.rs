//! Bounded one-use address tokens for future connections (RFC 9000 8.1.3).
//! Random opaque values reveal no previous CID/address. The issuer remembers
//! the IP and expiry. A token authenticates reachability, never TLS identity.
use core::net::IpAddr;
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const TOKEN_LEN: usize = 32;
const PREFIX: &[u8; 3] = b"HQN";
const LIFETIME_US: u64 = 60_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Capacity,
    Entropy,
    Clock,
    Collision,
}
struct Entry {
    bytes: Zeroizing<[u8; TOKEN_LEN]>,
    ip: IpAddr,
    expires: u64,
}
/// One issuer belongs to the listener. Route repeated Initial packets to an
/// existing connection before attempting another one-use admission.
pub struct Issuer<const N: usize> {
    entries: [Option<Entry>; N],
    last: u64,
}
impl<const N: usize> Default for Issuer<N> {
    fn default() -> Self {
        Self::new()
    }
}
impl<const N: usize> Issuer<N> {
    pub fn new() -> Self {
        Self {
            entries: core::array::from_fn(|_| None),
            last: 0,
        }
    }
    fn advance(&mut self, now: u64) -> Result<(), Error> {
        if now < self.last {
            return Err(Error::Clock);
        }
        self.last = now;
        for entry in &mut self.entries {
            if entry.as_ref().is_some_and(|e| e.expires <= now) {
                *entry = None;
            }
        }
        Ok(())
    }
    pub fn issue(
        &mut self,
        ip: IpAddr,
        now: u64,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<[u8; TOKEN_LEN], Error> {
        self.advance(now)?;
        let expires = now.checked_add(LIFETIME_US).ok_or(Error::Clock)?;
        let index = self
            .entries
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let mut bytes = Zeroizing::new([0; TOKEN_LEN]);
        rng.try_fill_bytes(&mut bytes[..])
            .map_err(|_| Error::Entropy)?;
        bytes[..PREFIX.len()].copy_from_slice(PREFIX);
        if self
            .entries
            .iter()
            .flatten()
            .any(|e| bool::from(e.bytes[..].ct_eq(&bytes[..])))
        {
            return Err(Error::Collision);
        }
        let wire = *bytes;
        self.entries[index] = Some(Entry { bytes, ip, expires });
        Ok(wire)
    }
    /// Invalid, expired, foreign-IP and replayed tokens confer no authority.
    /// The caller may still admit an unvalidated connection under the ordinary
    /// anti-amplification limit; it must not discard all NEW_TOKEN-bearing Initials.
    pub fn consume(&mut self, bytes: &[u8], ip: IpAddr, now: u64) -> Result<bool, Error> {
        self.advance(now)?;
        if bytes.len() != TOKEN_LEN || &bytes[..PREFIX.len()] != PREFIX {
            return Ok(false);
        }
        let found = self.entries.iter().position(|entry| {
            entry
                .as_ref()
                .is_some_and(|e| bool::from(e.bytes[..].ct_eq(bytes)) && e.ip == ip)
        });
        if let Some(index) = found {
            self.entries[index] = None;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    struct Rng(u8);
    impl RngCore for Rng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(1);
            self.0 as u64
        }
        fn fill_bytes(&mut self, out: &mut [u8]) {
            self.try_fill_bytes(out).unwrap();
        }
        fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
            for b in out {
                *b = self.next_u64() as u8;
            }
            Ok(())
        }
    }
    impl CryptoRng for Rng {}
    fn ip() -> IpAddr {
        IpAddr::V4(core::net::Ipv4Addr::LOCALHOST)
    }
    #[test]
    fn one_use_ip_bound_and_no_unexpired_eviction() {
        let mut issuer = Issuer::<1>::new();
        let mut rng = Rng(0);
        let token = issuer.issue(ip(), 10, &mut rng).unwrap();
        assert_eq!(issuer.issue(ip(), 11, &mut rng), Err(Error::Capacity));
        assert!(
            !issuer
                .consume(&token, IpAddr::V6(core::net::Ipv6Addr::LOCALHOST), 12)
                .unwrap()
        );
        let mut forged = token;
        forged[8] ^= 1;
        assert!(!issuer.consume(&forged, ip(), 13).unwrap());
        assert!(issuer.consume(&token, ip(), 14).unwrap());
        assert!(!issuer.consume(&token, ip(), 15).unwrap());
        assert!(issuer.issue(ip(), 16, &mut rng).is_ok());
    }
    #[test]
    fn expiry_clock_and_format_fail_closed() {
        let mut issuer = Issuer::<1>::new();
        let mut rng = Rng(0);
        let token = issuer.issue(ip(), 10, &mut rng).unwrap();
        assert_eq!(issuer.consume(&token, ip(), 9), Err(Error::Clock));
        assert!(!issuer.consume(b"HQR", ip(), 10).unwrap());
        assert!(!issuer.consume(&token, ip(), 10 + LIFETIME_US).unwrap());
        assert!(issuer.issue(ip(), 10 + LIFETIME_US, &mut rng).is_ok());
    }
}
