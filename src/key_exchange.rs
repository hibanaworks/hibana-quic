//! Fixed-storage X25519 wrapper over the official dalek implementation.
//! No curve arithmetic is implemented here. Each owner consumes a fresh injected
//! secret exactly once and rejects non-contributory (all-zero) shared secrets.
use rand_core::{CryptoRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Entropy,
    InvalidShare,
    NonContributory,
}

pub struct X25519Secret(StaticSecret);
impl X25519Secret {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self, Error> {
        let mut bytes = Zeroizing::new([0; 32]);
        rng.try_fill_bytes(&mut *bytes)
            .map_err(|_| Error::Entropy)?;
        Ok(Self(StaticSecret::from(*bytes)))
    }
    pub fn public_key(&self) -> [u8; 32] {
        PublicKey::from(&self.0).to_bytes()
    }
    pub fn complete(self, peer: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
        let bytes: [u8; 32] = peer.try_into().map_err(|_| Error::InvalidShare)?;
        let shared = self.0.diffie_hellman(&PublicKey::from(bytes));
        if !shared.was_contributory() {
            return Err(Error::NonContributory);
        }
        Ok(Zeroizing::new(shared.to_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex(s: &str) -> [u8; 32] {
        let mut out = [0; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }
    fn secret(s: &str) -> X25519Secret {
        X25519Secret(StaticSecret::from(hex(s)))
    }
    #[test]
    fn rfc7748_section_61_agreement() {
        let a = secret("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let b = secret("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let ap = a.public_key();
        let bp = b.public_key();
        assert_eq!(
            ap,
            hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        assert_eq!(
            bp,
            hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        );
        let expected = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(*a.complete(&bp).unwrap(), expected);
        assert_eq!(*b.complete(&ap).unwrap(), expected);
    }
    #[test]
    fn invalid_lengths_and_low_order_points_reject() {
        for len in [0, 1, 31, 33, 65] {
            assert_eq!(
                X25519Secret(StaticSecret::from([7; 32]))
                    .complete(&[0; 65][..len])
                    .unwrap_err(),
                Error::InvalidShare
            );
        }
        for first in [0, 1] {
            let mut p = [0; 32];
            p[0] = first;
            assert_eq!(
                X25519Secret(StaticSecret::from([7; 32]))
                    .complete(&p)
                    .unwrap_err(),
                Error::NonContributory
            );
        }
    }
    #[test]
    fn rfc7748_masks_public_high_bit() {
        let a = StaticSecret::from([9; 32]);
        let mut p = PublicKey::from(&StaticSecret::from([11; 32])).to_bytes();
        let first = X25519Secret(a).complete(&p).unwrap();
        p[31] |= 128;
        assert_eq!(
            *first,
            *X25519Secret(StaticSecret::from([9; 32]))
                .complete(&p)
                .unwrap()
        );
    }
    struct Entropy {
        next: u8,
        fail: bool,
    }
    impl CryptoRng for Entropy {}
    impl RngCore for Entropy {
        fn next_u32(&mut self) -> u32 {
            panic!("unused")
        }
        fn next_u64(&mut self) -> u64 {
            panic!("unused")
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.try_fill_bytes(dest).unwrap();
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            if self.fail {
                return Err(core::num::NonZeroU32::new(1).unwrap().into());
            }
            for b in dest {
                *b = self.next;
                self.next = self.next.wrapping_add(1);
            }
            Ok(())
        }
    }
    #[test]
    fn fresh_injected_entropy_and_failure_are_explicit() {
        let mut rng = Entropy {
            next: 1,
            fail: false,
        };
        let a = X25519Secret::generate(&mut rng).unwrap();
        let b = X25519Secret::generate(&mut rng).unwrap();
        assert_ne!(a.public_key(), b.public_key());
        rng.fail = true;
        assert!(matches!(
            X25519Secret::generate(&mut rng),
            Err(Error::Entropy)
        ));
    }
}
