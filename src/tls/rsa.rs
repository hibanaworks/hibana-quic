//! Bounded RSA signature verification adapter, without allocation.
//!
//! Official RustCrypto fixed-size arithmetic and borrowed DER parsing surround
//! mechanically extracted upstream verification helpers. This is a review-required
//! project adapter, NOT an upstream public RSA API. See docs/tls-rsa-feasibility.md.
//! Exact 2048/3072/4096-bit moduli and odd 32-bit public exponents are supported.
//! No RSA signing, private-key operations, key generation or TLS advertisement.

use crypto_bigint::{
    Encoding, Integer, U64, U2048, U3072, U4096,
    modular::runtime_mod::{DynResidue, DynResidueParams},
};
use der::Decode;
use sha2::{Digest, Sha256};
#[path = "../../vendor/rustcrypto-rsa-verification-0.9.10/mod.rs"]
mod upstream;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidDer,
    UnsupportedKeySize,
    InvalidModulus,
    InvalidExponent,
    InvalidSignature,
}

struct PublicKey<'a> {
    modulus: &'a [u8],
    exponent: u32,
}
fn public_key(der: &[u8]) -> Result<PublicKey<'_>, Error> {
    let key = pkcs1::RsaPublicKey::from_der(der).map_err(|_| Error::InvalidDer)?;
    let modulus = key.modulus.as_bytes();
    let exponent = key.public_exponent.as_bytes();
    if !matches!(modulus.len(), 256 | 384 | 512) || modulus[0] & 0x80 == 0 {
        return Err(Error::UnsupportedKeySize);
    }
    if modulus[modulus.len() - 1] & 1 == 0 {
        return Err(Error::InvalidModulus);
    }
    if exponent.len() > 4 {
        return Err(Error::InvalidExponent);
    }
    let mut e = 0u32;
    for byte in exponent {
        e = (e << 8) | u32::from(*byte);
    }
    if e < 3 || e & 1 == 0 {
        return Err(Error::InvalidExponent);
    }
    Ok(PublicKey {
        modulus,
        exponent: e,
    })
}

macro_rules! public_operation {
    ($name:ident,$integer:ty,$bytes:expr) => {
        // Keep each fixed-width workspace in its own stack frame. This changes
        // compiler layout only; the official arithmetic operations are identical.
        #[inline(never)]
        fn $name(key: &PublicKey<'_>, signature: &[u8], output: &mut [u8]) -> Result<(), Error> {
            // All slice widths and modulus oddness are validated before invoking
            // the official constructors (whose API requires exact widths/oddness).
            if key.modulus.len() != $bytes || signature.len() != $bytes || output.len() != $bytes {
                return Err(Error::InvalidSignature);
            }
            let n = <$integer>::from_be_slice(key.modulus);
            debug_assert!(bool::from(n.is_odd()));
            let s = <$integer>::from_be_slice(signature);
            if s >= n {
                return Err(Error::InvalidSignature);
            }
            let params = DynResidueParams::new(&n);
            let recovered = DynResidue::new(&s, params)
                .pow_bounded_exp(&U64::from_u64(u64::from(key.exponent)), 32)
                .retrieve();
            output.copy_from_slice(&recovered.to_be_bytes());
            Ok(())
        }
    };
}
public_operation!(public_2048, U2048, 256);
public_operation!(public_3072, U3072, 384);
public_operation!(public_4096, U4096, 512);

// RFC8017 Appendix B.1's DER DigestInfo prefix for SHA-256, including NULL
// AlgorithmIdentifier parameters. It is public format data, not key material.
const SHA256_DIGEST_INFO: &[u8; 19] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
fn verify(public_der: &[u8], message: &[u8], signature: &[u8], pss: bool) -> Result<(), Error> {
    let key = public_key(public_der)?;
    let width = key.modulus.len();
    if signature.len() != width {
        return Err(Error::InvalidSignature);
    }
    let mut encoded = [0u8; 512];
    let encoded = &mut encoded[..width];
    match width {
        256 => public_2048(&key, signature, encoded)?,
        384 => public_3072(&key, signature, encoded)?,
        512 => public_4096(&key, signature, encoded)?,
        _ => return Err(Error::UnsupportedKeySize),
    }
    let digest = Sha256::digest(message);
    if pss {
        // TLS rsa_pss_rsae_sha256 requires SHA256/MGF1-SHA256 and salt32.
        upstream::pss::emsa_pss_verify_digest::<Sha256>(&digest, encoded, 32, width * 8)
    } else {
        upstream::pkcs1v15::pkcs1v15_sign_unpad(SHA256_DIGEST_INFO, &digest, encoded, width)
    }
    .map_err(|_| Error::InvalidSignature)
}

/// RSASSA-PSS with SHA256, MGF1-SHA256 and exactly32 salt bytes. `public_key_der`
/// is borrowed PKCS#1 RSAPublicKey DER, as carried inside an RSA SPKI bit string.
pub fn verify_pss_sha256(
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    verify(public_key_der, message, signature, true)
}
/// RSASSA-PKCS1-v1_5/SHA256 certificate-signature verification. TLS1.3 must not
/// use this scheme for CertificateVerify. Signature bytes must be modulus-width.
pub fn verify_pkcs1_sha256(
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    verify(public_key_der, message, signature, false)
}
