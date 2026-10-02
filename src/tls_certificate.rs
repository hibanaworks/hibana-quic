//! Borrowed, no-allocation SHA-256 certificate authentication building block.
//!
//! webpki validates chains, time, name constraints, EKU, and hostnames; RustCrypto
//! verifies ECDSA and the bounded `tls_rsa` adapter verifies RSA signatures.
//! A small `der`-based extension reader additionally enforces
//! X.509 KeyUsage (digitalSignature for the leaf, keyCertSign for actual CAs).
//! RSA verification permits exact 2048/3072/4096-bit rsaEncryption keys. PSS
//! uses SHA-256/MGF1-SHA256/salt32; PKCS1-v1_5 is certificate-only. This does not
//! implement RSA signing, PSS-restricted SPKI keys, or a full TLS backend.
//! The RSA adapter has significant target stack cost; see tls-rsa-feasibility.md.
//! No certificate failure has a permissive fallback. No heap, clock, entropy,
//! network trust-root lookup, or ring dependency is used by this module.

use der::{
    Decode, Reader, Tag, TagNumber, Tagged,
    asn1::{AnyRef, BitStringRef, OctetStringRef},
};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier as _};
use rustls_pki_types::{
    AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id,
};

pub use rustls_pki_types::{CertificateDer, ServerName, TrustAnchor, UnixTime};

pub const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
pub const RSA_PSS_RSAE_SHA256: u16 = 0x0804;
/// Certificate-signature scheme only; forbidden for TLS1.3 CertificateVerify.
pub const RSA_PKCS1_SHA256_SCHEME: u16 = 0x0401;
pub const MAX_INTERMEDIATES: usize = 8;
pub const MAX_TRUST_ANCHORS: usize = 32;
pub const MAX_CERTIFICATE_BYTES: usize = 65_535;
const MAX_EXTENSIONS: usize = 64;
const SERVER_VERIFY_CONTEXT: &[u8; 33] = b"TLS 1.3, server CertificateVerify";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidLimits,
    NoTrustAnchors,
    TooManyTrustAnchors,
    TooManyIntermediates,
    CertificateTooLarge,
    ChainTooLarge,
    InvalidDer,
    InvalidKeyUsage,
    MissingDigitalSignature,
    MissingKeyCertSign,
    UnsupportedSignatureScheme(u16),
    Certificate(webpki::Error),
    CertificateVerify,
}

/// Fixed hard caps supplement webpki's fixed-depth/bounded-work path builder.
/// Byte/count limits are policy limits, not a measurement of peak target stack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_certificate_bytes: usize,
    pub max_chain_bytes: usize,
    pub max_intermediates: usize,
    pub max_trust_anchors: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_certificate_bytes: 8192,
            max_chain_bytes: 32768,
            max_intermediates: MAX_INTERMEDIATES,
            max_trust_anchors: 16,
        }
    }
}
impl Limits {
    fn validate(self) -> Result<(), Error> {
        if self.max_certificate_bytes == 0
            || self.max_certificate_bytes > MAX_CERTIFICATE_BYTES
            || self.max_chain_bytes < self.max_certificate_bytes
            || self.max_intermediates > MAX_INTERMEDIATES
            || self.max_trust_anchors == 0
            || self.max_trust_anchors > MAX_TRUST_ANCHORS
        {
            return Err(Error::InvalidLimits);
        }
        Ok(())
    }
}

/// Public stateless adapter for webpki's signature-verification interface.
/// Algorithm identifiers are supplied by rustls-pki-types, not handwritten OIDs.
#[derive(Debug)]
pub struct P256Sha256;
pub static P256_SHA256: P256Sha256 = P256Sha256;
static SIGNATURE_ALGORITHMS: [&dyn SignatureVerificationAlgorithm; 4] = [
    &P256_SHA256,
    &RSA_PSS_SHA256,
    &RSA_PKCS1_SHA256,
    &RSA_PKCS1_SHA256_ABSENT_PARAMS,
];

/// RSA-PSS with rsaEncryption+NULL SPKI and exact official SHA256/MGF1-SHA256/
/// salt32 parameters. webpki compares both AlgorithmIdentifiers byte-for-byte
/// before invoking this primitive; PSS-restricted public keys cannot match it.
#[derive(Debug)]
pub struct RsaPssSha256;
pub static RSA_PSS_SHA256: RsaPssSha256 = RsaPssSha256;

impl SignatureVerificationAlgorithm for RsaPssSha256 {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        crate::tls_rsa::verify_pss_sha256(public_key, message, signature)
            .map_err(|_| InvalidSignature)
    }
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }
    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_PSS_SHA256
    }
}

/// Certificate-only PKCS1-v1_5/SHA256. Private fields restrict instances to the
/// two exact accepted AlgorithmIdentifiers; neither is a CertificateVerify mode.
#[derive(Debug)]
pub struct RsaPkcs1Sha256 {
    absent_parameters: bool,
}
pub static RSA_PKCS1_SHA256: RsaPkcs1Sha256 = RsaPkcs1Sha256 {
    absent_parameters: false,
};
/// RFC4055 section5 requires accepting absent as well as NULL signature
/// parameters. Reuse the exact pinned webpki identifier, with no broad ASN.1
/// equivalence or relaxation of the encoded signature's DigestInfo.
pub static RSA_PKCS1_SHA256_ABSENT_PARAMS: RsaPkcs1Sha256 = RsaPkcs1Sha256 {
    absent_parameters: true,
};

impl SignatureVerificationAlgorithm for RsaPkcs1Sha256 {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        crate::tls_rsa::verify_pkcs1_sha256(public_key, message, signature)
            .map_err(|_| InvalidSignature)
    }
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }
    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        if self.absent_parameters {
            AlgorithmIdentifier::from_slice(include_bytes!(
                "../vendor/rustls-webpki-0.103.15/src/data/alg-rsa-pkcs1-sha256-absent-params.der"
            ))
        } else {
            alg_id::RSA_PKCS1_SHA256
        }
    }
}

impl SignatureVerificationAlgorithm for P256Sha256 {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let key = VerifyingKey::from_sec1_bytes(public_key).map_err(|_| InvalidSignature)?;
        let signature = Signature::from_der(signature).map_err(|_| InvalidSignature)?;
        key.verify(message, &signature)
            .map_err(|_| InvalidSignature)
    }
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_P256
    }
    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_SHA256
    }
}

/// Convert an already-trusted caller-provisioned root to a borrowed trust anchor.
/// This does not establish trust or download/install a root. Self-signature and
/// root validity dates are not a substitute for the caller's trust decision.
pub fn trust_anchor_from_der<'a>(
    certificate: &'a CertificateDer<'a>,
) -> Result<TrustAnchor<'a>, Error> {
    if certificate.as_ref().len() > MAX_CERTIFICATE_BYTES {
        return Err(Error::CertificateTooLarge);
    }
    check_key_usage(certificate.as_ref(), RequiredUsage::Ca)?;
    webpki::anchor_from_trusted_cert(certificate).map_err(Error::Certificate)
}

/// Trust roots/time are supplied by the caller. The caller must provide a trusted
/// time source; omitting time verification or substituting a made-up time is not
/// a supported certificate-verification mode.
pub struct ServerVerifier<'a> {
    anchors: &'a [TrustAnchor<'a>],
    time: UnixTime,
    limits: Limits,
}
impl<'a> ServerVerifier<'a> {
    pub fn new(
        anchors: &'a [TrustAnchor<'a>],
        time: UnixTime,
        limits: Limits,
    ) -> Result<Self, Error> {
        limits.validate()?;
        if anchors.is_empty() {
            return Err(Error::NoTrustAnchors);
        }
        if anchors.len() > limits.max_trust_anchors {
            return Err(Error::TooManyTrustAnchors);
        }
        Ok(Self {
            anchors,
            time,
            limits,
        })
    }

    /// Validate the server certificate chain, requested hostname/IP, validity,
    /// basic/name constraints, EKU and KeyUsage. Returned certificate remains
    /// borrowed from the caller. TLS CertificateVerify and Finished are separate,
    /// mandatory subsequent checks before application data may be authorized.
    pub fn verify_server<'c>(
        &self,
        leaf: &'c CertificateDer<'c>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
    ) -> Result<ValidatedServerCertificate<'c>, Error> {
        if intermediates.len() > self.limits.max_intermediates {
            return Err(Error::TooManyIntermediates);
        }
        let mut total = 0usize;
        for cert in core::iter::once(leaf).chain(intermediates.iter()) {
            if cert.as_ref().len() > self.limits.max_certificate_bytes {
                return Err(Error::CertificateTooLarge);
            }
            total = total
                .checked_add(cert.as_ref().len())
                .ok_or(Error::ChainTooLarge)?;
            if total > self.limits.max_chain_bytes {
                return Err(Error::ChainTooLarge);
            }
        }
        let cert = webpki::EndEntityCert::try_from(leaf).map_err(Error::Certificate)?;
        check_key_usage(leaf.as_ref(), RequiredUsage::Leaf)?;
        {
            let path = cert
                .verify_for_usage(
                    &SIGNATURE_ALGORITHMS,
                    self.anchors,
                    intermediates,
                    self.time,
                    webpki::KeyUsage::server_auth(),
                    None,
                    None,
                )
                .map_err(Error::Certificate)?;
            for intermediate in path.intermediate_certificates() {
                check_key_usage(intermediate.der().as_ref(), RequiredUsage::Ca)?;
            }
        }
        cert.verify_is_valid_for_subject_name(name)
            .map_err(Error::Certificate)?;
        Ok(ValidatedServerCertificate { cert })
    }
}

/// Chain/name/usage-validated certificate, NOT an authenticated TLS connection.
/// This type intentionally cannot be cloned and exposes no unverified leaf key.
pub struct ValidatedServerCertificate<'a> {
    cert: webpki::EndEntityCert<'a>,
}
impl ValidatedServerCertificate<'_> {
    /// RFC9846 section4.4.3 server CertificateVerify with the transcript hash
    /// BEFORE CertificateVerify. Permits ECDSA-P256 (0x0403) and RSA-PSS-rsae
    /// (0x0804), both SHA256. PKCS1 (0x0401) and PSS-restricted keys (0x0809)
    /// reject. The signature bytes are exactly those carried in the TLS message.
    pub fn verify_certificate_verify(
        &self,
        scheme: u16,
        transcript_hash: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), Error> {
        let algorithm: &dyn SignatureVerificationAlgorithm = match scheme {
            ECDSA_SECP256R1_SHA256 => &P256_SHA256,
            RSA_PSS_RSAE_SHA256 => &RSA_PSS_SHA256,
            _ => return Err(Error::UnsupportedSignatureScheme(scheme)),
        };
        // 64 spaces + 33-byte context + one zero + SHA-256 transcript hash.
        let mut message = [0x20; 130];
        message[64..97].copy_from_slice(SERVER_VERIFY_CONTEXT);
        message[97] = 0;
        message[98..].copy_from_slice(transcript_hash);
        self.cert
            .verify_signature(algorithm, &message, signature)
            .map_err(|_| Error::CertificateVerify)
    }
}

#[derive(Clone, Copy)]
enum RequiredUsage {
    Leaf,
    Ca,
}

fn check_key_usage(certificate: &[u8], required: RequiredUsage) -> Result<(), Error> {
    let Some(usage) = read_key_usage(certificate).map_err(|_| Error::InvalidDer)? else {
        // RFC8446: digitalSignature is required when the extension is present.
        return Ok(());
    };
    if usage.is_empty() || usage.bit_len() > 9 || !usage.bits().any(|set| set) {
        return Err(Error::InvalidKeyUsage);
    }
    // DER named-bit strings may not contain nonzero unused trailing bits.
    if let Some(last) = usage.raw_bytes().last()
        && usage.unused_bits() != 0
        && last & ((1u8 << usage.unused_bits()) - 1) != 0
    {
        return Err(Error::InvalidKeyUsage);
    }
    let bit = match required {
        RequiredUsage::Leaf => 0,
        RequiredUsage::Ca => 5,
    };
    if !usage.bits().nth(bit).unwrap_or(false) {
        return Err(match required {
            RequiredUsage::Leaf => Error::MissingDigitalSignature,
            RequiredUsage::Ca => Error::MissingKeyCertSign,
        });
    }
    Ok(())
}

/// Supplement webpki's intentionally ignored KeyUsage bitfield. All ASN.1 tags,
/// lengths, nested limits, BIT STRING and OCTET STRING decoding use RustCrypto
/// der's borrowed parser; there is no handwritten DER-length parser here.
fn read_key_usage(certificate: &[u8]) -> der::Result<Option<BitStringRef<'_>>> {
    AnyRef::from_der(certificate)?.sequence(|certificate| {
        let tbs: AnyRef<'_> = certificate.decode()?;
        let _: AnyRef<'_> = certificate.decode()?;
        let _: BitStringRef<'_> = certificate.decode()?;
        tbs.sequence(|tbs| {
            let version = Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::N0,
            };
            if !tbs.is_finished() && tbs.peek_tag()? == version {
                let _: AnyRef<'_> = tbs.decode()?;
            }
            // serialNumber, signature, issuer, validity, subject, SPKI.
            for tag in [
                Tag::Integer,
                Tag::Sequence,
                Tag::Sequence,
                Tag::Sequence,
                Tag::Sequence,
                Tag::Sequence,
            ] {
                let value: AnyRef<'_> = tbs.decode()?;
                value.tag().assert_eq(tag)?;
            }
            if tbs.is_finished() {
                return Ok(None);
            }
            let extensions: AnyRef<'_> = tbs.decode()?;
            extensions.tag().assert_eq(Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::N3,
            })?;
            AnyRef::from_der(extensions.value())?.sequence(|extensions| {
                let mut usage = None;
                let mut count = 0;
                while !extensions.is_finished() {
                    count += 1;
                    if count > MAX_EXTENSIONS {
                        return Err(Tag::Sequence.value_error());
                    }
                    let extension: AnyRef<'_> = extensions.decode()?;
                    extension.sequence(|extension| {
                        let oid: AnyRef<'_> = extension.decode()?;
                        oid.tag().assert_eq(Tag::ObjectIdentifier)?;
                        if !extension.is_finished() && extension.peek_tag()? == Tag::Boolean {
                            let _: bool = extension.decode()?;
                        }
                        let value: OctetStringRef<'_> = extension.decode()?;
                        // id-ce-keyUsage, 2.5.29.15. OID value bytes, not a full TLV.
                        if oid.value() == [0x55, 0x1d, 0x0f] {
                            if usage.is_some() {
                                return Err(Tag::BitString.value_error());
                            }
                            usage = Some(BitStringRef::from_der(value.as_bytes())?);
                        }
                        Ok(())
                    })?;
                }
                Ok(usage)
            })
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::time::Duration;

    fn hex<const N: usize>(text: &str) -> [u8; N] {
        let mut out = [0; N];
        let mut n = 0;
        for ch in text.bytes().filter(|ch| !ch.is_ascii_whitespace()) {
            let x = match ch {
                b'0'..=b'9' => ch - b'0',
                b'a'..=b'f' => ch - b'a' + 10,
                _ => panic!("bad hex"),
            };
            assert!(n / 2 < N);
            out[n / 2] = (out[n / 2] << 4) | x;
            n += 1;
        }
        assert_eq!(n, N * 2);
        out
    }

    // Real ephemeral P-256 CA/intermediate/leaf generated with rcgen 0.13.2
    // and ring 0.17.14. CertificateVerify was signed by ring over the standard
    // server context and transcript hash [0x42;32]. No private key is retained.
    // Fixtures' validity is 2025-01-01 through 2035-01-01; tests inject time.
    fn root() -> [u8; 392] {
        hex(
            "3082018430820129a0030201020214634e303a6f1f18a40bd9673aec18016eb2
            7e16dc300a06082a8648ce3d04030230143112301006035504030c0974657374
            20726f6f74301e170d3235303130313030303030305a170d3335303130313030
            303030305a30143112301006035504030c097465737420726f6f743059301306
            072a8648ce3d020106082a8648ce3d030107034200045d0a7848239e3b29fde0
            60cfc744c76d88a9e8a241e3e5329251c513c618c50be5d257b37cfd40d22bc8
            959636c9eb1c0cbface8a49f538f71d23e43bbb85c94a359305730140603551d
            11040d300b82097465737420726f6f74300f0603551d0f0101ff040503030706
            00301d0603551d0e041604148eb92b8aa47af202e8e6f9d68d14798f8672d14f
            300f0603551d130101ff040530030101ff300a06082a8648ce3d040302034900
            3046022100f53b961b495597acc028a8c6c00fc1bbb8405e8da3d43265eb06e5
            9d38c9e8ed022100e295ac20bea89ff508eb074afc1b9c211f78ffb1daf8bb7c
            7b4a62ce2765b65c",
        )
    }
    fn wrong_root() -> [u8; 395] {
        hex(
            "308201873082012ca00302010202141c975ffd0948062bec56984411230fef4c
            80ea5d300a06082a8648ce3d04030230153113301106035504030c0a77726f6e
            6720726f6f74301e170d3235303130313030303030305a170d33353031303130
            30303030305a30153113301106035504030c0a77726f6e6720726f6f74305930
            1306072a8648ce3d020106082a8648ce3d0301070342000490f6e43e33df559f
            238cd2e3e33ad2cd845e986e8dda74f8f7bf444930b9cb7eb69bc18386c1dd38
            c2b0cd432701ad8a7abe3fd268c0b56807ccb26184362920a35a305830150603
            551d11040e300c820a77726f6e6720726f6f74300f0603551d0f0101ff040503
            03070600301d0603551d0e0416041423cd5a653d762fa689fc59c7e3b4fbd544
            6e4927300f0603551d130101ff040530030101ff300a06082a8648ce3d040302
            0349003046022100dfe35572169f7b9b9f08bfaad65dec300d506bf599b8c1a8
            cde06056977a002a022100f29a90952c109234aecacaac239f41bc5beec1b556
            10ffa995d771828021032e",
        )
    }
    fn intermediate() -> [u8; 410] {
        hex(
            "308201963082013ca0030201020214645fc7c2dce0329f5d39bbad8407a1132b
            60208c300a06082a8648ce3d04030230143112301006035504030c0974657374
            20726f6f74301e170d3235303130313030303030305a170d3335303130313030
            303030305a301c311a301806035504030c117465737420696e7465726d656469
            6174653059301306072a8648ce3d020106082a8648ce3d03010703420004c715
            e83c99564d432de616bd7d2caed1554cfc4e4175c5e28f358346dd0cb0624bed
            c54348310cf9445bb0539f33b918eb5ea7ac97ecba5013f4dd2a3ae1417ea364
            3062301c0603551d110415301382117465737420696e7465726d656469617465
            300f0603551d0f0101ff04050303070600301d0603551d0e041604142169d229
            fb9689229f540a8a75697293a6bf588230120603551d130101ff040830060101
            ff020100300a06082a8648ce3d0403020348003045022100c60faddf6bedd880
            20ddefeefdf58a5b7ebab06866f5b4a10ea68080d1f0cb5002206c2996aaa6d3
            40e1fb91a0b337f9b92ac8cd8a56aa0beda668e296631f259af2",
        )
    }
    fn bad_ca_usage() -> [u8; 410] {
        hex(
            "308201963082013ca0030201020214645fc7c2dce0329f5d39bbad8407a1132b
            60208c300a06082a8648ce3d04030230143112301006035504030c0974657374
            20726f6f74301e170d3235303130313030303030305a170d3335303130313030
            303030305a301c311a301806035504030c117465737420696e7465726d656469
            6174653059301306072a8648ce3d020106082a8648ce3d03010703420004c715
            e83c99564d432de616bd7d2caed1554cfc4e4175c5e28f358346dd0cb0624bed
            c54348310cf9445bb0539f33b918eb5ea7ac97ecba5013f4dd2a3ae1417ea364
            3062301c0603551d110415301382117465737420696e7465726d656469617465
            300f0603551d0f0101ff04050303078000301d0603551d0e041604142169d229
            fb9689229f540a8a75697293a6bf588230120603551d130101ff040830060101
            ff020100300a06082a8648ce3d0403020348003045022100abd76f2c9ed8a2d0
            99bad13a12d9f67d8179b184bb3fad457389676d7edfb5120220172831c19c37
            fdfa01313b0caf79257da8e7b6a1cdec61c2b3ef157935a1eaf7",
        )
    }
    fn leaf() -> [u8; 372] {
        hex(
            "3082017030820116a0030201020214503708698b167fb4dabe5fc37713f9292a
            fa2342300a06082a8648ce3d040302301c311a301806035504030c1174657374
            20696e7465726d656469617465301e170d3235303130313030303030305a170d
            3335303130313030303030305a30143112301006035504030c096c6f63616c68
            6f73743059301306072a8648ce3d020106082a8648ce3d03010703420004bd6e
            187a4448091d5e5d15b2b1766efa92dc7857ad34cf9f806caabe153f05bc121c
            b9ca9e3d77f8f7837e08389bd24223c010a877a6254755debd5edf8cb151a33e
            303c30140603551d11040d300b82096c6f63616c686f7374300f0603551d0f01
            01ff0405030307800030130603551d25040c300a06082b06010505070301300a
            06082a8648ce3d0403020348003045022100cd3e0b6e5162265c8a3035ab648e
            ad936369e7d7533dc4c47873e70b3fccc846022061c3460f474bf555abe08828
            5736c82c441a39790a8ef3f51d88ce93ce125701",
        )
    }
    fn bad_key_usage() -> [u8; 372] {
        hex(
            "3082017030820116a0030201020214503708698b167fb4dabe5fc37713f9292a
            fa2342300a06082a8648ce3d040302301c311a301806035504030c1174657374
            20696e7465726d656469617465301e170d3235303130313030303030305a170d
            3335303130313030303030305a30143112301006035504030c096c6f63616c68
            6f73743059301306072a8648ce3d020106082a8648ce3d03010703420004bd6e
            187a4448091d5e5d15b2b1766efa92dc7857ad34cf9f806caabe153f05bc121c
            b9ca9e3d77f8f7837e08389bd24223c010a877a6254755debd5edf8cb151a33e
            303c30140603551d11040d300b82096c6f63616c686f7374300f0603551d0f01
            01ff0405030307200030130603551d25040c300a06082b06010505070301300a
            06082a8648ce3d04030203480030450220590b98ffd2338e4bec26decb61ea7d
            c1ba61b6105e18bc9a2055d843bd8452d60221008971afa5c8061f27206fade7
            9c2fb347b9b43e4d57744ff9eb0d8d86fac5ae8e",
        )
    }
    fn bad_eku() -> [u8; 371] {
        hex(
            "3082016f30820116a0030201020214503708698b167fb4dabe5fc37713f9292a
            fa2342300a06082a8648ce3d040302301c311a301806035504030c1174657374
            20696e7465726d656469617465301e170d3235303130313030303030305a170d
            3335303130313030303030305a30143112301006035504030c096c6f63616c68
            6f73743059301306072a8648ce3d020106082a8648ce3d03010703420004bd6e
            187a4448091d5e5d15b2b1766efa92dc7857ad34cf9f806caabe153f05bc121c
            b9ca9e3d77f8f7837e08389bd24223c010a877a6254755debd5edf8cb151a33e
            303c30140603551d11040d300b82096c6f63616c686f7374300f0603551d0f01
            01ff0405030307800030130603551d25040c300a06082b06010505070302300a
            06082a8648ce3d040302034700304402203d417153f2dfa05132363df10f4bd8
            bca91d6a1579feef82c633b2b019f6012602204bf3ed8f60a3c5a335cd5e1e7d
            4d739e3c98157352bbb2cd442478eeb2a8e06f",
        )
    }
    fn no_key_usage() -> [u8; 354] {
        hex(
            "3082015e30820105a0030201020214503708698b167fb4dabe5fc37713f9292a
            fa2342300a06082a8648ce3d040302301c311a301806035504030c1174657374
            20696e7465726d656469617465301e170d3235303130313030303030305a170d
            3335303130313030303030305a30143112301006035504030c096c6f63616c68
            6f73743059301306072a8648ce3d020106082a8648ce3d03010703420004bd6e
            187a4448091d5e5d15b2b1766efa92dc7857ad34cf9f806caabe153f05bc121c
            b9ca9e3d77f8f7837e08389bd24223c010a877a6254755debd5edf8cb151a32d
            302b30140603551d11040d300b82096c6f63616c686f737430130603551d2504
            0c300a06082b06010505070301300a06082a8648ce3d04030203470030440220
            7649970d8146164c6bf792532aa3166f91957e5e111552bdabdcccd8ff5074fe
            022031efdb1736124eb2c9147822febc0ddf0f285da36b2595ed969c606ee854
            bef2",
        )
    }
    fn certificate_verify() -> [u8; 71] {
        hex(
            "3045022049e13b465faaa5456711957c334064c0e52e386e852547599a3d9417
            23c822c80221008906687d637e341498c8b92d416fe9a525561bbf281abd6c90
            7b14635061b0a6",
        )
    }

    const VALID_TIME: u64 = 1_800_000_000;
    fn validate(
        leaf: &[u8],
        intermediate: &[u8],
        root: &[u8],
        name: &str,
        now: u64,
        signature: Option<&[u8]>,
    ) -> Result<(), Error> {
        let root = CertificateDer::from(root);
        let anchors = [trust_anchor_from_der(&root)?];
        let verifier = ServerVerifier::new(
            &anchors,
            UnixTime::since_unix_epoch(Duration::from_secs(now)),
            Limits::default(),
        )?;
        let leaf = CertificateDer::from(leaf);
        let intermediate_array = [CertificateDer::from(intermediate)];
        let chain = if intermediate.is_empty() {
            &[][..]
        } else {
            &intermediate_array[..]
        };
        let verified =
            verifier.verify_server(&leaf, chain, &ServerName::try_from(name).unwrap())?;
        if let Some(signature) = signature {
            verified.verify_certificate_verify(ECDSA_SECP256R1_SHA256, &[0x42; 32], signature)?;
        }
        Ok(())
    }

    #[test]
    fn actual_ca_intermediate_hostname_and_tls_certificate_verify_succeed() {
        assert_eq!(
            validate(
                &leaf(),
                &intermediate(),
                &root(),
                "localhost",
                VALID_TIME,
                Some(&certificate_verify())
            ),
            Ok(())
        );
        assert_eq!(
            validate(
                &no_key_usage(),
                &intermediate(),
                &root(),
                "localhost",
                VALID_TIME,
                Some(&certificate_verify())
            ),
            Ok(())
        );
    }

    #[test]
    fn wrong_trust_root_hostname_missing_intermediate_and_corrupted_certificate_fail() {
        assert!(matches!(
            validate(
                &leaf(),
                &intermediate(),
                &wrong_root(),
                "localhost",
                VALID_TIME,
                None
            ),
            Err(Error::Certificate(webpki::Error::UnknownIssuer))
        ));
        assert!(matches!(
            validate(
                &leaf(),
                &intermediate(),
                &root(),
                "wrong.example",
                VALID_TIME,
                None
            ),
            Err(Error::Certificate(webpki::Error::CertNotValidForName(_)))
        ));
        assert!(matches!(
            validate(&leaf(), &[], &root(), "localhost", VALID_TIME, None),
            Err(Error::Certificate(webpki::Error::UnknownIssuer))
        ));
        let mut tampered = leaf();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(matches!(
            validate(
                &tampered,
                &intermediate(),
                &root(),
                "localhost",
                VALID_TIME,
                None
            ),
            Err(Error::Certificate(_))
        ));
    }

    #[test]
    fn actual_chain_validity_and_both_key_usages_are_enforced() {
        assert!(matches!(
            validate(
                &leaf(),
                &intermediate(),
                &root(),
                "localhost",
                1_500_000_000,
                None
            ),
            Err(Error::Certificate(webpki::Error::CertNotValidYet { .. }))
        ));
        assert!(matches!(
            validate(
                &leaf(),
                &intermediate(),
                &root(),
                "localhost",
                2_200_000_000,
                None
            ),
            Err(Error::Certificate(webpki::Error::CertExpired { .. }))
        ));
        assert_eq!(
            validate(
                &bad_key_usage(),
                &intermediate(),
                &root(),
                "localhost",
                VALID_TIME,
                None
            ),
            Err(Error::MissingDigitalSignature)
        );
        assert_eq!(
            validate(
                &leaf(),
                &bad_ca_usage(),
                &root(),
                "localhost",
                VALID_TIME,
                None
            ),
            Err(Error::MissingKeyCertSign)
        );
        assert!(matches!(
            validate(
                &bad_eku(),
                &intermediate(),
                &root(),
                "localhost",
                VALID_TIME,
                None
            ),
            Err(Error::Certificate(
                webpki::Error::RequiredEkuNotFoundContext(_)
            ))
        ));
        assert_eq!(
            trust_anchor_from_der(&CertificateDer::from(bad_ca_usage().as_slice())).err(),
            Some(Error::MissingKeyCertSign)
        );
    }

    #[test]
    fn certificate_verify_rejects_signature_context_hash_and_unsupported_scheme() {
        let root_bytes = root();
        let root = CertificateDer::from(root_bytes.as_slice());
        let anchors = [trust_anchor_from_der(&root).unwrap()];
        let verifier = ServerVerifier::new(
            &anchors,
            UnixTime::since_unix_epoch(Duration::from_secs(VALID_TIME)),
            Limits::default(),
        )
        .unwrap();
        let leaf_bytes = leaf();
        let leaf = CertificateDer::from(leaf_bytes.as_slice());
        let intermediate_bytes = intermediate();
        let chain = [CertificateDer::from(intermediate_bytes.as_slice())];
        let cert = verifier
            .verify_server(&leaf, &chain, &ServerName::try_from("localhost").unwrap())
            .unwrap();
        let signature = certificate_verify();
        cert.verify_certificate_verify(0x0403, &[0x42; 32], &signature)
            .unwrap();
        assert_eq!(
            cert.verify_certificate_verify(0x0403, &[0x43; 32], &signature),
            Err(Error::CertificateVerify)
        );
        assert_eq!(
            cert.verify_certificate_verify(0x0804, &[0x42; 32], &signature),
            Err(Error::CertificateVerify)
        );
        for scheme in [RSA_PKCS1_SHA256_SCHEME, 0x0809] {
            assert_eq!(
                cert.verify_certificate_verify(scheme, &[0x42; 32], &signature),
                Err(Error::UnsupportedSignatureScheme(scheme))
            );
        }
        for i in 0..signature.len() {
            let mut bad = signature;
            bad[i] ^= 1;
            assert_eq!(
                cert.verify_certificate_verify(0x0403, &[0x42; 32], &bad),
                Err(Error::CertificateVerify)
            );
        }
        for len in 0..signature.len() {
            assert_eq!(
                cert.verify_certificate_verify(0x0403, &[0x42; 32], &signature[..len]),
                Err(Error::CertificateVerify)
            );
        }
    }

    #[test]
    fn malformed_der_limits_and_missing_roots_fail_without_authentication() {
        let root_bytes = root();
        let root = CertificateDer::from(root_bytes.as_slice());
        let anchors = [trust_anchor_from_der(&root).unwrap()];
        let now = UnixTime::since_unix_epoch(Duration::from_secs(VALID_TIME));
        assert!(matches!(
            ServerVerifier::new(&[], now, Limits::default()),
            Err(Error::NoTrustAnchors)
        ));
        let limits = Limits {
            max_intermediates: MAX_INTERMEDIATES + 1,
            ..Limits::default()
        };
        assert!(matches!(
            ServerVerifier::new(&anchors, now, limits),
            Err(Error::InvalidLimits)
        ));
        let limits = Limits {
            max_certificate_bytes: 64,
            ..Limits::default()
        };
        let verifier = ServerVerifier::new(&anchors, now, limits).unwrap();
        let leaf_bytes = leaf();
        let leaf_cert = CertificateDer::from(leaf_bytes.as_slice());
        let name = ServerName::try_from("localhost").unwrap();
        assert!(matches!(
            verifier.verify_server(&leaf_cert, &[], &name),
            Err(Error::CertificateTooLarge)
        ));
        let verifier = ServerVerifier::new(&anchors, now, Limits::default()).unwrap();
        let too_many: [CertificateDer<'_>; MAX_INTERMEDIATES + 1] =
            core::array::from_fn(|_| CertificateDer::from(&[][..]));
        assert!(matches!(
            verifier.verify_server(&leaf_cert, &too_many, &name),
            Err(Error::TooManyIntermediates)
        ));
        for len in 0..leaf_bytes.len() {
            let truncated = CertificateDer::from(&leaf_bytes[..len]);
            assert!(verifier.verify_server(&truncated, &[], &name).is_err());
        }
        assert!(read_key_usage(&[0x30, 0x80, 0, 0]).is_err());
        assert!(read_key_usage(&[0x30, 0xff]).is_err());
    }
}
