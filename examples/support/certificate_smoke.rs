//! Real certificate and CertificateVerify paths shared by allocator/link probes.
//! Public generated fixtures only; no private key, TLS connection or network I/O.
use core::time::Duration;
use hibana_quic::tls_certificate::{
    CertificateDer, ECDSA_SECP256R1_SHA256, Error, Limits, ServerName, ServerVerifier, UnixTime,
    trust_anchor_from_der,
};

const ROOT: &[u8] = include_bytes!("../../tests/vectors/certificates/root.der");
const WRONG_ROOT: &[u8] = include_bytes!("../../tests/vectors/certificates/wrong_root.der");
const INTERMEDIATE: &[u8] = include_bytes!("../../tests/vectors/certificates/intermediate.der");
const BAD_CA_USAGE: &[u8] = include_bytes!("../../tests/vectors/certificates/bad_ca_usage.der");
const LEAF: &[u8] = include_bytes!("../../tests/vectors/certificates/leaf.der");
const BAD_KEY_USAGE: &[u8] = include_bytes!("../../tests/vectors/certificates/bad_key_usage.der");
const BAD_EKU: &[u8] = include_bytes!("../../tests/vectors/certificates/bad_eku.der");
const SIGNATURE: &[u8] = include_bytes!("../../tests/vectors/certificates/certificate_verify.sig");

pub fn exercise() {
    let now = UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_000));
    let root = CertificateDer::from(core::hint::black_box(ROOT));
    let anchors = [trust_anchor_from_der(&root).unwrap()];
    let verifier = ServerVerifier::new(&anchors, now, Limits::default()).unwrap();
    let leaf = CertificateDer::from(core::hint::black_box(LEAF));
    let intermediate = [CertificateDer::from(core::hint::black_box(INTERMEDIATE))];
    let name = ServerName::try_from("localhost").unwrap();
    let validated = verifier.verify_server(&leaf, &intermediate, &name).unwrap();
    validated
        .verify_certificate_verify(
            ECDSA_SECP256R1_SHA256,
            &[0x42; 32],
            core::hint::black_box(SIGNATURE),
        )
        .unwrap();
    assert_eq!(
        validated.verify_certificate_verify(ECDSA_SECP256R1_SHA256, &[0x43; 32], SIGNATURE),
        Err(Error::CertificateVerify)
    );
    // RSA-PSS/SHA256 is implemented, but this validated key and signature are
    // ECDSA. Keep the actual algorithm/key mismatch as an authentication failure.
    assert_eq!(
        validated.verify_certificate_verify(0x0804, &[0x42; 32], SIGNATURE),
        Err(Error::CertificateVerify)
    );
    // SHA384 remains outside the explicitly supported signature profile.
    assert_eq!(
        validated.verify_certificate_verify(0x0805, &[0x42; 32], SIGNATURE),
        Err(Error::UnsupportedSignatureScheme(0x0805))
    );
    assert!(
        verifier
            .verify_server(
                &leaf,
                &intermediate,
                &ServerName::try_from("wrong.example").unwrap()
            )
            .is_err()
    );
    assert!(verifier.verify_server(&leaf, &[], &name).is_err());
    let bad_usage = CertificateDer::from(BAD_KEY_USAGE);
    assert!(matches!(
        verifier.verify_server(&bad_usage, &intermediate, &name),
        Err(Error::MissingDigitalSignature)
    ));
    let bad_ca = [CertificateDer::from(BAD_CA_USAGE)];
    assert!(matches!(
        verifier.verify_server(&leaf, &bad_ca, &name),
        Err(Error::MissingKeyCertSign)
    ));
    let bad_eku = CertificateDer::from(BAD_EKU);
    assert!(
        verifier
            .verify_server(&bad_eku, &intermediate, &name)
            .is_err()
    );
    let wrong_root = CertificateDer::from(WRONG_ROOT);
    let wrong_anchors = [trust_anchor_from_der(&wrong_root).unwrap()];
    let wrong_verifier = ServerVerifier::new(&wrong_anchors, now, Limits::default()).unwrap();
    assert!(
        wrong_verifier
            .verify_server(&leaf, &intermediate, &name)
            .is_err()
    );
    for seconds in [1_500_000_000, 2_200_000_000] {
        let invalid_time = UnixTime::since_unix_epoch(Duration::from_secs(seconds));
        let verifier = ServerVerifier::new(&anchors, invalid_time, Limits::default()).unwrap();
        assert!(verifier.verify_server(&leaf, &intermediate, &name).is_err());
    }
}
