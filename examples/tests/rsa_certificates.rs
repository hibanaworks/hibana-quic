//! Public independently generated RSA/mixed-chain fixtures. This test lives in
//! the clean host package so allocating rustls/webpki error features are absent.
use hibana_tls::certificate as cert;
use hibana_tls::certificate::*;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    time::Duration,
};
thread_local! { static COUNT: Cell<Option<usize>> = const { Cell::new(None) }; }
struct Counter;
fn allocation() {
    let _ = COUNT.try_with(|n| {
        if let Some(v) = n.get() {
            n.set(Some(v + 1));
        }
    });
}
unsafe impl GlobalAlloc for Counter {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        allocation();
        unsafe { System.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        allocation();
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        allocation();
        unsafe { System.realloc(p, l, n) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
}
#[global_allocator]
static ALLOCATOR: Counter = Counter;
fn measured<T>(f: impl FnOnce() -> T) -> T {
    COUNT.with(|n| n.set(Some(0)));
    let result = f();
    let count = COUNT.with(|n| n.replace(None).unwrap());
    assert_eq!(count, 0, "bounded RSA certificate path allocated");
    result
}
macro_rules! fixture {
    ($name:literal) => {
        include_bytes!(concat!("../../tests/vectors/certificates/rsa/", $name)).as_slice()
    };
}
const NOW: u64 = 1_800_000_000;
#[allow(clippy::too_many_arguments)]
fn verify(
    leaf: &[u8],
    root: &[u8],
    chain: &[&[u8]],
    hostname: &str,
    now: u64,
    cv: Option<(u16, &[u8; 32], &[u8])>,
) -> Result<(), cert::Error> {
    measured(|| {
        let root = CertificateDer::from(root);
        let anchors = [trust_anchor_from_der(&root)?];
        let verifier = ServerVerifier::new(
            &anchors,
            UnixTime::since_unix_epoch(Duration::from_secs(now)),
            Limits::default(),
        )?;
        let leaf = CertificateDer::from(leaf);
        let mut intermediates: [CertificateDer<'_>; 8] =
            core::array::from_fn(|_| CertificateDer::from(&[][..]));
        for (slot, bytes) in intermediates.iter_mut().zip(chain) {
            *slot = CertificateDer::from(*bytes);
        }
        let name = ServerName::try_from(hostname).unwrap();
        let validated = verifier.verify_server(&leaf, &intermediates[..chain.len()], &name)?;
        if let Some((scheme, hash, signature)) = cv {
            validated.verify_certificate_verify(scheme, hash, signature)?;
        }
        Ok(())
    })
}
#[test]
fn rsa_sizes_pkcs1_and_pss_chains_and_certificate_verify_allocate_zero() {
    for (root, pkcs1, pss, cv) in [
        (
            fixture!("root-2048.der"),
            fixture!("leaf-2048-pkcs1.der"),
            fixture!("leaf-2048-pss.der"),
            fixture!("cv-2048-pss.sig"),
        ),
        (
            fixture!("root-3072.der"),
            fixture!("leaf-3072-pkcs1.der"),
            fixture!("leaf-3072-pss.der"),
            fixture!("cv-3072-pss.sig"),
        ),
        (
            fixture!("root-4096.der"),
            fixture!("leaf-4096-pkcs1.der"),
            fixture!("leaf-4096-pss.der"),
            fixture!("cv-4096-pss.sig"),
        ),
    ] {
        for leaf in [pkcs1, pss] {
            assert_eq!(
                verify(
                    leaf,
                    root,
                    &[],
                    "localhost",
                    NOW,
                    Some((RSA_PSS_RSAE_SHA256, &[0x42; 32], cv))
                ),
                Ok(())
            );
        }
    }
}
#[test]
fn trust_name_time_usage_and_certificate_authentication_reject_without_allocation() {
    let root = fixture!("root-2048.der");
    let leaf = fixture!("leaf-2048-pkcs1.der");
    assert!(verify(leaf, fixture!("root-3072.der"), &[], "localhost", NOW, None).is_err());
    assert!(verify(leaf, root, &[], "wrong.example", NOW, None).is_err());
    for time in [1_500_000_000, 2_500_000_000] {
        assert!(verify(leaf, root, &[], "localhost", time, None).is_err());
    }
    assert_eq!(
        verify(
            fixture!("leaf-bad-ku.der"),
            root,
            &[],
            "localhost",
            NOW,
            None
        ),
        Err(cert::Error::MissingDigitalSignature)
    );
    assert!(
        verify(
            fixture!("leaf-bad-eku.der"),
            root,
            &[],
            "localhost",
            NOW,
            None
        )
        .is_err()
    );
    let mut corrupt = [0; 4096];
    corrupt[..leaf.len()].copy_from_slice(leaf);
    corrupt[leaf.len() - 1] ^= 1;
    assert!(verify(&corrupt[..leaf.len()], root, &[], "localhost", NOW, None).is_err());
    for len in [0, 1, leaf.len() / 2, leaf.len() - 1] {
        assert!(verify(&leaf[..len], root, &[], "localhost", NOW, None).is_err());
    }
}
#[test]
fn unsupported_pss_and_pkcs1_signature_algorithms_reject() {
    for leaf in [
        fixture!("leaf-pss-salt20.der"),
        fixture!("leaf-pss-mgf1-sha384.der"),
        fixture!("leaf-pss-sha384.der"),
        fixture!("leaf-pkcs1-sha384.der"),
    ] {
        assert!(verify(leaf, fixture!("root-2048.der"), &[], "localhost", NOW, None).is_err());
    }
}

#[test]
fn exact_algorithm_identifiers_allow_absent_signature_params_but_reject_restricted_spki() {
    let root = fixture!("root-2048.der");
    let cv = Some((
        RSA_PSS_RSAE_SHA256,
        &[0x42; 32],
        fixture!("cv-2048-pss.sig"),
    ));
    assert_eq!(
        verify(
            fixture!("leaf-pkcs1-absent-params.der"),
            root,
            &[],
            "localhost",
            NOW,
            cv
        ),
        Ok(())
    );
    for leaf in [
        fixture!("leaf-pss-restricted-spki.der"),
        fixture!("leaf-rsa-spki-absent-params.der"),
    ] {
        // The issuer signature is real and valid. Authentication still requires
        // CertificateVerify to enforce the leaf's exact SPKI algorithm policy.
        assert_eq!(verify(leaf, root, &[], "localhost", NOW, None), Ok(()));
        assert_eq!(
            verify(leaf, root, &[], "localhost", NOW, cv),
            Err(cert::Error::CertificateVerify)
        );
    }
}
#[test]
fn certificate_verify_never_accepts_pkcs1_wrong_parameters_or_bad_transcripts() {
    let root = fixture!("root-2048.der");
    let leaf = fixture!("leaf-2048-pkcs1.der");
    let valid = fixture!("cv-2048-pss.sig");
    for (scheme, signature) in [
        (RSA_PKCS1_SHA256_SCHEME, fixture!("cv-pkcs1.sig")),
        (0x0809, valid),
        (ECDSA_SECP256R1_SHA256, valid),
    ] {
        assert!(
            verify(
                leaf,
                root,
                &[],
                "localhost",
                NOW,
                Some((scheme, &[0x42; 32], signature))
            )
            .is_err()
        );
    }
    for signature in [
        fixture!("cv-pkcs1.sig"),
        fixture!("cv-pss-salt0.sig"),
        fixture!("cv-pss-mgf1-sha384.sig"),
        &valid[..valid.len() - 1],
    ] {
        assert!(
            verify(
                leaf,
                root,
                &[],
                "localhost",
                NOW,
                Some((RSA_PSS_RSAE_SHA256, &[0x42; 32], signature))
            )
            .is_err()
        );
    }
    assert!(
        verify(
            leaf,
            root,
            &[],
            "localhost",
            NOW,
            Some((RSA_PSS_RSAE_SHA256, &[0x43; 32], valid))
        )
        .is_err()
    );
    let mut corrupt = [0; 256];
    corrupt.copy_from_slice(valid);
    corrupt[0] ^= 1;
    assert!(
        verify(
            leaf,
            root,
            &[],
            "localhost",
            NOW,
            Some((RSA_PSS_RSAE_SHA256, &[0x42; 32], &corrupt))
        )
        .is_err()
    );
    let mut extended = [0; 257];
    extended[..256].copy_from_slice(valid);
    assert!(
        verify(
            leaf,
            root,
            &[],
            "localhost",
            NOW,
            Some((RSA_PSS_RSAE_SHA256, &[0x42; 32], &extended))
        )
        .is_err()
    );
}
#[test]
fn mixed_ec_rsa_chain_enforces_ca_usage_name_constraints_and_path_length() {
    let root = fixture!("mixed-root.der");
    let leaf = fixture!("mixed-leaf.der");
    assert_eq!(
        verify(
            leaf,
            root,
            &[fixture!("mixed-intermediate.der")],
            "localhost",
            NOW,
            Some((
                ECDSA_SECP256R1_SHA256,
                &[0x42; 32],
                fixture!("mixed-cv.sig")
            ))
        ),
        Ok(())
    );
    assert!(verify(leaf, root, &[], "localhost", NOW, None).is_err());
    assert_eq!(
        verify(
            leaf,
            root,
            &[fixture!("mixed-intermediate-bad-ku.der")],
            "localhost",
            NOW,
            None
        ),
        Err(cert::Error::MissingKeyCertSign)
    );
    assert!(
        verify(
            leaf,
            root,
            &[fixture!("mixed-intermediate-name-constraint.der")],
            "localhost",
            NOW,
            None
        )
        .is_err()
    );
    assert!(
        verify(
            fixture!("mixed-too-deep-leaf.der"),
            root,
            &[
                fixture!("mixed-subca.der"),
                fixture!("mixed-intermediate.der")
            ],
            "localhost",
            NOW,
            None
        )
        .is_err()
    );
}
