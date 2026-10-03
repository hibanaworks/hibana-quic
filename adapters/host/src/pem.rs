//! Allocating host setup only. Do not include this module in the no_std core.
//!
//! Slice APIs deliberately require only pki-types/alloc, not pki-types/std.
//! Parse every certificate block (including errors after a valid block), but
//! select the first supported private key, matching the previous PEM reader.
//! PEM decoding does not validate DER, algorithms, trust, or key/cert matching;
//! the TLS/signing configuration must still perform those checks.

use rustls_pki_types::{
    CertificateDer, PrivateKeyDer,
    pem::{Error, PemObject},
};
use std::{fs, path::Path};

type Result<T> = std::result::Result<T, String>;

pub fn certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let bytes = fs::read(path)
        .map_err(|e| format!("cannot read certificate file {}: {e}", path.display()))?;
    certificate_bytes(&bytes)
}

fn certificate_bytes(bytes: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_slice_iter(bytes)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| format!("invalid certificate PEM: {e}"))?;
    if certs.is_empty() {
        return Err("certificate PEM contains no certificates".into());
    }
    Ok(certs)
}

// The verifying client includes this module but never reads a private key.
#[allow(dead_code)]
pub fn private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let bytes =
        fs::read(path).map_err(|e| format!("cannot read key file {}: {e}", path.display()))?;
    private_key_bytes(&bytes)
}

fn private_key_bytes(bytes: &[u8]) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_slice(bytes).map_err(|e| match e {
        Error::NoItemsFound => "key PEM contains no supported private key".into(),
        other => format!("invalid private-key PEM: {other}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tiny alleged DER values isolate PEM decoding from TLS's DER validation.
    const CERT: &str = "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n";
    const KEY: &str = "-----BEGIN PRIVATE KEY-----\nBAUG\n-----END PRIVATE KEY-----\n";
    const BAD_CERT: &str = "-----BEGIN CERTIFICATE-----\n!invalid!\n-----END CERTIFICATE-----\n";
    const BAD_KEY: &str = "-----BEGIN PRIVATE KEY-----\n!invalid!\n-----END PRIVATE KEY-----\n";

    #[test]
    fn certificates_collect_all_and_skip_other_well_formed_sections() {
        let pem = format!("comment\n{KEY}{CERT}{CERT}");
        let certs = certificate_bytes(pem.as_bytes()).unwrap();
        assert_eq!(certs.len(), 2);
        assert!(certs.iter().all(|cert| cert.as_ref() == [1, 2, 3]));
        assert_eq!(
            certificate_bytes(CERT.replace('\n', "\r\n").as_bytes())
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            certificate_bytes(CERT.trim_end().as_bytes()).unwrap().len(),
            1
        );
    }

    #[test]
    fn certificates_reject_malformed_blocks_even_after_a_valid_certificate() {
        for bad in [
            BAD_CERT,
            BAD_KEY,
            "-----BEGIN CERTIFICATE----\nAQID\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nAQID\n",
            "-----BEGIN CERTIFICATE-----\nAQID\n-----END PRIVATE KEY-----\n",
        ] {
            assert!(
                certificate_bytes(bad.as_bytes())
                    .unwrap_err()
                    .starts_with("invalid certificate PEM:")
            );
            assert!(certificate_bytes(format!("{CERT}{bad}").as_bytes()).is_err());
        }
    }

    #[test]
    fn absence_of_certificate_or_supported_key_fails_closed() {
        for bytes in [b"".as_slice(), b"plain text", KEY.as_bytes()] {
            assert_eq!(
                certificate_bytes(bytes).unwrap_err(),
                "certificate PEM contains no certificates"
            );
        }
        for bytes in [
            b"".as_slice(),
            b"plain text",
            CERT.as_bytes(),
            b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nAQID\n-----END ENCRYPTED PRIVATE KEY-----\n",
        ] {
            assert_eq!(
                private_key_bytes(bytes).unwrap_err(),
                "key PEM contains no supported private key"
            );
        }
    }

    #[test]
    fn first_supported_key_selection_and_formats_are_preserved() {
        for (label, expected) in [
            ("RSA PRIVATE KEY", 1),
            ("PRIVATE KEY", 8),
            ("EC PRIVATE KEY", 2),
        ] {
            let pem = format!(
                "{CERT}-----BEGIN {label}-----\nBAUG\n-----END {label}-----\n{KEY}{BAD_KEY}"
            );
            let key = private_key_bytes(pem.as_bytes()).unwrap();
            let actual = match key {
                PrivateKeyDer::Pkcs1(key) => {
                    assert_eq!(key.secret_pkcs1_der(), [4, 5, 6]);
                    1
                }
                PrivateKeyDer::Pkcs8(key) => {
                    assert_eq!(key.secret_pkcs8_der(), [4, 5, 6]);
                    8
                }
                PrivateKeyDer::Sec1(key) => {
                    assert_eq!(key.secret_sec1_der(), [4, 5, 6]);
                    2
                }
                _ => panic!("unexpected key format"),
            };
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn malformed_data_before_a_key_is_not_silently_skipped() {
        for bad in [
            BAD_KEY,
            BAD_CERT,
            "-----BEGIN PRIVATE KEY----\nBAUG\n-----END PRIVATE KEY-----\n",
        ] {
            assert!(
                private_key_bytes(format!("{bad}{KEY}").as_bytes())
                    .unwrap_err()
                    .starts_with("invalid private-key PEM:")
            );
        }
        assert!(private_key_bytes(b"-----BEGIN PRIVATE KEY-----\nBAUG\n").is_err());
    }

    #[test]
    fn file_io_errors_remain_errors_with_path_context() {
        let absent = std::env::temp_dir().join(format!("hibana-absent-pem-{}", std::process::id()));
        assert!(!absent.exists());
        assert!(
            certificates(&absent)
                .unwrap_err()
                .starts_with("cannot read certificate file ")
        );
        assert!(
            private_key(&absent)
                .unwrap_err()
                .starts_with("cannot read key file ")
        );
        // Reading a directory fails on the supported Linux host, too.
        assert!(certificates(&std::env::temp_dir()).is_err());
        assert!(private_key(&std::env::temp_dir()).is_err());
    }
}
