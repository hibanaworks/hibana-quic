//! Allocating host PEM input. Project-owned RFC7468 envelope/base64 decoding.
//! No DER/trust/protocol progress decisions. All blocks before the selected
//! object are validated; certificate collections validate the complete file.
use hibana_tls::secret::Secret;
use std::{fs, path::Path};
type Result<T> = std::result::Result<T, String>;
#[derive(Debug)]
pub enum PrivateKeyDer {
    Pkcs8(Secret<Vec<u8>>),
    Sec1(Secret<Vec<u8>>),
}
pub fn certificates(path: &Path) -> Result<Vec<Vec<u8>>> {
    let bytes = fs::read(path)
        .map_err(|e| format!("cannot read certificate file {}: {e}", path.display()))?;
    certificate_bytes(&bytes)
}
fn certificate_bytes(bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut rest = bytes;
    let mut result = Vec::new();
    while let Some((label, value)) =
        block(&mut rest).map_err(|e| format!("invalid certificate PEM: {e}"))?
    {
        let mut value = Secret::new(value);
        if label == b"CERTIFICATE" {
            result.push(std::mem::take(&mut *value));
        }
    }
    if result.is_empty() {
        return Err("certificate PEM contains no certificates".into());
    }
    Ok(result)
}
#[allow(dead_code)]
pub fn private_key(path: &Path) -> Result<PrivateKeyDer> {
    let bytes = Secret::new(
        fs::read(path).map_err(|e| format!("cannot read key file {}: {e}", path.display()))?,
    );
    private_key_bytes(&bytes)
}
fn private_key_bytes(bytes: &[u8]) -> Result<PrivateKeyDer> {
    let mut rest = bytes;
    while let Some((label, value)) =
        block(&mut rest).map_err(|e| format!("invalid private-key PEM: {e}"))?
    {
        let value = Secret::new(value);
        match label {
            b"RSA PRIVATE KEY" => {
                return Err("unsupported RSA signing key; ECDSA P-256 required".into());
            }
            b"PRIVATE KEY" => return Ok(PrivateKeyDer::Pkcs8(value)),
            b"EC PRIVATE KEY" => return Ok(PrivateKeyDer::Sec1(value)),
            _ => {}
        }
    }
    Err("key PEM contains no supported private key".into())
}
fn line<'a>(input: &mut &'a [u8]) -> &'a [u8] {
    let end = input
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(input.len());
    let value = &input[..end];
    *input = &input[(end + 1).min(input.len())..];
    value.strip_suffix(b"\r").unwrap_or(value)
}
// Borrowed label and owned decoded bytes; no wrapper or additional allocation.
#[allow(clippy::type_complexity)]
fn block<'a>(
    input: &mut &'a [u8],
) -> std::result::Result<Option<(&'a [u8], Vec<u8>)>, &'static str> {
    while !input.is_empty() {
        let header = line(input);
        if !header.starts_with(b"-----BEGIN ") {
            continue;
        }
        let label = header
            .strip_prefix(b"-----BEGIN ")
            .and_then(|s| s.strip_suffix(b"-----"))
            .ok_or("bad header")?;
        if label.is_empty()
            || !label
                .iter()
                .all(|b| b.is_ascii_uppercase() || *b == b' ' || b.is_ascii_digit())
        {
            return Err("bad label");
        }
        let mut encoded = Secret::new(Vec::new());
        while !input.is_empty() {
            let next = line(input);
            if next.starts_with(b"-----END ") {
                if next
                    .strip_prefix(b"-----END ")
                    .and_then(|s| s.strip_suffix(b"-----"))
                    != Some(label)
                {
                    return Err("mismatched footer");
                }
                return Ok(Some((label, decode(&encoded)?)));
            }
            encoded.extend(next.iter().filter(|b| !b.is_ascii_whitespace()));
        }
        return Err("missing footer");
    }
    Ok(None)
}
fn decode(input: &[u8]) -> std::result::Result<Vec<u8>, &'static str> {
    if input.is_empty() || !input.len().is_multiple_of(4) {
        return Err("invalid base64 length");
    }
    let mut result = Secret::new(Vec::with_capacity(input.len() / 4 * 3));
    let digit = |b: u8| -> std::result::Result<u8, &'static str> {
        match b {
            b'A'..=b'Z' => Ok(b - b'A'),
            b'a'..=b'z' => Ok(b - b'a' + 26),
            b'0'..=b'9' => Ok(b - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err("invalid base64 digit"),
        }
    };
    for (i, chunk) in input.chunks_exact(4).enumerate() {
        let a = digit(chunk[0])?;
        let b = digit(chunk[1])?;
        let last = (i + 1) * 4 == input.len();
        result.push((a << 2) | (b >> 4));
        if chunk[2] == b'=' {
            if !last || chunk[3] != b'=' || b & 15 != 0 {
                return Err("invalid base64 padding");
            }
        } else {
            let c = digit(chunk[2])?;
            result.push((b << 4) | (c >> 2));
            if chunk[3] == b'=' {
                if !last || c & 3 != 0 {
                    return Err("invalid base64 padding");
                }
            } else {
                result.push((c << 6) | digit(chunk[3])?);
            }
        }
    }
    Ok(std::mem::take(&mut *result))
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
        for (label, expected) in [("PRIVATE KEY", 8), ("EC PRIVATE KEY", 2)] {
            let pem = format!(
                "{CERT}-----BEGIN {label}-----\nBAUG\n-----END {label}-----\n{KEY}{BAD_KEY}"
            );
            let key = private_key_bytes(pem.as_bytes()).unwrap();
            let actual = match key {
                PrivateKeyDer::Pkcs8(key) => {
                    assert_eq!(key.as_slice(), [4, 5, 6]);
                    8
                }
                PrivateKeyDer::Sec1(key) => {
                    assert_eq!(key.as_slice(), [4, 5, 6]);
                    2
                }
            };
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn unsupported_rsa_signing_material_is_rejected_without_selecting_a_later_key() {
        let bytes =
            format!("-----BEGIN RSA PRIVATE KEY-----\nBAUG\n-----END RSA PRIVATE KEY-----\n{KEY}");
        assert_eq!(
            private_key_bytes(bytes.as_bytes()).unwrap_err(),
            "unsupported RSA signing key; ECDSA P-256 required"
        );
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
