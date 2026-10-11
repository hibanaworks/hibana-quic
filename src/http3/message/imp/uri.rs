//! Bounded HTTPS URI-component validation (RFC 9110 sections 4.1–4.3).
use crate::http3::Error;

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
fn unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-._~".contains(&byte)
}
fn subdelimiter(byte: u8) -> bool {
    b"!$&'()*+,;=".contains(&byte)
}
fn component(bytes: &[u8], permitted: impl Fn(u8) -> bool) -> Result<(), Error> {
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            let high = bytes
                .get(at + 1)
                .and_then(|b| hex(*b))
                .ok_or(Error::Field)?;
            let low = bytes
                .get(at + 2)
                .and_then(|b| hex(*b))
                .ok_or(Error::Field)?;
            let _ = (high, low);
            at += 3;
        } else if permitted(bytes[at]) {
            at += 1;
        } else {
            return Err(Error::Field);
        }
    }
    Ok(())
}
pub(super) fn path(bytes: &[u8], options: bool) -> Result<(), Error> {
    if bytes == b"*" {
        return if options { Ok(()) } else { Err(Error::Field) };
    }
    if !bytes.starts_with(b"/") {
        return Err(Error::Field);
    }
    // HTTP absolute-path permits repeated slashes (RFC 9114 erratum 7014).
    component(bytes, |b| {
        unreserved(b) || subdelimiter(b) || b":@/?".contains(&b)
    })
}

#[derive(PartialEq)]
enum Host<'a> {
    Name(&'a [u8]),
    V6(core::net::Ipv6Addr),
}
struct Authority<'a> {
    host: Host<'a>,
    port: u16,
}
fn authority(bytes: &[u8]) -> Result<Authority<'_>, Error> {
    let (host, port) = if bytes.starts_with(b"[") {
        let end = bytes.iter().position(|b| *b == b']').ok_or(Error::Field)?;
        let host = core::str::from_utf8(&bytes[1..end])
            .map_err(|_| Error::Field)?
            .parse::<core::net::Ipv6Addr>()
            .map_err(|_| Error::Field)?;
        (Host::V6(host), bytes.get(end + 1..).ok_or(Error::Field)?)
    } else {
        let end = bytes.iter().position(|b| *b == b':').unwrap_or(bytes.len());
        let host = &bytes[..end];
        if host.is_empty() {
            return Err(Error::Field);
        }
        component(host, |b| unreserved(b) || subdelimiter(b))?;
        (Host::Name(host), &bytes[end..])
    };
    let port = if port.is_empty() || port == b":" {
        443
    } else {
        let digits = port.strip_prefix(b":").ok_or(Error::Field)?;
        let mut value = 0u16;
        for byte in digits {
            if !byte.is_ascii_digit() {
                return Err(Error::Field);
            }
            value = value
                .checked_mul(10)
                .and_then(|n| n.checked_add((byte - b'0') as u16))
                .ok_or(Error::Field)?;
        }
        value
    };
    Ok(Authority { host, port })
}
pub(super) fn valid_authority(bytes: &[u8]) -> Result<(), Error> {
    authority(bytes).map(|_| ())
}

// Decode only percent-encoded unreserved characters for URI comparison.
// Reserved escapes remain escapes; their hex digits compare case-insensitively.
fn next_name(bytes: &[u8], at: &mut usize) -> Option<u8> {
    let byte = *bytes.get(*at)?;
    if byte == b'%' {
        let decoded = hex(bytes[*at + 1])? * 16 + hex(bytes[*at + 2])?;
        if unreserved(decoded) {
            *at += 3;
            return Some(decoded.to_ascii_lowercase());
        }
    }
    *at += 1;
    Some(byte.to_ascii_lowercase())
}
pub(super) fn same_authority(a: &[u8], b: &[u8]) -> Result<bool, Error> {
    let a = authority(a)?;
    let b = authority(b)?;
    if a.port != b.port {
        return Ok(false);
    }
    match (a.host, b.host) {
        (Host::V6(a), Host::V6(b)) => Ok(a == b),
        (Host::Name(a), Host::Name(b)) => {
            let (mut ai, mut bi) = (0, 0);
            loop {
                match (next_name(a, &mut ai), next_name(b, &mut bi)) {
                    (None, None) => return Ok(true),
                    (Some(a), Some(b)) if a == b => {}
                    _ => return Ok(false),
                }
            }
        }
        _ => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn https_authority_comparison_is_bounded_and_normalized() {
        for (a, b) in [
            (b"EXAMPLE.com".as_slice(), b"example.com:0443".as_slice()),
            (b"[::1]", b"[0:0:0:0:0:0:0:1]:443"),
            (b"%65xample.com:", b"example.com"),
        ] {
            assert_eq!(same_authority(a, b), Ok(true));
        }
        assert_eq!(
            same_authority(b"example.com:444", b"example.com"),
            Ok(false)
        );
        for value in [
            b"user@host".as_slice(),
            b":443",
            b"host:abc",
            b"host/path",
            b"host:65536",
            b"[::1]suffix",
            b"host%zz",
        ] {
            assert!(valid_authority(value).is_err());
        }
    }
    #[test]
    fn request_paths_follow_http_absolute_path_and_options_asterisk() {
        for value in [b"/".as_slice(), b"//a", b"/a%20b?x=1", b"/a:b@c"] {
            assert!(path(value, false).is_ok());
        }
        for value in [
            b"relative".as_slice(),
            b"/a b",
            b"/a#fragment",
            b"/%zz",
            b"*",
        ] {
            assert!(path(value, false).is_err());
        }
        assert!(path(b"*", true).is_ok());
    }
}
