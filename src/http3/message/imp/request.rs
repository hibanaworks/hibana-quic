//! Bounded request frame and field validation.
use super::wire::unknown;
use crate::http3::message::{Error, Result};
use crate::http3::{self, Fields};
/// A FIN-complete bounded GET request: HEADERS first, then an empty body.
/// Unknown extensions are skipped by their actual lengths. This file-service
/// profile does not accept pushed responses, CONNECT, or nonempty GET bodies.
pub fn decode_request(input: &[u8]) -> Result<Fields> {
    let mut offset = 0usize;
    let decoded = loop {
        let frame = http3::decode_frame_header(input.get(offset..).ok_or("request framing")?)
            .map_err(Error::from)?;
        offset = offset
            .checked_add(frame.encoded_len)
            .ok_or("request offset overflow")?;
        let end = offset
            .checked_add(usize::try_from(frame.length).map_err(Error::from)?)
            .ok_or("request length overflow")?;
        let bytes = input.get(offset..end).ok_or("truncated request frame")?;
        offset = end;
        if frame.kind == 1 {
            break http3::decode_fields(bytes).map_err(Error::from)?;
        }
        unknown(frame.kind)?;
    };
    if decoded.status.is_some()
        || decoded.method != Some(http3::Method::Get)
        || decoded.https != Some(true)
        || decoded.path_len == 0
        || decoded.authority_len == 0
        || decoded.content_length.is_some_and(|n| n != 0)
    {
        return Err("request is not a bounded HTTPS GET".into());
    }
    while offset < input.len() {
        let frame = http3::decode_frame_header(&input[offset..]).map_err(Error::from)?;
        offset += frame.encoded_len;
        let end = offset
            .checked_add(usize::try_from(frame.length).map_err(Error::from)?)
            .ok_or("request length overflow")?;
        input.get(offset..end).ok_or("truncated request body")?;
        if frame.kind != 0 || frame.length != 0 {
            unknown(frame.kind)?;
        }
        offset = end;
    }
    Ok(decoded)
}

/// Validate the ordinary HTTPS request profile without retaining temporary
/// Huffman-decoded field slices. CONNECT needs separate tunnel semantics.
pub(in crate::http3) fn ordinary(encoded: &[u8], fields: &Fields) -> Result<()> {
    if fields.status.is_some() || fields.method.is_none() || fields.https != Some(true) {
        return Err("invalid ordinary HTTPS request pseudo-header".into());
    }
    if fields.method == Some(http3::Method::Connect) {
        return Err("CONNECT requires a tunnel consumer".into());
    }
    super::uri::path(
        &fields.path[..fields.path_len],
        fields.method == Some(http3::Method::Options),
    )?;
    let authority = &fields.authority[..fields.authority_len];
    if !authority.is_empty() {
        super::uri::valid_authority(authority)?;
    }
    let mut hosts = 0u8;
    http3::decode_fields_with(encoded, |name, value| {
        if name == b"host" {
            hosts = hosts.checked_add(1).ok_or(http3::Error::Duplicate)?;
            if hosts != 1 {
                return Err(http3::Error::Duplicate);
            }
            super::uri::valid_authority(value)?;
            if !authority.is_empty() && !super::uri::same_authority(authority, value)? {
                return Err(http3::Error::Field);
            }
        }
        Ok(())
    })?;
    if authority.is_empty() && hosts == 0 {
        return Err("HTTPS request has no authority or Host".into());
    }
    Ok(())
}

/// TE is permitted only in initial request headers, never responses or trailers.
pub(in crate::http3) fn without_te(encoded: &[u8]) -> Result<()> {
    http3::decode_fields_with(encoded, |name, _| {
        if name == b"te" {
            Err(http3::Error::Field)
        } else {
            Ok(())
        }
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn validate(fields: &[(&[u8], &[u8])]) -> bool {
        let mut encoded = [0; 1024];
        let n = http3::encode_fields(fields.iter().copied(), &mut encoded).unwrap();
        let decoded = http3::decode_fields(&encoded[..n]).unwrap();
        ordinary(&encoded[..n], &decoded).is_ok()
    }
    #[test]
    fn host_only_normalized_authority_and_request_target_validation() {
        assert!(validate(&[
            (b":method", b"GET"),
            (b":scheme", b"HTTPS"),
            (b":path", b"//a"),
            (b"host", b"example.com")
        ]));
        assert!(validate(&[
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"EXAMPLE.com:443"),
            (b":path", b"/"),
            (b"host", b"example.com")
        ]));
        assert!(!validate(&[
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"a.example"),
            (b":path", b"/"),
            (b"host", b"b.example")
        ]));
        assert!(!validate(&[
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":path", b"/"),
            (b"host", b"example.com"),
            (b"host", b"example.com")
        ]));
        assert!(!validate(&[
            (b":method", b"CONNECT"),
            (b":scheme", b"https"),
            (b":authority", b"example.com"),
            (b":path", b"/")
        ]));
        assert!(!validate(&[
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"example.com"),
            (b":path", b"*")
        ]));
        assert!(validate(&[
            (b":method", b"OPTIONS"),
            (b":scheme", b"https"),
            (b":authority", b"example.com"),
            (b":path", b"*")
        ]));
    }
    #[test]
    fn te_is_rejected_outside_initial_request_headers() {
        let mut encoded = [0; 128];
        let n = http3::encode_fields([(b"te".as_slice(), b"trailers".as_slice())], &mut encoded)
            .unwrap();
        assert!(without_te(&encoded[..n]).is_err());
        assert!(validate(&[
            (b":method", b"POST"),
            (b":scheme", b"https"),
            (b":authority", b"example.com"),
            (b":path", b"/"),
            (b"te", b"trailers")
        ]));
    }
}
