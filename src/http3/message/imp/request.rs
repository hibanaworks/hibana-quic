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
