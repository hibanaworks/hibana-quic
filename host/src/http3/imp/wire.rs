//! File reads and bounded frame decoding; no endpoint progression.
use super::super::Result;
use hibana_quic::http3::{self, Fields, FrameHeader};
use std::{fs::File, os::unix::fs::FileExt};
pub(in crate::http3) fn fail(e: impl std::fmt::Debug) -> String {
    format!("HTTP/3 response: {e:?}")
}
fn varint(file: &File, cursor: &mut u64, total: u64) -> Result<u64> {
    if *cursor >= total {
        return Err("truncated HTTP/3 integer".into());
    }
    let mut bytes = [0; 8];
    file.read_exact_at(&mut bytes[..1], *cursor).map_err(fail)?;
    let len = 1usize << (bytes[0] >> 6);
    if (len as u64) > total - *cursor {
        return Err("truncated HTTP/3 integer".into());
    }
    file.read_exact_at(&mut bytes[..len], *cursor)
        .map_err(fail)?;
    *cursor += len as u64;
    Ok(
        hibana_quic::quic::kernel::packet::decode_varint(&bytes[..len])
            .map_err(fail)?
            .0,
    )
}
pub(in crate::http3) fn next(file: &File, cursor: &mut u64, total: u64) -> Result<Option<FrameHeader>> {
    if *cursor == total {
        return Ok(None);
    }
    let start = *cursor;
    let kind = varint(file, cursor, total)?;
    let length = varint(file, cursor, total)?;
    if length > total - *cursor {
        return Err("truncated HTTP/3 frame".into());
    }
    if matches!(kind, 2 | 6 | 8 | 9) {
        return Err("reserved HTTP/2 frame on HTTP/3 stream".into());
    }
    Ok(Some(FrameHeader {
        kind,
        length,
        encoded_len: (*cursor - start) as usize,
    }))
}
pub(in crate::http3) fn fields(file: &File, cursor: &mut u64, length: u64) -> Result<Fields> {
    let length = usize::try_from(length).map_err(fail)?;
    let mut bytes = [0; http3::FIELD_LIMIT];
    let output = bytes
        .get_mut(..length)
        .ok_or("HTTP/3 field section exceeds bounded storage")?;
    file.read_exact_at(output, *cursor).map_err(fail)?;
    *cursor += length as u64;
    http3::decode_fields(output).map_err(fail)
}
pub(in crate::http3) fn unknown(kind: u64) -> Result<()> {
    if matches!(kind, 0 | 1 | 3 | 4 | 5 | 7 | 13) {
        Err("unexpected HTTP/3 frame on response stream".into())
    } else {
        Ok(())
    }
}
