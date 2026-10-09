//! Random-access reads and bounded frame decoding; no endpoint progression.
use super::super::{Error, Result};
use crate::http3::{self, Fields, FrameHeader};
use crate::io::RandomAccess;
fn varint(file: &impl RandomAccess, cursor: &mut u64, total: u64) -> Result<u64> {
    if *cursor >= total {
        return Err("truncated HTTP/3 integer".into());
    }
    let mut bytes = [0; 8];
    file.read_exact_at(&mut bytes[..1], *cursor)
        .map_err(Error::from)?;
    let len = 1usize << (bytes[0] >> 6);
    if (len as u64) > total - *cursor {
        return Err("truncated HTTP/3 integer".into());
    }
    file.read_exact_at(&mut bytes[..len], *cursor)
        .map_err(Error::from)?;
    *cursor += len as u64;
    Ok(
        crate::quic::imp::kernel::packet::decode_varint(&bytes[..len])
            .map_err(Error::from)?
            .0,
    )
}
pub(in crate::http3) fn next(
    file: &impl RandomAccess,
    cursor: &mut u64,
    total: u64,
) -> Result<Option<FrameHeader>> {
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
pub(in crate::http3) fn fields(
    file: &impl RandomAccess,
    cursor: &mut u64,
    length: u64,
) -> Result<Fields> {
    let length = usize::try_from(length).map_err(Error::from)?;
    let mut bytes = [0; http3::FIELD_LIMIT];
    let output = bytes
        .get_mut(..length)
        .ok_or("HTTP/3 field section exceeds bounded storage")?;
    file.read_exact_at(output, *cursor).map_err(Error::from)?;
    *cursor += length as u64;
    http3::decode_fields(output).map_err(Error::from)
}
pub(in crate::http3) fn unknown(kind: u64) -> Result<()> {
    if matches!(kind, 0 | 1 | 3 | 4 | 5 | 7 | 13) {
        Err("unexpected HTTP/3 frame on response stream".into())
    } else {
        Ok(())
    }
}
