//! Direct reader/writer locals. Each stored chunk precedes the next read.
use super::{Result, global::*, wire::*};
use hibana::Endpoint;
use hibana_quic::http3::Fields;
use std::{cell::RefCell, fs::File, os::unix::fs::FileExt};
pub(super) struct Exchange {
    pub(super) fields: RefCell<Option<Fields>>,
    pub(super) bytes: RefCell<[u8; 4096]>,
}
pub(super) async fn read(
    endpoint: &mut Endpoint<'_, READER>,
    file: &File,
    total: u64,
    exchange: &Exchange,
) -> Result<()> {
    let mut cursor = 0;
    loop {
        let frame = next(file, &mut cursor, total)?.ok_or("response ended before final headers")?;
        if frame.kind != 1 {
            unknown(frame.kind)?;
            cursor += frame.length;
            continue;
        }
        let decoded = fields(file, &mut cursor, frame.length)?;
        let status = decoded.status.ok_or("response has no status")?;
        if decoded.method_get.is_some()
            || decoded.https.is_some()
            || decoded.path_len != 0
            || decoded.authority_len != 0
            || !(100..=599).contains(&status)
            || status == 101
        {
            return Err("invalid response pseudo-header".into());
        }
        *exchange.fields.borrow_mut() = Some(decoded);
        if status < 200 {
            endpoint.send::<Information>(&()).await.map_err(fail)?;
            endpoint.recv::<Stored>().await.map_err(fail)?;
        } else {
            endpoint.send::<Headers>(&()).await.map_err(fail)?;
            endpoint.recv::<Stored>().await.map_err(fail)?;
            break;
        }
    }
    let trailers = loop {
        let Some(frame) = next(file, &mut cursor, total)? else {
            break None;
        };
        if frame.kind == 1 {
            break Some(fields(file, &mut cursor, frame.length)?);
        }
        if frame.kind != 0 {
            unknown(frame.kind)?;
            cursor += frame.length;
            continue;
        }
        let mut remaining = frame.length;
        while remaining != 0 {
            let count = usize::try_from(remaining.min(4096)).map_err(fail)?;
            file.read_exact_at(&mut exchange.bytes.borrow_mut()[..count], cursor)
                .map_err(fail)?;
            cursor += count as u64;
            remaining -= count as u64;
            endpoint.send::<Data>(&(count as u64)).await.map_err(fail)?;
            endpoint.recv::<Stored>().await.map_err(fail)?;
        }
    };
    endpoint.send::<BodyEnd>(&()).await.map_err(fail)?;
    if let Some(trailers) = trailers {
        *exchange.fields.borrow_mut() = Some(trailers);
        endpoint.send::<Trailers>(&()).await.map_err(fail)?;
        endpoint.recv::<Stored>().await.map_err(fail)?;
        while let Some(frame) = next(file, &mut cursor, total)? {
            unknown(frame.kind)?;
            cursor += frame.length;
        }
    } else {
        endpoint.send::<NoTrailers>(&()).await.map_err(fail)?;
    }
    endpoint.send::<End>(&()).await.map_err(fail)?;
    endpoint.recv::<Done>().await.map_err(fail)?;
    Ok(())
}
pub(super) async fn write(
    endpoint: &mut Endpoint<'_, WRITER>,
    file: &File,
    exchange: &Exchange,
    written: &RefCell<u64>,
) -> Result<()> {
    let expected = loop {
        let offered = endpoint.offer().await.map_err(fail)?;
        match offered.label() {
            1 => {
                offered.recv::<Information>().await.map_err(fail)?;
                let fields = exchange
                    .fields
                    .borrow_mut()
                    .take()
                    .ok_or("missing informational fields")?;
                if fields.content_length.is_some() {
                    return Err("informational content-length".into());
                }
                endpoint.send::<Stored>(&()).await.map_err(fail)?;
            }
            2 => {
                offered.recv::<Headers>().await.map_err(fail)?;
                let fields = exchange
                    .fields
                    .borrow_mut()
                    .take()
                    .ok_or("missing response fields")?;
                if fields.status != Some(200) {
                    return Err("download response was not 200".into());
                }
                endpoint.send::<Stored>(&()).await.map_err(fail)?;
                break fields.content_length;
            }
            _ => return Err("unexpected response header continuation".into()),
        }
    };
    let mut offset = 0u64;
    loop {
        let offered = endpoint.offer().await.map_err(fail)?;
        match offered.label() {
            4 => {
                let count =
                    usize::try_from(offered.recv::<Data>().await.map_err(fail)?).map_err(fail)?;
                {
                    let bytes = exchange.bytes.borrow();
                    file.write_all_at(bytes.get(..count).ok_or("body chunk capacity")?, offset)
                        .map_err(fail)?;
                }
                offset = offset
                    .checked_add(count as u64)
                    .ok_or("body length overflow")?;
                if expected.is_some_and(|length| offset > length) {
                    return Err("body exceeds content-length".into());
                }
                endpoint.send::<Stored>(&()).await.map_err(fail)?;
            }
            5 => {
                offered.recv::<BodyEnd>().await.map_err(fail)?;
                break;
            }
            _ => return Err("unexpected response body continuation".into()),
        }
    }
    let offered = endpoint.offer().await.map_err(fail)?;
    match offered.label() {
        6 => {
            offered.recv::<Trailers>().await.map_err(fail)?;
            let fields = exchange
                .fields
                .borrow_mut()
                .take()
                .ok_or("missing trailers")?;
            if fields.has_pseudo() || fields.content_length.is_some() {
                return Err("invalid response trailers".into());
            }
            endpoint.send::<Stored>(&()).await.map_err(fail)?;
        }
        7 => {
            offered.recv::<NoTrailers>().await.map_err(fail)?;
        }
        _ => return Err("unexpected response trailer continuation".into()),
    }
    endpoint.recv::<End>().await.map_err(fail)?;
    if expected.is_some_and(|length| length != offset) {
        return Err("body differs from content-length".into());
    }
    file.set_len(offset).map_err(fail)?;
    *written.borrow_mut() = offset;
    endpoint.send::<Done>(&()).await.map_err(fail)?;
    Ok(())
}
