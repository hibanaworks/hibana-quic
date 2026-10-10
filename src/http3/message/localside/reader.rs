//! READER: parse incoming response frames and transfer each owned chunk.
use crate::http3::message::{Error, Exchange, Result, global::*, imp::wire::*};
use crate::io::RandomAccess;
use hibana::Endpoint;
pub async fn run(
    endpoint: &mut Endpoint<'_, READER>,
    file: &impl RandomAccess,
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
        if decoded.method.is_some()
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
            endpoint
                .send::<Information>(&())
                .await
                .map_err(Error::from)?;
            endpoint.recv::<Stored>().await.map_err(Error::from)?;
        } else {
            endpoint.send::<Headers>(&()).await.map_err(Error::from)?;
            endpoint.recv::<Stored>().await.map_err(Error::from)?;
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
            let count = usize::try_from(remaining.min(4096)).map_err(Error::from)?;
            file.read_exact_at(&mut exchange.bytes.borrow_mut()[..count], cursor)
                .map_err(Error::from)?;
            cursor += count as u64;
            remaining -= count as u64;
            endpoint
                .send::<Data>(&(count as u64))
                .await
                .map_err(Error::from)?;
            endpoint.recv::<Stored>().await.map_err(Error::from)?;
        }
    };
    endpoint.send::<BodyEnd>(&()).await.map_err(Error::from)?;
    if let Some(trailers) = trailers {
        *exchange.fields.borrow_mut() = Some(trailers);
        endpoint.send::<Trailers>(&()).await.map_err(Error::from)?;
        endpoint.recv::<Stored>().await.map_err(Error::from)?;
        while let Some(frame) = next(file, &mut cursor, total)? {
            unknown(frame.kind)?;
            cursor += frame.length;
        }
    } else {
        endpoint
            .send::<NoTrailers>(&())
            .await
            .map_err(Error::from)?;
    }
    endpoint.send::<End>(&()).await.map_err(Error::from)?;
    endpoint.recv::<Done>().await.map_err(Error::from)?;
    Ok(())
}
