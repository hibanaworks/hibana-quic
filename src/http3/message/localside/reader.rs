//! READER: parse incoming response frames and transfer each owned chunk.
//!
//! Cancelling a localside retires the entire exchange: drop all of its role
//! futures and borrowed receipts. Do not resume peers or reuse the old Exchange;
//! an owned slice may no longer occupy its slot. Caller storage can be reused
//! in a fresh Exchange after the entire cancelled exchange has been dropped.
use crate::http3::message::{
    Error, Exchange, Result,
    global::*,
    imp::{
        input::{exact, fields, next, skip},
        wire::unknown,
    },
};
use crate::quic::application::BodyReader;
use hibana::Endpoint;

/// Drive the response reader of [`super::super::global::client`]. The response
/// reader receives the actual method directly from the writer and relays it
/// to the consumer. Application code cannot replace this parsing authority.
pub async fn client<const ROLE: u8>(
    endpoint: &mut Endpoint<'_, ROLE>,
    reader: &mut impl BodyReader,
    exchange: &Exchange<'_>,
) -> Result<()> {
    let method = endpoint
        .recv::<RequestMethod>()
        .await
        .map_err(Error::from)?;
    endpoint
        .send::<RequestMethod>(&method)
        .await
        .map_err(Error::from)?;
    let method = super::writer::request_method(method)?;
    run(endpoint, reader, exchange, method).await
}

pub async fn run<const ROLE: u8>(
    endpoint: &mut Endpoint<'_, ROLE>,
    reader: &mut impl BodyReader,
    exchange: &Exchange<'_>,
    request_method: &[u8],
) -> Result<()> {
    let (expected, bodyless) = loop {
        let frame = next(reader)
            .await?
            .ok_or("response ended before final headers")?;
        if frame.kind != 1 {
            unknown(frame.kind)?;
            skip(reader, frame.length).await?;
            continue;
        }
        let storage = exchange.headers.take()?;
        let result = fields(reader, frame.length, storage).await;
        exchange.headers.put(storage)?;
        let (decoded, length) = result?;
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
        super::super::imp::request::without_te(
            &exchange
                .headers
                .try_borrow()
                .map_err(|_| Error::Invalid("HTTP storage is loaned"))?[..length],
        )?;
        if (status < 200 || status == 204) && decoded.content_length.is_some()
            || status == 205 && decoded.content_length.is_some_and(|n| n != 0)
        {
            return Err("invalid response content-length".into());
        }
        if request_method == b"CONNECT" && (200..300).contains(&status) {
            return Err("successful CONNECT requires a tunnel consumer".into());
        }
        let expected = decoded.content_length;
        let bodyless = request_method == b"HEAD" || matches!(status, 204 | 205 | 304);
        *exchange.fields.borrow_mut() = Some((decoded, length));
        if status < 200 {
            endpoint
                .send::<Information>(&())
                .await
                .map_err(Error::from)?;
            endpoint.recv::<Stored>().await.map_err(Error::from)?;
        } else {
            endpoint.send::<Headers>(&()).await.map_err(Error::from)?;
            endpoint.recv::<Stored>().await.map_err(Error::from)?;
            break (expected, bodyless);
        }
    };
    content(endpoint, reader, exchange, expected, bodyless).await
}

/// Receive an ordinary HTTPS request with caller-selected reader role.
/// CONNECT tunnel semantics are outside this message consumer.
pub async fn request<const ROLE: u8>(
    endpoint: &mut Endpoint<'_, ROLE>,
    reader: &mut impl BodyReader,
    exchange: &Exchange<'_>,
) -> Result<()> {
    let (decoded, length) = request_head(reader, exchange).await?;
    publish_request(endpoint, reader, exchange, decoded, length).await
}

/// Drive the reader of [`super::super::global::server`]. The parsed method is
/// transferred to the writer before the application can take the header fields.
pub async fn server<const ROLE: u8>(
    endpoint: &mut Endpoint<'_, ROLE>,
    reader: &mut impl BodyReader,
    exchange: &Exchange<'_>,
) -> Result<()> {
    let (decoded, length) = request_head(reader, exchange).await?;
    let method = decoded.method.ok_or("request has no method")? as u8;
    endpoint
        .send::<RequestMethod>(&method)
        .await
        .map_err(Error::from)?;
    publish_request(endpoint, reader, exchange, decoded, length).await
}

async fn request_head(
    reader: &mut impl BodyReader,
    exchange: &Exchange<'_>,
) -> Result<(crate::http3::Fields, usize)> {
    loop {
        let frame = next(reader).await?.ok_or("request ended before headers")?;
        if frame.kind != 1 {
            unknown(frame.kind)?;
            skip(reader, frame.length).await?;
            continue;
        }
        let storage = exchange.headers.take()?;
        let result = fields(reader, frame.length, storage).await;
        exchange.headers.put(storage)?;
        let (decoded, length) = result?;
        crate::http3::message::imp::request::ordinary(
            &exchange
                .headers
                .try_borrow()
                .map_err(|_| Error::Invalid("HTTP storage is loaned"))?[..length],
            &decoded,
        )?;
        return Ok((decoded, length));
    }
}

async fn publish_request<const ROLE: u8>(
    endpoint: &mut Endpoint<'_, ROLE>,
    reader: &mut impl BodyReader,
    exchange: &Exchange<'_>,
    decoded: crate::http3::Fields,
    length: usize,
) -> Result<()> {
    let expected = decoded.content_length;
    *exchange.fields.borrow_mut() = Some((decoded, length));
    endpoint.send::<Headers>(&()).await.map_err(Error::from)?;
    endpoint.recv::<Stored>().await.map_err(Error::from)?;
    content(endpoint, reader, exchange, expected, false).await
}

async fn content<const ROLE: u8>(
    endpoint: &mut Endpoint<'_, ROLE>,
    reader: &mut impl BodyReader,
    exchange: &Exchange<'_>,
    expected: Option<u64>,
    bodyless: bool,
) -> Result<()> {
    let mut received = 0u64;
    let trailers = loop {
        let Some(frame) = next(reader).await? else {
            break None;
        };
        if frame.kind == 1 {
            let storage = exchange.headers.take()?;
            let result = fields(reader, frame.length, storage).await;
            exchange.headers.put(storage)?;
            break Some(result?);
        }
        if frame.kind != 0 {
            unknown(frame.kind)?;
            skip(reader, frame.length).await?;
            continue;
        }
        if bodyless {
            return Err("body on a bodyless response".into());
        }
        received = received
            .checked_add(frame.length)
            .ok_or("HTTP body length overflow")?;
        if expected.is_some_and(|length| received > length) {
            return Err("HTTP body exceeds content-length".into());
        }
        let mut remaining = frame.length;
        while remaining != 0 {
            let count = usize::try_from(
                remaining.min(
                    exchange
                        .bytes
                        .try_borrow()
                        .map_err(|_| Error::Invalid("HTTP storage is loaned"))?
                        .len() as u64,
                ),
            )
            .map_err(Error::from)?;
            if count == 0 {
                return Err("empty HTTP/3 body storage".into());
            }
            let storage = exchange.bytes.take()?;
            let result = exact(reader, &mut storage[..count]).await;
            exchange.bytes.put(storage)?;
            result?;
            remaining -= count as u64;
            endpoint
                .send::<Data>(&(count as u64))
                .await
                .map_err(Error::from)?;
            endpoint.recv::<Stored>().await.map_err(Error::from)?;
        }
    };
    if !bodyless && expected.is_some_and(|length| received != length) {
        return Err("HTTP body differs from content-length".into());
    }
    endpoint.send::<BodyEnd>(&()).await.map_err(Error::from)?;
    if let Some(trailers) = trailers {
        if trailers.0.has_pseudo() || trailers.0.content_length.is_some() {
            return Err("invalid HTTP trailers".into());
        }
        super::super::imp::request::without_te(
            &exchange
                .headers
                .try_borrow()
                .map_err(|_| Error::Invalid("HTTP storage is loaned"))?[..trailers.1],
        )?;
        *exchange.fields.borrow_mut() = Some(trailers);
        endpoint.send::<Trailers>(&()).await.map_err(Error::from)?;
        endpoint.recv::<Stored>().await.map_err(Error::from)?;
        while let Some(frame) = next(reader).await? {
            unknown(frame.kind)?;
            skip(reader, frame.length).await?;
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
