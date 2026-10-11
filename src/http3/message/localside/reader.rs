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
/// consumer first receives its actual request method from the request writer;
/// this receipt makes that sender change an explicit causal handoff.
pub async fn client<const ROLE: u8>(
    endpoint: &mut Endpoint<'_, ROLE>,
    reader: &mut impl BodyReader,
    exchange: &Exchange<'_>,
) -> Result<()> {
    endpoint.recv::<MethodStored>().await.map_err(Error::from)?;
    run(endpoint, reader, exchange).await
}

pub async fn run<const ROLE: u8>(
    endpoint: &mut Endpoint<'_, ROLE>,
    reader: &mut impl BodyReader,
    exchange: &Exchange<'_>,
) -> Result<()> {
    loop {
        let frame = next(reader)
            .await?
            .ok_or("response ended before final headers")?;
        if frame.kind != 1 {
            unknown(frame.kind)?;
            skip(reader, frame.length).await?;
            continue;
        }
        let storage = exchange.headers.take();
        let result = fields(reader, frame.length, storage).await;
        *exchange.headers.borrow_mut() = storage;
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
            break;
        }
    }
    content(endpoint, reader, exchange).await
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
        let storage = exchange.headers.take();
        let result = fields(reader, frame.length, storage).await;
        *exchange.headers.borrow_mut() = storage;
        let (decoded, length) = result?;
        crate::http3::message::imp::request::ordinary(
            &exchange.headers.borrow()[..length],
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
    *exchange.fields.borrow_mut() = Some((decoded, length));
    endpoint.send::<Headers>(&()).await.map_err(Error::from)?;
    endpoint.recv::<Stored>().await.map_err(Error::from)?;
    content(endpoint, reader, exchange).await
}

async fn content<const ROLE: u8>(
    endpoint: &mut Endpoint<'_, ROLE>,
    reader: &mut impl BodyReader,
    exchange: &Exchange<'_>,
) -> Result<()> {
    let trailers = loop {
        let Some(frame) = next(reader).await? else {
            break None;
        };
        if frame.kind == 1 {
            let storage = exchange.headers.take();
            let result = fields(reader, frame.length, storage).await;
            *exchange.headers.borrow_mut() = storage;
            break Some(result?);
        }
        if frame.kind != 0 {
            unknown(frame.kind)?;
            skip(reader, frame.length).await?;
            continue;
        }
        let mut remaining = frame.length;
        while remaining != 0 {
            let count = usize::try_from(remaining.min(exchange.bytes.borrow().len() as u64))
                .map_err(Error::from)?;
            if count == 0 {
                return Err("empty HTTP/3 body storage".into());
            }
            let storage = exchange.bytes.take();
            let result = exact(reader, &mut storage[..count]).await;
            *exchange.bytes.borrow_mut() = storage;
            result?;
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
