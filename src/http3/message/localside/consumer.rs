//! CONSUMER: consume headers, body chunks and trailers before acknowledging completion.
//!
//! Cancelling a localside retires the entire exchange: drop all of its role
//! futures and borrowed receipts. Do not resume peers or reuse the old Exchange;
//! an owned slice may no longer occupy its slot. Caller storage can be reused
//! in a fresh Exchange after the entire cancelled exchange has been dropped.
use crate::http3::message::{Error, Exchange, Result, global::*};
use hibana::Endpoint;
pub async fn run<const ROLE: u8>(
    endpoint: &mut Endpoint<'_, ROLE>,
    consumer: &mut impl Consumer,
    request_method: &[u8],
    exchange: &Exchange<'_>,
) -> Result<u64> {
    let (expected, bodyless) = loop {
        let offered = endpoint.offer().await.map_err(Error::from)?;
        match offered.label() {
            1 => {
                offered.recv::<Information>().await.map_err(Error::from)?;
                let (fields, length) = exchange
                    .fields
                    .borrow_mut()
                    .take()
                    .ok_or("missing informational fields")?;
                if fields.content_length.is_some() {
                    return Err("informational content-length".into());
                }
                {
                    crate::http3::message::imp::request::without_te(
                        &exchange.headers.borrow()[..length],
                    )?;
                    let encoded = exchange.headers.take();
                    let result = consumer
                        .information(FieldSection {
                            metadata: &fields,
                            encoded: &encoded[..length],
                        })
                        .await;
                    *exchange.headers.borrow_mut() = encoded;
                    result?;
                }
                endpoint.send::<Stored>(&()).await.map_err(Error::from)?;
            }
            2 => {
                offered.recv::<Headers>().await.map_err(Error::from)?;
                let (fields, length) = exchange
                    .fields
                    .borrow_mut()
                    .take()
                    .ok_or("missing response fields")?;
                let status = fields.status.ok_or("missing final response status")?;
                if (status == 204 && fields.content_length.is_some())
                    || (status == 205 && fields.content_length.is_some_and(|n| n != 0))
                {
                    return Err("invalid content-length on a bodyless response".into());
                }
                if request_method == b"CONNECT" && (200..300).contains(&status) {
                    return Err("successful CONNECT requires a tunnel consumer".into());
                }
                {
                    crate::http3::message::imp::request::without_te(
                        &exchange.headers.borrow()[..length],
                    )?;
                    let encoded = exchange.headers.take();
                    let result = consumer
                        .headers(FieldSection {
                            metadata: &fields,
                            encoded: &encoded[..length],
                        })
                        .await;
                    *exchange.headers.borrow_mut() = encoded;
                    result?;
                }
                endpoint.send::<Stored>(&()).await.map_err(Error::from)?;
                break (
                    fields.content_length,
                    request_method == b"HEAD" || matches!(status, 204 | 205 | 304),
                );
            }
            _ => return Err("unexpected response header continuation".into()),
        }
    };
    content(endpoint, consumer, expected, bodyless, exchange).await
}

/// Consume the request fragment on the application's projected role.
/// Original method and field bytes remain available through FieldSection.
pub async fn request<const ROLE: u8>(
    endpoint: &mut Endpoint<'_, ROLE>,
    consumer: &mut impl Consumer,
    exchange: &Exchange<'_>,
) -> Result<u64> {
    endpoint.recv::<Headers>().await.map_err(Error::from)?;
    let (fields, length) = exchange
        .fields
        .borrow_mut()
        .take()
        .ok_or("missing request fields")?;
    let expected = fields.content_length;
    {
        let encoded = exchange.headers.take();
        let result = consumer
            .headers(FieldSection {
                metadata: &fields,
                encoded: &encoded[..length],
            })
            .await;
        *exchange.headers.borrow_mut() = encoded;
        result?;
    }
    endpoint.send::<Stored>(&()).await.map_err(Error::from)?;
    content(endpoint, consumer, expected, false, exchange).await
}

pub(in crate::http3) async fn content<const ROLE: u8>(
    endpoint: &mut Endpoint<'_, ROLE>,
    consumer: &mut impl Consumer,
    expected: Option<u64>,
    bodyless: bool,
    exchange: &Exchange<'_>,
) -> Result<u64> {
    let mut offset = 0u64;
    loop {
        let offered = endpoint.offer().await.map_err(Error::from)?;
        match offered.label() {
            4 => {
                let count = usize::try_from(offered.recv::<Data>().await.map_err(Error::from)?)
                    .map_err(Error::from)?;
                if bodyless {
                    return Err("body on a bodyless response".into());
                }
                let end = offset
                    .checked_add(count as u64)
                    .ok_or("body length overflow")?;
                if expected.is_some_and(|length| end > length) {
                    return Err("body exceeds content-length".into());
                }
                {
                    let bytes = exchange.bytes.take();
                    let result = match bytes.get(..count) {
                        Some(chunk) => consumer.data(offset, chunk).await,
                        None => Err("body chunk capacity".into()),
                    };
                    *exchange.bytes.borrow_mut() = bytes;
                    result?;
                }
                offset = end;
                endpoint.send::<Stored>(&()).await.map_err(Error::from)?;
            }
            5 => {
                offered.recv::<BodyEnd>().await.map_err(Error::from)?;
                break;
            }
            _ => return Err("unexpected response body continuation".into()),
        }
    }
    let offered = endpoint.offer().await.map_err(Error::from)?;
    match offered.label() {
        6 => {
            offered.recv::<Trailers>().await.map_err(Error::from)?;
            let (fields, length) = exchange
                .fields
                .borrow_mut()
                .take()
                .ok_or("missing trailers")?;
            if fields.has_pseudo() || fields.content_length.is_some() {
                return Err("invalid response trailers".into());
            }
            {
                crate::http3::message::imp::request::without_te(
                    &exchange.headers.borrow()[..length],
                )?;
                let encoded = exchange.headers.take();
                let result = consumer
                    .trailers(FieldSection {
                        metadata: &fields,
                        encoded: &encoded[..length],
                    })
                    .await;
                *exchange.headers.borrow_mut() = encoded;
                result?;
            }
            endpoint.send::<Stored>(&()).await.map_err(Error::from)?;
        }
        7 => {
            offered.recv::<NoTrailers>().await.map_err(Error::from)?;
        }
        _ => return Err("unexpected response trailer continuation".into()),
    }
    endpoint.recv::<End>().await.map_err(Error::from)?;
    if !bodyless && expected.is_some_and(|length| length != offset) {
        return Err("body differs from content-length".into());
    }
    consumer.complete(offset).await?;
    endpoint.send::<Done>(&()).await.map_err(Error::from)?;
    Ok(offset)
}

use core::future::Future;

/// A validated field section borrowed until its consumer returns.
/// Ordinary fields, duplicate values and original method bytes remain available.
pub struct FieldSection<'a> {
    pub metadata: &'a crate::http3::Fields,
    pub(crate) encoded: &'a [u8],
}
impl FieldSection<'_> {
    pub fn for_each(
        &self,
        visit: impl FnMut(&[u8], &[u8]) -> core::result::Result<(), crate::http3::Error>,
    ) -> Result<()> {
        crate::http3::decode_fields_with(self.encoded, visit)?;
        Ok(())
    }
}
/// The localside invokes these effects in the order defined by `global`.
/// Returning from a borrowed field/body effect returns that storage to the reader.
pub trait Consumer {
    fn information(&mut self, _fields: FieldSection<'_>) -> impl Future<Output = Result<()>> {
        async { Ok(()) }
    }
    fn headers(&mut self, fields: FieldSection<'_>) -> impl Future<Output = Result<()>>;
    fn data(&mut self, offset: u64, bytes: &[u8]) -> impl Future<Output = Result<()>>;
    fn trailers(&mut self, _fields: FieldSection<'_>) -> impl Future<Output = Result<()>> {
        async { Ok(()) }
    }
    fn complete(&mut self, length: u64) -> impl Future<Output = Result<()>>;
}
