//! Encode the writer projection into ordinary HTTP/3 stream bytes.
use crate::http3::message::{Consumer, Error, Exchange, FieldSection, Result};
use core::future::Future;
use hibana::Endpoint;

/// Borrowed output for one HTTP message stream. A successful finish seals the
/// stream's send half; it must not claim transport acknowledgment.
pub trait BodyWriter {
    fn write(&mut self, bytes: &[u8]) -> impl Future<Output = core::result::Result<(), ()>>;
    fn finish(&mut self) -> impl Future<Output = core::result::Result<(), ()>>;
}

struct Encode<'a, W> {
    output: &'a mut W,
    max_field_section_size: u64,
}
impl<W: BodyWriter> Encode<'_, W> {
    async fn fields(&mut self, fields: FieldSection<'_>) -> Result<()> {
        // SETTINGS limits the decoded field list, including each field's
        // 32-byte overhead, not its compressed QPACK representation. Reject
        // before emitting even the HEADERS frame prefix.
        if fields.metadata.field_bytes as u64 > self.max_field_section_size {
            return Err("response exceeds peer field-section limit".into());
        }
        self.frame(1, fields.encoded).await
    }

    async fn frame(&mut self, kind: u64, bytes: &[u8]) -> Result<()> {
        let mut prefix = [0; 16];
        let n = crate::http3::frame_header(kind, bytes.len() as u64, &mut prefix)?;
        self.output
            .write(&prefix[..n])
            .await
            .map_err(|_| Error::Invalid("HTTP/3 output failed"))?;
        self.output
            .write(bytes)
            .await
            .map_err(|_| Error::Invalid("HTTP/3 output failed"))
    }
}
impl<W: BodyWriter> Consumer for Encode<'_, W> {
    async fn information(&mut self, fields: FieldSection<'_>) -> Result<()> {
        self.fields(fields).await
    }
    async fn headers(&mut self, fields: FieldSection<'_>) -> Result<()> {
        self.fields(fields).await
    }
    async fn data(&mut self, _: u64, bytes: &[u8]) -> Result<()> {
        self.frame(0, bytes).await
    }
    async fn trailers(&mut self, fields: FieldSection<'_>) -> Result<()> {
        self.fields(fields).await
    }
    async fn complete(&mut self, _: u64) -> Result<()> {
        self.output
            .finish()
            .await
            .map_err(|_| Error::Invalid("HTTP/3 output finish failed"))
    }
}

/// Drive the actual writer endpoint of a composed response graph.
pub async fn response<const ROLE: u8>(
    endpoint: &mut Endpoint<'_, ROLE>,
    writer: &mut impl BodyWriter,
    request_method: &[u8],
    exchange: &Exchange<'_>,
) -> Result<u64> {
    encode_response(endpoint, writer, request_method, u64::MAX, exchange).await
}

/// Drive the writer of [`super::super::global::server`]. The reader supplies
/// request semantics through the actual endpoint; authenticated admission
/// supplies the peer's immutable SETTINGS limit. Neither fact comes from the
/// application's response producer.
pub async fn server<const ROLE: u8>(
    endpoint: &mut Endpoint<'_, ROLE>,
    writer: &mut impl BodyWriter,
    max_field_section_size: u64,
    exchange: &Exchange<'_>,
) -> Result<u64> {
    let method = endpoint
        .recv::<super::super::global::RequestMethod>()
        .await
        .map_err(Error::from)?;
    let method = request_method(method)?;
    encode_response(endpoint, writer, method, max_field_section_size, exchange).await
}

/// Convert the local method fact for the independent response-consumer API.
/// The empty selector represents an extension method, never a fabricated
/// original method name. All such methods have ordinary response framing.
pub(in crate::http3) fn request_method(method: u8) -> Result<&'static [u8]> {
    use crate::http3::Method;
    // The existing independent response consumer takes method bytes. Only
    // HEAD and CONNECT change its framing semantics; extension methods retain
    // ordinary response semantics without inventing an original method name.
    Ok(match method {
        n if n == Method::Get as u8 => b"GET",
        n if n == Method::Post as u8 => b"POST",
        n if n == Method::Head as u8 => b"HEAD",
        n if n == Method::Connect as u8 => b"CONNECT",
        n if n == Method::Options as u8 => b"OPTIONS",
        n if n == Method::Other as u8 => b"",
        _ => return Err("invalid request-method handoff".into()),
    })
}

/// Encode an independent request fragment with the peer's actual field limit.
pub async fn request<const ROLE: u8>(
    endpoint: &mut Endpoint<'_, ROLE>,
    writer: &mut impl BodyWriter,
    max_field_section_size: u64,
    exchange: &Exchange<'_>,
) -> Result<u64> {
    let mut encode = Encode {
        output: writer,
        max_field_section_size,
    };
    let (_, expected) = request_head(endpoint, &mut encode, exchange).await?;
    endpoint
        .send::<super::super::global::Stored>(&())
        .await
        .map_err(Error::from)?;
    super::consumer::content(endpoint, &mut encode, expected, false, exchange).await
}

/// Drive the request writer of [`super::super::global::client`]. After the
/// actual validated headers have been accepted by output, transfer their method
/// to the response consumer before returning the upload storage receipt.
pub async fn client<const ROLE: u8>(
    endpoint: &mut Endpoint<'_, ROLE>,
    writer: &mut impl BodyWriter,
    max_field_section_size: u64,
    exchange: &Exchange<'_>,
) -> Result<u64> {
    use super::super::global::{RequestMethod, Stored};
    let mut encode = Encode {
        output: writer,
        max_field_section_size,
    };
    let (method, expected) = request_head(endpoint, &mut encode, exchange).await?;
    endpoint
        .send::<RequestMethod>(&method)
        .await
        .map_err(Error::from)?;
    endpoint.send::<Stored>(&()).await.map_err(Error::from)?;
    super::consumer::content(endpoint, &mut encode, expected, false, exchange).await
}

async fn request_head<const ROLE: u8>(
    endpoint: &mut Endpoint<'_, ROLE>,
    encode: &mut Encode<'_, impl BodyWriter>,
    exchange: &Exchange<'_>,
) -> Result<(u8, Option<u64>)> {
    use super::super::global::Headers;
    endpoint.recv::<Headers>().await.map_err(Error::from)?;
    let (fields, length) = exchange
        .fields
        .borrow_mut()
        .take()
        .ok_or("missing request fields")?;
    let method = fields.method.ok_or("request has no method")? as u8;
    let expected = fields.content_length;
    {
        let encoded = exchange.headers.borrow();
        crate::http3::message::imp::request::ordinary(&encoded[..length], &fields)?;
        encode
            .headers(FieldSection {
                metadata: &fields,
                encoded: &encoded[..length],
            })
            .await?;
    }
    Ok((method, expected))
}

async fn encode_response<const ROLE: u8>(
    endpoint: &mut Endpoint<'_, ROLE>,
    writer: &mut impl BodyWriter,
    request_method: &[u8],
    max_field_section_size: u64,
    exchange: &Exchange<'_>,
) -> Result<u64> {
    super::consumer::run(
        endpoint,
        &mut Encode {
            output: writer,
            max_field_section_size,
        },
        request_method,
        exchange,
    )
    .await
}

#[cfg(test)]
#[path = "writer_tests.rs"]
mod tests;
