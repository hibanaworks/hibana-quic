//! Application actions for the request-consumer projection.
//! Borrowed receipts retain their storage until explicitly returned through
//! the same projected role. Dropping a receipt never fabricates an acknowledgment.
//! Cancel the whole exchange after abandoning an operation or receipt; an
//! individually cancelled operation may already have committed.
use crate::http3::message::{Error, Exchange, FieldSection, Result, global::*};
use core::cell::Ref;
use hibana::Endpoint;

pub struct Request<'a, 'storage, const ROLE: u8> {
    exchange: &'a Exchange<'storage>,
    content_length: Option<u64>,
    received: u64,
}
impl<'a, 'storage, const ROLE: u8> Request<'a, 'storage, ROLE> {
    pub const fn new(exchange: &'a Exchange<'storage>) -> Self {
        Self {
            exchange,
            content_length: None,
            received: 0,
        }
    }

    pub async fn headers<'q>(
        &'q mut self,
        endpoint: &mut Endpoint<'_, ROLE>,
    ) -> Result<Head<'q, ROLE>> {
        endpoint.recv::<Headers>().await.map_err(Error::from)?;
        let (metadata, length) = self
            .exchange
            .fields
            .borrow_mut()
            .take()
            .ok_or("missing request fields")?;
        self.content_length = metadata.content_length;
        let encoded = Ref::map(self.exchange.headers.borrow(), |bytes| &bytes[..length]);
        Ok(Head { metadata, encoded })
    }

    /// Return one storage loan. Its borrow does not retain the endpoint, so
    /// the application may execute a parallel response action before releasing it.
    pub async fn chunk<'q>(
        &'q mut self,
        endpoint: &mut Endpoint<'_, ROLE>,
    ) -> Result<Option<Chunk<'q, ROLE>>> {
        let offered = endpoint.offer().await.map_err(Error::from)?;
        match offered.label() {
            4 => {
                let length = usize::try_from(offered.recv::<Data>().await.map_err(Error::from)?)?;
                let end = self
                    .received
                    .checked_add(length as u64)
                    .ok_or("request body length overflow")?;
                if self.content_length.is_some_and(|expected| end > expected) {
                    return Err("request body exceeds content-length".into());
                }
                let bytes = self.exchange.bytes.borrow();
                if length > bytes.len() {
                    return Err("request body chunk capacity".into());
                }
                self.received = end;
                Ok(Some(Chunk {
                    bytes: Ref::map(bytes, |bytes| &bytes[..length]),
                }))
            }
            5 => {
                offered.recv::<BodyEnd>().await.map_err(Error::from)?;
                Ok(None)
            }
            _ => Err("unexpected request body continuation".into()),
        }
    }

    /// Consume and validate optional trailers before completing the message.
    /// The visitor runs while the actual trailer storage remains borrowed.
    pub async fn trailers(
        &mut self,
        endpoint: &mut Endpoint<'_, ROLE>,
        visit: impl FnOnce(FieldSection<'_>) -> Result<()>,
    ) -> Result<()> {
        let offered = endpoint.offer().await.map_err(Error::from)?;
        match offered.label() {
            6 => {
                offered.recv::<Trailers>().await.map_err(Error::from)?;
                let (fields, length) = self
                    .exchange
                    .fields
                    .borrow_mut()
                    .take()
                    .ok_or("missing request trailers")?;
                if fields.has_pseudo() || fields.content_length.is_some() {
                    return Err("invalid request trailers".into());
                }
                {
                    let encoded = self.exchange.headers.borrow();
                    crate::http3::message::imp::request::without_te(&encoded[..length])?;
                    visit(FieldSection {
                        metadata: &fields,
                        encoded: &encoded[..length],
                    })?;
                }
                endpoint.send::<Stored>(&()).await.map_err(Error::from)?;
                Ok(())
            }
            7 => {
                offered.recv::<NoTrailers>().await.map_err(Error::from)?;
                Ok(())
            }
            _ => Err("unexpected request trailer continuation".into()),
        }
    }

    /// Complete after trailers have been consumed. End belongs to the reader
    /// only after actual input FIN; this operation does not close the connection.
    pub async fn finish(self, endpoint: &mut Endpoint<'_, ROLE>) -> Result<u64> {
        endpoint.recv::<End>().await.map_err(Error::from)?;
        if self
            .content_length
            .is_some_and(|length| length != self.received)
        {
            return Err("request body differs from content-length".into());
        }
        endpoint.send::<Done>(&()).await.map_err(Error::from)?;
        Ok(self.received)
    }
}

#[must_use = "release this header receipt or cancel the entire exchange"]
pub struct Head<'a, const ROLE: u8> {
    metadata: crate::http3::Fields,
    encoded: Ref<'a, [u8]>,
}
impl<const ROLE: u8> Head<'_, ROLE> {
    pub fn fields(&self) -> FieldSection<'_> {
        FieldSection {
            metadata: &self.metadata,
            encoded: &self.encoded,
        }
    }
    pub async fn release(self, endpoint: &mut Endpoint<'_, ROLE>) -> Result<()> {
        drop(self);
        endpoint.send::<Stored>(&()).await.map_err(Error::from)
    }
}

#[must_use = "release this body receipt or cancel the entire exchange"]
pub struct Chunk<'a, const ROLE: u8> {
    bytes: Ref<'a, [u8]>,
}
impl<const ROLE: u8> Chunk<'_, ROLE> {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub async fn release(self, endpoint: &mut Endpoint<'_, ROLE>) -> Result<()> {
        drop(self);
        endpoint.send::<Stored>(&()).await.map_err(Error::from)
    }
}
