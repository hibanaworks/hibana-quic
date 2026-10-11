//! The application's response-producing projection.
//! Every operation advances the supplied endpoint and waits for the writer's
//! actual storage receipt. There is no second message-phase state.
//! Cancellation retires the entire exchange; an individually cancelled action
//! may already have committed and must not be retried.
use crate::http3::message::{Error, Exchange, Result, global::*};
use hibana::Endpoint;

pub struct Response<'a, 'storage, const ROLE: u8> {
    exchange: &'a Exchange<'storage>,
}
impl<'a, 'storage, const ROLE: u8> Response<'a, 'storage, ROLE> {
    pub const fn new(exchange: &'a Exchange<'storage>) -> Self {
        Self { exchange }
    }

    /// Produce final response headers. Field values are encoded into caller
    /// storage, retained until the writer returns its projected receipt.
    pub async fn headers(
        &mut self,
        endpoint: &mut Endpoint<'_, ROLE>,
        status: u16,
        fields: &[(&[u8], &[u8])],
    ) -> Result<()> {
        if !(200..=599).contains(&status) || fields.iter().any(|(n, _)| n.starts_with(b":")) {
            return Err("invalid final response fields".into());
        }
        let status = [
            b'0' + (status / 100) as u8,
            b'0' + (status / 10 % 10) as u8,
            b'0' + (status % 10) as u8,
        ];
        {
            let mut storage = self
                .exchange
                .headers
                .try_borrow_mut()
                .map_err(|_| Error::Invalid("response header storage is borrowed"))?;
            let n = crate::http3::encode_fields(
                core::iter::once((b":status".as_slice(), status.as_slice()))
                    .chain(fields.iter().copied()),
                &mut storage,
            )?;
            let decoded = crate::http3::decode_fields(&storage[..n])?;
            *self
                .exchange
                .fields
                .try_borrow_mut()
                .map_err(|_| Error::Invalid("response field storage is borrowed"))? =
                Some((decoded, n));
        }
        endpoint.send::<Headers>(&()).await.map_err(Error::from)?;
        endpoint.recv::<Stored>().await.map_err(Error::from)?;
        Ok(())
    }

    /// Stream bytes through bounded caller storage. No whole-body allocation
    /// or size limit is introduced. Each slice is copied once into this exchange;
    /// the writer borrows it until its storage receipt is returned.
    pub async fn write(
        &mut self,
        endpoint: &mut Endpoint<'_, ROLE>,
        mut bytes: &[u8],
    ) -> Result<()> {
        while !bytes.is_empty() {
            let count = bytes.len().min(
                self.exchange
                    .bytes
                    .try_borrow()
                    .map_err(|_| Error::Invalid("response body storage is borrowed"))?
                    .len(),
            );
            if count == 0 {
                return Err("empty response body storage".into());
            }
            self.exchange
                .bytes
                .try_borrow_mut()
                .map_err(|_| Error::Invalid("response body storage is borrowed"))?[..count]
                .copy_from_slice(&bytes[..count]);
            endpoint
                .send::<Data>(&(count as u64))
                .await
                .map_err(Error::from)?;
            endpoint.recv::<Stored>().await.map_err(Error::from)?;
            bytes = &bytes[count..];
        }
        Ok(())
    }

    /// Seal this response without trailers. Done is the local writer's receipt,
    /// not a QUIC peer acknowledgment or a connection-close receipt.
    pub async fn finish(self, endpoint: &mut Endpoint<'_, ROLE>) -> Result<()> {
        endpoint.send::<BodyEnd>(&()).await.map_err(Error::from)?;
        endpoint
            .send::<NoTrailers>(&())
            .await
            .map_err(Error::from)?;
        endpoint.send::<End>(&()).await.map_err(Error::from)?;
        endpoint.recv::<Done>().await.map_err(Error::from)?;
        Ok(())
    }
}
