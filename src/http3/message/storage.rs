//! Storage-only HTTP fields and body loans for direct endpoint localsides.
//!
//! None of these operations advances a choreography. The caller sends or receives
//! `Headers`, `Data`, `Stored`, and the other messages on its actual endpoint.
//! Release every borrowed view before sending the corresponding `Stored` receipt.
//! Storage receipts acknowledge local reuse, never network delivery. Abandoning
//! an exchange after an endpoint action requires cancelling the whole exchange.
use super::imp::buffer::Slot;
use super::{Error, Exchange, FieldSection, Result};

/// A field-section loan. Dropping it releases storage, not a protocol receipt.
pub struct Fields<'a, 'storage> {
    metadata: crate::http3::Fields,
    encoded: &'storage mut [u8],
    length: usize,
    slot: &'a Slot<'storage>,
}
impl Fields<'_, '_> {
    pub fn section(&self) -> FieldSection<'_> {
        FieldSection {
            metadata: &self.metadata,
            encoded: &self.encoded[..self.length],
        }
    }
}
impl Drop for Fields<'_, '_> {
    fn drop(&mut self) {
        self.slot
            .put(core::mem::take(&mut self.encoded))
            .expect("unique HTTP field loan");
    }
}

/// An owned storage loan, safe to retain across another endpoint's await.
/// Dropping it returns the slice; the application still sends `Stored` itself.
pub struct Body<'a, 'storage> {
    bytes: &'storage mut [u8],
    length: usize,
    slot: &'a Slot<'storage>,
}
impl Body<'_, '_> {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}
impl Drop for Body<'_, '_> {
    fn drop(&mut self) {
        self.slot
            .put(core::mem::take(&mut self.bytes))
            .expect("unique HTTP body loan");
    }
}

impl<'storage> Exchange<'storage> {
    /// Borrow the field section after the matching endpoint receive succeeds.
    pub fn fields(&self) -> Result<Fields<'_, 'storage>> {
        let encoded = self
            .headers
            .try_borrow()
            .map_err(|_| Error::Invalid("HTTP header storage is borrowed"))?;
        let (metadata, length) = self
            .fields
            .try_borrow_mut()
            .map_err(|_| Error::Invalid("HTTP field storage is borrowed"))?
            .take()
            .ok_or("missing HTTP fields")?;
        if length > encoded.len() {
            return Err("HTTP field storage length".into());
        }
        drop(encoded);
        Ok(Fields {
            metadata,
            encoded: self.headers.take()?,
            length,
            slot: &self.headers,
        })
    }

    /// Borrow the bytes named by a received `Data` length, without copying.
    pub fn body(&self, length: u64) -> Result<Body<'_, 'storage>> {
        let length = usize::try_from(length)?;
        let bytes = self
            .bytes
            .try_borrow()
            .map_err(|_| Error::Invalid("HTTP body storage is borrowed"))?;
        if length > bytes.len() {
            return Err("HTTP body storage length".into());
        }
        drop(bytes);
        Ok(Body {
            bytes: self.bytes.take()?,
            length,
            slot: &self.bytes,
        })
    }

    /// Copy one bounded chunk into the outgoing slot. Send its returned length
    /// as `Data`, then receive `Stored` before preparing another chunk.
    pub fn write(&self, bytes: &[u8]) -> Result<u64> {
        let mut storage = self
            .bytes
            .try_borrow_mut()
            .map_err(|_| Error::Invalid("HTTP body storage is borrowed"))?;
        let count = storage.len().min(bytes.len());
        if count == 0 && !bytes.is_empty() {
            return Err("empty HTTP body storage".into());
        }
        storage[..count].copy_from_slice(&bytes[..count]);
        Ok(count as u64)
    }

    /// Prepare ordinary request fields before sending `Headers`.
    pub fn request(
        &self,
        method: &[u8],
        authority: &[u8],
        path: &[u8],
        fields: &[(&[u8], &[u8])],
    ) -> Result<()> {
        if fields.iter().any(|(name, _)| name.starts_with(b":")) {
            return Err("request fields contain an additional pseudo-header".into());
        }
        let pseudo = [
            (b":method".as_slice(), method),
            (b":scheme".as_slice(), b"https".as_slice()),
            (b":authority".as_slice(), authority),
            (b":path".as_slice(), path),
        ];
        self.store_fields(
            pseudo.into_iter().chain(fields.iter().copied()),
            super::imp::request::ordinary,
        )
    }

    /// Prepare informational or final response fields. Send `Information` for
    /// 1xx and `Headers` for the final response; the writer validates the match.
    pub fn response(&self, status: u16, fields: &[(&[u8], &[u8])]) -> Result<()> {
        if !(100..=599).contains(&status)
            || status == 101
            || fields.iter().any(|(name, _)| name.starts_with(b":"))
        {
            return Err("invalid response fields".into());
        }
        let digits = [
            b'0' + (status / 100) as u8,
            b'0' + (status / 10 % 10) as u8,
            b'0' + (status % 10) as u8,
        ];
        self.store_fields(
            core::iter::once((b":status".as_slice(), digits.as_slice()))
                .chain(fields.iter().copied()),
            |encoded, _| super::imp::request::without_te(encoded),
        )
    }

    /// Prepare trailing fields before sending `Trailers`.
    pub fn trailers(&self, fields: &[(&[u8], &[u8])]) -> Result<()> {
        self.store_fields(fields.iter().copied(), |encoded, metadata| {
            if metadata.has_pseudo() || metadata.content_length.is_some() {
                return Err("invalid HTTP trailers".into());
            }
            super::imp::request::without_te(encoded)
        })
    }

    fn store_fields<'a>(
        &self,
        fields: impl Iterator<Item = (&'a [u8], &'a [u8])>,
        validate: impl FnOnce(&[u8], &crate::http3::Fields) -> Result<()>,
    ) -> Result<()> {
        let mut headers = self
            .headers
            .try_borrow_mut()
            .map_err(|_| Error::Invalid("HTTP header storage is borrowed"))?;
        let mut slot = self
            .fields
            .try_borrow_mut()
            .map_err(|_| Error::Invalid("HTTP field storage is borrowed"))?;
        if slot.is_some() {
            return Err("HTTP fields have not been consumed".into());
        }
        let length = crate::http3::encode_fields(fields, &mut headers)?;
        let metadata = crate::http3::decode_fields(&headers[..length])?;
        validate(&headers[..length], &metadata)?;
        *slot = Some((metadata, length));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn storage_operations_borrow_and_copy_only_once() {
        let (mut bytes, mut headers) = ([0; 3], [0; 256]);
        let address = bytes.as_ptr();
        let exchange = Exchange::new(&mut bytes, &mut headers);
        assert_eq!(exchange.write(b"hello").unwrap(), 3);
        let body = exchange.body(3).unwrap();
        assert_eq!(body.bytes(), b"hel");
        assert_eq!(body.bytes().as_ptr(), address);
        assert!(exchange.write(b"x").is_err());
        assert!(exchange.body(0).is_err());
        assert!(exchange.body(1).is_err());
        drop(body);
        let empty = exchange.body(0).unwrap();
        assert!(exchange.body(0).is_err());
        drop(empty);
        assert_eq!(exchange.body(3).unwrap().bytes().as_ptr(), address);
        exchange
            .request(b"GET", b"localhost", b"/hello", &[])
            .unwrap();
        assert!(exchange.response(200, &[]).is_err());
        let fields = exchange.fields().unwrap();
        assert_eq!(
            &fields.section().metadata.path[..fields.section().metadata.path_len],
            b"/hello"
        );
        assert!(exchange.response(200, &[]).is_err());
        drop(fields);
        exchange
            .response(103, &[(b"link", b"</style.css>")])
            .unwrap();
        assert_eq!(
            exchange.fields().unwrap().section().metadata.status,
            Some(103)
        );
        assert!(exchange.trailers(&[(b"content-length", b"3")]).is_err());
        exchange.trailers(&[(b"x-checksum", b"ok")]).unwrap();
        assert!(!exchange.fields().unwrap().section().metadata.has_pseudo());
    }
}

#[cfg(test)]
mod ownership_tests {
    use super::*;
    use core::{
        future::Future,
        pin::pin,
        task::{Context, Waker},
    };
    #[test]
    fn zero_capacity_resource_is_distinct_from_an_outstanding_loan() {
        let (mut body, mut headers) = ([], [0; 64]);
        let exchange = Exchange::new(&mut body, &mut headers);
        let first = exchange.body(0).unwrap();
        assert!(exchange.body(0).is_err());
        drop(first);
        let second = exchange.body(0).unwrap();
        assert!(second.bytes().is_empty());
        drop(second);
        assert!(exchange.bytes.try_borrow().is_ok());
    }
    #[test]
    fn cancelling_an_owned_loan_restores_the_original_slice_without_allocation() {
        let (mut body, mut headers) = ([0; 4], [0; 64]);
        let pointer = body.as_ptr();
        let exchange = Exchange::new(&mut body, &mut headers);
        exchange.write(b"data").unwrap();
        let guard = actor_test_allocator::NoAlloc::start();
        {
            let pending = async {
                let loan = exchange.body(4).unwrap();
                assert_eq!(loan.bytes().as_ptr(), pointer);
                core::future::pending::<()>().await;
                drop(loan);
            };
            let mut pending = pin!(pending);
            let mut cx = Context::from_waker(Waker::noop());
            assert!(pending.as_mut().poll(&mut cx).is_pending());
            assert!(exchange.body(0).is_err());
            assert!(exchange.write(b"x").is_err());
        }
        assert_eq!(exchange.body(4).unwrap().bytes().as_ptr(), pointer);
        guard.finish();
    }
}
