//! Direct TLS transcript roles for `protocol`.
//!
//! The numerical operations never dispatch on a handwritten TLS phase. The
//! owner's async continuation and the projected endpoints determine order.
//! The QUIC connection and its transcript tests embed these roles directly.
use super::{BoundedTls, Failure, Mode, protocol as p};
use crate::tls::Level;
use core::{
    cell::{Cell, RefCell},
    future::Future,
};
use hibana::{Endpoint, EndpointError};

#[derive(Debug)]
pub enum Error {
    Endpoint(EndpointError),
    Crypto(Failure),
    Binding,
    Capacity,
    Input(crate::tls::Error),
}
impl From<EndpointError> for Error {
    fn from(e: EndpointError) -> Self {
        Self::Endpoint(e)
    }
}
impl From<Failure> for Error {
    fn from(e: Failure) -> Self {
        Self::Crypto(e)
    }
}
fn check(actual: u64, expected: u64) -> Result<(), Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(Error::Binding)
    }
}
/// Caller-owned space for one complete TLS handshake message. No allocation,
/// clone of secret-bearing buffers, or arbitrary message queue is introduced.
pub struct MessageSlot<'a> {
    bytes: RefCell<Option<&'a mut [u8]>>,
    len: Cell<usize>,
}
impl<'a> MessageSlot<'a> {
    pub fn new(bytes: &'a mut [u8]) -> Self {
        Self {
            bytes: RefCell::new(Some(bytes)),
            len: Cell::new(0),
        }
    }
    fn apply<T>(&self, f: impl FnOnce(&[u8]) -> Result<T, Failure>) -> Result<T, Error> {
        let n = self.len.get();
        if n == 0 {
            return Err(Error::Binding);
        }
        let bytes = self.bytes.borrow();
        let bytes = bytes.as_deref().ok_or(Error::Binding)?;
        f(&bytes[..n]).map_err(Error::Crypto)
    }
    pub(crate) fn into_buffer(self) -> Result<&'a mut [u8], Error> {
        self.bytes.into_inner().ok_or(Error::Binding)
    }
    fn clear(&self) {
        use zeroize::Zeroize;
        let n = self.len.replace(0);
        if let Some(bytes) = self.bytes.borrow_mut().as_deref_mut() {
            bytes[..n].zeroize();
        }
    }
}
/// A CRYPTO-stream adapter must return exactly one complete TLS message at the
/// requested level, including its four-byte handshake header. It must retain
/// following messages for later calls and reject wrong-level input.
pub trait MessageInput {
    fn read_message(
        &mut self,
        level: Level,
        bytes: &mut [u8],
    ) -> impl Future<Output = Result<usize, Error>>;
}
/// Exclusive ownership of the input buffer while I/O is pending. No RefCell
/// guard crosses an await. Partial bytes are erased even before len is committed.
struct InputLease<'s, 'buf> {
    slot: &'s MessageSlot<'buf>,
    bytes: Option<&'buf mut [u8]>,
}
impl Drop for InputLease<'_, '_> {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Some(bytes) = self.bytes.take() {
            bytes.zeroize();
            *self.slot.bytes.borrow_mut() = Some(bytes);
        }
    }
}
async fn fill(
    slot: &MessageSlot<'_>,
    io: &mut impl MessageInput,
    level: Level,
) -> Result<(), Error> {
    if slot.len.get() != 0 {
        return Err(Error::Binding);
    }
    let bytes = slot.bytes.borrow_mut().take().ok_or(Error::Binding)?;
    let mut lease = InputLease {
        slot,
        bytes: Some(bytes),
    };
    let bytes = lease.bytes.as_deref_mut().ok_or(Error::Binding)?;
    let n = io.read_message(level, bytes).await?;
    if n < 4 || n > bytes.len() {
        return Err(Error::Capacity);
    }
    let encoded = ((bytes[1] as usize) << 16) | ((bytes[2] as usize) << 8) | bytes[3] as usize;
    if encoded.checked_add(4) != Some(n) {
        return Err(Error::Binding);
    }
    *slot.bytes.borrow_mut() = lease.bytes.take();
    slot.len.set(n);
    Ok(())
}

/// A cancelled/erroring owner erases its outstanding message and fails its key
/// material closed. Successful completion preserves only the normal handoff.
/// Borrow access only: this trait carries no protocol events or transition logic.
/// It permits TX/key handoff locals to borrow the same numeric owner between
/// awaited input operations without holding a RefCell guard across an await.
pub trait CryptoAccess {
    fn with_crypto<R>(&self, f: impl FnOnce(&mut BoundedTls<'_, '_>) -> R) -> R;
    fn applied(&self) -> Result<(), Error> {
        Ok(())
    }
}
impl CryptoAccess for RefCell<BoundedTls<'_, '_>> {
    fn with_crypto<R>(&self, f: impl FnOnce(&mut BoundedTls<'_, '_>) -> R) -> R {
        f(&mut self.borrow_mut())
    }
}
struct Owner<'a, 'slot, T: CryptoAccess> {
    tls: &'a T,
    slot: &'a MessageSlot<'slot>,
    complete: bool,
}
impl<T: CryptoAccess> Drop for Owner<'_, '_, T> {
    fn drop(&mut self) {
        self.slot.clear();
        if !self.complete {
            self.tls.with_crypto(|tls| {
                tls.fail(Failure::State);
            });
        }
    }
}

pub async fn client_owner(
    endpoint: &mut Endpoint<'_, { p::VERIFY }>,
    tls: &impl CryptoAccess,
    slot: &MessageSlot<'_>,
) -> Result<(), Error> {
    if !tls.with_crypto(|t| matches!(t.mode, Mode::Client(_)) && t.pristine()) {
        return Err(Error::Binding);
    }
    let mut owner = Owner {
        tls,
        slot,
        complete: false,
    };
    let mut id = 0;
    endpoint.send::<p::NeedHello>(&id).await?;
    check(endpoint.recv::<p::Hello>().await?, id)?;
    let retry = slot.apply(|m| owner.tls.with_crypto(|tls| tls.client_hello(m, false)))?;
    owner.tls.applied()?;
    slot.clear();
    endpoint.send::<p::Applied>(&id).await?;
    id += 1;
    if retry {
        endpoint.send::<p::Retry>(&id).await?;
        endpoint.send::<p::NeedRetryHello>(&id).await?;
        check(endpoint.recv::<p::RetryHello>().await?, id)?;
        if slot.apply(|m| owner.tls.with_crypto(|tls| tls.client_hello(m, true)))? {
            return Err(Error::Binding);
        }
        owner.tls.applied()?;
        slot.clear();
        endpoint.send::<p::Applied>(&id).await?;
        id += 1;
    } else {
        endpoint.send::<p::HelloReady>(&id).await?;
    }
    endpoint.send::<p::NeedExtensions>(&id).await?;
    check(endpoint.recv::<p::Extensions>().await?, id)?;
    slot.apply(|m| owner.tls.with_crypto(|tls| tls.client_extensions(m)))?;
    owner.tls.applied()?;
    slot.clear();
    endpoint.send::<p::Applied>(&id).await?;
    id += 1;
    if owner.tls.with_crypto(|tls| tls.resumed) {
        endpoint.send::<p::Resumed>(&id).await?;
    } else {
        endpoint.send::<p::Full>(&id).await?;
        endpoint.send::<p::NeedCertificate>(&id).await?;
        check(endpoint.recv::<p::Certificate>().await?, id)?;
        slot.apply(|m| owner.tls.with_crypto(|tls| tls.client_certificate(m)))?;
        owner.tls.applied()?;
        slot.clear();
        endpoint.send::<p::Applied>(&id).await?;
        id += 1;
        endpoint.send::<p::NeedCertificateVerify>(&id).await?;
        check(endpoint.recv::<p::CertificateVerify>().await?, id)?;
        slot.apply(|m| {
            owner
                .tls
                .with_crypto(|tls| tls.client_certificate_verify(m))
        })?;
        owner.tls.applied()?;
        slot.clear();
        endpoint.send::<p::Applied>(&id).await?;
        id += 1;
    }
    endpoint.send::<p::NeedFinished>(&id).await?;
    check(endpoint.recv::<p::Finished>().await?, id)?;
    slot.apply(|m| owner.tls.with_crypto(|tls| tls.client_finished(m)))?;
    owner.tls.with_crypto(|tls| tls.record_verified_finished());
    owner.tls.applied()?;
    slot.clear();
    endpoint.send::<p::Applied>(&id).await?;
    id += 1;
    endpoint.send::<p::Complete>(&id).await?;
    owner.complete = true;
    Ok(())
}

pub async fn server_owner(
    endpoint: &mut Endpoint<'_, { p::VERIFY }>,
    tls: &impl CryptoAccess,
    slot: &MessageSlot<'_>,
) -> Result<(), Error> {
    if !tls.with_crypto(|t| matches!(t.mode, Mode::Server(_)) && t.pristine()) {
        return Err(Error::Binding);
    }
    let mut owner = Owner {
        tls,
        slot,
        complete: false,
    };
    let mut id = 0;
    endpoint.send::<p::NeedHello>(&id).await?;
    check(endpoint.recv::<p::Hello>().await?, id)?;
    let retry = slot.apply(|m| owner.tls.with_crypto(|tls| tls.server_hello(m, false)))?;
    owner.tls.applied()?;
    slot.clear();
    endpoint.send::<p::Applied>(&id).await?;
    id += 1;
    if retry {
        endpoint.send::<p::Retry>(&id).await?;
        endpoint.send::<p::NeedRetryHello>(&id).await?;
        check(endpoint.recv::<p::RetryHello>().await?, id)?;
        if slot.apply(|m| owner.tls.with_crypto(|tls| tls.server_hello(m, true)))? {
            return Err(Error::Binding);
        }
        owner.tls.applied()?;
        slot.clear();
        endpoint.send::<p::Applied>(&id).await?;
        id += 1;
    } else {
        endpoint.send::<p::HelloReady>(&id).await?;
    }
    endpoint.send::<p::NeedFinished>(&id).await?;
    check(endpoint.recv::<p::Finished>().await?, id)?;
    slot.apply(|m| owner.tls.with_crypto(|tls| tls.server_finished(m)))?;
    owner.tls.with_crypto(|tls| tls.record_verified_finished());
    owner.tls.applied()?;
    slot.clear();
    endpoint.send::<p::Applied>(&id).await?;
    id += 1;
    endpoint.send::<p::Complete>(&id).await?;
    owner.complete = true;
    Ok(())
}

pub async fn client_input(
    endpoint: &mut Endpoint<'_, { p::INPUT }>,
    slot: &MessageSlot<'_>,
    io: &mut impl MessageInput,
) -> Result<(), Error> {
    let mut id = 0;

    check(endpoint.recv::<p::NeedHello>().await?, id)?;
    fill(slot, io, Level::Initial).await?;
    endpoint.send::<p::Hello>(&id).await?;
    check(endpoint.recv::<p::Applied>().await?, id)?;
    id += 1;
    let route = endpoint.offer().await?;
    match route.label() {
        183 => {
            check(route.recv::<p::Retry>().await?, id)?;
            check(endpoint.recv::<p::NeedRetryHello>().await?, id)?;
            fill(slot, io, Level::Initial).await?;
            endpoint.send::<p::RetryHello>(&id).await?;
            check(endpoint.recv::<p::Applied>().await?, id)?;
            id += 1;
        }
        184 => check(route.recv::<p::HelloReady>().await?, id)?,
        _ => return Err(Error::Binding),
    }

    check(endpoint.recv::<p::NeedExtensions>().await?, id)?;
    fill(slot, io, Level::Handshake).await?;
    endpoint.send::<p::Extensions>(&id).await?;
    check(endpoint.recv::<p::Applied>().await?, id)?;
    id += 1;
    let route = endpoint.offer().await?;
    match route.label() {
        189 => check(route.recv::<p::Resumed>().await?, id)?,
        190 => {
            check(route.recv::<p::Full>().await?, id)?;
            check(endpoint.recv::<p::NeedCertificate>().await?, id)?;
            fill(slot, io, Level::Handshake).await?;
            endpoint.send::<p::Certificate>(&id).await?;
            check(endpoint.recv::<p::Applied>().await?, id)?;
            id += 1;
            check(endpoint.recv::<p::NeedCertificateVerify>().await?, id)?;
            fill(slot, io, Level::Handshake).await?;
            endpoint.send::<p::CertificateVerify>(&id).await?;
            check(endpoint.recv::<p::Applied>().await?, id)?;
            id += 1;
        }
        _ => return Err(Error::Binding),
    }
    check(endpoint.recv::<p::NeedFinished>().await?, id)?;
    fill(slot, io, Level::Handshake).await?;
    endpoint.send::<p::Finished>(&id).await?;
    check(endpoint.recv::<p::Applied>().await?, id)?;
    id += 1;
    check(endpoint.recv::<p::Complete>().await?, id)
}
pub async fn server_input(
    endpoint: &mut Endpoint<'_, { p::INPUT }>,
    slot: &MessageSlot<'_>,
    io: &mut impl MessageInput,
) -> Result<(), Error> {
    let mut id = 0;

    check(endpoint.recv::<p::NeedHello>().await?, id)?;
    fill(slot, io, Level::Initial).await?;
    endpoint.send::<p::Hello>(&id).await?;
    check(endpoint.recv::<p::Applied>().await?, id)?;
    id += 1;
    let route = endpoint.offer().await?;
    match route.label() {
        183 => {
            check(route.recv::<p::Retry>().await?, id)?;
            check(endpoint.recv::<p::NeedRetryHello>().await?, id)?;
            fill(slot, io, Level::Initial).await?;
            endpoint.send::<p::RetryHello>(&id).await?;
            check(endpoint.recv::<p::Applied>().await?, id)?;
            id += 1;
        }
        184 => check(route.recv::<p::HelloReady>().await?, id)?,
        _ => return Err(Error::Binding),
    }

    check(endpoint.recv::<p::NeedFinished>().await?, id)?;
    fill(slot, io, Level::Handshake).await?;
    endpoint.send::<p::Finished>(&id).await?;
    check(endpoint.recv::<p::Applied>().await?, id)?;
    id += 1;
    check(endpoint.recv::<p::Complete>().await?, id)
}

// The adapter stays private: callers cannot borrow the combined TLS provider
// back out of a KeySource. The existing projected owner performs every step.
struct SourceAccess<'a, 'scope, 'cfg, 'buf>(
    &'a RefCell<&'a mut super::key_source::KeySource<'scope, 'cfg, 'buf>>,
);
impl CryptoAccess for SourceAccess<'_, '_, '_, '_> {
    fn with_crypto<R>(&self, f: impl FnOnce(&mut BoundedTls<'_, '_>) -> R) -> R {
        f(self.0.borrow_mut().material())
    }
}
pub async fn client_source_owner<'a>(
    endpoint: &mut Endpoint<'_, { p::VERIFY }>,
    source: &'a RefCell<&'a mut super::key_source::KeySource<'_, '_, '_>>,
    slot: &MessageSlot<'_>,
) -> Result<(), Error> {
    client_owner(endpoint, &SourceAccess(source), slot).await
}
pub async fn server_source_owner<'a>(
    endpoint: &mut Endpoint<'_, { p::VERIFY }>,
    source: &'a RefCell<&'a mut super::key_source::KeySource<'_, '_, '_>>,
    slot: &MessageSlot<'_>,
) -> Result<(), Error> {
    server_owner(endpoint, &SourceAccess(source), slot).await
}
