//! Actual Initial key resources and retirement receipt slots.
use crate::crypto::directional::ApplicationKeyScope;
use crate::quic::*;
use core::{cell::Ref, future::Future, pin::pin};
pub(in crate::quic) struct Keys<'scope> {
    scope: &'scope ApplicationKeyScope,
    read: RefCell<Option<ReceivePacketKey<'scope>>>,
    alternate_read: RefCell<Option<ReceivePacketKey<'scope>>>,
    write: RefCell<Option<crypto::PacketKey>>,
    publication_waker: RefCell<Option<Waker>>,
}
impl<'scope> Keys<'scope> {
    pub fn new(
        scope: &'scope ApplicationKeyScope,
        read: crypto::PacketKey,
        write: crypto::PacketKey,
    ) -> Result<Self, Error> {
        if write.kind() != crypto::KeyKind::Initial {
            return Err(Error::Binding);
        }
        write.ensure_active()?;
        Ok(Self {
            scope,
            read: RefCell::new(Some(ReceivePacketKey::from_initial(scope, read)?)),
            alternate_read: RefCell::new(None),
            write: RefCell::new(Some(write)),
            publication_waker: RefCell::new(None),
        })
    }
    /// Called only after the projected pre-Retry publication join. Both actual
    /// key directions are replaced together; no outstanding native send exists.
    pub(in crate::quic) fn replace_for_retry(&self, destination: &[u8]) -> Result<(), Error> {
        let mut material = crypto::initial_keys(destination)?;
        let mut write = self.write.borrow_mut();
        material
            .client
            .inherit_send_usage(write.as_ref().ok_or(Error::Binding)?)?;
        let read = ReceivePacketKey::from_initial(self.scope, material.server)?;
        let mut alternate = self.alternate_read.borrow_mut();
        if let Some(previous) = alternate.as_ref() {
            let pair = crypto::initial_keys_for_version(previous.version(), destination)?;
            *alternate = Some(ReceivePacketKey::from_initial(self.scope, pair.server)?);
        }
        *self.read.borrow_mut() = Some(read);
        *write = Some(material.client);
        Ok(())
    }
    pub(in crate::quic) fn install_alternate_read(
        &self,
        key: crypto::PacketKey,
    ) -> Result<(), Error> {
        let mut a = self.alternate_read.borrow_mut();
        if a.is_some() {
            return Err(Error::Binding);
        }
        *a = Some(ReceivePacketKey::from_initial(self.scope, key)?);
        Ok(())
    }
    pub(in crate::quic) fn select_write_version(
        &self,
        version: crate::quic::imp::kernel::version::Version,
        destination: &[u8],
        side: Side,
    ) -> Result<(), Error> {
        let mut w = self.write.borrow_mut();
        let previous = w.as_ref().ok_or(Error::Binding)?;
        if previous.version() == version {
            return Ok(());
        }
        let pair = crypto::initial_keys_for_version(version, destination)?;
        let mut next = match side {
            Side::Client => pair.client,
            Side::Server => pair.server,
        };
        next.inherit_send_usage(previous)?;
        *w = Some(next);
        Ok(())
    }
    pub(in crate::quic) fn read_version(
        &self,
        version: crate::quic::imp::kernel::version::Version,
    ) -> Ref<'_, Option<ReceivePacketKey<'scope>>> {
        let primary = self.read.borrow();
        if primary.as_ref().is_some_and(|k| k.version() == version) {
            primary
        } else {
            drop(primary);
            self.alternate_read.borrow()
        }
    }
    pub fn available(&self) -> bool {
        self.write.borrow().is_some()
    }
    /// This guard is used only within the synchronous packet-open block.
    #[cfg(test)]
    pub fn read(&self) -> Ref<'_, Option<ReceivePacketKey<'scope>>> {
        self.read.borrow()
    }
    pub fn seal<'book, const N: usize>(
        &self,
        plain: wire::PlainPacket<N>,
        reservation: recovery::Reservation<'book>,
        ack: Option<recovery::AckSnapshot<'book>>,
    ) -> Result<wire::Datagram<'book, N>, (Error, recovery::Reservation<'book>)> {
        if !core::ptr::eq(self.scope, reservation.scope()) {
            return Err((Error::Binding, reservation));
        }
        let mut key = self.write.borrow_mut();
        match key.as_mut() {
            Some(key) => plain.seal_initial(key, reservation, ack),
            None => Err((Error::UnsupportedLevel, reservation)),
        }
    }
    pub(in crate::quic) fn revoke(
        &self,
        evidence: &recovery::InitialRetirement<'scope>,
    ) -> Result<(), Error> {
        if !core::ptr::eq(self.scope, evidence.scope()) {
            return Err(Error::Binding);
        }
        let alternate = self.alternate_read.borrow_mut().take();
        drop(alternate);
        let read = self.read.borrow_mut().take();
        let write = self.write.borrow_mut().take();
        drop(read);
        drop(write);
        let wake = self.publication_waker.borrow_mut().take();
        if let Some(wake) = wake {
            wake.wake();
        }
        Ok(())
    }
    /// None means the actual adapter future was dropped without acceptance.
    /// A Ready result from the same poll is authoritative even if its callback
    /// triggered revocation; Pending promises that no acceptance happened.
    pub async fn submit<F: Future>(&self, future: F) -> Option<F::Output> {
        let mut future = pin!(future);
        poll_fn(|cx| {
            if !self.available() {
                return Poll::Ready(None);
            }
            let next = cx.waker().clone();
            let old = self.publication_waker.borrow_mut().replace(next);
            drop(old);
            if !self.available() {
                return Poll::Ready(None);
            }
            match future.as_mut().poll(cx) {
                Poll::Ready(result) => Poll::Ready(Some(result)),
                Poll::Pending if !self.available() => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            }
        })
        .await
    }
}

pub(in crate::quic) struct Exchange<'scope> {
    pub(in crate::quic) event: Inbox<recovery::InitialRetirement<'scope>>,
    pub(in crate::quic) retired: Inbox<recovery::InitialRetired<'scope>>,
}
impl<'scope> Exchange<'scope> {
    pub fn new() -> Self {
        Self {
            event: Inbox::new(),
            retired: Inbox::new(),
        }
    }
}
