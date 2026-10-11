//! Bounded decoded header/body exchange.
use crate::http3::Fields;
use core::cell::RefCell;
pub struct Exchange<'a> {
    pub(crate) fields: RefCell<Option<(Fields, usize)>>,
    pub(crate) bytes: Slot<'a>,
    pub(crate) headers: Slot<'a>,
}

impl<'a> Exchange<'a> {
    /// Borrow caller-owned storage for one projected message exchange.
    /// The reader cannot reuse a section until its consumer returns the
    /// choreography's storage receipt. No payload allocation is performed.
    pub const fn new(body: &'a mut [u8], headers: &'a mut [u8]) -> Self {
        Self {
            fields: RefCell::new(None),
            bytes: Slot::new(body),
            headers: Slot::new(headers),
        }
    }
}

/// One actual reusable slice resource. `None` means a localside owns the slice;
/// `Some(&mut [])` is a real zero-capacity resource, never an ownership marker.
pub(crate) struct Slot<'a>(RefCell<Option<&'a mut [u8]>>);
impl<'a> Slot<'a> {
    const fn new(bytes: &'a mut [u8]) -> Self {
        Self(RefCell::new(Some(bytes)))
    }
    pub(crate) fn take(&self) -> super::super::Result<&'a mut [u8]> {
        self.0
            .try_borrow_mut()
            .map_err(|_| super::super::Error::Invalid("HTTP storage is borrowed"))?
            .take()
            .ok_or(super::super::Error::Invalid(
                "HTTP storage is already loaned",
            ))
    }
    pub(crate) fn put(&self, bytes: &'a mut [u8]) -> super::super::Result<()> {
        let mut slot = self
            .0
            .try_borrow_mut()
            .map_err(|_| super::super::Error::Invalid("HTTP storage is borrowed"))?;
        if slot.is_some() {
            return Err(super::super::Error::Invalid(
                "HTTP storage already returned",
            ));
        }
        *slot = Some(bytes);
        Ok(())
    }
    pub(crate) fn try_borrow(&self) -> core::result::Result<core::cell::Ref<'_, &'a mut [u8]>, ()> {
        core::cell::Ref::filter_map(self.0.try_borrow().map_err(|_| ())?, |slot| slot.as_ref())
            .map_err(|_| ())
    }
    pub(crate) fn try_borrow_mut(
        &self,
    ) -> core::result::Result<core::cell::RefMut<'_, &'a mut [u8]>, ()> {
        core::cell::RefMut::filter_map(self.0.try_borrow_mut().map_err(|_| ())?, |slot| {
            slot.as_mut()
        })
        .map_err(|_| ())
    }
    pub(crate) fn borrow(&self) -> core::cell::Ref<'_, &'a mut [u8]> {
        self.try_borrow().expect("HTTP storage must be present")
    }
}
