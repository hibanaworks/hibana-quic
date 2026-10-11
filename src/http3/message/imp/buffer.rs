//! Bounded decoded header/body exchange.
use crate::http3::Fields;
use core::cell::RefCell;
pub struct Exchange<'a> {
    pub(crate) fields: RefCell<Option<(Fields, usize)>>,
    pub(crate) bytes: RefCell<&'a mut [u8]>,
    pub(crate) headers: RefCell<&'a mut [u8]>,
}

impl<'a> Exchange<'a> {
    /// Borrow caller-owned storage for one projected message exchange.
    /// The reader cannot reuse a section until its consumer returns the
    /// choreography's storage receipt. No payload allocation is performed.
    pub const fn new(body: &'a mut [u8], headers: &'a mut [u8]) -> Self {
        Self {
            fields: RefCell::new(None),
            bytes: RefCell::new(body),
            headers: RefCell::new(headers),
        }
    }
}
