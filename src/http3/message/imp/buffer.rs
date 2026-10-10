//! Bounded decoded header/body exchange.
use crate::http3::Fields;
use core::cell::RefCell;
pub struct Exchange {
    pub fields: RefCell<Option<Fields>>,
    pub bytes: RefCell<[u8; 4096]>,
}
