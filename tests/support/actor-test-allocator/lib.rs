//! Exact thread-local allocator instrumentation for crate-private actor tests.
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

pub struct Counting;
thread_local! { static TRACK: Cell<Option<usize>> = const { Cell::new(None) }; }
fn allocation() {
    let _ = TRACK.try_with(|n| {
        if let Some(count) = n.get() {
            n.set(Some(count + 1));
        }
    });
}
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        allocation();
        unsafe { System.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        allocation();
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        allocation();
        unsafe { System.realloc(p, l, n) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
}
pub struct NoAlloc;
impl NoAlloc {
    pub fn start() -> Self {
        TRACK.with(|n| {
            assert!(n.get().is_none());
            n.set(Some(0));
        });
        Self
    }
    pub fn finish(self) {
        let count = TRACK.with(|n| n.replace(None).unwrap());
        assert_eq!(count, 0, "TLS constructors and actor operations allocated");
    }
}
impl Drop for NoAlloc {
    fn drop(&mut self) {
        TRACK.with(|n| n.set(None));
    }
}
