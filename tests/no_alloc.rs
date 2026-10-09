//! Measures implemented component paths only, not a complete QUIC/TLS handshake.
use hibana_quic::{
    quic::kernel::accounting::{AckRange, PacketKind, PathBudget, SentLedger},
    quic::kernel::flow::{ConnectionReceive, StreamReceive},
    tls::buffer::CryptoBuffer,
    quic::kernel::packet::{decode_varint, encode_varint},
    quic::kernel::storage::{LeasePool, OwnerId},
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

#[path = "embedded/support/component_smoke.rs"]
mod component_smoke;

struct Counting;
thread_local! {
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
    static ALLOCS: Cell<usize> = const { Cell::new(0) };
}
fn count() {
    let _ = ACTIVE.try_with(|active| {
        if active.get() {
            let _ = ALLOCS.try_with(|n| n.set(n.get() + 1));
        }
    });
}
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count();
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count();
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        count();
        unsafe { System.realloc(ptr, layout, size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Counting = Counting;
struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        ACTIVE.with(|a| a.set(false));
    }
}

#[test]
fn implemented_components_do_not_allocate() {
    ALLOCS.with(|n| n.set(0));
    ACTIVE.with(|a| a.set(true));
    let guard = Guard;
    component_smoke::exercise();
    let mut arena = [[0_u8; 128]; 2];
    let mut pool = LeasePool::new(1, 1, &mut arena);
    let lease = pool.acquire(OwnerId(1), 0, 16).unwrap();
    pool.bytes_mut(OwnerId(1), &lease).unwrap().fill(7);
    let moved = pool.transfer(OwnerId(1), &lease, OwnerId(2)).unwrap();
    assert_eq!(pool.bytes(OwnerId(2), &moved).unwrap(), &[7; 16]);
    pool.release(OwnerId(2), &moved).unwrap();
    let mut wire = [0; 8];
    let len = encode_varint((1 << 40) + 3, &mut wire).unwrap();
    assert_eq!(decode_varint(&wire[..len]).unwrap().0, (1 << 40) + 3);
    let mut bytes = [0; 16];
    let mut bitmap = [0; 16];
    let mut crypto = CryptoBuffer::new(&mut bytes, &mut bitmap).unwrap();
    crypto.insert(4, b"efgh").unwrap();
    crypto.insert(0, b"abcd").unwrap();
    crypto.consume(8).unwrap();
    let mut connection = ConnectionReceive::new(32).unwrap();
    let mut stream = StreamReceive::new(16).unwrap();
    stream.on_data(&mut connection, 0, 8, true).unwrap();
    let mut sent = SentLedger::<4>::new(1);
    let r = sent.reserve(PacketKind::Initial, 1200, true).unwrap();
    sent.adapter_accepted(r, 0).unwrap();
    let pn = r.packet();
    sent.acknowledge(
        pn.space,
        &[AckRange {
            start: pn.value,
            end: pn.value,
        }],
    )
    .unwrap();
    let mut path = PathBudget::<2>::new(1, 1);
    path.record_received(1200).unwrap();
    let r = path.reserve(1200).unwrap();
    path.adapter_accepted(r).unwrap();
    drop(guard);
    assert_eq!(ALLOCS.with(Cell::get), 0);
}
