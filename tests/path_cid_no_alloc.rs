//! Allocation measurement of the remaining numeric CID history kernel.
//! PKT authentication is outside this fixture; this is not a QUIC wire test.
use hibana_quic::quic::connection_id::Cid;
use hibana_quic::quic::connection_id::LocalCidSlot;
use hibana_quic::quic::connection_id::LocalCidTable;
use hibana_quic::quic::connection_id::PeerCidSlot;
use hibana_quic::quic::connection_id::PeerCidTable;
use hibana_quic::quic::connection_id::ResetToken;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

thread_local! { static TRACK: Cell<Option<usize>> = const { Cell::new(None) }; }
struct Counter;
fn count() {
    let _ = TRACK.try_with(|v| {
        if let Some(n) = v.get() {
            v.set(Some(n + 1));
        }
    });
}
unsafe impl GlobalAlloc for Counter {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        count();
        unsafe { System.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        count();
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        count();
        unsafe { System.realloc(p, l, n) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
}
#[global_allocator]
static ALLOCATOR: Counter = Counter;
fn measured(f: impl FnOnce()) {
    TRACK.with(|v| v.set(Some(0)));
    f();
    let n = TRACK.with(|v| v.replace(None).unwrap());
    assert_eq!(n, 0);
}
#[test]
fn cid_history_allocates_zero_on_exercised_success_and_rejection() {
    let mut locals = [LocalCidSlot::EMPTY; 4];
    let mut peers = [const { PeerCidSlot::<2>::EMPTY }; 4];
    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1000);
    let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2000);
    measured(|| {
        let mut local_table = LocalCidTable::new(0, 17, &mut locals, 2).unwrap();
        let local_cid = local_table
            .issue_initial(Cid::new(&[1; 8]).unwrap(), None)
            .unwrap();
        let mut peer_table =
            PeerCidTable::new(1, 17, &mut peers, 2, Cid::new(&[2; 8]).unwrap()).unwrap();
        let peer_cid = peer_table.initial().unwrap().handle;
        peer_table
            .install_initial_token_verified(ResetToken::new([42; 16]))
            .unwrap();
        peer_table.record_sent(peer_cid, local, remote).unwrap();
        local_table.mark_advertised(local_cid.handle).unwrap();
        let mut reset = [0u8; 21];
        reset[5..].fill(42);
        assert!(peer_table.detect_stateless_reset(&reset, remote));
        reset[20] ^= 1;
        assert!(!peer_table.detect_stateless_reset(&reset, remote));
        peer_table.retire(peer_cid).unwrap();
        reset[20] ^= 1;
        assert!(!peer_table.detect_stateless_reset(&reset, remote));
        assert!(
            local_table
                .retire_authenticated(0, local_cid.cid.as_bytes())
                .is_err()
        );
    });
}
