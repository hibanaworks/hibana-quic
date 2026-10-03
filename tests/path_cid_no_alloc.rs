//! Allocation measurement of independent Path/CID kernels migrated from the legacy host test.
//! PKT authentication is outside this fixture; this is not a QUIC wire test.
use hibana_quic::{
    connection_id::{Cid, LocalCidSlot, LocalCidTable, PeerCidSlot, PeerCidTable, ResetToken},
    path::{Address, Config, Control, InitialValidation, PathSlot, Paths},
};
use rand_core::{CryptoRng, RngCore};
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
struct FixtureRandom(u64);
impl RngCore for FixtureRandom {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.0 += 1;
        self.0
    }
    fn fill_bytes(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let v = self.next_u64().to_be_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(out);
        Ok(())
    }
}
impl CryptoRng for FixtureRandom {}

#[test]
fn path_cid_kernels_allocate_zero_on_exercised_success_and_rejection() {
    let mut paths = [PathSlot::<2, 3>::empty()];
    let mut locals = [LocalCidSlot::EMPTY; 4];
    let mut peers = [PeerCidSlot::<2>::EMPTY; 4];
    let mut rng = FixtureRandom(0);
    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1000);
    let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2000);
    let address = Address { local, remote };
    measured(|| {
        let mut paths = Paths::new(
            &mut paths,
            17,
            Config {
                probe_interval_us: 100,
                validation_timeout_us: 300,
                max_attempts: 3,
            },
        )
        .unwrap();
        let path = paths
            .insert(address, InitialValidation::Unvalidated, 0)
            .unwrap();
        paths.received(path, 400).unwrap();
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
        let output = paths.reserve_probe(path, 1200, 0, &mut rng).unwrap();
        let Some(Control::Challenge(data)) = output.control() else {
            panic!()
        };
        assert!(paths.response(data, 0).unwrap().is_none());
        paths.adapter_accepted(output, 0).unwrap();
        peer_table.record_sent(peer_cid, local, remote).unwrap();
        local_table.mark_advertised(local_cid.handle).unwrap();
        assert!(paths.response(data, 1).unwrap().unwrap().mtu_validated);
        assert!(paths.response(data, 1).unwrap().is_none());
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
        assert_eq!(paths.snapshot(path).unwrap().sent, 1200);
    });
}
