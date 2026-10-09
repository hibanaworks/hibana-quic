//! Host-only allocation instrumentation for the bounded ticket/cache primitives.
//! This is not a claim that PSK wire negotiation is integrated into BoundedTls.
use hibana_quic::{
    tls::schedule::{KeySchedule, Transcript},
    tls::ticket::{
        Acceptance, Binding, ClientCache, ClientSlot, ReceivedTicket, ReplayPolicy, ReplaySlot,
        SEALED_TICKET_BYTES, TicketKey,
    },
};
use hibana_quic_host::entropy::KernelEntropy;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};
thread_local! {static ALLOCS:Cell<Option<usize>>=const{Cell::new(None)};}
struct Counting;
fn count() {
    let _ = ALLOCS.try_with(|n| {
        if let Some(v) = n.get() {
            n.set(Some(v + 1))
        }
    });
}
unsafe impl GlobalAlloc for Counting {
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
static ALLOCATOR: Counting = Counting;
#[test]
fn issuance_cache_binder_verification_and_replay_rejection_allocate_zero() {
    let mut transcript = Transcript::new();
    transcript.append(&[1, 0, 0, 0]).unwrap();
    transcript.append(&[2, 0, 0, 0]).unwrap();
    let mut schedule = KeySchedule::new(None).unwrap();
    schedule.derive_handshake(&[7; 32], &transcript).unwrap();
    transcript.append(&[20, 0, 0, 0]).unwrap();
    schedule.derive_master(&transcript).unwrap();
    transcript.append(&[20, 0, 0, 0]).unwrap();
    schedule.derive_resumption(&transcript).unwrap();
    // Above is a synthetic KDF fixture, not a TLS authentication shortcut.
    let mut replay = [ReplaySlot::empty(), ReplaySlot::empty()];
    let mut slots = [ClientSlot::<256>::empty(), ClientSlot::empty()];
    let mut output = [0; SEALED_TICKET_BYTES];
    let hash = [9; 32];
    ALLOCS.with(|n| n.set(Some(0)));
    {
        let bind = Binding::new("server.test", b"hq-interop", b"stable transport limits").unwrap();
        let mut key = TicketKey::generate(
            &mut KernelEntropy,
            ReplayPolicy::SingleUseOneRtt,
            &mut replay,
        )
        .unwrap();
        let token = key
            .prepare(&mut KernelEntropy, 1000, 60, 0x1301, bind)
            .unwrap();
        let psk = schedule.resumption_psk(token.ticket_nonce()).unwrap();
        let issued = key.seal(token, psk, &mut output).unwrap();
        let psk = schedule.resumption_psk(&issued.nonce).unwrap();
        let mut cache = ClientCache::new(&mut slots);
        cache
            .insert(
                1020,
                ReceivedTicket {
                    ticket: &output,
                    lifetime_seconds: issued.lifetime_seconds,
                    age_add: issued.age_add,
                    suite: 0x1301,
                    binding: bind,
                },
                psk,
            )
            .unwrap();
        let mut offered = cache.take(2000, &bind, 0x1301).unwrap().unwrap();
        let binder = offered.binder(&hash).unwrap();
        let age = offered.obfuscated_age(2000).unwrap();
        let request = || Acceptance {
            now_ms: 2000,
            obfuscated_age: age,
            max_age_skew_ms: 100,
            binding: &bind,
            suite: 0x1301,
            transcript_hash: &hash,
            binder: &binder,
        };
        let accepted = key.accept(offered.identity(), request()).unwrap();
        assert_eq!(accepted.suite(), 0x1301);
        assert!(key.accept(offered.identity(), request()).is_err());
        key.retire();
        assert!(key.accept(offered.identity(), request()).is_err());
        assert!(cache.take(2000, &bind, 0x1301).unwrap().is_none());
    }
    let count = ALLOCS.with(|n| n.replace(None).unwrap());
    assert_eq!(count, 0, "ticket lifecycle allocated");
}
