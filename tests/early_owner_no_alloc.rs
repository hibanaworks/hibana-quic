//! Allocation measurement for a real TLS-claim-backed owner and Q1 lifecycle.
//! TLS setup runs before counting. No certificate/0-RTT timing claim is made.
use hibana::runtime::{SessionKitStorage, ids::SessionId, program::project};
use hibana_quic::{
    carrier::CarrierStorage,
    early_data::{QuarantineSlot, ServerPolicy},
    mailbox::Mailbox,
    roles::{
        early_owner::{self, Command, ControlSlot, Outcome, State},
        protocol_early::early_choreography,
    },
    runtime,
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};
#[path = "support/early_owner_fixture.rs"]
mod auth;
#[path = "support/early_original_choreography.rs"]
mod original;
struct Counting;
thread_local! {static ACTIVE:Cell<bool>=const {Cell::new(false)};static COUNT:Cell<usize>=const {Cell::new(0)};}
fn count() {
    let _ = ACTIVE.try_with(|active| {
        if active.get() {
            let _ = COUNT.try_with(|count| count.set(count.get() + 1));
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
    unsafe fn realloc(&self, p: *mut u8, layout: Layout, n: usize) -> *mut u8 {
        count();
        unsafe { System.realloc(p, layout, n) }
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        unsafe { System.dealloc(p, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Counting = Counting;
struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        ACTIVE.with(|active| active.set(false));
    }
}
#[test]
fn real_tls_claim_owned_q1_setup_inspect_and_retire_do_not_allocate() {
    exercise(true, false, 3);
}
#[test]
fn real_tls_claim_owned_q1_pending_cancellation_does_not_allocate() {
    exercise(false, false, 1);
}
#[test]
fn first_retire_requires_no_dummy_work_and_no_allocations() {
    exercise(true, false, 0);
}
#[test]
fn original_after_inspect_retirement_remains_unresolved() {
    exercise(true, true, 1);
}
fn exercise(retire: bool, original_graph: bool, inspections: usize) {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            let payload = &[0x0b, 0, 3, b'g', b'e', b't'];
            let generation = 1701;
            let evidence = auth::evidence(generation, payload);
            let mut slots = [QuarantineSlot::EMPTY];
            let mut controls = [ControlSlot::<32>::EMPTY];
            let state = State::<16, 32, 128>::new(
                ServerPolicy::BufferedReplaySafeRequests {
                    max_bytes: 16,
                    max_streams: 1,
                },
                evidence.grant,
                &mut slots,
                &mut controls,
            )
            .unwrap();
            let carrier = CarrierStorage::<1, 16, 48>::new();
            let mut slab = [0; 65536];
            let mut storage = SessionKitStorage::uninit();
            let kit = storage.init();
            let sid = SessionId::new(1701);
            let rv = kit
                .rendezvous(&mut slab, carrier.bind(sid).unwrap())
                .unwrap();
            let global = early_choreography::<32, 33>();
            let old = original::early_choreography::<32, 33>();
            let cp = if original_graph {
                project::<32, _>(&old)
            } else {
                project::<32, _>(&global)
            };
            let op = if original_graph {
                project::<33, _>(&old)
            } else {
                project::<33, _>(&global)
            };
            let mut c = rv.enter(sid, &cp).unwrap();
            let mut o = rv.enter(sid, &op).unwrap();
            let mut cq = [None];
            let mut rq = [None];
            let cq = Mailbox::new(&mut cq).unwrap();
            let rq = Mailbox::new(&mut rq).unwrap();
            let (tx, rx) = cq.split().unwrap();
            let (rtx, rrx) = rq.split().unwrap();
            let mut exchange = early_owner::Exchange::new();
            let work = async {
                let mut client = early_owner::Client::connect(tx, rrx, generation)
                    .await
                    .unwrap();
                for _ in 0..inspections {
                    assert!(matches!(
                        client.request(Command::Inspect).await.unwrap(),
                        Outcome::Inspected
                    ));
                }
                assert_eq!(client.snapshot().charged, 0);
                assert_eq!(client.snapshot().admitted_packets, 0);
                if retire {
                    client.retire().await.unwrap();
                    Ok(())
                } else {
                    core::future::pending::<Result<(), early_owner::ServiceError>>().await
                }
            };
            COUNT.with(|count| count.set(0));
            ACTIVE.with(|active| active.set(true));
            let guard = Guard;
            let running = runtime::join2(
                early_owner::run_borrowed(&mut c, &mut o, state, rx, rtx, &mut exchange),
                work,
            );
            let result = if retire {
                auth::drive(running)
            } else {
                use core::{
                    future::Future,
                    task::{Context, Poll, Waker},
                };
                let mut running = core::pin::pin!(running);
                let mut cx = Context::from_waker(Waker::noop());
                for _ in 0..64 {
                    assert!(matches!(running.as_mut().poll(&mut cx), Poll::Pending));
                }
                Ok(())
            };
            drop(guard);
            assert_eq!(COUNT.with(Cell::get), 0);
            if original_graph {
                match result {
                    Err(early_owner::ServiceError::HibanaStep { label: 99, source }) => {
                        assert!(std::format!("{source:?}").contains("PhaseInvariant"))
                    }
                    other => panic!("original trace changed: {other:?}"),
                }
            } else {
                result.unwrap();
            }
            assert!(exchange.is_empty());
            assert!(cq.is_empty());
            assert!(rq.is_empty());
            assert_eq!(COUNT.with(Cell::get), 0);
        })
        .unwrap()
        .join()
        .unwrap();
}
