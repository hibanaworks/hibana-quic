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

/// The production bootstrap retains real caller storage before TLS acceptance.
/// Install moves the actual claim, not a copied limits/status observation.
#[test]
fn delayed_real_tls_claim_install_and_cancellation_do_not_allocate() {
    delayed_install(Cancellation::Pending);
}
#[test]
fn delayed_activated_cancellation_remains_an_error_without_allocations() {
    delayed_install(Cancellation::Activated);
}
#[test]
fn delayed_queued_activation_cancellation_remains_an_error_without_allocations() {
    delayed_install(Cancellation::Queued);
}
#[derive(Clone, Copy)]
enum Cancellation {
    Pending,
    Activated,
    Queued,
}
fn delayed_install(cancellation: Cancellation) {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            const GEN: u64 = 1702;
            let evidence = auth::evidence(GEN, &[1]);
            let mut slots = [QuarantineSlot::<1024>::EMPTY];
            let mut controls = [ControlSlot::<128>::EMPTY];
            let storage = early_owner::Storage::new(
                GEN,
                ServerPolicy::BufferedReplaySafeRequests {
                    max_bytes: 16,
                    max_streams: 1,
                },
                &mut slots,
                &mut controls,
            )
            .unwrap();
            let carrier = CarrierStorage::<1, 16, 48>::new();
            let mut slab = [0; 65536];
            let mut kit_storage = SessionKitStorage::uninit();
            let kit = kit_storage.init();
            let sid = SessionId::new(1702);
            let rv = kit
                .rendezvous(&mut slab, carrier.bind(sid).unwrap())
                .unwrap();
            let global = early_choreography::<32, 33>();
            let cp = project::<32, _>(&global);
            let op = project::<33, _>(&global);
            let mut c = rv.enter(sid, &cp).unwrap();
            let mut o = rv.enter(sid, &op).unwrap();
            let mut cq: [Option<Command<1568>>; 1] = [None];
            let mut rq: [Option<early_owner::Reply<1568>>; 1] = [None];
            let cq = Mailbox::new(&mut cq).unwrap();
            let rq = Mailbox::new(&mut rq).unwrap();
            let (tx, rx) = cq.split().unwrap();
            let (rtx, rrx) = rq.split().unwrap();
            let mut exchange = early_owner::Exchange::new();
            let installed = Cell::new(false);
            let work = async {
                let starter = early_owner::Starter::new(tx, rrx, GEN);
                if matches!(cancellation, Cancellation::Queued) {
                    use core::{
                        future::Future,
                        task::{Context, Poll, Waker},
                    };
                    let mut activation = core::pin::pin!(starter.activate(evidence.grant));
                    let mut cx = Context::from_waker(Waker::noop());
                    assert!(matches!(activation.as_mut().poll(&mut cx), Poll::Pending));
                    assert_eq!(cq.len(), 1);
                    // Drop after publication but before the service's receipt.
                    // The queued genuine claim must not turn into unused exit.
                    return Ok(());
                }
                let mut client = starter.activate(evidence.grant).await.unwrap();
                assert_eq!(client.generation(), GEN);
                assert!(!client.snapshot().release_ready);
                assert!(!client.snapshot().has_releasable);
                assert!(matches!(
                    client.request(Command::Inspect).await.unwrap(),
                    Outcome::Inspected
                ));
                installed.set(true);
                if matches!(cancellation, Cancellation::Activated) {
                    client.close();
                    return Ok(());
                }
                core::future::pending::<Result<(), early_owner::ServiceError>>().await
            };
            COUNT.with(|count| count.set(0));
            ACTIVE.with(|active| active.set(true));
            let guard = Guard;
            {
                use core::{
                    future::Future,
                    task::{Context, Poll, Waker},
                };
                let running = runtime::join2(
                    async {
                        let completion = early_owner::run_unclaimed_borrowed(
                            &mut c,
                            &mut o,
                            storage,
                            rx,
                            rtx,
                            &mut exchange,
                        )
                        .await?;
                        assert_eq!(completion, early_owner::ServiceCompletion::Retired);
                        Ok(())
                    },
                    work,
                );
                let mut running = core::pin::pin!(running);
                match cancellation {
                    Cancellation::Pending => {
                        let mut cx = Context::from_waker(Waker::noop());
                        for _ in 0..64 {
                            assert!(matches!(running.as_mut().poll(&mut cx), Poll::Pending));
                        }
                    }
                    Cancellation::Activated => assert!(matches!(
                        auth::drive(running),
                        Err(early_owner::ServiceError::CommandsClosed)
                    )),
                    Cancellation::Queued => assert!(matches!(
                        auth::drive(running),
                        Err(early_owner::ServiceError::RepliesClosed)
                    )),
                }
            }
            drop(guard);
            assert_eq!(
                installed.get(),
                !matches!(cancellation, Cancellation::Queued)
            );
            assert!(exchange.is_empty());
            assert!(cq.is_empty());
            assert!(rq.is_empty());
            assert_eq!(COUNT.with(Cell::get), 0);
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn unactivated_storage_cancellation_is_not_a_retired_exchange() {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let mut slots = [QuarantineSlot::<1024>::EMPTY];
            let mut controls = [ControlSlot::<128>::EMPTY];
            let storage = early_owner::Storage::new(
                1703,
                ServerPolicy::BufferedReplaySafeRequests {
                    max_bytes: 16,
                    max_streams: 1,
                },
                &mut slots,
                &mut controls,
            )
            .unwrap();
            let carrier = CarrierStorage::<1, 16, 48>::new();
            let mut slab = [0; 65536];
            let mut kit_storage = SessionKitStorage::uninit();
            let kit = kit_storage.init();
            let sid = SessionId::new(1703);
            let rv = kit
                .rendezvous(&mut slab, carrier.bind(sid).unwrap())
                .unwrap();
            let global = early_choreography::<32, 33>();
            let cp = project::<32, _>(&global);
            let op = project::<33, _>(&global);
            let mut c = rv.enter(sid, &cp).unwrap();
            let mut o = rv.enter(sid, &op).unwrap();
            let mut cq: [Option<Command<1568>>; 1] = [None];
            let mut rq: [Option<early_owner::Reply<1568>>; 1] = [None];
            let cq = Mailbox::new(&mut cq).unwrap();
            let rq = Mailbox::new(&mut rq).unwrap();
            let (tx, rx) = cq.split().unwrap();
            let (rtx, rrx) = rq.split().unwrap();
            let mut exchange = early_owner::Exchange::new();
            let mut starter = early_owner::Starter::new(tx, rrx, 1703);
            COUNT.with(|count| count.set(0));
            ACTIVE.with(|active| active.set(true));
            let guard = Guard;
            {
                use core::{
                    future::Future,
                    task::{Context, Poll, Waker},
                };
                let mut running = core::pin::pin!(early_owner::run_unclaimed_borrowed(
                    &mut c,
                    &mut o,
                    storage,
                    rx,
                    rtx,
                    &mut exchange
                ));
                let mut cx = Context::from_waker(Waker::noop());
                assert!(matches!(running.as_mut().poll(&mut cx), Poll::Pending));
                assert!(rq.is_empty());
                assert_eq!(carrier.queued(), 0);
                starter.close();
                let result = auth::drive(running);
                assert!(matches!(
                    result,
                    Ok(early_owner::ServiceCompletion::UnactivatedCancelled)
                ));
            }
            drop(guard);
            assert!(exchange.is_empty());
            assert!(cq.is_empty());
            assert!(rq.is_empty());
            assert_eq!(carrier.queued(), 0);
            assert_eq!(COUNT.with(Cell::get), 0);
        })
        .unwrap()
        .join()
        .unwrap();
}
