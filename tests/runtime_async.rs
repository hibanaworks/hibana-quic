#![forbid(unsafe_code)]

use core::{
    cell::{Cell, RefCell},
    future::{Future, poll_fn, ready},
    pin::{Pin, pin},
    task::{Context, Poll, Waker},
};
use hibana::{
    Endpoint, EndpointError,
    g::{self, Msg},
    runtime::{
        SessionKitStorage,
        ids::SessionId,
        program::{RoleProgram, project},
    },
};
use hibana_quic::{
    runtime::carrier::CarrierStorage,
    runtime::{TaskSet, join2, join6, yield_now},
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::Wake,
};

struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
fn context_waker() -> (Arc<WakeCount>, Waker) {
    let count = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = Waker::from(count.clone());
    (count, waker)
}
fn count(counter: &WakeCount) -> usize {
    counter.0.load(Ordering::SeqCst)
}

fn with_pair<R>(
    projection: (RoleProgram<0>, RoleProgram<1>),
    body: impl for<'r> FnOnce(Endpoint<'r, 0>, Endpoint<'r, 1>, &CarrierStorage<1, 16, 8>) -> R,
) -> R {
    let carrier = CarrierStorage::<1, 16, 8>::new();
    let mut slab = [0u8; 32 * 1024];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init();
    let sid = SessionId::new(33);
    let rv = kit
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    body(
        rv.enter(sid, &projection.0).unwrap(),
        rv.enter(sid, &projection.1).unwrap(),
        &carrier,
    )
}
fn pair_programs() -> (RoleProgram<0>, RoleProgram<1>) {
    let program = g::seq(
        g::send::<0, 1, Msg<10, u32>>(),
        g::send::<1, 0, Msg<11, u32>>(),
    )
    .roll();
    (project(&program), project(&program))
}

#[test]
fn real_pending_receive_stores_latest_parent_waker_without_spinning() {
    with_pair(pair_programs(), |mut sender, mut receiver, _| {
        let (old_count, old_waker) = context_waker();
        let (new_count, new_waker) = context_waker();
        let mut receive = pin!(async { receiver.recv::<Msg<10, u32>>().await });
        assert!(
            receive
                .as_mut()
                .poll(&mut Context::from_waker(&old_waker))
                .is_pending()
        );
        assert!(
            receive
                .as_mut()
                .poll(&mut Context::from_waker(&new_waker))
                .is_pending()
        );
        assert_eq!(count(&old_count), 0);
        assert_eq!(count(&new_count), 0);
        let mut send = pin!(async { sender.send::<Msg<10, u32>>(&17).await });
        assert!(matches!(
            send.as_mut().poll(&mut Context::from_waker(&new_waker)),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(count(&old_count), 0);
        assert!(count(&new_count) > 0);
        assert!(matches!(
            receive.as_mut().poll(&mut Context::from_waker(&new_waker)),
            Poll::Ready(Ok(17))
        ));
    });
}

#[test]
fn full_carrier_parks_then_reader_and_writer_wakes_complete_real_awaits() {
    let program = g::seq(
        g::send::<0, 1, Msg<10, u32>>(),
        g::send::<0, 1, Msg<12, u32>>(),
    );
    with_pair(
        (project(&program), project(&program)),
        |mut sender, mut receiver, carrier| {
            let open = Cell::new(false);
            let gate_waker = RefCell::new(None::<Waker>);
            let (wakes, waker) = context_waker();
            let mut cx = Context::from_waker(&waker);
            let producer = async {
                sender.send::<Msg<10, u32>>(&17).await?;
                sender.send::<Msg<12, u32>>(&18).await?;
                Ok::<_, EndpointError>(())
            };
            let consumer = async {
                poll_fn(|cx| {
                    if open.get() {
                        Poll::Ready(())
                    } else {
                        *gate_waker.borrow_mut() = Some(cx.waker().clone());
                        Poll::Pending
                    }
                })
                .await;
                assert_eq!(receiver.recv::<Msg<10, u32>>().await?, 17);
                assert_eq!(receiver.recv::<Msg<12, u32>>().await?, 18);
                Ok::<_, EndpointError>(())
            };
            let mut running = pin!(join2(producer, consumer));
            assert!(running.as_mut().poll(&mut cx).is_pending());
            assert_eq!(carrier.queued(), 1);
            assert_eq!(count(&wakes), 0, "fully parked tasks must not self-wake");
            open.set(true);
            gate_waker.borrow_mut().take().unwrap().wake();
            assert_eq!(count(&wakes), 1);
            assert!(running.as_mut().poll(&mut cx).is_pending());
            assert!(
                count(&wakes) > 1,
                "dequeue and enqueue wake their actual peers"
            );
            assert!(matches!(
                running.as_mut().poll(&mut cx),
                Poll::Ready(Ok(()))
            ));
            assert_eq!(carrier.queued(), 0);
        },
    );
}

#[test]
fn wake_during_sweep_is_preserved_for_an_already_polled_task() {
    let ready = Cell::new(false);
    let parked = RefCell::new(None::<Waker>);
    let first_polls = Cell::new(0);
    let first = poll_fn(|cx| {
        first_polls.set(first_polls.get() + 1);
        if ready.get() {
            Poll::Ready(Ok::<_, ()>(()))
        } else {
            *parked.borrow_mut() = Some(cx.waker().clone());
            Poll::Pending
        }
    });
    let second = async {
        ready.set(true);
        parked.borrow_mut().take().unwrap().wake();
        Ok(())
    };
    let (wakes, waker) = context_waker();
    let mut cx = Context::from_waker(&waker);
    let mut joined = pin!(join2(first, second));
    assert!(joined.as_mut().poll(&mut cx).is_pending());
    assert_eq!(count(&wakes), 1);
    assert_eq!(first_polls.get(), 1, "no resweep inside one poll");
    assert!(matches!(joined.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
    assert_eq!(first_polls.get(), 2);
}

#[test]
fn fixed_sweeps_rotate_order_never_repoll_completed_tasks_and_leave_idle_asleep() {
    let order = RefCell::new(([0usize; 12], 0));
    let polls = [Cell::new(0), Cell::new(0), Cell::new(0)];
    let make = |index: usize| {
        let polls = &polls;
        let order = &order;
        poll_fn(move |_cx| {
            polls[index].set(polls[index].get() + 1);
            let mut record = order.borrow_mut();
            let next = record.1;
            record.0[next] = index;
            record.1 += 1;
            if index == 1 {
                Poll::Ready(Ok::<_, ()>(()))
            } else {
                Poll::Pending
            }
        })
    };
    let mut a = pin!(make(0));
    let mut b = pin!(make(1));
    let mut c = pin!(make(2));
    let mut set = pin!(TaskSet::new([a.as_mut(), b.as_mut(), c.as_mut()]));
    let (wakes, waker) = context_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(set.as_mut().poll(&mut cx).is_pending());
    assert!(set.as_mut().poll(&mut cx).is_pending());
    assert!(set.as_mut().poll(&mut cx).is_pending());
    assert_eq!(polls.each_ref().map(Cell::get), [3, 1, 3]);
    let record = order.borrow();
    assert_eq!(&record.0[..record.1], &[0, 1, 2, 2, 0, 2, 0]);
    assert_eq!(count(&wakes), 0);
}

#[test]
fn ready_loops_yield_after_bounded_work_so_all_six_tasks_progress() {
    let completed = [const { Cell::new(0usize) }; 6];
    async fn actor(completed: &Cell<usize>) -> Result<(), ()> {
        for _ in 0..4 {
            ready(()).await;
            completed.set(completed.get() + 1);
            yield_now().await;
        }
        Ok(())
    }
    let (wakes, waker) = context_waker();
    let mut cx = Context::from_waker(&waker);
    let mut joined = pin!(join6(
        actor(&completed[0]),
        actor(&completed[1]),
        actor(&completed[2]),
        actor(&completed[3]),
        actor(&completed[4]),
        actor(&completed[5])
    ));
    for expected in 1..=4 {
        assert!(joined.as_mut().poll(&mut cx).is_pending());
        assert_eq!(completed.each_ref().map(Cell::get), [expected; 6]);
        assert_eq!(count(&wakes), expected * 6);
    }
    assert!(matches!(joined.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
}

struct DropCount<'a>(&'a Cell<usize>);
impl Drop for DropCount<'_> {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}
#[test]
fn owned_join_drops_every_child_on_error_and_cancellation() {
    let (wakes, waker) = context_waker();
    let mut cx = Context::from_waker(&waker);
    for fail in [false, true] {
        let dropped = Cell::new(0);
        {
            let first_guard = DropCount(&dropped);
            let second_guard = DropCount(&dropped);
            let first = async move {
                let _guard = first_guard;
                core::future::pending::<()>().await;
                Ok::<_, u8>(())
            };
            let second = async move {
                let _guard = second_guard;
                if fail {
                    Err(7)
                } else {
                    core::future::pending().await
                }
            };
            let mut running = pin!(join2(first, second));
            if fail {
                assert_eq!(running.as_mut().poll(&mut cx), Poll::Ready(Err(7)));
                assert_eq!(dropped.get(), 2, "error cancels siblings before returning");
            } else {
                assert!(running.as_mut().poll(&mut cx).is_pending());
                assert_eq!(dropped.get(), 0);
            }
        }
        assert_eq!(dropped.get(), 2);
    }
    assert_eq!(count(&wakes), 0);
}

#[test]
fn outer_session_drop_closes_pending_generation_wakes_peer_and_prevents_replay() {
    with_pair(pair_programs(), |sender, mut receiver, carrier| {
        let (wakes, waker) = context_waker();
        let mut cx = Context::from_waker(&waker);
        let mut waiting = pin!(async { receiver.recv::<Msg<10, u32>>().await });
        assert!(waiting.as_mut().poll(&mut cx).is_pending());
        {
            let owner = async move {
                let _sender = sender;
                join2(
                    core::future::pending::<Result<(), EndpointError>>(),
                    core::future::pending::<Result<(), EndpointError>>(),
                )
                .await
            };
            let mut owner = pin!(owner);
            assert!(owner.as_mut().poll(&mut cx).is_pending());
            assert!(!carrier.is_closed());
        }
        assert!(carrier.is_closed());
        assert!(count(&wakes) > 0);
        assert_eq!(carrier.queued(), 0);
        assert!(matches!(
            waiting.as_mut().poll(&mut cx),
            Poll::Ready(Err(_))
        ));
        // The old transport is still bound. Neither cancellation nor the same
        // numeric session ID can reopen that generation or replay a frame.
        assert!(carrier.bind(SessionId::new(33)).is_err());
    });
}

#[test]
fn empty_task_set_is_ready_without_waking() {
    let (wakes, waker) = context_waker();
    let mut set = TaskSet::<(), 0>::new([]);
    assert_eq!(
        Pin::new(&mut set).poll(&mut Context::from_waker(&waker)),
        Poll::Ready(Ok(()))
    );
    assert_eq!(count(&wakes), 0);
}

#[test]
fn six_real_roles_repeat_parallel_routes_while_an_independent_receive_is_idle() {
    let idle = g::seq(
        g::send::<0, 1, Msg<50, u32>>(),
        g::send::<1, 0, Msg<51, u32>>(),
    )
    .roll();
    let first = g::route(
        g::seq(
            g::send::<2, 3, Msg<60, u32>>(),
            g::send::<3, 2, Msg<61, u32>>(),
        ),
        g::seq(
            g::send::<2, 3, Msg<62, u32>>(),
            g::send::<3, 2, Msg<63, u32>>(),
        ),
    )
    .roll();
    let second = g::seq(
        g::send::<4, 5, Msg<70, u32>>(),
        g::send::<5, 4, Msg<71, u32>>(),
    )
    .roll();
    let program = g::par(idle, g::par(first, second));
    let carrier = CarrierStorage::<1, 16, 12>::new();
    let mut slab = [0u8; 32 * 1024];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init();
    let sid = SessionId::new(34);
    let rv = kit
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    // The enclosing session owns endpoints until every actor has stopped.
    let mut e0 = rv.enter(sid, &project::<0, _>(&program)).unwrap();
    let mut e1 = rv.enter(sid, &project::<1, _>(&program)).unwrap();
    let mut e2 = rv.enter(sid, &project::<2, _>(&program)).unwrap();
    let mut e3 = rv.enter(sid, &project::<3, _>(&program)).unwrap();
    let mut e4 = rv.enter(sid, &project::<4, _>(&program)).unwrap();
    let mut e5 = rv.enter(sid, &project::<5, _>(&program)).unwrap();
    let first_count = Cell::new(0);
    let second_count = Cell::new(0);
    let role0 = async {
        core::future::pending::<()>().await;
        e0.send::<Msg<50, u32>>(&0).await?;
        e0.recv::<Msg<51, u32>>().await?;
        Ok::<_, EndpointError>(())
    };
    let role1 = async {
        let value = e1.recv::<Msg<50, u32>>().await?;
        e1.send::<Msg<51, u32>>(&value).await?;
        Ok(())
    };
    let role2 = async {
        for value in 0..3 {
            if value == 1 {
                e2.send::<Msg<62, u32>>(&value).await?;
                assert_eq!(e2.recv::<Msg<63, u32>>().await?, value);
            } else {
                e2.send::<Msg<60, u32>>(&value).await?;
                assert_eq!(e2.recv::<Msg<61, u32>>().await?, value);
            }
            first_count.set(first_count.get() + 1);
            yield_now().await;
        }
        Ok(())
    };
    let role3 = async {
        for _ in 0..3 {
            let branch = e3.offer().await?;
            match branch.label() {
                60 => {
                    let value = branch.recv::<Msg<60, u32>>().await?;
                    e3.send::<Msg<61, u32>>(&value).await?;
                }
                62 => {
                    let value = branch.recv::<Msg<62, u32>>().await?;
                    e3.send::<Msg<63, u32>>(&value).await?;
                }
                label => panic!("unexpected route label {label}"),
            }
            yield_now().await;
        }
        Ok(())
    };
    let role4 = async {
        for value in 0..3 {
            e4.send::<Msg<70, u32>>(&value).await?;
            assert_eq!(e4.recv::<Msg<71, u32>>().await?, value);
            second_count.set(second_count.get() + 1);
            yield_now().await;
        }
        Ok(())
    };
    let role5 = async {
        for _ in 0..3 {
            let value = e5.recv::<Msg<70, u32>>().await?;
            e5.send::<Msg<71, u32>>(&value).await?;
            yield_now().await;
        }
        Ok(())
    };
    let (wakes, waker) = context_waker();
    let mut cx = Context::from_waker(&waker);
    let mut running = pin!(join6(role0, role1, role2, role3, role4, role5));
    for _ in 0..100 {
        let before = count(&wakes);
        assert!(running.as_mut().poll(&mut cx).is_pending());
        if count(&wakes) == before {
            assert_eq!((first_count.get(), second_count.get()), (3, 3));
            assert_eq!(carrier.queued(), 0);
            return;
        }
    }
    panic!("bounded repeated work failed to finish and leave only idle tasks");
}

#[test]
fn runtime_select_prefers_observed_first_completion_and_drops_the_loser() {
    struct Pending<'a>(&'a Cell<usize>);
    impl Future for Pending<'_> {
        type Output = ();
        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
            Poll::Pending
        }
    }
    impl Drop for Pending<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let dropped = Cell::new(0);
    let mut task = pin!(hibana_quic::runtime::select(ready(7), Pending(&dropped)));
    assert_eq!(
        task.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(core::ops::ControlFlow::Break(7))
    );
    assert_eq!(dropped.get(), 1);
    let mut both = pin!(hibana_quic::runtime::select(ready(1), ready(2)));
    assert_eq!(
        both.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(core::ops::ControlFlow::Break(1))
    );
}

#[test]
fn runtime_companion_preserves_the_same_pending_io_owner() {
    struct Io<'a> {
        polls: &'a Cell<usize>,
        dropped: &'a Cell<usize>,
    }
    impl Future for Io<'_> {
        type Output = u8;
        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<u8> {
            self.polls.set(self.polls.get() + 1);
            if self.polls.get() == 1 {
                Poll::Pending
            } else {
                Poll::Ready(9)
            }
        }
    }
    impl Drop for Io<'_> {
        fn drop(&mut self) {
            self.dropped.set(self.dropped.get() + 1);
        }
    }
    let polls = Cell::new(0);
    let dropped = Cell::new(0);
    let task = hibana_quic::runtime::on_pending(
        Io {
            polls: &polls,
            dropped: &dropped,
        },
        async {
            assert_eq!(polls.get(), 1);
            assert_eq!(dropped.get(), 0);
            Ok::<(), ()>(())
        },
    );
    let mut task = pin!(task);
    assert_eq!(
        task.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Ok(9))
    );
    assert_eq!(polls.get(), 2);
    assert_eq!(dropped.get(), 1);
    let ran = Cell::new(false);
    let mut ready_io = pin!(hibana_quic::runtime::on_pending(ready(10), async {
        ran.set(true);
        Ok::<(), ()>(())
    }));
    assert_eq!(
        ready_io
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Ok(10))
    );
    assert!(!ran.get());
}

#[test]
fn standard_join_macro_drives_actual_capacity_one_hibana_locals() {
    with_pair(pair_programs(), |mut source, mut sink, carrier| {
        let first = async {
            for n in 0..4 {
                source.send::<Msg<10, u32>>(&n).await?;
                assert_eq!(source.recv::<Msg<11, u32>>().await?, n);
            }
            Ok::<(), EndpointError>(())
        };
        let second = async {
            for _ in 0..4 {
                let n = sink.recv::<Msg<10, u32>>().await?;
                sink.send::<Msg<11, u32>>(&n).await?;
            }
            Ok::<(), EndpointError>(())
        };
        let mut joined = pin!(hibana_quic::runtime::join2(first, second));
        for _ in 0..32 {
            if let Poll::Ready(result) = joined
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
            {
                result.unwrap();
                assert_eq!(carrier.queued(), 0);
                return;
            }
        }
        panic!("real local continuations failed to join");
    });
}
