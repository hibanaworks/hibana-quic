#![cfg(target_os = "linux")]

use hibana_quic::{
    quic::path::Address,
    runtime::{join2, yield_now},
};
use hibana_quic_pal::{async_io::Reactor, udp::Codepoint};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    future::{Future, poll_fn},
    io,
    net::UdpSocket,
    pin::pin,
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    task::{Context, Poll, Waker},
    thread,
    time::{Duration, Instant},
};

// Unsafe exists only in this test's conventional allocator instrumentation;
// the product host crate forbids unsafe code.
struct Counting;
thread_local! {
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
    static ALLOCS: Cell<usize> = const { Cell::new(0) };
}
fn allocation() {
    let _ = ACTIVE.try_with(|active| {
        if active.get() {
            let _ = ALLOCS.try_with(|n| n.set(n.get() + 1));
        }
    });
}
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        allocation();
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        allocation();
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        allocation();
        unsafe { System.realloc(ptr, layout, size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Counting = Counting;
fn measured<T>(run: impl FnOnce() -> T) -> (T, usize) {
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            ACTIVE.with(|active| active.set(false));
        }
    }
    ALLOCS.with(|n| n.set(0));
    ACTIVE.with(|active| active.set(true));
    let guard = Guard;
    let result = run();
    drop(guard);
    (result, ALLOCS.with(Cell::get))
}
fn bind(v6: bool) -> UdpSocket {
    UdpSocket::bind(if v6 { "[::1]:0" } else { "127.0.0.1:0" }).unwrap()
}
async fn watchdog<F: Future>(reactor: &Reactor<2, 4>, future: F) -> F::Output {
    let mut future = pin!(future);
    let mut timer = pin!(reactor.sleep(Duration::from_secs(2)).unwrap());
    poll_fn(|cx| {
        if let Poll::Ready(output) = future.as_mut().poll(cx) {
            return Poll::Ready(output);
        }
        assert!(
            timer.as_mut().poll(cx).is_pending(),
            "reactor operation timed out"
        );
        Poll::Pending
    })
    .await
}

fn metadata_roundtrip(v6: bool) {
    let reactor = Reactor::<2, 4>::new().unwrap();
    let receiver = reactor.register_udp(bind(v6)).unwrap();
    let sender = reactor.register_udp(bind(v6)).unwrap();
    let received_at = receiver.local_addr().unwrap();
    let sent_from = sender.local_addr().unwrap();
    let mut bytes = [0; 32];
    reactor
        .block_on(watchdog(
            &reactor,
            join2(
                async {
                    reactor.sleep(Duration::from_millis(15))?.await?;
                    assert_eq!(
                        sender
                            .send_from(
                                b"actual UDP",
                                Address {
                                    local: sent_from,
                                    remote: received_at
                                },
                                Codepoint::Ect0
                            )
                            .await?,
                        10
                    );
                    Ok::<_, io::Error>(())
                },
                async {
                    let received = receiver.recv_from(&mut bytes).await?;
                    assert_eq!(received.local, received_at);
                    assert_eq!(received.source, sent_from);
                    assert_eq!(received.ecn, Some(Codepoint::Ect0));
                    assert_eq!(&bytes[..received.len], b"actual UDP");
                    Ok(())
                },
            ),
        ))
        .unwrap()
        .unwrap();
    let stats = reactor.statistics();
    assert!(stats.socket_events >= 1);
    assert!(stats.timer_events >= 1);
    assert!(stats.polls <= 6, "idle receive must not spin: {stats:?}");
}
#[test]
fn ipv4_uses_actual_poll_readiness_and_preserves_metadata() {
    metadata_roundtrip(false);
}
#[test]
fn ipv6_uses_actual_poll_readiness_and_preserves_metadata() {
    metadata_roundtrip(true);
}

#[test]
fn idle_timer_sleeps_and_does_not_expire_early() {
    let reactor = Reactor::<0, 1>::new().unwrap();
    let started = Instant::now();
    let deadline = started + Duration::from_millis(25) + Duration::from_micros(123);
    reactor
        .block_on(reactor.sleep_until(deadline))
        .unwrap()
        .unwrap();
    assert!(Instant::now() >= deadline);
    let stats = reactor.statistics();
    assert_eq!(stats.polls, 2, "an idle timer needs exactly one wake");
    assert_eq!(stats.waits, 1);
    assert_eq!(stats.zero_timeout_waits, 0);
    assert_eq!(stats.timer_events, 1);
}

#[test]
fn cross_thread_waker_interrupts_a_blocking_wait() {
    let reactor = Reactor::<2, 4>::new().unwrap();
    let (send, receive) = mpsc::sync_channel::<Waker>(1);
    let ready = Arc::new(AtomicBool::new(false));
    let worker_ready = Arc::clone(&ready);
    let worker = thread::spawn(move || {
        let waker = receive.recv().unwrap();
        thread::sleep(Duration::from_millis(25));
        worker_ready.store(true, Ordering::Release);
        waker.wake();
    });
    let mut registered = false;
    let started = Instant::now();
    reactor
        .block_on(watchdog(
            &reactor,
            poll_fn(|cx| {
                if ready.load(Ordering::Acquire) {
                    return Poll::Ready(());
                }
                if !registered {
                    send.send(cx.waker().clone()).unwrap();
                    registered = true;
                }
                Poll::Pending
            }),
        ))
        .unwrap();
    worker.join().unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(reactor.statistics().polls, 2);
    assert_eq!(reactor.statistics().timer_events, 0);
}

#[test]
fn wake_between_condition_check_and_pending_is_not_lost() {
    let reactor = Reactor::<2, 4>::new().unwrap();
    let (send, receive) = mpsc::sync_channel::<Waker>(1);
    let barrier = Arc::new(Barrier::new(2));
    let worker_barrier = Arc::clone(&barrier);
    let ready = Arc::new(AtomicBool::new(false));
    let worker_ready = Arc::clone(&ready);
    let worker = thread::spawn(move || {
        let waker = receive.recv().unwrap();
        worker_ready.store(true, Ordering::Release);
        waker.wake();
        worker_barrier.wait();
    });
    let mut registered = false;
    let started = Instant::now();
    reactor
        .block_on(watchdog(
            &reactor,
            poll_fn(|cx| {
                if ready.load(Ordering::Acquire) {
                    return Poll::Ready(());
                }
                if !registered {
                    send.send(cx.waker().clone()).unwrap();
                    barrier.wait(); // Wake has completed before this first Pending.
                    registered = true;
                }
                Poll::Pending
            }),
        ))
        .unwrap();
    worker.join().unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(reactor.statistics().timer_events, 0);
    assert_eq!(reactor.statistics().polls, 2);
}

#[test]
fn cancelled_receive_releases_interest_and_allows_reuse() {
    let reactor = Reactor::<2, 4>::new().unwrap();
    let socket = reactor.register_udp(bind(false)).unwrap();
    let sender = bind(false);
    let mut first_bytes = [0; 8];
    let mut second_bytes = [0; 8];
    {
        let mut first = pin!(socket.recv_from(&mut first_bytes));
        let mut second = pin!(socket.recv_from(&mut second_bytes));
        let mut context = Context::from_waker(Waker::noop());
        assert!(first.as_mut().poll(&mut context).is_pending());
        let Poll::Ready(Err(error)) = second.as_mut().poll(&mut context) else {
            panic!("second reader must be rejected");
        };
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    }
    sender
        .send_to(b"reuse", socket.local_addr().unwrap())
        .unwrap();
    let received = reactor
        .block_on(watchdog(&reactor, socket.recv_from(&mut second_bytes)))
        .unwrap()
        .unwrap();
    assert_eq!(&second_bytes[..received.len], b"reuse");
}

#[test]
fn socket_and_timer_capacity_cancel_and_reuse_are_bounded() {
    let reactor = Reactor::<1, 1>::new().unwrap();
    let socket = reactor.register_udp(bind(false)).unwrap();
    assert!(
        matches!(reactor.register_udp(bind(false)), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
    );
    drop(socket);
    let _replacement = reactor.register_udp(bind(false)).unwrap();
    let mut context = Context::from_waker(Waker::noop());
    let deadline = Instant::now() + Duration::from_secs(30);
    {
        let mut first = pin!(reactor.sleep_until(deadline));
        assert!(first.as_mut().poll(&mut context).is_pending());
        let mut excess = pin!(reactor.sleep_until(deadline));
        assert!(
            matches!(excess.as_mut().poll(&mut context), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::WouldBlock)
        );
    }
    reactor
        .block_on(reactor.sleep(Duration::from_millis(1)).unwrap())
        .unwrap()
        .unwrap();
}

#[test]
fn source_validation_and_truncation_survive_async_adapter() {
    let reactor = Reactor::<2, 4>::new().unwrap();
    let sender = reactor.register_udp(bind(false)).unwrap();
    let receiver = reactor.register_udp(bind(false)).unwrap();
    let mut wrong = sender.local_addr().unwrap();
    wrong.set_port(wrong.port().wrapping_add(1));
    let error = reactor
        .block_on(sender.send_from(
            b"x",
            Address {
                local: wrong,
                remote: receiver.local_addr().unwrap(),
            },
            Codepoint::NotEct,
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    reactor
        .block_on(sender.send_to(
            b"too long",
            receiver.local_addr().unwrap(),
            Codepoint::NotEct,
        ))
        .unwrap()
        .unwrap();
    let error = reactor
        .block_on(watchdog(&reactor, receiver.recv_from(&mut [0; 1])))
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn self_waking_actor_does_not_starve_socket_readiness() {
    let reactor = Reactor::<2, 4>::new().unwrap();
    let socket = reactor.register_udp(bind(false)).unwrap();
    let local = socket.local_addr().unwrap();
    let worker = thread::spawn(move || {
        thread::sleep(Duration::from_millis(15));
        bind(false).send_to(b"event", local).unwrap();
    });
    let done = Cell::new(false);
    let sweeps = Cell::new(0_u64);
    let mut bytes = [0; 16];
    reactor
        .block_on(watchdog(
            &reactor,
            join2(
                async {
                    while !done.get() {
                        sweeps.set(sweeps.get() + 1);
                        yield_now().await;
                    }
                    Ok::<_, io::Error>(())
                },
                async {
                    let received = socket.recv_from(&mut bytes).await?;
                    assert_eq!(&bytes[..received.len], b"event");
                    done.set(true);
                    Ok(())
                },
            ),
        ))
        .unwrap()
        .unwrap();
    worker.join().unwrap();
    assert!(sweeps.get() > 1);
    // The aggregate may consume the UDP packet in the sweep racing its arrival,
    // before poll dispatch; either case progresses without starving timers.
    assert_eq!(reactor.statistics().timer_events, 0);
}

#[test]
fn explicit_setup_allocations_and_zero_allocation_scheduling() {
    let (reactor, allocations) = measured(|| Reactor::<2, 4>::new().unwrap());
    assert_eq!(
        allocations, 1,
        "one explicit Arc for safe thread-capable Wake"
    );
    let receiver = bind(false);
    let (receiver, allocations) = measured(|| reactor.register_udp(receiver).unwrap());
    assert_eq!(allocations, 1, "one existing UDP ancillary receive buffer");
    let sender = bind(false);
    sender
        .send_to(b"allocation", receiver.local_addr().unwrap())
        .unwrap();
    let mut bytes = [0; 32];
    let (_, allocations) = measured(|| {
        reactor
            .block_on(receiver.recv_from(&mut bytes))
            .unwrap()
            .unwrap()
    });
    assert_eq!(allocations, 0, "receive and waker cloning allocate nothing");
    let (_, allocations) = measured(|| {
        reactor
            .block_on(async {
                for _ in 0..256 {
                    yield_now().await;
                }
                reactor
                    .sleep(Duration::from_millis(2))
                    .unwrap()
                    .await
                    .unwrap();
            })
            .unwrap()
    });
    assert_eq!(allocations, 0, "executor/poll/timers allocate nothing");
    let (_, allocations) = measured(|| {
        reactor
            .block_on(receiver.send_from(
                b"native send",
                Address {
                    local: receiver.local_addr().unwrap(),
                    remote: sender.local_addr().unwrap(),
                },
                Codepoint::Ect0,
            ))
            .unwrap()
            .unwrap()
    });
    assert_eq!(
        allocations, 0,
        "native sendmsg uses only stack ancillary storage"
    );
}

#[test]
fn nested_executor_entry_is_rejected_without_poisoning_next_run() {
    let reactor = Reactor::<0, 0>::new().unwrap();
    let nested = reactor
        .block_on(async { reactor.block_on(async {}) })
        .unwrap();
    assert_eq!(nested.unwrap_err().kind(), io::ErrorKind::AlreadyExists);
    reactor.block_on(async {}).unwrap();
}
