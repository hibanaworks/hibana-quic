#![cfg(target_os = "linux")]

//! A Waker's clone, drop, and wake functions are arbitrary caller code. These
//! callbacks reenter another timer operation without polling the same future.
//! Unsafe is confined to the standard Arc-backed RawWaker test instrumentation.

use hibana_quic_pal::unix::reactor::Reactor;
use hibana_quic_pal::unix::{UdpSocket, error as io};
use std::{
    cell::RefCell,
    future::{Future, poll_fn},
    mem::ManuallyDrop,
    pin::{Pin, pin},
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
    time::Duration,
};

type TestReactor = Reactor<2, 8>;
thread_local! {
    static REACTOR: RefCell<Option<Rc<TestReactor>>> = const { RefCell::new(None) };
}

struct Hook;
impl Hook {
    fn install(reactor: &Rc<TestReactor>) -> Self {
        REACTOR.with(|slot| {
            assert!(slot.borrow_mut().replace(Rc::clone(reactor)).is_none());
        });
        Self
    }
}
impl Drop for Hook {
    fn drop(&mut self) {
        REACTOR.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}
fn inspect() {
    let reactor = REACTOR.with(|slot| slot.borrow().as_ref().cloned());
    if let Some(reactor) = reactor {
        // Reenter through the public API, reserving and then releasing a
        // separate slot. This also detects a held registry RefCell borrow.
        let mut timer = reactor.sleep(Duration::from_secs(3600)).unwrap();
        assert!(
            Pin::new(&mut timer)
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    }
}
#[derive(Default)]
struct Calls {
    clone: AtomicUsize,
    wake: AtomicUsize,
    drop: AtomicUsize,
}
unsafe fn raw_clone(data: *const ()) -> RawWaker {
    // Each raw pointer owns one Arc count; a clone preserves the source count.
    let calls = ManuallyDrop::new(unsafe { Arc::from_raw(data.cast::<Calls>()) });
    calls.clone.fetch_add(1, Ordering::Relaxed);
    inspect();
    RawWaker::new(Arc::into_raw(Arc::clone(&calls)).cast(), &VTABLE)
}
unsafe fn raw_wake(data: *const ()) {
    let calls = unsafe { Arc::from_raw(data.cast::<Calls>()) };
    calls.wake.fetch_add(1, Ordering::Relaxed);
    inspect();
}
unsafe fn raw_wake_by_ref(data: *const ()) {
    let calls = ManuallyDrop::new(unsafe { Arc::from_raw(data.cast::<Calls>()) });
    calls.wake.fetch_add(1, Ordering::Relaxed);
    inspect();
}
unsafe fn raw_drop(data: *const ()) {
    let calls = unsafe { Arc::from_raw(data.cast::<Calls>()) };
    calls.drop.fetch_add(1, Ordering::Relaxed);
    inspect();
}
static VTABLE: RawWakerVTable = RawWakerVTable::new(raw_clone, raw_wake, raw_wake_by_ref, raw_drop);
fn waker() -> (Arc<Calls>, Waker) {
    let calls = Arc::new(Calls::default());
    // The backing Arc is Send + Sync; the reentrant hook is thread-local, so
    // all four functions are valid even if a Waker moves to another thread.
    let waker = unsafe {
        Waker::from_raw(RawWaker::new(
            Arc::into_raw(Arc::clone(&calls)).cast(),
            &VTABLE,
        ))
    };
    (calls, waker)
}
fn reactor() -> (Rc<TestReactor>, Hook) {
    let reactor = Rc::new(TestReactor::new().unwrap());
    let hook = Hook::install(&reactor);
    (reactor, hook)
}
fn bind() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap()
}

#[test]
fn socket_waker_clone_replace_cancel_and_competing_error_release_registry() {
    let (reactor, _hook) = reactor();
    let socket = reactor.register_udp(bind()).unwrap();
    let (calls, waker) = waker();
    let mut cx = Context::from_waker(&waker);
    let mut first_bytes = [0; 8];
    let mut second_bytes = [0; 8];
    {
        let mut first = pin!(socket.recv_from(&mut first_bytes));
        assert!(first.as_mut().poll(&mut cx).is_pending());
        assert!(first.as_mut().poll(&mut cx).is_pending());
        let mut second = pin!(socket.recv_from(&mut second_bytes));
        assert!(
            matches!(second.as_mut().poll(&mut cx), Poll::Ready(Err(error))
            if error.kind() == io::ErrorKind::AlreadyExists)
        );
    }
    assert!(calls.clone.load(Ordering::Relaxed) >= 3);
    assert!(calls.drop.load(Ordering::Relaxed) >= 3);
    // Cancellation must still release unique receive admission.
    let mut later = pin!(socket.recv_from(&mut first_bytes));
    assert!(later.as_mut().poll(&mut cx).is_pending());
}

#[test]
fn timer_waker_clone_replace_cancel_and_ready_release_registry() {
    let (reactor, _hook) = reactor();
    let (calls, old) = waker();
    let (_, new) = waker();
    {
        let mut timer = reactor.sleep(Duration::from_secs(60)).unwrap();
        assert!(
            Pin::new(&mut timer)
                .poll(&mut Context::from_waker(&old))
                .is_pending()
        );
        assert!(
            Pin::new(&mut timer)
                .poll(&mut Context::from_waker(&old))
                .is_pending()
        );
        assert!(
            Pin::new(&mut timer)
                .poll(&mut Context::from_waker(&new))
                .is_pending()
        );
    }
    assert!(calls.clone.load(Ordering::Relaxed) > 0);
    assert!(calls.drop.load(Ordering::Relaxed) > 0);
    let mut timer = reactor.sleep(Duration::from_millis(20)).unwrap();
    assert!(
        Pin::new(&mut timer)
            .poll(&mut Context::from_waker(&old))
            .is_pending()
    );
    std::thread::sleep(Duration::from_millis(25));
    assert!(matches!(
        Pin::new(&mut timer).poll(&mut Context::from_waker(&old)),
        Poll::Ready(Ok(()))
    ));
}

#[test]
fn timer_dispatch_calls_waker_after_releasing_registry() {
    let (reactor, _hook) = reactor();
    let (calls, waker) = waker();
    let mut timer = reactor.sleep(Duration::from_millis(20)).unwrap();
    reactor
        .block_on(poll_fn(|_| {
            Pin::new(&mut timer).poll(&mut Context::from_waker(&waker))
        }))
        .unwrap()
        .unwrap();
    assert!(calls.wake.load(Ordering::Relaxed) > 0);
}

#[test]
fn socket_dispatch_and_success_call_waker_after_releasing_registry() {
    let (reactor, _hook) = reactor();
    let socket = reactor.register_udp(bind()).unwrap();
    let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    let (calls, waker) = waker();
    let mut bytes = [0; 8];
    let mut receive = pin!(socket.recv_from(&mut bytes));
    assert!(
        receive
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    // The reactor dispatches the actual readiness before this custom-context
    // receive is polled again; a deadline keeps a broken dispatch test bounded.
    sender.send_to(b"ready", address).unwrap();
    let mut timeout = pin!(reactor.sleep(Duration::from_secs(1)).unwrap());
    let mut first = true;
    let received = reactor
        .block_on(poll_fn(|cx| {
            if first {
                first = false;
            } else if let Poll::Ready(result) =
                receive.as_mut().poll(&mut Context::from_waker(&waker))
            {
                return Poll::Ready(result);
            }
            assert!(timeout.as_mut().poll(cx).is_pending(), "readiness lost");
            Poll::Pending
        }))
        .unwrap()
        .unwrap();
    assert_eq!(received.len, 5);
    assert!(calls.wake.load(Ordering::Relaxed) > 0);
}

#[test]
fn socket_removal_drops_forgotten_operation_waker_outside_registry() {
    let (reactor, _hook) = reactor();
    let socket = reactor.register_udp(bind()).unwrap();
    let (calls, waker) = waker();
    let mut bytes = [0; 8];
    let mut receive = Box::pin(socket.recv_from(&mut bytes));
    assert!(
        receive
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    // Safe code can forget a future. Socket teardown must still release its
    // retained registry waker even though the operation guard will not run.
    core::mem::forget(receive);
    let before = calls.drop.load(Ordering::Relaxed);
    drop(socket);
    assert!(calls.drop.load(Ordering::Relaxed) > before);
    let replacement = reactor.register_udp(bind()).unwrap();
    assert!(replacement.local_addr().is_ok());
}
