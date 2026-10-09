//! Product mailbox code is safe/no_std/no_alloc. Unsafe code here is limited to
//! a counting test allocator and a data-free RawWaker for callback reentrancy.

use core::{
    future::Future,
    marker::PhantomPinned,
    pin::{Pin, pin},
    task::{Context, Poll, RawWaker, RawWakerVTable, Waker},
};
use hibana_quic::{
    runtime::mailbox::{AlreadySplit, Closed, InitError, Mailbox, SendError},
    runtime::join2,
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::{Cell, RefCell},
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::Wake,
};

struct Counting;
thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}
fn record_allocation() {
    let _ = COUNTING.try_with(|active| {
        if active.get() {
            let _ = ALLOCATIONS.try_with(|count| count.set(count.get() + 1));
        }
    });
}
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record_allocation();
        unsafe { System.realloc(pointer, layout, size) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Counting = Counting;
struct AllocationGuard;
impl AllocationGuard {
    fn start() -> Self {
        ALLOCATIONS.with(|count| count.set(0));
        COUNTING.with(|active| active.set(true));
        Self
    }
}
impl Drop for AllocationGuard {
    fn drop(&mut self) {
        COUNTING.with(|active| active.set(false));
    }
}

struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
fn counting_waker() -> (Arc<WakeCount>, Waker) {
    let count = Arc::new(WakeCount(AtomicUsize::new(0)));
    (count.clone(), Waker::from(count))
}
fn wakes(count: &WakeCount) -> usize {
    count.0.load(Ordering::SeqCst)
}
fn poll<F: Future + Unpin>(future: &mut F, waker: &Waker) -> Poll<F::Output> {
    Pin::new(future).poll(&mut Context::from_waker(waker))
}

#[test]
fn empty_receive_parks_and_publication_wakes_only_latest_waker() {
    let mut slots = [None; 2];
    let mailbox = Mailbox::new(&mut slots).unwrap();
    let (mut sender, mut receiver) = mailbox.split().unwrap();
    let (old_count, old_waker) = counting_waker();
    let (new_count, new_waker) = counting_waker();
    let mut receive = receiver.recv();
    assert!(poll(&mut receive, &old_waker).is_pending());
    assert!(poll(&mut receive, &new_waker).is_pending());
    assert_eq!((wakes(&old_count), wakes(&new_count)), (0, 0));
    assert_eq!(poll(&mut sender.send(71), &new_waker), Poll::Ready(Ok(())));
    assert_eq!((wakes(&old_count), wakes(&new_count)), (0, 1));
    assert_eq!(poll(&mut receive, &new_waker), Poll::Ready(Ok(71)));
    assert!(mailbox.is_empty());
}

#[test]
fn full_send_parks_replaces_waker_then_resumes_fifo_across_wraparound() {
    let mut slots = [None; 3];
    let mailbox = Mailbox::new(&mut slots).unwrap();
    let (mut sender, mut receiver) = mailbox.split().unwrap();
    let (old_count, old_waker) = counting_waker();
    let (new_count, new_waker) = counting_waker();
    for value in 0..3 {
        assert_eq!(
            poll(&mut sender.send(value), &old_waker),
            Poll::Ready(Ok(()))
        );
    }
    assert_eq!(mailbox.len(), mailbox.capacity());
    {
        let mut send = sender.send(3);
        assert!(poll(&mut send, &old_waker).is_pending());
        assert!(poll(&mut send, &new_waker).is_pending());
        assert_eq!((wakes(&old_count), wakes(&new_count)), (0, 0));
        assert_eq!(poll(&mut receiver.recv(), &new_waker), Poll::Ready(Ok(0)));
        assert_eq!((wakes(&old_count), wakes(&new_count)), (0, 1));
        assert_eq!(poll(&mut send, &new_waker), Poll::Ready(Ok(())));
    }
    for value in 1..4 {
        assert_eq!(
            poll(&mut receiver.recv(), &new_waker),
            Poll::Ready(Ok(value))
        );
    }
    assert!(mailbox.is_empty());
}

#[derive(Debug)]
struct OwnedValue {
    id: usize,
    drops: Rc<[Cell<usize>; 4]>,
    inspect_on_drop: bool,
}
impl OwnedValue {
    fn new(id: usize, drops: &Rc<[Cell<usize>; 4]>) -> Self {
        Self {
            id,
            drops: drops.clone(),
            inspect_on_drop: false,
        }
    }
}
impl Drop for OwnedValue {
    fn drop(&mut self) {
        self.drops[self.id].set(self.drops[self.id].get() + 1);
        if self.inspect_on_drop {
            callback(Callback::ValueDrop);
        }
    }
}
fn drops() -> Rc<[Cell<usize>; 4]> {
    Rc::new(core::array::from_fn(|_| Cell::new(0)))
}

#[test]
fn canceling_unpolled_and_full_sends_drops_only_the_unpublished_value() {
    let counts = drops();
    let mut slots = [None];
    let mailbox = Mailbox::new(&mut slots).unwrap();
    let (mut sender, mut receiver) = mailbox.split().unwrap();
    let (wake_count, waker) = counting_waker();
    drop(sender.send(OwnedValue::new(0, &counts)));
    assert_eq!(counts[0].get(), 1);
    assert!(mailbox.is_empty());
    assert!(poll(&mut sender.send(OwnedValue::new(1, &counts)), &waker).is_ready());
    {
        let mut pending = sender.send(OwnedValue::new(2, &counts));
        assert!(poll(&mut pending, &waker).is_pending());
        assert_eq!(counts[2].get(), 0);
    }
    assert_eq!(counts[2].get(), 1);
    assert_eq!(mailbox.len(), 1);
    let Poll::Ready(Ok(value)) = poll(&mut receiver.recv(), &waker) else {
        panic!("published value missing");
    };
    assert_eq!(value.id, 1);
    assert_eq!(counts[1].get(), 0);
    assert_eq!(wakes(&wake_count), 0, "canceled waiter must be removed");
    drop(value);
    assert_eq!(counts[1].get(), 1);
    assert!(poll(&mut receiver.recv(), &waker).is_pending());
}

#[test]
fn canceling_receive_clears_its_waiter_without_losing_later_publication() {
    let mut slots = [None];
    let mailbox = Mailbox::new(&mut slots).unwrap();
    let (mut sender, mut receiver) = mailbox.split().unwrap();
    let (count, waker) = counting_waker();
    {
        let mut receive = receiver.recv();
        assert!(poll(&mut receive, &waker).is_pending());
    }
    assert_eq!(poll(&mut sender.send(91), &waker), Poll::Ready(Ok(())));
    assert_eq!(wakes(&count), 0);
    assert_eq!(poll(&mut receiver.recv(), &waker), Poll::Ready(Ok(91)));
    assert!(!sender.is_closed());
}

#[test]
fn cancellation_after_a_wake_does_not_publish_or_consume_a_value() {
    let counts = drops();
    let mut slots = [None];
    let mailbox = Mailbox::new(&mut slots).unwrap();
    let (mut sender, mut receiver) = mailbox.split().unwrap();
    let (count, waker) = counting_waker();
    {
        let mut receive = receiver.recv();
        assert!(poll(&mut receive, &waker).is_pending());
        assert!(poll(&mut sender.send(OwnedValue::new(0, &counts)), &waker).is_ready());
        assert_eq!(wakes(&count), 1);
        // Cancel after notification, before receipt. The mailbox still owns 0.
    }
    assert_eq!(mailbox.len(), 1);
    assert_eq!(counts[0].get(), 0);
    {
        let mut send = sender.send(OwnedValue::new(1, &counts));
        assert!(poll(&mut send, &waker).is_pending());
        let Poll::Ready(Ok(value)) = poll(&mut receiver.recv(), &waker) else {
            panic!("wake consumed a value without a receive poll");
        };
        assert_eq!(value.id, 0);
        drop(value);
        assert_eq!(wakes(&count), 2);
        // Cancel after capacity notification, before publication.
    }
    assert!(mailbox.is_empty());
    assert_eq!(counts.each_ref().map(|count| count.get()), [1, 1, 0, 0]);
    assert!(poll(&mut receiver.recv(), &waker).is_pending());
}

#[test]
fn canceling_a_producer_actor_closes_and_keeps_only_accepted_work() {
    let counts = drops();
    let mut slots = [None];
    let mailbox = Mailbox::new(&mut slots).unwrap();
    let (mut sender, mut receiver) = mailbox.split().unwrap();
    let producer_counts = counts.clone();
    let waker = Waker::noop();
    {
        let mut actor = pin!(async move {
            sender
                .send(OwnedValue::new(0, &producer_counts))
                .await
                .unwrap();
            sender
                .send(OwnedValue::new(1, &producer_counts))
                .await
                .unwrap();
        });
        assert!(
            actor
                .as_mut()
                .poll(&mut Context::from_waker(waker))
                .is_pending()
        );
        assert_eq!(mailbox.len(), 1);
        // Ending the scope cancels the actual actor, not only a pinned reference.
    }
    assert_eq!(counts[1].get(), 1);
    let Poll::Ready(Ok(value)) = poll(&mut receiver.recv(), waker) else {
        panic!("accepted command lost when producer was canceled");
    };
    assert_eq!(value.id, 0);
    drop(value);
    assert!(matches!(
        poll(&mut receiver.recv(), waker),
        Poll::Ready(Err(Closed))
    ));
    assert_eq!(counts.each_ref().map(|count| count.get()), [1, 1, 0, 0]);
}

#[test]
fn canceling_a_consumer_actor_closes_its_command_capability() {
    let mut slots = [None::<u8>];
    let mailbox = Mailbox::new(&mut slots).unwrap();
    let (mut sender, mut receiver) = mailbox.split().unwrap();
    let (count, waker) = counting_waker();
    {
        let mut actor = pin!(async move { receiver.recv().await });
        assert!(
            actor
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
    }
    assert!(sender.is_closed());
    assert_eq!(
        poll(&mut sender.send(8), &waker),
        Poll::Ready(Err(SendError(8)))
    );
    assert_eq!(
        wakes(&count),
        0,
        "canceled consumer waiter must be released"
    );
    assert!(mailbox.is_empty());
}

#[test]
fn sender_drop_wakes_empty_receiver_with_explicit_closed() {
    let mut slots = [None::<u8>];
    let mailbox = Mailbox::new(&mut slots).unwrap();
    let (sender, mut receiver) = mailbox.split().unwrap();
    let (count, waker) = counting_waker();
    {
        let mut receive = receiver.recv();
        assert!(poll(&mut receive, &waker).is_pending());
        drop(sender);
        assert_eq!(wakes(&count), 1);
        assert_eq!(poll(&mut receive, &waker), Poll::Ready(Err(Closed)));
    }
    assert!(receiver.is_closed());
    assert_eq!(poll(&mut receiver.recv(), &waker), Poll::Ready(Err(Closed)));
}

#[test]
fn sender_drop_preserves_buffered_values_until_they_are_consumed() {
    let mut slots = [None; 2];
    let mailbox = Mailbox::new(&mut slots).unwrap();
    let (mut sender, mut receiver) = mailbox.split().unwrap();
    let waker = Waker::noop();
    assert_eq!(poll(&mut sender.send(3), waker), Poll::Ready(Ok(())));
    assert_eq!(poll(&mut sender.send(4), waker), Poll::Ready(Ok(())));
    drop(sender);
    assert!(!receiver.is_closed());
    assert_eq!(poll(&mut receiver.recv(), waker), Poll::Ready(Ok(3)));
    assert!(!receiver.is_closed());
    assert_eq!(poll(&mut receiver.recv(), waker), Poll::Ready(Ok(4)));
    assert!(receiver.is_closed());
    assert_eq!(poll(&mut receiver.recv(), waker), Poll::Ready(Err(Closed)));
}

#[test]
fn receiver_drop_discards_queued_work_and_returns_blocked_and_later_values() {
    let counts = drops();
    let mut slots = [None];
    let mailbox = Mailbox::new(&mut slots).unwrap();
    let (mut sender, receiver) = mailbox.split().unwrap();
    let (count, waker) = counting_waker();
    assert!(poll(&mut sender.send(OwnedValue::new(0, &counts)), &waker).is_ready());
    {
        let mut send = sender.send(OwnedValue::new(1, &counts));
        assert!(poll(&mut send, &waker).is_pending());
        drop(receiver);
        assert_eq!(wakes(&count), 1);
        assert_eq!(counts[0].get(), 1);
        assert!(mailbox.is_empty());
        let Poll::Ready(Err(SendError(value))) = poll(&mut send, &waker) else {
            panic!("closed receiver accepted stale command");
        };
        assert_eq!(value.id, 1);
        assert_eq!(counts[1].get(), 0);
        drop(value);
    }
    assert!(sender.is_closed());
    let Poll::Ready(Err(SendError(value))) =
        poll(&mut sender.send(OwnedValue::new(2, &counts)), &waker)
    else {
        panic!("closed command capability was reused");
    };
    assert_eq!(value.id, 2);
    drop(value);
    assert_eq!(counts.each_ref().map(|count| count.get()), [1, 1, 1, 0]);
}

#[test]
fn explicit_close_is_idempotent_and_never_reopens_the_mailbox() {
    let mut slots = [None];
    let mailbox = Mailbox::new(&mut slots).unwrap();
    let (mut sender, mut receiver) = mailbox.split().unwrap();
    let waker = Waker::noop();
    assert!(matches!(mailbox.split(), Err(AlreadySplit)));
    assert_eq!(poll(&mut sender.send(5), waker), Poll::Ready(Ok(())));
    sender.close();
    sender.close();
    assert_eq!(
        poll(&mut sender.send(6), waker),
        Poll::Ready(Err(SendError(6)))
    );
    assert_eq!(poll(&mut receiver.recv(), waker), Poll::Ready(Ok(5)));
    receiver.close();
    receiver.close();
    assert_eq!(poll(&mut receiver.recv(), waker), Poll::Ready(Err(Closed)));
    drop((sender, receiver));
    assert!(matches!(mailbox.split(), Err(AlreadySplit)));
}

#[test]
fn zero_capacity_and_occupied_storage_are_rejected_without_consuming_values() {
    let mut zero = [] as [Option<u8>; 0];
    assert!(matches!(
        Mailbox::new(&mut zero),
        Err(InitError::ZeroCapacity)
    ));
    let counts = drops();
    let mut occupied = [Some(OwnedValue::new(0, &counts))];
    assert!(matches!(
        Mailbox::new(&mut occupied),
        Err(InitError::OccupiedStorage)
    ));
    assert_eq!(counts[0].get(), 0);
    assert_eq!(occupied[0].as_ref().unwrap().id, 0);
    drop(occupied);
    assert_eq!(counts[0].get(), 1);
}

#[test]
fn mailbox_drop_recovers_storage_even_when_halves_were_forgotten() {
    let counts = drops();
    let mut slots = [None];
    {
        let mailbox = Mailbox::new(&mut slots).unwrap();
        let (mut sender, receiver) = mailbox.split().unwrap();
        assert!(poll(&mut sender.send(OwnedValue::new(0, &counts)), Waker::noop()).is_ready());
        core::mem::forget(sender);
        core::mem::forget(receiver);
    }
    assert!(slots[0].is_none());
    assert_eq!(counts[0].get(), 1);
}

#[test]
fn messages_need_neither_send_nor_unpin_and_borrowed_data_stays_in_scope() {
    struct LocalMessage<'a> {
        borrowed: &'a str,
        local: Rc<Cell<usize>>,
        _pinned: PhantomPinned,
    }
    let text = String::from("caller-owned");
    let local = Rc::new(Cell::new(7));
    let mut slots = [None];
    let mailbox = Mailbox::new(&mut slots).unwrap();
    let (mut sender, mut receiver) = mailbox.split().unwrap();
    let value = LocalMessage {
        borrowed: &text,
        local: local.clone(),
        _pinned: PhantomPinned,
    };
    assert!(poll(&mut sender.send(value), Waker::noop()).is_ready());
    let Poll::Ready(Ok(value)) = poll(&mut receiver.recv(), Waker::noop()) else {
        panic!("message unavailable");
    };
    assert_eq!(value.borrowed, "caller-owned");
    value.local.set(8);
    assert_eq!(local.get(), 8);
}

#[test]
fn actual_async_actors_stop_when_parked_and_resume_on_peer_wakes() {
    let mut slots = [None; 1];
    let mailbox = Mailbox::new(&mut slots).unwrap();
    let (mut sender, mut receiver) = mailbox.split().unwrap();
    let consumed = Cell::new(0);
    let open = Cell::new(false);
    let gate = RefCell::new(None::<Waker>);
    let (count, waker) = counting_waker();
    let producer = async {
        sender.send(10).await.map_err(|_| ())?;
        sender.send(11).await.map_err(|_| ())?;
        sender.close();
        Ok::<_, ()>(())
    };
    let consumer = async {
        core::future::poll_fn(|cx| {
            if open.get() {
                Poll::Ready(())
            } else {
                *gate.borrow_mut() = Some(cx.waker().clone());
                Poll::Pending
            }
        })
        .await;
        assert_eq!(receiver.recv().await, Ok(10));
        consumed.set(consumed.get() + 1);
        assert_eq!(receiver.recv().await, Ok(11));
        consumed.set(consumed.get() + 1);
        assert_eq!(receiver.recv().await, Err(Closed));
        Ok(())
    };
    let mut joined = pin!(join2(producer, consumer));
    let mut cx = Context::from_waker(&waker);
    assert!(joined.as_mut().poll(&mut cx).is_pending());
    assert_eq!(mailbox.len(), 1);
    assert_eq!(wakes(&count), 0, "parked actors cannot self-wake");
    assert_eq!(consumed.get(), 0);
    open.set(true);
    gate.borrow_mut().take().unwrap().wake();
    assert_eq!(wakes(&count), 1);
    assert!(joined.as_mut().poll(&mut cx).is_pending());
    assert!(wakes(&count) > 1);
    assert_eq!(joined.as_mut().poll(&mut cx), Poll::Ready(Ok(())));
    assert_eq!(consumed.get(), 2);
}

#[derive(Clone, Copy)]
enum Callback {
    Clone,
    Wake,
    Drop,
    ValueDrop,
}
type Hook = Box<dyn Fn(Callback)>;
thread_local! {
    static CALLBACK: RefCell<Option<Hook>> = const { RefCell::new(None) };
}
fn callback(kind: Callback) {
    CALLBACK.with(|slot| {
        if let Some(hook) = slot.borrow().as_ref() {
            hook(kind);
        }
    });
}
struct HookGuard;
impl Drop for HookGuard {
    fn drop(&mut self) {
        let hook = CALLBACK.with(|slot| slot.borrow_mut().take());
        drop(hook);
    }
}
fn reentrant_waker() -> Waker {
    unsafe fn clone(_: *const ()) -> RawWaker {
        callback(Callback::Clone);
        RawWaker::new(core::ptr::null(), &VTABLE)
    }
    unsafe fn wake(_: *const ()) {
        callback(Callback::Wake);
    }
    unsafe fn wake_by_ref(_: *const ()) {
        callback(Callback::Wake);
    }
    unsafe fn drop(_: *const ()) {
        callback(Callback::Drop);
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);
    // No raw pointer is read, and no reference count or external state belongs
    // to this waker. Callbacks use only the calling thread's own TLS, including
    // if a Waker clone is moved to another thread.
    unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) }
}

#[test]
fn waker_clone_wake_drop_and_value_drop_can_reenter_read_only_inspection() {
    // Leaking just the test backing array provides a stable 'static owner for a
    // TLS callback. All queued values are still explicitly destroyed exactly once.
    let storage = Box::leak(Box::new([None, None]));
    let mailbox = Rc::new(Mailbox::new(storage).unwrap());
    let counts = drops();
    let callback_counts = Rc::new([const { Cell::new(0) }; 4]);
    let inspect = mailbox.clone();
    let observed = callback_counts.clone();
    CALLBACK.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move |kind| {
            assert!(inspect.len() <= inspect.capacity());
            let _ = inspect.is_empty();
            let index = kind as usize;
            observed[index].set(observed[index].get() + 1);
        }));
    });
    let guard = HookGuard;
    let waker = reentrant_waker();
    let (mut sender, mut receiver) = mailbox.split().unwrap();
    {
        let mut receive = receiver.recv();
        assert!(poll(&mut receive, &waker).is_pending());
        assert!(poll(&mut receive, &waker).is_pending());
        let mut value = OwnedValue::new(0, &counts);
        value.inspect_on_drop = true;
        assert!(poll(&mut sender.send(value), &waker).is_ready());
        let Poll::Ready(Ok(value)) = poll(&mut receive, &waker) else {
            panic!("missing value");
        };
        drop(value);
    }
    for id in 1..3 {
        let mut value = OwnedValue::new(id, &counts);
        value.inspect_on_drop = true;
        assert!(poll(&mut sender.send(value), &waker).is_ready());
    }
    {
        let mut value = OwnedValue::new(3, &counts);
        value.inspect_on_drop = true;
        let mut pending = sender.send(value);
        assert!(poll(&mut pending, &waker).is_pending());
        assert!(poll(&mut pending, &waker).is_pending());
        // Pending send cancellation also destroys its registered waker and its
        // unpublished owned value outside the interior borrow.
    }
    receiver.close();
    assert!(mailbox.is_empty());
    assert_eq!(counts.each_ref().map(|count| count.get()), [1, 1, 1, 1]);
    assert!(callback_counts[Callback::Clone as usize].get() > 0);
    assert!(callback_counts[Callback::Wake as usize].get() > 0);
    assert!(callback_counts[Callback::Drop as usize].get() > 0);
    assert_eq!(callback_counts[Callback::ValueDrop as usize].get(), 4);
    drop((sender, receiver, waker));
    drop(guard);
}

#[test]
fn complete_backpressure_cancellation_and_closure_paths_allocate_nothing() {
    let (count, waker) = counting_waker();
    let guard = AllocationGuard::start();
    {
        let mut slots = [None; 2];
        let mailbox = Mailbox::new(&mut slots).unwrap();
        let (mut sender, mut receiver) = mailbox.split().unwrap();
        {
            let mut receive = receiver.recv();
            assert!(poll(&mut receive, &waker).is_pending());
            assert!(poll(&mut receive, &waker).is_pending());
        }
        for value in 0..2 {
            assert_eq!(poll(&mut sender.send(value), &waker), Poll::Ready(Ok(())));
        }
        {
            let mut send = sender.send(2);
            assert!(poll(&mut send, &waker).is_pending());
            assert!(poll(&mut send, &waker).is_pending());
            assert_eq!(poll(&mut receiver.recv(), &waker), Poll::Ready(Ok(0)));
            assert_eq!(poll(&mut send, &waker), Poll::Ready(Ok(())));
        }
        {
            let mut canceled = sender.send(3);
            assert!(poll(&mut canceled, &waker).is_pending());
        }
        {
            let mut blocked = sender.send(4);
            assert!(poll(&mut blocked, &waker).is_pending());
            receiver.close();
            assert_eq!(poll(&mut blocked, &waker), Poll::Ready(Err(SendError(4))));
        }
        assert_eq!(poll(&mut receiver.recv(), &waker), Poll::Ready(Err(Closed)));
        sender.close();
        assert_eq!(
            poll(&mut sender.send(5), &waker),
            Poll::Ready(Err(SendError(5)))
        );
        assert!(mailbox.is_empty());
    }
    drop(guard);
    assert!(wakes(&count) > 0);
    assert_eq!(ALLOCATIONS.with(Cell::get), 0);
}
