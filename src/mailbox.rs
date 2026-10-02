//! A bounded, single-owner async mailbox for role-local work.
//!
//! The caller supplies all message storage. There is one sender, one receiver,
//! and at most one outstanding operation on each half. A full send or empty
//! receive parks with the current task's waker; publication, consumption, and
//! closure wake the relevant peer. No executor, allocation, protocol state, or
//! endpoint choreography is hidden here.
//!
//! Cancellation before publication drops the send future's value without
//! enqueuing it. After publication, the mailbox owns that value until receipt
//! or receiver closure. Sender closure permits queued values to drain; receiver
//! closure drops them. Waker callbacks and message destructors always run after
//! releasing the mailbox's interior borrow. Callbacks may inspect the mailbox
//! or schedule other work, but must follow the executor's normal non-reentrant
//! task-polling contract.
//!
//! These types deliberately stay on one thread, even for `Send` message types.
//! The caller may pin `!Unpin` role futures and store `!Unpin` messages: messages
//! themselves are never structurally pinned by a mailbox operation.

use core::{
    cell::RefCell,
    future::Future,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll, Waker},
};

/// Invalid caller-owned mailbox storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitError {
    /// Zero slots cannot buffer a value. This mailbox is not a rendezvous queue.
    ZeroCapacity,
    /// All slots must initially be `None`; existing values remain caller-owned.
    OccupiedStorage,
}

/// The mailbox's unique sender and receiver have already been issued.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AlreadySplit;

/// This receiver cannot produce another value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Closed;

/// Publication failed because the sender or receiver has closed.
///
/// The unsent value is returned to the caller; it was never enqueued.
#[derive(Debug, Eq, PartialEq)]
pub struct SendError<T>(pub T);

struct State<'storage, T, const N: usize> {
    slots: &'storage mut [Option<T>; N],
    head: usize,
    len: usize,
    split: bool,
    sender_open: bool,
    receiver_open: bool,
    sender_waker: Option<Waker>,
    receiver_waker: Option<Waker>,
}

impl<T, const N: usize> State<'_, T, N> {
    /// Moves a value out; never drops a message or invokes a waker.
    fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        let value = self.slots[self.head].take();
        self.head = (self.head + 1) % N;
        self.len -= 1;
        value
    }
}

/// Caller-storage-backed FIFO, permanently closed after its halves close.
///
/// `split` succeeds exactly once. Its shared borrow allows read-only inspection
/// while the unique halves are running; it cannot produce duplicate halves.
///
/// The mailbox cannot outlive its backing storage:
/// ```compile_fail
/// use hibana_quic::mailbox::Mailbox;
/// let mailbox;
/// {
///     let mut slots = [None::<u8>];
///     mailbox = Mailbox::new(&mut slots).unwrap();
/// }
/// drop(mailbox);
/// ```
/// The mailbox and both halves are deliberately `!Send` and `!Sync`:
/// ```compile_fail
/// use hibana_quic::mailbox::Mailbox;
/// fn require_send<T: Send>(_: T) {}
/// let mut slots = [None::<u8>];
/// require_send(Mailbox::new(&mut slots).unwrap());
/// ```
/// ```compile_fail
/// use hibana_quic::mailbox::Mailbox;
/// fn require_sync<T: Sync>(_: &T) {}
/// let mut slots = [None::<u8>];
/// let mailbox = Mailbox::new(&mut slots).unwrap();
/// require_sync(&mailbox);
/// ```
pub struct Mailbox<'storage, T, const N: usize> {
    state: RefCell<State<'storage, T, N>>,
    // Raw pointers are neither Send nor Sync. This marker stores no pointer and
    // entails no unsafe code or pointer operations.
    _local: PhantomData<*mut ()>,
}

impl<'storage, T, const N: usize> Mailbox<'storage, T, N> {
    /// Borrow an initially empty, nonzero-capacity array for this mailbox.
    pub fn new(slots: &'storage mut [Option<T>; N]) -> Result<Self, InitError> {
        if N == 0 {
            return Err(InitError::ZeroCapacity);
        }
        if slots.iter().any(Option::is_some) {
            return Err(InitError::OccupiedStorage);
        }
        Ok(Self {
            state: RefCell::new(State {
                slots,
                head: 0,
                len: 0,
                split: false,
                sender_open: false,
                receiver_open: false,
                sender_waker: None,
                receiver_waker: None,
            }),
            _local: PhantomData,
        })
    }

    /// Issue the unique halves. A closed mailbox cannot be reopened.
    pub fn split(
        &self,
    ) -> Result<(Sender<'_, 'storage, T, N>, Receiver<'_, 'storage, T, N>), AlreadySplit> {
        {
            let mut state = self.state.borrow_mut();
            if state.split {
                return Err(AlreadySplit);
            }
            state.split = true;
            state.sender_open = true;
            state.receiver_open = true;
        }
        Ok((Sender { mailbox: self }, Receiver { mailbox: self }))
    }

    pub const fn capacity(&self) -> usize {
        N
    }

    /// The number of published values still owned by the mailbox.
    pub fn len(&self) -> usize {
        self.state.borrow().len
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn close_sender(&self) {
        let (sender_waker, receiver_waker) = {
            let mut state = self.state.borrow_mut();
            state.sender_open = false;
            (state.sender_waker.take(), state.receiver_waker.take())
        };
        drop(sender_waker);
        if let Some(waker) = receiver_waker {
            waker.wake();
        }
    }

    fn close_receiver(&self) {
        let (sender_waker, receiver_waker) = {
            let mut state = self.state.borrow_mut();
            state.receiver_open = false;
            (state.sender_waker.take(), state.receiver_waker.take())
        };
        drop(receiver_waker);
        if let Some(waker) = sender_waker {
            waker.wake();
        }
        // Extract only one value at a time, avoiding a second N-slot buffer.
        // Closing first prevents reentrant callbacks from publishing more work.
        loop {
            let value = { self.state.borrow_mut().pop() };
            match value {
                Some(value) => drop(value),
                None => break,
            }
        }
    }
}

impl<T, const N: usize> Drop for Mailbox<'_, T, N> {
    fn drop(&mut self) {
        // Also handles a deliberately forgotten half: storage is always returned
        // empty once the caller can access it again.
        self.close_receiver();
        self.close_sender();
    }
}

/// The unique producer; dropping it closes publication but preserves queued work.
///
/// ```compile_fail
/// use hibana_quic::mailbox::Mailbox;
/// fn require_send<T: Send>(_: T) {}
/// let mut slots = [None::<u8>];
/// let mailbox = Mailbox::new(&mut slots).unwrap();
/// let (sender, _) = mailbox.split().unwrap();
/// require_send(sender);
/// ```
/// Two sends cannot simultaneously borrow this half:
/// ```compile_fail
/// use hibana_quic::mailbox::Mailbox;
/// let mut slots = [None::<u8>];
/// let mailbox = Mailbox::new(&mut slots).unwrap();
/// let (mut sender, _receiver) = mailbox.split().unwrap();
/// let first = sender.send(1);
/// let second = sender.send(2);
/// drop((first, second));
/// ```
pub struct Sender<'channel, 'storage, T, const N: usize> {
    mailbox: &'channel Mailbox<'storage, T, N>,
}

impl<'storage, T, const N: usize> Sender<'_, 'storage, T, N> {
    /// Wait for capacity, then publish the owned value exactly once.
    pub fn send(&mut self, value: T) -> Send<'_, 'storage, T, N> {
        Send {
            mailbox: self.mailbox,
            value: Some(value),
            finished: false,
        }
    }

    /// Prevent further sends and wake an empty receiver. Already queued values
    /// remain available to receive. Closing again has no effect.
    pub fn close(&mut self) {
        self.mailbox.close_sender();
    }

    pub fn is_closed(&self) -> bool {
        let state = self.mailbox.state.borrow();
        !state.sender_open || !state.receiver_open
    }
}

impl<T, const N: usize> Drop for Sender<'_, '_, T, N> {
    fn drop(&mut self) {
        self.mailbox.close_sender();
    }
}

/// The unique consumer; dropping it closes sends and releases all queued values.
///
/// ```compile_fail
/// use hibana_quic::mailbox::Mailbox;
/// fn require_sync<T: Sync>(_: &T) {}
/// let mut slots = [None::<u8>];
/// let mailbox = Mailbox::new(&mut slots).unwrap();
/// let (_sender, receiver) = mailbox.split().unwrap();
/// require_sync(&receiver);
/// ```
/// Two receives cannot simultaneously borrow this half:
/// ```compile_fail
/// use hibana_quic::mailbox::Mailbox;
/// let mut slots = [None::<u8>];
/// let mailbox = Mailbox::new(&mut slots).unwrap();
/// let (_sender, mut receiver) = mailbox.split().unwrap();
/// let first = receiver.recv();
/// let second = receiver.recv();
/// drop((first, second));
/// ```
pub struct Receiver<'channel, 'storage, T, const N: usize> {
    mailbox: &'channel Mailbox<'storage, T, N>,
}

impl<'storage, T, const N: usize> Receiver<'_, 'storage, T, N> {
    /// Wait for the oldest value, or for closure after the queue drains.
    pub fn recv(&mut self) -> Recv<'_, 'storage, T, N> {
        Recv {
            mailbox: self.mailbox,
            finished: false,
        }
    }

    /// Close publication, release queued values, and wake a blocked sender.
    pub fn close(&mut self) {
        self.mailbox.close_receiver();
    }

    /// Whether future receives must return `Closed`. Sender closure alone does
    /// not make this true while buffered values remain.
    pub fn is_closed(&self) -> bool {
        let state = self.mailbox.state.borrow();
        !state.receiver_open || (!state.sender_open && state.len == 0)
    }
}

impl<T, const N: usize> Drop for Receiver<'_, '_, T, N> {
    fn drop(&mut self) {
        self.mailbox.close_receiver();
    }
}

/// An unpublished send owns its value and borrows the unique sender.
#[must_use = "send futures do nothing until polled"]
pub struct Send<'operation, 'storage, T, const N: usize> {
    mailbox: &'operation Mailbox<'storage, T, N>,
    value: Option<T>,
    finished: bool,
}

// No pinned projection of `value` is ever exposed: moving a !Unpin message out
// on publication, cancellation, or failure is part of the API's contract.
impl<T, const N: usize> Unpin for Send<'_, '_, T, N> {}

impl<T, const N: usize> Future for Send<'_, '_, T, N> {
    type Output = Result<(), SendError<T>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        assert!(!this.finished, "completed mailbox send polled again");
        // Clone before borrowing: a RawWaker clone is arbitrary user code.
        let mut current_waker = Some(cx.waker().clone());
        let (result, old_waker, receiver_waker) = {
            let mut state = this.mailbox.state.borrow_mut();
            if !state.sender_open || !state.receiver_open {
                this.finished = true;
                (
                    Poll::Ready(Err(SendError(
                        this.value.take().expect("unpublished value"),
                    ))),
                    state.sender_waker.take(),
                    None,
                )
            } else if state.len < N {
                let index = (state.head + state.len) % N;
                debug_assert!(state.slots[index].is_none());
                state.slots[index] = this.value.take();
                state.len += 1;
                this.finished = true;
                (
                    Poll::Ready(Ok(())),
                    state.sender_waker.take(),
                    state.receiver_waker.take(),
                )
            } else {
                let old = core::mem::replace(&mut state.sender_waker, current_waker.take());
                (Poll::Pending, old, None)
            }
        };
        drop(old_waker);
        drop(current_waker);
        if let Some(waker) = receiver_waker {
            waker.wake();
        }
        result
    }
}

impl<T, const N: usize> Drop for Send<'_, '_, T, N> {
    fn drop(&mut self) {
        let waker = { self.mailbox.state.borrow_mut().sender_waker.take() };
        drop(waker);
        // `value`, if still present, is dropped after this body without a borrow.
    }
}

/// A pending receive borrows the unique consumer and owns no queued value.
#[must_use = "receive futures do nothing until polled"]
pub struct Recv<'operation, 'storage, T, const N: usize> {
    mailbox: &'operation Mailbox<'storage, T, N>,
    finished: bool,
}

impl<T, const N: usize> Future for Recv<'_, '_, T, N> {
    type Output = Result<T, Closed>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        assert!(!this.finished, "completed mailbox receive polled again");
        let mut current_waker = Some(cx.waker().clone());
        let (result, old_waker, sender_waker) = {
            let mut state = this.mailbox.state.borrow_mut();
            if !state.receiver_open {
                this.finished = true;
                (Poll::Ready(Err(Closed)), state.receiver_waker.take(), None)
            } else if let Some(value) = state.pop() {
                this.finished = true;
                (
                    Poll::Ready(Ok(value)),
                    state.receiver_waker.take(),
                    state.sender_waker.take(),
                )
            } else if !state.sender_open {
                this.finished = true;
                (Poll::Ready(Err(Closed)), state.receiver_waker.take(), None)
            } else {
                let old = core::mem::replace(&mut state.receiver_waker, current_waker.take());
                (Poll::Pending, old, None)
            }
        };
        drop(old_waker);
        drop(current_waker);
        if let Some(waker) = sender_waker {
            waker.wake();
        }
        result
    }
}

impl<T, const N: usize> Drop for Recv<'_, '_, T, N> {
    fn drop(&mut self) {
        let waker = { self.mailbox.state.borrow_mut().receiver_waker.take() };
        drop(waker);
    }
}
