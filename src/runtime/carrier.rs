//! Caller-owned, single-connection Hibana carrier.
//!
//! This queue carries internal descriptors, never network UDP packets. Each
//! binding is one connection generation. All handles and the runtime have one
//! cooperative owner; this type is deliberately not `Sync`. The carrier owns
//! logical inboxes for the run; individual handles may be replaced after a loan.
//! Closing or dropping the carrier quarantines frames and wakes parked I/O.
//! A new binding can be created only after the old carrier has been dropped.

use core::{
    cell::{Cell, RefCell},
    num::NonZeroUsize,
    task::{Context, Poll, Waker},
};
use hibana::runtime::{
    ids::SessionId,
    transport::{
        EndpointBinding, FrameHeader, Outgoing, PortOpen, ReceivedFrame, Transport, TransportError,
    },
    wire::Payload,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PortKey {
    session: SessionId,
    lane: u8,
    role: u8,
}

pub struct Frame<const BYTES: usize> {
    header: [u8; 9],
    bytes: [u8; BYTES],
    len: usize,
}
impl<const BYTES: usize> Frame<BYTES> {
    pub fn header(&self) -> [u8; 9] {
        self.header
    }
    pub fn payload(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
    fn received(&self) -> ReceivedFrame<'_> {
        ReceivedFrame::framed(
            FrameHeader::from_bytes(self.header),
            Payload::new(&self.bytes[..self.len]),
        )
    }
}

struct SendWaiter {
    // Circular FIFO links index the existing sender slots in State::ports.
    destination: usize,
    previous: usize,
    next: usize,
    waker: Waker,
}

struct PortState<const QUEUE: usize, const BYTES: usize> {
    key: PortKey,
    queue: [Option<Frame<BYTES>>; QUEUE],
    len: usize,
    restored: Option<Frame<BYTES>>,
    send_waiter: Option<SendWaiter>,
    blocked_senders: Option<NonZeroUsize>,
    recv_waker: Option<Waker>,
}
impl<const Q: usize, const B: usize> PortState<Q, B> {
    fn pop(&mut self) -> Option<Frame<B>> {
        if self.len == 0 {
            return None;
        }
        let frame = self.queue[0].take();
        for index in 1..self.len {
            self.queue[index - 1] = self.queue[index].take();
        }
        self.len -= 1;
        frame
    }
}
struct State<const QUEUE: usize, const BYTES: usize, const PORTS: usize> {
    generation: u64,
    peer: Option<(u8, u8)>,
    peer_waker: Option<Waker>,
    peer_input_waker: Option<Waker>,
    outgoing_open: bool,
    bound: bool,
    closed: bool,
    session: SessionId,
    ports: [Option<PortState<QUEUE, BYTES>>; PORTS],
}
impl<const Q: usize, const B: usize, const P: usize> State<Q, B, P> {
    const fn new() -> Self {
        Self {
            generation: 0,
            peer: None,
            peer_waker: None,
            peer_input_waker: None,
            outgoing_open: true,
            bound: false,
            closed: true,
            session: SessionId::new(0),
            ports: [const { None }; P],
        }
    }
    fn valid(&self, generation: u64) -> bool {
        self.bound && !self.closed && self.generation == generation
    }

    fn open_key(&mut self, key: PortKey) -> Result<usize, TransportError> {
        if let Some(index) = self
            .ports
            .iter()
            .position(|port| port.as_ref().is_some_and(|port| port.key == key))
        {
            return Ok(index);
        }
        let index = self
            .ports
            .iter()
            .position(Option::is_none)
            .ok_or(TransportError::Capacity)?;
        self.ports[index] = Some(PortState {
            key,
            queue: [const { None }; Q],
            len: 0,
            restored: None,
            send_waiter: None,
            blocked_senders: None,
            recv_waker: None,
        });
        Ok(index)
    }

    fn take_send_waiter(&mut self, index: usize) -> Option<Waker> {
        let waiter = self.ports[index].as_mut()?.send_waiter.take()?;
        let head = &mut self.ports[waiter.destination]
            .as_mut()
            .expect("waited inbox")
            .blocked_senders;
        if waiter.next == index {
            *head = None;
        } else {
            if head.is_some_and(|head| head.get() - 1 == index) {
                *head = NonZeroUsize::new(waiter.next + 1);
            }
            self.ports[waiter.previous]
                .as_mut()
                .expect("previous sender")
                .send_waiter
                .as_mut()
                .expect("linked sender")
                .next = waiter.next;
            self.ports[waiter.next]
                .as_mut()
                .expect("next sender")
                .send_waiter
                .as_mut()
                .expect("linked sender")
                .previous = waiter.previous;
        }
        Some(waiter.waker)
    }

    fn replace_send_waiter(
        &mut self,
        index: usize,
        destination: usize,
        waker: Waker,
    ) -> Option<Waker> {
        let old = self.take_send_waiter(index);
        let head = self.ports[destination]
            .as_ref()
            .expect("waited inbox")
            .blocked_senders;
        let (previous, next) = match head {
            Some(head) => {
                let head = head.get() - 1;
                let tail = self.ports[head]
                    .as_ref()
                    .expect("first sender")
                    .send_waiter
                    .as_ref()
                    .expect("linked sender")
                    .previous;
                self.ports[tail]
                    .as_mut()
                    .expect("last sender")
                    .send_waiter
                    .as_mut()
                    .expect("linked sender")
                    .next = index;
                self.ports[head]
                    .as_mut()
                    .expect("first sender")
                    .send_waiter
                    .as_mut()
                    .expect("linked sender")
                    .previous = index;
                (tail, head)
            }
            None => {
                self.ports[destination]
                    .as_mut()
                    .expect("waited inbox")
                    .blocked_senders = NonZeroUsize::new(index + 1);
                (index, index)
            }
        };
        self.ports[index]
            .as_mut()
            .expect("sender inbox")
            .send_waiter = Some(SendWaiter {
            destination,
            previous,
            next,
            waker,
        });
        old
    }
}

/// Fixed caller-owned storage: `QUEUE` messages per logical inbox, `BYTES`
/// bytes per message, and `PORTS` descriptor-derived inboxes.
/// Each logical inbox also holds one uncommitted frame returned by `requeue`.
/// Each Rx owns its last borrowed delivery. Neither buffer tracks a holder or
/// protocol progress. Wakers are supplied by the caller's executor.
pub struct CarrierStorage<const QUEUE: usize, const BYTES: usize, const PORTS: usize> {
    state: RefCell<State<QUEUE, BYTES, PORTS>>,
}
impl<const Q: usize, const B: usize, const P: usize> Default for CarrierStorage<Q, B, P> {
    fn default() -> Self {
        Self::new()
    }
}
impl<const Q: usize, const B: usize, const P: usize> CarrierStorage<Q, B, P> {
    pub const fn new() -> Self {
        Self {
            state: RefCell::new(State::new()),
        }
    }

    /// Begin a fresh generation. The same numeric SessionId may safely be used
    /// after a previous carrier is dropped: old frames and waiters are gone.
    /// `bindings` identifies the integration's unique initial issuers. It does
    /// not record current holders, and rebinding does not replenish issuance.
    pub fn bind<'s>(
        &'s self,
        session: SessionId,
        bindings: &'s [(u8, &'s EndpointBinding)],
    ) -> Result<LocalCarrier<'s, Q, B, P>, TransportError> {
        if bindings.iter().enumerate().any(|(index, (role, _))| {
            bindings[..index]
                .iter()
                .any(|(previous, _)| previous == role)
        }) {
            return Err(TransportError::Failed);
        }
        let generation = {
            let mut state = self.state.borrow_mut();
            if state.bound {
                return Err(TransportError::Failed);
            }
            if Q == 0 || P == 0 {
                return Err(TransportError::Capacity);
            }
            let next = state
                .generation
                .checked_add(1)
                .ok_or(TransportError::Failed)?;
            state.generation = next;
            state.peer = None;
            state.peer_waker = None;
            state.peer_input_waker = None;
            state.outgoing_open = true;
            state.session = session;
            state.bound = true;
            state.closed = false;
            next
        };
        Ok(LocalCarrier {
            storage: self,
            generation,
            bindings,
        })
    }

    /// Terminally close the active generation, quarantine its queued frames,
    /// and wake parked operations. Later polls report Offline, never Pending.
    pub fn close(&self) {
        let generation = self.state.borrow().generation;
        self.close_generation(generation);
    }
    pub fn queued(&self) -> usize {
        let state = self.state.borrow();
        state
            .ports
            .iter()
            .flatten()
            .map(|port| port.len + usize::from(port.restored.is_some()))
            .sum()
    }
    pub fn is_closed(&self) -> bool {
        self.state.borrow().closed
    }

    fn close_generation(&self, generation: u64) {
        let peer;
        let peer_input;
        let mut readers: [Option<Waker>; P] = [const { None }; P];
        let mut writers: [Option<Waker>; P] = [const { None }; P];
        {
            let mut state = self.state.borrow_mut();
            if state.generation != generation || state.closed {
                return;
            }
            state.closed = true;
            peer = state.peer_waker.take();
            peer_input = state.peer_input_waker.take();
            for (index, port) in state.ports.iter_mut().enumerate() {
                if let Some(port) = port {
                    port.queue = [const { None }; Q];
                    port.len = 0;
                    port.restored = None;
                    readers[index] = port.recv_waker.take();
                    writers[index] = port.send_waiter.take().map(|waiter| waiter.waker);
                    port.blocked_senders = None;
                }
            }
        }
        // Never invoke executor callbacks while holding the RefCell borrow.
        for waker in readers
            .iter_mut()
            .chain(writers.iter_mut())
            .filter_map(Option::take)
            .chain([peer, peer_input].into_iter().flatten())
        {
            waker.wake();
        }
    }

    fn open_key(&self, key: PortKey, generation: u64) -> Result<usize, TransportError> {
        let mut state = self.state.borrow_mut();
        if !state.valid(generation) || key.session != state.session {
            return Err(TransportError::Offline);
        }
        state.open_key(key)
    }

    fn wake_capacity_waiters(&self, destination: usize, generation: u64) {
        loop {
            let waker = {
                let mut state = self.state.borrow_mut();
                if !state.valid(generation) {
                    return;
                }
                let inbox = state.ports[destination].as_ref().expect("freed inbox");
                if inbox.len == Q {
                    return;
                }
                let Some(sender) = inbox.blocked_senders else {
                    return;
                };
                state
                    .take_send_waiter(sender.get() - 1)
                    .expect("blocked sender")
            };
            waker.wake();
        }
    }

    fn send_bytes(
        &self,
        token: &PortToken,
        lane: u8,
        target: u8,
        label: u16,
        bytes: &[u8],
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), TransportError>> {
        let index = match token.index {
            Ok(index) => index,
            Err(error) => return Poll::Ready(Err(error)),
        };
        // clone/drop/wake may execute caller code, so do all outside the borrow.
        let mut next_waker = Some(cx.waker().clone());
        let old_waker;
        let mut receiver = None;
        let mut peer = None;
        let result;
        {
            let mut state = self.state.borrow_mut();
            if !state.valid(token.generation) {
                return Poll::Ready(Err(TransportError::Offline));
            }
            if !state.outgoing_open && state.peer.is_some_and(|(local, _)| local == token.key.role)
            {
                return Poll::Ready(Err(TransportError::Offline));
            }
            if lane != token.key.lane || target == token.key.role {
                return Poll::Ready(Err(TransportError::Failed));
            }
            if bytes.len() > B {
                return Poll::Ready(Err(TransportError::Capacity));
            }
            let destination = match state.open_key(PortKey {
                session: token.key.session,
                lane,
                role: target,
            }) {
                Ok(index) => index,
                Err(error) => return Poll::Ready(Err(error)),
            };
            if state.ports[destination]
                .as_ref()
                .expect("destination inbox")
                .len
                == Q
            {
                old_waker = state.replace_send_waiter(
                    index,
                    destination,
                    next_waker.take().expect("new waker"),
                );
                result = Poll::Pending;
            } else {
                old_waker = state.take_send_waiter(index);
                let sid = token.key.session.raw().to_be_bytes();
                let label = label.to_be_bytes();
                let mut frame = Frame {
                    header: [
                        sid[0],
                        sid[1],
                        sid[2],
                        sid[3],
                        lane,
                        token.key.role,
                        target,
                        label[0],
                        label[1],
                    ],
                    bytes: [0; B],
                    len: bytes.len(),
                };
                frame.bytes[..bytes.len()].copy_from_slice(bytes);
                let inbox = state.ports[destination]
                    .as_mut()
                    .expect("destination inbox");
                inbox.queue[inbox.len] = Some(frame);
                inbox.len += 1;
                receiver = inbox.recv_waker.take();
                peer = state.peer_waker.take();
                result = Poll::Ready(Ok(()));
            }
        }
        drop(old_waker);
        drop(next_waker);
        for waker in [receiver, peer].into_iter().flatten() {
            waker.wake();
        }
        if result.is_pending() && !self.state.borrow().valid(token.generation) {
            return Poll::Ready(Err(TransportError::Offline));
        }
        result
    }
}

/// Owner of one connection run. Runtimes borrow it as their `Transport`, so a
/// holder's runtime may end without closing another holder's logical inbox.
/// Construct with [`CarrierStorage::bind`].
pub struct LocalCarrier<'s, const Q: usize, const B: usize, const P: usize> {
    storage: &'s CarrierStorage<Q, B, P>,
    generation: u64,
    bindings: &'s [(u8, &'s EndpointBinding)],
}
impl<const Q: usize, const B: usize, const P: usize> Drop for LocalCarrier<'_, Q, B, P> {
    fn drop(&mut self) {
        self.storage.close_generation(self.generation);
        let retired = {
            let mut state = self.storage.state.borrow_mut();
            if state.generation == self.generation {
                state.bound = false;
                core::mem::replace(&mut state.ports, [const { None }; P])
            } else {
                [const { None }; P]
            }
        };
        drop(retired);
    }
}
struct PortToken {
    key: PortKey,
    generation: u64,
    index: Result<usize, TransportError>,
}
/// Descriptor-bound sending handle, managed by Hibana.
pub struct Sender<'s, const Q: usize, const B: usize, const P: usize> {
    storage: &'s CarrierStorage<Q, B, P>,
    token: PortToken,
}
/// Descriptor-bound receiving handle with one owned current-frame slot.
pub struct Receiver<'s, const Q: usize, const B: usize, const P: usize> {
    storage: &'s CarrierStorage<Q, B, P>,
    token: PortToken,
    current: Option<Frame<B>>,
}

impl<const Q: usize, const B: usize, const P: usize> Transport for &LocalCarrier<'_, Q, B, P> {
    type Tx<'a>
        = Sender<'a, Q, B, P>
    where
        Self: 'a;
    type Rx<'a>
        = Receiver<'a, Q, B, P>
    where
        Self: 'a;

    fn initial_endpoint_binding(&self, session: SessionId, role: u8) -> Option<&EndpointBinding> {
        let state = self.storage.state.borrow();
        if state.session != session || state.generation != self.generation || state.closed {
            return None;
        }
        drop(state);
        self.bindings
            .iter()
            .find_map(|(bound_role, binding)| (*bound_role == role).then_some(*binding))
    }

    fn open<'a>(&'a self, port: PortOpen) -> (Self::Tx<'a>, Self::Rx<'a>) {
        let key = PortKey {
            session: port.session_id(),
            lane: port.lane(),
            role: port.local_role(),
        };
        let index = self.storage.open_key(key, self.generation);
        (
            Sender {
                storage: self.storage,
                token: PortToken {
                    key,
                    generation: self.generation,
                    index,
                },
            },
            Receiver {
                storage: self.storage,
                token: PortToken {
                    key,
                    generation: self.generation,
                    index,
                },
                current: None,
            },
        )
    }
    fn poll_send<'f>(
        &self,
        tx: &mut Sender<'_, Q, B, P>,
        outgoing: Outgoing<'f>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), TransportError>> {
        if !core::ptr::eq(self.storage, tx.storage) || self.generation != tx.token.generation {
            return Poll::Ready(Err(TransportError::Failed));
        }
        self.storage.send_bytes(
            &tx.token,
            outgoing.lane(),
            outgoing.target_role(),
            outgoing.frame_label().raw(),
            outgoing.payload().as_bytes(),
            cx,
        )
    }
    fn cancel_send(&self, tx: &mut Sender<'_, Q, B, P>) {
        self.cancel_current(tx);
    }
    fn poll_recv<'a>(
        &'a self,
        rx: &'a mut Receiver<'_, Q, B, P>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<ReceivedFrame<'a>, TransportError>> {
        self.recv_current(rx, cx)
    }
    fn requeue<'a>(&self, rx: &mut Receiver<'a, Q, B, P>) -> Result<(), TransportError> {
        self.restore_current(rx)
    }
}

impl<const Q: usize, const B: usize, const P: usize> LocalCarrier<'_, Q, B, P> {
    fn cancel_current(&self, tx: &mut Sender<'_, Q, B, P>) {
        if !core::ptr::eq(self.storage, tx.storage) || self.generation != tx.token.generation {
            return;
        }
        let old = {
            let mut state = self.storage.state.borrow_mut();
            if state.generation != tx.token.generation {
                return;
            }
            tx.token
                .index
                .ok()
                .and_then(|index| state.take_send_waiter(index))
        };
        drop(old); // Pending never copied or retained any payload bytes.
    }
    fn recv_current<'a>(
        &self,
        rx: &'a mut Receiver<'_, Q, B, P>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<ReceivedFrame<'a>, TransportError>> {
        if !core::ptr::eq(self.storage, rx.storage) || self.generation != rx.token.generation {
            return Poll::Ready(Err(TransportError::Failed));
        }
        let index = match rx.token.index {
            Ok(index) => index,
            Err(error) => return Poll::Ready(Err(error)),
        };
        if !self.storage.state.borrow().valid(rx.token.generation) {
            rx.current = None;
            return Poll::Ready(Err(TransportError::Offline));
        }
        rx.current = None;
        let mut next_waker = Some(cx.waker().clone());
        let old_waker;
        let mut peer_input = None;
        let released;
        {
            let mut state = self.storage.state.borrow_mut();
            if !state.valid(rx.token.generation) {
                return Poll::Ready(Err(TransportError::Offline));
            }
            if let Some(frame) = state.ports[index]
                .as_mut()
                .expect("live inbox")
                .restored
                .take()
            {
                rx.current = Some(frame);
                old_waker = state.ports[index]
                    .as_mut()
                    .expect("live inbox")
                    .recv_waker
                    .take();
                released = None;
            } else if let Some(frame) = state.ports[index].as_mut().expect("live inbox").pop() {
                rx.current = Some(frame);
                peer_input = state.peer_input_waker.take();
                old_waker = state.ports[index]
                    .as_mut()
                    .expect("live port")
                    .recv_waker
                    .take();
                released = Some(index);
            } else {
                old_waker = state.ports[index]
                    .as_mut()
                    .expect("live port")
                    .recv_waker
                    .replace(next_waker.take().expect("new waker"));
                released = None;
            }
        }
        drop(old_waker);
        drop(next_waker);
        if let Some(destination) = released {
            self.storage
                .wake_capacity_waiters(destination, rx.token.generation);
        }
        if let Some(waker) = peer_input {
            waker.wake();
        }
        if !self.storage.state.borrow().valid(rx.token.generation) {
            rx.current = None;
            return Poll::Ready(Err(TransportError::Offline));
        }
        match rx.current.as_ref() {
            Some(frame) => Poll::Ready(Ok(frame.received())),
            None => Poll::Pending,
        }
    }
    fn restore_current(&self, rx: &mut Receiver<'_, Q, B, P>) -> Result<(), TransportError> {
        if !core::ptr::eq(self.storage, rx.storage) || self.generation != rx.token.generation {
            return Err(TransportError::Failed);
        }
        let index = rx.token.index?;
        let wake = {
            let mut state = self.storage.state.borrow_mut();
            if !state.valid(rx.token.generation) {
                return Err(TransportError::Offline);
            }
            let inbox = state.ports[index].as_mut().expect("live inbox");
            if inbox.restored.is_some() {
                return Err(TransportError::Failed);
            }
            inbox.restored = Some(rx.current.take().ok_or(TransportError::Failed)?);
            inbox.recv_waker.take()
        };
        if let Some(waker) = wake {
            waker.wake();
        }
        Ok(())
    }
}

/// A connection-scoped bridge used by network drivers, not application locals.
/// It admits only the configured remote role and preserves frame metadata.
pub struct Peer<'a, const Q: usize, const B: usize, const P: usize> {
    storage: &'a CarrierStorage<Q, B, P>,
    generation: u64,
    local: u8,
    remote: u8,
    next: Cell<usize>,
}
impl<const Q: usize, const B: usize, const P: usize> CarrierStorage<Q, B, P> {
    pub fn peer(&self, local: u8, remote: u8) -> Result<Peer<'_, Q, B, P>, TransportError> {
        let mut state = self.state.borrow_mut();
        if state.peer.is_some() || local == remote || !state.bound || state.closed {
            return Err(TransportError::Failed);
        }
        state.peer = Some((local, remote));
        Ok(Peer {
            storage: self,
            generation: state.generation,
            local,
            remote,
            next: Cell::new(0),
        })
    }
}
impl<const Q: usize, const B: usize, const P: usize> Peer<'_, Q, B, P> {
    /// Seal local publication after the application local completes. Already
    /// committed frames remain owned by the driver until they have been drained.
    pub fn finish(&self) {
        let old = {
            let mut state = self.storage.state.borrow_mut();
            if !state.valid(self.generation) {
                return;
            }
            state.outgoing_open = false;
            state.peer_waker.take()
        };
        if let Some(waker) = old {
            waker.wake();
        }
    }
    pub fn poll_outgoing(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Frame<B>>, TransportError>> {
        let mut next = Some(cx.waker().clone());
        let old;
        let mut peer_input = None;
        let released;
        let result;
        {
            let mut state = self.storage.state.borrow_mut();
            if !state.valid(self.generation) {
                return Poll::Ready(Err(TransportError::Offline));
            }
            if let Some(index) =
                (0..P)
                    .map(|offset| (self.next.get() + offset) % P)
                    .find(|&index| {
                        state.ports[index]
                            .as_ref()
                            .is_some_and(|port| port.key.role == self.remote && port.len != 0)
                    })
            {
                let frame = state.ports[index]
                    .as_mut()
                    .expect("outgoing inbox")
                    .pop()
                    .expect("queued frame");
                if frame.header[5] != self.local {
                    return Poll::Ready(Err(TransportError::Failed));
                }
                self.next.set((index + 1) % P);
                peer_input = state.peer_input_waker.take();
                old = state.peer_waker.take();
                released = Some(index);
                result = Poll::Ready(Ok(Some(frame)));
            } else if !state.outgoing_open {
                old = state.peer_waker.take();
                released = None;
                result = Poll::Ready(Ok(None));
            } else {
                old = state.peer_waker.replace(next.take().expect("new waker"));
                released = None;
                result = Poll::Pending;
            }
        }
        drop(old);
        drop(next);
        if let Some(destination) = released {
            self.storage
                .wake_capacity_waiters(destination, self.generation);
        }
        if let Some(waker) = peer_input {
            waker.wake();
        }
        result
    }
    pub fn poll_incoming(
        &self,
        header: [u8; 9],
        payload: &[u8],
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), TransportError>> {
        let next = cx.waker().clone();
        let old;
        let full;
        {
            let mut state = self.storage.state.borrow_mut();
            if !state.valid(self.generation) {
                return Poll::Ready(Err(TransportError::Offline));
            }
            if header[..4] != state.session.raw().to_be_bytes()
                || header[5] != self.remote
                || header[6] != self.local
            {
                return Poll::Ready(Err(TransportError::Failed));
            }
            if payload.len() > B {
                return Poll::Ready(Err(TransportError::Capacity));
            }
            let session = state.session;
            let index = match state.open_key(PortKey {
                session,
                lane: header[4],
                role: self.local,
            }) {
                Ok(index) => index,
                Err(error) => return Poll::Ready(Err(error)),
            };
            full = state.ports[index].as_ref().expect("incoming inbox").len == Q;
            old = if full {
                state.peer_input_waker.replace(next)
            } else {
                state.peer_input_waker.take()
            };
        }
        drop(old);
        if !self.storage.state.borrow().valid(self.generation) {
            return Poll::Ready(Err(TransportError::Offline));
        }
        if full {
            Poll::Pending
        } else {
            Poll::Ready(self.incoming(header, payload))
        }
    }
    /// The caller supplies one authenticated, complete application frame.
    /// Capacity or identity failures abort the connection; bytes are never truncated.
    pub fn incoming(&self, header: [u8; 9], payload: &[u8]) -> Result<(), TransportError> {
        let reader;
        {
            let mut state = self.storage.state.borrow_mut();
            if !state.valid(self.generation) {
                return Err(TransportError::Offline);
            }
            if header[..4] != state.session.raw().to_be_bytes()
                || header[5] != self.remote
                || header[6] != self.local
            {
                return Err(TransportError::Failed);
            }
            if payload.len() > B {
                return Err(TransportError::Capacity);
            }
            let session = state.session;
            let index = state.open_key(PortKey {
                session,
                lane: header[4],
                role: self.local,
            })?;
            let inbox = state.ports[index].as_mut().expect("incoming inbox");
            if inbox.len == Q {
                return Err(TransportError::Capacity);
            }
            let mut frame = Frame {
                header,
                bytes: [0; B],
                len: payload.len(),
            };
            frame.bytes[..payload.len()].copy_from_slice(payload);
            inbox.queue[inbox.len] = Some(frame);
            inbox.len += 1;
            reader = inbox.recv_waker.take();
        }
        if let Some(waker) = reader {
            waker.wake();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::Wake,
    };

    struct Counter(AtomicUsize);
    impl Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn waker() -> (Arc<Counter>, Waker) {
        let count = Arc::new(Counter(AtomicUsize::new(0)));
        (count.clone(), Waker::from(count))
    }
    fn key(role: u8, lane: u8) -> PortKey {
        PortKey {
            session: SessionId::new(7),
            lane,
            role,
        }
    }
    fn token<const Q: usize, const B: usize, const P: usize>(
        carrier: &LocalCarrier<'_, Q, B, P>,
        key: PortKey,
    ) -> PortToken {
        PortToken {
            key,
            generation: carrier.generation,
            index: carrier.storage.open_key(key, carrier.generation),
        }
    }
    fn receiver<'a, const Q: usize, const B: usize, const P: usize>(
        carrier: &'a LocalCarrier<'_, Q, B, P>,
        key: PortKey,
    ) -> Receiver<'a, Q, B, P> {
        Receiver {
            storage: carrier.storage,
            token: token(carrier, key),
            current: None,
        }
    }

    #[test]
    fn capacity_release_wakes_all_and_only_that_inboxs_senders() {
        let storage = CarrierStorage::<1, 8, 6>::new();
        let carrier = storage.bind(SessionId::new(7), &[]).unwrap();
        let first = token(&carrier, key(0, 0));
        let second = token(&carrier, key(1, 0));
        let other = token(&carrier, key(0, 1));
        let mut target = receiver(&carrier, key(2, 0));
        let mut other_target = receiver(&carrier, key(2, 1));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(
            storage
                .send_bytes(&first, 0, 2, 4, &[10], &mut cx)
                .is_ready()
        );
        assert!(
            storage
                .send_bytes(&other, 1, 2, 4, &[20], &mut cx)
                .is_ready()
        );
        let (first_count, first_waker) = waker();
        let (second_count, second_waker) = waker();
        let (other_count, other_waker) = waker();
        for (tx, lane, wake) in [
            (&first, 0, &first_waker),
            (&second, 0, &second_waker),
            (&other, 1, &other_waker),
        ] {
            assert!(
                storage
                    .send_bytes(tx, lane, 2, 4, &[30], &mut Context::from_waker(wake))
                    .is_pending()
            );
        }
        assert!(matches!(
            carrier.recv_current(&mut target, &mut cx),
            Poll::Ready(Ok(_))
        ));
        assert_eq!(first_count.0.load(Ordering::Relaxed), 1);
        assert_eq!(second_count.0.load(Ordering::Relaxed), 1);
        assert_eq!(other_count.0.load(Ordering::Relaxed), 0);
        assert!(carrier.recv_current(&mut target, &mut cx).is_pending());
        assert_eq!(other_count.0.load(Ordering::Relaxed), 0);
        assert!(matches!(
            carrier.recv_current(&mut other_target, &mut cx),
            Poll::Ready(Ok(_))
        ));
        assert_eq!(other_count.0.load(Ordering::Relaxed), 1);
        std::eprintln!(
            "CarrierStorage<1,32,128>: {} bytes",
            core::mem::size_of::<CarrierStorage<1, 32, 128>>()
        );
    }

    #[test]
    fn alias_repoll_replaces_the_waiter_and_moves_its_destination() {
        let storage = CarrierStorage::<1, 8, 4>::new();
        let carrier = storage.bind(SessionId::new(7), &[]).unwrap();
        let first = token(&carrier, key(0, 0));
        let alias = token(&carrier, key(0, 0));
        let mut left = receiver(&carrier, key(1, 0));
        let mut right = receiver(&carrier, key(2, 0));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(
            storage
                .send_bytes(&first, 0, 1, 4, &[10], &mut cx)
                .is_ready()
        );
        assert!(
            storage
                .send_bytes(&first, 0, 2, 4, &[20], &mut cx)
                .is_ready()
        );
        let (old_count, old_waker) = waker();
        let (new_count, new_waker) = waker();
        assert!(
            storage
                .send_bytes(&first, 0, 1, 4, &[30], &mut Context::from_waker(&old_waker))
                .is_pending()
        );
        assert!(
            storage
                .send_bytes(&alias, 0, 2, 4, &[40], &mut Context::from_waker(&new_waker))
                .is_pending()
        );
        assert!(matches!(
            carrier.recv_current(&mut left, &mut cx),
            Poll::Ready(Ok(_))
        ));
        assert_eq!(old_count.0.load(Ordering::Relaxed), 0);
        assert_eq!(new_count.0.load(Ordering::Relaxed), 0);
        assert!(matches!(
            carrier.recv_current(&mut right, &mut cx),
            Poll::Ready(Ok(_))
        ));
        assert_eq!(old_count.0.load(Ordering::Relaxed), 0);
        assert_eq!(new_count.0.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn cancel_unlinks_the_middle_head_and_tail_without_losing_other_senders() {
        let storage = CarrierStorage::<1, 8, 4>::new();
        let carrier = storage.bind(SessionId::new(7), &[]).unwrap();
        let mut senders = [0, 1, 2].map(|role| Sender {
            storage: &storage,
            token: token(&carrier, key(role, 0)),
        });
        let mut target = receiver(&carrier, key(3, 0));
        let counts = [waker(), waker(), waker()];
        let mut cx = Context::from_waker(Waker::noop());
        for cancel in [[1, 0], [0, 2]] {
            assert!(
                storage
                    .send_bytes(&senders[0].token, 0, 3, 4, &[10], &mut cx)
                    .is_ready()
            );
            for (sender, (_, wake)) in senders.iter().zip(&counts) {
                assert!(
                    storage
                        .send_bytes(
                            &sender.token,
                            0,
                            3,
                            4,
                            &[20],
                            &mut Context::from_waker(wake)
                        )
                        .is_pending()
                );
            }
            carrier.cancel_current(&mut senders[cancel[0]]);
            carrier.cancel_current(&mut senders[cancel[1]]);
            assert!(matches!(
                carrier.recv_current(&mut target, &mut cx),
                Poll::Ready(Ok(_))
            ));
        }
        assert_eq!(counts[0].0.0.load(Ordering::Relaxed), 0);
        assert_eq!(counts[1].0.0.load(Ordering::Relaxed), 1);
        assert_eq!(counts[2].0.0.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn peer_drain_wakes_only_senders_for_the_drained_queue() {
        let storage = CarrierStorage::<1, 8, 4>::new();
        let carrier = storage.bind(SessionId::new(7), &[]).unwrap();
        let first = token(&carrier, key(0, 0));
        let second = token(&carrier, key(0, 1));
        let peer = storage.peer(0, 1).unwrap();
        let mut cx = Context::from_waker(Waker::noop());
        assert!(
            storage
                .send_bytes(&first, 0, 1, 4, &[10], &mut cx)
                .is_ready()
        );
        assert!(
            storage
                .send_bytes(&second, 1, 1, 4, &[20], &mut cx)
                .is_ready()
        );
        let (first_count, first_waker) = waker();
        let (second_count, second_waker) = waker();
        assert!(
            storage
                .send_bytes(
                    &first,
                    0,
                    1,
                    4,
                    &[30],
                    &mut Context::from_waker(&first_waker)
                )
                .is_pending()
        );
        assert!(
            storage
                .send_bytes(
                    &second,
                    1,
                    1,
                    4,
                    &[40],
                    &mut Context::from_waker(&second_waker)
                )
                .is_pending()
        );
        let Poll::Ready(Ok(Some(frame))) = peer.poll_outgoing(&mut cx) else {
            panic!("first outgoing frame")
        };
        assert_eq!(frame.header()[4], 0);
        assert_eq!(first_count.0.load(Ordering::Relaxed), 1);
        assert_eq!(second_count.0.load(Ordering::Relaxed), 0);
        let Poll::Ready(Ok(Some(frame))) = peer.poll_outgoing(&mut cx) else {
            panic!("second outgoing frame")
        };
        assert_eq!(frame.header()[4], 1);
        assert_eq!(second_count.0.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn network_peer_preserves_frames_and_seals_without_dropping_committed_data() {
        let storage = CarrierStorage::<2, 8, 4>::new();
        let carrier = storage.bind(SessionId::new(7), &[]).unwrap();
        let tx = token(&carrier, key(0, 0));
        let peer = storage.peer(0, 1).unwrap();
        let (count, wake) = waker();
        let mut cx = Context::from_waker(&wake);
        assert!(peer.poll_outgoing(&mut cx).is_pending());
        assert!(matches!(
            storage.send_bytes(&tx, 0, 1, 0x1234, &[10], &mut cx),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(count.0.load(Ordering::Relaxed), 1);
        peer.finish();
        let Poll::Ready(Ok(Some(frame))) = peer.poll_outgoing(&mut cx) else {
            panic!("committed frame lost");
        };
        assert_eq!(frame.header(), [0, 0, 0, 7, 0, 0, 1, 0x12, 0x34]);
        assert_eq!(frame.payload(), [10]);
        assert!(matches!(peer.poll_outgoing(&mut cx), Poll::Ready(Ok(None))));
        assert!(matches!(
            storage.send_bytes(&tx, 0, 1, 4, &[20], &mut cx),
            Poll::Ready(Err(TransportError::Offline))
        ));
    }
    #[test]
    fn network_peer_rejects_wrong_identity_and_obeys_receive_restore() {
        let storage = CarrierStorage::<2, 8, 4>::new();
        let carrier = storage.bind(SessionId::new(7), &[]).unwrap();
        let mut rx = receiver(&carrier, key(0, 0));
        let peer = storage.peer(0, 1).unwrap();
        assert!(storage.peer(0, 1).is_err());
        assert!(peer.incoming([0, 0, 0, 8, 0, 1, 0, 0, 4], &[9]).is_err());
        assert!(peer.incoming([0, 0, 0, 7, 0, 2, 0, 0, 4], &[9]).is_err());
        assert!(peer.incoming([0, 0, 0, 7, 0, 1, 2, 0, 4], &[9]).is_err());
        assert!(peer.incoming([0, 0, 0, 7, 0, 1, 0, 0, 4], &[9; 9]).is_err());
        peer.incoming([0, 0, 0, 7, 0, 1, 0, 0, 4], &[9]).unwrap();
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            carrier.recv_current(&mut rx, &mut cx),
            Poll::Ready(Ok(_))
        ));
        carrier.restore_current(&mut rx).unwrap();
        let Poll::Ready(Ok(frame)) = carrier.recv_current(&mut rx, &mut cx) else {
            panic!("restore lost frame");
        };
        assert_eq!(frame.payload().as_bytes(), [9]);
        assert!(carrier.recv_current(&mut rx, &mut cx).is_pending());
        storage.close();
        assert!(peer.incoming([0, 0, 0, 7, 0, 1, 0, 0, 4], &[9]).is_err());
        assert!(matches!(
            peer.poll_outgoing(&mut cx),
            Poll::Ready(Err(TransportError::Offline))
        ));
    }
    #[test]
    fn requeue_preserves_fifo_across_replacement_handles_with_a_full_queue() {
        let storage = CarrierStorage::<2, 8, 4>::new();
        let carrier = storage.bind(SessionId::new(7), &[]).unwrap();
        let tx = token(&carrier, key(0, 0));
        let mut cx = Context::from_waker(Waker::noop());
        let mut replacement = {
            let mut rx = receiver(&carrier, key(1, 0));
            assert!(matches!(
                storage.send_bytes(&tx, 0, 1, 4, &[10], &mut cx),
                Poll::Ready(Ok(()))
            ));
            assert!(matches!(
                storage.send_bytes(&tx, 0, 1, 4, &[20], &mut cx),
                Poll::Ready(Ok(()))
            ));
            let first = match carrier.recv_current(&mut rx, &mut cx) {
                Poll::Ready(Ok(frame)) => frame.payload().as_bytes()[0],
                _ => panic!("first frame"),
            };
            assert_eq!(first, 10);
            assert!(matches!(
                storage.send_bytes(&tx, 0, 1, 4, &[30], &mut cx),
                Poll::Ready(Ok(()))
            ));
            carrier.restore_current(&mut rx).unwrap();
            assert_eq!(storage.queued(), 3);
            assert_eq!(
                carrier.restore_current(&mut rx),
                Err(TransportError::Failed),
                "one restore per delivery"
            );
            receiver(&carrier, key(1, 0))
        };
        let restored = match carrier.recv_current(&mut replacement, &mut cx) {
            Poll::Ready(Ok(frame)) => frame.payload().as_bytes()[0],
            _ => panic!("restored frame"),
        };
        assert_eq!(restored, 10);
        let second = match carrier.recv_current(&mut replacement, &mut cx) {
            Poll::Ready(Ok(frame)) => frame.payload().as_bytes()[0],
            _ => panic!("second frame"),
        };
        assert_eq!(second, 20);
        let third = match carrier.recv_current(&mut replacement, &mut cx) {
            Poll::Ready(Ok(frame)) => frame.payload().as_bytes()[0],
            _ => panic!("third frame"),
        };
        assert_eq!(third, 30);
        assert!(carrier.recv_current(&mut replacement, &mut cx).is_pending());
    }

    #[test]
    fn requeue_wakes_a_waiting_replacement_receiver() {
        let storage = CarrierStorage::<1, 8, 4>::new();
        let carrier = storage.bind(SessionId::new(7), &[]).unwrap();
        let tx = token(&carrier, key(0, 0));
        let mut replacement = receiver(&carrier, key(1, 0));
        let mut idle = Context::from_waker(Waker::noop());
        let (wakes, reader) = waker();
        {
            let mut previous = receiver(&carrier, key(1, 0));
            assert!(matches!(
                storage.send_bytes(&tx, 0, 1, 4, &[10], &mut idle),
                Poll::Ready(Ok(()))
            ));
            assert!(matches!(
                carrier.recv_current(&mut previous, &mut idle),
                Poll::Ready(Ok(_))
            ));
            assert!(
                carrier
                    .recv_current(&mut replacement, &mut Context::from_waker(&reader))
                    .is_pending()
            );
            carrier.restore_current(&mut previous).unwrap();
            assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
        }
        let Poll::Ready(Ok(frame)) = carrier.recv_current(&mut replacement, &mut idle) else {
            panic!("replacement lost the uncommitted frame");
        };
        assert_eq!(frame.payload().as_bytes(), [10]);
        assert!(
            carrier
                .recv_current(&mut replacement, &mut idle)
                .is_pending()
        );
        assert_eq!(storage.queued(), 0);
    }

    #[test]
    fn close_quarantines_queued_and_restored_frames_and_wakes_both_sides() {
        let storage = CarrierStorage::<1, 8, 4>::new();
        let carrier = storage.bind(SessionId::new(7), &[]).unwrap();
        let tx = token(&carrier, key(0, 0));
        let mut rx = receiver(&carrier, key(1, 0));
        let mut other = receiver(&carrier, key(2, 1));
        let mut idle = Context::from_waker(Waker::noop());
        assert!(matches!(
            storage.send_bytes(&tx, 0, 1, 4, &[10], &mut idle),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            carrier.recv_current(&mut rx, &mut idle),
            Poll::Ready(Ok(_))
        ));
        carrier.restore_current(&mut rx).unwrap();
        assert!(matches!(
            storage.send_bytes(&tx, 0, 1, 4, &[20], &mut idle),
            Poll::Ready(Ok(()))
        ));
        let (writes, writer) = waker();
        let (reads, reader) = waker();
        assert!(
            storage
                .send_bytes(&tx, 0, 1, 4, &[30], &mut Context::from_waker(&writer))
                .is_pending()
        );
        assert!(
            carrier
                .recv_current(&mut other, &mut Context::from_waker(&reader))
                .is_pending()
        );
        storage.close();
        assert_eq!(storage.queued(), 0);
        assert_eq!(writes.0.load(Ordering::Relaxed), 1);
        assert_eq!(reads.0.load(Ordering::Relaxed), 1);
        assert!(matches!(
            carrier.recv_current(&mut rx, &mut idle),
            Poll::Ready(Err(TransportError::Offline))
        ));
        assert!(matches!(
            carrier.recv_current(&mut other, &mut idle),
            Poll::Ready(Err(TransportError::Offline))
        ));
        assert!(matches!(
            storage.send_bytes(&tx, 0, 1, 4, &[40], &mut idle),
            Poll::Ready(Err(TransportError::Offline))
        ));
        storage.close();
        assert_eq!(writes.0.load(Ordering::Relaxed), 1, "closure is idempotent");
    }

    #[test]
    fn new_binding_separates_generations_and_retired_ids_do_not_replay() {
        let storage = CarrierStorage::<2, 8, 4>::new();
        let mut cx = Context::from_waker(Waker::noop());
        let stale;
        {
            let carrier = storage.bind(SessionId::new(7), &[]).unwrap();
            stale = token(&carrier, key(0, 0));
            assert!(
                storage.bind(SessionId::new(7), &[]).is_err(),
                "one live carrier owner"
            );
            assert!(matches!(
                storage.send_bytes(&stale, 0, 1, 4, &[99], &mut cx),
                Poll::Ready(Ok(()))
            ));
        }
        assert_eq!(storage.queued(), 0);
        let carrier = storage.bind(SessionId::new(7), &[]).unwrap();
        let mut rx = receiver(&carrier, key(1, 0));
        assert!(
            carrier.recv_current(&mut rx, &mut cx).is_pending(),
            "old queued bytes must not leak"
        );
        assert!(matches!(
            storage.send_bytes(&stale, 0, 1, 4, &[99], &mut cx),
            Poll::Ready(Err(TransportError::Offline))
        ));
        let fresh = token(&carrier, key(0, 0));
        assert!(matches!(
            storage.send_bytes(&fresh, 0, 1, 4, &[11], &mut cx),
            Poll::Ready(Ok(()))
        ));
        let value = match carrier.recv_current(&mut rx, &mut cx) {
            Poll::Ready(Ok(frame)) => frame.payload().as_bytes()[0],
            _ => panic!("fresh frame"),
        };
        assert_eq!(value, 11);
    }

    #[test]
    fn bound_roles_lanes_sessions_and_foreign_handles_cannot_cross() {
        let storage = CarrierStorage::<2, 8, 4>::new();
        let foreign = CarrierStorage::<2, 8, 4>::new();
        let carrier = storage.bind(SessionId::new(7), &[]).unwrap();
        let other_carrier = foreign.bind(SessionId::new(7), &[]).unwrap();
        let tx = token(&carrier, key(0, 0));
        let mut right = receiver(&carrier, key(1, 0));
        let mut wrong_lane = receiver(&carrier, key(1, 1));
        let wrong_session = PortKey {
            session: SessionId::new(8),
            lane: 0,
            role: 2,
        };
        assert_eq!(
            storage.open_key(wrong_session, carrier.generation),
            Err(TransportError::Offline)
        );
        assert_eq!(
            storage.open_key(key(0, 0), carrier.generation),
            tx.index,
            "a replacement handle uses the same logical inbox"
        );
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            storage.send_bytes(&tx, 1, 1, 4, &[10], &mut cx),
            Poll::Ready(Err(TransportError::Failed))
        ));
        assert!(matches!(
            storage.send_bytes(&tx, 0, 1, 4, &[10], &mut cx),
            Poll::Ready(Ok(()))
        ));
        assert!(carrier.recv_current(&mut wrong_lane, &mut cx).is_pending());
        assert!(matches!(
            other_carrier.recv_current(&mut right, &mut cx),
            Poll::Ready(Err(TransportError::Failed))
        ));
        let value = match carrier.recv_current(&mut right, &mut cx) {
            Poll::Ready(Ok(frame)) => frame.payload().as_bytes()[0],
            _ => panic!("correctly bound frame"),
        };
        assert_eq!(value, 10);
    }

    #[test]
    fn pending_payload_is_not_retained_and_cancel_drops_waiter() {
        let storage = CarrierStorage::<1, 8, 4>::new();
        let carrier = storage.bind(SessionId::new(7), &[]).unwrap();
        let mut tx = Sender {
            storage: &storage,
            token: token(&carrier, key(0, 0)),
        };
        let mut rx = receiver(&carrier, key(1, 0));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            storage.send_bytes(&tx.token, 0, 1, 4, &[10], &mut cx),
            Poll::Ready(Ok(()))
        ));
        let (count, writer) = waker();
        {
            let scratch = [20_u8; 4];
            assert!(
                storage
                    .send_bytes(
                        &tx.token,
                        0,
                        1,
                        4,
                        &scratch,
                        &mut Context::from_waker(&writer)
                    )
                    .is_pending()
            );
        } // old scratch storage no longer exists
        carrier.cancel_current(&mut tx);
        assert!(matches!(
            carrier.recv_current(&mut rx, &mut cx),
            Poll::Ready(Ok(_))
        ));
        assert_eq!(
            count.0.load(Ordering::Relaxed),
            0,
            "cancelled sender is not woken"
        );
        assert!(
            carrier.recv_current(&mut rx, &mut cx).is_pending(),
            "cancelled Pending bytes never become visible"
        );
        let replacement = [30_u8; 4];
        assert!(matches!(
            storage.send_bytes(&tx.token, 0, 1, 4, &replacement, &mut cx),
            Poll::Ready(Ok(()))
        ));
        match carrier.recv_current(&mut rx, &mut cx) {
            Poll::Ready(Ok(frame)) => assert_eq!(frame.payload().as_bytes(), &replacement),
            _ => panic!("fresh scratch payload"),
        }
    }

    #[test]
    fn handles_do_not_close_the_run_but_carrier_drop_wakes_parked_io() {
        let storage = CarrierStorage::<2, 8, 4>::new();
        let other = CarrierStorage::<2, 8, 4>::new();
        let carrier = storage.bind(SessionId::new(7), &[]).unwrap();
        let _other_carrier = other.bind(SessionId::new(7), &[]).unwrap();
        let (count, reader) = waker();
        let mut cx = Context::from_waker(&reader);
        {
            let mut rx = receiver(&carrier, key(1, 0));
            {
                let _tx = Sender {
                    storage: &storage,
                    token: token(&carrier, key(0, 0)),
                };
                assert!(carrier.recv_current(&mut rx, &mut cx).is_pending());
            }
            assert_eq!(count.0.load(Ordering::Relaxed), 0);
            assert!(!storage.is_closed());
            assert!(carrier.recv_current(&mut rx, &mut cx).is_pending());
        }
        drop(carrier);
        assert!(storage.is_closed());
        assert_eq!(count.0.load(Ordering::Relaxed), 1);
        assert!(!other.is_closed());
    }
    #[test]
    fn bounded_capacity_and_latest_reader_waker_are_observable() {
        assert!(
            CarrierStorage::<0, 8, 4>::new()
                .bind(SessionId::new(7), &[])
                .is_err()
        );
        assert!(
            CarrierStorage::<2, 8, 0>::new()
                .bind(SessionId::new(7), &[])
                .is_err()
        );
        let storage = CarrierStorage::<2, 1, 2>::new();
        let carrier = storage.bind(SessionId::new(7), &[]).unwrap();
        let tx = token(&carrier, key(0, 0));
        let mut rx = receiver(&carrier, key(1, 0));
        assert_eq!(
            storage.open_key(key(2, 0), carrier.generation),
            Err(TransportError::Capacity)
        );
        let (old_count, old_waker) = waker();
        let (new_count, new_waker) = waker();
        assert!(
            carrier
                .recv_current(&mut rx, &mut Context::from_waker(&old_waker))
                .is_pending()
        );
        assert!(
            carrier
                .recv_current(&mut rx, &mut Context::from_waker(&new_waker))
                .is_pending()
        );
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            storage.send_bytes(&tx, 0, 1, 4, &[10, 11], &mut cx),
            Poll::Ready(Err(TransportError::Capacity))
        ));
        assert_eq!(storage.queued(), 0);
        assert!(matches!(
            storage.send_bytes(&tx, 0, 1, 4, &[12], &mut cx),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(old_count.0.load(Ordering::Relaxed), 0);
        assert_eq!(new_count.0.load(Ordering::Relaxed), 1);
    }
    std::thread_local! {
        static CALLBACK_STORAGE: CarrierStorage<1, 8, 4> = const { CarrierStorage::new() };
    }

    struct RefillAndParkOnWake {
        token: PortToken,
        repolled: Arc<Counter>,
    }

    impl Wake for RefillAndParkOnWake {
        fn wake(self: Arc<Self>) {
            CALLBACK_STORAGE.with(|storage| {
                assert!(matches!(
                    storage.send_bytes(
                        &self.token,
                        0,
                        3,
                        4,
                        &[20],
                        &mut Context::from_waker(Waker::noop())
                    ),
                    Poll::Ready(Ok(()))
                ));
                let wake = Waker::from(self.repolled.clone());
                assert!(
                    storage
                        .send_bytes(&self.token, 0, 3, 4, &[21], &mut Context::from_waker(&wake))
                        .is_pending()
                );
            });
        }
    }

    #[test]
    fn a_refilling_callback_keeps_other_waiters_until_capacity_is_released_again() {
        CALLBACK_STORAGE.with(|storage| {
            let carrier = storage.bind(SessionId::new(7), &[]).unwrap();
            let first = token(&carrier, key(0, 0));
            let second = token(&carrier, key(1, 0));
            let mut target = receiver(&carrier, key(3, 0));
            let mut cx = Context::from_waker(Waker::noop());
            assert!(matches!(
                storage.send_bytes(&first, 0, 3, 4, &[10], &mut cx),
                Poll::Ready(Ok(()))
            ));
            let (repolled, _) = waker();
            let wake = Waker::from(Arc::new(RefillAndParkOnWake {
                token: token(&carrier, key(0, 0)),
                repolled: repolled.clone(),
            }));
            let (second_count, second_waker) = waker();
            assert!(
                storage
                    .send_bytes(&first, 0, 3, 4, &[11], &mut Context::from_waker(&wake))
                    .is_pending()
            );
            assert!(
                storage
                    .send_bytes(
                        &second,
                        0,
                        3,
                        4,
                        &[12],
                        &mut Context::from_waker(&second_waker)
                    )
                    .is_pending()
            );
            match carrier.recv_current(&mut target, &mut cx) {
                Poll::Ready(Ok(frame)) => assert_eq!(frame.payload().as_bytes(), &[10]),
                _ => panic!("first frame"),
            }
            assert_eq!(second_count.0.load(Ordering::Relaxed), 0);
            assert_eq!(repolled.0.load(Ordering::Relaxed), 0);
            match carrier.recv_current(&mut target, &mut cx) {
                Poll::Ready(Ok(frame)) => assert_eq!(frame.payload().as_bytes(), &[20]),
                _ => panic!("callback's refill"),
            }
            assert_eq!(second_count.0.load(Ordering::Relaxed), 1);
            assert_eq!(repolled.0.load(Ordering::Relaxed), 1);
        });
    }

    struct CloseOnWake;

    impl Wake for CloseOnWake {
        fn wake(self: Arc<Self>) {
            CALLBACK_STORAGE.with(CarrierStorage::close);
        }
    }

    #[test]
    fn a_closing_writer_callback_stops_delivery_and_wakes_remaining_waiters_once() {
        CALLBACK_STORAGE.with(|storage| {
            let carrier = storage.bind(SessionId::new(7), &[]).unwrap();
            let first = token(&carrier, key(0, 0));
            let second = token(&carrier, key(1, 0));
            let mut target = receiver(&carrier, key(3, 0));
            let mut cx = Context::from_waker(Waker::noop());
            assert!(matches!(
                storage.send_bytes(&first, 0, 3, 4, &[10], &mut cx),
                Poll::Ready(Ok(()))
            ));
            let close = Waker::from(Arc::new(CloseOnWake));
            let (second_count, second_waker) = waker();
            assert!(
                storage
                    .send_bytes(&first, 0, 3, 4, &[11], &mut Context::from_waker(&close))
                    .is_pending()
            );
            assert!(
                storage
                    .send_bytes(
                        &second,
                        0,
                        3,
                        4,
                        &[12],
                        &mut Context::from_waker(&second_waker)
                    )
                    .is_pending()
            );
            assert!(matches!(
                carrier.recv_current(&mut target, &mut cx),
                Poll::Ready(Err(TransportError::Offline))
            ));
            assert_eq!(second_count.0.load(Ordering::Relaxed), 1);
            assert!(storage.is_closed());
            assert_eq!(storage.queued(), 0);
        });
    }

    #[test]
    fn stale_capacity_notifications_leave_new_generation_waiters_parked() {
        let storage = CarrierStorage::<1, 8, 4>::new();
        let previous = storage.bind(SessionId::new(7), &[]).unwrap();
        let previous_generation = previous.generation;
        drop(previous);
        let carrier = storage.bind(SessionId::new(7), &[]).unwrap();
        let sender = token(&carrier, key(0, 0));
        let destination = storage.open_key(key(1, 0), carrier.generation).unwrap();
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            storage.send_bytes(&sender, 0, 1, 4, &[10], &mut cx),
            Poll::Ready(Ok(()))
        ));
        let (count, wake) = waker();
        assert!(
            storage
                .send_bytes(&sender, 0, 1, 4, &[11], &mut Context::from_waker(&wake))
                .is_pending()
        );
        // A pop releases capacity before the caller invokes any wake callbacks.
        assert!(
            storage.state.borrow_mut().ports[destination]
                .as_mut()
                .unwrap()
                .pop()
                .is_some()
        );
        storage.wake_capacity_waiters(destination, previous_generation);
        assert_eq!(count.0.load(Ordering::Relaxed), 0);
        storage.wake_capacity_waiters(destination, carrier.generation);
        assert_eq!(count.0.load(Ordering::Relaxed), 1);
    }

    struct CloseOnDrop;
    #[allow(
        clippy::manual_noop_waker,
        reason = "The regression requires reentrant Drop; Waker::noop has no destructor."
    )]
    impl Wake for CloseOnDrop {
        fn wake(self: Arc<Self>) {}
    }
    impl Drop for CloseOnDrop {
        fn drop(&mut self) {
            CALLBACK_STORAGE.with(CarrierStorage::close);
        }
    }

    #[test]
    fn replacing_reader_waker_allows_reentrant_close_without_delivering_after_close() {
        CALLBACK_STORAGE.with(|storage| {
            let carrier = storage.bind(SessionId::new(7), &[]).unwrap();
            let mut rx = receiver(&carrier, key(1, 0));
            let old = Waker::from(Arc::new(CloseOnDrop));
            assert!(
                carrier
                    .recv_current(&mut rx, &mut Context::from_waker(&old))
                    .is_pending()
            );
            drop(old); // the port now holds the last reference
            assert!(matches!(
                carrier.recv_current(&mut rx, &mut Context::from_waker(Waker::noop())),
                Poll::Ready(Err(TransportError::Offline))
            ));
        });
    }

    #[test]
    fn replacing_writer_waker_allows_reentrant_close_without_pending_forever() {
        CALLBACK_STORAGE.with(|storage| {
            let carrier = storage.bind(SessionId::new(7), &[]).unwrap();
            let tx = token(&carrier, key(0, 0));
            let mut cx = Context::from_waker(Waker::noop());
            assert!(matches!(
                storage.send_bytes(&tx, 0, 1, 4, &[10], &mut cx),
                Poll::Ready(Ok(()))
            ));
            let old = Waker::from(Arc::new(CloseOnDrop));
            assert!(
                storage
                    .send_bytes(&tx, 0, 1, 4, &[20], &mut Context::from_waker(&old))
                    .is_pending()
            );
            drop(old);
            assert!(matches!(
                storage.send_bytes(&tx, 0, 1, 4, &[20], &mut cx),
                Poll::Ready(Err(TransportError::Offline))
            ));
            assert_eq!(storage.queued(), 0);
        });
    }
}
