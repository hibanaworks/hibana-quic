//! Caller-owned, single-connection Hibana carrier.
//!
//! This queue carries internal descriptors, never network UDP packets. Each
//! binding is one connection generation. All handles and the runtime have one
//! cooperative owner; this type is deliberately not `Sync`. Closing or dropping
//! a live port quarantines accepted frames and wakes both readers and writers.
//! A new binding can be created only after the old carrier has been dropped.

use core::{
    cell::RefCell,
    task::{Context, Poll, Waker},
};
use hibana::runtime::{
    ids::SessionId,
    transport::{FrameHeader, Outgoing, PortOpen, ReceivedFrame, Transport, TransportError},
    wire::Payload,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PortKey {
    session: SessionId,
    lane: u8,
    role: u8,
}

struct Frame<const BYTES: usize> {
    header: [u8; 8],
    bytes: [u8; BYTES],
    len: usize,
}
impl<const BYTES: usize> Frame<BYTES> {
    fn matches(&self, key: PortKey) -> bool {
        self.header[..4] == key.session.raw().to_be_bytes()
            && self.header[4] == key.lane
            && self.header[6] == key.role
    }
    fn received(&self) -> ReceivedFrame<'_> {
        ReceivedFrame::framed(
            FrameHeader::from_bytes(self.header),
            Payload::new(&self.bytes[..self.len]),
        )
    }
}

struct PortState {
    key: PortKey,
    send_waker: Option<Waker>,
    recv_waker: Option<Waker>,
}
struct State<const QUEUE: usize, const BYTES: usize, const PORTS: usize> {
    generation: u64,
    bound: bool,
    closed: bool,
    session: SessionId,
    queue: [Option<Frame<BYTES>>; QUEUE],
    len: usize,
    ports: [Option<PortState>; PORTS],
}
impl<const Q: usize, const B: usize, const P: usize> State<Q, B, P> {
    const fn new() -> Self {
        Self {
            generation: 0,
            bound: false,
            closed: true,
            session: SessionId::new(0),
            queue: [const { None }; Q],
            len: 0,
            ports: [const { None }; P],
        }
    }
    fn valid(&self, generation: u64) -> bool {
        self.bound && !self.closed && self.generation == generation
    }
}

/// Fixed caller-owned storage: `QUEUE` queued messages, `BYTES` bytes per
/// message, and `PORTS` simultaneously opened descriptor-derived ports.
/// Each Rx additionally owns one bounded current frame for borrowed delivery
/// and zero-commit requeue. Wakers are supplied by the caller's executor.
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
    pub fn bind(&self, session: SessionId) -> Result<LocalCarrier<'_, Q, B, P>, TransportError> {
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
            state.session = session;
            state.bound = true;
            state.closed = false;
            next
        };
        Ok(LocalCarrier {
            storage: self,
            generation,
        })
    }

    /// Terminally close the active generation, quarantine its queued frames,
    /// and wake parked operations. Later polls report Offline, never Pending.
    pub fn close(&self) {
        let generation = self.state.borrow().generation;
        self.close_generation(generation);
    }
    pub fn queued(&self) -> usize {
        self.state.borrow().len
    }
    pub fn is_closed(&self) -> bool {
        self.state.borrow().closed
    }

    fn close_generation(&self, generation: u64) {
        let mut readers: [Option<Waker>; P] = [const { None }; P];
        let mut writers: [Option<Waker>; P] = [const { None }; P];
        {
            let mut state = self.state.borrow_mut();
            if state.generation != generation || state.closed {
                return;
            }
            state.closed = true;
            state.queue = [const { None }; Q];
            state.len = 0;
            for (index, port) in state.ports.iter_mut().enumerate() {
                if let Some(port) = port {
                    readers[index] = port.recv_waker.take();
                    writers[index] = port.send_waker.take();
                }
            }
        }
        // Never invoke executor callbacks while holding the RefCell borrow.
        for waker in readers.into_iter().chain(writers).flatten() {
            waker.wake();
        }
    }

    fn open_key(&self, key: PortKey, generation: u64) -> Result<usize, TransportError> {
        let mut state = self.state.borrow_mut();
        if !state.valid(generation) || key.session != state.session {
            return Err(TransportError::Offline);
        }
        if state.ports.iter().flatten().any(|port| port.key == key) {
            return Err(TransportError::Failed);
        }
        let index = state
            .ports
            .iter()
            .position(Option::is_none)
            .ok_or(TransportError::Capacity)?;
        state.ports[index] = Some(PortState {
            key,
            send_waker: None,
            recv_waker: None,
        });
        Ok(index)
    }

    fn send_bytes(
        &self,
        token: &PortToken,
        lane: u8,
        target: u8,
        label: u8,
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
        let result;
        {
            let mut state = self.state.borrow_mut();
            if !state.valid(token.generation) {
                return Poll::Ready(Err(TransportError::Offline));
            }
            if lane != token.key.lane || target == token.key.role {
                return Poll::Ready(Err(TransportError::Failed));
            }
            if bytes.len() > B {
                return Poll::Ready(Err(TransportError::Capacity));
            }
            if state.len == Q {
                old_waker = state.ports[index]
                    .as_mut()
                    .expect("live port")
                    .send_waker
                    .replace(next_waker.take().expect("new waker"));
                result = Poll::Pending;
            } else {
                old_waker = state.ports[index]
                    .as_mut()
                    .expect("live port")
                    .send_waker
                    .take();
                let sid = token.key.session.raw().to_be_bytes();
                let mut frame = Frame {
                    header: [
                        sid[0],
                        sid[1],
                        sid[2],
                        sid[3],
                        lane,
                        token.key.role,
                        target,
                        label,
                    ],
                    bytes: [0; B],
                    len: bytes.len(),
                };
                frame.bytes[..bytes.len()].copy_from_slice(bytes);
                let offset = state.len;
                state.queue[offset] = Some(frame);
                state.len += 1;
                for port in state.ports.iter_mut().flatten() {
                    if port.key.session == token.key.session
                        && port.key.lane == lane
                        && port.key.role == target
                    {
                        receiver = port.recv_waker.take();
                        break;
                    }
                }
                result = Poll::Ready(Ok(()));
            }
        }
        drop(old_waker);
        drop(next_waker);
        if let Some(waker) = receiver {
            waker.wake();
        }
        if result.is_pending() && !self.state.borrow().valid(token.generation) {
            return Poll::Ready(Err(TransportError::Offline));
        }
        result
    }
}

/// Borrowed transport for one connection. Not Clone: a connection has one local
/// runtime owner. Construct with [`CarrierStorage::bind`].
pub struct LocalCarrier<'s, const Q: usize, const B: usize, const P: usize> {
    storage: &'s CarrierStorage<Q, B, P>,
    generation: u64,
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
    restore: bool,
}
impl<const Q: usize, const B: usize, const P: usize> Drop for Sender<'_, Q, B, P> {
    fn drop(&mut self) {
        if self.token.index.is_ok() {
            self.storage.close_generation(self.token.generation);
        }
    }
}
impl<const Q: usize, const B: usize, const P: usize> Drop for Receiver<'_, Q, B, P> {
    fn drop(&mut self) {
        if self.token.index.is_ok() {
            self.storage.close_generation(self.token.generation);
        }
    }
}

impl<const Q: usize, const B: usize, const P: usize> Transport for LocalCarrier<'_, Q, B, P> {
    type Tx<'a>
        = Sender<'a, Q, B, P>
    where
        Self: 'a;
    type Rx<'a>
        = Receiver<'a, Q, B, P>
    where
        Self: 'a;

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
                restore: false,
            },
        )
    }
    fn poll_send<'a, 'f>(
        &self,
        tx: &'a mut Sender<'a, Q, B, P>,
        outgoing: Outgoing<'f>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), TransportError>>
    where
        'a: 'f,
    {
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
    fn cancel_send<'a>(&self, tx: &'a mut Sender<'a, Q, B, P>) {
        self.cancel_current(tx);
    }
    fn poll_recv<'a>(
        &'a self,
        rx: &'a mut Self::Rx<'a>,
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
                .and_then(|index| state.ports[index].as_mut())
                .and_then(|port| port.send_waker.take())
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
            rx.restore = false;
            return Poll::Ready(Err(TransportError::Offline));
        }
        if rx.restore {
            rx.restore = false;
            return Poll::Ready(Ok(rx
                .current
                .as_ref()
                .expect("requeued current frame")
                .received()));
        }
        rx.current = None;
        let mut next_waker = Some(cx.waker().clone());
        let old_waker;
        let mut writers: [Option<Waker>; P] = [const { None }; P];
        {
            let mut state = self.storage.state.borrow_mut();
            if !state.valid(rx.token.generation) {
                return Poll::Ready(Err(TransportError::Offline));
            }
            if let Some(offset) = state.queue[..state.len].iter().position(|frame| {
                frame
                    .as_ref()
                    .is_some_and(|frame| frame.matches(rx.token.key))
            }) {
                rx.current = state.queue[offset].take();
                for i in offset..state.len - 1 {
                    state.queue[i] = state.queue[i + 1].take();
                }
                state.len -= 1;
                old_waker = state.ports[index]
                    .as_mut()
                    .expect("live port")
                    .recv_waker
                    .take();
                for (index, port) in state.ports.iter_mut().enumerate() {
                    if let Some(port) = port {
                        writers[index] = port.send_waker.take();
                    }
                }
            } else {
                old_waker = state.ports[index]
                    .as_mut()
                    .expect("live port")
                    .recv_waker
                    .replace(next_waker.take().expect("new waker"));
            }
        }
        drop(old_waker);
        drop(next_waker);
        for waker in writers.into_iter().flatten() {
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
        if !self.storage.state.borrow().valid(rx.token.generation) {
            return Err(TransportError::Offline);
        }
        if rx.current.is_none() || rx.restore {
            return Err(TransportError::Failed);
        }
        rx.restore = true;
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
            restore: false,
        }
    }

    #[test]
    fn requeue_is_same_handle_fifo_and_not_duplicate_commit() {
        let storage = CarrierStorage::<2, 8, 4>::new();
        let carrier = storage.bind(SessionId::new(7)).unwrap();
        let tx = token(&carrier, key(0, 0));
        let mut rx = receiver(&carrier, key(1, 0));
        let mut cx = Context::from_waker(Waker::noop());
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
        carrier.restore_current(&mut rx).unwrap();
        assert_eq!(
            carrier.restore_current(&mut rx),
            Err(TransportError::Failed),
            "one restore per delivery"
        );
        let restored = match carrier.recv_current(&mut rx, &mut cx) {
            Poll::Ready(Ok(frame)) => frame.payload().as_bytes()[0],
            _ => panic!("restored frame"),
        };
        assert_eq!(restored, 10);
        let second = match carrier.recv_current(&mut rx, &mut cx) {
            Poll::Ready(Ok(frame)) => frame.payload().as_bytes()[0],
            _ => panic!("second frame"),
        };
        assert_eq!(second, 20);
        assert!(carrier.recv_current(&mut rx, &mut cx).is_pending());
    }

    #[test]
    fn close_quarantines_queued_and_restored_frames_and_wakes_both_sides() {
        let storage = CarrierStorage::<1, 8, 4>::new();
        let carrier = storage.bind(SessionId::new(7)).unwrap();
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
            let carrier = storage.bind(SessionId::new(7)).unwrap();
            stale = token(&carrier, key(0, 0));
            assert!(
                storage.bind(SessionId::new(7)).is_err(),
                "one live carrier owner"
            );
            assert!(matches!(
                storage.send_bytes(&stale, 0, 1, 4, &[99], &mut cx),
                Poll::Ready(Ok(()))
            ));
        }
        assert_eq!(storage.queued(), 0);
        let carrier = storage.bind(SessionId::new(7)).unwrap();
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
        let carrier = storage.bind(SessionId::new(7)).unwrap();
        let other_carrier = foreign.bind(SessionId::new(7)).unwrap();
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
            Err(TransportError::Failed)
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
        let carrier = storage.bind(SessionId::new(7)).unwrap();
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
    fn dropping_a_port_wakes_peer_and_does_not_close_another_connection() {
        let storage = CarrierStorage::<2, 8, 4>::new();
        let other = CarrierStorage::<2, 8, 4>::new();
        let carrier = storage.bind(SessionId::new(7)).unwrap();
        let _other_carrier = other.bind(SessionId::new(7)).unwrap();
        let tx = Sender {
            storage: &storage,
            token: token(&carrier, key(0, 0)),
        };
        let mut rx = receiver(&carrier, key(1, 0));
        let (count, reader) = waker();
        let mut cx = Context::from_waker(&reader);
        assert!(carrier.recv_current(&mut rx, &mut cx).is_pending());
        drop(tx);
        assert_eq!(count.0.load(Ordering::Relaxed), 1);
        assert!(matches!(
            carrier.recv_current(&mut rx, &mut cx),
            Poll::Ready(Err(TransportError::Offline))
        ));
        assert!(!other.is_closed());
    }
    #[test]
    fn bounded_capacity_and_latest_reader_waker_are_observable() {
        assert!(
            CarrierStorage::<0, 8, 4>::new()
                .bind(SessionId::new(7))
                .is_err()
        );
        assert!(
            CarrierStorage::<2, 8, 0>::new()
                .bind(SessionId::new(7))
                .is_err()
        );
        let storage = CarrierStorage::<2, 1, 2>::new();
        let carrier = storage.bind(SessionId::new(7)).unwrap();
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
    struct CloseOnDrop;
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
            let carrier = storage.bind(SessionId::new(7)).unwrap();
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
            let carrier = storage.bind(SessionId::new(7)).unwrap();
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
