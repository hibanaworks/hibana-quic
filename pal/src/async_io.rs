//! Bounded Linux readiness reactor for caller-owned async role futures.
//!
//! The caller owns this reactor, its fixed socket/timer registries, and its
//! pinned root future. [`Reactor::block_on`] uses a real UnixStream-backed waker:
//! every wake (including another thread's wake) interrupts `poll`. It
//! never sleeps after checking a userspace flag without a kernel wake source.
//! Socket interests exist only while an operation actually returned WouldBlock;
//! timers use the nearest monotonic deadline, rounded UP to milliseconds.
//!
//! Resource boundary: construction allocates exactly one Arc for Wake ownership
//! and creates two kernel descriptors. Each registered socket uses the existing
//! UDP adapter's one ancillary-buffer allocation. The fixed arrays, operation
//! futures, waker clones, timer dispatch, and executor polls allocate nothing.
//! Native sendmsg ancillary storage is on the stack, so sending does not allocate.
//! Socket setup still allocates; this is not a no_alloc transport boundary.
//! No unsafe code, additional threads, or hidden protocol state machines live
//! here. Always-ready actors must use the core runtime's cooperative yield at a
//! bounded work boundary; a single Future::poll cannot be preempted.

use crate::sys::{self, PollBatch, PollFd};
use crate::udp::{Codepoint, Received, UdpMetadataSocket};
use hibana_quic::quic::path::Address;
use std::io::{Read, Write};
use std::os::{fd::AsRawFd, unix::net::UnixStream};
use std::{
    cell::{Cell, RefCell},
    future::{Future, poll_fn},
    io,
    net::{SocketAddr, UdpSocket},
    pin::{Pin, pin},
    sync::{
        Arc,
        atomic::{AtomicI32, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
    time::{Duration, Instant},
};

struct Signal {
    reader: UnixStream,
    writer: UnixStream,
    error: AtomicI32,
}
impl Signal {
    fn notify(&self) {
        loop {
            match (&self.writer).write(&[1]) {
                Ok(_) => return,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    self.error
                        .store(error.raw_os_error().unwrap_or(5), Ordering::Release);
                    return;
                }
            }
        }
    }
    fn drain(&self) -> io::Result<()> {
        let error = self.error.swap(0, Ordering::AcqRel);
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error));
        }
        // One read drains the entire non-semaphore counter. Do not loop until
        // EAGAIN: a continuously waking producer must not starve socket work.
        match (&self.reader).read(&mut [0; 256]) {
            Ok(0) => Err(io::ErrorKind::BrokenPipe.into()),
            Ok(_) => Ok(()),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}
impl Wake for Signal {
    fn wake(self: Arc<Self>) {
        self.notify();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.notify();
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Statistics {
    pub polls: u64,
    pub waits: u64,
    pub zero_timeout_waits: u64,
    pub socket_events: u64,
    pub timer_events: u64,
    pub wake_events: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SocketKey {
    index: usize,
    generation: u32,
}
impl SocketKey {
    fn token(self) -> u64 {
        (u64::from(self.generation) << 32) | (self.index as u64 + 1)
    }
    fn decode(token: u64) -> Option<Self> {
        let index = token as u32;
        (index != 0).then_some(Self {
            index: index.wrapping_sub(1) as usize,
            generation: (token >> 32) as u32,
        })
    }
}
#[derive(Default)]
struct Interest {
    owner: Option<u64>,
    waker: Option<Waker>,
    armed: bool,
}
struct SocketEntry {
    socket: UdpMetadataSocket,
    read: Interest,
    write: Interest,
    next_operation: u64,
}
struct SocketSlot {
    generation: u32,
    entry: Option<SocketEntry>,
}
#[derive(Clone, Copy)]
struct TimerKey {
    index: usize,
    generation: u64,
}
struct TimerEntry {
    deadline: Instant,
    waker: Waker,
}
struct TimerSlot {
    generation: u64,
    entry: Option<TimerEntry>,
}
struct State<const S: usize, const T: usize> {
    sockets: [SocketSlot; S],
    timers: [TimerSlot; T],
}

/// A single-threaded executor/reactor with fixed maximum socket/timer counts.
/// Futures may be borrowed, `!Send`, and `!Unpin`; its Waker is Send + Sync.
/// Socket and timer exhaustion returns WouldBlock without allocating a queue.
pub struct Reactor<const S: usize, const T: usize> {
    signal: Arc<Signal>,
    state: RefCell<State<S, T>>,
    running: Cell<bool>,
    statistics: Cell<Statistics>,
}
impl<const S: usize, const T: usize> Reactor<S, T> {
    pub fn new() -> io::Result<Self> {
        if S >= u32::MAX as usize {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let (reader, writer) = UnixStream::pair()?;
        reader.set_nonblocking(true)?;
        writer.set_nonblocking(true)?;
        Ok(Self {
            signal: Arc::new(Signal {
                reader,
                writer,
                error: AtomicI32::new(0),
            }),
            state: RefCell::new(State {
                sockets: std::array::from_fn(|_| SocketSlot {
                    generation: 0,
                    entry: None,
                }),
                timers: std::array::from_fn(|_| TimerSlot {
                    generation: 0,
                    entry: None,
                }),
            }),
            running: Cell::new(false),
            statistics: Cell::new(Statistics::default()),
        })
    }
    pub fn statistics(&self) -> Statistics {
        self.statistics.get()
    }
    /// Actual retained native owners, inspected after the root future drops.
    pub fn active_resources(&self) -> (usize, usize) {
        let state = self.state.borrow();
        (
            state
                .sockets
                .iter()
                .filter(|slot| slot.entry.is_some())
                .count(),
            state
                .timers
                .iter()
                .filter(|slot| slot.entry.is_some())
                .count(),
        )
    }
    fn update_statistics(&self, update: impl FnOnce(&mut Statistics)) {
        let mut statistics = self.statistics.get();
        update(&mut statistics);
        self.statistics.set(statistics);
    }

    /// Take ownership of an existing bound, unconnected UDP socket. The socket
    /// is made nonblocking; all datagrams still use UdpMetadataSocket validation.
    /// Wildcard binds retain its actual-destination packet-info requirements.
    pub fn register_udp(&self, socket: UdpSocket) -> io::Result<AsyncUdp<'_, S, T>> {
        if socket.peer_addr().is_ok() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut state = self.state.borrow_mut();
        let (index, slot) = state
            .sockets
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.entry.is_none() && slot.generation < u32::MAX)
            .ok_or(io::ErrorKind::WouldBlock)?;
        socket.set_nonblocking(true)?;
        let socket = UdpMetadataSocket::new(socket)?;
        slot.generation += 1;
        slot.entry = Some(SocketEntry {
            socket,
            read: Interest::default(),
            write: Interest::default(),
            next_operation: 0,
        });
        Ok(AsyncUdp {
            reactor: self,
            key: SocketKey {
                index,
                generation: slot.generation,
            },
        })
    }

    pub fn sleep_until(&self, deadline: Instant) -> Sleep<'_, S, T> {
        Sleep {
            reactor: self,
            deadline,
            key: None,
            finished: false,
        }
    }
    /// Duration overflow is an InvalidInput result, never an immediate timeout.
    pub fn sleep(&self, duration: Duration) -> io::Result<Sleep<'_, S, T>> {
        Ok(self.sleep_until(
            Instant::now()
                .checked_add(duration)
                .ok_or(io::ErrorKind::InvalidInput)?,
        ))
    }

    /// Drive a caller-owned aggregate to completion. Every aggregate sweep is
    /// followed by poll, so self-waking work cannot starve kernel readiness or
    /// due timers. All-idle futures block until readiness, a wake, or a deadline.
    /// A nested call is rejected. Cancellation is ordinary Rust future drop.
    pub fn block_on<F: Future>(&self, future: F) -> io::Result<F::Output> {
        if self.running.replace(true) {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        struct Running<'a>(&'a Cell<bool>);
        impl Drop for Running<'_> {
            fn drop(&mut self) {
                self.0.set(false);
            }
        }
        let _running = Running(&self.running);
        let mut future = pin!(future);
        let waker = Waker::from(Arc::clone(&self.signal));
        let mut context = Context::from_waker(&waker);
        loop {
            // Drain BEFORE polling, never after Pending. Wakes during or after
            // that poll remain readable across the check-then-wait boundary.
            self.signal.drain()?;
            self.update_statistics(|s| s.polls = s.polls.saturating_add(1));
            if let Poll::Ready(result) = future.as_mut().poll(&mut context) {
                return Ok(result);
            }
            self.wait_and_dispatch()?;
        }
    }

    fn timeout(&self, now: Instant) -> i32 {
        let state = self.state.borrow();
        let deadline = state
            .timers
            .iter()
            .filter_map(|slot| slot.entry.as_ref().map(|timer| timer.deadline))
            .min();
        match deadline {
            None => -1,
            Some(deadline) => {
                let nanos = deadline.saturating_duration_since(now).as_nanos();
                nanos.div_ceil(1_000_000).min(i32::MAX as u128) as i32
            }
        }
    }
    fn wait_and_dispatch(&self) -> io::Result<()> {
        let timeout = self.timeout(Instant::now());
        let mut batch = PollBatch {
            wake: PollFd {
                fd: self.signal.reader.as_raw_fd(),
                events: sys::READ,
                revents: 0,
            },
            sockets: [PollFd::EMPTY; S],
        };
        let mut tokens = [0u64; S];
        {
            let state = self.state.borrow();
            for (index, slot) in state.sockets.iter().enumerate() {
                if let Some(entry) = &slot.entry {
                    let events = (if entry.read.armed { sys::READ } else { 0 })
                        | (if entry.write.armed { sys::WRITE } else { 0 });
                    if events != 0 {
                        batch.sockets[index] = PollFd {
                            fd: entry.socket.socket().as_raw_fd(),
                            events,
                            revents: 0,
                        };
                        tokens[index] = SocketKey {
                            index,
                            generation: slot.generation,
                        }
                        .token();
                    }
                }
            }
        }
        self.update_statistics(|s| {
            s.waits = s.waits.saturating_add(1);
            if timeout == 0 {
                s.zero_timeout_waits = s.zero_timeout_waits.saturating_add(1);
            }
        });
        match sys::wait(&mut batch, timeout) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
        if batch.wake.revents != 0 {
            self.update_statistics(|s| s.wake_events = s.wake_events.saturating_add(1));
        }
        for (entry, token) in batch.sockets.iter().zip(tokens) {
            if entry.revents != 0 {
                self.dispatch_socket(token, entry.revents)?;
            }
        }
        let now = Instant::now();
        for index in 0..T {
            let waker = {
                let mut state = self.state.borrow_mut();
                let slot = &mut state.timers[index];
                if slot
                    .entry
                    .as_ref()
                    .is_some_and(|timer| timer.deadline <= now)
                {
                    slot.entry.take().map(|timer| timer.waker)
                } else {
                    None
                }
            };
            if let Some(waker) = waker {
                self.update_statistics(|s| s.timer_events = s.timer_events.saturating_add(1));
                waker.wake();
            }
        }
        Ok(())
    }
    fn socket_entry(state: &mut State<S, T>, key: SocketKey) -> io::Result<&mut SocketEntry> {
        let slot = state
            .sockets
            .get_mut(key.index)
            .ok_or(io::ErrorKind::NotConnected)?;
        if slot.generation != key.generation {
            return Err(io::ErrorKind::NotConnected.into());
        }
        slot.entry
            .as_mut()
            .ok_or_else(|| io::ErrorKind::NotConnected.into())
    }
    fn dispatch_socket(&self, token: u64, flags: i16) -> io::Result<()> {
        let Some(key) = SocketKey::decode(token) else {
            return Ok(());
        };
        let (read, write) = {
            let mut state = self.state.borrow_mut();
            let Ok(entry) = Self::socket_entry(&mut state, key) else {
                return Ok(());
            };
            let terminal = flags & sys::TERMINAL != 0;
            let read = if terminal || flags & sys::READ != 0 {
                entry.read.armed = false;
                entry.read.waker.take()
            } else {
                None
            };
            let write = if terminal || flags & sys::WRITE != 0 {
                entry.write.armed = false;
                entry.write.waker.take()
            } else {
                None
            };
            (read, write)
        };
        // Even an error must release displaced wakers after the registry borrow.
        self.update_statistics(|s| s.socket_events = s.socket_events.saturating_add(1));
        // User wakers are never called with a registry RefCell borrow held.
        if let Some(waker) = read {
            waker.wake();
        }
        if let Some(waker) = write {
            waker.wake();
        }
        Ok(())
    }
    fn poll_io<O>(
        &self,
        key: SocketKey,
        read: bool,
        owner: &mut Option<u64>,
        cx: &mut Context<'_>,
        operation: impl FnOnce(&mut UdpMetadataSocket) -> io::Result<O>,
    ) -> Poll<io::Result<O>> {
        // RawWaker clone/drop callbacks are arbitrary caller code, just like
        // wake. Keep both the incoming clone and displaced ownership outside
        // the registry borrow, including every early error path.
        let mut next_waker = Some(cx.waker().clone());
        let mut old_waker = None;
        let mut interrupted = false;
        let result = (|| {
            let mut state = self.state.borrow_mut();
            let entry = match Self::socket_entry(&mut state, key) {
                Ok(entry) => entry,
                Err(error) => return Poll::Ready(Err(error)),
            };
            let interest = if read {
                &mut entry.read
            } else {
                &mut entry.write
            };
            if let Some(owner) = *owner {
                if interest.owner != Some(owner) {
                    return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
                }
            } else {
                if interest.owner.is_some() {
                    return Poll::Ready(Err(io::ErrorKind::AlreadyExists.into()));
                }
                let Some(next) = entry.next_operation.checked_add(1) else {
                    return Poll::Ready(Err(io::ErrorKind::WouldBlock.into()));
                };
                entry.next_operation = next;
                interest.owner = Some(next);
                *owner = Some(next);
            }
            interest.armed = false;
            old_waker = interest.waker.take();
            let result = operation(&mut entry.socket);
            let interest = if read {
                &mut entry.read
            } else {
                &mut entry.write
            };
            match result {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    interest.armed = true;
                    interest.waker = next_waker.take();
                    Poll::Pending
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    interrupted = true;
                    Poll::Pending
                }
                result => {
                    interest.owner = None;
                    *owner = None;
                    Poll::Ready(result)
                }
            }
        })();
        drop(old_waker);
        drop(next_waker);
        if interrupted {
            cx.waker().wake_by_ref();
        }
        result
    }
    fn cancel_io(&self, key: SocketKey, read: bool, owner: Option<u64>) {
        let Some(owner) = owner else {
            return;
        };
        let old = {
            let mut state = self.state.borrow_mut();
            let Ok(entry) = Self::socket_entry(&mut state, key) else {
                return;
            };
            let interest = if read {
                &mut entry.read
            } else {
                &mut entry.write
            };
            if interest.owner != Some(owner) {
                return;
            }
            core::mem::take(interest)
        };
        drop(old);
    }
    fn remove_socket(&self, key: SocketKey) {
        let entry = {
            let mut state = self.state.borrow_mut();
            let Some(slot) = state.sockets.get_mut(key.index) else {
                return;
            };
            if slot.generation != key.generation {
                return;
            }
            slot.entry.take()
        };
        drop(entry);
    }

    fn cancel_timer(&self, key: TimerKey) {
        let retired = {
            let mut state = self.state.borrow_mut();
            let slot = &mut state.timers[key.index];
            if slot.generation == key.generation {
                slot.entry.take()
            } else {
                None
            }
        };
        drop(retired);
    }
}

/// One owned registered socket. At most one receive and one send may be pending
/// concurrently; a second operation in that direction returns AlreadyExists.
/// The payload remains borrowed until send acceptance/error/cancellation.
pub struct AsyncUdp<'a, const S: usize, const T: usize> {
    reactor: &'a Reactor<S, T>,
    key: SocketKey,
}
impl<const S: usize, const T: usize> AsyncUdp<'_, S, T> {
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        let mut state = self.reactor.state.borrow_mut();
        Reactor::socket_entry(&mut state, self.key)?
            .socket
            .local_addr()
    }
    pub async fn recv_from(&self, bytes: &mut [u8]) -> io::Result<Received> {
        let mut wait = IoWait {
            reactor: self.reactor,
            key: self.key,
            read: true,
            owner: None,
        };
        poll_fn(|cx| {
            self.reactor
                .poll_io(self.key, true, &mut wait.owner, cx, |socket| {
                    socket.recv_from(bytes)
                })
        })
        .await
    }
    pub async fn send_from(
        &self,
        bytes: &[u8],
        address: Address,
        ecn: Codepoint,
    ) -> io::Result<usize> {
        let mut wait = IoWait {
            reactor: self.reactor,
            key: self.key,
            read: false,
            owner: None,
        };
        poll_fn(|cx| {
            self.reactor
                .poll_io(self.key, false, &mut wait.owner, cx, |socket| {
                    socket.send_from(bytes, address, ecn)
                })
        })
        .await
    }
    pub async fn send_to(
        &self,
        bytes: &[u8],
        destination: SocketAddr,
        ecn: Codepoint,
    ) -> io::Result<usize> {
        let mut wait = IoWait {
            reactor: self.reactor,
            key: self.key,
            read: false,
            owner: None,
        };
        poll_fn(|cx| {
            self.reactor
                .poll_io(self.key, false, &mut wait.owner, cx, |socket| {
                    socket.send_to(bytes, destination, ecn)
                })
        })
        .await
    }
}
impl<const S: usize, const T: usize> Drop for AsyncUdp<'_, S, T> {
    fn drop(&mut self) {
        self.reactor.remove_socket(self.key);
    }
}
struct IoWait<'a, const S: usize, const T: usize> {
    reactor: &'a Reactor<S, T>,
    key: SocketKey,
    read: bool,
    owner: Option<u64>,
}
impl<const S: usize, const T: usize> Drop for IoWait<'_, S, T> {
    fn drop(&mut self) {
        self.reactor.cancel_io(self.key, self.read, self.owner);
    }
}

/// One cancel-safe monotonic timer. A slot is reserved on its first pending
/// poll, and released on firing or Drop. Stale generations cannot cancel reuse.
#[must_use = "timers only run while polled"]
pub struct Sleep<'a, const S: usize, const T: usize> {
    reactor: &'a Reactor<S, T>,
    deadline: Instant,
    key: Option<TimerKey>,
    finished: bool,
}
impl<const S: usize, const T: usize> Future for Sleep<'_, S, T> {
    type Output = io::Result<()>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        assert!(!this.finished, "completed timer polled again");
        if Instant::now() >= this.deadline {
            if let Some(key) = this.key.take() {
                this.reactor.cancel_timer(key);
            }
            this.finished = true;
            return Poll::Ready(Ok(()));
        }
        let mut next_waker = Some(cx.waker().clone());
        let mut old_waker = None;
        let result = (|| {
            let mut state = this.reactor.state.borrow_mut();
            if let Some(key) = this.key {
                let slot = &mut state.timers[key.index];
                if slot.generation != key.generation || slot.entry.is_none() {
                    this.finished = true;
                    return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
                }
                let timer = slot.entry.as_mut().expect("checked timer");
                if !timer.waker.will_wake(cx.waker()) {
                    old_waker = Some(core::mem::replace(
                        &mut timer.waker,
                        next_waker.take().expect("current waker"),
                    ));
                }
            } else {
                let Some((index, slot)) = state
                    .timers
                    .iter_mut()
                    .enumerate()
                    .find(|(_, slot)| slot.entry.is_none() && slot.generation < u64::MAX)
                else {
                    this.finished = true;
                    return Poll::Ready(Err(io::ErrorKind::WouldBlock.into()));
                };
                slot.generation += 1;
                slot.entry = Some(TimerEntry {
                    deadline: this.deadline,
                    waker: next_waker.take().expect("current waker"),
                });
                this.key = Some(TimerKey {
                    index,
                    generation: slot.generation,
                });
            }
            Poll::Pending
        })();
        drop(old_waker);
        drop(next_waker);
        result
    }
}
impl<const S: usize, const T: usize> Drop for Sleep<'_, S, T> {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            self.reactor.cancel_timer(key);
        }
    }
}

impl<const S: usize, const T: usize> hibana_quic::io::DatagramSocket for AsyncUdp<'_, S, T> {
    async fn receive_from(
        &self,
        bytes: &mut [u8],
    ) -> Result<hibana_quic::io::ReceivedDatagram, hibana_quic::io::IoError> {
        loop {
            match self.recv_from(bytes).await {
                Ok(m) => {
                    return Ok(hibana_quic::io::ReceivedDatagram {
                        path: Some(Address {
                            local: m.local,
                            remote: m.source,
                        }),
                        len: m.len,
                        ecn: m.ecn,
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::InvalidData => continue,
                Err(_) => return Err(hibana_quic::io::IoError::Rejected),
            }
        }
    }
    async fn send_to_path(
        &self,
        bytes: &[u8],
        path: Address,
        ecn: Codepoint,
    ) -> Result<usize, hibana_quic::io::IoError> {
        self.send_from(bytes, path, ecn)
            .await
            .map_err(|_| hibana_quic::io::IoError::Rejected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[derive(Default)]
    struct CountWake(AtomicUsize);
    impl Wake for CountWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn bind() -> UdpSocket {
        UdpSocket::bind("127.0.0.1:0").unwrap()
    }

    #[test]
    fn stale_socket_event_cannot_wake_reused_slot() {
        let reactor = Reactor::<1, 1>::new().unwrap();
        let old = reactor.register_udp(bind()).unwrap();
        let old_key = old.key;
        drop(old);
        let replacement = reactor.register_udp(bind()).unwrap();
        assert_ne!(replacement.key, old_key);
        let count = Arc::new(CountWake::default());
        let waker = Waker::from(Arc::clone(&count));
        let mut cx = Context::from_waker(&waker);
        let mut bytes = [0; 16];
        let mut read = pin!(replacement.recv_from(&mut bytes));
        assert!(read.as_mut().poll(&mut cx).is_pending());
        reactor.dispatch_socket(old_key.token(), sys::READ).unwrap();
        assert_eq!(count.0.load(Ordering::Relaxed), 0);
        assert!(
            reactor.state.borrow().sockets[0]
                .entry
                .as_ref()
                .unwrap()
                .read
                .armed
        );
    }

    #[test]
    fn expired_timer_drop_cannot_cancel_reused_slot() {
        let reactor = Reactor::<0, 1>::new().unwrap();
        let mut expired = reactor.sleep(Duration::from_millis(1)).unwrap();
        let mut cx = Context::from_waker(Waker::noop());
        assert!(Pin::new(&mut expired).poll(&mut cx).is_pending());
        let old_key = expired.key.unwrap();
        reactor.wait_and_dispatch().unwrap();
        let mut replacement = reactor.sleep(Duration::from_secs(30)).unwrap();
        assert!(Pin::new(&mut replacement).poll(&mut cx).is_pending());
        assert_ne!(replacement.key.unwrap().generation, old_key.generation);
        drop(expired);
        assert!(reactor.state.borrow().timers[0].entry.is_some());
        drop(replacement);
        assert!(reactor.state.borrow().timers[0].entry.is_none());
    }

    #[test]
    fn generation_exhaustion_retires_slots_instead_of_wrapping() {
        let reactor = Reactor::<1, 1>::new().unwrap();
        {
            let mut state = reactor.state.borrow_mut();
            state.sockets[0].generation = u32::MAX;
            state.timers[0].generation = u64::MAX;
        }
        assert!(
            matches!(reactor.register_udp(bind()), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );
        let mut timer = pin!(reactor.sleep(Duration::from_secs(1)).unwrap());
        let mut cx = Context::from_waker(Waker::noop());
        assert!(
            matches!(timer.as_mut().poll(&mut cx), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::WouldBlock)
        );
    }

    #[test]
    fn backpressure_registration_uses_actual_poll_writable_event() {
        let reactor = Reactor::<1, 1>::new().unwrap();
        let socket = reactor.register_udp(bind()).unwrap();
        let count = Arc::new(CountWake::default());
        let waker = Waker::from(Arc::clone(&count));
        let mut cx = Context::from_waker(&waker);
        let mut write_owner = None;
        // Fault-inject ONLY the initial syscall outcome: reliably exhausting a
        // localhost UDP send buffer would require an unqualified network setup.
        // The subsequent readiness event is the actual socket's EPOLLOUT.
        assert!(
            reactor
                .poll_io(socket.key, false, &mut write_owner, &mut cx, |_| Err::<
                    usize,
                    _,
                >(
                    io::ErrorKind::WouldBlock.into()
                ))
                .is_pending()
        );
        assert!(
            reactor.state.borrow().sockets[0]
                .entry
                .as_ref()
                .unwrap()
                .write
                .armed
        );
        reactor.wait_and_dispatch().unwrap();
        assert_eq!(count.0.load(Ordering::Relaxed), 1);
        assert!(
            !reactor.state.borrow().sockets[0]
                .entry
                .as_ref()
                .unwrap()
                .write
                .armed
        );
        // Ownership survives the readiness notification until acceptance/drop.
        let mut competing = None;
        assert!(
            matches!(reactor.poll_io(socket.key, false, &mut competing, &mut cx,
            |_| Ok(1)), Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::AlreadyExists)
        );
        let receiver = bind();
        let address = Address {
            local: socket.local_addr().unwrap(),
            remote: receiver.local_addr().unwrap(),
        };
        assert!(matches!(
            reactor.poll_io(socket.key, false, &mut write_owner, &mut cx, |socket| {
                socket.send_from(b"ready", address, Codepoint::Ect0)
            }),
            Poll::Ready(Ok(5))
        ));
        assert!(write_owner.is_none());
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut bytes = [0; 8];
        assert_eq!(receiver.recv_from(&mut bytes).unwrap().0, 5);
        assert_eq!(&bytes[..5], b"ready");
    }

    #[test]
    fn cancelled_write_preserves_concurrent_read_interest() {
        let reactor = Reactor::<1, 1>::new().unwrap();
        let socket = reactor.register_udp(bind()).unwrap();
        let mut cx = Context::from_waker(Waker::noop());
        let mut read_owner = None;
        let mut write_owner = None;
        let mut bytes = [0; 8];
        assert!(
            reactor
                .poll_io(socket.key, true, &mut read_owner, &mut cx, |socket| socket
                    .recv_from(&mut bytes))
                .is_pending()
        );
        assert!(
            reactor
                .poll_io(socket.key, false, &mut write_owner, &mut cx, |_| Err::<
                    usize,
                    _,
                >(
                    io::ErrorKind::WouldBlock.into()
                ))
                .is_pending()
        );
        reactor.cancel_io(socket.key, false, write_owner);
        {
            let state = reactor.state.borrow();
            let entry = state.sockets[0].entry.as_ref().unwrap();
            assert!(entry.read.armed);
            assert!(!entry.write.armed);
        }
        reactor.cancel_io(socket.key, true, read_owner);
        assert!(
            !reactor.state.borrow().sockets[0]
                .entry
                .as_ref()
                .unwrap()
                .read
                .armed
        );
    }
}
