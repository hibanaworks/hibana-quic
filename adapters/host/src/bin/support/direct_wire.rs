//! Retained host UDP/readiness attachment for the direct connection roles.
use hibana_quic::{connection::{Clock, DatagramRx, DatagramTx, IoError}, ecn::Codepoint, path::Address};
use hibana_quic_host::async_io::{AsyncUdp, Reactor};
use std::{cell::{Cell, RefCell}, future::{Future, poll_fn}, io, pin::pin, task::Poll, time::{Duration, Instant}};
pub type HostReactor = Reactor<4, 8>;
pub type HostSocket<'a> = AsyncUdp<'a, 4, 8>;
#[derive(Default)]
pub struct Statistics { pub sent: Cell<u64>, pub received: Cell<u64>, pub foreign: Cell<u64>, pub last_accepted: Cell<Option<u64>> }
pub struct HostClock<'a> { pub reactor: &'a HostReactor, pub start: Instant, fault: RefCell<Option<io::Error>> }
impl<'a> HostClock<'a> {
    pub fn new(reactor: &'a HostReactor, start: Instant) -> Self { Self { reactor, start, fault: RefCell::new(None) } }
    pub fn fail(&self, error: io::Error) { let mut fault = self.fault.borrow_mut(); if fault.is_none() { *fault = Some(error); } }
    fn take_fault(&self) -> Option<io::Error> { self.fault.borrow_mut().take() }
}
impl Clock for HostClock<'_> {
    fn now(&self) -> u64 { u64::try_from(self.start.elapsed().as_micros()).unwrap_or(u64::MAX) }
    async fn wait_until(&self, deadline: u64) {
        let Some(deadline) = self.start.checked_add(Duration::from_micros(deadline)) else { self.fail(io::ErrorKind::InvalidInput.into()); return; };
        if let Err(error) = self.reactor.sleep_until(deadline).await { self.fail(error); }
    }
}
/// The operation and its absolute deadline are pinned once. A Pending
/// datagram is never recreated, and hard expiry wins before another syscall.
pub async fn before_deadline<T>(clock: &HostClock<'_>, deadline: Instant, future: impl Future<Output = Result<T, String>>) -> Result<T, String> {
    let mut operation = pin!(future); let mut timer = pin!(clock.reactor.sleep_until(deadline));
    poll_fn(|cx| {
        if let Some(error) = clock.take_fault() { return Poll::Ready(Err(format!("host I/O: {error}"))); }
        if Instant::now() >= deadline { return Poll::Ready(Err("connection deadline expired".into())); }
        let result = operation.as_mut().poll(cx);
        if let Some(error) = clock.take_fault() { return Poll::Ready(Err(format!("host I/O: {error}"))); }
        if result.is_ready() { return result; }
        match timer.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Err("connection deadline expired".into())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(format!("host deadline: {error}"))),
            Poll::Pending => Poll::Pending,
        }
    }).await
}
pub struct Receive<'a, 'r> {
    pub socket: &'a HostSocket<'r>, pub address: Address, pub first: Option<&'a [u8]>,
    pub clock: &'a HostClock<'a>, pub statistics: &'a Statistics,
}
impl DatagramRx for Receive<'_, '_> {
    async fn receive(&mut self, bytes: &mut [u8]) -> Result<usize, IoError> {
        if let Some(first) = self.first.take() {
            if first.len() > bytes.len() { return Err(IoError::Rejected); }
            bytes[..first.len()].copy_from_slice(first); self.statistics.received.set(self.statistics.received.get() + 1); return Ok(first.len());
        }
        loop {
            let received = match self.socket.recv_from(bytes).await {
                Ok(received) => received,
                Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                    // Truncation does not credit this path's amplification ledger.
                    hibana_quic::runtime::yield_now().await; continue;
                }
                Err(error) => { self.clock.fail(error); return Err(IoError::Closed); }
            };
            if received.source == self.address.remote && received.local == self.address.local {
                self.statistics.received.set(self.statistics.received.get() + 1); return Ok(received.len);
            }
            self.statistics.foreign.set(self.statistics.foreign.get() + 1);
            hibana_quic::runtime::yield_now().await;
        }
    }
}
pub struct Transmit<'a, 'r> { pub socket: &'a HostSocket<'r>, pub address: Address, pub clock: &'a HostClock<'a>, pub statistics: &'a Statistics }
impl DatagramTx for Transmit<'_, '_> {
    async fn send(&mut self, bytes: &[u8]) -> Result<u64, IoError> {
        match self.socket.send_from(bytes, self.address, Codepoint::NotEct).await {
            Ok(len) if len == bytes.len() => {
                // Receipt only after full real sendmsg acceptance.
                let accepted = self.clock.now(); self.statistics.sent.set(self.statistics.sent.get() + 1); self.statistics.last_accepted.set(Some(accepted)); Ok(accepted)
            }
            Ok(_) => { self.clock.fail(io::ErrorKind::WriteZero.into()); Err(IoError::Rejected) }
            Err(error) => { self.clock.fail(error); Err(IoError::Rejected) }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*; use std::net::UdpSocket;
    #[test]
    fn accepted_send_has_real_bytes_address_and_monotonic_receipt() {
        let reactor = HostReactor::new().unwrap(); let socket = reactor.register_udp(UdpSocket::bind("127.0.0.1:0").unwrap()).unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap(); peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let clock = HostClock::new(&reactor, Instant::now()); let statistics = Statistics::default();
        let address = Address { local: socket.local_addr().unwrap(), remote: peer.local_addr().unwrap() };
        let mut tx = Transmit { socket: &socket, address, clock: &clock, statistics: &statistics };
        let accepted = reactor.block_on(tx.send(b"direct role output")).unwrap().unwrap(); let mut bytes = [0; 32]; let (len, source) = peer.recv_from(&mut bytes).unwrap();
        assert_eq!(&bytes[..len], b"direct role output"); assert_eq!(source, address.local); assert_eq!(statistics.last_accepted.get(), Some(accepted)); assert!(accepted <= clock.now());
    }
    #[test]
    fn foreign_peer_cannot_credit_the_admitted_path() {
        let reactor = HostReactor::new().unwrap(); let socket = reactor.register_udp(UdpSocket::bind("127.0.0.1:0").unwrap()).unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap(); let foreign = UdpSocket::bind("127.0.0.1:0").unwrap(); let clock = HostClock::new(&reactor, Instant::now()); let statistics = Statistics::default();
        let address = Address { local: socket.local_addr().unwrap(), remote: peer.local_addr().unwrap() }; foreign.send_to(b"foreign", address.local).unwrap(); peer.send_to(b"admitted", address.local).unwrap();
        let mut rx = Receive { socket: &socket, address, first: None, clock: &clock, statistics: &statistics }; let mut bytes = [0; 32];
        let len = reactor.block_on(before_deadline(&clock, clock.start + Duration::from_secs(1), async { rx.receive(&mut bytes).await.map_err(|e| format!("{e:?}")) })).unwrap().unwrap();
        assert_eq!(&bytes[..len], b"admitted"); assert_eq!(statistics.received.get(), 1); assert_eq!(statistics.foreign.get(), 1);
    }
    #[test]
    fn expired_hard_deadline_never_polls_ready_submission() {
        let reactor = HostReactor::new().unwrap(); let clock = HostClock::new(&reactor, Instant::now()); let attempted = Cell::new(false);
        let result = reactor.block_on(before_deadline(&clock, clock.start, async { attempted.set(true); Ok(()) })).unwrap(); assert!(result.is_err()); assert!(!attempted.get());
    }
    #[test]
    fn idle_timeout_parks_and_cancels_the_registered_receive() {
        let reactor = HostReactor::new().unwrap(); let socket = reactor.register_udp(UdpSocket::bind("127.0.0.1:0").unwrap()).unwrap(); let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let clock = HostClock::new(&reactor, Instant::now()); let statistics = Statistics::default(); let address = Address { local: socket.local_addr().unwrap(), remote: peer.local_addr().unwrap() };
        let mut rx = Receive { socket: &socket, address, first: None, clock: &clock, statistics: &statistics }; let mut bytes = [0; 32];
        let result = reactor.block_on(before_deadline(&clock, clock.start + Duration::from_millis(10), async { rx.receive(&mut bytes).await.map_err(|e| format!("{e:?}")) })).unwrap();
        assert!(result.is_err()); assert!(reactor.statistics().polls <= 3, "idle socket must sleep in epoll"); assert!(reactor.statistics().timer_events > 0);
        peer.send_to(b"after cancellation", address.local).unwrap();
        let len = reactor.block_on(before_deadline(&clock, Instant::now() + Duration::from_secs(1), async { rx.receive(&mut bytes).await.map_err(|e| format!("{e:?}")) })).unwrap().unwrap(); assert_eq!(&bytes[..len], b"after cancellation");
    }
    #[test]
    fn rejected_send_never_records_acceptance() {
        let reactor = HostReactor::new().unwrap(); let socket = reactor.register_udp(UdpSocket::bind("127.0.0.1:0").unwrap()).unwrap(); let clock = HostClock::new(&reactor, Instant::now()); let statistics = Statistics::default();
        let address = Address { local: socket.local_addr().unwrap(), remote: "[::1]:4433".parse().unwrap() }; let mut tx = Transmit { socket: &socket, address, clock: &clock, statistics: &statistics };
        assert_eq!(reactor.block_on(tx.send(b"invalid family")).unwrap(), Err(IoError::Rejected)); assert_eq!(statistics.sent.get(), 0); assert_eq!(statistics.last_accepted.get(), None); assert!(clock.take_fault().is_some());
    }
}
