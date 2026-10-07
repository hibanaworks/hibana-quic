//! Retained host UDP/readiness attachment for the direct connection roles.
use crate::async_io::{AsyncUdp, Reactor};
/// Fixed datagram buffer size of the current host profile.
pub use crate::storage::DATAGRAM;
use hibana_quic::{
    ecn::Codepoint,
    path::Address,
    quic::{Clock, DatagramRx, DatagramTx, IoError},
};
use std::{
    cell::{Cell, RefCell},
    future::{Future, poll_fn},
    io,
    pin::pin,
    task::Poll,
    time::{Duration, Instant},
};
pub type HostReactor<const S: usize = 4, const T: usize = 8> = Reactor<S, T>;
pub type HostSocket<'a, const S: usize = 4, const T: usize = 8> = AsyncUdp<'a, S, T>;
#[derive(Default)]
pub struct Statistics {
    pub sent: Cell<u64>,
    pub received: Cell<u64>,
    pub foreign: Cell<u64>,
    pub last_accepted: Cell<Option<u64>>,
}
pub struct HostClock<'a, const S: usize = 4, const T: usize = 8> {
    pub reactor: &'a HostReactor<S, T>,
    pub start: Instant,
    fault: RefCell<Option<io::Error>>,
}
impl<'a, const S: usize, const T: usize> HostClock<'a, S, T> {
    pub fn new(reactor: &'a HostReactor<S, T>, start: Instant) -> Self {
        Self {
            reactor,
            start,
            fault: RefCell::new(None),
        }
    }
    pub fn fail(&self, error: io::Error) {
        let mut fault = self.fault.borrow_mut();
        if fault.is_none() {
            *fault = Some(error);
        }
    }
    fn take_fault(&self) -> Option<io::Error> {
        self.fault.borrow_mut().take()
    }
}
impl<const S: usize, const T: usize> Clock for HostClock<'_, S, T> {
    fn now(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_micros()).unwrap_or(u64::MAX)
    }
    async fn wait_until(&self, deadline: u64) {
        let Some(deadline) = self.start.checked_add(Duration::from_micros(deadline)) else {
            self.fail(io::ErrorKind::InvalidInput.into());
            return;
        };
        if let Err(error) = self.reactor.sleep_until(deadline).await {
            self.fail(error);
        }
    }
}
/// Read-only host timing evidence for one projected session. This view borrows
/// the same physical clock and fault owner, registers no extra timer, and never
/// selects a protocol route or changes a deadline.
pub struct ObservedClock<'a, 'r, const S: usize, const T: usize> {
    pub physical: &'a HostClock<'r, S, T>,
    pub session: u32,
}
impl<const S: usize, const T: usize> Clock for ObservedClock<'_, '_, S, T> {
    fn now(&self) -> u64 {
        self.physical.now()
    }
    async fn wait_until(&self, deadline: u64) {
        if std::env::var("HIBANA_QUIC_DIAGNOSTICS").as_deref() == Ok("1") {
            eprintln!(
                "connection-clock session={} now_us={} deadline_us={} stage=requested",
                self.session,
                self.now(),
                deadline
            );
        }
        self.physical.wait_until(deadline).await;
        if std::env::var("HIBANA_QUIC_DIAGNOSTICS").as_deref() == Ok("1") {
            eprintln!(
                "connection-clock session={} now_us={} deadline_us={} stage=returned",
                self.session,
                self.now(),
                deadline
            );
        }
    }
}

/// The operation and its absolute deadline are pinned once. A Pending
/// datagram is never recreated, and hard expiry wins before another syscall.
pub async fn before_deadline<T, const S: usize, const N: usize>(
    clock: &HostClock<'_, S, N>,
    deadline: Instant,
    future: impl Future<Output = Result<T, String>>,
) -> Result<T, String> {
    let mut operation = pin!(future);
    let mut timer = pin!(clock.reactor.sleep_until(deadline));
    poll_fn(|cx| {
        if let Some(error) = clock.take_fault() {
            return Poll::Ready(Err(format!("host I/O: {error}")));
        }
        if Instant::now() >= deadline {
            return Poll::Ready(Err("connection deadline expired".into()));
        }
        let result = operation.as_mut().poll(cx);
        if let Some(error) = clock.take_fault() {
            return Poll::Ready(Err(format!("host I/O: {error}")));
        }
        if result.is_ready() {
            return result;
        }
        match timer.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Err("connection deadline expired".into())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(format!("host deadline: {error}"))),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}
pub struct Receive<'a, 'r, const S: usize = 4, const T: usize = 8> {
    pub alternate: Option<(&'a HostSocket<'r, S, T>, Vec<u8>)>,
    pub socket: &'a HostSocket<'r, S, T>,
    pub address: Address,
    pub first: Option<(&'a [u8], Option<Codepoint>)>,
    pub routed: Option<&'a mut crate::receive_routes::Receiver<{ crate::io::DATAGRAM }>>,
    pub clock: &'a HostClock<'a, S, T>,
    pub statistics: &'a Statistics,
}
impl<const S: usize, const T: usize> DatagramRx for Receive<'_, '_, S, T> {
    async fn receive(
        &mut self,
        bytes: &mut [u8],
    ) -> Result<hibana_quic::quic::ReceivedDatagram, IoError> {
        if let Some((first, ecn)) = self.first.take() {
            if first.len() > bytes.len() {
                return Err(IoError::Rejected);
            }
            bytes[..first.len()].copy_from_slice(first);
            self.statistics
                .received
                .set(self.statistics.received.get() + 1);
            return Ok(hibana_quic::quic::ReceivedDatagram {
                path: Some(self.address),
                len: first.len(),
                ecn,
            });
        }
        if let Some(route) = self.routed.as_mut() {
            let packet = route.receive().await.map_err(|_| IoError::Closed)?;
            if packet.bytes().len() > bytes.len() {
                return Err(IoError::Rejected);
            }
            bytes[..packet.bytes().len()].copy_from_slice(packet.bytes());
            self.statistics
                .received
                .set(self.statistics.received.get() + 1);
            return Ok(hibana_quic::quic::ReceivedDatagram {
                path: Some(packet.address()),
                len: packet.bytes().len(),
                ecn: packet.ecn(),
            });
        }
        loop {
            let physical = if let Some((alternate, storage)) = self.alternate.as_mut() {
                match hibana_quic::runtime::select(
                    alternate.recv_from(storage),
                    self.socket.recv_from(bytes),
                )
                .await
                {
                    core::ops::ControlFlow::Continue(result) => result,
                    core::ops::ControlFlow::Break(result) => {
                        if let Ok(ref packet) = result {
                            if packet.len > bytes.len() {
                                return Err(IoError::Rejected);
                            }
                            bytes[..packet.len].copy_from_slice(&storage[..packet.len]);
                        }
                        result
                    }
                }
            } else {
                self.socket.recv_from(bytes).await
            };
            let received = match physical {
                Ok(received) => received,
                Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                    // Truncation does not credit this path's amplification ledger.
                    hibana_quic::runtime::yield_now().await;
                    continue;
                }
                Err(error) => {
                    self.clock.fail(error);
                    return Err(IoError::Closed);
                }
            };
            if received.source != self.address.remote || received.local != self.address.local {
                self.statistics
                    .foreign
                    .set(self.statistics.foreign.get() + 1);
            }
            self.statistics
                .received
                .set(self.statistics.received.get() + 1);
            return Ok(hibana_quic::quic::ReceivedDatagram {
                len: received.len,
                ecn: received.ecn,
                path: Some(Address {
                    local: received.local,
                    remote: received.source,
                }),
            });
        }
    }
}
pub struct Transmit<'a, 'r, const S: usize = 4, const T: usize = 8> {
    pub alternate: Option<&'a HostSocket<'r, S, T>>,
    pub socket: &'a HostSocket<'r, S, T>,
    pub address: Address,
    pub clock: &'a HostClock<'a, S, T>,
    pub statistics: &'a Statistics,
}
impl<const S: usize, const T: usize> DatagramTx for Transmit<'_, '_, S, T> {
    async fn send(&mut self, bytes: &[u8], ecn: Codepoint) -> Result<u64, IoError> {
        self.send_on_path(bytes, ecn, Some(self.address)).await
    }
    async fn send_on_path(
        &mut self,
        bytes: &[u8],
        ecn: Codepoint,
        path: Option<Address>,
    ) -> Result<u64, IoError> {
        if ecn == Codepoint::Ce {
            return Err(IoError::Rejected);
        }
        let path = path.unwrap_or(self.address);
        let socket = if let Some(alternate) = self.alternate {
            if alternate.local_addr().map_err(|_| IoError::Closed)?.port() == path.local.port() {
                alternate
            } else {
                self.socket
            }
        } else {
            self.socket
        };
        match socket.send_from(bytes, path, ecn).await {
            Ok(len) if len == bytes.len() => {
                let at = self.clock.now();
                self.statistics.sent.set(self.statistics.sent.get() + 1);
                self.statistics.last_accepted.set(Some(at));
                Ok(at)
            }
            Ok(_) => {
                self.clock.fail(io::ErrorKind::WriteZero.into());
                Err(IoError::Rejected)
            }
            Err(e) => {
                self.clock.fail(e);
                Err(IoError::Rejected)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn observed_clock_uses_one_physical_timer_and_cancels_that_same_timer() {
        use super::*;
        use std::task::{Context, Waker};
        let reactor = HostReactor::<1, 2>::new().unwrap();
        let physical = HostClock::new(&reactor, Instant::now());
        let observed = ObservedClock {
            physical: &physical,
            session: 7,
        };
        let mut wait = Box::pin(observed.wait_until(physical.now() + 1_000_000));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(wait.as_mut().poll(&mut cx).is_pending());
        assert_eq!(reactor.active_resources(), (0, 1));
        drop(wait);
        assert_eq!(reactor.active_resources(), (0, 0));
        let mut expired = Box::pin(observed.wait_until(0));
        assert!(expired.as_mut().poll(&mut cx).is_ready());
        drop(expired);
        assert_eq!(reactor.active_resources(), (0, 0));
        assert!(physical.take_fault().is_none());
    }
    use super::*;
    use std::net::UdpSocket;
    #[test]
    fn accepted_send_has_real_bytes_address_and_monotonic_receipt() {
        let reactor = HostReactor::<4, 8>::new().unwrap();
        let socket = reactor
            .register_udp(UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let clock = HostClock::new(&reactor, Instant::now());
        let statistics = Statistics::default();
        let address = Address {
            local: socket.local_addr().unwrap(),
            remote: peer.local_addr().unwrap(),
        };
        let mut tx = Transmit {
            alternate: None,
            socket: &socket,
            address,
            clock: &clock,
            statistics: &statistics,
        };
        let accepted = reactor
            .block_on(tx.send(b"direct role output", Codepoint::NotEct))
            .unwrap()
            .unwrap();
        let mut bytes = [0; 32];
        let (len, source) = peer.recv_from(&mut bytes).unwrap();
        assert_eq!(&bytes[..len], b"direct role output");
        assert_eq!(source, address.local);
        assert_eq!(statistics.last_accepted.get(), Some(accepted));
        assert!(accepted <= clock.now());
    }
    #[test]
    fn actual_transmit_marks_each_datagram_and_rejects_ce_before_send() {
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let reactor = HostReactor::<4, 8>::new().unwrap();
            let socket = reactor
                .register_udp(UdpSocket::bind(bind).unwrap())
                .unwrap();
            let raw = UdpSocket::bind(bind).unwrap();
            raw.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            let remote = raw.local_addr().unwrap();
            let mut peer = crate::udp::UdpMetadataSocket::new(raw).unwrap();
            let clock = HostClock::new(&reactor, Instant::now());
            let statistics = Statistics::default();
            let address = Address {
                local: socket.local_addr().unwrap(),
                remote,
            };
            let mut tx = Transmit {
                alternate: None,
                socket: &socket,
                address,
                clock: &clock,
                statistics: &statistics,
            };
            for mark in [
                Codepoint::Ect0,
                Codepoint::NotEct,
                Codepoint::Ect1,
                Codepoint::NotEct,
            ] {
                let at = reactor
                    .block_on(tx.send(b"real marked send", mark))
                    .unwrap()
                    .unwrap();
                let mut bytes = [0; 32];
                let got = peer.recv_from(&mut bytes).unwrap();
                assert_eq!(&bytes[..got.len], b"real marked send");
                assert_eq!(got.ecn, Some(mark));
                assert_eq!(got.source, address.local);
                assert!(at <= clock.now());
            }
            assert_eq!(statistics.sent.get(), 4);
            let previous = statistics.last_accepted.get();
            assert_eq!(
                reactor
                    .block_on(tx.send(b"forbidden CE", Codepoint::Ce))
                    .unwrap(),
                Err(IoError::Rejected)
            );
            assert_eq!(statistics.sent.get(), 4);
            assert_eq!(statistics.last_accepted.get(), previous);
        }
    }
    #[test]
    fn actual_native_receive_preserves_ecn_with_its_datagram() {
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let reactor = HostReactor::<4, 8>::new().unwrap();
            let socket = reactor
                .register_udp(UdpSocket::bind(bind).unwrap())
                .unwrap();
            let raw = UdpSocket::bind(bind).unwrap();
            let remote = raw.local_addr().unwrap();
            let peer = crate::udp::UdpMetadataSocket::new(raw).unwrap();
            let clock = HostClock::new(&reactor, Instant::now());
            let statistics = Statistics::default();
            let address = Address {
                local: socket.local_addr().unwrap(),
                remote,
            };
            let mut rx = Receive {
                alternate: None,
                socket: &socket,
                address,
                first: None,
                routed: None,
                clock: &clock,
                statistics: &statistics,
            };
            for mark in [
                Codepoint::NotEct,
                Codepoint::Ect0,
                Codepoint::Ect1,
                Codepoint::Ce,
            ] {
                // CE is injected by this explicit metadata fixture only.
                peer.send_to(b"measured metadata", address.local, mark)
                    .unwrap();
                let mut bytes = [0; 32];
                let observed = reactor
                    .block_on(before_deadline(
                        &clock,
                        Instant::now() + Duration::from_secs(1),
                        async { rx.receive(&mut bytes).await.map_err(|e| format!("{e:?}")) },
                    ))
                    .unwrap()
                    .unwrap();
                assert_eq!(&bytes[..observed.len], b"measured metadata");
                assert_eq!(observed.ecn, Some(mark));
            }
            assert_eq!(statistics.received.get(), 4);
        }
    }

    #[test]
    fn receive_preserves_each_physical_path_for_core_admission() {
        let reactor = HostReactor::<4, 8>::new().unwrap();
        let socket = reactor
            .register_udp(UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let foreign = UdpSocket::bind("127.0.0.1:0").unwrap();
        let clock = HostClock::new(&reactor, Instant::now());
        let statistics = Statistics::default();
        let address = Address {
            local: socket.local_addr().unwrap(),
            remote: peer.local_addr().unwrap(),
        };
        foreign.send_to(b"foreign", address.local).unwrap();
        peer.send_to(b"admitted", address.local).unwrap();
        let mut rx = Receive {
            alternate: None,
            socket: &socket,
            address,
            first: None,
            routed: None,
            clock: &clock,
            statistics: &statistics,
        };
        let mut bytes = [0; 32];
        let len = reactor
            .block_on(before_deadline(
                &clock,
                clock.start + Duration::from_secs(1),
                async { rx.receive(&mut bytes).await.map_err(|e| format!("{e:?}")) },
            ))
            .unwrap()
            .unwrap();
        assert_eq!(&bytes[..len.len], b"foreign");
        assert_eq!(
            len.path,
            Some(Address {
                local: address.local,
                remote: foreign.local_addr().unwrap()
            })
        );
        assert_eq!(len.ecn, Some(Codepoint::NotEct));
        let admitted = reactor
            .block_on(before_deadline(
                &clock,
                clock.start + Duration::from_secs(1),
                async { rx.receive(&mut bytes).await.map_err(|e| format!("{e:?}")) },
            ))
            .unwrap()
            .unwrap();
        assert_eq!(&bytes[..admitted.len], b"admitted");
        assert_eq!(admitted.path, Some(address));
        // These are physical observations, not amplification or authentication credit.
        // The handshake prefix filters the initial address before credit; the
        // application path owner only sees observations after AEAD admission.
        assert_eq!(statistics.received.get(), 2);
        assert_eq!(statistics.foreign.get(), 1);
    }
    #[test]
    fn expired_hard_deadline_never_polls_ready_submission() {
        let reactor = HostReactor::<4, 8>::new().unwrap();
        let clock = HostClock::new(&reactor, Instant::now());
        let attempted = Cell::new(false);
        let result = reactor
            .block_on(before_deadline(&clock, clock.start, async {
                attempted.set(true);
                Ok(())
            }))
            .unwrap();
        assert!(result.is_err());
        assert!(!attempted.get());
    }
    #[test]
    fn idle_timeout_parks_and_cancels_the_registered_receive() {
        let reactor = HostReactor::<4, 8>::new().unwrap();
        let socket = reactor
            .register_udp(UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let clock = HostClock::new(&reactor, Instant::now());
        let statistics = Statistics::default();
        let address = Address {
            local: socket.local_addr().unwrap(),
            remote: peer.local_addr().unwrap(),
        };
        let mut rx = Receive {
            alternate: None,
            socket: &socket,
            address,
            first: None,
            routed: None,
            clock: &clock,
            statistics: &statistics,
        };
        let mut bytes = [0; 32];
        let result = reactor
            .block_on(before_deadline(
                &clock,
                clock.start + Duration::from_millis(10),
                async { rx.receive(&mut bytes).await.map_err(|e| format!("{e:?}")) },
            ))
            .unwrap();
        assert!(result.is_err());
        assert!(
            reactor.statistics().polls <= 3,
            "idle socket must sleep in epoll"
        );
        assert!(reactor.statistics().timer_events > 0);
        peer.send_to(b"after cancellation", address.local).unwrap();
        let len = reactor
            .block_on(before_deadline(
                &clock,
                Instant::now() + Duration::from_secs(1),
                async { rx.receive(&mut bytes).await.map_err(|e| format!("{e:?}")) },
            ))
            .unwrap()
            .unwrap();
        assert_eq!(&bytes[..len.len], b"after cancellation");
        assert_eq!(len.ecn, Some(Codepoint::NotEct));
    }
    #[test]
    fn rejected_send_never_records_acceptance() {
        let reactor = HostReactor::<4, 8>::new().unwrap();
        let socket = reactor
            .register_udp(UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap();
        let clock = HostClock::new(&reactor, Instant::now());
        let statistics = Statistics::default();
        let address = Address {
            local: socket.local_addr().unwrap(),
            remote: "[::1]:4433".parse().unwrap(),
        };
        let mut tx = Transmit {
            alternate: None,
            socket: &socket,
            address,
            clock: &clock,
            statistics: &statistics,
        };
        assert_eq!(
            reactor
                .block_on(tx.send(b"invalid family", Codepoint::NotEct))
                .unwrap(),
            Err(IoError::Rejected)
        );
        assert_eq!(statistics.sent.get(), 0);
        assert_eq!(statistics.last_accepted.get(), None);
        assert!(clock.take_fault().is_some());
    }
}
