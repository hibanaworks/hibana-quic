//! Real Linux host UDP boundary for the owned QUIC publication path.
//! Kept separate so its syscall/deadline semantics can be tested without lowering
//! the complete connection projection. These tests do not qualify the protocol.
use hibana_quic::roles::path_owner;
use hibana_quic_host::async_io::{AsyncUdp, Reactor};
use std::{
    future::{Future, poll_fn},
    io,
    net::SocketAddr,
    pin::pin,
    task::Poll,
    time::Instant,
};
type HostReactor = Reactor<4, 8>;
type HostSocket<'a> = AsyncUdp<'a, 4, 8>;
fn now(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX)
}

/// Submit ready UDP before servicing a soft recovery/probe deadline. Hard
/// wall, idle, and closing expiry always win before another syscall attempt.
/// A soft wake returns None only when submission actually remains Pending;
/// the caller then rejects its reservation and gives receive work a turn.
pub(super) async fn send_activity<T>(
    reactor: &HostReactor,
    hard_deadline: Instant,
    soft_deadline: Option<Instant>,
    operation: impl Future<Output = io::Result<T>>,
) -> io::Result<Option<T>> {
    let wake_deadline = soft_deadline.map_or(hard_deadline, |soft| soft.min(hard_deadline));
    let mut operation = pin!(operation);
    let mut timer = pin!(reactor.sleep_until(wake_deadline));
    poll_fn(|cx| {
        if Instant::now() >= hard_deadline {
            return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
        }
        if let Poll::Ready(result) = operation.as_mut().poll(cx) {
            return Poll::Ready(result.map(Some));
        }
        if let Poll::Ready(result) = timer.as_mut().poll(cx) {
            return Poll::Ready(result.and_then(|()| {
                if Instant::now() >= hard_deadline {
                    Err(io::ErrorKind::TimedOut.into())
                } else {
                    Ok(None)
                }
            }));
        }
        Poll::Pending
    })
    .await
}

/// Diagnostic outcome retained by the trusted host boundary. The protocol only
/// receives actual acceptance time or rejection; after it settles every affine
/// reservation the host handles the corresponding deadline or I/O failure.
#[derive(Debug)]
pub(super) enum HostSendOutcome {
    NotAttempted,
    Accepted(u64),
    SoftDeadline,
    HardDeadline,
    Failed(io::Error),
}
pub(super) struct HostUdpAdapter<'a, 'reactor> {
    pub(super) reactor: &'a HostReactor,
    pub(super) socket: &'a HostSocket<'reactor>,
    pub(super) preferred_socket: Option<&'a HostSocket<'reactor>>,
    pub(super) preferred_address: Option<SocketAddr>,
    pub(super) start: Instant,
    pub(super) hard_deadline: Instant,
    pub(super) soft_deadline: Option<Instant>,
    pub(super) outcome: HostSendOutcome,
}
impl path_owner::UdpAdapter for HostUdpAdapter<'_, '_> {
    async fn send(&mut self, datagram: path_owner::Datagram<'_>) -> std::result::Result<u64, ()> {
        let sender = if self.preferred_address == Some(datagram.address.local) {
            match self.preferred_socket {
                Some(socket) => socket,
                None => {
                    self.outcome = HostSendOutcome::Failed(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "missing preferred socket",
                    ));
                    return Err(());
                }
            }
        } else {
            self.socket
        };
        match send_activity(
            self.reactor,
            self.hard_deadline,
            self.soft_deadline,
            sender.send_from(datagram.bytes, datagram.address, datagram.ecn),
        )
        .await
        {
            Ok(Some(n)) if n == datagram.bytes.len() => {
                // Timestamp only after the entire real sendmsg was accepted.
                let accepted_at = now(self.start);
                self.outcome = HostSendOutcome::Accepted(accepted_at);
                Ok(accepted_at)
            }
            Ok(Some(n)) => {
                self.outcome = HostSendOutcome::Failed(io::Error::new(
                    io::ErrorKind::WriteZero,
                    format!(
                        "UDP accepted {n} of {} datagram bytes",
                        datagram.bytes.len()
                    ),
                ));
                Err(())
            }
            Ok(None) => {
                self.outcome = HostSendOutcome::SoftDeadline;
                Err(())
            }
            Err(error) if error.kind() == io::ErrorKind::TimedOut => {
                self.outcome = HostSendOutcome::HardDeadline;
                Err(())
            }
            Err(error) => {
                self.outcome = HostSendOutcome::Failed(error);
                Err(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hibana_quic::{
        ecn::{Codepoint, PathIdentity},
        path::Address,
    };
    use path_owner::UdpAdapter;
    use std::{cell::Cell, net::UdpSocket, time::Duration};

    fn datagram(bytes: &[u8], address: Address) -> path_owner::Datagram<'_> {
        path_owner::Datagram {
            bytes,
            path: PathIdentity {
                connection_generation: 1,
                slot: 0,
                path_generation: 1,
            },
            address,
            ecn: Codepoint::NotEct,
        }
    }
    fn adapter<'a, 'r>(
        reactor: &'a HostReactor,
        socket: &'a HostSocket<'r>,
        start: Instant,
    ) -> HostUdpAdapter<'a, 'r> {
        HostUdpAdapter {
            reactor,
            socket,
            preferred_socket: None,
            preferred_address: None,
            start,
            hard_deadline: start + Duration::from_secs(1),
            soft_deadline: None,
            outcome: HostSendOutcome::NotAttempted,
        }
    }
    #[test]
    fn whole_real_datagram_records_actual_acceptance_and_source() {
        let reactor = HostReactor::new().unwrap();
        let sender = reactor
            .register_udp(UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        let start = Instant::now();
        let mut adapter = adapter(&reactor, &sender, start);
        // A ready syscall wins over an overdue soft recovery timer.
        adapter.soft_deadline = Some(start);
        let address = Address {
            local: sender.local_addr().unwrap(),
            remote: receiver.local_addr().unwrap(),
        };
        let accepted = reactor
            .block_on(adapter.send(datagram(b"real owned output", address)))
            .unwrap()
            .unwrap();
        assert!(accepted <= now(start));
        assert!(matches!(adapter.outcome, HostSendOutcome::Accepted(at) if at == accepted));
        let mut bytes = [0; 32];
        let (len, source) = receiver.recv_from(&mut bytes).unwrap();
        assert_eq!(&bytes[..len], b"real owned output");
        assert_eq!(source, address.local);
    }
    #[test]
    fn preferred_path_uses_the_actual_preferred_socket() {
        let reactor = HostReactor::new().unwrap();
        let normal = reactor
            .register_udp(UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap();
        let preferred = reactor
            .register_udp(UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        let start = Instant::now();
        let mut adapter = adapter(&reactor, &normal, start);
        adapter.preferred_socket = Some(&preferred);
        adapter.preferred_address = Some(preferred.local_addr().unwrap());
        let address = Address {
            local: preferred.local_addr().unwrap(),
            remote: receiver.local_addr().unwrap(),
        };
        reactor
            .block_on(adapter.send(datagram(b"preferred", address)))
            .unwrap()
            .unwrap();
        let mut bytes = [0; 32];
        let (len, source) = receiver.recv_from(&mut bytes).unwrap();
        assert_eq!(&bytes[..len], b"preferred");
        assert_eq!(source, address.local);
        assert_ne!(source, normal.local_addr().unwrap());
    }
    #[test]
    fn socket_errors_are_retained_and_never_become_acceptance() {
        let reactor = HostReactor::new().unwrap();
        let sender = reactor
            .register_udp(UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        let mut wrong = sender.local_addr().unwrap();
        wrong.set_port(if wrong.port() == 1 { 2 } else { 1 });
        let mut adapter = adapter(&reactor, &sender, Instant::now());
        assert!(
            reactor
                .block_on(adapter.send(datagram(
                    b"reject",
                    Address {
                        local: wrong,
                        remote: receiver.local_addr().unwrap()
                    }
                )))
                .unwrap()
                .is_err()
        );
        assert!(
            matches!(adapter.outcome, HostSendOutcome::Failed(ref error) if error.kind() == io::ErrorKind::InvalidInput)
        );
        assert_eq!(
            receiver.recv_from(&mut [0; 16]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
    #[test]
    fn missing_preferred_socket_is_an_explicit_failure() {
        let reactor = HostReactor::new().unwrap();
        let sender = reactor
            .register_udp(UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        let mut adapter = adapter(&reactor, &sender, Instant::now());
        adapter.preferred_address = Some(sender.local_addr().unwrap());
        assert!(
            reactor
                .block_on(adapter.send(datagram(
                    b"reject",
                    Address {
                        local: sender.local_addr().unwrap(),
                        remote: receiver.local_addr().unwrap()
                    }
                )))
                .unwrap()
                .is_err()
        );
        assert!(
            matches!(adapter.outcome, HostSendOutcome::Failed(ref error) if error.kind() == io::ErrorKind::NotConnected)
        );
        assert_eq!(
            receiver.recv_from(&mut [0; 16]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
    #[test]
    fn hard_expiry_prevents_even_ready_udp() {
        let reactor = HostReactor::new().unwrap();
        let sender = reactor
            .register_udp(UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        let start = Instant::now();
        let mut adapter = adapter(&reactor, &sender, start);
        adapter.hard_deadline = start;
        assert!(
            reactor
                .block_on(adapter.send(datagram(
                    b"expired",
                    Address {
                        local: sender.local_addr().unwrap(),
                        remote: receiver.local_addr().unwrap()
                    }
                )))
                .unwrap()
                .is_err()
        );
        assert!(matches!(adapter.outcome, HostSendOutcome::HardDeadline));
        assert_eq!(
            receiver.recv_from(&mut [0; 16]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
    #[test]
    fn soft_wake_rejects_only_an_actually_pending_operation() {
        let reactor = HostReactor::new().unwrap();
        let polls = Cell::new(0);
        let start = Instant::now();
        let pending = poll_fn(|_| {
            polls.set(polls.get() + 1);
            Poll::<io::Result<usize>>::Pending
        });
        let result = reactor
            .block_on(send_activity(
                &reactor,
                start + Duration::from_secs(1),
                Some(start + Duration::from_millis(2)),
                pending,
            ))
            .unwrap()
            .unwrap();
        assert_eq!(result, None);
        assert_eq!(polls.get(), 2);
    }
}
