//! Explicit UDP socket routing for a bounded set of concrete local addresses.
//!
//! Each socket must be bound to one concrete IP and port. Wildcard binds are
//! rejected: without IP_PKTINFO/IPV6_PKTINFO they do not identify a datagram's
//! actual local destination. Existing recvmsg ECN metadata is retained. All
//! sockets are unconnected and nonblocking; no automatic source/path fallback
//! occurs. Native ancillary sends do not allocate; host socket setup remains
//! outside the no_alloc core.

use crate::unix::udp::{Codepoint, UdpMetadataSocket};
use crate::unix::{UdpSocket, error as io};
use hibana_quic::io::Address;

pub struct BoundSocket {
    local: core::net::SocketAddr,
    socket: UdpMetadataSocket,
}
impl BoundSocket {
    pub fn new(socket: UdpSocket) -> io::Result<Self> {
        let local = socket.local_addr()?;
        if local.ip().is_unspecified() || local.port() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path socket needs a concrete bound address",
            ));
        }
        if socket.peer_addr().is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path socket must be unconnected",
            ));
        }
        socket.set_nonblocking(true)?;
        Ok(Self {
            local,
            socket: UdpMetadataSocket::new(socket)?,
        })
    }
    pub fn local_addr(&self) -> core::net::SocketAddr {
        self.local
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Datagram {
    pub len: usize,
    pub address: Address,
    pub ecn: Option<Codepoint>,
}

/// Caller-owned bounded socket slots, polled fairly with at most one recvmsg
/// attempt per socket per call. An idle set returns WouldBlock, never an inferred
/// timeout or connection close. The caller owns readiness/timer scheduling.
pub struct SocketSet<'a> {
    sockets: &'a mut [BoundSocket],
    next: usize,
}
impl<'a> SocketSet<'a> {
    pub fn new(sockets: &'a mut [BoundSocket]) -> io::Result<Self> {
        if sockets.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty path socket set",
            ));
        }
        for (i, s) in sockets.iter().enumerate() {
            if sockets[..i].iter().any(|other| other.local == s.local) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "duplicate local path address",
                ));
            }
        }
        Ok(Self { sockets, next: 0 })
    }
    pub fn recv(&mut self, bytes: &mut [u8]) -> io::Result<Datagram> {
        for _ in 0..self.sockets.len() {
            let i = self.next;
            self.next = (self.next + 1) % self.sockets.len();
            let socket = &mut self.sockets[i];
            match socket.socket.recv_from(bytes) {
                Ok(data) => {
                    return Ok(Datagram {
                        len: data.len,
                        address: Address {
                            local: socket.local,
                            remote: data.source,
                        },
                        ecn: data.ecn,
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
        Err(io::ErrorKind::WouldBlock.into())
    }
    /// Only a full successful send authorizes the core's adapter-accepted path
    /// callback. The returned byte count is the actual sendmsg outcome.
    pub fn send(&self, bytes: &[u8], address: Address, ecn: Codepoint) -> io::Result<usize> {
        let socket = self
            .sockets
            .iter()
            .find(|s| s.local == address.local)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "unknown local path address")
            })?;
        socket.socket.send_to(bytes, address.remote, ecn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::{Ipv4Addr, SocketAddr},
        thread,
        time::{Duration, Instant},
    };
    fn bound(v6: bool) -> BoundSocket {
        BoundSocket::new(
            UdpSocket::bind(
                (if v6 { "[::1]:0" } else { "127.0.0.1:0" })
                    .parse()
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap()
    }
    fn receive(set: &mut SocketSet<'_>, buf: &mut [u8]) -> Datagram {
        let end = Instant::now() + Duration::from_secs(2);
        loop {
            match set.recv(buf) {
                Ok(d) => return d,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < end => {
                    thread::yield_now()
                }
                Err(e) => panic!("receive failed: {e}"),
            }
        }
    }
    fn actual_routing(v6: bool) {
        let mut client_sockets = [bound(v6), bound(v6)];
        let mut server_sockets = [bound(v6), bound(v6)];
        let client = [
            client_sockets[0].local_addr(),
            client_sockets[1].local_addr(),
        ];
        let server = [
            server_sockets[0].local_addr(),
            server_sockets[1].local_addr(),
        ];
        let mut clients = SocketSet::new(&mut client_sockets).unwrap();
        let mut servers = SocketSet::new(&mut server_sockets).unwrap();
        let mut bytes = [0; 64];
        assert_eq!(
            servers.recv(&mut bytes).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        for i in 0..2 {
            let sent = Address {
                local: client[i],
                remote: server[1 - i],
            };
            assert_eq!(
                clients
                    .send(&[10 + i as u8], sent, Codepoint::Ect0)
                    .unwrap(),
                1
            );
            let received = receive(&mut servers, &mut bytes);
            assert_eq!(
                received.address,
                Address {
                    local: sent.remote,
                    remote: sent.local
                }
            );
            assert_eq!(received.ecn, Some(Codepoint::Ect0));
            assert_eq!(&bytes[..received.len], &[10 + i as u8]);
            assert_eq!(
                servers
                    .send(&[20 + i as u8], received.address, Codepoint::NotEct)
                    .unwrap(),
                1
            );
            let response = receive(&mut clients, &mut bytes);
            assert_eq!(response.address, sent);
            assert_eq!(&bytes[..response.len], &[20 + i as u8]);
        }
        let unknown = SocketAddr::from((Ipv4Addr::LOCALHOST, 1));
        assert_eq!(
            clients
                .send(
                    &[1],
                    Address {
                        local: unknown,
                        remote: server[0]
                    },
                    Codepoint::NotEct
                )
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
    #[test]
    fn ipv4_preserves_actual_local_remote_and_ecn_on_two_paths() {
        actual_routing(false);
    }
    #[test]
    fn ipv6_preserves_actual_local_remote_and_ecn_on_two_paths() {
        actual_routing(true);
    }
    #[test]
    fn wildcard_connected_and_empty_socket_sets_fail_explicitly() {
        assert!(BoundSocket::new(UdpSocket::bind("0.0.0.0:0".parse().unwrap()).unwrap()).is_err());
        assert!(BoundSocket::new(UdpSocket::bind("[::]:0".parse().unwrap()).unwrap()).is_err());
        let s = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        s.connect("127.0.0.1:9".parse().unwrap()).unwrap();
        assert!(BoundSocket::new(s).is_err());
        assert!(SocketSet::new(&mut []).is_err());
    }
}
