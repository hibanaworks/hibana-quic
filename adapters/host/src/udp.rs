//! Safe typed Linux UDP ancillary metadata using nix's recvmsg/sendmsg wrappers.
//! No raw control-message casts or unsafe code are implemented here. Host setup
//! and nix's sendmsg control buffer can allocate; this is not a no_alloc boundary.
//! No socket-global ECN setting is changed when sending an individual datagram.

pub use hibana_quic::ecn::Codepoint;
use nix::sys::socket::{
    ControlMessage, ControlMessageOwned, MsgFlags, SockaddrStorage, recvmsg, sendmsg, setsockopt,
    sockopt,
};
use std::{
    io::{self, IoSlice, IoSliceMut},
    net::{SocketAddr, UdpSocket},
    os::fd::AsRawFd,
    time::Duration,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Received {
    pub len: usize,
    pub source: SocketAddr,
    /// None is unavailable metadata, never fabricated Not-ECT evidence.
    pub ecn: Option<Codepoint>,
}

pub struct UdpMetadataSocket {
    socket: UdpSocket,
    control: Vec<u8>,
}

impl UdpMetadataSocket {
    /// Enable native IPv4 TOS or IPv6 Traffic Class reception. Errors are
    /// reported so the caller can explicitly disable ECN rather than claim it.
    /// IPv4-mapped dual-stack delivery is not a qualified profile here.
    pub fn new(socket: UdpSocket) -> io::Result<Self> {
        if socket.local_addr()?.is_ipv4() {
            setsockopt(&socket, sockopt::IpRecvTos, &true)?;
        } else {
            setsockopt(&socket, sockopt::Ipv6RecvTClass, &true)?;
        }
        Ok(Self {
            socket,
            control: nix::cmsg_space!(u8, i32),
        })
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.socket.set_read_timeout(timeout)
    }
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.socket.set_write_timeout(timeout)
    }

    /// Reject a truncated datagram or ancillary buffer; return optional actual
    /// kernel metadata for a complete datagram. An absent ECN message is allowed.
    pub fn recv_from(&mut self, bytes: &mut [u8]) -> io::Result<Received> {
        let mut iov = [IoSliceMut::new(bytes)];
        let message = recvmsg::<SockaddrStorage>(
            self.socket.as_raw_fd(),
            &mut iov,
            Some(&mut self.control),
            MsgFlags::empty(),
        )?;
        if message
            .flags
            .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC)
        {
            return Err(invalid("truncated UDP payload or ancillary metadata"));
        }
        let source = message
            .address
            .ok_or_else(|| invalid("missing UDP source address"))?;
        let source = if let Some(address) = source.as_sockaddr_in() {
            SocketAddr::from(*address)
        } else if let Some(address) = source.as_sockaddr_in6() {
            SocketAddr::from(*address)
        } else {
            return Err(invalid("non-IP UDP source address"));
        };
        let ecn = decode_ecn(message.cmsgs()?)?;
        Ok(Received {
            len: message.bytes,
            source,
            ecn,
        })
    }

    /// Set ECN in this sendmsg's ancillary data, with DSCP zero. The transport
    /// chooses ECT(0)/Not-ECT and commits accounting only after full acceptance.
    /// CE is exposed for explicit local metadata tests, never chosen by PathEcn.
    pub fn send_to(
        &self,
        bytes: &[u8],
        destination: SocketAddr,
        ecn: Codepoint,
    ) -> io::Result<usize> {
        if self.socket.local_addr()?.is_ipv4() != destination.is_ipv4() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "native address family mismatch",
            ));
        }
        let destination = SockaddrStorage::from(destination);
        let iov = [IoSlice::new(bytes)];
        let bits = ecn.bits();
        let class = i32::from(bits);
        let control = if destination.as_sockaddr_in().is_some() {
            ControlMessage::Ipv4Tos(&bits)
        } else {
            ControlMessage::Ipv6TClass(&class)
        };
        Ok(sendmsg(
            self.socket.as_raw_fd(),
            &iov,
            &[control],
            MsgFlags::empty(),
            Some(&destination),
        )?)
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn decode_ecn(
    messages: impl IntoIterator<Item = ControlMessageOwned>,
) -> io::Result<Option<Codepoint>> {
    let mut found = None;
    for message in messages {
        let bits = match message {
            ControlMessageOwned::Ipv4Tos(tos) => tos,
            ControlMessageOwned::Ipv6TClass(class) => {
                u8::try_from(class).map_err(|_| invalid("invalid IPv6 traffic class"))?
            }
            _ => continue,
        };
        let codepoint = Codepoint::from_ip_tos(bits);
        if found.is_some_and(|earlier| earlier != codepoint) {
            return Err(invalid("conflicting ECN ancillary metadata"));
        }
        found = Some(codepoint);
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn socket(v6: bool) -> UdpMetadataSocket {
        let socket = UdpSocket::bind(if v6 { "[::1]:0" } else { "127.0.0.1:0" }).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        UdpMetadataSocket::new(socket).unwrap()
    }
    fn roundtrip(v6: bool) {
        let sender = socket(v6);
        let mut receiver = socket(v6);
        let mut bytes = [0; 64];
        // Explicit real-kernel metadata tests; no QUIC/ECN-validation claim.
        for code in [
            Codepoint::NotEct,
            Codepoint::Ect0,
            Codepoint::Ect1,
            Codepoint::Ce,
            Codepoint::NotEct,
        ] {
            let data = [0xc0, code.bits(), 0xff];
            assert_eq!(
                sender
                    .send_to(&data, receiver.local_addr().unwrap(), code)
                    .unwrap(),
                data.len()
            );
            let received = receiver.recv_from(&mut bytes).unwrap();
            assert_eq!(received.len, data.len());
            assert_eq!(&bytes[..received.len], data);
            assert_eq!(received.source, sender.local_addr().unwrap());
            assert_eq!(received.ecn, Some(code));
        }
    }
    #[test]
    fn ipv4_kernel_tos_roundtrip() {
        roundtrip(false);
    }
    #[test]
    fn ipv6_kernel_traffic_class_roundtrip() {
        roundtrip(true);
    }
    #[test]
    fn absent_metadata_admits_payload_without_inventing_marking() {
        let sender = socket(false);
        let raw = UdpSocket::bind("127.0.0.1:0").unwrap();
        raw.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut receiver = UdpMetadataSocket {
            socket: raw,
            control: nix::cmsg_space!(u8, i32),
        };
        sender
            .send_to(
                b"real packet",
                receiver.local_addr().unwrap(),
                Codepoint::Ect0,
            )
            .unwrap();
        let mut bytes = [0; 64];
        let received = receiver.recv_from(&mut bytes).unwrap();
        assert_eq!(&bytes[..received.len], b"real packet");
        assert_eq!(received.ecn, None);
    }
    #[test]
    fn payload_truncation_is_not_admitted() {
        let sender = socket(false);
        let mut receiver = socket(false);
        sender
            .send_to(&[9; 32], receiver.local_addr().unwrap(), Codepoint::Ect0)
            .unwrap();
        assert_eq!(
            receiver.recv_from(&mut [0; 4]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
    #[test]
    fn ancillary_truncation_is_not_reported_as_unmarked() {
        let sender = socket(false);
        let mut receiver = socket(false);
        receiver.control = Vec::new();
        sender
            .send_to(b"x", receiver.local_addr().unwrap(), Codepoint::Ect0)
            .unwrap();
        assert_eq!(
            receiver.recv_from(&mut [0; 64]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
    #[test]
    fn malformed_or_conflicting_metadata_fails_closed() {
        assert_eq!(
            decode_ecn([ControlMessageOwned::Ipv4Tos(0xba)]).unwrap(),
            Some(Codepoint::Ect0)
        );
        for class in [-1, 256, i32::MAX] {
            assert_eq!(
                decode_ecn([ControlMessageOwned::Ipv6TClass(class)])
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
        assert!(
            decode_ecn([
                ControlMessageOwned::Ipv4Tos(2),
                ControlMessageOwned::Ipv6TClass(3)
            ])
            .is_err()
        );
        assert_eq!(
            decode_ecn([
                ControlMessageOwned::Ipv4Tos(2),
                ControlMessageOwned::Ipv6TClass(2)
            ])
            .unwrap(),
            Some(Codepoint::Ect0)
        );
    }
    #[test]
    fn send_family_mismatch_is_an_explicit_error() {
        assert_eq!(
            socket(false)
                .send_to(b"x", "[::1]:1".parse().unwrap(), Codepoint::Ect0)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
