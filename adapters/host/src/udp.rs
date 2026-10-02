//! Safe typed Linux UDP ancillary metadata using nix's recvmsg/sendmsg wrappers.
//! No raw control-message casts or unsafe code are implemented here. Host setup
//! and nix's sendmsg control buffer can allocate; this is not a no_alloc boundary.
//! No socket-global ECN setting is changed when sending an individual datagram.

pub use hibana_quic::ecn::Codepoint;
use hibana_quic::path::Address;
use nix::libc;
use nix::sys::socket::{
    ControlMessage, ControlMessageOwned, MsgFlags, SockaddrStorage, recvmsg, sendmsg, setsockopt,
    sockopt,
};
use std::{
    io::{self, IoSlice, IoSliceMut},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket},
    os::fd::AsRawFd,
    time::Duration,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Received {
    pub len: usize,
    pub source: SocketAddr,
    /// Actual destination IP from packet info, with this socket's bound port.
    /// Scoped IPv6 destinations include the receiving interface's scope ID.
    pub local: SocketAddr,
    /// None is unavailable metadata, never fabricated Not-ECT evidence.
    pub ecn: Option<Codepoint>,
}

pub struct UdpMetadataSocket {
    socket: UdpSocket,
    control: Vec<u8>,
}

impl UdpMetadataSocket {
    /// Borrow the existing descriptor for the host readiness reactor only.
    pub(crate) fn socket(&self) -> &UdpSocket {
        &self.socket
    }
    /// Enable native packet-info and IPv4 TOS or IPv6 Traffic Class reception.
    /// Errors are reported rather than inventing address or ECN metadata.
    /// IPv4-mapped dual-stack delivery is not a qualified profile here.
    pub fn new(socket: UdpSocket) -> io::Result<Self> {
        if socket.local_addr()?.is_ipv4() {
            setsockopt(&socket, sockopt::IpRecvTos, &true)?;
            setsockopt(&socket, sockopt::Ipv4PacketInfo, &true)?;
        } else {
            setsockopt(&socket, sockopt::Ipv6RecvTClass, &true)?;
            setsockopt(&socket, sockopt::Ipv6RecvPacketInfo, &true)?;
        }
        Ok(Self {
            socket,
            control: nix::cmsg_space!(u8, i32, libc::in_pktinfo, libc::in6_pktinfo),
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

    /// Reject a truncated datagram or ancillary buffer and retain kernel ECN.
    /// Missing ECN remains None. Missing destination metadata falls back only to
    /// a concrete bound address; it is an error for a wildcard binding.
    pub fn recv_from(&mut self, bytes: &mut [u8]) -> io::Result<Received> {
        let bound = self.socket.local_addr()?;
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
        if bound.is_ipv4() != source.is_ipv4()
            || matches!(source, SocketAddr::V6(a) if a.ip().to_ipv4_mapped().is_some())
        {
            return Err(invalid("non-native UDP source address"));
        }
        let (local, ecn) = decode_metadata(bound, message.cmsgs()?)?;
        Ok(Received {
            len: message.bytes,
            source,
            local,
            ecn,
        })
    }

    /// Send from the exact local endpoint in a path tuple. A wildcard binding
    /// permits concrete local IP selection; a concrete binding permits only its
    /// own IP. The family and bound port must match. The kernel checks whether
    /// the selected source/interface is usable; failures never trigger fallback.
    /// Source selection and ECN both apply only to this datagram.
    pub fn send_from(&self, bytes: &[u8], address: Address, ecn: Codepoint) -> io::Result<usize> {
        validate_source(self.socket.local_addr()?, address)?;
        let destination = SockaddrStorage::from(address.remote);
        let iov = [IoSlice::new(bytes)];
        let bits = ecn.bits();
        let class = i32::from(bits);
        let len = match address.local {
            SocketAddr::V4(local) => {
                let info = libc::in_pktinfo {
                    ipi_ifindex: 0,
                    // in_addr stores network-order bytes in native integer storage.
                    ipi_spec_dst: libc::in_addr {
                        s_addr: u32::from_ne_bytes(local.ip().octets()),
                    },
                    ipi_addr: libc::in_addr { s_addr: 0 },
                };
                sendmsg(
                    self.socket.as_raw_fd(),
                    &iov,
                    &[
                        ControlMessage::Ipv4PacketInfo(&info),
                        ControlMessage::Ipv4Tos(&bits),
                    ],
                    MsgFlags::empty(),
                    Some(&destination),
                )?
            }
            SocketAddr::V6(local) => {
                let info = libc::in6_pktinfo {
                    ipi6_addr: libc::in6_addr {
                        s6_addr: local.ip().octets(),
                    },
                    ipi6_ifindex: local.scope_id(),
                };
                sendmsg(
                    self.socket.as_raw_fd(),
                    &iov,
                    &[
                        ControlMessage::Ipv6PacketInfo(&info),
                        ControlMessage::Ipv6TClass(&class),
                    ],
                    MsgFlags::empty(),
                    Some(&destination),
                )?
            }
        };
        Ok(len)
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

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn scoped(ip: Ipv6Addr) -> bool {
    ip.is_unicast_link_local() || (ip.is_multicast() && ip.octets()[1] & 0x0f != 0x0e)
}

fn validate_source(bound: SocketAddr, address: Address) -> io::Result<()> {
    let local = address.local;
    if bound.is_ipv4() != local.is_ipv4() || local.is_ipv4() != address.remote.is_ipv4() {
        return Err(invalid_input("native address family mismatch"));
    }
    if bound.port() != local.port() || local.port() == 0 {
        return Err(invalid_input("source port does not match UDP binding"));
    }
    if local.ip().is_unspecified() || local.ip().is_multicast() {
        return Err(invalid_input("source address must be concrete unicast"));
    }
    if !bound.ip().is_unspecified() && bound.ip() != local.ip() {
        return Err(invalid_input("source address does not match UDP binding"));
    }
    match (bound, local, address.remote) {
        (SocketAddr::V4(_), SocketAddr::V4(local), _) if local.ip().is_broadcast() => {
            return Err(invalid_input("broadcast source address"));
        }
        (SocketAddr::V6(bound), SocketAddr::V6(local), SocketAddr::V6(remote)) => {
            if local.ip().to_ipv4_mapped().is_some() || remote.ip().to_ipv4_mapped().is_some() {
                return Err(invalid_input("IPv4-mapped addresses are not supported"));
            }
            if local.flowinfo() != 0 {
                return Err(invalid_input("source flow information is not supported"));
            }
            if (scoped(*local.ip()) && local.scope_id() == 0)
                || (bound.scope_id() != 0 && local.scope_id() != bound.scope_id())
            {
                return Err(invalid_input(
                    "source interface scope does not match UDP binding",
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

fn decode_metadata(
    bound: SocketAddr,
    messages: impl IntoIterator<Item = ControlMessageOwned>,
) -> io::Result<(SocketAddr, Option<Codepoint>)> {
    let mut destination = None;
    let mut ecn = None;
    for message in messages {
        let packet_info = match message {
            ControlMessageOwned::Ipv4PacketInfo(info) => {
                if !bound.is_ipv4() || info.ipi_ifindex <= 0 {
                    return Err(invalid("invalid IPv4 packet-info family or interface"));
                }
                let ip = Ipv4Addr::from(info.ipi_addr.s_addr.to_ne_bytes());
                (
                    SocketAddr::from((ip, bound.port())),
                    info.ipi_ifindex as u32,
                )
            }
            ControlMessageOwned::Ipv6PacketInfo(info) => {
                if !bound.is_ipv6() || info.ipi6_ifindex == 0 {
                    return Err(invalid("invalid IPv6 packet-info family or interface"));
                }
                let ip = Ipv6Addr::from(info.ipi6_addr.s6_addr);
                if ip.to_ipv4_mapped().is_some() {
                    return Err(invalid("IPv4-mapped packet info is not supported"));
                }
                let scope = if scoped(ip) { info.ipi6_ifindex } else { 0 };
                (
                    SocketAddr::V6(SocketAddrV6::new(ip, bound.port(), 0, scope)),
                    info.ipi6_ifindex,
                )
            }
            ControlMessageOwned::Ipv4Tos(tos) => {
                if !bound.is_ipv4() {
                    return Err(invalid("non-native IPv4 ECN metadata"));
                }
                record_ecn(&mut ecn, tos)?;
                continue;
            }
            ControlMessageOwned::Ipv6TClass(class) => {
                if !bound.is_ipv6() {
                    return Err(invalid("non-native IPv6 ECN metadata"));
                }
                record_ecn(&mut ecn, traffic_class(class)?)?;
                continue;
            }
            _ => continue,
        };
        if packet_info.0.ip().is_unspecified()
            || (!bound.ip().is_unspecified() && packet_info.0.ip() != bound.ip())
        {
            return Err(invalid("packet-info destination contradicts UDP binding"));
        }
        if let SocketAddr::V6(bound) = bound
            && bound.scope_id() != 0
            && bound.scope_id() != packet_info.1
        {
            return Err(invalid("packet-info interface contradicts UDP binding"));
        }
        if destination.is_some_and(|earlier| earlier != packet_info) {
            return Err(invalid("conflicting destination ancillary metadata"));
        }
        destination = Some(packet_info);
    }
    let local = match destination {
        Some((local, _)) => local,
        None if !bound.ip().is_unspecified() => bound,
        None => {
            return Err(invalid(
                "missing destination metadata for wildcard UDP binding",
            ));
        }
    };
    Ok((local, ecn))
}

fn traffic_class(class: i32) -> io::Result<u8> {
    u8::try_from(class).map_err(|_| invalid("invalid IPv6 traffic class"))
}

fn record_ecn(found: &mut Option<Codepoint>, bits: u8) -> io::Result<()> {
    let codepoint = Codepoint::from_ip_tos(bits);
    if found.is_some_and(|earlier| earlier != codepoint) {
        return Err(invalid("conflicting ECN ancillary metadata"));
    }
    *found = Some(codepoint);
    Ok(())
}

#[cfg(test)]
fn decode_ecn(
    messages: impl IntoIterator<Item = ControlMessageOwned>,
) -> io::Result<Option<Codepoint>> {
    let mut found = None;
    for message in messages {
        let bits = match message {
            ControlMessageOwned::Ipv4Tos(tos) => tos,
            ControlMessageOwned::Ipv6TClass(class) => traffic_class(class)?,
            _ => continue,
        };
        record_ecn(&mut found, bits)?;
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
            assert_eq!(received.local, receiver.local_addr().unwrap());
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
    fn send_from_concrete_binding_preserves_the_full_tuple_and_ecn() {
        for v6 in [false, true] {
            let sender = socket(v6);
            let mut receiver = socket(v6);
            let address = Address {
                local: sender.local_addr().unwrap(),
                remote: receiver.local_addr().unwrap(),
            };
            assert_eq!(sender.send_from(b"x", address, Codepoint::Ect0).unwrap(), 1);
            let mut bytes = [0; 8];
            let received = receiver.recv_from(&mut bytes).unwrap();
            assert_eq!(received.source, address.local);
            assert_eq!(received.local, address.remote);
            assert_eq!(received.ecn, Some(Codepoint::Ect0));
            assert_eq!(&bytes[..received.len], b"x");
        }
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
        assert_eq!(received.local, receiver.local_addr().unwrap());
    }

    #[test]
    fn wildcard_ipv4_destination_and_reply_source_are_actual_addresses() {
        let mut client = socket(false);
        let mut server = UdpMetadataSocket::new(UdpSocket::bind("0.0.0.0:0").unwrap()).unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut bytes = [0; 64];
        for ip in [Ipv4Addr::LOCALHOST, Ipv4Addr::new(127, 0, 0, 2)] {
            let destination = SocketAddr::from((ip, server.local_addr().unwrap().port()));
            client
                .send_to(b"request", destination, Codepoint::Ect0)
                .unwrap();
            let request = server.recv_from(&mut bytes).unwrap();
            assert_eq!(request.local, destination);
            assert_eq!(request.source, client.local_addr().unwrap());
            assert_eq!(request.ecn, Some(Codepoint::Ect0));
            assert_eq!(&bytes[..request.len], b"request");
            assert_eq!(
                server
                    .send_from(
                        b"response",
                        Address {
                            local: request.local,
                            remote: request.source
                        },
                        Codepoint::Ect1,
                    )
                    .unwrap(),
                8,
            );
            let response = client.recv_from(&mut bytes).unwrap();
            assert_eq!(response.local, request.source);
            assert_eq!(response.source, request.local);
            assert_eq!(response.ecn, Some(Codepoint::Ect1));
            assert_eq!(&bytes[..response.len], b"response");
        }
    }

    #[test]
    fn wildcard_ipv6_destination_and_reply_source_are_actual_addresses() {
        let mut client = socket(true);
        let mut server = UdpMetadataSocket::new(UdpSocket::bind("[::]:0").unwrap()).unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let destination =
            SocketAddr::from((Ipv6Addr::LOCALHOST, server.local_addr().unwrap().port()));
        let mut bytes = [0; 64];
        client
            .send_to(b"request", destination, Codepoint::Ce)
            .unwrap();
        let request = server.recv_from(&mut bytes).unwrap();
        assert_eq!(request.local, destination);
        assert_eq!(request.source, client.local_addr().unwrap());
        assert_eq!(request.ecn, Some(Codepoint::Ce));
        assert_eq!(&bytes[..request.len], b"request");
        assert_eq!(
            server
                .send_from(
                    b"response",
                    Address {
                        local: request.local,
                        remote: request.source
                    },
                    Codepoint::NotEct,
                )
                .unwrap(),
            8,
        );
        let response = client.recv_from(&mut bytes).unwrap();
        assert_eq!(response.local, request.source);
        assert_eq!(response.source, request.local);
        assert_eq!(response.ecn, Some(Codepoint::NotEct));
        assert_eq!(&bytes[..response.len], b"response");
    }

    #[test]
    fn wildcard_without_destination_metadata_fails_explicitly() {
        for v6 in [false, true] {
            let sender = socket(v6);
            let raw = UdpSocket::bind(if v6 { "[::]:0" } else { "0.0.0.0:0" }).unwrap();
            raw.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            let mut receiver = UdpMetadataSocket {
                socket: raw,
                control: nix::cmsg_space!(u8, i32, libc::in_pktinfo, libc::in6_pktinfo),
            };
            let mut destination = sender.local_addr().unwrap();
            destination.set_port(receiver.local_addr().unwrap().port());
            sender.send_to(b"x", destination, Codepoint::Ect0).unwrap();
            assert_eq!(
                receiver.recv_from(&mut [0; 8]).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    fn ipv4_info(ip: &str, interface: i32) -> ControlMessageOwned {
        ControlMessageOwned::Ipv4PacketInfo(libc::in_pktinfo {
            ipi_ifindex: interface,
            // Deliberately differ: the destination comes from ipi_addr.
            ipi_spec_dst: libc::in_addr { s_addr: 0 },
            ipi_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(ip.parse::<Ipv4Addr>().unwrap().octets()),
            },
        })
    }

    fn ipv6_info(ip: &str, interface: u32) -> ControlMessageOwned {
        ControlMessageOwned::Ipv6PacketInfo(libc::in6_pktinfo {
            ipi6_ifindex: interface,
            ipi6_addr: libc::in6_addr {
                s6_addr: ip.parse::<Ipv6Addr>().unwrap().octets(),
            },
        })
    }

    #[test]
    fn ipv6_scoped_destination_uses_actual_receiving_interface() {
        let wildcard = "[::]:9000".parse().unwrap();
        for ip in ["fe80::42", "ff02::42"] {
            let (local, ecn) = decode_metadata(wildcard, [ipv6_info(ip, 7)]).unwrap();
            assert_eq!(
                local,
                SocketAddr::V6(SocketAddrV6::new(ip.parse().unwrap(), 9000, 0, 7))
            );
            assert_eq!(ecn, None);
        }
        for ip in ["::1", "2001:db8::42", "ff0e::42"] {
            let (local, _) = decode_metadata(wildcard, [ipv6_info(ip, 7)]).unwrap();
            assert_eq!(
                local,
                SocketAddr::V6(SocketAddrV6::new(ip.parse().unwrap(), 9000, 0, 0))
            );
        }
    }

    #[test]
    fn malformed_conflicting_or_mismatched_destination_metadata_fails_closed() {
        let v4 = "0.0.0.0:9000".parse().unwrap();
        let v6 = "[::]:9000".parse().unwrap();
        for (bound, messages) in [
            (v4, vec![ipv4_info("0.0.0.0", 1)]),
            (v4, vec![ipv4_info("127.0.0.1", 0)]),
            (v4, vec![ipv4_info("127.0.0.1", -1)]),
            (v4, vec![ipv6_info("::1", 1)]),
            (
                v4,
                vec![ipv4_info("127.0.0.1", 1), ipv4_info("127.0.0.2", 1)],
            ),
            (
                v4,
                vec![ipv4_info("127.0.0.1", 1), ipv4_info("127.0.0.1", 2)],
            ),
            (v6, vec![ipv6_info("::", 1)]),
            (v6, vec![ipv6_info("::1", 0)]),
            (v6, vec![ipv6_info("::ffff:127.0.0.1", 1)]),
            (v6, vec![ipv4_info("127.0.0.1", 1)]),
            (v6, vec![ipv6_info("::1", 1), ipv6_info("::2", 1)]),
            (v6, vec![ipv6_info("::1", 1), ipv6_info("::1", 2)]),
            (
                "127.0.0.1:9000".parse().unwrap(),
                vec![ipv4_info("127.0.0.2", 1)],
            ),
            ("[::1]:9000".parse().unwrap(), vec![ipv6_info("::2", 1)]),
            (
                "[fe80::42%7]:9000".parse().unwrap(),
                vec![ipv6_info("fe80::42", 8)],
            ),
            (
                v4,
                vec![
                    ipv4_info("127.0.0.1", 1),
                    ControlMessageOwned::Ipv6TClass(2),
                ],
            ),
            (
                v6,
                vec![ipv6_info("::1", 1), ControlMessageOwned::Ipv4Tos(2)],
            ),
            (
                v6,
                vec![ipv6_info("::1", 1), ControlMessageOwned::Ipv6TClass(256)],
            ),
            (
                v4,
                vec![
                    ipv4_info("127.0.0.1", 1),
                    ControlMessageOwned::Ipv4Tos(2),
                    ControlMessageOwned::Ipv4Tos(3),
                ],
            ),
        ] {
            assert_eq!(
                decode_metadata(bound, messages).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
        assert_eq!(
            decode_metadata(v4, [ipv4_info("127.0.0.2", 1), ipv4_info("127.0.0.2", 1)]).unwrap(),
            ("127.0.0.2:9000".parse().unwrap(), None),
        );
    }

    #[test]
    fn send_from_enforces_bound_port_family_and_local_address_policy() {
        for v6 in [false, true] {
            let sender = socket(v6);
            let local = sender.local_addr().unwrap();
            let remote = socket(v6).local_addr().unwrap();
            let mut wrong_port = local;
            wrong_port.set_port(if local.port() == 1 { 2 } else { 1 });
            let wrong_family: SocketAddr =
                if v6 { "127.0.0.1:9" } else { "[::1]:9" }.parse().unwrap();
            let wrong_ip = if v6 {
                SocketAddr::from(("::2".parse::<Ipv6Addr>().unwrap(), local.port()))
            } else {
                SocketAddr::from((Ipv4Addr::new(127, 0, 0, 2), local.port()))
            };
            for address in [
                Address {
                    local: wrong_port,
                    remote,
                },
                Address {
                    local: wrong_ip,
                    remote,
                },
                Address {
                    local: wrong_family,
                    remote,
                },
                Address {
                    local,
                    remote: wrong_family,
                },
            ] {
                assert_eq!(
                    sender
                        .send_from(b"x", address, Codepoint::Ect0)
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::InvalidInput
                );
            }
        }
        let bound = "[::]:9000".parse().unwrap();
        let remote = "[::1]:9001".parse().unwrap();
        for local in [
            "[::]:9000",
            "[ff02::1%1]:9000",
            "[::ffff:127.0.0.1]:9000",
            "[fe80::1]:9000",
        ] {
            assert!(
                validate_source(
                    bound,
                    Address {
                        local: local.parse().unwrap(),
                        remote
                    }
                )
                .is_err()
            );
        }
        let source = "[fe80::1%7]:9000".parse().unwrap();
        assert!(
            validate_source(
                bound,
                Address {
                    local: source,
                    remote
                }
            )
            .is_ok()
        );
        assert!(
            validate_source(
                "[fe80::1%8]:9000".parse().unwrap(),
                Address {
                    local: source,
                    remote
                }
            )
            .is_err()
        );
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
