//! Native UDP ancillary metadata; no external socket package.
//! Source selection and ECN are per datagram.

use crate::sys::udp::{self as native, Metadata as ControlMessageOwned};
#[cfg(test)]
use crate::sys::udp::{In6Addr, InAddr, Info4, Info6};
pub use hibana_quic::quic::ecn::imp::Codepoint;
use hibana_quic::quic::path::Address;
use std::{
    io::{self},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket},
    time::Duration,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Received {
    pub len: usize,
    /// IPv4-mapped dual-stack peers are reported as native IPv4 addresses.
    pub source: SocketAddr,
    /// Actual destination IP from packet info, with this socket's bound port.
    /// Scoped IPv6 destinations include the receiving interface's scope ID.
    /// IPv4-mapped dual-stack destinations are reported as native IPv4.
    pub local: SocketAddr,
    /// None is unavailable metadata, never fabricated Not-ECT evidence.
    pub ecn: Option<Codepoint>,
}

pub struct UdpMetadataSocket {
    socket: UdpSocket,
    control: Vec<u8>,
    dual_stack: bool,
}

impl UdpMetadataSocket {
    /// Borrow the existing descriptor for the host readiness reactor only.
    pub(crate) fn socket(&self) -> &UdpSocket {
        &self.socket
    }
    /// Enable packet-info and IPv4 TOS or IPv6 Traffic Class reception.
    /// Errors are reported rather than inventing address or ECN metadata.
    /// Dual-stack IPv4 delivery is canonicalized to native IPv4 endpoints.
    pub fn new(socket: UdpSocket) -> io::Result<Self> {
        let ipv4 = socket.local_addr()?.is_ipv4();
        let dual_stack = !ipv4 && !native::ipv6_only(&socket)?;
        native::enable(&socket, ipv4, dual_stack)?;
        Ok(Self {
            socket,
            control: vec![0; native::CONTROL_CAPACITY],
            dual_stack,
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
        let message = native::receive(&self.socket, bytes, self.control.len())?;
        let source = message.address;
        let source = canonical_source(bound, source, self.dual_stack)?;
        let (local, ecn) = decode_metadata(
            bound,
            source.is_ipv4(),
            message.metadata.into_iter().flatten(),
        )?;
        Ok(Received {
            len: message.bytes,
            source,
            local,
            ecn,
        })
    }

    /// Send from the exact local endpoint in a path tuple. A wildcard binding
    /// permits concrete local IP selection; a concrete binding permits only its
    /// own IP. The wire family and bound port must match; IPv4 paths may use a
    /// dual-stack IPv6 binding. The kernel checks whether
    /// the selected source/interface is usable; failures never trigger fallback.
    /// Source selection and ECN both apply only to this datagram.
    pub fn send_from(&self, bytes: &[u8], address: Address, ecn: Codepoint) -> io::Result<usize> {
        let bound = self.socket.local_addr()?;
        validate_source(bound, address)?;
        let destination = send_destination(bound, address.remote, self.dual_stack)?;
        native::send(
            &self.socket,
            bytes,
            destination,
            Some(address.local),
            address.local.is_ipv4(),
            ecn.bits(),
        )
    }

    /// Set ECN in this sendmsg's ancillary data, with DSCP zero. The transport
    /// chooses ECT(0)/Not-ECT and commits accounting only after full acceptance.
    /// CE is exposed for explicit local metadata tests, never selected for sending by the current endpoint.
    pub fn send_to(
        &self,
        bytes: &[u8],
        destination: SocketAddr,
        ecn: Codepoint,
    ) -> io::Result<usize> {
        let ipv4 = destination.is_ipv4();
        let destination =
            send_destination(self.socket.local_addr()?, destination, self.dual_stack)?;
        native::send(&self.socket, bytes, destination, None, ipv4, ecn.bits())
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

fn canonical_address(address: SocketAddr) -> Option<SocketAddr> {
    if let SocketAddr::V6(address) = address
        && let Some(ip) = address.ip().to_ipv4_mapped()
    {
        // IPv4 has no equivalent scope or flow label. Never silently drop one.
        return (address.scope_id() == 0 && address.flowinfo() == 0)
            .then(|| SocketAddr::from((ip, address.port())));
    }
    Some(address)
}

fn supports_family(bound: SocketAddr, ipv4: bool) -> bool {
    canonical_address(bound).is_some_and(|canonical| canonical.is_ipv4() == ipv4)
        || (ipv4
            && matches!(bound, SocketAddr::V6(a)
                if a.ip().is_unspecified() && a.scope_id() == 0 && a.flowinfo() == 0))
}

fn canonical_source(
    bound: SocketAddr,
    source: SocketAddr,
    dual_stack: bool,
) -> io::Result<SocketAddr> {
    if bound.is_ipv4() != source.is_ipv4() {
        return Err(invalid("UDP source sockaddr family contradicts binding"));
    }
    let source = canonical_address(source)
        .ok_or_else(|| invalid("ambiguous IPv4-mapped UDP source address"))?;
    if !supports_family(bound, source.is_ipv4())
        || (bound.is_ipv6() && source.is_ipv4() && !dual_stack)
    {
        return Err(invalid("UDP source wire family contradicts binding"));
    }
    Ok(source)
}

fn send_destination(
    bound: SocketAddr,
    destination: SocketAddr,
    dual_stack: bool,
) -> io::Result<SocketAddr> {
    if canonical_address(destination) != Some(destination)
        || !supports_family(bound, destination.is_ipv4())
    {
        return Err(invalid_input("native address family mismatch"));
    }
    if let (SocketAddr::V6(_), SocketAddr::V4(destination)) = (bound, destination) {
        if !dual_stack {
            return Err(invalid_input("IPv4 destination on IPv6-only UDP binding"));
        }
        // Linux uses a mapped IPv6 sockaddr with IPv4 IP_PKTINFO/IP_TOS for
        // this wire family. Do not choose ancillary types from sockaddr family.
        return Ok(SocketAddr::V6(SocketAddrV6::new(
            destination.ip().to_ipv6_mapped(),
            destination.port(),
            0,
            0,
        )));
    }
    Ok(destination)
}

fn validate_source(bound: SocketAddr, address: Address) -> io::Result<()> {
    let local = address.local;
    if !supports_family(bound, local.is_ipv4()) || local.is_ipv4() != address.remote.is_ipv4() {
        return Err(invalid_input("native address family mismatch"));
    }
    let canonical_bound = canonical_address(bound)
        .ok_or_else(|| invalid_input("ambiguous IPv4-mapped UDP binding"))?;
    if bound.port() != local.port() || local.port() == 0 {
        return Err(invalid_input("source port does not match UDP binding"));
    }
    if local.ip().is_unspecified() || local.ip().is_multicast() {
        return Err(invalid_input("source address must be concrete unicast"));
    }
    if !canonical_bound.ip().is_unspecified() && canonical_bound.ip() != local.ip() {
        return Err(invalid_input("source address does not match UDP binding"));
    }
    match (bound, local, address.remote) {
        (_, SocketAddr::V4(local), _) if local.ip().is_broadcast() => {
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
    ipv4: bool,
    messages: impl IntoIterator<Item = ControlMessageOwned>,
) -> io::Result<(SocketAddr, Option<Codepoint>)> {
    let canonical_bound =
        canonical_address(bound).ok_or_else(|| invalid("ambiguous IPv4-mapped UDP binding"))?;
    if !supports_family(bound, ipv4) {
        return Err(invalid("UDP packet wire family contradicts binding"));
    }
    let mut destination = None;
    let mut ecn = None;
    for message in messages {
        let packet_info = match message {
            ControlMessageOwned::Ipv4PacketInfo(info) => {
                if !ipv4 || info.ipi_ifindex <= 0 {
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
                let scope = if scoped(ip) { info.ipi6_ifindex } else { 0 };
                (
                    canonical_address(SocketAddr::V6(SocketAddrV6::new(
                        ip,
                        bound.port(),
                        0,
                        scope,
                    )))
                    .ok_or_else(|| invalid("ambiguous IPv4-mapped packet info"))?,
                    info.ipi6_ifindex,
                )
            }
            ControlMessageOwned::Ipv4Tos(tos) => {
                if !ipv4 {
                    return Err(invalid("non-native IPv4 ECN metadata"));
                }
                record_ecn(&mut ecn, tos)?;
                continue;
            }
            ControlMessageOwned::Ipv6TClass(class) => {
                if ipv4 {
                    return Err(invalid("non-native IPv6 ECN metadata"));
                }
                record_ecn(&mut ecn, traffic_class(class)?)?;
                continue;
            }
        };
        if packet_info.0.is_ipv4() != ipv4 {
            return Err(invalid("packet-info family contradicts UDP source"));
        }
        if packet_info.0.ip().is_unspecified()
            || (!canonical_bound.ip().is_unspecified()
                && packet_info.0.ip() != canonical_bound.ip())
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
        None if !canonical_bound.ip().is_unspecified() => canonical_bound,
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
            ControlMessageOwned::Ipv4PacketInfo(_) | ControlMessageOwned::Ipv6PacketInfo(_) => {
                continue;
            }
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
            control: vec![0; native::SMALL_CONTROL_CAPACITY],
            dual_stack: false,
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
    fn dual_stack_alternating_wire_families_preserve_exact_tuple_and_ecn() {
        let mut server = UdpMetadataSocket::new(UdpSocket::bind("[::]:0").unwrap()).unwrap();
        assert!(server.dual_stack);
        server
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut v4 = socket(false);
        let mut v6 = socket(true);
        let mut bytes = [0; 64];
        for code in [
            Codepoint::NotEct,
            Codepoint::Ect0,
            Codepoint::Ect1,
            Codepoint::Ce,
            Codepoint::NotEct,
        ] {
            for ip in ["127.0.0.1", "::1", "127.0.0.2"] {
                let destination =
                    SocketAddr::new(ip.parse().unwrap(), server.local_addr().unwrap().port());
                let client = if destination.is_ipv4() {
                    &mut v4
                } else {
                    &mut v6
                };
                client.send_to(b"request", destination, code).unwrap();
                let request = server.recv_from(&mut bytes).unwrap();
                assert_eq!(request.source, client.local_addr().unwrap());
                assert_eq!(request.local, destination);
                assert_eq!(request.ecn, Some(code));
                assert_eq!(&bytes[..request.len], b"request");
                assert_eq!(
                    server
                        .send_from(
                            b"response",
                            Address {
                                local: request.local,
                                remote: request.source,
                            },
                            code
                        )
                        .unwrap(),
                    8
                );
                let response = client.recv_from(&mut bytes).unwrap();
                assert_eq!(response.source, destination);
                assert_eq!(response.local, request.source);
                assert_eq!(response.ecn, Some(code));
                assert_eq!(&bytes[..response.len], b"response");
            }
        }
    }

    #[test]
    fn mapped_concrete_binding_uses_canonical_ipv4_tuple() {
        let mut server =
            UdpMetadataSocket::new(UdpSocket::bind("[::ffff:127.0.0.2]:0").unwrap()).unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let destination = SocketAddr::from((
            Ipv4Addr::new(127, 0, 0, 2),
            server.local_addr().unwrap().port(),
        ));
        let mut client = socket(false);
        client
            .send_to(b"request", destination, Codepoint::Ce)
            .unwrap();
        let mut bytes = [0; 64];
        let request = server.recv_from(&mut bytes).unwrap();
        assert_eq!(request.local, destination);
        assert_eq!(request.source, client.local_addr().unwrap());
        assert_eq!(request.ecn, Some(Codepoint::Ce));
        server
            .send_from(
                b"response",
                Address {
                    local: request.local,
                    remote: request.source,
                },
                Codepoint::Ect1,
            )
            .unwrap();
        let response = client.recv_from(&mut bytes).unwrap();
        assert_eq!(response.source, destination);
        assert_eq!(response.local, request.source);
        assert_eq!(response.ecn, Some(Codepoint::Ect1));
        assert_eq!(&bytes[..response.len], b"response");
        let wrong_local = SocketAddr::from((Ipv4Addr::LOCALHOST, destination.port()));
        assert_eq!(
            server
                .send_from(
                    b"x",
                    Address {
                        local: wrong_local,
                        remote: request.source,
                    },
                    Codepoint::NotEct
                )
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn dual_stack_send_to_uses_ipv4_ecn_for_canonical_ipv4_destination() {
        let sender = UdpMetadataSocket::new(UdpSocket::bind("[::]:0").unwrap()).unwrap();
        let mut receiver = socket(false);
        for code in [
            Codepoint::Ce,
            Codepoint::NotEct,
            Codepoint::Ect0,
            Codepoint::Ect1,
        ] {
            sender
                .send_to(b"x", receiver.local_addr().unwrap(), code)
                .unwrap();
            let received = receiver.recv_from(&mut [0; 8]).unwrap();
            assert_eq!(received.ecn, Some(code));
            assert_eq!(received.source.ip(), Ipv4Addr::LOCALHOST);
            assert_eq!(received.source.port(), sender.local_addr().unwrap().port());
            assert_eq!(received.local, receiver.local_addr().unwrap());
        }
    }

    #[test]
    fn ipv6_only_socket_rejects_ipv4_without_changing_its_policy() {
        let mut server = UdpMetadataSocket::new(native::bind_v6_only().unwrap()).unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        assert!(!server.dual_stack);
        assert!(native::ipv6_only(&server.socket).unwrap());
        let local = SocketAddr::from((Ipv4Addr::LOCALHOST, server.local_addr().unwrap().port()));
        let remote = "127.0.0.1:9001".parse().unwrap();
        assert_eq!(
            server
                .send_from(b"x", Address { local, remote }, Codepoint::Ect0)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            server
                .send_to(b"x", remote, Codepoint::Ect0)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        let mut client = socket(true);
        let destination = SocketAddr::from((Ipv6Addr::LOCALHOST, local.port()));
        client.send_to(b"x", destination, Codepoint::Ce).unwrap();
        let request = server.recv_from(&mut [0; 8]).unwrap();
        assert_eq!(request.local, destination);
        assert_eq!(request.source, client.local_addr().unwrap());
        assert_eq!(request.ecn, Some(Codepoint::Ce));
        server
            .send_from(
                b"x",
                Address {
                    local: request.local,
                    remote: request.source,
                },
                Codepoint::Ect1,
            )
            .unwrap();
        let response = client.recv_from(&mut [0; 8]).unwrap();
        assert_eq!(response.source, destination);
        assert_eq!(response.ecn, Some(Codepoint::Ect1));
    }

    #[test]
    fn dual_stack_source_policy_preserves_port_concrete_and_family_checks() {
        let bound = "[::]:9000".parse().unwrap();
        let remote = "127.0.0.1:9001".parse().unwrap();
        for ip in ["127.0.0.1", "127.0.0.2"] {
            assert!(
                validate_source(
                    bound,
                    Address {
                        local: SocketAddr::new(ip.parse().unwrap(), 9000),
                        remote,
                    }
                )
                .is_ok()
            );
        }
        for local in [
            "127.0.0.1:0",
            "127.0.0.1:9002",
            "0.0.0.0:9000",
            "224.0.0.1:9000",
            "255.255.255.255:9000",
            "[::1]:9000",
            "[::ffff:127.0.0.1]:9000",
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
        let local = "127.0.0.1:9000".parse().unwrap();
        for remote in ["[::1]:9001", "[::ffff:127.0.0.1]:9001"] {
            assert!(
                validate_source(
                    bound,
                    Address {
                        local,
                        remote: remote.parse().unwrap()
                    }
                )
                .is_err()
            );
        }
        assert!(send_destination(bound, "[::1]:9001".parse().unwrap(), true).is_ok());
        assert!(send_destination(bound, "[::ffff:127.0.0.1]:9001".parse().unwrap(), true).is_err());
        assert!(validate_source("[::1]:9000".parse().unwrap(), Address { local, remote }).is_err());
        assert!(
            validate_source("[::%7]:9000".parse().unwrap(), Address { local, remote }).is_err()
        );
    }

    #[test]
    fn wildcard_without_destination_metadata_fails_explicitly() {
        for v6 in [false, true] {
            let sender = socket(v6);
            let raw = UdpSocket::bind(if v6 { "[::]:0" } else { "0.0.0.0:0" }).unwrap();
            raw.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            let mut receiver = UdpMetadataSocket {
                socket: raw,
                control: vec![0; native::CONTROL_CAPACITY],
                dual_stack: v6,
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
        ControlMessageOwned::Ipv4PacketInfo(Info4 {
            ipi_ifindex: interface,
            // Deliberately differ: the destination comes from ipi_addr.
            ipi_addr: InAddr {
                s_addr: u32::from_ne_bytes(ip.parse::<Ipv4Addr>().unwrap().octets()),
            },
        })
    }

    fn ipv6_info(ip: &str, interface: u32) -> ControlMessageOwned {
        ControlMessageOwned::Ipv6PacketInfo(Info6 {
            ipi6_ifindex: interface,
            ipi6_addr: In6Addr {
                s6_addr: ip.parse::<Ipv6Addr>().unwrap().octets(),
            },
        })
    }

    #[test]
    fn ipv6_scoped_destination_uses_actual_receiving_interface() {
        let wildcard = "[::]:9000".parse().unwrap();
        for ip in ["fe80::42", "ff02::42"] {
            let (local, ecn) = decode_metadata(wildcard, false, [ipv6_info(ip, 7)]).unwrap();
            assert_eq!(
                local,
                SocketAddr::V6(SocketAddrV6::new(ip.parse().unwrap(), 9000, 0, 7))
            );
            assert_eq!(ecn, None);
        }
        for ip in ["::1", "2001:db8::42", "ff0e::42"] {
            let (local, _) = decode_metadata(wildcard, false, [ipv6_info(ip, 7)]).unwrap();
            assert_eq!(
                local,
                SocketAddr::V6(SocketAddrV6::new(ip.parse().unwrap(), 9000, 0, 0))
            );
        }
    }

    #[test]
    fn mapped_source_canonicalization_rejects_ambiguous_or_mismatched_endpoints() {
        let bound = "[::]:9000".parse().unwrap();
        let mapped = "[::ffff:127.0.0.1]:9001".parse().unwrap();
        assert_eq!(
            canonical_source(bound, mapped, true).unwrap(),
            "127.0.0.1:9001".parse().unwrap()
        );
        let scoped = SocketAddr::V6(SocketAddrV6::new(
            "::ffff:127.0.0.1".parse().unwrap(),
            9001,
            0,
            7,
        ));
        let flow = SocketAddr::V6(SocketAddrV6::new(
            "::ffff:127.0.0.1".parse().unwrap(),
            9001,
            1,
            0,
        ));
        for (bound, source, dual_stack) in [
            (bound, mapped, false),
            (bound, scoped, true),
            (bound, flow, true),
            (bound, "127.0.0.1:9001".parse().unwrap(), true),
            ("0.0.0.0:9000".parse().unwrap(), mapped, false),
            ("[::1]:9000".parse().unwrap(), mapped, true),
            ("[::%7]:9000".parse().unwrap(), mapped, true),
            (
                "[::ffff:127.0.0.1]:9000".parse().unwrap(),
                "[::1]:9001".parse().unwrap(),
                true,
            ),
        ] {
            assert_eq!(
                canonical_source(bound, source, dual_stack)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn mapped_metadata_requires_agreeing_wire_family_destination_and_interface() {
        let bound = "[::]:9000".parse().unwrap();
        let expected = "127.0.0.2:9000".parse().unwrap();
        for messages in [
            vec![ipv6_info("::ffff:127.0.0.2", 7)],
            vec![ipv4_info("127.0.0.2", 7)],
            vec![ipv6_info("::ffff:127.0.0.2", 7), ipv4_info("127.0.0.2", 7)],
            vec![ipv4_info("127.0.0.2", 7), ipv6_info("::ffff:127.0.0.2", 7)],
        ] {
            assert_eq!(
                decode_metadata(bound, true, messages).unwrap(),
                (expected, None)
            );
        }
        for bits in [0, 1, 2, 3, 0xba] {
            assert_eq!(
                decode_metadata(
                    bound,
                    true,
                    [
                        ipv6_info("::ffff:127.0.0.2", 7),
                        ipv4_info("127.0.0.2", 7),
                        ControlMessageOwned::Ipv4Tos(bits),
                    ]
                )
                .unwrap(),
                (expected, Some(Codepoint::from_ip_tos(bits)))
            );
        }
        for messages in [
            vec![],
            vec![ControlMessageOwned::Ipv4Tos(2)],
            vec![ipv6_info("::1", 7)],
            vec![ipv6_info("::ffff:0.0.0.0", 7)],
            vec![ipv6_info("::ffff:127.0.0.2", 0)],
            vec![ipv4_info("127.0.0.2", 0)],
            vec![ipv4_info("127.0.0.2", -1)],
            vec![ipv6_info("::ffff:127.0.0.2", 7), ipv4_info("127.0.0.1", 7)],
            vec![ipv6_info("::ffff:127.0.0.2", 7), ipv4_info("127.0.0.2", 8)],
            vec![ipv6_info("::ffff:127.0.0.2", 7), ipv6_info("::1", 7)],
            vec![
                ipv6_info("::ffff:127.0.0.2", 7),
                ControlMessageOwned::Ipv6TClass(2),
            ],
            vec![
                ipv6_info("::ffff:127.0.0.2", 7),
                ControlMessageOwned::Ipv4Tos(2),
                ControlMessageOwned::Ipv4Tos(3),
            ],
        ] {
            assert_eq!(
                decode_metadata(bound, true, messages).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
        let concrete = "[::ffff:127.0.0.2]:9000".parse().unwrap();
        assert_eq!(
            decode_metadata(concrete, true, []).unwrap(),
            (expected, None)
        );
        assert!(decode_metadata(concrete, true, [ipv4_info("127.0.0.1", 7)]).is_err());
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
                decode_metadata(bound, bound.is_ipv4(), messages)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
        assert_eq!(
            decode_metadata(
                v4,
                true,
                [ipv4_info("127.0.0.2", 1), ipv4_info("127.0.0.2", 1)]
            )
            .unwrap(),
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
    fn mapped_payload_and_ancillary_truncation_fail_closed() {
        for truncate_control in [false, true] {
            let sender = socket(false);
            let mut receiver = UdpMetadataSocket::new(UdpSocket::bind("[::]:0").unwrap()).unwrap();
            receiver
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            if truncate_control {
                receiver.control = Vec::new();
            }
            let destination =
                SocketAddr::from((Ipv4Addr::LOCALHOST, receiver.local_addr().unwrap().port()));
            sender
                .send_to(&[9; 32], destination, Codepoint::Ce)
                .unwrap();
            let mut bytes = [0; 64];
            let len = if truncate_control { 64 } else { 4 };
            assert_eq!(
                receiver.recv_from(&mut bytes[..len]).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
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
