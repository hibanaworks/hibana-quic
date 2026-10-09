//! Native message ABI only. Ancillary bytes are parsed with checked slices.
//! Linux UAPI and Darwin XNU bsd/sys/socket.h, netinet/in.h, netinet6/in6.h.
use std::{
    ffi::c_void,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket},
    os::fd::AsRawFd,
};
#[cfg(target_os = "linux")]
type ControlLength = usize;
#[cfg(target_os = "macos")]
type ControlLength = u32;
#[cfg(target_os = "linux")]
type IoCount = usize;
#[cfg(target_os = "macos")]
type IoCount = i32;
#[repr(C)]
struct IoVector {
    base: *mut c_void,
    len: usize,
}
#[repr(C)]
struct Header {
    name: *mut c_void,
    name_len: u32,
    iov: *mut IoVector,
    iov_len: IoCount,
    control: *mut c_void,
    control_len: ControlLength,
    flags: i32,
}
#[repr(C, align(8))]
struct Bytes<const N: usize>([u8; N]);
unsafe extern "C" {
    fn recvmsg(fd: i32, message: *mut Header, flags: i32) -> isize;
    fn sendmsg(fd: i32, message: *const Header, flags: i32) -> isize;
    fn getsockopt(fd: i32, level: i32, name: i32, value: *mut c_void, len: *mut u32) -> i32;
    fn setsockopt(fd: i32, level: i32, name: i32, value: *const c_void, len: u32) -> i32;
    #[cfg(test)]
    fn socket(family: i32, kind: i32, protocol: i32) -> i32;
    #[cfg(test)]
    fn bind(fd: i32, address: *const c_void, len: u32) -> i32;
}
#[cfg(target_os = "linux")]
mod abi {
    pub const AF6: u16 = 10;
    pub const PKT4: i32 = 8;
    pub const TOS: i32 = 1;
    pub const RECVTOS: i32 = 13;
    pub const ONLY6: i32 = 26;
    pub const RECVPKT6: i32 = 49;
    pub const PKT6: i32 = 50;
    pub const RECVCLASS: i32 = 66;
    pub const CLASS: i32 = 67;
    pub const TRUNC: i32 = 0x20 | 8;
    pub const ALIGN: usize = core::mem::size_of::<usize>();
}
#[cfg(target_os = "macos")]
mod abi {
    pub const AF6: u16 = 30;
    pub const PKT4: i32 = 26;
    pub const TOS: i32 = 3;
    pub const RECVTOS: i32 = 27;
    pub const ONLY6: i32 = 27;
    pub const RECVPKT6: i32 = 61;
    pub const PKT6: i32 = 46;
    pub const RECVCLASS: i32 = 35;
    pub const CLASS: i32 = 36;
    pub const TRUNC: i32 = 0x10 | 0x20;
    pub const ALIGN: usize = 4;
}
const HEADER: usize = core::mem::size_of::<ControlLength>() + 8;
const fn aligned(n: usize) -> usize {
    (n + abi::ALIGN - 1) & !(abi::ALIGN - 1)
}
pub(crate) const CONTROL_CAPACITY: usize =
    aligned(HEADER + 1) + aligned(HEADER + 4) + aligned(HEADER + 12) + aligned(HEADER + 20);
#[cfg(test)]
pub(crate) const SMALL_CONTROL_CAPACITY: usize = 2 * aligned(HEADER + 4);
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid native UDP message")
}
fn result(n: isize) -> io::Result<usize> {
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}
fn option(socket: &impl AsRawFd, level: i32, name: i32, value: i32) -> io::Result<()> {
    // SAFETY: borrowed descriptor, live initialized i32 and exact byte length.
    result(unsafe {
        setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            (&value as *const i32).cast(),
            4,
        )
    } as isize)
    .map(|_| ())
}
pub(crate) fn ipv6_only(socket: &impl AsRawFd) -> io::Result<bool> {
    let mut value = 0i32;
    let mut len = 4u32;
    // SAFETY: both outputs have the exact writable sizes specified by this ABI.
    result(unsafe {
        getsockopt(
            socket.as_raw_fd(),
            41,
            abi::ONLY6,
            (&mut value as *mut i32).cast(),
            &mut len,
        )
    } as isize)?;
    if len != 4 {
        return Err(invalid());
    }
    Ok(value != 0)
}
pub(crate) fn enable(socket: &impl AsRawFd, ipv4: bool, dual: bool) -> io::Result<()> {
    if ipv4 || dual {
        option(socket, 0, abi::RECVTOS, 1)?;
        option(socket, 0, abi::PKT4, 1)?;
    }
    if !ipv4 {
        option(socket, 41, abi::RECVCLASS, 1)?;
        option(socket, 41, abi::RECVPKT6, 1)?;
    }
    Ok(())
}
fn encode(address: SocketAddr) -> (Bytes<128>, u32) {
    let mut bytes = Bytes([0; 128]);
    let (family, len) = if address.is_ipv4() {
        (2u16, 16)
    } else {
        (abi::AF6, 28)
    };
    #[cfg(target_os = "linux")]
    bytes.0[..2].copy_from_slice(&family.to_ne_bytes());
    #[cfg(target_os = "macos")]
    {
        bytes.0[0] = len as u8;
        bytes.0[1] = family as u8;
    }
    bytes.0[2..4].copy_from_slice(&address.port().to_be_bytes());
    match address {
        SocketAddr::V4(a) => bytes.0[4..8].copy_from_slice(&a.ip().octets()),
        SocketAddr::V6(a) => {
            bytes.0[4..8].copy_from_slice(&a.flowinfo().to_be_bytes());
            bytes.0[8..24].copy_from_slice(&a.ip().octets());
            bytes.0[24..28].copy_from_slice(&a.scope_id().to_ne_bytes());
        }
    }
    (bytes, len)
}
fn decode(bytes: &[u8]) -> io::Result<SocketAddr> {
    if bytes.len() < 4 {
        return Err(invalid());
    }
    #[cfg(target_os = "linux")]
    let family = u16::from_ne_bytes(bytes[..2].try_into().map_err(|_| invalid())?);
    #[cfg(target_os = "macos")]
    let family = {
        if bytes[0] as usize != bytes.len() {
            return Err(invalid());
        }
        bytes[1] as u16
    };
    let port = u16::from_be_bytes(bytes[2..4].try_into().map_err(|_| invalid())?);
    match (family, bytes.len()) {
        (2, 16) => Ok(SocketAddr::from((
            Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[4..8]).map_err(|_| invalid())?),
            port,
        ))),
        (f, 28) if f == abi::AF6 => Ok(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).map_err(|_| invalid())?),
            port,
            u32::from_be_bytes(bytes[4..8].try_into().map_err(|_| invalid())?),
            u32::from_ne_bytes(bytes[24..28].try_into().map_err(|_| invalid())?),
        ))),
        _ => Err(invalid()),
    }
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct InAddr {
    pub s_addr: u32,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct In6Addr {
    pub s6_addr: [u8; 16],
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Info4 {
    pub ipi_ifindex: i32,
    pub ipi_addr: InAddr,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Info6 {
    pub ipi6_addr: In6Addr,
    pub ipi6_ifindex: u32,
}
#[derive(Clone, Copy, Debug)]
pub(crate) enum Metadata {
    Ipv4PacketInfo(Info4),
    Ipv6PacketInfo(Info6),
    Ipv4Tos(u8),
    Ipv6TClass(i32),
}
pub(crate) struct Received {
    pub bytes: usize,
    pub address: SocketAddr,
    pub metadata: [Option<Metadata>; 8],
}
fn u32_at(bytes: &[u8], at: usize) -> io::Result<u32> {
    Ok(u32::from_ne_bytes(
        bytes
            .get(at..at + 4)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?,
    ))
}
fn parse(bytes: &[u8]) -> io::Result<[Option<Metadata>; 8]> {
    let mut out = [None; 8];
    let mut count = 0;
    let mut at = 0;
    while at < bytes.len() {
        let rest = &bytes[at..];
        if rest.len() < HEADER {
            return Err(invalid());
        }
        let len = ControlLength::from_ne_bytes(
            rest[..core::mem::size_of::<ControlLength>()]
                .try_into()
                .map_err(|_| invalid())?,
        ) as usize;
        if len < HEADER || len > rest.len() {
            return Err(invalid());
        }
        let level = u32_at(rest, HEADER - 8)? as i32;
        let kind = u32_at(rest, HEADER - 4)? as i32;
        let payload = &rest[HEADER..len];
        let value = match (level, kind) {
            (0, k) if k == abi::PKT4 => {
                if payload.len() != 12 {
                    return Err(invalid());
                }
                Some(Metadata::Ipv4PacketInfo(Info4 {
                    ipi_ifindex: u32_at(payload, 0)? as i32,
                    ipi_addr: InAddr {
                        s_addr: u32_at(payload, 8)?,
                    },
                }))
            }
            (41, k) if k == abi::PKT6 => {
                if payload.len() != 20 {
                    return Err(invalid());
                }
                Some(Metadata::Ipv6PacketInfo(Info6 {
                    ipi6_addr: In6Addr {
                        s6_addr: payload[..16].try_into().map_err(|_| invalid())?,
                    },
                    ipi6_ifindex: u32_at(payload, 16)?,
                }))
            }
            (0, k) if k == abi::TOS => {
                if payload.len() != 1 {
                    return Err(invalid());
                }
                Some(Metadata::Ipv4Tos(payload[0]))
            }
            (41, k) if k == abi::CLASS => {
                if payload.len() != 4 {
                    return Err(invalid());
                }
                Some(Metadata::Ipv6TClass(u32_at(payload, 0)? as i32))
            }
            _ => None,
        };
        if let Some(value) = value {
            *out.get_mut(count).ok_or_else(invalid)? = Some(value);
            count += 1;
        }
        let next = aligned(len);
        if next >= rest.len() {
            break;
        }
        at += next;
    }
    Ok(out)
}
pub(crate) fn receive(
    socket: &UdpSocket,
    bytes: &mut [u8],
    capacity: usize,
) -> io::Result<Received> {
    let mut address = Bytes([0u8; 128]);
    let mut control = Bytes([0u8; 512]);
    if capacity > control.0.len() {
        return Err(invalid());
    }
    let mut iov = IoVector {
        base: bytes.as_mut_ptr().cast(),
        len: bytes.len(),
    };
    let mut header = Header {
        name: address.0.as_mut_ptr().cast(),
        name_len: 128,
        iov: &mut iov,
        iov_len: 1,
        control: control.0.as_mut_ptr().cast(),
        control_len: capacity as ControlLength,
        flags: 0,
    };
    // SAFETY: ABI layout is repr(C); all referenced buffers are live, unique,
    // initialized and bounded by the supplied capacities for this synchronous call.
    let len = result(unsafe { recvmsg(socket.as_raw_fd(), &mut header, 0) })?;
    #[cfg(target_os = "linux")]
    let control_len = header.control_len;
    #[cfg(target_os = "macos")]
    let control_len = header.control_len as usize;
    if header.flags & abi::TRUNC != 0
        || len > bytes.len()
        || header.name_len > 128
        || control_len > capacity
    {
        return Err(invalid());
    }
    Ok(Received {
        bytes: len,
        address: decode(&address.0[..header.name_len as usize])?,
        metadata: parse(&control.0[..control_len])?,
    })
}
fn append(
    control: &mut [u8],
    at: &mut usize,
    level: i32,
    kind: i32,
    payload: &[u8],
) -> io::Result<()> {
    let len = HEADER + payload.len();
    let space = aligned(len);
    let end = at.checked_add(space).ok_or_else(invalid)?;
    let target = control.get_mut(*at..end).ok_or_else(invalid)?;
    target.fill(0);
    target[..core::mem::size_of::<ControlLength>()]
        .copy_from_slice(&(len as ControlLength).to_ne_bytes());
    target[HEADER - 8..HEADER - 4].copy_from_slice(&level.to_ne_bytes());
    target[HEADER - 4..HEADER].copy_from_slice(&kind.to_ne_bytes());
    target[HEADER..len].copy_from_slice(payload);
    *at = end;
    Ok(())
}
pub(crate) fn send(
    socket: &UdpSocket,
    bytes: &[u8],
    destination: SocketAddr,
    source: Option<SocketAddr>,
    ipv4: bool,
    ecn: u8,
) -> io::Result<usize> {
    let (mut address, address_len) = encode(destination);
    let mut control = Bytes([0u8; 128]);
    let mut used = 0;
    if let Some(source) = source {
        match source {
            SocketAddr::V4(a) => {
                let mut info = [0u8; 12];
                info[4..8].copy_from_slice(&a.ip().octets());
                append(&mut control.0, &mut used, 0, abi::PKT4, &info)?;
            }
            SocketAddr::V6(a) => {
                let mut info = [0u8; 20];
                info[..16].copy_from_slice(&a.ip().octets());
                info[16..].copy_from_slice(&a.scope_id().to_ne_bytes());
                append(&mut control.0, &mut used, 41, abi::PKT6, &info)?;
            }
        }
    }
    if ipv4 {
        #[cfg(target_os = "linux")]
        append(&mut control.0, &mut used, 0, abi::TOS, &[ecn])?;
        #[cfg(target_os = "macos")]
        append(
            &mut control.0,
            &mut used,
            0,
            abi::TOS,
            &i32::from(ecn).to_ne_bytes(),
        )?;
    } else {
        append(
            &mut control.0,
            &mut used,
            41,
            abi::CLASS,
            &i32::from(ecn).to_ne_bytes(),
        )?;
    }
    let mut iov = IoVector {
        base: bytes.as_ptr().cast_mut().cast(),
        len: bytes.len(),
    };
    let header = Header {
        name: address.0.as_mut_ptr().cast(),
        name_len: address_len,
        iov: &mut iov,
        iov_len: 1,
        control: control.0.as_mut_ptr().cast(),
        control_len: used as ControlLength,
        flags: 0,
    };
    // SAFETY: sendmsg only reads all buffers and the single iovec for this call;
    // pointers are live for the complete call and lengths bound their allocations.
    result(unsafe { sendmsg(socket.as_raw_fd(), &header, 0) })
}
#[cfg(test)]
pub(crate) fn bind_v6_only() -> io::Result<UdpSocket> {
    use std::os::fd::{FromRawFd, OwnedFd};
    // SAFETY: socket has no pointer parameters; a nonnegative result is a new fd.
    let fd = result(unsafe { socket(abi::AF6 as i32, 2, 0) } as isize)? as i32;
    // SAFETY: this fresh descriptor has exactly one Rust owner.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    option(&fd, 41, abi::ONLY6, 1)?;
    let (address, len) = encode("[::]:0".parse().map_err(|_| invalid())?);
    // SAFETY: encoded sockaddr remains live and its initialized length is exact.
    result(unsafe { bind(fd.as_raw_fd(), address.0.as_ptr().cast(), len) } as isize)?;
    Ok(UdpSocket::from(fd))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn live_native_ipv4_and_ipv6_metadata() {
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let receiver = UdpSocket::bind(bind).unwrap();
            let sender = UdpSocket::bind(bind).unwrap();
            receiver
                .set_read_timeout(Some(std::time::Duration::from_secs(1)))
                .unwrap();
            let destination = receiver.local_addr().unwrap();
            enable(&receiver, destination.is_ipv4(), false).unwrap();
            for ecn in 0..4 {
                assert_eq!(
                    send(
                        &sender,
                        b"hello",
                        destination,
                        Some(sender.local_addr().unwrap()),
                        destination.is_ipv4(),
                        ecn
                    )
                    .unwrap(),
                    5
                );
                let mut bytes = [0; 16];
                let packet = receive(&receiver, &mut bytes, CONTROL_CAPACITY).unwrap();
                assert_eq!(&bytes[..packet.bytes], b"hello");
                assert_eq!(packet.address, sender.local_addr().unwrap());
                assert!(packet.metadata.into_iter().flatten().any(|m| match m {
                    Metadata::Ipv4Tos(tos) => tos & 3 == ecn,
                    Metadata::Ipv6TClass(class) => class & 3 == i32::from(ecn),
                    _ => false,
                }));
            }
        }
    }
    #[test]
    fn message_layout_matches_native_64_bit_abi() {
        if core::mem::size_of::<usize>() == 8 {
            #[cfg(target_os = "linux")]
            assert_eq!(core::mem::size_of::<Header>(), 56);
            #[cfg(target_os = "macos")]
            assert_eq!(core::mem::size_of::<Header>(), 48);
        }
        assert_eq!(core::mem::offset_of!(Header, iov), 16);
        assert_eq!(
            core::mem::size_of::<IoVector>(),
            2 * core::mem::size_of::<usize>()
        );
    }
    #[test]
    fn sockaddr_round_trip_and_rejection() {
        for text in ["127.0.0.1:443", "[::1]:443", "[fe80::1%3]:65535"] {
            let address = text.parse().unwrap();
            let (bytes, len) = encode(address);
            assert_eq!(decode(&bytes.0[..len as usize]).unwrap(), address);
            assert!(decode(&bytes.0[..len as usize - 1]).is_err());
        }
        assert!(decode(&[]).is_err());
        assert!(decode(&[0; 16]).is_err());
    }
    #[test]
    fn ancillary_lengths_are_checked_before_payload_access() {
        let mut bytes = [0; 64];
        let mut used = 0;
        append(&mut bytes, &mut used, 0, abi::TOS, &[2]).unwrap();
        let metadata = parse(&bytes[..used]).unwrap();
        assert!(matches!(metadata[0], Some(Metadata::Ipv4Tos(2))));
        for n in 1..HEADER + 1 {
            assert!(parse(&bytes[..n]).is_err());
        }
        let mut short = bytes;
        short[..core::mem::size_of::<ControlLength>()]
            .copy_from_slice(&((HEADER - 1) as ControlLength).to_ne_bytes());
        assert!(parse(&short[..used]).is_err());
        let mut long = bytes;
        long[..core::mem::size_of::<ControlLength>()]
            .copy_from_slice(&(65 as ControlLength).to_ne_bytes());
        assert!(parse(&long[..used]).is_err());
        let mut wrong = [0; 64];
        let mut n = 0;
        append(&mut wrong, &mut n, 0, abi::PKT4, &[0; 11]).unwrap();
        assert!(parse(&wrong[..n]).is_err());
    }
    #[test]
    fn unknown_ancillary_is_skipped_and_known_capacity_is_bounded() {
        let mut bytes = [0; 512];
        let mut used = 0;
        append(&mut bytes, &mut used, 255, 255, &[7; 9]).unwrap();
        assert!(parse(&bytes[..used]).unwrap().iter().all(Option::is_none));
        for _ in 0..8 {
            append(&mut bytes, &mut used, 0, abi::TOS, &[0]).unwrap();
        }
        assert!(parse(&bytes[..used]).is_ok());
        append(&mut bytes, &mut used, 0, abi::TOS, &[0]).unwrap();
        assert!(parse(&bytes[..used]).is_err());
        assert!(append(&mut [0; 4], &mut 0, 0, abi::TOS, &[0]).is_err());
    }
}
