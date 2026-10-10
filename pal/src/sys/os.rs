//! Owned native descriptors and monotonic time; no Rust std dependency.
use crate::unix::error::{self as io, Error, ErrorKind};
use core::{ffi::c_void, net::SocketAddr, time::Duration};
#[cfg(target_os = "linux")]
const CLOEXEC: i32 = 0o2000000;
#[cfg(target_os = "macos")]
const CLOEXEC: i32 = 0;
#[link(name = "c")]
unsafe extern "C" {
    fn close(fd: i32) -> i32;
    fn fcntl(fd: i32, command: i32, ...) -> i32;
    fn socket(domain: i32, kind: i32, protocol: i32) -> i32;
    fn socketpair(domain: i32, kind: i32, protocol: i32, pair: *mut i32) -> i32;
    fn bind(fd: i32, address: *const c_void, len: u32) -> i32;
    fn connect(fd: i32, address: *const c_void, len: u32) -> i32;
    fn getsockname(fd: i32, address: *mut c_void, len: *mut u32) -> i32;
    fn getpeername(fd: i32, address: *mut c_void, len: *mut u32) -> i32;
    fn setsockopt(fd: i32, level: i32, name: i32, value: *const c_void, len: u32) -> i32;
    fn read(fd: i32, bytes: *mut c_void, len: usize) -> isize;
    fn send(fd: i32, bytes: *const c_void, len: usize, flags: i32) -> isize;
    fn clock_gettime(clock: i32, value: *mut Timespec) -> i32;
    #[cfg(target_os = "linux")]
    fn __errno_location() -> *mut i32;
    #[cfg(target_os = "macos")]
    fn __error() -> *mut i32;
}
pub(crate) fn errno() -> i32 {
    // SAFETY: the C runtime supplies this thread's live errno slot.
    unsafe {
        #[cfg(target_os = "linux")]
        {
            *__errno_location()
        }
        #[cfg(target_os = "macos")]
        {
            *__error()
        }
    }
}
fn checked(result: i32) -> io::Result<i32> {
    if result < 0 {
        Err(Error::last_os_error())
    } else {
        Ok(result)
    }
}
pub trait AsRawFd {
    fn as_raw_fd(&self) -> i32;
}
#[derive(Debug)]
pub struct OwnedFd(i32);
impl OwnedFd {
    /// Adopt one uniquely owned live native descriptor.
    /// # Safety
    /// The descriptor must be valid and relinquished by every previous owner.
    pub unsafe fn from_raw_fd(fd: i32) -> Self {
        Self(fd)
    }
    pub fn into_raw_fd(self) -> i32 {
        let fd = self.0;
        core::mem::forget(self);
        fd
    }
    fn acquired(fd: i32) -> io::Result<Self> {
        let owner = Self(checked(fd)?);
        // SAFETY: owner holds the live descriptor; F_SETFD takes one integer.
        #[cfg(target_os = "macos")]
        checked(unsafe { fcntl(owner.0, 2, 1) })?;
        Ok(owner)
    }
    pub fn set_nonblocking(&self, value: bool) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        const NONBLOCK: i32 = 0o4000;
        #[cfg(target_os = "macos")]
        const NONBLOCK: i32 = 4;
        // SAFETY: both fcntl operations borrow the live descriptor and retain no memory.
        let flags = checked(unsafe { fcntl(self.0, 3) })?;
        checked(unsafe {
            fcntl(
                self.0,
                4,
                if value {
                    flags | NONBLOCK
                } else {
                    flags & !NONBLOCK
                },
            )
        })?;
        Ok(())
    }
}
impl AsRawFd for OwnedFd {
    fn as_raw_fd(&self) -> i32 {
        self.0
    }
}
impl Drop for OwnedFd {
    fn drop(&mut self) {
        // Never retry close: EINTR may already have retired the descriptor.
        // SAFETY: this unique owner retires its descriptor exactly once.
        unsafe {
            close(self.0);
        }
    }
}
#[derive(Debug)]
pub struct UdpSocket(OwnedFd);
impl From<OwnedFd> for UdpSocket {
    fn from(fd: OwnedFd) -> Self {
        Self(fd)
    }
}
impl AsRawFd for UdpSocket {
    fn as_raw_fd(&self) -> i32 {
        self.0.as_raw_fd()
    }
}
impl UdpSocket {
    /// Duplicate the native handle; the kernel socket is shared and each handle closes once.
    pub fn try_clone(&self) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        const DUP: i32 = 1030;
        #[cfg(target_os = "macos")]
        const DUP: i32 = 67;
        // SAFETY: F_DUPFD_CLOEXEC borrows a live descriptor and returns a fresh owned handle.
        let fd = checked(unsafe { fcntl(self.0.0, DUP, 0) })?;
        Ok(Self(OwnedFd(fd)))
    }

    /// Ask the OS for the local route to a peer, then bind an unconnected socket there.
    pub fn bind_for_peer(peer: SocketAddr) -> io::Result<Self> {
        let wildcard = if peer.is_ipv4() {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0u16; 8], 0))
        };
        let route = Self::bind(wildcard)?;
        route.connect(peer)?;
        let mut local = route.local_addr()?;
        local.set_port(0);
        drop(route);
        Self::bind(local)
    }

    pub fn bind(address: SocketAddr) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        const AF6: i32 = 10;
        #[cfg(target_os = "macos")]
        const AF6: i32 = 30;
        // SAFETY: socket takes integer arguments and returns a new owned descriptor.
        let fd = OwnedFd::acquired(unsafe {
            socket(if address.is_ipv4() { 2 } else { AF6 }, 2 | CLOEXEC, 0)
        })?;
        let (bytes, len) = super::udp::encode(address);
        // SAFETY: encoded address is initialized, aligned, and live for this call.
        checked(unsafe { bind(fd.0, bytes.0.as_ptr().cast(), len) })?;
        Ok(Self(fd))
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.address(false)
    }
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.address(true)
    }
    fn address(&self, peer: bool) -> io::Result<SocketAddr> {
        let mut bytes = super::udp::Bytes([0; 128]);
        let mut len = 128u32;
        // SAFETY: unique initialized storage and length cover the complete sockaddr result.
        checked(unsafe {
            if peer {
                getpeername(self.0.0, bytes.0.as_mut_ptr().cast(), &mut len)
            } else {
                getsockname(self.0.0, bytes.0.as_mut_ptr().cast(), &mut len)
            }
        })?;
        super::udp::decode(bytes.0.get(..len as usize).ok_or(ErrorKind::InvalidData)?)
    }
    pub fn connect(&self, address: SocketAddr) -> io::Result<()> {
        let (bytes, len) = super::udp::encode(address);
        // SAFETY: descriptor and encoded address remain live throughout the syscall.
        checked(unsafe { connect(self.0.0, bytes.0.as_ptr().cast(), len) })?;
        Ok(())
    }
    pub fn set_nonblocking(&self, value: bool) -> io::Result<()> {
        self.0.set_nonblocking(value)
    }
    pub fn set_read_timeout(&self, value: Option<Duration>) -> io::Result<()> {
        self.timeout(value, true)
    }
    pub fn set_write_timeout(&self, value: Option<Duration>) -> io::Result<()> {
        self.timeout(value, false)
    }
    fn timeout(&self, value: Option<Duration>, read: bool) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        type Micros = isize;
        #[cfg(target_os = "macos")]
        type Micros = i32;
        #[repr(C)]
        struct Timeval {
            seconds: isize,
            micros: Micros,
        }
        if value.is_some_and(|v| v.is_zero()) {
            return Err(ErrorKind::InvalidInput.into());
        }
        let duration = value.unwrap_or_default();
        let seconds = isize::try_from(duration.as_secs()).map_err(|_| ErrorKind::InvalidInput)?;
        let micros = duration.subsec_nanos().div_ceil(1000) as isize;
        let time = Timeval {
            seconds: seconds
                .checked_add(micros / 1_000_000)
                .ok_or(ErrorKind::InvalidInput)?,
            micros: (micros % 1_000_000) as Micros,
        };
        #[cfg(target_os = "linux")]
        let (level, name) = (1, if read { 20 } else { 21 });
        #[cfg(target_os = "macos")]
        let (level, name) = (0xffff, if read { 0x1006 } else { 0x1005 });
        // SAFETY: platform timeval uses time_t seconds and platform suseconds_t microseconds; storage lives through the call.
        checked(unsafe {
            setsockopt(
                self.0.0,
                level,
                name,
                (&time as *const Timeval).cast(),
                core::mem::size_of::<Timeval>() as u32,
            )
        })?;
        Ok(())
    }
}
pub struct UnixStream(OwnedFd);
impl AsRawFd for UnixStream {
    fn as_raw_fd(&self) -> i32 {
        self.0.0
    }
}
impl UnixStream {
    pub fn pair() -> io::Result<(Self, Self)> {
        let mut pair = [-1; 2];
        // SAFETY: socketpair initializes exactly two descriptors on success.
        checked(unsafe { socketpair(1, 1 | CLOEXEC, 0, pair.as_mut_ptr()) })?;
        // Take both owners before any fallible configuration so every error closes both.
        let a = Self(OwnedFd(pair[0]));
        let b = Self(OwnedFd(pair[1]));
        #[cfg(target_os = "macos")]
        for fd in [a.as_raw_fd(), b.as_raw_fd()] {
            // SAFETY: both descriptors are owned and live.
            checked(unsafe { fcntl(fd, 2, 1) })?;
        }
        Ok((a, b))
    }
    pub fn set_nonblocking(&self, value: bool) -> io::Result<()> {
        self.0.set_nonblocking(value)
    }
    pub fn read(&self, bytes: &mut [u8]) -> io::Result<usize> {
        // SAFETY: unique output slice is valid for its exact length; syscall retains no pointer.
        let n = unsafe { read(self.0.0, bytes.as_mut_ptr().cast(), bytes.len()) };
        if n < 0 {
            Err(Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
    pub fn write(&self, bytes: &[u8]) -> io::Result<usize> {
        // SAFETY: immutable input slice is valid for its exact length; syscall retains no pointer.
        #[cfg(target_os = "linux")]
        const NO_SIGNAL: i32 = 0x4000;
        #[cfg(target_os = "macos")]
        const NO_SIGNAL: i32 = 0x80000;
        let n = unsafe { send(self.0.0, bytes.as_ptr().cast(), bytes.len(), NO_SIGNAL) };
        if n < 0 {
            Err(Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
}
#[repr(C)]
struct Timespec {
    seconds: isize,
    nanos: isize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Instant(Duration);
impl Instant {
    pub fn now() -> Self {
        #[cfg(target_os = "linux")]
        const CLOCK: i32 = 1;
        #[cfg(target_os = "macos")]
        const CLOCK: i32 = 6;
        let mut time = Timespec {
            seconds: 0,
            nanos: 0,
        };
        // SAFETY: clock_gettime writes one native timespec into initialized owned storage.
        let result = unsafe { clock_gettime(CLOCK, &mut time) };
        assert!(
            result == 0 && time.seconds >= 0 && (0..1_000_000_000).contains(&time.nanos),
            "monotonic clock unavailable"
        );
        Self(Duration::new(time.seconds as u64, time.nanos as u32))
    }
    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        self.0.checked_add(duration).map(Self)
    }
    pub fn saturating_duration_since(self, earlier: Self) -> Duration {
        self.0.saturating_sub(earlier.0)
    }
    pub fn elapsed(self) -> Duration {
        Self::now().saturating_duration_since(self)
    }
}
impl core::ops::Add<Duration> for Instant {
    type Output = Self;
    fn add(self, rhs: Duration) -> Self {
        self.checked_add(rhs).expect("monotonic deadline overflow")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_handle_clone_has_independent_ownership_and_close_on_exec() {
        let socket = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let local = socket.local_addr().unwrap();
        let duplicate = socket.try_clone().unwrap();
        assert_ne!(socket.as_raw_fd(), duplicate.as_raw_fd());
        for fd in [socket.as_raw_fd(), duplicate.as_raw_fd()] {
            // SAFETY: F_GETFD reads flags of a borrowed live descriptor.
            assert_ne!(unsafe { fcntl(fd, 1) } & 1, 0);
        }
        drop(socket);
        assert_eq!(duplicate.local_addr().unwrap(), local);
    }
    #[test]
    fn route_selection_returns_an_unconnected_bound_socket() {
        let peer = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let local = UdpSocket::bind_for_peer(peer.local_addr().unwrap()).unwrap();
        assert!(!local.local_addr().unwrap().ip().is_unspecified());
        assert_ne!(local.local_addr().unwrap().port(), 0);
        assert_eq!(
            local.peer_addr().unwrap_err().kind(),
            ErrorKind::NotConnected
        );
    }
    #[test]
    fn dropped_wake_reader_reports_broken_pipe() {
        let (reader, writer) = UnixStream::pair().unwrap();
        drop(reader);
        assert_eq!(
            writer.write(b"x").unwrap_err().kind(),
            ErrorKind::BrokenPipe
        );
    }
    #[test]
    fn monotonic_clock_never_moves_backwards() {
        let first = Instant::now();
        assert!(Instant::now() >= first);
        assert_eq!(first.saturating_duration_since(first), Duration::ZERO);
    }
}
