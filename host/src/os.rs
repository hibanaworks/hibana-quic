//! Small native Linux/macOS boundary. No external package or protocol progress.
use std::io;
#[cfg(target_os = "linux")]
type Count = usize;
#[cfg(target_os = "macos")]
type Count = u32;
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct PollFd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}
impl PollFd {
    pub const EMPTY: Self = Self {
        fd: -1,
        events: 0,
        revents: 0,
    };
}
pub(crate) const READ: i16 = 1;
pub(crate) const WRITE: i16 = 4;
pub(crate) const TERMINAL: i16 = 8 | 16 | 32;
#[repr(C)]
pub(crate) struct PollBatch<const N: usize> {
    pub wake: PollFd,
    pub sockets: [PollFd; N],
}
unsafe extern "C" {
    fn poll(fds: *mut PollFd, count: Count, timeout: i32) -> i32;
}
pub(crate) fn wait<const N: usize>(batch: &mut PollBatch<N>, timeout: i32) -> io::Result<usize> {
    let count = N
        .checked_add(1)
        .and_then(|n| Count::try_from(n).ok())
        .ok_or(io::ErrorKind::InvalidInput)?;
    // SAFETY: repr(C) places the same-alignment PollFd followed immediately by
    // its array. The complete unique struct borrow spans (N+1) initialized
    // entries. poll reads fd/events and writes i16 revents only during this call.
    // Derive the pointer from the whole allocation, not a restricted field.
    let result = unsafe { poll((batch as *mut PollBatch<N>).cast(), count, timeout) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}

pub(crate) mod udp;
