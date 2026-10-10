//! Small native Linux/macOS boundary. No external package or protocol progress.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("The native ABI implementation currently supports x86_64 and aarch64.");
use crate::unix::error as io;
pub(crate) mod os;
pub(crate) mod wake;
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

#[cfg(target_os = "macos")]
pub(crate) fn entropy(destination: &mut [u8]) -> io::Result<()> {
    unsafe extern "C" {
        fn getentropy(buffer: *mut core::ffi::c_void, length: usize) -> i32;
    }
    // Darwin accepts at most 256 bytes per call. No fallback source is used.
    // https://github.com/apple-oss-distributions/xnu/blob/main/bsd/man/man2/getentropy.2
    for bytes in destination.chunks_mut(256) {
        // SAFETY: the unique initialized slice stays valid for the entire syscall;
        // the kernel writes at most the supplied slice length and retains no pointer.
        if unsafe { getentropy(bytes.as_mut_ptr().cast(), bytes.len()) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn entropy(mut destination: &mut [u8]) -> io::Result<()> {
    unsafe extern "C" {
        fn getrandom(bytes: *mut core::ffi::c_void, len: usize, flags: u32) -> isize;
    }
    while !destination.is_empty() {
        // SAFETY: the unique initialized slice remains valid for its length. Flags zero waits for initialized kernel entropy.
        let n = unsafe { getrandom(destination.as_mut_ptr().cast(), destination.len(), 0) };
        if n < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if n == 0 || n as usize > destination.len() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        destination = &mut destination[n as usize..];
    }
    Ok(())
}
