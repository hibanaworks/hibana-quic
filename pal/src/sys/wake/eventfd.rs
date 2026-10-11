//! Linux kernel wake counter, with one owned descriptor for each side.
use crate::unix::{AsRawFd, OwnedFd, error as io};
use core::ffi::c_void;

const NONBLOCK: i32 = 0o4000;
const CLOEXEC: i32 = 0o2000000;
const DUPFD_CLOEXEC: i32 = 1030;

unsafe extern "C" {
    fn eventfd(initial: u32, flags: i32) -> i32;
    fn fcntl(fd: i32, command: i32, ...) -> i32;
    fn read(fd: i32, bytes: *mut c_void, len: usize) -> isize;
    fn write(fd: i32, bytes: *const c_void, len: usize) -> isize;
}

pub(super) struct EventFd(OwnedFd);
impl AsRawFd for EventFd {
    fn as_raw_fd(&self) -> i32 {
        self.0.as_raw_fd()
    }
}
impl EventFd {
    pub(super) fn pair() -> io::Result<(Self, Self)> {
        // SAFETY: eventfd takes only integer arguments and returns a new owned
        // descriptor. Both required flags are installed atomically at creation.
        let descriptor = unsafe { eventfd(0, NONBLOCK | CLOEXEC) };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the successful call created this uniquely owned descriptor.
        let reader = Self(unsafe { OwnedFd::from_raw_fd(descriptor) });
        // SAFETY: reader owns a live descriptor; F_DUPFD_CLOEXEC takes an int
        // minimum descriptor and creates a separate owner of the same counter.
        let descriptor = unsafe { fcntl(reader.as_raw_fd(), DUPFD_CLOEXEC, 0) };
        if descriptor < 0 {
            // The local reader owner closes the original on this error path.
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fcntl created this new unique descriptor. Its open-file
        // description shares the counter and nonblocking status with reader.
        let writer = Self(unsafe { OwnedFd::from_raw_fd(descriptor) });
        Ok((reader, writer))
    }

    pub(super) fn notify(&self) -> io::Result<()> {
        self.write_counter(1)
    }

    fn write_counter(&self, value: u64) -> io::Result<()> {
        // SAFETY: eventfd consumes exactly one native-endian u64. The aligned
        // value remains live for the syscall, which retains no pointer.
        let result = unsafe {
            write(
                self.as_raw_fd(),
                (&value as *const u64).cast(),
                core::mem::size_of::<u64>(),
            )
        };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else if result as usize != core::mem::size_of::<u64>() {
            Err(io::ErrorKind::InvalidData.into())
        } else {
            Ok(())
        }
    }

    pub(super) fn drain(&self) -> io::Result<()> {
        self.read_counter().map(|_| ())
    }

    fn read_counter(&self) -> io::Result<u64> {
        let mut value = 0u64;
        // SAFETY: the unique initialized native-endian u64 is writable for its
        // full size. A non-semaphore eventfd read drains the entire counter.
        let result = unsafe {
            read(
                self.as_raw_fd(),
                (&mut value as *mut u64).cast(),
                core::mem::size_of::<u64>(),
            )
        };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else if result as usize != core::mem::size_of::<u64>() {
            Err(io::ErrorKind::InvalidData.into())
        } else {
            Ok(value)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accumulated_notifications_drain_once_and_next_wake_survives() {
        let (reader, writer) = EventFd::pair().unwrap();
        for _ in 0..1024 {
            writer.notify().unwrap();
        }
        assert_eq!(reader.read_counter().unwrap(), 1024);
        assert_eq!(
            reader.drain().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        writer.notify().unwrap();
        assert_eq!(reader.read_counter().unwrap(), 1);
        assert_eq!(
            reader.drain().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn saturation_stays_nonblocking_and_read_restores_capacity() {
        let (reader, writer) = EventFd::pair().unwrap();
        writer.write_counter(u64::MAX - 1).unwrap();
        assert_eq!(
            writer.notify().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(reader.read_counter().unwrap(), u64::MAX - 1);
        writer.notify().unwrap();
        assert_eq!(reader.read_counter().unwrap(), 1);
    }

    #[test]
    fn saturated_waker_is_already_ready_and_drain_preserves_next_wake() {
        use super::super::{Signal, WakeStorage};
        static STORAGE: WakeStorage = WakeStorage::new();
        let signal = Signal::new(&STORAGE).unwrap();
        let wake = signal.waker();
        // SAFETY: signal and wake each hold a counted owner for the entire
        // immutable writer borrow; neither is released before its last use.
        let writer = unsafe { (*STORAGE.writer.get()).assume_init_ref() };
        writer.write_counter(u64::MAX - 1).unwrap();
        wake.wake_by_ref(); // EAGAIN means the counter is already readable.
        signal.drain().unwrap();
        assert_eq!(
            writer.read_counter().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        signal.drain().unwrap(); // An empty counter must not block or fail.
        wake.wake_by_ref();
        assert_eq!(writer.read_counter().unwrap(), 1);
    }

    #[test]
    fn descriptors_are_cloexec_and_nonblocking() {
        let (reader, writer) = EventFd::pair().unwrap();
        assert_ne!(reader.as_raw_fd(), writer.as_raw_fd());
        for fd in [reader.as_raw_fd(), writer.as_raw_fd()] {
            // SAFETY: each owner is live; F_GETFD and F_GETFL take no third arg.
            let descriptor_flags = unsafe { fcntl(fd, 1) };
            let status_flags = unsafe { fcntl(fd, 3) };
            assert!(descriptor_flags >= 0 && status_flags >= 0);
            assert_eq!(descriptor_flags & 1, 1);
            assert_eq!(status_flags & NONBLOCK, NONBLOCK);
        }
    }

    #[test]
    fn duplicated_owner_keeps_counter_live_after_reader_drop() {
        let (reader, writer) = EventFd::pair().unwrap();
        assert_ne!(reader.as_raw_fd(), writer.as_raw_fd());
        drop(reader);
        writer.notify().unwrap();
        assert_eq!(writer.read_counter().unwrap(), 1);
    }
}
