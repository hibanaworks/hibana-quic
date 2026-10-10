//! Allocation-free native wake ownership. Storage is supplied for the program
//! lifetime because arbitrary cloned Wakers may outlive the reactor itself.
use crate::unix::{AsRawFd, UnixStream, error as io};
use core::{
    cell::UnsafeCell,
    mem::MaybeUninit,
    sync::atomic::{AtomicI32, AtomicUsize, Ordering},
    task::{RawWaker, RawWakerVTable, Waker},
};
const EXCLUSIVE: usize = usize::MAX;
/// One reusable native wake source. The last outstanding Waker closes its writer.
/// Reuse is rejected while any previous reactor or Waker still owns the source.
/// No descriptor number can be observed through a stale, recycled wake handle.
pub struct WakeStorage {
    owners: AtomicUsize,
    writer: UnsafeCell<MaybeUninit<UnixStream>>,
    error: AtomicI32,
}
// SAFETY: initialization/destruction requires EXCLUSIVE ownership. Every other
// writer access holds a counted owner; concurrent accesses only borrow UnixStream.
unsafe impl Sync for WakeStorage {}
impl Default for WakeStorage {
    fn default() -> Self {
        Self::new()
    }
}
impl WakeStorage {
    pub const fn new() -> Self {
        Self {
            owners: AtomicUsize::new(0),
            writer: UnsafeCell::new(MaybeUninit::uninit()),
            error: AtomicI32::new(0),
        }
    }
    fn acquire(&'static self, writer: UnixStream) -> io::Result<()> {
        self.owners
            .compare_exchange(0, EXCLUSIVE, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
        // SAFETY: exclusive claim proves no initialized writer or outstanding handle.
        unsafe {
            (*self.writer.get()).write(writer);
        }
        self.error.store(0, Ordering::Relaxed);
        self.owners.store(1, Ordering::Release);
        Ok(())
    }
    fn retain(&self) {
        loop {
            let n = self.owners.load(Ordering::Relaxed);
            assert!(
                n > 0 && n < EXCLUSIVE - 1,
                "native wake reference count exhausted"
            );
            if self
                .owners
                .compare_exchange_weak(n, n + 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return;
            }
        }
    }
    fn release(&self) {
        loop {
            let n = self.owners.load(Ordering::Acquire);
            assert!(n > 0 && n < EXCLUSIVE);
            let next = if n == 1 { EXCLUSIVE } else { n - 1 };
            if self
                .owners
                .compare_exchange_weak(n, next, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }
            if n == 1 {
                // SAFETY: the last owner excludes every reader and claim until 0.
                unsafe {
                    (*self.writer.get()).assume_init_drop();
                }
                self.owners.store(0, Ordering::Release);
            }
            return;
        }
    }
    fn notify(&self) {
        // SAFETY: only counted Signal/Waker owners call this method. The writer
        // remains initialized until that owner releases after this call returns.
        let writer = unsafe { (*self.writer.get()).assume_init_ref() };
        loop {
            match writer.write(&[1]) {
                Ok(_) => return,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    self.error
                        .store(e.raw_os_error().unwrap_or(5), Ordering::Release);
                    return;
                }
            }
        }
    }
}
unsafe fn clone(data: *const ()) -> RawWaker {
    // SAFETY: every raw handle was made from this static storage with one owner.
    let storage = unsafe { &*data.cast::<WakeStorage>() };
    storage.retain();
    RawWaker::new(data, &VTABLE)
}
unsafe fn wake(data: *const ()) {
    // SAFETY: wake consumes exactly this handle's counted owner.
    let storage = unsafe { &*data.cast::<WakeStorage>() };
    storage.notify();
    storage.release();
}
unsafe fn wake_by_ref(data: *const ()) {
    // SAFETY: borrowed invocation retains the raw handle's owner throughout.
    unsafe { &*data.cast::<WakeStorage>() }.notify();
}
unsafe fn drop_waker(data: *const ()) {
    // SAFETY: dropping consumes exactly this raw handle's counted owner.
    unsafe { &*data.cast::<WakeStorage>() }.release();
}
static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop_waker);
pub(crate) struct Signal {
    storage: &'static WakeStorage,
    reader: UnixStream,
}
impl Signal {
    pub(crate) fn new(storage: &'static WakeStorage) -> io::Result<Self> {
        let (reader, writer) = UnixStream::pair()?;
        reader.set_nonblocking(true)?;
        writer.set_nonblocking(true)?;
        storage.acquire(writer)?;
        Ok(Self { storage, reader })
    }
    pub(crate) fn waker(&self) -> Waker {
        self.storage.retain();
        // SAFETY: the pointer is static, Send+Sync, with one counted owner.
        unsafe {
            Waker::from_raw(RawWaker::new(
                (self.storage as *const WakeStorage).cast(),
                &VTABLE,
            ))
        }
    }
    pub(crate) fn descriptor(&self) -> i32 {
        self.reader.as_raw_fd()
    }
    pub(crate) fn drain(&self) -> io::Result<()> {
        let error = self.storage.error.swap(0, Ordering::AcqRel);
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error));
        }
        match self.reader.read(&mut [0; 256]) {
            Ok(0) => Err(io::ErrorKind::BrokenPipe.into()),
            Ok(_) => Ok(()),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}
impl Drop for Signal {
    fn drop(&mut self) {
        self.storage.release();
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clones_outlive_reader_and_block_reuse_until_last_drop() {
        static STORAGE: WakeStorage = WakeStorage::new();
        let signal = Signal::new(&STORAGE).unwrap();
        let wake = signal.waker();
        let clone = wake.clone();
        drop(signal);
        wake.wake_by_ref(); // Closed peer is safe and cannot target another fd.
        assert!(Signal::new(&STORAGE).is_err());
        drop(wake);
        assert!(Signal::new(&STORAGE).is_err());
        drop(clone);
        let next = Signal::new(&STORAGE).unwrap();
        next.waker().wake();
        next.drain().unwrap();
    }
    #[test]
    #[allow(clippy::waker_clone_wake)] // Exercise consuming clone ownership, not only wake_by_ref.
    fn concurrent_clones_release_once_and_wake_native_reader() {
        static STORAGE: WakeStorage = WakeStorage::new();
        let signal = Signal::new(&STORAGE).unwrap();
        let wake = signal.waker();
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let wake = wake.clone();
                scope.spawn(move || {
                    for _ in 0..1000 {
                        wake.clone().wake();
                    }
                });
            }
        });
        signal.drain().unwrap();
        drop(wake);
        drop(signal);
        drop(Signal::new(&STORAGE).unwrap());
    }
}
