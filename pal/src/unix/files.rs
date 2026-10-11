//! Owned positional files and descriptor-relative operations.
//! The `_at` operations are confined to one child name; `File` opens a caller path.
use crate::unix::{AsRawFd, OwnedFd, error as io};
use core::ffi::c_char;
#[cfg(target_os = "linux")]
mod abi {
    pub type Mode = u32;
    pub const DIRECTORY: i32 = 0o200000;
    pub const NOFOLLOW: i32 = 0o400000;
    pub const NONBLOCK: i32 = 0o4000;
    pub const CLOEXEC: i32 = 0o2000000;
    pub const CREATE: i32 = 0o100 | 0o200;
    pub const NOFOLLOW_AT: i32 = 0x100;
}
#[cfg(target_os = "macos")]
mod abi {
    pub type Mode = u16;
    pub const DIRECTORY: i32 = 0x00100000;
    pub const NOFOLLOW: i32 = 0x100;
    pub const NONBLOCK: i32 = 4;
    pub const CLOEXEC: i32 = 0x01000000;
    pub const CREATE: i32 = 0x200 | 0x800;
    pub const NOFOLLOW_AT: i32 = 0x20;
}
pub const DIRECTORY_FLAGS: i32 = abi::DIRECTORY | abi::NOFOLLOW | abi::CLOEXEC;
unsafe extern "C" {
    fn openat(parent: i32, name: *const c_char, flags: i32, ...) -> i32;
    fn mkdirat(parent: i32, name: *const c_char, mode: abi::Mode) -> i32;
    fn faccessat(parent: i32, name: *const c_char, mode: i32, flags: i32) -> i32;
    fn linkat(
        parent: i32,
        source: *const c_char,
        target_parent: i32,
        target: *const c_char,
        flags: i32,
    ) -> i32;
    fn unlinkat(parent: i32, name: *const c_char, flags: i32) -> i32;
}
fn child(name: &str) -> io::Result<[c_char; 256]> {
    if name.is_empty()
        || matches!(name, "." | "..")
        || name.contains(['/', '\\', '\0'])
        || name.len() > 255
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut bytes = [0; 256];
    for (target, source) in bytes.iter_mut().zip(name.bytes()) {
        *target = source as c_char;
    }
    Ok(bytes)
}
fn checked(value: i32) -> io::Result<()> {
    if value == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
fn open(parent: &impl AsRawFd, name: &str, flags: i32) -> io::Result<OwnedFd> {
    let name = child(name)?;
    // SAFETY: parent is borrowed and live; name is terminated and valid throughout
    // the call. Variadic mode is promoted to unsigned int on both supported ABIs.
    // Match std file creation: the process umask restricts the requested mode.
    let fd = unsafe {
        openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | abi::NOFOLLOW | abi::CLOEXEC,
            0o666u32,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful openat returned a new uniquely owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
pub fn directory_at(parent: &impl AsRawFd, name: &str) -> io::Result<OwnedFd> {
    open(parent, name, abi::DIRECTORY)
}
pub fn read_at(parent: &impl AsRawFd, name: &str) -> io::Result<OwnedFd> {
    open(parent, name, abi::NONBLOCK)
}
pub fn create_at(parent: &impl AsRawFd, name: &str) -> io::Result<OwnedFd> {
    open(parent, name, 2 | abi::CREATE)
}
pub fn mkdir_at(parent: &impl AsRawFd, name: &str) -> io::Result<()> {
    let name = child(name)?;
    // SAFETY: the descriptor and terminated name remain live; no pointer is retained.
    checked(unsafe { mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o777) })
}
pub fn exists_at(parent: &impl AsRawFd, name: &str) -> io::Result<bool> {
    let name = child(name)?;
    // SAFETY: valid descriptor and terminated name; no output pointers.
    let result = unsafe { faccessat(parent.as_raw_fd(), name.as_ptr(), 0, abi::NOFOLLOW_AT) };
    if result == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound {
        Ok(false)
    } else {
        Err(error)
    }
}
pub fn link_at(parent: &impl AsRawFd, source: &str, target: &str) -> io::Result<()> {
    let source = child(source)?;
    let target = child(target)?;
    // SAFETY: all descriptors and terminated strings remain live for the call.
    // With flags zero linkat never overwrites an existing destination.
    checked(unsafe {
        linkat(
            parent.as_raw_fd(),
            source.as_ptr(),
            parent.as_raw_fd(),
            target.as_ptr(),
            0,
        )
    })
}
pub fn remove_at(parent: &impl AsRawFd, name: &str) -> io::Result<()> {
    let name = child(name)?;
    // SAFETY: valid descriptor and terminated name; flags zero removes only a file link.
    checked(unsafe { unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) })
}

/// An owned positional file. No sequential cursor is exposed.
///
/// All data access uses `pread`/`pwrite`. The private descriptor's offset may
/// change when querying its length; it is never used to address data. Opening
/// through this type keeps that offset independent from other file handles.
/// Concurrent truncation or overlapping writes retain ordinary OS file semantics;
/// callers coordinate those operations when they need a consistent snapshot.
pub struct File(OwnedFd);

// The supported native architectures use a signed 64-bit off_t, including x32.
type Offset = i64;

unsafe extern "C" {
    #[link_name = "open"]
    fn open_path(path: *const c_char, flags: i32, ...) -> i32;
    fn pread(fd: i32, bytes: *mut core::ffi::c_void, len: usize, offset: Offset) -> isize;
    fn pwrite(fd: i32, bytes: *const core::ffi::c_void, len: usize, offset: Offset) -> isize;
    fn lseek(fd: i32, offset: Offset, origin: i32) -> Offset;
    fn ftruncate(fd: i32, length: Offset) -> i32;
}
impl File {
    /// Open an existing file for positional reads. Does not follow a final symlink.
    pub fn open(path: &str) -> io::Result<Self> {
        Self::open_with(path, 0)
    }
    /// Exclusively create a read/write file; never overwrite an existing path.
    pub fn create_new(path: &str) -> io::Result<Self> {
        Self::open_with(path, 2 | abi::CREATE)
    }
    fn open_with(path: &str, flags: i32) -> io::Result<Self> {
        if path.is_empty() || path.len() >= 4096 || path.as_bytes().contains(&0) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut name = [0 as c_char; 4096];
        for (to, from) in name.iter_mut().zip(path.bytes()) {
            *to = from as c_char;
        }
        // SAFETY: name is terminated and retained throughout open. Mode is a
        // promoted variadic integer; umask applies. No descriptor is shared.
        let fd = unsafe {
            open_path(
                name.as_ptr(),
                flags | abi::CLOEXEC | abi::NOFOLLOW | abi::NONBLOCK,
                0o666u32,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful open returned one new owned descriptor.
        Ok(Self(unsafe { OwnedFd::from_raw_fd(fd) }))
    }
    /// Observe the current extent, not a cached length.
    pub fn len(&self) -> io::Result<u64> {
        // SAFETY: the descriptor remains owned and live. Its private offset is
        // not used by positional reads/writes; no caller-visible cursor changes.
        let end = unsafe { lseek(self.0.as_raw_fd(), 0, 2) };
        if end < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(end as u64)
        }
    }
    pub fn is_empty(&self) -> io::Result<bool> {
        self.len().map(|n| n == 0)
    }
    pub fn read_exact_at(&self, mut bytes: &mut [u8], mut offset: u64) -> io::Result<()> {
        checked_extent(offset, bytes.len())?;
        while !bytes.is_empty() {
            let count = bytes.len().min(i32::MAX as usize);
            // SAFETY: bytes is a writable live slice and its length is bounded;
            // checked_extent establishes that every native offset fits.
            let n = unsafe {
                pread(
                    self.0.as_raw_fd(),
                    bytes.as_mut_ptr().cast(),
                    count,
                    offset as Offset,
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected end of file",
                ));
            }
            bytes = &mut bytes[n as usize..];
            offset += n as u64;
        }
        Ok(())
    }
    pub fn write_all_at(&self, mut bytes: &[u8], mut offset: u64) -> io::Result<()> {
        checked_extent(offset, bytes.len())?;
        while !bytes.is_empty() {
            let count = bytes.len().min(i32::MAX as usize);
            // SAFETY: bytes is readable for count bytes, the descriptor is live,
            // and checked_extent established representable native offsets.
            let n = unsafe {
                pwrite(
                    self.0.as_raw_fd(),
                    bytes.as_ptr().cast(),
                    count,
                    offset as Offset,
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            if n == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            bytes = &bytes[n as usize..];
            offset += n as u64;
        }
        Ok(())
    }
    pub fn set_len(&self, length: u64) -> io::Result<()> {
        let length =
            Offset::try_from(length).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        loop {
            // SAFETY: the descriptor remains live and length is nonnegative.
            if unsafe { ftruncate(self.0.as_raw_fd(), length) } == 0 {
                return Ok(());
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
    }
}
fn checked_extent(offset: u64, length: usize) -> io::Result<()> {
    if offset
        .checked_add(length as u64)
        .is_none_or(|end| end > Offset::MAX as u64)
    {
        Err(io::ErrorKind::InvalidInput.into())
    } else {
        Ok(())
    }
}
impl hibana_quic::io::RandomAccess for File {
    fn len(&self) -> Result<u64, hibana_quic::io::IoError> {
        self.len().map_err(|_| hibana_quic::io::IoError::Rejected)
    }
    fn read_exact_at(&self, bytes: &mut [u8], offset: u64) -> Result<(), hibana_quic::io::IoError> {
        self.read_exact_at(bytes, offset)
            .map_err(|_| hibana_quic::io::IoError::Rejected)
    }
    fn write_all_at(&self, bytes: &[u8], offset: u64) -> Result<(), hibana_quic::io::IoError> {
        self.write_all_at(bytes, offset)
            .map_err(|_| hibana_quic::io::IoError::Rejected)
    }
    fn set_len(&self, length: u64) -> Result<(), hibana_quic::io::IoError> {
        self.set_len(length)
            .map_err(|_| hibana_quic::io::IoError::Rejected)
    }
}

impl hibana_quic::io::RandomAccess for &File {
    fn len(&self) -> Result<u64, hibana_quic::io::IoError> {
        hibana_quic::io::RandomAccess::len(*self)
    }
    fn read_exact_at(&self, bytes: &mut [u8], offset: u64) -> Result<(), hibana_quic::io::IoError> {
        hibana_quic::io::RandomAccess::read_exact_at(*self, bytes, offset)
    }
    fn write_all_at(&self, bytes: &[u8], offset: u64) -> Result<(), hibana_quic::io::IoError> {
        hibana_quic::io::RandomAccess::write_all_at(*self, bytes, offset)
    }
    fn set_len(&self, length: u64) -> Result<(), hibana_quic::io::IoError> {
        hibana_quic::io::RandomAccess::set_len(*self, length)
    }
}

#[cfg(test)]
mod positional_tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    struct Path(std::string::String);
    impl Path {
        fn new() -> Self {
            Self(std::format!(
                "{}/hibana-pal-file-{}-{}",
                std::env::temp_dir().display(),
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ))
        }
    }
    impl Drop for Path {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    #[test]
    fn positional_access_observes_extent_and_rejects_invalid_ranges() {
        let path = Path::new();
        let file = File::create_new(&path.0).unwrap();
        assert!(file.is_empty().unwrap());
        assert!(
            matches!(File::create_new(&path.0), Err(e) if e.kind() == io::ErrorKind::AlreadyExists)
        );
        file.write_all_at(b"end", 8192).unwrap();
        assert_eq!(file.len().unwrap(), 8195);
        file.write_all_at(b"start", 0).unwrap();
        let mut b = [0; 5];
        file.read_exact_at(&mut b, 0).unwrap();
        assert_eq!(&b, b"start");
        let mut end = [0; 3];
        file.read_exact_at(&mut end, 8192).unwrap();
        assert_eq!(&end, b"end");
        assert!(file.read_exact_at(&mut end, 8194).is_err());
        assert!(file.write_all_at(b"x", u64::MAX).is_err());
        assert!(file.read_exact_at(&mut end, u64::MAX).is_err());
        assert!(file.set_len(u64::MAX).is_err());
        file.set_len(2).unwrap();
        assert_eq!(file.len().unwrap(), 2);
        let read = File::open(&path.0).unwrap();
        assert!(read.write_all_at(b"x", 0).is_err());
        assert_eq!(read.len().unwrap(), 2);
        file.set_len(0).unwrap();
        assert!(read.is_empty().unwrap());
    }
    #[test]
    fn separate_positions_are_safe_during_concurrent_length_queries() {
        let path = Path::new();
        let file = File::create_new(&path.0).unwrap();
        file.set_len(8192).unwrap();
        std::thread::scope(|scope| {
            for index in 0..4 {
                let file = &file;
                scope.spawn(move || {
                    let mut actual = [0; 128];
                    let expected = [index as u8 + 1; 128];
                    for _ in 0..100 {
                        file.write_all_at(&expected, index * 1024).unwrap();
                        assert_eq!(file.len().unwrap(), 8192);
                        file.read_exact_at(&mut actual, index * 1024).unwrap();
                        assert_eq!(actual, expected);
                    }
                });
            }
        });
    }
    #[test]
    fn invalid_paths_and_final_symlinks_are_rejected() {
        assert!(File::open("").is_err());
        assert!(File::open("a\0b").is_err());
        let target = Path::new();
        let link = Path::new();
        let _file = File::create_new(&target.0).unwrap();
        std::os::unix::fs::symlink(&target.0, &link.0).unwrap();
        assert!(File::open(&link.0).is_err());
        assert!(File::create_new(&link.0).is_err());
    }
}
