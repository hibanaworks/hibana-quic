//! Descriptor-relative native file operations, confined to one child name.
use std::{
    ffi::{CString, c_char},
    fs::File,
    io,
    os::fd::{AsRawFd, FromRawFd},
};
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
pub(crate) const DIRECTORY_FLAGS: i32 = abi::DIRECTORY | abi::NOFOLLOW | abi::CLOEXEC;
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
fn child(name: &str) -> io::Result<CString> {
    if name.is_empty() || matches!(name, "." | "..") || name.contains(['/', '\\']) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    CString::new(name).map_err(|_| io::ErrorKind::InvalidInput.into())
}
fn checked(value: i32) -> io::Result<()> {
    if value == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
fn open(parent: &File, name: &str, flags: i32) -> io::Result<File> {
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
    Ok(unsafe { File::from_raw_fd(fd) })
}
pub(crate) fn directory(parent: &File, name: &str) -> io::Result<File> {
    open(parent, name, abi::DIRECTORY)
}
pub(crate) fn read(parent: &File, name: &str) -> io::Result<File> {
    open(parent, name, abi::NONBLOCK)
}
pub(crate) fn create(parent: &File, name: &str) -> io::Result<File> {
    open(parent, name, 2 | abi::CREATE)
}
pub(crate) fn mkdir(parent: &File, name: &str) -> io::Result<()> {
    let name = child(name)?;
    // SAFETY: the descriptor and terminated name remain live; no pointer is retained.
    checked(unsafe { mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o777) })
}
pub(crate) fn exists(parent: &File, name: &str) -> io::Result<bool> {
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
pub(crate) fn link(parent: &File, source: &str, target: &str) -> io::Result<()> {
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
pub(crate) fn remove(parent: &File, name: &str) -> io::Result<()> {
    let name = child(name)?;
    // SAFETY: valid descriptor and terminated name; flags zero removes only a file link.
    checked(unsafe { unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) })
}
