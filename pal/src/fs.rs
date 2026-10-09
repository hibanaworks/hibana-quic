//! Native file access for caller-owned random-access storage.
use hibana_quic::io::{IoError, RandomAccess};
use std::{fs::File, os::unix::fs::FileExt};
/// Borrows an already-open file; path selection and publication belong to its owner.
pub struct FileStorage<'a>(pub &'a File);
impl RandomAccess for FileStorage<'_> {
    fn len(&self) -> Result<u64, IoError> {
        self.0
            .metadata()
            .map(|m| m.len())
            .map_err(|_| IoError::Rejected)
    }
    fn read_exact_at(&self, bytes: &mut [u8], offset: u64) -> Result<(), IoError> {
        self.0
            .read_exact_at(bytes, offset)
            .map_err(|_| IoError::Rejected)
    }
    fn write_all_at(&self, bytes: &[u8], offset: u64) -> Result<(), IoError> {
        self.0
            .write_all_at(bytes, offset)
            .map_err(|_| IoError::Rejected)
    }
    fn set_len(&self, length: u64) -> Result<(), IoError> {
        self.0.set_len(length).map_err(|_| IoError::Rejected)
    }
}

/// Open an already-selected directory without following a final symlink.
pub fn directory(path: &std::path::Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(crate::sys::file::DIRECTORY_FLAGS)
        .open(path)
}
pub fn directory_at(parent: &File, name: &str) -> std::io::Result<File> {
    crate::sys::file::directory(parent, name)
}
pub fn read_at(parent: &File, name: &str) -> std::io::Result<File> {
    crate::sys::file::read(parent, name)
}
pub fn create_at(parent: &File, name: &str) -> std::io::Result<File> {
    crate::sys::file::create(parent, name)
}
pub fn mkdir_at(parent: &File, name: &str) -> std::io::Result<()> {
    crate::sys::file::mkdir(parent, name)
}
pub fn exists_at(parent: &File, name: &str) -> std::io::Result<bool> {
    crate::sys::file::exists(parent, name)
}
pub fn link_at(parent: &File, source: &str, target: &str) -> std::io::Result<()> {
    crate::sys::file::link(parent, source, target)
}
pub fn remove_at(parent: &File, name: &str) -> std::io::Result<()> {
    crate::sys::file::remove(parent, name)
}
