//! Filesystem selection and publication for the interoperability launcher.
use std::fs::File;
#[path = "../../unix/file.rs"]
mod storage;
pub use storage::FileStorage;
/// Open an already-selected directory without following a final symlink.
pub fn directory(path: &std::path::Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(hibana_quic_pal::unix::files::DIRECTORY_FLAGS)
        .open(path)
}
pub fn directory_at(parent: &File, name: &str) -> std::io::Result<File> {
    hibana_quic_pal::unix::files::directory_at(&Descriptor(parent), name)
        .map(into_file)
        .map_err(error)
}
pub fn read_at(parent: &File, name: &str) -> std::io::Result<File> {
    hibana_quic_pal::unix::files::read_at(&Descriptor(parent), name)
        .map(into_file)
        .map_err(error)
}
pub fn create_at(parent: &File, name: &str) -> std::io::Result<File> {
    hibana_quic_pal::unix::files::create_at(&Descriptor(parent), name)
        .map(into_file)
        .map_err(error)
}
pub fn mkdir_at(parent: &File, name: &str) -> std::io::Result<()> {
    hibana_quic_pal::unix::files::mkdir_at(&Descriptor(parent), name).map_err(error)
}
pub fn exists_at(parent: &File, name: &str) -> std::io::Result<bool> {
    hibana_quic_pal::unix::files::exists_at(&Descriptor(parent), name).map_err(error)
}
pub fn link_at(parent: &File, source: &str, target: &str) -> std::io::Result<()> {
    hibana_quic_pal::unix::files::link_at(&Descriptor(parent), source, target).map_err(error)
}
pub fn remove_at(parent: &File, name: &str) -> std::io::Result<()> {
    hibana_quic_pal::unix::files::remove_at(&Descriptor(parent), name).map_err(error)
}

struct Descriptor<'a>(&'a File);
impl hibana_quic_pal::unix::AsRawFd for Descriptor<'_> {
    fn as_raw_fd(&self) -> i32 {
        std::os::fd::AsRawFd::as_raw_fd(self.0)
    }
}
fn error(e: hibana_quic_pal::unix::error::Error) -> std::io::Error {
    match e.raw_os_error() {
        Some(code) => std::io::Error::from_raw_os_error(code),
        None => std::io::Error::new(std::io::ErrorKind::InvalidInput, e),
    }
}
fn into_file(fd: hibana_quic_pal::unix::OwnedFd) -> File {
    use std::os::fd::FromRawFd;
    // SAFETY: into_raw_fd transfers this uniquely owned descriptor exactly once.
    unsafe { File::from_raw_fd(fd.into_raw_fd()) }
}
