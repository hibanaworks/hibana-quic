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
