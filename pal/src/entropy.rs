//! Kernel entropy: Linux initialized random device or Darwin getentropy.
//!
//! /dev/random blocks until initialized (Linux >=5.6), unlike a bare early-boot
//! /dev/urandom read. On older kernels it may block again under entropy pressure.
//! No weak fallback is admitted. This adds a dependency on the kernel device
//! being available in the host namespace; missing or substituted files fail.
//! Reference: https://man7.org/linux/man-pages/man4/random.4.html
use hibana_quic::entropy::{Entropy, Unavailable};
#[cfg(target_os = "linux")]
use std::{
    fs::File,
    io::Read,
    os::unix::fs::{FileTypeExt, MetadataExt},
};

pub struct KernelEntropy;
#[cfg(target_os = "linux")]
impl Entropy for KernelEntropy {
    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Unavailable> {
        if destination.is_empty() {
            return Ok(());
        }
        let mut source = File::open("/dev/random").map_err(|_| Unavailable)?;
        let metadata = source.metadata().map_err(|_| Unavailable)?;
        // Linux device 1:8; checking the opened descriptor avoids a path race.
        if !metadata.file_type().is_char_device() || metadata.rdev() != 0x108 {
            return Err(Unavailable);
        }
        source.read_exact(destination).map_err(|_| Unavailable)
    }
}

#[cfg(target_os = "macos")]
impl Entropy for KernelEntropy {
    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Unavailable> {
        crate::sys::entropy(destination).map_err(|_| Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn kernel_device_fills_small_and_multi_read_requests() {
        for n in [0, 1, 32, 512, 513, 4096] {
            let mut bytes = vec![0; n];
            KernelEntropy.try_fill_bytes(&mut bytes).unwrap();
            // Success is IO coverage, not a statistical proof of entropy quality.
        }
    }
}
