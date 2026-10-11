//! Kernel-generated cryptographic entropy; no file paths or weak fallback.
use hibana_quic::entropy::{Entropy, Unavailable};
pub struct KernelEntropy;
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
