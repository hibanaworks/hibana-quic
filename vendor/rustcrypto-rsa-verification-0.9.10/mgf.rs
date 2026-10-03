// Mechanically extracted from RustCrypto/RSA 0.9.10; see README.md.
// MIT OR Apache-2.0. Function text is preserved verbatim.
use sha2::digest::{Digest, FixedOutputReset};

#[rustfmt::skip]
pub(crate) fn mgf1_xor_digest<D>(out: &mut [u8], digest: &mut D, seed: &[u8])
where
    D: Digest + FixedOutputReset,
{
    let mut counter = [0u8; 4];
    let mut i = 0;

    const MAX_LEN: u64 = core::u32::MAX as u64 + 1;
    assert!(out.len() as u64 <= MAX_LEN);

    while i < out.len() {
        Digest::update(digest, seed);
        Digest::update(digest, counter);

        let digest_output = digest.finalize_reset();
        let mut j = 0;
        loop {
            if j >= digest_output.len() || i >= out.len() {
                break;
            }

            out[i] ^= digest_output[j];
            j += 1;
            i += 1;
        }
        inc_counter(&mut counter);
    }
}

#[rustfmt::skip]
fn inc_counter(counter: &mut [u8; 4]) {
    for i in (0..4).rev() {
        counter[i] = counter[i].wrapping_add(1);
        if counter[i] != 0 {
            // No overflow
            return;
        }
    }
}
