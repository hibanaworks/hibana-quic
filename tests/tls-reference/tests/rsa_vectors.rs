//! Complete published signature corpora through the bounded adapter.
//! Corpus decoding uses borrowed static slices; each public verification call is
//! independently measured, including invalid signatures and parse failures.
use hibana_quic::tls::rsa::{self as tls_rsa, Error};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};
// Thread-local measurement avoids allocations in unrelated parallel test threads.
thread_local! { static TRACK: Cell<Option<usize>> = const { Cell::new(None) }; }
struct Counter;
fn allocation() {
    let _ = TRACK.try_with(|c| {
        if let Some(n) = c.get() {
            c.set(Some(n + 1))
        }
    });
}
unsafe impl GlobalAlloc for Counter {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        allocation();
        unsafe { System.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        allocation();
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        allocation();
        unsafe { System.realloc(p, l, n) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
}
#[global_allocator]
static ALLOCATOR: Counter = Counter;
fn measured<T>(f: impl FnOnce() -> T) -> T {
    TRACK.with(|c| c.set(Some(0)));
    let value = f();
    let n = TRACK.with(|c| c.replace(None).unwrap());
    assert_eq!(n, 0, "RSA verification allocated");
    value
}

type Verify = fn(&[u8], &[u8], &[u8]) -> Result<(), Error>;
fn take<'a>(data: &mut &'a [u8], n: usize) -> &'a [u8] {
    let (value, rest) = data.split_at(n);
    *data = rest;
    value
}
fn u32_value(data: &mut &[u8]) -> usize {
    u32::from_be_bytes(take(data, 4).try_into().unwrap()) as usize
}
fn run(mut data: &[u8], verify: Verify) {
    assert_eq!(take(&mut data, 8), b"RSAKAT01");
    let count = u32_value(&mut data);
    assert!(count > 0);
    for _ in 0..count {
        let id = u32_value(&mut data);
        let expected = take(&mut data, 1)[0] != 0;
        let key_len = u16::from_be_bytes(take(&mut data, 2).try_into().unwrap()) as usize;
        let msg_len = u32_value(&mut data);
        let sig_len = u32_value(&mut data);
        let key = take(&mut data, key_len);
        let msg = take(&mut data, msg_len);
        let sig = take(&mut data, sig_len);
        let result = measured(|| verify(key, msg, sig));
        assert_eq!(result.is_ok(), expected, "corpus tcId={id}: {result:?}");
    }
    assert!(data.is_empty());
}
macro_rules! corpus {
    ($name:ident,$path:literal,$verify:path) => {
        #[test]
        fn $name() {
            run(include_bytes!($path), $verify);
        }
    };
}
corpus!(
    pss2048,
    "../../../tests/vectors/rsa/rsa_pss_2048_sha256_mgf1_32_test.bin",
    tls_rsa::verify_pss_sha256
);
corpus!(
    pss3072,
    "../../../tests/vectors/rsa/rsa_pss_3072_sha256_mgf1_32_test.bin",
    tls_rsa::verify_pss_sha256
);
corpus!(
    pss4096,
    "../../../tests/vectors/rsa/rsa_pss_4096_sha256_mgf1_32_test.bin",
    tls_rsa::verify_pss_sha256
);
corpus!(
    pkcs1_2048,
    "../../../tests/vectors/rsa/rsa_signature_2048_sha256_test.bin",
    tls_rsa::verify_pkcs1_sha256
);
corpus!(
    pkcs1_3072,
    "../../../tests/vectors/rsa/rsa_signature_3072_sha256_test.bin",
    tls_rsa::verify_pkcs1_sha256
);
corpus!(
    pkcs1_4096,
    "../../../tests/vectors/rsa/rsa_signature_4096_sha256_test.bin",
    tls_rsa::verify_pkcs1_sha256
);
corpus!(
    pss_zero_salt_rejected,
    "../../../tests/vectors/rsa/rsa_pss_2048_sha256_mgf1_0_test.bin",
    tls_rsa::verify_pss_sha256
);

corpus!(
    pss_wrong_mgf_rejected,
    "../../../tests/vectors/rsa/rsa_pss_2048_sha256_mgf1sha1_20_test.bin",
    tls_rsa::verify_pss_sha256
);
