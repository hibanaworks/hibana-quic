//! Complete published signature corpora through the bounded adapter.
//! Corpus decoding uses borrowed static slices; each public verification call is
//! independently measured, including invalid signatures and parse failures.
use hibana_tls::signature::rsa as tls_rsa;
use hibana_tls::signature::rsa::Error;
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
#[test]
fn bounded_der_key_and_signature_preconditions_allocate_zero() {
    use der::{
        Decode, Encode,
        asn1::{AnyRef, UintRef},
    };
    fn encode_key(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        for integer in [modulus, exponent] {
            let mut scratch = [0u8; 600];
            body.extend_from_slice(
                UintRef::new(integer)
                    .unwrap()
                    .encode_to_slice(&mut scratch)
                    .unwrap(),
            );
        }
        assert!((256..=65535).contains(&body.len()));
        let mut out = vec![0x30, 0x82, (body.len() >> 8) as u8, body.len() as u8];
        out.extend_from_slice(&body);
        out
    }
    let key = include_bytes!("../../../tests/vectors/rsa/oracle/rsa2048.der");
    let sig = include_bytes!("../../../tests/vectors/rsa/oracle/rsa2048.sig");
    for verify in [
        tls_rsa::verify_pss_sha256 as Verify,
        tls_rsa::verify_pkcs1_sha256,
    ] {
        for n in 0..key.len() {
            assert!(measured(|| verify(&key[..n], b"", sig)).is_err());
        }
        assert_eq!(
            measured(|| verify(key, b"", &sig[..sig.len() - 1])),
            Err(Error::InvalidSignature)
        );
        assert_eq!(
            measured(|| verify(key, b"", &[0xff; 256])),
            Err(Error::InvalidSignature)
        );
        assert!(measured(|| verify(key, b"changed message", sig)).is_err());
        let (parsed_modulus, parsed_exponent) = AnyRef::from_der(key)
            .unwrap()
            .sequence(|reader| Ok((UintRef::decode(reader)?, UintRef::decode(reader)?)))
            .unwrap();
        let mut modulus = [0; 256];
        modulus.copy_from_slice(parsed_modulus.as_bytes());
        for exponent in [
            &[0u8][..],
            &[1][..],
            &[2][..],
            &[4][..],
            &[1, 0, 0, 0, 1][..],
        ] {
            let bytes = encode_key(&modulus, exponent);
            assert_eq!(
                measured(|| verify(&bytes, b"", sig)),
                Err(Error::InvalidExponent)
            );
        }
        modulus[255] &= 0xfe;
        let bytes = encode_key(&modulus, parsed_exponent.as_bytes());
        assert_eq!(
            measured(|| verify(&bytes, b"", sig)),
            Err(Error::InvalidModulus)
        );
        modulus[255] |= 1;
        modulus[0] &= 0x7f;
        let bytes = encode_key(&modulus, parsed_exponent.as_bytes());
        assert_eq!(
            measured(|| verify(&bytes, b"", sig)),
            Err(Error::UnsupportedKeySize)
        );
        let mut trailing = [0; 600];
        trailing[..key.len()].copy_from_slice(key);
        assert_eq!(
            measured(|| verify(&trailing[..key.len() + 1], b"", sig)),
            Err(Error::InvalidDer)
        );
        // Negative INTEGER and redundant leading zero are rejected by the
        // borrowed DER parser before any arithmetic or helper invocation.
        for malformed in [
            &b"\x30\x06\x02\x01\x80\x02\x01\x03"[..],
            &b"\x30\x07\x02\x02\x00\x01\x02\x01\x03"[..],
        ] {
            assert_eq!(
                measured(|| verify(malformed, b"", sig)),
                Err(Error::InvalidDer)
            );
        }
    }
}
#[test]
fn strict_public_key_grammar_matches_independent_der_under_bit_mutation() {
    use der::{
        Decode,
        asn1::{AnyRef, UintRef},
    };
    let key = include_bytes!("../../../tests/vectors/rsa/oracle/rsa2048.der");
    let signature = [0u8; 256];
    for index in 0..key.len() {
        for bit in 0..8 {
            let mut mutated = *key;
            mutated[index] ^= 1 << bit;
            let reference = AnyRef::from_der(&mutated).and_then(|sequence| {
                sequence.sequence(|reader| {
                    let _ = UintRef::decode(reader)?;
                    let _ = UintRef::decode(reader)?;
                    Ok(())
                })
            });
            let result = measured(|| tls_rsa::verify_pss_sha256(&mutated, b"", &signature));
            assert_eq!(
                result == Err(Error::InvalidDer),
                reference.is_err(),
                "DER acceptance differs at byte={index} bit={bit}: {result:?}"
            );
        }
    }
}
