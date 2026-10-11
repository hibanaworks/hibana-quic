#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Capacity,
    Method,
    LineEnding,
    Target,
}
fn validate(target: &str) -> Result<(), Error> {
    if !target.starts_with('/') || target.bytes().any(|b| b <= 0x20 || b == 0x7f) {
        Err(Error::Target)
    } else {
        Ok(())
    }
}
/// Encode a complete GET request. Failure leaves the supplied storage unchanged.
pub fn encode_request(target: &str, output: &mut [u8]) -> Result<usize, Error> {
    validate(target)?;
    let len = target.len().checked_add(6).ok_or(Error::Capacity)?;
    let output = output.get_mut(..len).ok_or(Error::Capacity)?;
    output[..4].copy_from_slice(b"GET ");
    output[4..len - 2].copy_from_slice(target.as_bytes());
    output[len - 2..].copy_from_slice(b"\r\n");
    Ok(len)
}
/// Borrow the target from a complete, FIN-terminated request. Path authorization,
/// percent decoding and file publication belong to the application's store.
pub fn decode_request(request: &[u8]) -> Result<&str, Error> {
    let line = request
        .strip_suffix(b"\r\n")
        .or_else(|| request.strip_suffix(b"\n"))
        .ok_or(Error::LineEnding)?;
    let target = line.strip_prefix(b"GET ").ok_or(Error::Method)?;
    let target = core::str::from_utf8(target).map_err(|_| Error::Target)?;
    validate(target)?;
    Ok(target)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn borrowed_target_and_bounded_output_need_no_allocator() {
        let guard = actor_test_allocator::NoAlloc::start();
        let mut bytes = [0; 32];
        let n = encode_request("/hello", &mut bytes).unwrap();
        assert_eq!(&bytes[..n], b"GET /hello\r\n");
        let target = decode_request(&bytes[..n]).unwrap();
        assert_eq!(target, "/hello");
        assert_eq!(target.as_ptr(), bytes[4..].as_ptr());
        assert_eq!(decode_request(b"GET /hello\n"), Ok("/hello"));
        guard.finish();
    }
    #[test]
    fn malformed_input_and_capacity_fail_without_output_changes() {
        for value in [
            b"POST /x\r\n".as_slice(),
            b"GET /x",
            b"GET /x HTTP/1.1\r\n",
            b"GET /x\r\nX: header\r\n",
            b"GET /x\0\n",
            b"GET relative\n",
        ] {
            assert!(decode_request(value).is_err());
        }
        for target in ["relative", "/x\n", "/x y"] {
            let mut out = [0xa5; 32];
            assert!(encode_request(target, &mut out).is_err());
            assert_eq!(out, [0xa5; 32]);
        }
        let mut out = [0xa5; 2];
        assert_eq!(encode_request("/x", &mut out), Err(Error::Capacity));
        assert_eq!(out, [0xa5; 2]);
    }
}
