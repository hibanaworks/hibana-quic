//! HTTP/3 file-service decoding using one Hibana global and direct locals.
//!
//! [`decode_response`] consumes a FIN-complete staging file in place. It is not
//! a streaming client or a connection factory. The caller owns publication of
//! the resulting file; an error must leave that staging file unpublished.
//! [`decode_request`] validates the bounded GET profile used by `hq`.
mod global;
mod local;
mod wire;
use global::*;
use hibana::runtime::{
    SessionKitStorage,
    ids::SessionId,
    program::{RoleProgram, project},
};
use hibana_quic::{
    http3::{self, Fields},
    runtime::carrier::CarrierStorage,
};
use local::Exchange;
use std::{cell::RefCell, fs::File};
use wire::{fail, unknown};
type Result<T> = std::result::Result<T, String>;

/// Decode only a FIN-complete staging file. No destination is published here;
/// the caller keeps its existing atomic download-finish ownership contract.
pub async fn decode_response(file: &File) -> Result<u64> {
    let total = file.metadata().map_err(fail)?.len();
    let global = choreography();
    let reader: RoleProgram<READER> = project(&global);
    let writer: RoleProgram<WRITER> = project(&global);
    let carrier = CarrierStorage::<1, 16, 128>::new();
    let mut slab = vec![0; 65536];
    let mut kit = SessionKitStorage::uninit();
    let sid = SessionId::new(1);
    let rendezvous = kit
        .init()
        .rendezvous(&mut slab, carrier.bind(sid).map_err(fail)?)
        .map_err(fail)?;
    let mut reader = rendezvous.enter(sid, &reader).map_err(fail)?;
    let mut writer = rendezvous.enter(sid, &writer).map_err(fail)?;
    let exchange = Exchange {
        fields: RefCell::new(None),
        bytes: RefCell::new([0; 4096]),
    };
    let written = RefCell::new(0);
    hibana_quic::runtime::join2(
        local::read(&mut reader, file, total, &exchange),
        local::write(&mut writer, file, &exchange, &written),
    )
    .await?;
    Ok(written.into_inner())
}

/// A FIN-complete bounded GET request: HEADERS first, then an empty body.
/// Unknown extensions are skipped by their actual lengths. This file-service
/// profile does not accept pushed responses, CONNECT, or nonempty GET bodies.
pub fn decode_request(input: &[u8]) -> Result<Fields> {
    let mut offset = 0usize;
    let decoded = loop {
        let frame = http3::decode_frame_header(input.get(offset..).ok_or("request framing")?)
            .map_err(fail)?;
        offset = offset
            .checked_add(frame.encoded_len)
            .ok_or("request offset overflow")?;
        let end = offset
            .checked_add(usize::try_from(frame.length).map_err(fail)?)
            .ok_or("request length overflow")?;
        let bytes = input.get(offset..end).ok_or("truncated request frame")?;
        offset = end;
        if frame.kind == 1 {
            break http3::decode_fields(bytes).map_err(fail)?;
        }
        unknown(frame.kind)?;
    };
    if decoded.status.is_some()
        || decoded.method_get != Some(true)
        || decoded.https != Some(true)
        || decoded.path_len == 0
        || decoded.authority_len == 0
        || decoded.content_length.is_some_and(|n| n != 0)
    {
        return Err("request is not a bounded HTTPS GET".into());
    }
    while offset < input.len() {
        let frame = http3::decode_frame_header(&input[offset..]).map_err(fail)?;
        offset += frame.encoded_len;
        let end = offset
            .checked_add(usize::try_from(frame.length).map_err(fail)?)
            .ok_or("request length overflow")?;
        input.get(offset..end).ok_or("truncated request body")?;
        if frame.kind != 0 || frame.length != 0 {
            unknown(frame.kind)?;
        }
        offset = end;
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::KernelEntropy;
    use hibana_quic::entropy::Entropy;
    use std::{
        fs::OpenOptions,
        io::{Read, Seek, SeekFrom, Write},
    };
    fn frame(kind: u64, bytes: &[u8], out: &mut Vec<u8>) {
        let mut header = [0; 16];
        let n = http3::frame_header(kind, bytes.len() as u64, &mut header).unwrap();
        out.extend_from_slice(&header[..n]);
        out.extend_from_slice(bytes);
    }
    fn decode(bytes: &[u8]) -> Result<Vec<u8>> {
        let path = std::env::temp_dir().join(format!(
            "hibana-h3-file-{:016x}",
            u64::from_le_bytes({
                let mut bytes = [0; 8];
                KernelEntropy.try_fill_bytes(&mut bytes).unwrap();
                bytes
            })
        ));
        let mut file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        // The open file remains usable; no persistent test artifact is needed.
        std::fs::remove_file(path).unwrap();
        file.write_all(bytes).unwrap();
        let reactor = crate::async_io::Reactor::<1, 1>::new().unwrap();
        reactor.block_on(decode_response(&file)).unwrap()?;
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut body = Vec::new();
        file.read_to_end(&mut body).unwrap();
        Ok(body)
    }
    #[test]
    fn projected_response_consumes_actual_headers_chunks_and_trailers() {
        let mut wire = Vec::new();
        frame(1, &[0, 0, 0xd8], &mut wire); // 103 informational
        frame(1, &[0, 0, 0xd9], &mut wire); // 200
        let body: Vec<u8> = (0..10000).map(|i| (i % 251) as u8).collect();
        frame(0, &body, &mut wire);
        frame(0, b"", &mut wire);
        frame(0x21, b"unknown extension", &mut wire);
        frame(1, &[0, 0], &mut wire); // empty trailers
        frame(0x21, b"trailing extension", &mut wire);
        assert_eq!(decode(&wire).unwrap(), body);
    }
    #[test]
    fn projected_response_rejects_missing_headers_and_data_after_trailers() {
        let mut wire = Vec::new();
        frame(0, b"body", &mut wire);
        assert!(decode(&wire).is_err());
        wire.clear();
        frame(1, &[0, 0, 0xd9], &mut wire);
        frame(1, &[0, 0], &mut wire);
        frame(0, b"body", &mut wire);
        assert!(decode(&wire).is_err());
        wire.clear();
        frame(1, &[0, 0, 0xd9], &mut wire);
        frame(4, b"", &mut wire);
        assert!(decode(&wire).is_err());
    }
    #[test]
    fn projected_response_requires_actual_fin_length_and_content_length() {
        let mut wire = Vec::new();
        // Static-name reference #4 content-length with literal value 3.
        frame(1, &[0, 0, 0xd9, 0x54, 1, b'3'], &mut wire);
        frame(0, b"abc", &mut wire);
        assert_eq!(decode(&wire).unwrap(), b"abc");
        wire.pop();
        assert!(decode(&wire).is_err());
        wire.clear();
        frame(1, &[0, 0, 0xd9, 0x54, 1, b'3'], &mut wire);
        frame(0, b"ab", &mut wire);
        assert!(decode(&wire).is_err());
        wire.clear();
        frame(1, &[0, 0, 0xd9], &mut wire);
        assert_eq!(decode(&wire).unwrap(), b"");
    }
}
