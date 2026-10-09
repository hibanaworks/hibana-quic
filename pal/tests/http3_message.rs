
use hibana_quic::http3::{self, message::decode_response};
use hibana_quic_pal::fs::FileStorage;
type Result<T> = std::result::Result<T, String>;
use hibana_quic::entropy::Entropy;
use hibana_quic_pal::entropy::KernelEntropy;
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
    let reactor = hibana_quic_pal::async_io::Reactor::<1, 1>::new().unwrap();
    let mut slab = vec![0; 65536];
    reactor
        .block_on(decode_response(&FileStorage(&file), &mut slab))
        .unwrap()
        .map_err(|e| format!("{e:?}"))?;
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
