//! HTTP/3 response framing is consumed by two literal projected local sides.
//! The read side owns wire offsets; the write side owns output offsets. Each
//! physical write is acknowledged before another input chunk can replace it.
use hibana::{
    Endpoint, g,
    runtime::{
        SessionKitStorage,
        ids::SessionId,
        program::{RoleProgram, project},
    },
};
use hibana_quic::{
    carrier::CarrierStorage,
    http3::{self, Fields, FrameHeader},
};
use std::{cell::RefCell, fs::File, os::unix::fs::FileExt};
type Result<T> = std::result::Result<T, String>;
const READER: u8 = 0;
const WRITER: u8 = 1;
type Information = g::Msg<1, ()>;
type Headers = g::Msg<2, ()>;
type Stored = g::Msg<3, ()>;
type Data = g::Msg<4, u64>;
type BodyEnd = g::Msg<5, ()>;
type Trailers = g::Msg<6, ()>;
type NoTrailers = g::Msg<7, ()>;
type End = g::Msg<8, ()>;
type Done = g::Msg<9, ()>;
type Head = g::Roll<
    g::Route<
        g::Seq<g::Send<READER, WRITER, Information>, g::Send<WRITER, READER, Stored>>,
        g::Seq<g::Send<READER, WRITER, Headers>, g::Send<WRITER, READER, Stored>>,
    >,
>;
type Body = g::Roll<
    g::Route<
        g::Seq<g::Send<READER, WRITER, Data>, g::Send<WRITER, READER, Stored>>,
        g::Send<READER, WRITER, BodyEnd>,
    >,
>;
type Tail = g::Route<
    g::Seq<g::Send<READER, WRITER, Trailers>, g::Send<WRITER, READER, Stored>>,
    g::Send<READER, WRITER, NoTrailers>,
>;
type Flow = g::Seq<
    Head,
    g::Seq<Body, g::Seq<Tail, g::Seq<g::Send<READER, WRITER, End>, g::Send<WRITER, READER, Done>>>>,
>;
fn choreography() -> g::Program<Flow> {
    g::seq(
        g::route(
            g::seq(
                g::send::<READER, WRITER, Information>(),
                g::send::<WRITER, READER, Stored>(),
            ),
            g::seq(
                g::send::<READER, WRITER, Headers>(),
                g::send::<WRITER, READER, Stored>(),
            ),
        )
        .roll(),
        g::seq(
            g::route(
                g::seq(
                    g::send::<READER, WRITER, Data>(),
                    g::send::<WRITER, READER, Stored>(),
                ),
                g::send::<READER, WRITER, BodyEnd>(),
            )
            .roll(),
            g::seq(
                g::route(
                    g::seq(
                        g::send::<READER, WRITER, Trailers>(),
                        g::send::<WRITER, READER, Stored>(),
                    ),
                    g::send::<READER, WRITER, NoTrailers>(),
                ),
                g::seq(
                    g::send::<READER, WRITER, End>(),
                    g::send::<WRITER, READER, Done>(),
                ),
            ),
        ),
    )
}
fn fail(e: impl std::fmt::Debug) -> String {
    format!("HTTP/3 response: {e:?}")
}
fn varint(file: &File, cursor: &mut u64, total: u64) -> Result<u64> {
    if *cursor >= total {
        return Err("truncated HTTP/3 integer".into());
    }
    let mut bytes = [0; 8];
    file.read_exact_at(&mut bytes[..1], *cursor).map_err(fail)?;
    let len = 1usize << (bytes[0] >> 6);
    if (len as u64) > total - *cursor {
        return Err("truncated HTTP/3 integer".into());
    }
    file.read_exact_at(&mut bytes[..len], *cursor)
        .map_err(fail)?;
    *cursor += len as u64;
    Ok(hibana_quic::packet::decode_varint(&bytes[..len])
        .map_err(fail)?
        .0)
}
fn next(file: &File, cursor: &mut u64, total: u64) -> Result<Option<FrameHeader>> {
    if *cursor == total {
        return Ok(None);
    }
    let start = *cursor;
    let kind = varint(file, cursor, total)?;
    let length = varint(file, cursor, total)?;
    if length > total - *cursor {
        return Err("truncated HTTP/3 frame".into());
    }
    if matches!(kind, 2 | 6 | 8 | 9) {
        return Err("reserved HTTP/2 frame on HTTP/3 stream".into());
    }
    Ok(Some(FrameHeader {
        kind,
        length,
        encoded_len: (*cursor - start) as usize,
    }))
}
fn fields(file: &File, cursor: &mut u64, length: u64) -> Result<Fields> {
    let length = usize::try_from(length).map_err(fail)?;
    let mut bytes = [0; http3::FIELD_LIMIT];
    let output = bytes
        .get_mut(..length)
        .ok_or("HTTP/3 field section exceeds bounded storage")?;
    file.read_exact_at(output, *cursor).map_err(fail)?;
    *cursor += length as u64;
    http3::decode_fields(output).map_err(fail)
}
fn unknown(kind: u64) -> Result<()> {
    if matches!(kind, 0 | 1 | 3 | 4 | 5 | 7 | 13) {
        Err("unexpected HTTP/3 frame on response stream".into())
    } else {
        Ok(())
    }
}
struct Exchange {
    fields: RefCell<Option<Fields>>,
    bytes: RefCell<[u8; 4096]>,
}
async fn read(
    endpoint: &mut Endpoint<'_, READER>,
    file: &File,
    total: u64,
    exchange: &Exchange,
) -> Result<()> {
    let mut cursor = 0;
    loop {
        let frame = next(file, &mut cursor, total)?.ok_or("response ended before final headers")?;
        if frame.kind != 1 {
            unknown(frame.kind)?;
            cursor += frame.length;
            continue;
        }
        let decoded = fields(file, &mut cursor, frame.length)?;
        let status = decoded.status.ok_or("response has no status")?;
        if decoded.method_get.is_some()
            || decoded.https.is_some()
            || decoded.path_len != 0
            || decoded.authority_len != 0
            || !(100..=599).contains(&status)
            || status == 101
        {
            return Err("invalid response pseudo-header".into());
        }
        *exchange.fields.borrow_mut() = Some(decoded);
        if status < 200 {
            endpoint.send::<Information>(&()).await.map_err(fail)?;
            endpoint.recv::<Stored>().await.map_err(fail)?;
        } else {
            endpoint.send::<Headers>(&()).await.map_err(fail)?;
            endpoint.recv::<Stored>().await.map_err(fail)?;
            break;
        }
    }
    let trailers = loop {
        let Some(frame) = next(file, &mut cursor, total)? else {
            break None;
        };
        if frame.kind == 1 {
            break Some(fields(file, &mut cursor, frame.length)?);
        }
        if frame.kind != 0 {
            unknown(frame.kind)?;
            cursor += frame.length;
            continue;
        }
        let mut remaining = frame.length;
        while remaining != 0 {
            let count = usize::try_from(remaining.min(4096)).map_err(fail)?;
            file.read_exact_at(&mut exchange.bytes.borrow_mut()[..count], cursor)
                .map_err(fail)?;
            cursor += count as u64;
            remaining -= count as u64;
            endpoint.send::<Data>(&(count as u64)).await.map_err(fail)?;
            endpoint.recv::<Stored>().await.map_err(fail)?;
        }
    };
    endpoint.send::<BodyEnd>(&()).await.map_err(fail)?;
    if let Some(trailers) = trailers {
        *exchange.fields.borrow_mut() = Some(trailers);
        endpoint.send::<Trailers>(&()).await.map_err(fail)?;
        endpoint.recv::<Stored>().await.map_err(fail)?;
        while let Some(frame) = next(file, &mut cursor, total)? {
            unknown(frame.kind)?;
            cursor += frame.length;
        }
    } else {
        endpoint.send::<NoTrailers>(&()).await.map_err(fail)?;
    }
    endpoint.send::<End>(&()).await.map_err(fail)?;
    endpoint.recv::<Done>().await.map_err(fail)?;
    Ok(())
}
async fn write(
    endpoint: &mut Endpoint<'_, WRITER>,
    file: &File,
    exchange: &Exchange,
    written: &RefCell<u64>,
) -> Result<()> {
    let expected = loop {
        let offered = endpoint.offer().await.map_err(fail)?;
        match offered.label() {
            1 => {
                offered.recv::<Information>().await.map_err(fail)?;
                let fields = exchange
                    .fields
                    .borrow_mut()
                    .take()
                    .ok_or("missing informational fields")?;
                if fields.content_length.is_some() {
                    return Err("informational content-length".into());
                }
                endpoint.send::<Stored>(&()).await.map_err(fail)?;
            }
            2 => {
                offered.recv::<Headers>().await.map_err(fail)?;
                let fields = exchange
                    .fields
                    .borrow_mut()
                    .take()
                    .ok_or("missing response fields")?;
                if fields.status != Some(200) {
                    return Err("download response was not 200".into());
                }
                endpoint.send::<Stored>(&()).await.map_err(fail)?;
                break fields.content_length;
            }
            _ => return Err("unexpected response header continuation".into()),
        }
    };
    let mut offset = 0u64;
    loop {
        let offered = endpoint.offer().await.map_err(fail)?;
        match offered.label() {
            4 => {
                let count =
                    usize::try_from(offered.recv::<Data>().await.map_err(fail)?).map_err(fail)?;
                let bytes = exchange.bytes.borrow();
                file.write_all_at(bytes.get(..count).ok_or("body chunk capacity")?, offset)
                    .map_err(fail)?;
                drop(bytes);
                offset = offset
                    .checked_add(count as u64)
                    .ok_or("body length overflow")?;
                if expected.is_some_and(|length| offset > length) {
                    return Err("body exceeds content-length".into());
                }
                endpoint.send::<Stored>(&()).await.map_err(fail)?;
            }
            5 => {
                offered.recv::<BodyEnd>().await.map_err(fail)?;
                break;
            }
            _ => return Err("unexpected response body continuation".into()),
        }
    }
    let offered = endpoint.offer().await.map_err(fail)?;
    match offered.label() {
        6 => {
            offered.recv::<Trailers>().await.map_err(fail)?;
            let fields = exchange
                .fields
                .borrow_mut()
                .take()
                .ok_or("missing trailers")?;
            if fields.has_pseudo() || fields.content_length.is_some() {
                return Err("invalid response trailers".into());
            }
            endpoint.send::<Stored>(&()).await.map_err(fail)?;
        }
        7 => {
            offered.recv::<NoTrailers>().await.map_err(fail)?;
        }
        _ => return Err("unexpected response trailer continuation".into()),
    }
    endpoint.recv::<End>().await.map_err(fail)?;
    if expected.is_some_and(|length| length != offset) {
        return Err("body differs from content-length".into());
    }
    file.set_len(offset).map_err(fail)?;
    *written.borrow_mut() = offset;
    endpoint.send::<Done>(&()).await.map_err(fail)?;
    Ok(())
}
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
        read(&mut reader, file, total, &exchange),
        write(&mut writer, file, &exchange, &written),
    )
    .await?;
    Ok(written.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{OsRng, RngCore};
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
        let path = std::env::temp_dir().join(format!("hibana-h3-file-{:016x}", OsRng.next_u64()));
        let mut file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        // The open file remains usable; no persistent test artifact is needed.
        std::fs::remove_file(path).unwrap();
        file.write_all(bytes).unwrap();
        let reactor = hibana_quic_host::async_io::Reactor::<1, 1>::new().unwrap();
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
