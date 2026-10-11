//! The peer's real control-stream bytes cross a projected SETTINGS boundary.
//! Retained fields below are bytes/stream identities, not a phase dispatcher.
use crate::http3;
use crate::quic::application::Error;
use crate::quic::imp::kernel::streams::StreamHandle;
use crate::quic::imp::tls::Inbox;
use core::cell::RefCell;

pub(crate) struct Frame {
    pub kind: u64,
    pub bytes: [u8; http3::FIELD_LIMIT],
    pub len: usize,
}
struct Stream {
    handle: StreamHandle,
    kind: Option<u64>,
    bytes: [u8; http3::FIELD_LIMIT],
    len: usize,
}
pub(crate) struct Ingress {
    streams: RefCell<[Option<Stream>; 3]>,
    pub frame: Inbox<Option<Frame>>,
    pub settings: RefCell<Option<http3::Settings>>,
}
impl Ingress {
    pub fn new() -> Self {
        Self {
            streams: RefCell::new([const { None }; 3]),
            frame: Inbox::new(),
            settings: RefCell::new(None),
        }
    }
    pub fn append(&self, handle: StreamHandle, bytes: &[u8], fin: bool) -> Result<(), Error> {
        let mut streams = self.streams.try_borrow_mut().map_err(|_| Error::Binding)?;
        let slot = if let Some(i) = streams
            .iter()
            .position(|s| s.as_ref().is_some_and(|s| s.handle == handle))
        {
            i
        } else {
            let i = streams
                .iter()
                .position(Option::is_none)
                .ok_or(Error::Capacity)?;
            streams[i] = Some(Stream {
                handle,
                kind: None,
                bytes: [0; http3::FIELD_LIMIT],
                len: 0,
            });
            i
        };
        let stream = streams[slot].as_mut().ok_or(Error::Binding)?;
        if stream.kind.is_some_and(|kind| !matches!(kind, 0..=3)) {
            return Ok(());
        }
        let end = stream.len.checked_add(bytes.len()).ok_or(Error::Capacity)?;
        stream
            .bytes
            .get_mut(stream.len..end)
            .ok_or(Error::Capacity)?
            .copy_from_slice(bytes);
        stream.len = end;
        if stream.kind.is_none() {
            match crate::quic::imp::kernel::packet::decode_varint(&stream.bytes[..stream.len]) {
                Ok((kind, used)) => {
                    stream.kind = Some(kind);
                    stream.bytes.copy_within(used..stream.len, 0);
                    stream.len -= used;
                }
                Err(crate::quic::imp::kernel::packet::Error::Truncated) if !fin => return Ok(()),
                Err(_) => return Err(Error::Application),
            }
        }
        let kind = stream.kind.ok_or(Error::Application)?;
        if kind == 1 || (fin && matches!(kind, 0 | 2 | 3)) {
            return Err(Error::Application);
        }
        if kind == 2 && stream.len != 0 {
            return Err(Error::Application);
        }
        if kind == 3 && stream.len != 0 {
            // The static encoder has no outstanding inserts or sections. Only
            // stream cancellation has no dynamic resource left to acknowledge.
            let mut used = 0;
            while used < stream.len {
                if stream.bytes[used] & 0xc0 != 0x40 {
                    return Err(Error::Application);
                }
                match http3::decode_prefix_integer(&stream.bytes[used..stream.len], 6) {
                    Ok((_, n)) => used += n,
                    Err(http3::Error::Truncated) => break,
                    Err(_) => return Err(Error::Application),
                }
            }
            stream.bytes.copy_within(used..stream.len, 0);
            stream.len -= used;
        }
        if !matches!(kind, 0 | 2 | 3) {
            stream.len = 0;
        }
        if matches!(kind, 0 | 2 | 3)
            && streams
                .iter()
                .enumerate()
                .any(|(i, s)| i != slot && s.as_ref().is_some_and(|s| s.kind == Some(kind)))
        {
            return Err(Error::Application);
        }
        Ok(())
    }
    pub fn next_frame(&self, handle: StreamHandle) -> Result<Option<Frame>, Error> {
        let mut streams = self.streams.try_borrow_mut().map_err(|_| Error::Binding)?;
        let stream = streams
            .iter_mut()
            .flatten()
            .find(|s| s.handle == handle)
            .ok_or(Error::Binding)?;
        if stream.kind != Some(0) {
            return Ok(None);
        }
        let header = match http3::decode_frame_header(&stream.bytes[..stream.len]) {
            Ok(header) => header,
            Err(http3::Error::Truncated) => return Ok(None),
            Err(_) => return Err(Error::Application),
        };
        let length = usize::try_from(header.length).map_err(|_| Error::Capacity)?;
        let end = header
            .encoded_len
            .checked_add(length)
            .ok_or(Error::Capacity)?;
        if end > http3::FIELD_LIMIT {
            return Err(Error::Capacity);
        }
        if end > stream.len {
            return Ok(None);
        }
        let mut frame = Frame {
            kind: header.kind,
            bytes: [0; http3::FIELD_LIMIT],
            len: length,
        };
        frame.bytes[..length].copy_from_slice(&stream.bytes[header.encoded_len..end]);
        stream.bytes.copy_within(end..stream.len, 0);
        stream.len -= end;
        Ok(Some(frame))
    }
}
