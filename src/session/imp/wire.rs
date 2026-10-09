use super::super::Protocol;
use crate::{
    http3::{self, Method},
    runtime::carrier::Frame,
};
pub const CAPACITY: usize = 1024;
pub struct Bytes {
    pub bytes: [u8; CAPACITY],
    pub len: usize,
    pub offset: usize,
}
impl Bytes {
    pub fn new() -> Self {
        Self {
            bytes: [0; CAPACITY],
            len: 0,
            offset: 0,
        }
    }
    pub fn append(&mut self, value: &[u8]) -> Result<(), ()> {
        let end = self
            .len
            .checked_add(value.len())
            .filter(|n| *n <= CAPACITY)
            .ok_or(())?;
        self.bytes[self.len..end].copy_from_slice(value);
        self.len = end;
        Ok(())
    }
    pub fn read(&mut self, out: &mut [u8]) -> usize {
        let n = out.len().min(self.len - self.offset);
        out[..n].copy_from_slice(&self.bytes[self.offset..self.offset + n]);
        self.offset += n;
        n
    }
    fn frame(&mut self, kind: u64, value: &[u8]) -> Result<(), ()> {
        let mut header = [0; 16];
        let n = http3::frame_header(kind, value.len() as u64, &mut header).map_err(|_| ())?;
        self.append(&header[..n])?;
        self.append(value)
    }
}
pub fn prefix(protocol: Protocol, authority: Option<&str>) -> Result<Bytes, ()> {
    let mut result = Bytes::new();
    if matches!(protocol, Protocol::Quic) {
        result.append(b"HBN1")?;
        return Ok(result);
    }
    let mut fields = [0; 512];
    let n = if let Some(authority) = authority {
        let n =
            http3::request_fields(authority.as_bytes(), b"/hibana", &mut fields).map_err(|_| ())?;
        fields[2] = 0xd4; // QPACK static :method POST.
        n
    } else {
        http3::response_fields(&mut fields).map_err(|_| ())?
    };
    result.frame(1, &fields[..n])?;
    Ok(result)
}
pub fn message(protocol: Protocol, frame: Frame<256>) -> Result<Bytes, ()> {
    let mut envelope = Bytes::new();
    envelope.append(&((8 + frame.payload().len()) as u32).to_be_bytes())?;
    envelope.append(&frame.header())?;
    envelope.append(frame.payload())?;
    if matches!(protocol, Protocol::Quic) {
        return Ok(envelope);
    }
    let mut out = Bytes::new();
    out.frame(0, &envelope.bytes[..envelope.len])?;
    Ok(out)
}
/// Only retained bytes and their consumed wire offset are tracked here.
pub struct Decoded<'a> {
    pub consumed: usize,
    pub header: [u8; 8],
    pub payload: &'a [u8],
}
pub struct Decoder {
    pub bytes: [u8; CAPACITY],
    pub len: usize,
    offset: u64,
    protocol: Protocol,
    request: bool,
}
impl Decoder {
    pub fn new(protocol: Protocol, request: bool) -> Self {
        Self {
            bytes: [0; CAPACITY],
            len: 0,
            offset: 0,
            protocol,
            request,
        }
    }
    pub fn consume(&mut self, n: usize) -> Result<(), ()> {
        if n > self.len {
            return Err(());
        }
        self.bytes.copy_within(n..self.len, 0);
        self.len -= n;
        self.offset = self.offset.checked_add(n as u64).ok_or(())?;
        Ok(())
    }
    pub fn prefix(&mut self) -> Result<bool, ()> {
        if self.offset != 0 {
            return Ok(true);
        }
        if matches!(self.protocol, Protocol::Quic) {
            if self.len < 4 {
                return Ok(false);
            }
            if &self.bytes[..4] != b"HBN1" {
                return Err(());
            }
            self.consume(4)?;
            return Ok(true);
        }
        let h = match http3::decode_frame_header(&self.bytes[..self.len]) {
            Ok(h) => h,
            Err(http3::Error::Truncated) => return Ok(false),
            Err(_) => return Err(()),
        };
        let end = h
            .encoded_len
            .checked_add(usize::try_from(h.length).map_err(|_| ())?)
            .filter(|n| *n <= CAPACITY)
            .ok_or(())?;
        if self.len < end {
            return Ok(false);
        }
        if h.kind != 1 {
            return Err(());
        }
        let f = http3::decode_fields(&self.bytes[h.encoded_len..end]).map_err(|_| ())?;
        if self.request {
            if f.method != Some(Method::Post)
                || f.https != Some(true)
                || f.status.is_some()
                || &f.path[..f.path_len] != b"/hibana"
                || f.authority_len == 0
            {
                return Err(());
            }
        } else if f.status != Some(200)
            || f.method.is_some()
            || f.https.is_some()
            || f.path_len != 0
            || f.authority_len != 0
        {
            return Err(());
        }
        // A streaming body has no predeclared length in this profile.
        if f.content_length.is_some() {
            return Err(());
        }
        self.consume(end)?;
        Ok(true)
    }
    pub fn next(&self) -> Result<Option<Decoded<'_>>, ()> {
        let (head, total, bytes) = if matches!(self.protocol, Protocol::Http3) {
            let h = match http3::decode_frame_header(&self.bytes[..self.len]) {
                Ok(h) => h,
                Err(http3::Error::Truncated) => return Ok(None),
                Err(_) => return Err(()),
            };
            if h.kind != 0 {
                return Err(());
            }
            let end = h
                .encoded_len
                .checked_add(usize::try_from(h.length).map_err(|_| ())?)
                .filter(|n| *n <= CAPACITY)
                .ok_or(())?;
            if self.len < end {
                return Ok(None);
            }
            (h.encoded_len, Some(end), &self.bytes[h.encoded_len..end])
        } else {
            (0, None, &self.bytes[..self.len])
        };
        if bytes.len() < 4 {
            return if total.is_some() { Err(()) } else { Ok(None) };
        }
        let n = u32::from_be_bytes(bytes[..4].try_into().map_err(|_| ())?) as usize;
        if !(8..=264).contains(&n) {
            return Err(());
        }
        let end = 4 + n;
        if bytes.len() < end {
            return if total.is_some() { Err(()) } else { Ok(None) };
        }
        if total.is_some() && bytes.len() != end {
            return Err(());
        }
        Ok(Some(Decoded {
            consumed: head + end,
            header: bytes[4..12].try_into().map_err(|_| ())?,
            payload: &bytes[12..end],
        }))
    }
    pub fn finish(&self) -> Result<(), ()> {
        if self.offset == 0 || self.len != 0 {
            Err(())
        } else {
            Ok(())
        }
    }
}
