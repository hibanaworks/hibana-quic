//! Bounded framing for the raw QUIC application carrier.
//! Native HTTP/3 messages use their own projected message localsides.
use crate::runtime::carrier::Frame;
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
}
pub fn prefix() -> Bytes {
    let mut result = Bytes::new();
    result.bytes[..4].copy_from_slice(b"HBN1");
    result.len = 4;
    result
}
pub fn message(frame: Frame<256>) -> Result<Bytes, ()> {
    let mut envelope = Bytes::new();
    envelope.append(&((8 + frame.payload().len()) as u32).to_be_bytes())?;
    envelope.append(&frame.header())?;
    envelope.append(frame.payload())?;
    Ok(envelope)
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
}
impl Decoder {
    pub fn new() -> Self {
        Self {
            bytes: [0; CAPACITY],
            len: 0,
            offset: 0,
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
        if self.len < 4 {
            return Ok(false);
        }
        if &self.bytes[..4] != b"HBN1" {
            return Err(());
        }
        self.consume(4)?;
        Ok(true)
    }
    pub fn next(&self) -> Result<Option<Decoded<'_>>, ()> {
        let bytes = &self.bytes[..self.len];
        if bytes.len() < 4 {
            return Ok(None);
        }
        let n = u32::from_be_bytes(bytes[..4].try_into().map_err(|_| ())?) as usize;
        if !(8..=264).contains(&n) {
            return Err(());
        }
        let end = 4 + n;
        if bytes.len() < end {
            return Ok(None);
        }
        Ok(Some(Decoded {
            consumed: end,
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
