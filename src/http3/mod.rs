//! Bounded HTTP/3 wire data. Protocol progression belongs to projected locals;
//! these routines only interpret bytes, lengths and immutable field values.
mod tables;
pub const FIELD_LIMIT: usize = 4096;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protocol {
    Http09,
    Http3,
}
impl Protocol {
    pub const fn alpn(self) -> &'static [u8] {
        match self {
            Self::Http09 => b"hq-interop",
            Self::Http3 => b"h3",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Truncated,
    Capacity,
    Integer,
    Huffman,
    DynamicReference,
    Field,
    Duplicate,
    PseudoOrder,
    Frame,
    Length,
}
fn integer(bytes: &[u8], prefix: u8) -> Result<(u64, usize), Error> {
    let first = *bytes.first().ok_or(Error::Truncated)?;
    let mask = (1u16 << prefix) - 1;
    let mut value = u64::from(first) & u64::from(mask);
    if value < u64::from(mask) {
        return Ok((value, 1));
    }
    let mut shift = 0u32;
    for (i, b) in bytes.iter().copied().enumerate().skip(1) {
        if shift >= 56 {
            return Err(Error::Integer);
        }
        value = value
            .checked_add(u64::from(b & 127) << shift)
            .ok_or(Error::Integer)?;
        if b & 128 == 0 {
            return Ok((value, i + 1));
        }
        shift += 7;
    }
    Err(Error::Truncated)
}
fn put_integer(out: &mut [u8], mut value: u64, prefix: u8, bits: u8) -> Result<usize, Error> {
    let mask = ((1u16 << prefix) - 1) as u64;
    let first = out.first_mut().ok_or(Error::Capacity)?;
    if value < mask {
        *first = bits | value as u8;
        return Ok(1);
    }
    *first = bits | mask as u8;
    value -= mask;
    let mut i = 1;
    while value >= 128 {
        *out.get_mut(i).ok_or(Error::Capacity)? = (value as u8 & 127) | 128;
        value >>= 7;
        i += 1;
    }
    *out.get_mut(i).ok_or(Error::Capacity)? = value as u8;
    Ok(i + 1)
}
fn huffman(input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let (mut value, mut bits, mut used) = (0u32, 0u8, 0usize);
    for byte in input {
        for shift in (0..8).rev() {
            value = (value << 1) | u32::from((byte >> shift) & 1);
            bits += 1;
            if let Some((symbol, _)) = tables::HUFFMAN
                .iter()
                .enumerate()
                .find(|(_, entry)| entry.1 == bits && entry.0 == value)
            {
                if symbol == 256 {
                    return Err(Error::Huffman);
                }
                *out.get_mut(used).ok_or(Error::Capacity)? = symbol as u8;
                used += 1;
                value = 0;
                bits = 0;
            } else if bits >= 30 {
                return Err(Error::Huffman);
            }
        }
    }
    if bits > 7 || value != (1u32 << bits) - 1 {
        return Err(Error::Huffman);
    }
    Ok(used)
}
fn string(
    input: &[u8],
    prefix: u8,
    huffman_bit: u8,
    out: &mut [u8],
) -> Result<(usize, usize), Error> {
    let (length, head) = integer(input, prefix)?;
    let length = usize::try_from(length).map_err(|_| Error::Capacity)?;
    let end = head.checked_add(length).ok_or(Error::Capacity)?;
    let raw = input.get(head..end).ok_or(Error::Truncated)?;
    let n = if input[0] & huffman_bit != 0 {
        huffman(raw, out)?
    } else {
        out.get_mut(..length)
            .ok_or(Error::Capacity)?
            .copy_from_slice(raw);
        length
    };
    Ok((n, end))
}
#[derive(Debug)]
pub struct Fields {
    pub status: Option<u16>,
    pub method_get: Option<bool>,
    pub https: Option<bool>,
    pub path: [u8; 1024],
    pub path_len: usize,
    pub authority: [u8; 256],
    pub authority_len: usize,
    pub content_length: Option<u64>,
    pub field_bytes: usize,
}
impl Fields {
    pub fn empty() -> Self {
        Self {
            status: None,
            method_get: None,
            https: None,
            path: [0; 1024],
            path_len: 0,
            authority: [0; 256],
            authority_len: 0,
            content_length: None,
            field_bytes: 0,
        }
    }
    pub fn has_pseudo(&self) -> bool {
        self.status.is_some()
            || self.method_get.is_some()
            || self.https.is_some()
            || self.path_len != 0
            || self.authority_len != 0
    }
    fn field(&mut self, name: &[u8], value: &[u8], regular: &mut usize) -> Result<(), Error> {
        if name.is_empty()
            || name.iter().enumerate().any(|(i, b)| {
                !b.is_ascii_lowercase()
                    && !b.is_ascii_digit()
                    && !b"!#$%&'*+-.^_`|~".contains(b)
                    && !(i == 0 && *b == b':')
            })
            || value.iter().any(|b| matches!(*b, 0 | b'\r' | b'\n'))
        {
            return Err(Error::Field);
        }
        self.field_bytes = self
            .field_bytes
            .checked_add(name.len() + value.len() + 32)
            .ok_or(Error::Capacity)?;
        if self.field_bytes > FIELD_LIMIT {
            return Err(Error::Capacity);
        }
        if name[0] == b':' {
            if *regular != 0 {
                return Err(Error::PseudoOrder);
            }
        } else {
            *regular += 1;
        }
        match name {
            b":status" => {
                if self.status.is_some() {
                    return Err(Error::Duplicate);
                }
                if value.len() != 3 || !value.iter().all(u8::is_ascii_digit) {
                    return Err(Error::Field);
                }
                self.status = Some(
                    ((value[0] - b'0') as u16) * 100
                        + ((value[1] - b'0') as u16) * 10
                        + (value[2] - b'0') as u16,
                );
            }
            b":method" => {
                if self.method_get.replace(value == b"GET").is_some() {
                    return Err(Error::Duplicate);
                }
            }
            b":scheme" => {
                if self.https.replace(value == b"https").is_some() {
                    return Err(Error::Duplicate);
                }
            }
            b":path" => {
                if self.path_len != 0 {
                    return Err(Error::Duplicate);
                }
                if value.is_empty() {
                    return Err(Error::Field);
                }
                self.path
                    .get_mut(..value.len())
                    .ok_or(Error::Capacity)?
                    .copy_from_slice(value);
                self.path_len = value.len();
            }
            b":authority" => {
                if self.authority_len != 0 {
                    return Err(Error::Duplicate);
                }
                if value.is_empty() {
                    return Err(Error::Field);
                }
                self.authority
                    .get_mut(..value.len())
                    .ok_or(Error::Capacity)?
                    .copy_from_slice(value);
                self.authority_len = value.len();
            }
            b"content-length" => {
                if self.content_length.is_some() {
                    return Err(Error::Duplicate);
                }
                if value.is_empty() {
                    return Err(Error::Field);
                }
                let mut n = 0u64;
                for b in value {
                    if !b.is_ascii_digit() {
                        return Err(Error::Field);
                    }
                    n = n
                        .checked_mul(10)
                        .and_then(|n| n.checked_add(u64::from(b - b'0')))
                        .ok_or(Error::Integer)?;
                }
                self.content_length = Some(n);
            }
            b"connection" | b"proxy-connection" | b"keep-alive" | b"transfer-encoding"
            | b"upgrade" => return Err(Error::Field),
            b"te" if value != b"trailers" => return Err(Error::Field),
            _ if name[0] == b':' => return Err(Error::Field),
            _ => {}
        }
        Ok(())
    }
}
pub fn decode_fields(input: &[u8]) -> Result<Fields, Error> {
    let (required, a) = integer(input, 8)?;
    if required != 0 {
        return Err(Error::DynamicReference);
    }
    let (base, b) = integer(input.get(a..).ok_or(Error::Truncated)?, 7)?;
    if base != 0 || input[a] & 128 != 0 {
        return Err(Error::DynamicReference);
    }
    let mut pos = a + b;
    let mut fields = Fields::empty();
    let mut regular = 0;
    let (mut name, mut value) = ([0u8; 1024], [0u8; FIELD_LIMIT]);
    while pos < input.len() {
        let x = input[pos];
        if x & 128 != 0 {
            if x & 64 == 0 {
                return Err(Error::DynamicReference);
            }
            let (index, n) = integer(&input[pos..], 6)?;
            let (nm, val) = *tables::STATIC
                .get(usize::try_from(index).map_err(|_| Error::Integer)?)
                .ok_or(Error::Field)?;
            fields.field(nm, val, &mut regular)?;
            pos += n;
        } else if x & 64 != 0 {
            if x & 16 == 0 {
                return Err(Error::DynamicReference);
            }
            let (index, n) = integer(&input[pos..], 4)?;
            let (nm, _) = *tables::STATIC
                .get(usize::try_from(index).map_err(|_| Error::Integer)?)
                .ok_or(Error::Field)?;
            pos += n;
            let (v, n) = string(&input[pos..], 7, 128, &mut value)?;
            pos += n;
            fields.field(nm, &value[..v], &mut regular)?;
        } else if x & 32 != 0 {
            let (nm, n) = string(&input[pos..], 3, 8, &mut name)?;
            pos += n;
            let (v, n) = string(&input[pos..], 7, 128, &mut value)?;
            pos += n;
            fields.field(&name[..nm], &value[..v], &mut regular)?;
        } else {
            return Err(Error::DynamicReference);
        }
    }
    Ok(fields)
}
fn literal(out: &mut [u8], index: u64, value: &[u8]) -> Result<usize, Error> {
    let mut n = put_integer(out, index, 4, 0x50)?;
    n += put_integer(&mut out[n..], value.len() as u64, 7, 0)?;
    out.get_mut(n..n + value.len())
        .ok_or(Error::Capacity)?
        .copy_from_slice(value);
    Ok(n + value.len())
}
pub fn request_fields(authority: &[u8], path: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    out.get_mut(..4)
        .ok_or(Error::Capacity)?
        .copy_from_slice(&[0, 0, 0xd1, 0xd7]);
    let mut n = 4;
    n += literal(&mut out[n..], 0, authority)?;
    n += literal(&mut out[n..], 1, path)?;
    Ok(n)
}
pub fn response_fields(out: &mut [u8]) -> Result<usize, Error> {
    out.get_mut(..3)
        .ok_or(Error::Capacity)?
        .copy_from_slice(&[0, 0, 0xd9]);
    Ok(3)
}
pub fn frame_header(kind: u64, length: u64, out: &mut [u8]) -> Result<usize, Error> {
    let n = crate::packet::encode_varint(kind, out).map_err(|_| Error::Integer)?;
    let m = crate::packet::encode_varint(length, &mut out[n..]).map_err(|_| Error::Integer)?;
    Ok(n + m)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn static_request_response_roundtrip() {
        let mut b = [0; 256];
        let n = request_fields(b"localhost:443", b"/hello", &mut b).unwrap();
        let f = decode_fields(&b[..n]).unwrap();
        assert_eq!(f.method_get, Some(true));
        assert_eq!(&f.path[..f.path_len], b"/hello");
        let n = response_fields(&mut b).unwrap();
        assert_eq!(decode_fields(&b[..n]).unwrap().status, Some(200));
    }
    #[test]
    fn rfc_huffman_and_invalid_eos() {
        let mut o = [0; 64];
        let n = huffman(
            &[
                0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
            ],
            &mut o,
        )
        .unwrap();
        assert_eq!(&o[..n], b"www.example.com");
        assert!(huffman(&[0xff; 4], &mut o).is_err());
        assert!(huffman(&[0], &mut o).is_err());
    }
    #[test]
    fn dynamic_and_duplicate_pseudo_rejected() {
        assert_eq!(decode_fields(&[1, 0]).unwrap_err(), Error::DynamicReference);
        assert_eq!(
            decode_fields(&[0, 0, 0xd9, 0xd9]).unwrap_err(),
            Error::Duplicate
        );
    }
}
