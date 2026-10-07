//! RFC 9000 §18 transport-parameter syntax and fixed semantic bounds.
//! Parsing does not authenticate the TLS transcript. Apply parameters only after
//! the handshake authenticates them, and compare connection IDs to observed wire
//! values. Unknown parameters are retained and ignored, not silently reinterpreted.
use crate::packet::{MAX_VARINT, decode_varint};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Peer {
    Client,
    Server,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Truncated,
    Duplicate,
    Capacity,
    InvalidValue,
    ForbiddenForClient,
    MissingConnectionId,
    ConnectionIdMismatch,
}
#[derive(Clone, Copy, Debug)]
pub struct Parameters<'a> {
    input: &'a [u8],
    peer: Peer,
}

fn next(input: &[u8]) -> Result<(u64, &[u8], usize), Error> {
    let (id, a) = decode_varint(input).map_err(|_| Error::Truncated)?;
    let (len, b) = decode_varint(&input[a..]).map_err(|_| Error::Truncated)?;
    let len = usize::try_from(len).map_err(|_| Error::Truncated)?;
    let end = (a + b).checked_add(len).ok_or(Error::Truncated)?;
    Ok((id, input.get(a + b..end).ok_or(Error::Truncated)?, end))
}
fn integer(value: &[u8]) -> Result<u64, Error> {
    let (n, len) = decode_varint(value).map_err(|_| Error::InvalidValue)?;
    if len != value.len() {
        return Err(Error::InvalidValue);
    }
    Ok(n)
}

impl<'a> Parameters<'a> {
    /// Validate the entire list before exposing any values. `seen` is caller-owned
    /// scratch for duplicate detection, including unknown IDs. Capacity exhaustion
    /// is a local admission limit and must not be misreported as a peer violation.
    pub fn parse(input: &'a [u8], peer: Peer, seen: &mut [u64]) -> Result<Self, Error> {
        let mut count = 0;
        let mut remaining = input;
        while !remaining.is_empty() {
            let (id, value, used) = next(remaining)?;
            if seen[..count].contains(&id) {
                return Err(Error::Duplicate);
            }
            if count == seen.len() {
                return Err(Error::Capacity);
            }
            seen[count] = id;
            count += 1;
            if peer == Peer::Client && matches!(id, 0 | 2 | 13 | 16) {
                return Err(Error::ForbiddenForClient);
            }
            match id {
                0 | 15 | 16 if value.len() > 20 => return Err(Error::InvalidValue),
                2 if value.len() != 16 => return Err(Error::InvalidValue),
                12 if !value.is_empty() => return Err(Error::InvalidValue),
                1 | 3..=11 | 14 => {
                    let n = integer(value)?;
                    if (id == 3 && n < 1200)
                        || (matches!(id, 8 | 9) && n > (1 << 60))
                        || (id == 10 && n > 20)
                        || (id == 11 && n >= (1 << 14))
                        || (id == 14 && n < 2)
                    {
                        return Err(Error::InvalidValue);
                    }
                }
                0x11 => {
                    crate::version::Information::parse(value, peer == Peer::Client)
                        .map_err(|_| Error::InvalidValue)?;
                }
                13 => {
                    if value.len() < 41 {
                        return Err(Error::InvalidValue);
                    }
                    let cid_len = value[24] as usize;
                    if cid_len == 0 || cid_len > 20 || value.len() != 41 + cid_len {
                        return Err(Error::InvalidValue);
                    }
                }
                _ => {}
            }
            remaining = &remaining[used..];
        }
        if !seen[..count].contains(&15) || (peer == Peer::Server && !seen[..count].contains(&0)) {
            return Err(Error::MissingConnectionId);
        }
        Ok(Self { input, peer })
    }

    pub fn get(&self, id: u64) -> Option<&'a [u8]> {
        let mut input = self.input;
        while !input.is_empty() {
            let (found, value, used) = next(input).ok()?;
            if found == id {
                return Some(value);
            }
            input = &input[used..];
        }
        None
    }

    pub fn get_integer(&self, id: u64, default: u64) -> Result<u64, Error> {
        if default > MAX_VARINT || !matches!(id, 1 | 3..=11 | 14) {
            return Err(Error::InvalidValue);
        }
        self.get(id).map(integer).unwrap_or(Ok(default))
    }

    /// Validate against connection IDs retained from this connection's packets.
    /// Client peers never advertise ODCID or Retry SCID. For servers, `original`
    /// must be the client's first Initial DCID; `retry` is Some only after Retry.
    pub fn verify_connection_ids(
        &self,
        initial: &[u8],
        original: Option<&[u8]>,
        retry: Option<&[u8]>,
    ) -> Result<(), Error> {
        if self.get(15) != Some(initial) {
            return Err(Error::ConnectionIdMismatch);
        }
        match self.peer {
            Peer::Client if original.is_some() || retry.is_some() => {
                return Err(Error::InvalidValue);
            }
            Peer::Client => {}
            Peer::Server => {
                if original.is_none() || self.get(0) != original || self.get(16) != retry {
                    return Err(Error::ConnectionIdMismatch);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::encode_varint;
    use std::vec::Vec;
    fn params(items: &[(u64, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0; 8];
        for (id, data) in items {
            let n = encode_varint(*id, &mut buf).unwrap();
            out.extend_from_slice(&buf[..n]);
            let n = encode_varint(data.len() as u64, &mut buf).unwrap();
            out.extend_from_slice(&buf[..n]);
            out.extend_from_slice(data);
        }
        out
    }
    #[test]
    fn validates_ids_and_nonminimal_integer_value() {
        let bytes = params(&[
            (0, b"orig"),
            (15, b"server"),
            (16, b"retry"),
            (10, &[0x40, 3]),
        ]);
        let p = Parameters::parse(&bytes, Peer::Server, &mut [0; 8]).unwrap();
        assert_eq!(p.get_integer(10, 3), Ok(3));
        assert_eq!(
            p.verify_connection_ids(b"server", Some(b"orig"), Some(b"retry")),
            Ok(())
        );
        assert_eq!(
            p.verify_connection_ids(b"server", Some(b"orig"), None),
            Err(Error::ConnectionIdMismatch)
        );
    }
    #[test]
    fn rejects_missing_duplicate_unknown_and_capacity() {
        assert!(matches!(
            Parameters::parse(&[], Peer::Client, &mut [0; 4]),
            Err(Error::MissingConnectionId)
        ));
        let bytes = params(&[(15, b""), (99, b"x"), (99, b"x")]);
        assert!(matches!(
            Parameters::parse(&bytes, Peer::Client, &mut [0; 4]),
            Err(Error::Duplicate)
        ));
        let bytes = params(&[(15, b""), (99, b"x")]);
        assert!(matches!(
            Parameters::parse(&bytes, Peer::Client, &mut [0; 1]),
            Err(Error::Capacity)
        ));
        let p = Parameters::parse(&bytes, Peer::Client, &mut [0; 2]).unwrap();
        assert_eq!(p.get(99), Some(&b"x"[..]));
    }
    #[test]
    fn numeric_bounds_and_forbidden_server_fields() {
        for (id, n) in [
            (3, 1199),
            (8, (1 << 60) + 1),
            (9, (1 << 60) + 1),
            (10, 21),
            (11, 1 << 14),
            (14, 1),
        ] {
            let mut b = [0; 8];
            let len = encode_varint(n, &mut b).unwrap();
            let input = params(&[(15, b""), (id, &b[..len])]);
            assert!(matches!(
                Parameters::parse(&input, Peer::Client, &mut [0; 2]),
                Err(Error::InvalidValue)
            ));
        }
        for id in [0, 2, 13, 16] {
            let input = params(&[(15, b""), (id, b"")]);
            assert!(matches!(
                Parameters::parse(&input, Peer::Client, &mut [0; 2]),
                Err(Error::ForbiddenForClient)
            ));
        }
    }
    #[test]
    fn preferred_address_and_truncation() {
        let mut address = [0; 45];
        address[24] = 4;
        let input = params(&[(0, b""), (15, b""), (13, &address)]);
        assert!(Parameters::parse(&input, Peer::Server, &mut [0; 3]).is_ok());
        address[24] = 0;
        let input = params(&[(0, b""), (15, b""), (13, &address)]);
        assert!(matches!(
            Parameters::parse(&input, Peer::Server, &mut [0; 3]),
            Err(Error::InvalidValue)
        ));
        assert!(matches!(
            Parameters::parse(&[15, 4, 1], Peer::Client, &mut [0; 3]),
            Err(Error::Truncated)
        ));
    }
}
