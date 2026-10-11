//! Encoding of locally advertised transport parameters into caller storage.
use crate::quic::imp::kernel::{
    packet::{Error, encode_varint},
    streams::Limits,
    version::Version,
};
/// Values advertised by this endpoint; resource limits must match owned storage.
pub struct Advertisement<'a> {
    pub version: Version,
    pub local: &'a [u8],
    pub original: Option<&'a [u8]>,
    pub application_limits: Option<Limits>,
    pub retry_source: Option<&'a [u8]>,
    pub idle_timeout_ms: u64,
    pub max_datagram_size: u64,
}
impl Advertisement<'_> {
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, Error> {
        let Self {
            version,
            local,
            original,
            application_limits,
            retry_source,
            idle_timeout_ms,
            max_datagram_size,
        } = *self;
        let mut used = 0usize;
        if version == Version::V2 {
            let chosen = if original.is_some() {
                version.wire()
            } else {
                1
            };
            append(output, &mut used, &[0x11, 12])?;
            append(output, &mut used, &chosen.to_be_bytes())?;
            append(output, &mut used, &version.wire().to_be_bytes())?;
            append(output, &mut used, &1u32.to_be_bytes())?;
        }
        let mut encoded = [0; 8];
        for (kind, value) in [(15, Some(local)), (0, original), (16, retry_source)] {
            if let Some(value) = value {
                let len = encode_varint(kind, &mut encoded)?;
                append(output, &mut used, &encoded[..len])?;
                let len = encode_varint(value.len() as u64, &mut encoded)?;
                append(output, &mut used, &encoded[..len])?;
                append(output, &mut used, value)?;
            }
        }
        if let Some(limits) = application_limits {
            // Advertise exactly the windows backed by application_storage.
            for (kind, value) in [
                (1, idle_timeout_ms),
                (3, max_datagram_size),
                (4, limits.max_data),
                (5, limits.stream_data_bidi_local),
                (6, limits.stream_data_bidi_remote),
                (7, limits.stream_data_uni),
                (8, limits.max_streams_bidi),
                (9, limits.max_streams_uni),
            ] {
                let mut value_bytes = [0; 8];
                let value_len = encode_varint(value, &mut value_bytes)?;
                let len = encode_varint(kind, &mut encoded)?;
                append(output, &mut used, &encoded[..len])?;
                let len = encode_varint(value_len as u64, &mut encoded)?;
                append(output, &mut used, &encoded[..len])?;
                append(output, &mut used, &value_bytes[..value_len])?;
            }
        }
        Ok(used)
    }
}
fn append(output: &mut [u8], used: &mut usize, bytes: &[u8]) -> Result<(), Error> {
    let end = used.checked_add(bytes.len()).ok_or(Error::InvalidLength)?;
    output
        .get_mut(*used..end)
        .ok_or(Error::BufferTooShort)?
        .copy_from_slice(bytes);
    *used = end;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::imp::kernel::parameters::{Parameters, Peer};
    fn advertisement() -> Advertisement<'static> {
        Advertisement {
            version: Version::V1,
            local: b"local001",
            original: Some(b"original"),
            application_limits: Some(Limits {
                max_data: 8192,
                stream_data_bidi_local: 1024,
                stream_data_bidi_remote: 1024,
                stream_data_uni: 1024,
                max_streams_bidi: 2,
                max_streams_uni: 3,
            }),
            retry_source: Some(b"retry001"),
            idle_timeout_ms: 5000,
            max_datagram_size: 1536,
        }
    }
    #[test]
    fn advertised_values_round_trip_and_capacity_is_exact() {
        let values = advertisement();
        let mut buffer = [0; 256];
        let len = values.encode(&mut buffer).unwrap();
        let parsed = Parameters::parse(&buffer[..len], Peer::Server, &mut [0; 32]).unwrap();
        assert_eq!(parsed.get_integer(1, 0).unwrap(), 5000);
        assert_eq!(parsed.get_integer(3, 0).unwrap(), 1536);
        assert_eq!(parsed.get_integer(4, 0).unwrap(), 8192);
        assert_eq!(parsed.get_integer(8, 0).unwrap(), 2);
        assert_eq!(values.encode(&mut buffer[..len]).unwrap(), len);
        for capacity in 0..len {
            assert!(values.encode(&mut [0; 256][..capacity]).is_err());
        }
    }
    #[test]
    fn v2_version_information_keeps_role_specific_chosen_version() {
        let mut values = advertisement();
        values.version = Version::V2;
        let mut bytes = [0; 256];
        values.encode(&mut bytes).unwrap();
        assert_eq!(&bytes[..2], &[0x11, 12]);
        assert_eq!(&bytes[2..6], &Version::V2.wire().to_be_bytes());
        values.original = None;
        values.retry_source = None;
        values.encode(&mut bytes).unwrap();
        assert_eq!(&bytes[2..6], &1u32.to_be_bytes());
    }
}
