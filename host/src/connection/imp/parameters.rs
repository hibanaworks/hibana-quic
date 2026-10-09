use hibana_quic::quic::imp::kernel::packet::encode_varint;
type Result<T> = std::result::Result<T, String>;
pub fn parameters(
    version: hibana_quic::quic::imp::kernel::version::Version,
    local: &[u8],
    original: Option<&[u8]>,
    application_limits: Option<hibana_quic::quic::imp::kernel::streams::Limits>,
    retry_source: Option<&[u8]>,
    idle_timeout_ms: u64,
) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    if version == hibana_quic::quic::imp::kernel::version::Version::V2 {
        let chosen = if original.is_some() {
            version.wire()
        } else {
            1
        };
        bytes.extend_from_slice(&[0x11, 12]);
        bytes.extend_from_slice(&chosen.to_be_bytes());
        bytes.extend_from_slice(&version.wire().to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
    }
    let mut encoded = [0; 8];
    for (kind, value) in [(15, Some(local)), (0, original), (16, retry_source)] {
        if let Some(value) = value {
            let len = encode_varint(kind, &mut encoded).map_err(|e| format!("parameter: {e:?}"))?;
            bytes.extend_from_slice(&encoded[..len]);
            let len = encode_varint(value.len() as u64, &mut encoded)
                .map_err(|e| format!("parameter: {e:?}"))?;
            bytes.extend_from_slice(&encoded[..len]);
            bytes.extend_from_slice(value);
        }
    }
    if let Some(limits) = application_limits {
        // Advertise exactly the windows backed by application_storage.
        for (kind, value) in [
            (1, idle_timeout_ms),
            (3, crate::connection::DATAGRAM as u64),
            (4, limits.max_data),
            (5, limits.stream_data_bidi_local),
            (6, limits.stream_data_bidi_remote),
            (7, limits.stream_data_uni),
            (8, limits.max_streams_bidi),
            (9, limits.max_streams_uni),
        ] {
            let mut value_bytes = [0; 8];
            let value_len = encode_varint(value, &mut value_bytes)
                .map_err(|e| format!("parameter value: {e:?}"))?;
            let len =
                encode_varint(kind, &mut encoded).map_err(|e| format!("parameter kind: {e:?}"))?;
            bytes.extend_from_slice(&encoded[..len]);
            let len = encode_varint(value_len as u64, &mut encoded)
                .map_err(|e| format!("parameter length: {e:?}"))?;
            bytes.extend_from_slice(&encoded[..len]);
            bytes.extend_from_slice(&value_bytes[..value_len]);
        }
    }
    Ok(bytes)
}
