//! Encoding for authenticated 0-RTT controls retained until Finished.
use crate::quic::imp::kernel::packet::{self, EncryptionLevel, Frame, FrameIter, ParseLimits};

/// Write non-STREAM controls directly into the uncommitted tail of quarantine.
/// The caller advances its retained length only on success. An error may leave
/// bytes in that unused tail, but never makes them eligible for delivery.
pub(in crate::quic::early_data) fn retain_control(
    plaintext: &[u8],
    output: &mut [u8],
) -> Result<usize, packet::Error> {
    let mut len = 0;
    for frame in FrameIter::new(
        plaintext,
        EncryptionLevel::ZeroRtt,
        ParseLimits {
            max_frames: 128,
            ..ParseLimits::default()
        },
    )? {
        let frame = frame?;
        if matches!(
            frame,
            Frame::Stream { .. } | Frame::Ping | Frame::Padding { .. }
        ) {
            continue;
        }
        len += packet::encode_frame(&frame, &mut output[len..])?;
    }
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retains_controls_without_copying_stream_payload() {
        let mut input = [0; 64];
        let mut len = packet::encode_frame(&Frame::Ping, &mut input).unwrap();
        len += packet::encode_frame(
            &Frame::Stream {
                id: 0,
                offset: 0,
                fin: false,
                data: b"payload",
            },
            &mut input[len..],
        )
        .unwrap();
        len += packet::encode_frame(&Frame::MaxData { maximum: 4096 }, &mut input[len..]).unwrap();
        let mut output = [0; 64];
        let written = retain_control(&input[..len], &mut output).unwrap();
        let mut expected = [0; 64];
        let expected_len =
            packet::encode_frame(&Frame::MaxData { maximum: 4096 }, &mut expected).unwrap();
        assert_eq!(&output[..written], &expected[..expected_len]);
        assert_eq!(
            retain_control(&input[..len], &mut []),
            Err(packet::Error::BufferTooShort)
        );
    }
}
