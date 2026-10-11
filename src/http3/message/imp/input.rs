//! Bounded stream reads. Frame order is owned by the reader localside.
use super::super::{Error, Result};
use crate::http3::{self, Fields, FrameHeader};
use crate::quic::application::BodyReader;

pub(in crate::http3) async fn exact(
    reader: &mut impl BodyReader,
    mut output: &mut [u8],
) -> Result<()> {
    let mut reads = 0;
    while !output.is_empty() {
        let count = reader
            .read(output)
            .await
            .map_err(|_| Error::Invalid("HTTP/3 input failed"))?;
        if count == 0 {
            return Err("truncated HTTP/3 input".into());
        }
        if count > output.len() {
            return Err("HTTP/3 input exceeded its buffer".into());
        }
        output = &mut output[count..];
        reads += 1;
        if reads == 16 && !output.is_empty() {
            crate::runtime::yield_now().await;
            reads = 0;
        }
    }
    Ok(())
}
async fn integer(reader: &mut impl BodyReader, first: u8) -> Result<(u64, usize)> {
    let mut bytes = [0; 8];
    bytes[0] = first;
    let count = 1usize << (first >> 6);
    exact(reader, &mut bytes[1..count]).await?;
    let value = crate::quic::imp::kernel::packet::decode_varint(&bytes[..count])
        .map_err(Error::from)?
        .0;
    Ok((value, count))
}
pub(in crate::http3) async fn next(reader: &mut impl BodyReader) -> Result<Option<FrameHeader>> {
    // A peer may send arbitrarily many empty extension frames.
    crate::runtime::yield_now().await;
    let mut first = [0];
    match reader
        .read(&mut first)
        .await
        .map_err(|_| Error::Invalid("HTTP/3 input failed"))?
    {
        0 => return Ok(None),
        1 => {}
        _ => return Err("HTTP/3 input exceeded its buffer".into()),
    }
    let (kind, a) = integer(reader, first[0]).await?;
    exact(reader, &mut first).await?;
    let (length, b) = integer(reader, first[0]).await?;
    if matches!(kind, 2 | 6 | 8 | 9) {
        return Err("reserved HTTP/2 frame on HTTP/3 stream".into());
    }
    Ok(Some(FrameHeader {
        kind,
        length,
        encoded_len: a + b,
    }))
}
pub(in crate::http3) async fn fields(
    reader: &mut impl BodyReader,
    length: u64,
    storage: &mut [u8],
) -> Result<(Fields, usize)> {
    let length = usize::try_from(length).map_err(Error::from)?;
    if length > http3::FIELD_LIMIT {
        return Err("HTTP/3 field section exceeds bounded storage".into());
    }
    let output = storage
        .get_mut(..length)
        .ok_or("HTTP/3 field section exceeds supplied storage")?;
    exact(reader, output).await?;
    Ok((http3::decode_fields(output).map_err(Error::from)?, length))
}
pub(in crate::http3) async fn skip(reader: &mut impl BodyReader, mut length: u64) -> Result<()> {
    let mut bytes = [0; 256];
    let mut chunks = 0;
    while length != 0 {
        let count = length.min(bytes.len() as u64) as usize;
        exact(reader, &mut bytes[..count]).await?;
        length -= count as u64;
        chunks += 1;
        if chunks == 16 && length != 0 {
            crate::runtime::yield_now().await;
            chunks = 0;
        }
    }
    Ok(())
}

/// Sequential view of already-owned storage, used by the in-place download path.
/// The exact FIN-complete extent belongs to the caller; no protocol phase is stored.
pub(in crate::http3) struct Stored<'a, F> {
    file: &'a F,
    offset: u64,
    extent: u64,
}
impl<'a, F: crate::io::RandomAccess> Stored<'a, F> {
    pub(in crate::http3) fn new(file: &'a F) -> Result<Self> {
        Ok(Self {
            file,
            offset: 0,
            extent: file.len().map_err(Error::from)?,
        })
    }
}
impl<F: crate::io::RandomAccess> BodyReader for Stored<'_, F> {
    async fn read(&mut self, output: &mut [u8]) -> core::result::Result<usize, ()> {
        let count = (self.extent - self.offset).min(output.len() as u64) as usize;
        if count == 0 {
            return Ok(0);
        }
        self.file
            .read_exact_at(&mut output[..count], self.offset)
            .map_err(|_| ())?;
        self.offset += count as u64;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };
    struct Fragmented<'a> {
        bytes: &'a [u8],
        limit: usize,
    }
    impl BodyReader for Fragmented<'_> {
        async fn read(&mut self, output: &mut [u8]) -> core::result::Result<usize, ()> {
            crate::runtime::yield_now().await;
            let n = self.limit.min(output.len()).min(self.bytes.len());
            output[..n].copy_from_slice(&self.bytes[..n]);
            self.bytes = &self.bytes[n..];
            Ok(n)
        }
    }
    fn run<T>(future: impl Future<Output = T>) -> T {
        let mut future = pin!(future);
        let mut context = Context::from_waker(Waker::noop());
        for _ in 0..100_000 {
            if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
                return value;
            }
        }
        panic!("bounded fragmented read failed to complete")
    }
    #[test]
    fn fragmented_varints_and_large_frame_contents_use_bounded_storage() {
        let mut encoded = [0; 16];
        let n = http3::frame_header(0x1ffff, 32768, &mut encoded).unwrap();
        for limit in 1..=8 {
            let mut reader = Fragmented {
                bytes: &encoded[..n],
                limit,
            };
            let frame = run(next(&mut reader)).unwrap().unwrap();
            assert_eq!((frame.kind, frame.length), (0x1ffff, 32768));
            assert!(run(next(&mut reader)).unwrap().is_none());
        }
        let body = [0x5a; 32768];
        let mut reader = Fragmented {
            bytes: &body,
            limit: 7,
        };
        run(skip(&mut reader, 32768)).unwrap();
        assert!(reader.bytes.is_empty());
    }
    #[test]
    fn truncated_integer_content_and_headers_fail_at_the_actual_end() {
        let mut encoded = [0; 16];
        let n = http3::frame_header(0x1ffff, 32768, &mut encoded).unwrap();
        for end in 1..n {
            let mut reader = Fragmented {
                bytes: &encoded[..end],
                limit: 1,
            };
            assert!(run(next(&mut reader)).is_err());
        }
        let mut reader = Fragmented {
            bytes: &[1, 2, 3],
            limit: 1,
        };
        assert!(run(skip(&mut reader, 4)).is_err());
        let mut reader = Fragmented {
            bytes: &[0, 0, 0xd9],
            limit: 1,
        };
        assert_eq!(
            run(fields(&mut reader, 3, &mut [0; 8])).unwrap().0.status,
            Some(200)
        );
        let mut reader = Fragmented {
            bytes: &[0, 0],
            limit: 1,
        };
        assert!(run(fields(&mut reader, 3, &mut [0; 8])).is_err());
    }
}
