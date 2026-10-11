//! Bounded HTTP stream storage attached to QUIC's actual byte grants.
use crate::quic::application::{BodyReader, StreamSink};
use crate::runtime::byte_pipe::{Reader, Writer};
use core::task::{Context, Poll};

impl BodyReader for Reader<'_, '_> {
    async fn read(&mut self, output: &mut [u8]) -> Result<usize, ()> {
        Reader::read(self, output).await.map_err(|_| ())
    }
}
impl crate::http3::message::localside::writer::BodyWriter for Writer<'_, '_> {
    async fn write(&mut self, mut bytes: &[u8]) -> Result<(), ()> {
        while !bytes.is_empty() {
            let count = Writer::write(self, bytes).await.map_err(|_| ())?;
            if count == 0 {
                return Err(());
            }
            bytes = &bytes[count..];
        }
        Ok(())
    }
    async fn finish(&mut self) -> Result<(), ()> {
        Writer::finish(self).map_err(|_| ())
    }
}

/// Owns exactly the receive grant for the selected request stream.
pub(crate) struct Incoming<'pipe, 'storage> {
    pub writer: Writer<'pipe, 'storage>,
    pub stream: u64,
}
impl StreamSink for Incoming<'_, '_> {
    fn poll_write(
        &mut self,
        stream: u64,
        bytes: &[u8],
        cx: &mut Context<'_>,
    ) -> Poll<Result<usize, ()>> {
        if stream != self.stream {
            return Poll::Ready(Err(()));
        }
        self.writer
            .poll_write(bytes, cx)
            .map(|result| result.map_err(|_| ()))
    }
    async fn finish(&mut self, stream: u64) -> Result<(), ()> {
        if stream != self.stream {
            return Err(());
        }
        self.writer.finish().map_err(|_| ())
    }
}
