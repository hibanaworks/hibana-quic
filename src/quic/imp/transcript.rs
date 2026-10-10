//! CRYPTO offsets and borrowed TLS material.
use crate::quic::*;
use hibana_tls::handshake::keys::KeySource;
pub(in crate::quic) struct Numbers<'source, 'scope, 'cfg, 'buf> {
    pub(in crate::quic) source: RefCell<&'source mut KeySource<'scope, 'cfg, 'buf>>,
    sent: RefCell<&'source mut [u64; 3]>,
    received: RefCell<&'source mut [u64; 3]>,
}
impl<'source, 'scope, 'cfg, 'buf> Numbers<'source, 'scope, 'cfg, 'buf> {
    pub fn new(source: &'source mut Transcript<'scope, 'cfg, 'buf>) -> Self {
        Self {
            source: RefCell::new(&mut source.source),
            sent: RefCell::new(&mut source.sent),
            received: RefCell::new(&mut source.received),
        }
    }
    pub(in crate::quic) fn transmit<const N: usize>(
        &self,
    ) -> Result<Option<CryptoFlight<N>>, hibana_tls::quic::Error> {
        let mut source = self.source.borrow_mut();
        if source.last_failure().is_some() {
            return Err(hibana_tls::quic::Error::Handshake);
        }
        let mut bytes = [0; N];
        let Some(output) = source.transmit(&mut bytes)? else {
            return Ok(None);
        };
        if output.len == 0 || output.len > N {
            return Err(hibana_tls::quic::Error::InvalidInput);
        }
        let index = crate::quic::imp::tls::level_index(output.level);
        let mut sent = self.sent.borrow_mut();
        let offset = sent[index];
        sent[index] = crate::quic::imp::tls::range_end(offset, output.len)?;
        Ok(Some(CryptoFlight {
            level: output.level,
            offset,
            bytes,
            len: output.len,
        }))
    }
    pub(in crate::quic) fn record_verified_consumed(
        &self,
        consumed: [u64; 2],
    ) -> Result<(), Error> {
        let mut received = self.received.borrow_mut();
        for (index, end) in consumed.into_iter().enumerate() {
            if end < received[index] || end > crate::quic::imp::kernel::packet::MAX_VARINT {
                return Err(hibana_tls::quic::Error::InvalidInput.into());
            }
            received[index] = end;
        }
        Ok(())
    }
    pub(in crate::quic) fn restore_buffer(&self, bytes: &'buf mut [u8]) -> Result<(), Error> {
        self.source
            .borrow_mut()
            .restore_message_buffer(bytes)
            .map_err(Error::from)
    }
}
