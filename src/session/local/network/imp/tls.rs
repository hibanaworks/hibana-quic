use alloc::{vec, vec::Vec};
use hibana_tls::handshake::Storage as TlsStorage;
pub(crate) struct TlsBuffers {
    rx: Vec<u8>,
    tx: Vec<u8>,
    certificates: Vec<u8>,
    parameters: Vec<u8>,
}
impl TlsBuffers {
    pub(crate) fn new() -> Self {
        Self {
            rx: vec![0; 16384],
            tx: vec![0; 16384],
            certificates: vec![0; 16384],
            parameters: vec![0; super::super::PARAMETERS],
        }
    }
    pub(crate) fn storage(&mut self) -> TlsStorage<'_> {
        TlsStorage {
            rx_message: &mut self.rx,
            tx_flight: &mut self.tx,
            peer_certificates: &mut self.certificates,
            peer_parameters: &mut self.parameters,
        }
    }
}
