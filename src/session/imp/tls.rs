use hibana_tls::handshake::Storage as TlsStorage;
pub(crate) struct TlsBuffers {
    rx: [u8; 16384],
    tx: [u8; 16384],
    certificates: [u8; 16384],
    parameters: [u8; crate::session::PARAMETERS],
}
impl TlsBuffers {
    pub(crate) fn new() -> Self {
        Self {
            rx: [0; 16384],
            tx: [0; 16384],
            certificates: [0; 16384],
            parameters: [0; crate::session::PARAMETERS],
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
