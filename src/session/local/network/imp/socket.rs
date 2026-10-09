//! Borrowed physical datagram capabilities used by a single connection.
use crate::io::{Clock, DatagramRx, DatagramSocket, DatagramTx, IoError, ReceivedDatagram};
use crate::quic::{ecn::imp::Codepoint, path::Address};
pub(in crate::session::local::network) struct Receive<'a, S> {
    pub socket: &'a S,
    pub address: Address,
    pub first: Option<(&'a [u8], Option<Codepoint>)>,
}
impl<S: DatagramSocket> DatagramRx for Receive<'_, S> {
    async fn receive(&mut self, bytes: &mut [u8]) -> Result<ReceivedDatagram, IoError> {
        if let Some((first, ecn)) = self.first.take() {
            bytes
                .get_mut(..first.len())
                .ok_or(IoError::Rejected)?
                .copy_from_slice(first);
            return Ok(ReceivedDatagram {
                path: Some(self.address),
                len: first.len(),
                ecn,
            });
        }
        self.socket.receive_from(bytes).await
    }
}
pub(in crate::session::local::network) struct Transmit<'a, S, C> {
    pub socket: &'a S,
    pub address: Address,
    pub clock: &'a C,
}
impl<S: DatagramSocket, C: Clock> DatagramTx for Transmit<'_, S, C> {
    async fn send(&mut self, bytes: &[u8], ecn: Codepoint) -> Result<u64, IoError> {
        self.send_on_path(bytes, ecn, Some(self.address)).await
    }
    async fn send_on_path(
        &mut self,
        bytes: &[u8],
        ecn: Codepoint,
        path: Option<Address>,
    ) -> Result<u64, IoError> {
        if ecn == Codepoint::Ce {
            return Err(IoError::Rejected);
        }
        let count = self
            .socket
            .send_to_path(bytes, path.unwrap_or(self.address), ecn)
            .await?;
        if count != bytes.len() {
            return Err(IoError::Rejected);
        }
        Ok(self.clock.now())
    }
}
