//! Connection datagram admission and acceptance accounting over physical I/O.
use crate::io::{Address, Codepoint};
use crate::io::{Clock, DatagramRx, DatagramSocket, DatagramTx, IoError};
use core::cell::Cell;
#[derive(Default)]
pub struct Statistics {
    pub sent: Cell<u64>,
    pub received: Cell<u64>,
    pub foreign: Cell<u64>,
    pub last_accepted: Cell<Option<u64>>,
}
pub struct Receive<'a, 'storage, S, const N: usize> {
    pub alternate: Option<(&'a S, &'a mut [u8])>,
    pub socket: &'a S,
    pub address: Address,
    pub first: Option<(&'a [u8], Option<Codepoint>)>,
    pub routed: Option<&'a mut crate::quic::imp::receive_routes::Receiver<'storage, N>>,
    pub statistics: &'a Statistics,
}
impl<S: DatagramSocket, const N: usize> DatagramRx for Receive<'_, '_, S, N> {
    async fn receive(
        &mut self,
        bytes: &mut [u8],
    ) -> Result<crate::quic::ReceivedDatagram, IoError> {
        if let Some((first, ecn)) = self.first.take() {
            if first.len() > bytes.len() {
                return Err(IoError::Rejected);
            }
            bytes[..first.len()].copy_from_slice(first);
            self.statistics
                .received
                .set(self.statistics.received.get() + 1);
            return Ok(crate::quic::ReceivedDatagram {
                path: Some(self.address),
                len: first.len(),
                ecn,
            });
        }
        if let Some(route) = self.routed.as_mut() {
            let packet = route.receive(bytes).await.map_err(|error| match error {
                crate::quic::imp::receive_routes::Error::Capacity => IoError::Rejected,
                _ => IoError::Closed,
            })?;
            self.statistics
                .received
                .set(self.statistics.received.get() + 1);
            return Ok(packet);
        }
        {
            let physical = if let Some((alternate, storage)) = self.alternate.as_mut() {
                match crate::runtime::select(
                    alternate.receive_from(storage),
                    self.socket.receive_from(bytes),
                )
                .await
                {
                    core::ops::ControlFlow::Continue(result) => result,
                    core::ops::ControlFlow::Break(result) => {
                        if let Ok(ref packet) = result {
                            if packet.len > bytes.len() || packet.len > storage.len() {
                                return Err(IoError::Rejected);
                            }
                            bytes[..packet.len].copy_from_slice(&storage[..packet.len]);
                        }
                        result
                    }
                }
            } else {
                self.socket.receive_from(bytes).await
            };
            let received = physical?;
            if received.len > bytes.len() {
                return Err(IoError::Rejected);
            }
            if received.path.is_some_and(|path| path != self.address) {
                self.statistics
                    .foreign
                    .set(self.statistics.foreign.get() + 1);
            }
            self.statistics
                .received
                .set(self.statistics.received.get() + 1);
            Ok(received)
        }
    }
}
pub struct Transmit<'a, S, C> {
    pub alternate: Option<&'a S>,
    pub socket: &'a S,
    pub address: Address,
    pub clock: &'a C,
    pub statistics: &'a Statistics,
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
        let path = path.unwrap_or(self.address);
        let socket = if let Some(alternate) = self.alternate {
            let bound = alternate.local_address()?;
            if bound == path.local
                || (bound.ip().is_unspecified()
                    && bound.port() == path.local.port()
                    && bound.is_ipv4() == path.local.is_ipv4())
            {
                alternate
            } else {
                self.socket
            }
        } else {
            self.socket
        };
        match socket.send_to_path(bytes, path, ecn).await {
            Ok(len) if len == bytes.len() => {
                let at = self.clock.now();
                self.statistics.sent.set(self.statistics.sent.get() + 1);
                self.statistics.last_accepted.set(Some(at));
                Ok(at)
            }
            Ok(_) => Err(IoError::Rejected),
            Err(error) => Err(error),
        }
    }
}
