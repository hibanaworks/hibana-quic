//! Executor-neutral physical I/O contracts. No protocol progression lives here.
use core::future::Future;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoError {
    Rejected,
    Closed,
}
/// The adapter is bound to this connection's admitted peer/path. Arbitrary
/// socket-source datagrams must be filtered before returning their byte count.
/// Physical metadata returned with the exact received datagram. Missing ECN
/// metadata is not evidence of Not-ECT. Authentication still precedes counting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceivedDatagram {
    pub path: Option<crate::quic::path::Address>,
    pub len: usize,
    pub ecn: Option<crate::quic::ecn::imp::Codepoint>,
}
pub trait DatagramRx {
    fn receive(
        &mut self,
        bytes: &mut [u8],
    ) -> impl Future<Output = Result<ReceivedDatagram, IoError>>;
}
/// Success is the actual monotonic microsecond timestamp of UDP acceptance.
/// A pending or dropped future must not have accepted this datagram.
pub trait DatagramTx {
    fn send_on_path(
        &mut self,
        bytes: &[u8],
        ecn: crate::quic::ecn::imp::Codepoint,
        path: Option<crate::quic::path::Address>,
    ) -> impl Future<Output = Result<u64, IoError>> {
        async move {
            if path.is_some() {
                Err(IoError::Rejected)
            } else {
                self.send(bytes, ecn).await
            }
        }
    }
    fn send(
        &mut self,
        bytes: &[u8],
        ecn: crate::quic::ecn::imp::Codepoint,
    ) -> impl Future<Output = Result<u64, IoError>>;
}
pub trait Clock {
    fn now(&self) -> u64;
    fn wait_until(&self, deadline: u64) -> impl Future<Output = ()>;
}

/// Caller-owned random-access storage. Reads and writes complete in this call;
/// each operation must either transfer its entire slice or return an error.
/// The implementation provides interior access to one underlying byte store.
pub trait RandomAccess {
    fn len(&self) -> Result<u64, IoError>;
    fn is_empty(&self) -> Result<bool, IoError> {
        self.len().map(|n| n == 0)
    }
    fn read_exact_at(&self, bytes: &mut [u8], offset: u64) -> Result<(), IoError>;
    fn write_all_at(&self, bytes: &[u8], offset: u64) -> Result<(), IoError>;
    fn set_len(&self, length: u64) -> Result<(), IoError>;
}

/// Unconnected UDP access for server admission, before peer binding.
/// Receive returns the actual source and destination path with the datagram.
pub trait DatagramSocket {
    fn receive_from(
        &self,
        bytes: &mut [u8],
    ) -> impl Future<Output = Result<ReceivedDatagram, IoError>>;
    fn send_to_path(
        &self,
        bytes: &[u8],
        path: crate::quic::path::Address,
        ecn: crate::quic::ecn::imp::Codepoint,
    ) -> impl Future<Output = Result<usize, IoError>>;
}
