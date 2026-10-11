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
    pub path: Option<crate::io::Address>,
    pub len: usize,
    pub ecn: Option<crate::io::Codepoint>,
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
        ecn: crate::io::Codepoint,
        path: Option<crate::io::Address>,
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
        ecn: crate::io::Codepoint,
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
    /// Actual bound local address of this socket.
    fn local_address(&self) -> Result<core::net::SocketAddr, IoError>;
    fn receive_from(
        &self,
        bytes: &mut [u8],
    ) -> impl Future<Output = Result<ReceivedDatagram, IoError>>;
    fn send_to_path(
        &self,
        bytes: &[u8],
        path: crate::io::Address,
        ecn: crate::io::Codepoint,
    ) -> impl Future<Output = Result<usize, IoError>>;
}

use core::net::SocketAddr;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Address {
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Codepoint {
    NotEct = 0,
    Ect1 = 1,
    Ect0 = 2,
    Ce = 3,
}
impl Codepoint {
    /// The upper six bits are DSCP, not ECN.
    pub const fn from_ip_tos(tos: u8) -> Self {
        match tos & 3 {
            0 => Self::NotEct,
            1 => Self::Ect1,
            2 => Self::Ect0,
            _ => Self::Ce,
        }
    }
    pub const fn bits(self) -> u8 {
        self as u8
    }
}
