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
    pub path: Option<crate::path::Address>,
    pub len: usize,
    pub ecn: Option<crate::ecn::Codepoint>,
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
        ecn: crate::ecn::Codepoint,
        path: Option<crate::path::Address>,
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
        ecn: crate::ecn::Codepoint,
    ) -> impl Future<Output = Result<u64, IoError>>;
}
pub trait Clock {
    fn now(&self) -> u64;
    fn wait_until(&self, deadline: u64) -> impl Future<Output = ()>;
}
