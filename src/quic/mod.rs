//! Direct role-local QUIC connection from the composed global choreography.
//! TLS message order runs in tls::handshake::{global,local}; packet framing,
//! cryptographic arithmetic and recovery bookkeeping remain role-owned data.
//! See the current validation ledger for tested and unqualified scenarios.

pub mod early_data;
pub mod ecn;
pub mod kernel;
pub mod path;
pub mod retry;

mod attach;
pub use attach::Error as AttachmentError;

pub mod application;
pub mod stream;
// Existing import path; the implementation has one canonical stream parts module.
pub use stream::imp as application_stream;
pub mod application_wire;
pub mod early_client;
pub mod early_wire;
pub mod global;
mod idle;
mod initial;
pub mod local;
pub mod parameters;
pub mod recovery;
mod retry_client;
#[cfg(test)]
mod scheduler_tests;
mod timer;
pub mod tls;
mod transcript;
mod wire;

use crate::{
    crypto::{
        self, IntegrityBudget,
        directional::{ApplicationKeyScope, ApplicationReadKeys, ApplicationWriteKeys},
    },
    tls::Level,
    tls::buffer::CryptoBuffer,
    tls::handshake::key_source::{ReceivePacketKey, TransmitPacketKey},
};
use core::{
    cell::{Cell, RefCell},
    future::{Future, poll_fn},
    pin::pin,
    task::{Poll, Waker},
};
use hibana::{
    Endpoint, EndpointError,
    runtime::resolver::{DecisionArm, ResolverError, ResolverRef},
};
use tls::{CryptoFlight, CryptoInput, Finished, Inbox, InboxError, Transcript};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Client,
    Server,
}

#[derive(Clone, Copy)]
pub struct Config<'a> {
    pub initial_path: Option<crate::quic::path::Address>,
    pub local_preferred: Option<crate::quic::path::preferred::Preferred>,
    pub version: crate::quic::kernel::version::Version,
    pub side: Side,
    pub local_connection_id: &'a [u8],
    pub original_destination_id: &'a [u8],
    /// Actual Retry SCID, retained separately from the original destination.
    pub retry_source_id: Option<&'a [u8]>,
    /// Actual server-issued token, repeated in subsequent client Initials.
    pub initial_token: &'a [u8],
    pub peer_connection_id: &'a [u8],
}
impl Config<'_> {
    fn validate(&self) -> Result<(), Error> {
        if self.initial_token.len() > 512
            || self.local_connection_id.len() > 20
            || self.peer_connection_id.len() > 20
            || self.original_destination_id.len() > 20
            || self.retry_source_id.is_some_and(|id| {
                id.is_empty() || id.len() > 20 || id == self.original_destination_id
            })
            || (self.side == Side::Client && self.original_destination_id.len() < 8)
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
}

pub use crate::io::{Clock, DatagramRx, DatagramTx, IoError, ReceivedDatagram};

#[derive(Debug)]
pub enum Error {
    Endpoint(EndpointError),
    Transcript(crate::tls::handshake::local::Error),
    Resolver(ResolverError),
    Crypto(crypto::Error),
    EndpointAt {
        role: u8,
        expected_label: u8,
        error: EndpointError,
    },
    Tls(crate::tls::Error),
    Packet(crate::quic::kernel::packet::Error),
    Reassembly(crate::tls::buffer::Error),
    Recovery(recovery::Error),
    Gate(publication_gate::Error),
    Slot(InboxError),
    Io(IoError),
    Binding,
    Capacity,
    UnsupportedFrame,
    UnsupportedLevel,
    UnexpectedLabel(u8),
}
impl From<EndpointError> for Error {
    fn from(v: EndpointError) -> Self {
        Self::Endpoint(v)
    }
}
impl From<ResolverError> for Error {
    fn from(v: ResolverError) -> Self {
        Self::Resolver(v)
    }
}
impl From<crypto::Error> for Error {
    fn from(v: crypto::Error) -> Self {
        Self::Crypto(v)
    }
}
impl From<crate::tls::Error> for Error {
    fn from(v: crate::tls::Error) -> Self {
        Self::Tls(v)
    }
}
impl From<crate::quic::kernel::packet::Error> for Error {
    fn from(v: crate::quic::kernel::packet::Error) -> Self {
        Self::Packet(v)
    }
}
impl From<crate::tls::buffer::Error> for Error {
    fn from(v: crate::tls::buffer::Error) -> Self {
        Self::Reassembly(v)
    }
}
impl From<recovery::Error> for Error {
    fn from(v: recovery::Error) -> Self {
        Self::Recovery(v)
    }
}
impl From<publication_gate::Error> for Error {
    fn from(v: publication_gate::Error) -> Self {
        Self::Gate(v)
    }
}
impl From<InboxError> for Error {
    fn from(v: InboxError) -> Self {
        Self::Slot(v)
    }
}
impl From<IoError> for Error {
    fn from(v: IoError) -> Self {
        Self::Io(v)
    }
}

/// Only an actual operation result can populate this resolver state. The
/// receiver consumes the declared route, then its owner clears the result.
pub struct Outcome {
    value: Cell<Option<DecisionArm>>,
}
impl Outcome {
    pub const fn new() -> Self {
        Self {
            value: Cell::new(None),
        }
    }
    fn set(&self, accepted: bool) -> Result<(), Error> {
        if self.value.get().is_some() {
            return Err(Error::Binding);
        }
        self.value.set(Some(if accepted {
            DecisionArm::Left
        } else {
            DecisionArm::Right
        }));
        Ok(())
    }
    fn clear(&self) {
        self.value.set(None);
    }
    pub fn resolver<const ID: u16>(&self) -> ResolverRef<'_, ID> {
        ResolverRef::decision_state(self, |state| {
            state.value.get().ok_or_else(ResolverError::reject)
        })
    }
}
impl Default for Outcome {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy)]
pub struct ConnectionId {
    bytes: [u8; 20],
    len: usize,
}
impl ConnectionId {
    pub fn new(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 20 {
            return Err(Error::Capacity);
        }
        let mut id = Self {
            bytes: [0; 20],
            len: bytes.len(),
        };
        id.bytes[..bytes.len()].copy_from_slice(bytes);
        Ok(id)
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

pub use wire::{ReceiveContinuation, ReceiveMaterial, TransmitContinuation};

pub struct Roles<'a> {
    pub rx: Endpoint<'a, { global::RX }>,
    pub tls_rx: Endpoint<'a, { global::TLS_RX }>,
    pub tx: Endpoint<'a, { global::TX }>,
    pub tls_tx: Endpoint<'a, { global::TLS_TX }>,
    pub tls_complete: Endpoint<'a, { global::TLS_COMPLETE }>,
    pub tls_handoff: Endpoint<'a, { global::TLS_HANDOFF }>,
    pub udp: Endpoint<'a, { global::UDP }>,
    pub timer: Endpoint<'a, { global::TIMER }>,
    pub initial_event: Endpoint<'a, { global::INITIAL_EVENT }>,
    pub initial_owner: Endpoint<'a, { global::INITIAL_OWNER }>,
    pub timer_stop: Endpoint<'a, { global::TIMER_STOP }>,
    pub receive_stop: Endpoint<'a, { global::RECEIVE_STOP }>,
    pub timer_tx: Endpoint<'a, { global::TIMER_TX }>,
    pub tx_wire: Endpoint<'a, { global::TX_WIRE }>,
}

struct Schedule {
    revision: Cell<u64>,
    wakers: [RefCell<Option<Waker>>; 4],
}
impl Schedule {
    fn new() -> Self {
        Self {
            revision: Cell::new(0),
            wakers: core::array::from_fn(|_| RefCell::new(None)),
        }
    }
    fn register(&self, lane: usize, waker: &Waker) {
        let next = waker.clone();
        let previous = self.wakers[lane].borrow_mut().replace(next);
        drop(previous);
    }
    fn changed(&self) -> Result<(), Error> {
        self.revision
            .set(self.revision.get().checked_add(1).ok_or(Error::Binding)?);
        for slot in &self.wakers {
            let wake = slot.borrow_mut().take();
            if let Some(wake) = wake {
                wake.wake();
            }
        }
        Ok(())
    }
    async fn wait_changed(&self, lane: usize, observed: u64) {
        poll_fn(|cx| {
            if self.revision.get() != observed {
                return Poll::Ready(());
            }
            self.register(lane, cx.waker());
            if self.revision.get() != observed {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await
    }
}

/// Bounded exchange memory, exclusively borrowed for one handshake operation.
/// Protocol authority belongs to the actual TLS/key owners and Hibana roles;
/// these slots do not mirror their progression with a claimed flag.
///
/// ```compile_fail
/// use hibana_quic::quic::Storage;
/// fn use_slots(_: &mut Storage<'_, '_, 1200, 1>) {}
/// let mut slots = Storage::new(b"peer").unwrap();
/// let first = &mut slots;
/// let second = &mut slots;
/// use_slots(first);
/// use_slots(second); // concurrent exchange ownership is forbidden
/// ```
pub struct Storage<'scope, 'book, const N: usize, const P: usize> {
    peer: RefCell<ConnectionId>,
    schedule: Schedule,
    input: Inbox<CryptoInput<'scope, N>>,
    flight: Inbox<CryptoFlight<N>>,
    read_handshake: Inbox<ReceivePacketKey<'scope>>,
    write_handshake: Inbox<TransmitPacketKey<'scope>>,
    read_application: Inbox<ApplicationReadKeys<'scope>>,
    write_application: Inbox<ApplicationWriteKeys<'scope>>,
    finished: Inbox<Finished<'scope, P>>,
    datagram: Inbox<wire::Datagram<'book, N>>,
    failure: Cell<Option<crate::tls::Error>>,
    early_packets: RefCell<Option<&'book mut dyn early_wire::RetainPackets>>,
    pending_application: RefCell<Option<([u8; N], ReceivedDatagram, u64)>>,
}
impl<'scope, 'book, const N: usize, const P: usize> Storage<'scope, 'book, N, P> {
    pub fn new(peer: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            peer: RefCell::new(ConnectionId::new(peer)?),
            schedule: Schedule::new(),
            input: Inbox::new(),
            flight: Inbox::new(),
            read_handshake: Inbox::new(),
            write_handshake: Inbox::new(),
            read_application: Inbox::new(),
            write_application: Inbox::new(),
            finished: Inbox::new(),
            datagram: Inbox::new(),
            failure: Cell::new(None),
            early_packets: RefCell::new(None),
            pending_application: RefCell::new(None),
        })
    }
    pub fn with_early_packets(
        peer: &[u8],
        packets: &'book mut early_wire::PendingPackets<'_>,
    ) -> Result<Self, Error> {
        let storage = Self::new(peer)?;
        *storage.early_packets.borrow_mut() = Some(packets);
        Ok(storage)
    }
    // Retain ciphertext only. Authentication and frame effects belong to the
    // application receive role after the actual handshake join and key transfer.
    fn retain_application(
        &self,
        packet: &[u8],
        ecn: Option<crate::quic::ecn::Codepoint>,
        path: Option<crate::quic::path::Address>,
        received_at: u64,
    ) -> Result<(), Error> {
        if packet.is_empty() || packet.len() > N {
            return Err(Error::Capacity);
        }
        let mut pending = self.pending_application.borrow_mut();
        if pending.is_none() {
            let mut bytes = [0; N];
            bytes[..packet.len()].copy_from_slice(packet);
            *pending = Some((
                bytes,
                ReceivedDatagram {
                    path,
                    len: packet.len(),
                    ecn,
                },
                received_at,
            ));
        }
        Ok(())
    }
    fn clear(&self) {
        drop(self.input.take());
        drop(self.flight.take());
        drop(self.read_handshake.take());
        drop(self.write_handshake.take());
        drop(self.read_application.take());
        drop(self.write_application.take());
        drop(self.finished.take());
        drop(self.datagram.take());
        self.failure.set(None);
        let _ = self.pending_application.borrow_mut().take();
    }
}
struct Clear<'a, 'scope, 'book, const N: usize, const P: usize>(&'a Storage<'scope, 'book, N, P>);
impl<const N: usize, const P: usize> Drop for Clear<'_, '_, '_, N, P> {
    fn drop(&mut self) {
        self.0.clear();
    }
}

pub use local::handshake;
pub(crate) use local::handshake_with_early;

pub mod publication_gate;

#[cfg(test)]
mod retained_application_tests {
    use super::*;

    #[test]
    fn first_packet_is_owned_and_not_overwritten() {
        let storage = Storage::<8, 1>::new(b"peer").unwrap();
        let mut packet = [1, 2, 3];
        storage.retain_application(&packet, None, None, 10).unwrap();
        packet.fill(9);
        storage.retain_application(&packet, None, None, 99).unwrap();
        let (bytes, len, received_at) = storage.pending_application.borrow_mut().take().unwrap();
        assert_eq!(received_at, 10);
        assert_eq!(&bytes[..len.len], &[1, 2, 3]);
        assert!(storage.pending_application.borrow_mut().take().is_none());
    }
    #[test]
    fn cleanup_preserves_ciphertext_for_owned_transfer() {
        let storage = Storage::<8, 1>::new(b"peer").unwrap();
        storage.retain_application(&[7], None, None, 10).unwrap();
        let (bytes, len, received_at) = storage.pending_application.borrow_mut().take().unwrap();
        storage.clear();
        assert!(storage.pending_application.borrow().is_none());
        assert_eq!(received_at, 10);
        assert_eq!(&bytes[..len.len], &[7]);
    }
    #[test]
    fn failed_or_cancelled_exchange_cannot_leave_retained_input() {
        let storage = Storage::<8, 1>::new(b"peer").unwrap();
        storage.retain_application(&[7], None, None, 10).unwrap();
        drop(Clear(&storage));
        assert!(storage.pending_application.borrow().is_none());
    }
    #[test]
    fn invalid_packet_lengths_do_not_publish_a_buffer() {
        let storage = Storage::<8, 1>::new(b"peer").unwrap();
        assert!(storage.retain_application(&[], None, None, 10).is_err());
        assert!(storage.retain_application(&[1; 9], None, None, 10).is_err());
        assert!(storage.pending_application.borrow().is_none());
    }
}
