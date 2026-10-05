//! A single projected connection from authenticated application admission to
//! bounded stream IO, ordinary retirement, closing and draining.

mod acknowledgments;
mod early;
mod early_client;
mod io;
mod keys;
pub mod protocol;
mod receive;
pub(super) mod reclaim;
mod reset;
mod run;
mod startup;
mod termination;
mod timer;
mod transmit;

pub use run::{client, client_early, server};

use super::{Config, Outcome, application_stream, parameters, recovery};
use crate::{connection::publication_gate, crypto, handshake::CryptoBuffer, packet, streams};
use core::{
    cell::{Cell, RefCell},
    future::{Future, poll_fn},
    pin::pin,
    task::{Poll, Waker},
};
use hibana::{Endpoint, EndpointError};

pub const MAX_REQUEST_BYTES: usize = 1024;
/// Finite workload admission bound, independent of reusable live stream slots.
pub const MAX_REQUESTS: usize = 4096;

/// Reads a response through caller-owned bounded storage. Zero means EOF.
pub trait BodyReader {
    fn read(&mut self, output: &mut [u8]) -> impl Future<Output = Result<usize, ()>>;
}
/// The request is the actual authenticated, FIN-complete HTTP/0.9 request.
pub trait ServerHandler {
    type Body: BodyReader;
    /// A finite application workload, sampled once before receiving requests.
    /// None keeps serving until peer termination. Reaching this count retires
    /// the source; completion still requires real FIN delivery and peer ACKs.
    fn request_limit(&self) -> Option<core::num::NonZeroUsize> {
        None
    }
    fn open(
        &mut self,
        stream_id: u64,
        request: &[u8],
    ) -> impl Future<Output = Result<Self::Body, ()>>;
}
/// A pending request stays pending until exactly one successful `started`.
pub trait ClientRequests {
    fn next(&mut self, output: &mut [u8]) -> impl Future<Output = Result<Option<usize>, ()>>;
    fn started(&mut self, stream_id: u64) -> Result<(), ()>;
}
pub trait StreamSink {
    fn write(&mut self, stream_id: u64, bytes: &[u8]) -> impl Future<Output = Result<(), ()>>;
    fn finish(&mut self, stream_id: u64) -> impl Future<Output = Result<(), ()>>;
}

pub struct Buffers<'a, const RX: usize, const CHUNK: usize> {
    pub streams: &'a mut [streams::StreamSlot<RX>],
    pub chunks: &'a mut [streams::SendChunk<CHUNK>],
    pub references: &'a mut [streams::PacketReference],
    pub crypto: CryptoBuffer<'a>,
}
pub struct EarlyServer<'a, const RX: usize> {
    pub packets: super::early_wire::PendingPackets<'a>,
    pub slots: &'a mut [crate::early_data::QuarantineSlot<RX>],
    pub policy: crate::early_data::ServerPolicy,
}
pub struct Setup<'a, const RX: usize, const CHUNK: usize> {
    /// Opaque server-issued address token, published only after authenticated Finished.
    pub server_token: Option<&'a [u8]>,
    /// Must match the local max_idle_timeout actually advertised in TLS.
    pub local_idle_timeout_ms: u64,
    /// Optional target write generation, reached only after actual ACK and QUIC confirmation. Zero leaves initiation to the peer.
    pub key_update_target: u64,
    pub early: Option<EarlyServer<'a, RX>>,
    pub config: Config<'a>,
    pub local_limits: streams::Limits,
    pub handshake_crypto: [CryptoBuffer<'a>; 2],
    pub application: Buffers<'a, RX, CHUNK>,
}
pub struct Outcomes {
    pub tls: Outcome,
    pub handshake_adapter: Outcome,
    pub application_adapter: Outcome,
    pub application_reset: Outcome,
}
impl Outcomes {
    pub const fn new() -> Self {
        Self {
            tls: Outcome::new(),
            handshake_adapter: Outcome::new(),
            application_adapter: Outcome::new(),
            application_reset: Outcome::new(),
        }
    }
}
impl Default for Outcomes {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Termination {
    Closed,
    IdleExpired,
}
#[derive(Clone, Copy, Debug)]
pub struct Report {
    /// Issued only after all ordinary I/O and key retirement has joined.
    pub termination: Termination,
    /// Actual installed write generation observed before final key retirement.
    pub key_generation: u64,
    pub early_accepted_packets: usize,
    pub early_stream_bytes: u64,
    pub early_finished_streams: usize,
    pub confirmed: bool,
    pub submitted_streams: usize,
    pub completed_streams: usize,
    pub all_streams_acked: bool,
    pub close_completed: bool,
    /// Actual admitted-path datagram bytes before closing starts.
    pub received_bytes: u64,
    /// Actual UDP-accepted datagram bytes before closing starts.
    pub sent_bytes: u64,
}

pub struct Roles<'a> {
    pub handshake: super::Roles<'a>,
    pub source: Endpoint<'a, { protocol::SOURCE }>,
    pub ingress: Endpoint<'a, { protocol::INGRESS }>,
    pub receive: Endpoint<'a, { protocol::RECEIVE }>,
    pub sink: Endpoint<'a, { protocol::SINK }>,
    pub rx_keys: Endpoint<'a, { protocol::RX_KEYS }>,
    pub tx_keys: Endpoint<'a, { protocol::TX_KEYS }>,
    pub clock: Endpoint<'a, { protocol::CLOCK }>,
    pub tx_clock: Endpoint<'a, { protocol::TX_CLOCK }>,
    pub transmit: Endpoint<'a, { protocol::TRANSMIT }>,
    pub adapter: Endpoint<'a, { protocol::ADAPTER }>,
    pub peer_event: Endpoint<'a, { protocol::PEER_EVENT }>,
    pub peer_close: Endpoint<'a, { protocol::PEER_CLOSE }>,
    pub files_event: Endpoint<'a, { protocol::FILES_EVENT }>,
    pub files_close: Endpoint<'a, { protocol::FILES_CLOSE }>,
    pub close_join: Endpoint<'a, { protocol::CLOSE_JOIN }>,
    pub source_collector: Endpoint<'a, { protocol::SOURCE_COLLECTOR }>,
    pub input_collector: Endpoint<'a, { protocol::INPUT_COLLECTOR }>,
    pub delivery_collector: Endpoint<'a, { protocol::DELIVERY_COLLECTOR }>,
}

#[derive(Debug)]
pub enum Error {
    Connection(super::Error),
    Endpoint(EndpointError),
    Recovery(recovery::Error),
    Streams(application_stream::Error),
    Crypto(crypto::Error),
    Packet(packet::Error),
    Parameters(parameters::Error),
    Binding,
    Capacity,
    Application,
    Incomplete,
    KeyControlBinding,
    KeyControlRetired,
    Early(crate::early_data::owner::Failure),
    UnexpectedLabel(u8),
}
impl From<super::Error> for Error {
    fn from(value: super::Error) -> Self {
        Self::Connection(value)
    }
}
impl From<EndpointError> for Error {
    fn from(value: EndpointError) -> Self {
        Self::Endpoint(value)
    }
}
impl From<recovery::Error> for Error {
    fn from(value: recovery::Error) -> Self {
        Self::Recovery(value)
    }
}
impl From<application_stream::Error> for Error {
    fn from(value: application_stream::Error) -> Self {
        Self::Streams(value)
    }
}
impl From<crypto::Error> for Error {
    fn from(value: crypto::Error) -> Self {
        Self::Crypto(value)
    }
}
impl From<packet::Error> for Error {
    fn from(value: packet::Error) -> Self {
        Self::Packet(value)
    }
}
impl From<parameters::Error> for Error {
    fn from(value: parameters::Error) -> Self {
        Self::Parameters(value)
    }
}
impl From<keys::Error> for Error {
    fn from(value: keys::Error) -> Self {
        match value {
            keys::Error::Crypto(error) => Self::Crypto(error),
            keys::Error::Endpoint(error) => Self::Endpoint(error),
            keys::Error::Slot(error) => Self::Connection(super::Error::Slot(error)),
            keys::Error::Binding => Self::KeyControlBinding,
            keys::Error::Retired => Self::KeyControlRetired,
            keys::Error::UnexpectedLabel(label) => Self::UnexpectedLabel(label),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum CloseKind {
    Local { application: bool, code: u64 },
    Peer { code: u64 },
    IdleExpired,
}

/// Readiness and publication cancellation only. Protocol phase ownership belongs
/// to the projected local futures and affine terminal messages.
pub(crate) struct Control<'gate, 'scope> {
    revision: Cell<u64>,
    wakers: [RefCell<Option<Waker>>; 8],
    failed: Cell<bool>,
    protocol_error: RefCell<Option<Error>>,
    stop: RefCell<Option<publication_gate::Stop<'gate, 'scope>>>,
}
impl<'gate, 'scope> Control<'gate, 'scope> {
    pub(crate) fn new(stop: publication_gate::Stop<'gate, 'scope>) -> Self {
        Self {
            revision: Cell::new(0),
            wakers: core::array::from_fn(|_| RefCell::new(None)),
            failed: Cell::new(false),
            protocol_error: RefCell::new(None),
            stop: RefCell::new(Some(stop)),
        }
    }
    // Diagnostic outcome only; this does not choose a protocol continuation.
    pub(crate) fn record_protocol_error(&self, error: Error) {
        let mut first = self.protocol_error.borrow_mut();
        if first.is_none() {
            *first = Some(error);
        }
    }
    pub(crate) fn take_protocol_error(&self) -> Option<Error> {
        self.protocol_error.borrow_mut().take()
    }
    pub(crate) fn stopping(&self) -> bool {
        self.stop.borrow().is_none()
    }
    pub(crate) fn revision(&self) -> u64 {
        self.revision.get()
    }
    pub(crate) fn failed(&self) -> bool {
        self.failed.get()
    }
    pub(crate) fn changed(&self) -> Result<(), Error> {
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
    fn register(&self, lane: usize, waker: &Waker) {
        let new = waker.clone();
        let old = self.wakers[lane].borrow_mut().replace(new);
        drop(old);
    }
    pub(crate) async fn wait(&self, lane: usize, revision: u64) {
        poll_fn(|cx| {
            if self.revision() != revision || self.stopping() {
                return Poll::Ready(());
            }
            self.register(lane, cx.waker());
            if self.revision() != revision || self.stopping() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await
    }
    pub(crate) async fn until_stop<F: Future>(&self, lane: usize, future: F) -> Option<F::Output> {
        let mut future = pin!(future);
        poll_fn(|cx| {
            if self.stopping() {
                return Poll::Ready(None);
            }
            self.register(lane, cx.waker());
            if self.stopping() {
                return Poll::Ready(None);
            }
            future.as_mut().poll(cx).map(Some)
        })
        .await
    }
    pub(crate) fn revoke(&self) -> Result<(), Error> {
        let stop = self.stop.borrow_mut().take();
        if let Some(stop) = stop {
            stop.revoke();
        }
        self.changed()
    }
    pub(crate) fn fail(&self) -> Result<(), Error> {
        self.failed.set(true);
        self.changed()
    }
}

/// Minted privately only after every ordinary projected role has retired.
pub struct OrdinaryRetired<'scope> {
    scope: &'scope crypto::directional::ApplicationKeyScope,
}
impl<'scope> OrdinaryRetired<'scope> {
    pub(crate) fn scope(&self) -> &'scope crypto::directional::ApplicationKeyScope {
        self.scope
    }
}

impl From<crate::early_data::owner::Failure> for Error {
    fn from(value: crate::early_data::owner::Failure) -> Self {
        Self::Early(value)
    }
}
