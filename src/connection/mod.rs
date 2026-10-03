//! Direct role-local QUIC connection continuation.
//! APPROXIMATE SOURCE RECOVERY after executor replacement, 2026-10-03.
//! This reconstructs the historical handshake orchestration from retained API
//! and control-flow descriptions. It has not been compiled or tested. The
//! reconstructed and subsequent implementation requires fresh compilation and tests.

pub mod protocol;
pub mod tls;
pub mod recovery;
pub mod application_wire;
pub mod parameters;
pub mod application_stream;
pub mod application;
mod initial;
mod locals;
mod transcript;
mod timer;
mod wire;
#[cfg(test)] mod scheduler_tests;

use core::{cell::{Cell, RefCell}, future::{Future, poll_fn}, pin::pin, task::{Poll, Waker}};
use hibana::{Endpoint, EndpointError, runtime::resolver::{DecisionArm, ResolverError, ResolverRef}};
use crate::{crypto::{self, IntegrityBudget, directional::{ApplicationKeyScope, ApplicationReadKeys, ApplicationWriteKeys}},
    bounded_tls::key_source::{ReceivePacketKey, TransmitPacketKey}, handshake::CryptoBuffer,
    roles::publication_gate, tls::Level};
use tls::{Transcript, CryptoInput, CryptoFlight, Finished, Inbox, InboxError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side { Client, Server }

#[derive(Clone, Copy)]
pub struct Config<'a> {
    pub side: Side,
    pub local_connection_id: &'a [u8],
    pub original_destination_id: &'a [u8],
    pub peer_connection_id: &'a [u8],
}
impl Config<'_> {
    fn validate(&self) -> Result<(), Error> {
        if self.local_connection_id.len() > 20 || self.peer_connection_id.len() > 20
            || self.original_destination_id.len() > 20
            || (self.side == Side::Client && self.original_destination_id.len() < 8) {
            return Err(Error::Binding);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoError { Rejected, Closed }
/// The adapter is bound to this connection's admitted peer/path. Arbitrary
/// socket-source datagrams must be filtered before returning their byte count.
pub trait DatagramRx {
    fn receive(&mut self, bytes: &mut [u8]) -> impl Future<Output = Result<usize, IoError>>;
}
/// Success is the actual monotonic microsecond timestamp of UDP acceptance.
/// A pending or dropped future must not have accepted this datagram.
pub trait DatagramTx {
    fn send(&mut self, bytes: &[u8]) -> impl Future<Output = Result<u64, IoError>>;
}
pub trait Clock {
    fn now(&self) -> u64;
    fn wait_until(&self, deadline: u64) -> impl Future<Output = ()>;
}

#[derive(Debug)]
pub enum Error {
    Endpoint(EndpointError), Resolver(ResolverError), Crypto(crypto::Error),
    Tls(crate::tls::Error), Packet(crate::packet::Error),
    Reassembly(crate::handshake::Error), Recovery(recovery::Error),
    Gate(publication_gate::Error), Slot(InboxError), Io(IoError),
    Binding, Capacity, UnsupportedFrame, UnsupportedLevel, UnexpectedLabel(u8),
}
impl From<EndpointError> for Error { fn from(v: EndpointError) -> Self { Self::Endpoint(v) } }
impl From<ResolverError> for Error { fn from(v: ResolverError) -> Self { Self::Resolver(v) } }
impl From<crypto::Error> for Error { fn from(v: crypto::Error) -> Self { Self::Crypto(v) } }
impl From<crate::tls::Error> for Error { fn from(v: crate::tls::Error) -> Self { Self::Tls(v) } }
impl From<crate::packet::Error> for Error { fn from(v: crate::packet::Error) -> Self { Self::Packet(v) } }
impl From<crate::handshake::Error> for Error { fn from(v: crate::handshake::Error) -> Self { Self::Reassembly(v) } }
impl From<recovery::Error> for Error { fn from(v: recovery::Error) -> Self { Self::Recovery(v) } }
impl From<publication_gate::Error> for Error { fn from(v: publication_gate::Error) -> Self { Self::Gate(v) } }
impl From<InboxError> for Error { fn from(v: InboxError) -> Self { Self::Slot(v) } }
impl From<IoError> for Error { fn from(v: IoError) -> Self { Self::Io(v) } }

/// Only an actual operation result can populate this resolver state. The
/// receiver consumes the declared route, then its owner clears the result.
pub struct Outcome { value: Cell<Option<DecisionArm>> }
impl Outcome {
    pub const fn new() -> Self { Self { value: Cell::new(None) } }
    fn set(&self, accepted: bool) -> Result<(), Error> {
        if self.value.get().is_some() { return Err(Error::Binding); }
        self.value.set(Some(if accepted { DecisionArm::Left } else { DecisionArm::Right }));
        Ok(())
    }
    fn clear(&self) { self.value.set(None); }
    pub fn resolver<const ID: u16>(&self) -> ResolverRef<'_, ID> {
        ResolverRef::decision_state(self, |state| state.value.get().ok_or_else(ResolverError::reject))
    }
}
impl Default for Outcome { fn default() -> Self { Self::new() } }

#[derive(Clone, Copy)]
pub struct ConnectionId { bytes: [u8; 20], len: usize }
impl ConnectionId {
    pub fn new(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 20 { return Err(Error::Capacity); }
        let mut id = Self { bytes: [0; 20], len: bytes.len() };
        id.bytes[..bytes.len()].copy_from_slice(bytes); Ok(id)
    }
    pub fn bytes(&self) -> &[u8] { &self.bytes[..self.len] }
}

pub use wire::{ReceiveContinuation, ReceiveMaterial, TransmitContinuation};

pub struct Roles<'a> {
    pub rx: Endpoint<'a, {protocol::RX}>, pub tls_rx: Endpoint<'a, {protocol::TLS_RX}>,
    pub tx: Endpoint<'a, {protocol::TX}>, pub tls_tx: Endpoint<'a, {protocol::TLS_TX}>,
    pub udp: Endpoint<'a, {protocol::UDP}>, pub timer: Endpoint<'a, {protocol::TIMER}>,
    pub initial_event: Endpoint<'a, {protocol::INITIAL_EVENT}>, pub initial_owner: Endpoint<'a, {protocol::INITIAL_OWNER}>,
    pub timer_tx: Endpoint<'a, {protocol::TIMER_TX}>, pub tx_wire: Endpoint<'a, {protocol::TX_WIRE}>,
}

struct Schedule {
    revision: Cell<u64>, wakers: [RefCell<Option<Waker>>; 4],
    stop_timer: Cell<bool>, transmit_done: Cell<bool>,
    keys: Cell<[bool; 2]>,
}
impl Schedule {
    fn new() -> Self {
        Self { revision: Cell::new(0), wakers: core::array::from_fn(|_| RefCell::new(None)),
            stop_timer: Cell::new(false), transmit_done: Cell::new(false), keys: Cell::new([true, false]) }
    }
    fn register(&self, lane: usize, waker: &Waker) {
        let next = waker.clone();
        let previous = self.wakers[lane].borrow_mut().replace(next);
        drop(previous);
    }
    fn changed(&self) -> Result<(), Error> {
        self.revision.set(self.revision.get().checked_add(1).ok_or(Error::Binding)?);
        for slot in &self.wakers {
            let wake = slot.borrow_mut().take();
            if let Some(wake) = wake { wake.wake(); }
        }
        Ok(())
    }
    async fn wait_changed(&self, lane: usize, observed: u64) {
        poll_fn(|cx| {
            if self.revision.get() != observed { return Poll::Ready(()); }
            self.register(lane, cx.waker());
            if self.revision.get() != observed { Poll::Ready(()) } else { Poll::Pending }
        }).await
    }
}

pub struct Storage<'scope, 'book, const N: usize, const P: usize> {
    claimed: Cell<bool>, peer: RefCell<ConnectionId>, schedule: Schedule,
    input: Inbox<CryptoInput<'scope, N>>, flight: Inbox<CryptoFlight<N>>,
    read_handshake: Inbox<ReceivePacketKey<'scope>>, write_handshake: Inbox<TransmitPacketKey<'scope>>,
    read_application: Inbox<ApplicationReadKeys<'scope>>, write_application: Inbox<ApplicationWriteKeys<'scope>>,
    finished: Inbox<Finished<'scope, P>>, datagram: Inbox<wire::Datagram<'book, N>>,
    failure: Cell<Option<crate::tls::Error>>,
}
impl<'scope, 'book, const N: usize, const P: usize> Storage<'scope, 'book, N, P> {
    pub fn new(peer: &[u8]) -> Result<Self, Error> {
        Ok(Self { claimed: Cell::new(false), peer: RefCell::new(ConnectionId::new(peer)?), schedule: Schedule::new(),
            input: Inbox::new(), flight: Inbox::new(), read_handshake: Inbox::new(), write_handshake: Inbox::new(),
            read_application: Inbox::new(), write_application: Inbox::new(), finished: Inbox::new(), datagram: Inbox::new(), failure: Cell::new(None) })
    }
    fn claim(&self) -> Result<(), Error> {
        if self.claimed.replace(true) { Err(Error::Binding) } else { Ok(()) }
    }
    fn clear(&self) {
        drop(self.input.take()); drop(self.flight.take()); drop(self.read_handshake.take());
        drop(self.write_handshake.take()); drop(self.read_application.take()); drop(self.write_application.take());
        drop(self.finished.take()); drop(self.datagram.take()); self.failure.set(None);
    }
}
struct Clear<'a, 'scope, 'book, const N: usize, const P: usize>(&'a Storage<'scope, 'book, N, P>);
impl<const N: usize, const P: usize> Drop for Clear<'_, '_, '_, N, P> { fn drop(&mut self) { self.0.clear(); } }

#[allow(clippy::too_many_arguments)]
pub async fn handshake<'scope, 'book, const N: usize, const P: usize>(
    roles: &mut Roles<'_>, source: &mut Transcript<'scope, '_, '_>, config: Config<'_>,
    reassembly: [CryptoBuffer<'_>; 2], receive_io: &mut impl DatagramRx,
    send_io: &mut impl DatagramTx, clock: &impl Clock,
    issuer: &mut publication_gate::Issuer<'_, 'scope>, storage: &Storage<'scope, 'book, N, P>,
    book: &'book mut recovery::Recovery<'scope, N>, tls_outcome: &Outcome, adapter_outcome: &Outcome,
) -> Result<(ReceiveContinuation<'scope, P>, TransmitContinuation<'scope>), Error> {
    config.validate()?;
    if N < 1200 || book.max_datagram_size() > N as u64
        || !core::ptr::eq(source.scope(), book.scope()) || config.side != book.side()
        || storage.peer.borrow().bytes() != config.peer_connection_id {
        return Err(Error::Binding);
    }
    let expected_side = match config.side { Side::Client => crate::tls_schedule::Side::Client,
        Side::Server => crate::tls_schedule::Side::Server };
    if source.side() != expected_side { return Err(Error::Binding); }
    storage.claim()?;
    let _clear = Clear(storage);
    let scope = source.scope();
    let integrity = source.take_integrity_budget()?;
    let initial = crypto::initial_keys(config.original_destination_id)?;
    let (read, write) = match config.side { Side::Client => (initial.server, initial.client), Side::Server => (initial.client, initial.server) };
    let initial = initial::Keys::new(scope, read, write)?;
    let initial_exchange = initial::Exchange::new();
    let numbers = transcript::Numbers::new(source);
    let (mut tx, mut rx, mut clock_book, mut publication, mut retirement) = book.split()?;
    let mut initial_owner = tx.initial_retirement_owner();
    let (mut receive_initial, mut publish_initial) = match config.side {
        Side::Client => (None, Some(&mut roles.initial_event)),
        Side::Server => (Some(&mut roles.initial_event), None),
    };
    let mut received = None;
    let mut transmitted = None;
    {
        let mut receive = pin!(async {
            received = Some(locals::receive(&mut roles.rx, receive_io, storage, config, scope, &initial, &initial_exchange, receive_initial.as_deref_mut(), integrity, reassembly, &mut rx, clock).await?);
            Ok(())
        });
        let mut transmit = pin!(async {
            transmitted = Some(locals::transmit(&mut roles.tx, &mut roles.tx_wire, storage, config, scope, &initial, &mut tx, clock).await?);
            Ok(())
        });
        let mut tls_receive = pin!(transcript::receive(&mut roles.tls_rx, &numbers, storage, tls_outcome));
        let mut tls_transmit = pin!(transcript::transmit(&mut roles.tls_tx, &numbers, storage));
        let mut publish = pin!(locals::publish(&mut roles.udp, send_io, storage, &initial, &initial_exchange, publish_initial.as_deref_mut(), issuer, adapter_outcome, &mut publication));
        let mut timer = pin!(timer::run(&mut roles.timer, storage, &mut clock_book, clock));
        let mut timer_receiver = pin!(timer::receive(&mut roles.timer_tx, &storage.schedule));
        let mut initial_retirement = pin!(initial::retire(&mut roles.initial_owner, &initial,
            &initial_exchange, &storage.schedule, &mut initial_owner, config.side));
        crate::runtime::TaskSet::new([receive.as_mut(), transmit.as_mut(), tls_receive.as_mut(),
            tls_transmit.as_mut(), publish.as_mut(), timer.as_mut(), timer_receiver.as_mut(),
            initial_retirement.as_mut()]).await?;
    }
    if initial.available() { return Err(Error::Binding); }
    retirement.disarm();
    Ok((received.ok_or(Error::Binding)?, transmitted.ok_or(Error::Binding)?))
}
