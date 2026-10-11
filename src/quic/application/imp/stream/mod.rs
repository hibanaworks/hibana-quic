//! Bounded stream arithmetic shared by the application continuations.
//!
//! This module owns no keys, connection phase, packet-number allocator, IO, or
//! asynchronous operation. The receive facet is a connection-private producer:
//! its caller must first authenticate the complete packet and validate recovery
//! effects. Facets borrow the numeric kernels only for synchronous operations;
//! bytes carried across an await are owned `Prepared` values.

use core::cell::RefCell;

use crate::crypto::directional::ApplicationKeyScope;
use crate::quic::imp::kernel::accounting::PacketNumber;
use crate::quic::imp::kernel::accounting::PacketNumberSpace;
use crate::quic::imp::kernel::packet;
use crate::quic::imp::kernel::packet::Frame;
use crate::quic::imp::kernel::streams;
use crate::quic::imp::kernel::streams::ChunkHandle;
use crate::quic::imp::kernel::streams::Limits;
use crate::quic::imp::kernel::streams::PacketReference;
use crate::quic::imp::kernel::streams::Role;
use crate::quic::imp::kernel::streams::SendChunk;
use crate::quic::imp::kernel::streams::SendQueue;
use crate::quic::imp::kernel::streams::StreamHandle;
use crate::quic::imp::kernel::streams::StreamSlot;
use crate::quic::imp::kernel::streams::StreamTable;

const CONTROL_CAPACITY: usize = crate::quic::imp::recovery::LEDGER_CAPACITY;
pub const MAX_LIVE_STREAMS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Streams(streams::Error),
    Packet(packet::Error),
    Binding,
    Borrowed,
    Capacity,
    UnsupportedStream,
    UnsupportedFrame,
}
impl From<streams::Error> for Error {
    fn from(value: streams::Error) -> Self {
        Self::Streams(value)
    }
}
impl From<packet::Error> for Error {
    fn from(value: packet::Error) -> Self {
        Self::Packet(value)
    }
}

struct Identity {
    generation: u64,
}

pub struct StreamNumbers<'storage, 'scope, const RX: usize, const CHUNK: usize> {
    identity: Identity,
    scope: &'scope ApplicationKeyScope,
    numbers: RefCell<Numbers<'storage, RX, CHUNK>>,
}

impl<'storage, 'scope, const RX: usize, const CHUNK: usize>
    StreamNumbers<'storage, 'scope, RX, CHUNK>
{
    /// `peer` must be the limits extracted from this connection's validated
    /// Finished boundary. That boundary, rather than this arithmetic object,
    /// owns permission to enter the application protocol.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: &'scope ApplicationKeyScope,
        role: Role,
        peer: Limits,
        local: Limits,
        slots: &'storage mut [StreamSlot<RX>],
        chunks: &'storage mut [SendChunk<CHUNK>],
        references: &'storage mut [PacketReference],
    ) -> Result<Self, Error> {
        if slots.len() > MAX_LIVE_STREAMS {
            return Err(Error::Capacity);
        }
        let generation = scope.connection_generation();
        let table = StreamTable::new(slots, role, generation, local, peer)?;
        let queue = SendQueue::new(generation, chunks, references)?;
        Ok(Self {
            identity: Identity { generation },
            scope,
            numbers: RefCell::new(Numbers {
                table,
                queue,
                role,
                streams: [const { StreamState::EMPTY }; MAX_LIVE_STREAMS],
                data_credit: Credit::new(local.max_data),
                bidi_credit: Credit::new(local.max_streams_bidi),
                control_cursor: 0,
                controls: [ControlReference::EMPTY; CONTROL_CAPACITY],
            }),
        })
    }

    /// Exclusive split prevents manufacturing another independent set of roles
    /// while the previous set still holds publication reservations.
    pub fn split(&mut self) -> Facets<'_, 'storage, 'scope, RX, CHUNK> {
        Facets {
            app: App { core: self },
            rx: Rx { core: self },
            tx: Tx { core: self },
            publication: Publication { core: self },
            reset: FrameEffects { core: self },
        }
    }

    pub const fn scope(&self) -> &'scope ApplicationKeyScope {
        self.scope
    }
}

pub struct Facets<'book, 'storage, 'scope, const RX: usize, const CHUNK: usize> {
    pub app: App<'book, 'storage, 'scope, RX, CHUNK>,
    pub rx: Rx<'book, 'storage, 'scope, RX, CHUNK>,
    pub tx: Tx<'book, 'storage, 'scope, RX, CHUNK>,
    pub publication: Publication<'book, 'storage, 'scope, RX, CHUNK>,
    pub(crate) reset: FrameEffects<'book, 'storage, 'scope, RX, CHUNK>,
}

pub struct App<'book, 'storage, 'scope, const RX: usize, const CHUNK: usize> {
    core: &'book StreamNumbers<'storage, 'scope, RX, CHUNK>,
}
/// One production lease for one live stream in this exact table. It cannot be
/// cloned or reissued after FIN/abandon. The projected source continuation owns
/// it while producing bytes; retransmission uses independent retained chunks.
pub(crate) struct Production<'book> {
    identity: &'book Identity,
    stream: StreamHandle,
}
impl Production<'_> {
    pub(in crate::quic) fn id(&self) -> u64 {
        self.stream.id()
    }
}

/// Copyable correlation data is not a release capability.
#[derive(Clone, Copy)]
pub(in crate::quic) struct Origin<'book> {
    identity: &'book Identity,
    stream: StreamHandle,
}
impl Origin<'_> {
    pub(in crate::quic) fn id(self) -> u64 {
        self.stream.id()
    }
    pub(in crate::quic) fn slot(self) -> usize {
        self.stream.slot()
    }
    pub(in crate::quic) fn same(self, other: Self) -> bool {
        core::ptr::eq(self.identity, other.identity) && self.stream == other.stream
    }
}
pub(in crate::quic) struct ProductionReleased<'book> {
    origin: Origin<'book>,
}
pub(in crate::quic) struct InputReleased<'book> {
    origin: Origin<'book>,
}
pub(in crate::quic) struct DeliveryReleased<'book> {
    origin: Origin<'book>,
}
impl<'book> ProductionReleased<'book> {
    pub(in crate::quic) fn origin(&self) -> Origin<'book> {
        self.origin
    }
}
impl<'book> InputReleased<'book> {
    pub(in crate::quic) fn origin(&self) -> Origin<'book> {
        self.origin
    }
}
impl<'book> DeliveryReleased<'book> {
    pub(in crate::quic) fn origin(&self) -> Origin<'book> {
        self.origin
    }
}

pub struct Rx<'book, 'storage, 'scope, const RX: usize, const CHUNK: usize> {
    core: &'book StreamNumbers<'storage, 'scope, RX, CHUNK>,
}
pub struct Tx<'book, 'storage, 'scope, const RX: usize, const CHUNK: usize> {
    core: &'book StreamNumbers<'storage, 'scope, RX, CHUNK>,
}
pub struct Publication<'book, 'storage, 'scope, const RX: usize, const CHUNK: usize> {
    core: &'book StreamNumbers<'storage, 'scope, RX, CHUNK>,
}

pub(crate) struct FrameEffects<'book, 'storage, 'scope, const RX: usize, const CHUNK: usize> {
    core: &'book StreamNumbers<'storage, 'scope, RX, CHUNK>,
}

/// Actual authenticated STOP_SENDING observation, not a copied phase flag.
pub(in crate::quic) struct StopIntent<'book> {
    identity: &'book Identity,
    stream: StreamHandle,
    error_code: u64,
}
impl StopIntent<'_> {
    pub(in crate::quic) fn id(&self) -> u64 {
        self.stream.id()
    }
    pub(in crate::quic) fn slot(&self) -> usize {
        self.stream.slot()
    }
    pub(in crate::quic) fn same_stream(&self, other: &Self) -> bool {
        core::ptr::eq(self.identity, other.identity) && self.stream == other.stream
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Read {
    pub len: usize,
    /// All bytes through FIN have been consumed by the application.
    pub fin: bool,
    pub reset: Option<u64>,
}

/// An immutable copy of actual encoded frames. Its origin and chunk handle are
/// private, so a arbitrary byte buffer cannot manufacture a stream reservation.
pub struct Prepared<'book, const N: usize> {
    identity: &'book Identity,
    bytes: [u8; N],
    len: usize,
    chunk: Option<ChunkHandle>,
    controls: Controls,
}
impl<const N: usize> Prepared<'_, N> {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
    fn append(&mut self, frame: &Frame<'_>) -> Result<(), Error> {
        self.len += packet::encode_frame(frame, &mut self.bytes[self.len..])?;
        Ok(())
    }
}

#[must_use = "settle the stream reservation after the actual adapter result"]
pub struct Transmission<'book> {
    identity: &'book Identity,
    packet_number: u64,
    stream: Option<(StreamHandle, streams::Transmission)>,
    control: Option<(usize, u64)>,
}
impl Transmission<'_> {
    pub fn packet_number(&self) -> u64 {
        self.packet_number
    }
}

#[derive(Clone, Copy)]
struct Credit {
    current: u64,
    acknowledged: u64,
    pending: bool,
}
impl Credit {
    const fn new(initial: u64) -> Self {
        Self {
            current: initial,
            acknowledged: initial,
            pending: false,
        }
    }
    fn should_update(self, maximum: u64, window: u64) -> bool {
        maximum > self.current
            && (maximum == streams::MAX_OFFSET || maximum - self.current >= (window / 2).max(1))
    }
    fn update(&mut self, maximum: u64) {
        if maximum > self.current {
            self.current = maximum;
            self.pending = true;
        }
    }
    fn next(self, probe: bool) -> Option<u64> {
        if self.pending || (probe && self.current > self.acknowledged) {
            Some(self.current)
        } else {
            None
        }
    }
    fn published(&mut self, value: Option<u64>) {
        if value == Some(self.current) {
            self.pending = false;
        }
    }
    fn acknowledge(&mut self, value: Option<u64>) {
        if let Some(value) = value {
            self.acknowledged = self.acknowledged.max(value);
        }
        if self.acknowledged >= self.current {
            self.pending = false;
        }
    }
    fn retry(&mut self, value: Option<u64>) {
        if value.is_some_and(|v| v > self.acknowledged) {
            self.pending = true;
        }
    }
}

#[derive(Clone, Copy)]
struct Controls {
    max_data: Option<u64>,
    max_streams_bidi: Option<u64>,
    max_stream_data: Option<(StreamHandle, u64)>,
    reset: Option<(StreamHandle, streams::Reset)>,
}
impl Controls {
    const EMPTY: Self = Self {
        max_data: None,
        max_streams_bidi: None,
        max_stream_data: None,
        reset: None,
    };
    fn is_empty(self) -> bool {
        self.max_data.is_none()
            && self.max_streams_bidi.is_none()
            && self.max_stream_data.is_none()
            && self.reset.is_none()
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum ReferenceState {
    Free,
    Reserved,
    Sent,
    Lost,
}
#[derive(Clone, Copy)]
struct ControlReference {
    generation: u64,
    packet: u64,
    state: ReferenceState,
    contents: Controls,
}
impl ControlReference {
    const EMPTY: Self = Self {
        generation: 0,
        packet: 0,
        state: ReferenceState::Free,
        contents: Controls::EMPTY,
    };
}
/// Payload facts from a newly ACKed FIN/RESET, never a reusable phase flag.
struct TerminalEvidence {
    stream: StreamHandle,
    final_size: u64,
    reset: Option<u64>,
}
#[derive(Clone, Copy)]
/// Read-only observation of a completion already received through Hibana.
/// This value carries no permission to produce, reset, ACK, or retire a stream.
pub struct DeliveryRecord {
    pub final_size: u64,
    pub reset: Option<u64>,
}
/// This owned receipt crosses the actual StreamDelivered edge exactly once.
pub(in crate::quic) struct Delivered<'book> {
    identity: &'book Identity,
    evidence: TerminalEvidence,
}
impl Delivered<'_> {
    pub(in crate::quic) fn id(&self) -> u64 {
        self.evidence.stream.id()
    }
}
struct StreamState {
    handle: Option<StreamHandle>,
    production: Option<StreamHandle>,
    input_release: Option<StreamHandle>,
    credit: Credit,
    reset: Option<streams::Reset>,
    terminal: Option<TerminalEvidence>,
    delivered: Option<DeliveryRecord>,
}
impl StreamState {
    const EMPTY: Self = Self {
        handle: None,
        production: None,
        input_release: None,
        credit: Credit::new(0),
        reset: None,
        terminal: None,
        delivered: None,
    };
}
struct Numbers<'storage, const RX: usize, const CHUNK: usize> {
    table: StreamTable<'storage, RX>,
    queue: SendQueue<'storage, CHUNK>,
    role: Role,
    streams: [StreamState; MAX_LIVE_STREAMS],
    data_credit: Credit,
    bidi_credit: Credit,
    control_cursor: usize,
    controls: [ControlReference; CONTROL_CAPACITY],
}

#[cfg(test)]
mod tests;

mod accounting;
mod application;
mod ownership;
mod receive;
mod transmit;
