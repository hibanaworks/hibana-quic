//! Bounded stream arithmetic shared by the application continuations.
//!
//! This module owns no keys, connection phase, packet-number allocator, IO, or
//! asynchronous operation. The receive facet is a connection-private producer:
//! its caller must first authenticate the complete packet and validate recovery
//! effects. Facets borrow the numeric kernels only for synchronous operations;
//! bytes carried across an await are owned `Prepared` values.

use core::cell::RefCell;

use crate::{
    accounting::{PacketNumber, PacketNumberSpace},
    crypto::directional::ApplicationKeyScope,
    packet::{self, Frame},
    streams::{
        self, ChunkHandle, Limits, PacketReference, Role, SendChunk, SendQueue, StreamHandle,
        StreamSlot, StreamTable,
    },
};

const CONTROL_CAPACITY: usize = super::recovery::LEDGER_CAPACITY;
pub const MAX_LIVE_STREAMS: usize = 16;

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
pub(super) struct Production<'book> {
    identity: &'book Identity,
    stream: StreamHandle,
}
impl Production<'_> {
    pub(super) fn id(&self) -> u64 {
        self.stream.id()
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
pub(super) struct StopIntent<'book> {
    identity: &'book Identity,
    stream: StreamHandle,
    error_code: u64,
}
impl StopIntent<'_> {
    pub(super) fn id(&self) -> u64 {
        self.stream.id()
    }
    pub(super) fn slot(&self) -> usize {
        self.stream.slot()
    }
    pub(super) fn same_stream(&self, other: &Self) -> bool {
        core::ptr::eq(self.identity, other.identity) && self.stream == other.stream
    }
}
impl<'book, const RX: usize, const CHUNK: usize> FrameEffects<'book, '_, '_, RX, CHUNK> {
    pub(super) fn take_delivery(&mut self) -> Result<Option<Delivered<'book>>, Error> {
        let mut n = self
            .core
            .numbers
            .try_borrow_mut()
            .map_err(|_| Error::Borrowed)?;
        for index in 0..MAX_LIVE_STREAMS {
            let Some(evidence) = n.streams[index].terminal.as_ref() else {
                continue;
            };
            if n.table.unacknowledged_chunks(evidence.stream)? == 0 {
                let evidence = n.streams[index].terminal.take().ok_or(Error::Binding)?;
                return Ok(Some(Delivered {
                    identity: &self.core.identity,
                    evidence,
                }));
            }
        }
        Ok(None)
    }
    pub(super) fn acknowledge(
        &mut self,
        grant: super::recovery::FrameAcknowledgments<'_>,
    ) -> Result<(), Error> {
        if !core::ptr::eq(grant.scope(), self.core.scope) {
            return Err(Error::Binding);
        }
        self.core
            .numbers
            .try_borrow_mut()
            .map_err(|_| Error::Borrowed)?
            .acknowledge(grant.packets())
    }
    pub(super) fn apply(&mut self, intent: StopIntent<'_>) -> Result<(), Error> {
        if !core::ptr::eq(intent.identity, &self.core.identity) {
            return Err(Error::Binding);
        }
        let mut n = self
            .core
            .numbers
            .try_borrow_mut()
            .map_err(|_| Error::Borrowed)?;
        let state = n.state(intent.stream)?;
        if state.delivered.is_some()
            || (state.terminal.is_some() && n.table.unacknowledged_chunks(intent.stream)? == 0)
        {
            return Ok(());
        }
        let Numbers { table, queue, .. } = &mut *n;
        if let Some(reset) = queue.reset(table, intent.stream, intent.error_code)? {
            let state = n.state_mut(intent.stream)?;
            if state.reset.is_none() {
                state.reset = Some(reset);
                state.terminal = None;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Read {
    pub len: usize,
    /// All bytes through FIN have been copied into the application's sink.
    pub fin: bool,
    pub reset: Option<u64>,
}

impl<'book, const RX: usize, const CHUNK: usize> App<'book, '_, '_, RX, CHUNK> {
    /// Open a locally initiated bidirectional stream using authenticated peer credit.
    pub fn open_local(&mut self) -> Result<StreamHandle, Error> {
        let mut n = self
            .core
            .numbers
            .try_borrow_mut()
            .map_err(|_| Error::Borrowed)?;
        let stream = n.table.open_local(true)?;
        n.register(stream)?;
        Ok(stream)
    }

    pub(super) fn take_production(
        &mut self,
        stream: StreamHandle,
    ) -> Result<Production<'book>, Error> {
        let mut numbers = self
            .core
            .numbers
            .try_borrow_mut()
            .map_err(|_| Error::Borrowed)?;
        let issued = numbers
            .state_mut(stream)?
            .production
            .take()
            .ok_or(Error::Binding)?;
        Ok(Production {
            identity: &self.core.identity,
            stream: issued,
        })
    }

    fn production_stream(&self, production: &Production<'_>) -> Result<StreamHandle, Error> {
        if !core::ptr::eq(production.identity, &self.core.identity) {
            return Err(Error::Binding);
        }
        Ok(production.stream)
    }

    /// Admit at most one chunk and the available peer credit. FIN is attached
    /// only when the complete supplied suffix fits.
    pub(super) fn enqueue_prefix(
        &mut self,
        production: &mut Production<'_>,
        bytes: &[u8],
        fin: bool,
    ) -> Result<usize, Error> {
        let stream = self.production_stream(production)?;
        let mut n = self
            .core
            .numbers
            .try_borrow_mut()
            .map_err(|_| Error::Borrowed)?;
        let credit = n.table.send_credit(stream)?;
        let len = bytes.len().min(CHUNK).min(
            usize::try_from(credit.connection_available.min(credit.stream_available))
                .unwrap_or(usize::MAX),
        );
        if len == 0 && !bytes.is_empty() {
            return Err(streams::Error::FlowControl.into());
        }
        let Numbers { table, queue, .. } = &mut *n;
        queue.enqueue(table, stream, &bytes[..len], fin && len == bytes.len())?;
        Ok(len)
    }

    /// Copy and consume a contiguous prefix without exposing a borrowed view.
    /// Freed storage schedules reliable MAX_DATA/MAX_STREAM_DATA updates.
    pub fn read(&mut self, stream: StreamHandle, output: &mut [u8]) -> Result<Read, Error> {
        let mut n = self
            .core
            .numbers
            .try_borrow_mut()
            .map_err(|_| Error::Borrowed)?;
        n.state(stream)?;
        let (len, fin, reset) = {
            let view = n.table.receive(stream)?;
            let ready = view.first.len() + view.second.len();
            let len = ready.min(output.len());
            let first = len.min(view.first.len());
            output[..first].copy_from_slice(&view.first[..first]);
            output[first..len].copy_from_slice(&view.second[..len - first]);
            (len, view.fin && len == ready, view.reset)
        };
        n.table.consume(stream, len)?;
        if reset.is_some() {
            n.table.acknowledge_received_reset(stream)?;
        }
        if len != 0 || reset.is_some() {
            n.replenish_credit(stream)?;
        }
        Ok(Read { len, fin, reset })
    }

    /// Owned handles only: no table/view borrow crosses the caller's await.
    /// A consumed FIN/reset remains observable until the application retires it.
    pub fn ready_streams(&self) -> Result<[Option<StreamHandle>; MAX_LIVE_STREAMS], Error> {
        let n = self
            .core
            .numbers
            .try_borrow()
            .map_err(|_| Error::Borrowed)?;
        let mut ready = [None; MAX_LIVE_STREAMS];
        let mut count = 0;
        for stream in n.table.live_handles() {
            let view = n.table.receive(stream)?;
            if !view.first.is_empty() || !view.second.is_empty() || view.fin || view.reset.is_some()
            {
                ready[count] = Some(stream);
                count += 1;
            }
        }
        Ok(ready)
    }

    pub fn readable_stream(&self) -> Result<Option<StreamHandle>, Error> {
        Ok(self.ready_streams()?.into_iter().flatten().next())
    }

    pub fn delivery(&self, stream: StreamHandle) -> Result<Option<DeliveryRecord>, Error> {
        let n = self
            .core
            .numbers
            .try_borrow()
            .map_err(|_| Error::Borrowed)?;
        Ok(n.state(stream)?.delivered)
    }
    pub fn send_complete(&self, stream: StreamHandle) -> Result<bool, Error> {
        let n = self
            .core
            .numbers
            .try_borrow()
            .map_err(|_| Error::Borrowed)?;
        Ok(n.state(stream)?.delivered.is_some())
    }

    pub fn receive_complete(&self, stream: StreamHandle) -> Result<bool, Error> {
        let n = self
            .core
            .numbers
            .try_borrow()
            .map_err(|_| Error::Borrowed)?;
        let view = n.table.receive(stream)?;
        Ok(view.reset.is_some() || (view.fin && view.first.is_empty() && view.second.is_empty()))
    }

    pub fn queued_chunks(&self) -> Result<usize, Error> {
        let n = self
            .core
            .numbers
            .try_borrow()
            .map_err(|_| Error::Borrowed)?;
        Ok(n.queue.queued_chunks())
    }
}

impl<'book, const RX: usize, const CHUNK: usize> Rx<'book, '_, '_, RX, CHUNK> {
    pub(super) fn stop_intent(
        &mut self,
        id: u64,
        error_code: u64,
    ) -> Result<StopIntent<'book>, Error> {
        if error_code > streams::MAX_OFFSET {
            return Err(streams::Error::InvalidId.into());
        }
        let mut n = self
            .core
            .numbers
            .try_borrow_mut()
            .map_err(|_| Error::Borrowed)?;
        let stream = n.accept_stream(id)?;
        Ok(StopIntent {
            identity: &self.core.identity,
            stream,
            error_code,
        })
    }

    /// The caller is the authenticated connection receive continuation, after
    /// whole-packet AEAD/frame/recovery validation. An arbitrary public caller
    /// cannot feed frames directly into this producer boundary.
    pub(super) fn apply(&mut self, frame: &Frame<'_>) -> Result<(), Error> {
        let mut n = self
            .core
            .numbers
            .try_borrow_mut()
            .map_err(|_| Error::Borrowed)?;
        match *frame {
            Frame::Stream {
                id,
                offset,
                fin,
                data,
            } => {
                let stream = n.accept_stream(id)?;
                n.table.on_stream(stream, offset, data, fin)?;
            }
            Frame::ResetStream {
                id,
                error_code,
                final_size,
            } => {
                let stream = n.accept_stream(id)?;
                n.table.on_reset(stream, error_code, final_size)?;
            }
            Frame::MaxData { maximum } => n.table.on_max_data(maximum)?,
            Frame::MaxStreamData { id, maximum } => {
                let stream = n.accept_stream(id)?;
                n.table.on_max_stream_data(stream, maximum)?;
            }
            Frame::MaxStreams {
                bidirectional,
                maximum,
            } => {
                n.table.on_max_streams(bidirectional, maximum)?;
            }
            Frame::StreamDataBlocked { id, .. } => {
                n.accept_stream(id)?;
            }
            Frame::DataBlocked { .. } | Frame::StreamsBlocked { .. } => {}
            _ => return Err(Error::UnsupportedFrame),
        }
        Ok(())
    }
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

impl<'book, const RX: usize, const CHUNK: usize> Tx<'book, '_, '_, RX, CHUNK> {
    /// Cancel a reservation which TX could not seal/transfer to the adapter.
    /// Accepted packets can be committed only through the publication facet.
    pub(super) fn cancel_transmission(
        &mut self,
        transmission: Transmission<'_>,
    ) -> Result<(), Error> {
        Publication { core: self.core }.cancel(transmission)
    }

    // Recovery-driven arithmetic is also available to the transmit facet.
    // It never grants permission to authenticate or apply peer frames.
    pub(super) fn record_delivery(&mut self, receipt: Delivered<'_>) -> Result<(), Error> {
        if !core::ptr::eq(receipt.identity, &self.core.identity) {
            return Err(Error::Binding);
        }
        let mut n = self
            .core
            .numbers
            .try_borrow_mut()
            .map_err(|_| Error::Borrowed)?;
        let state = n.state_mut(receipt.evidence.stream)?;
        if state.delivered.is_some() {
            return Err(Error::Binding);
        }
        state.delivered = Some(DeliveryRecord {
            final_size: receipt.evidence.final_size,
            reset: receipt.evidence.reset,
        });
        Ok(())
    }
    pub(super) fn lost(&mut self, packet_number: u64) -> Result<(), Error> {
        let mut n = self
            .core
            .numbers
            .try_borrow_mut()
            .map_err(|_| Error::Borrowed)?;
        n.queue.on_packet_lost(packet_number);
        for index in 0..CONTROL_CAPACITY {
            let reference = n.controls[index];
            if reference.packet == packet_number && reference.state == ReferenceState::Sent {
                n.controls[index].state = ReferenceState::Lost;
                n.retry_control(reference.contents);
            }
        }
        Ok(())
    }

    /// Only call when Recovery has explicitly stopped retaining this lost PN.
    pub(super) fn forget_lost(&mut self, packet_number: u64) -> Result<(), Error> {
        let mut n = self
            .core
            .numbers
            .try_borrow_mut()
            .map_err(|_| Error::Borrowed)?;
        let Numbers { table, queue, .. } = &mut *n;
        queue.forget_lost_packet(table, packet_number)?;
        for r in &mut n.controls {
            if r.packet == packet_number && r.state == ReferenceState::Lost {
                r.state = ReferenceState::Free;
            }
        }
        Ok(())
    }

    /// Prefer a pending STREAM chunk; on a PTO an outstanding range may be
    /// copied under a fresh packet number without declaring the old copy lost.
    /// Dirty control limits/reset are encoded before the chunk. A caller may
    /// prepend/append its own recovery-produced ACK when composing plaintext.
    pub fn prepare<const N: usize>(
        &self,
        probe: bool,
    ) -> Result<Option<Prepared<'book, N>>, Error> {
        let n = self
            .core
            .numbers
            .try_borrow()
            .map_err(|_| Error::Borrowed)?;
        let chunk = n
            .queue
            .next_pending()
            .or_else(|| if probe { n.queue.probe_chunk() } else { None });
        let controls = n.next_controls(probe);
        if chunk.is_none() && controls.is_empty() {
            return Ok(None);
        }
        let mut prepared = Prepared {
            identity: &self.core.identity,
            bytes: [0; N],
            len: 0,
            chunk,
            controls,
        };
        if let Some(maximum) = controls.max_data {
            prepared.append(&Frame::MaxData { maximum })?;
        }
        if let Some((stream, maximum)) = controls.max_stream_data {
            prepared.append(&Frame::MaxStreamData {
                id: stream.id(),
                maximum,
            })?;
        }
        if let Some((_, reset)) = controls.reset {
            prepared.append(&Frame::ResetStream {
                id: reset.id,
                error_code: reset.error_code,
                final_size: reset.final_size,
            })?;
        }
        if let Some(chunk) = chunk {
            let view = n.queue.chunk(chunk)?;
            prepared.append(&Frame::Stream {
                id: view.stream.id(),
                offset: view.offset,
                fin: view.fin,
                data: view.data,
            })?;
        }
        Ok(Some(prepared))
    }

    /// Bind the exact selected chunk/control frames to the actual packet number
    /// allocated by Recovery before handing bytes to the adapter.
    pub fn reserve_transmission<const N: usize>(
        &mut self,
        prepared: &Prepared<'book, N>,
        packet_number: u64,
    ) -> Result<Transmission<'book>, Error> {
        if !core::ptr::eq(prepared.identity, &self.core.identity)
            || prepared.identity.generation != self.core.scope.connection_generation()
            || packet_number > streams::MAX_OFFSET
        {
            return Err(Error::Binding);
        }
        let mut n = self
            .core
            .numbers
            .try_borrow_mut()
            .map_err(|_| Error::Borrowed)?;
        if n.controls
            .iter()
            .any(|r| r.state != ReferenceState::Free && r.packet == packet_number)
        {
            return Err(Error::Binding);
        }
        let control = if prepared.controls.is_empty() {
            None
        } else {
            Some(
                n.controls
                    .iter()
                    .position(|r| r.state == ReferenceState::Free && r.generation != u64::MAX)
                    .ok_or(Error::Capacity)?,
            )
        };
        let stream = match prepared.chunk {
            Some(chunk) => {
                let handle = n.queue.chunk(chunk)?.stream;
                n.state(handle)?;
                let reference = n.queue.reserve_transmission(chunk, packet_number)?;
                Some((handle, reference))
            }
            None => None,
        };
        let control = control.map(|slot| {
            let generation = n.controls[slot].generation + 1;
            n.controls[slot] = ControlReference {
                generation,
                packet: packet_number,
                state: ReferenceState::Reserved,
                contents: prepared.controls,
            };
            (slot, generation)
        });
        Ok(Transmission {
            identity: &self.core.identity,
            packet_number,
            stream,
            control,
        })
    }
}

impl<const RX: usize, const CHUNK: usize> Publication<'_, '_, '_, RX, CHUNK> {
    /// Call only after the adapter confirms publication. Dropping or cancelling
    /// its pending future cannot be treated as successful transmission.
    pub fn commit(&mut self, transmission: Transmission<'_>) -> Result<(), Error> {
        self.settle(transmission, true)
    }
    pub fn cancel(&mut self, transmission: Transmission<'_>) -> Result<(), Error> {
        self.settle(transmission, false)
    }
    fn settle(&mut self, transmission: Transmission<'_>, published: bool) -> Result<(), Error> {
        if !core::ptr::eq(transmission.identity, &self.core.identity) {
            return Err(Error::Binding);
        }
        let mut n = self
            .core
            .numbers
            .try_borrow_mut()
            .map_err(|_| Error::Borrowed)?;
        if let Some((slot, generation)) = transmission.control {
            let r = n.controls.get(slot).ok_or(Error::Binding)?;
            if r.generation != generation
                || r.state != ReferenceState::Reserved
                || r.packet != transmission.packet_number
            {
                return Err(Error::Binding);
            }
        }
        if let Some((_stream, reference)) = transmission.stream {
            let Numbers { table, queue, .. } = &mut *n;
            if published {
                queue.commit_transmission(table, reference)?;
            } else {
                queue.cancel_transmission(table, reference)?;
            }
        }
        if let Some((slot, _)) = transmission.control {
            let contents = n.controls[slot].contents;
            if published {
                n.controls[slot].state = ReferenceState::Sent;
                n.data_credit.published(contents.max_data);
                if let Some((stream, maximum)) = contents.max_stream_data {
                    n.state_mut(stream)?.credit.published(Some(maximum));
                    n.control_cursor = (stream.slot() + 1) % MAX_LIVE_STREAMS;
                }
                if let Some((stream, _)) = contents.reset {
                    n.control_cursor = (stream.slot() + 1) % MAX_LIVE_STREAMS;
                }
            } else {
                n.controls[slot].state = ReferenceState::Free;
            }
        }
        n.collect_controls();
        Ok(())
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
    max_stream_data: Option<(StreamHandle, u64)>,
    reset: Option<(StreamHandle, streams::Reset)>,
}
impl Controls {
    const EMPTY: Self = Self {
        max_data: None,
        max_stream_data: None,
        reset: None,
    };
    fn is_empty(self) -> bool {
        self.max_data.is_none() && self.max_stream_data.is_none() && self.reset.is_none()
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
pub(super) struct Delivered<'book> {
    identity: &'book Identity,
    evidence: TerminalEvidence,
}
impl Delivered<'_> {
    pub(super) fn id(&self) -> u64 {
        self.evidence.stream.id()
    }
}
struct StreamState {
    handle: Option<StreamHandle>,
    production: Option<StreamHandle>,
    credit: Credit,
    reset: Option<streams::Reset>,
    terminal: Option<TerminalEvidence>,
    delivered: Option<DeliveryRecord>,
}
impl StreamState {
    const EMPTY: Self = Self {
        handle: None,
        production: None,
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
    control_cursor: usize,
    controls: [ControlReference; CONTROL_CAPACITY],
}
impl<const RX: usize, const CHUNK: usize> Numbers<'_, RX, CHUNK> {
    fn state(&self, stream: StreamHandle) -> Result<&StreamState, Error> {
        let state = self.streams.get(stream.slot()).ok_or(Error::Binding)?;
        if state.handle != Some(stream) {
            return Err(streams::Error::StaleHandle.into());
        }
        Ok(state)
    }
    fn state_mut(&mut self, stream: StreamHandle) -> Result<&mut StreamState, Error> {
        let state = self.streams.get_mut(stream.slot()).ok_or(Error::Binding)?;
        if state.handle != Some(stream) {
            return Err(streams::Error::StaleHandle.into());
        }
        Ok(state)
    }
    fn register(&mut self, stream: StreamHandle) -> Result<(), Error> {
        if self.streams[stream.slot()].handle == Some(stream) {
            return Ok(());
        }
        let local = self.table.local_limits();
        let local_bit = u64::from(self.role == Role::Server);
        let locally_initiated = stream.id() & 1 == local_bit;
        let maximum = if stream.id() & 2 != 0 {
            if locally_initiated {
                0
            } else {
                local.stream_data_uni
            }
        } else if locally_initiated {
            local.stream_data_bidi_local
        } else {
            local.stream_data_bidi_remote
        };
        self.streams[stream.slot()] = StreamState {
            handle: Some(stream),
            production: Some(stream),
            credit: Credit::new(maximum),
            ..StreamState::EMPTY
        };
        Ok(())
    }
    fn accept_stream(&mut self, id: u64) -> Result<StreamHandle, Error> {
        let stream = self.table.get_or_accept(id)?;
        // Implicit lower peer streams also get real per-slot control metadata.
        let mut handles = [None; MAX_LIVE_STREAMS];
        for (slot, h) in handles.iter_mut().zip(self.table.live_handles()) {
            *slot = Some(h);
        }
        for handle in handles.into_iter().flatten() {
            self.register(handle)?;
        }
        Ok(stream)
    }
    fn replenish_credit(&mut self, stream: StreamHandle) -> Result<(), Error> {
        let data = self.table.receive_data_capacity();
        self.table.grant_max_data(data)?;
        self.data_credit.update(data);
        if self.table.receive_final_size(stream)?.is_none() {
            let maximum = self.table.stream_receive_capacity(stream)?;
            self.table.grant_max_stream_data(stream, maximum)?;
            self.state_mut(stream)?.credit.update(maximum);
        }
        Ok(())
    }
    /// Only actual newly acknowledged packet numbers returned by Recovery may
    /// enter here. The stream queue never interprets unvalidated ACK ranges.
    fn acknowledge(&mut self, packets: &[Option<PacketNumber>]) -> Result<(), Error> {
        if packets
            .iter()
            .flatten()
            .any(|pn| pn.space != PacketNumberSpace::ApplicationData)
        {
            return Err(Error::Binding);
        }
        let contains = |pn| packets.iter().flatten().any(|packet| packet.value == pn);
        let n = self;
        if n.controls
            .iter()
            .any(|r| r.state == ReferenceState::Reserved && contains(r.packet))
        {
            return Err(streams::Error::UnsentAcknowledgment.into());
        }
        let Numbers {
            table,
            queue,
            streams,
            ..
        } = &mut *n;
        queue.on_packets_acked(table, contains, |stream, final_size| {
            let state = &mut streams[stream.slot()];
            if state.reset.is_none() && state.delivered.is_none() {
                state.terminal = Some(TerminalEvidence {
                    stream,
                    final_size,
                    reset: None,
                });
            }
        })?;
        queue.release_acked_references(table)?;
        for index in 0..CONTROL_CAPACITY {
            let reference = n.controls[index];
            if reference.state != ReferenceState::Free && contains(reference.packet) {
                n.acknowledge_control(reference.contents)?;
                n.controls[index].state = ReferenceState::Free;
            }
        }
        n.collect_controls();
        Ok(())
    }
    fn next_controls(&self, probe: bool) -> Controls {
        let mut controls = Controls {
            max_data: self.data_credit.next(probe),
            ..Controls::EMPTY
        };
        for offset in 0..MAX_LIVE_STREAMS {
            let state = &self.streams[(self.control_cursor + offset) % MAX_LIVE_STREAMS];
            let Some(stream) = state.handle else {
                continue;
            };
            if controls.max_stream_data.is_none() {
                controls.max_stream_data =
                    state.credit.next(probe).map(|maximum| (stream, maximum));
            }
            if controls.reset.is_none()
                && (probe
                    || !self.controls.iter().any(|reference| {
                        matches!(
                            reference.state,
                            ReferenceState::Reserved | ReferenceState::Sent
                        ) && reference
                            .contents
                            .reset
                            .is_some_and(|(handle, _)| handle == stream)
                    }))
            {
                controls.reset = state.reset.map(|reset| (stream, reset));
            }
        }
        controls
    }
    fn acknowledge_control(&mut self, contents: Controls) -> Result<(), Error> {
        self.data_credit.acknowledge(contents.max_data);
        if let Some((stream, maximum)) = contents.max_stream_data {
            self.state_mut(stream)?.credit.acknowledge(Some(maximum));
        }
        if let Some((stream, reset)) = contents.reset {
            if self
                .state(stream)?
                .reset
                .is_some_and(|retained| retained != reset)
            {
                return Err(Error::Binding);
            }
            let state = self.state_mut(stream)?;
            if state.reset.take().is_some() {
                state.terminal = Some(TerminalEvidence {
                    stream,
                    final_size: reset.final_size,
                    reset: Some(reset.error_code),
                });
            }
        }
        Ok(())
    }
    fn retry_control(&mut self, contents: Controls) {
        self.data_credit.retry(contents.max_data);
        if let Some((stream, maximum)) = contents.max_stream_data {
            if let Ok(state) = self.state_mut(stream) {
                state.credit.retry(Some(maximum));
            }
        }
    }

    fn collect_controls(&mut self) {
        for index in 0..CONTROL_CAPACITY {
            let r = self.controls[index];
            if matches!(r.state, ReferenceState::Sent | ReferenceState::Lost)
                && r.contents
                    .max_data
                    .is_none_or(|v| v <= self.data_credit.acknowledged)
                && r.contents.max_stream_data.is_none_or(|(stream, maximum)| {
                    self.state(stream)
                        .is_ok_and(|s| maximum <= s.credit.acknowledged)
                })
                && r.contents
                    .reset
                    .is_none_or(|(stream, _)| self.state(stream).is_ok_and(|s| s.reset.is_none()))
            {
                self.controls[index].state = ReferenceState::Free;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local(role: Role) -> Limits {
        Limits {
            max_data: 8,
            max_streams_bidi: u64::from(role == Role::Server),
            stream_data_bidi_local: 8,
            stream_data_bidi_remote: 8,
            ..Limits::ZERO
        }
    }
    fn packet(pn: u64) -> Option<PacketNumber> {
        Some(PacketNumber {
            space: PacketNumberSpace::ApplicationData,
            value: pn,
        })
    }

    #[test]
    fn production_is_one_shot_even_after_drop_and_same_stream_registration() {
        // These expressions become ambiguous if somebody adds Copy or Clone
        // to the lease. They check affinity at compile time, without a fixture
        // that could merely fail because the type is private.
        trait NotCopy<A> {
            fn witness() {}
        }
        impl<T: ?Sized> NotCopy<()> for T {}
        impl<T: ?Sized + Copy> NotCopy<u8> for T {}
        let _ = <Production<'static> as NotCopy<_>>::witness;
        let _ = <Delivered<'static> as NotCopy<_>>::witness;
        trait NotClone<A> {
            fn witness() {}
        }
        impl<T: ?Sized> NotClone<()> for T {}
        impl<T: ?Sized + Clone> NotClone<u8> for T {}
        let _ = <Production<'static> as NotClone<_>>::witness;
        let _ = <Delivered<'static> as NotClone<_>>::witness;
        let scope = ApplicationKeyScope::new(707);
        let mut slots = [StreamSlot::<8>::EMPTY];
        let mut chunks = [SendChunk::<8>::EMPTY];
        let mut references = [PacketReference::EMPTY; 4];
        let mut core = StreamNumbers::new(
            &scope,
            Role::Client,
            local(Role::Server),
            local(Role::Client),
            &mut slots,
            &mut chunks,
            &mut references,
        )
        .unwrap();
        let mut app = core.split().app;
        let stream = app.open_local().unwrap();
        let allocation = actor_test_allocator::NoAlloc::start();
        let production = app.take_production(stream).unwrap();
        assert!(matches!(app.take_production(stream), Err(Error::Binding)));
        drop(production);
        app.core.numbers.borrow_mut().register(stream).unwrap();
        assert!(matches!(app.take_production(stream), Err(Error::Binding)));
        allocation.finish();
    }

    #[test]
    fn production_cannot_cross_tables_with_identical_numeric_stream_ids() {
        let scope = ApplicationKeyScope::new(708);
        let mut slots_a = [StreamSlot::<8>::EMPTY];
        let mut chunks_a = [SendChunk::<8>::EMPTY];
        let mut refs_a = [PacketReference::EMPTY; 4];
        let mut slots_b = [StreamSlot::<8>::EMPTY];
        let mut chunks_b = [SendChunk::<8>::EMPTY];
        let mut refs_b = [PacketReference::EMPTY; 4];
        let mut a = StreamNumbers::new(
            &scope,
            Role::Client,
            local(Role::Server),
            local(Role::Client),
            &mut slots_a,
            &mut chunks_a,
            &mut refs_a,
        )
        .unwrap();
        let mut b = StreamNumbers::new(
            &scope,
            Role::Client,
            local(Role::Server),
            local(Role::Client),
            &mut slots_b,
            &mut chunks_b,
            &mut refs_b,
        )
        .unwrap();
        let mut a = a.split().app;
        let mut b = b.split().app;
        let sa = a.open_local().unwrap();
        let sb = b.open_local().unwrap();
        assert_eq!(
            sa, sb,
            "numeric identities alone must not authorize a different table"
        );
        let allocation = actor_test_allocator::NoAlloc::start();
        let mut production = a.take_production(sa).unwrap();
        assert!(matches!(
            b.enqueue_prefix(&mut production, b"data", false),
            Err(Error::Binding)
        ));
        assert_eq!(
            a.enqueue_prefix(&mut production, b"data", false).unwrap(),
            4
        );
        assert_eq!(a.queued_chunks().unwrap(), 1);
        assert_eq!(b.queued_chunks().unwrap(), 0);
        allocation.finish();
    }

    #[test]
    fn three_streams_have_independent_windows_payloads_and_completion() {
        let scope = ApplicationKeyScope::new(13);
        let mut slots = [const { StreamSlot::<8>::EMPTY }; 3];
        let mut chunks = [const { SendChunk::<8>::EMPTY }; 3];
        let mut references = [PacketReference::EMPTY; 8];
        let mut core = StreamNumbers::new(
            &scope,
            Role::Server,
            Limits {
                max_data: 24,
                ..local(Role::Client)
            },
            Limits {
                max_data: 24,
                max_streams_bidi: 3,
                ..local(Role::Server)
            },
            &mut slots,
            &mut chunks,
            &mut references,
        )
        .unwrap();
        let Facets {
            mut app,
            mut rx,
            mut tx,
            mut publication,
            mut reset,
        } = core.split();
        // The highest incoming ID materializes the two implicit lower streams.
        for id in [8, 0, 4] {
            rx.apply(&Frame::Stream {
                id,
                offset: 0,
                fin: false,
                data: b"12345678",
            })
            .unwrap();
        }
        let handles = app.ready_streams().unwrap();
        let mut output = [0; 8];
        for stream in handles.into_iter().flatten() {
            assert_eq!(app.read(stream, &mut output).unwrap().len, 8);
            assert_eq!(&output, b"12345678");
        }
        let mut seen = [false; 3];
        for pn in 0..3 {
            let prepared = tx.prepare::<64>(false).unwrap().unwrap();
            let frames = packet::FrameIter::new(
                prepared.bytes(),
                packet::EncryptionLevel::OneRtt,
                packet::ParseLimits::default(),
            )
            .unwrap();
            for frame in frames {
                if let Frame::MaxStreamData { id, maximum } = frame.unwrap() {
                    assert_eq!(maximum, 16);
                    assert!(!seen[(id / 4) as usize]);
                    seen[(id / 4) as usize] = true;
                }
            }
            let reservation = tx.reserve_transmission(&prepared, pn).unwrap();
            publication.commit(reservation).unwrap();
        }
        assert_eq!(seen, [true; 3]);
        rx.core
            .numbers
            .borrow_mut()
            .acknowledge(&[packet(0), packet(1), packet(2)])
            .unwrap();
        assert!(tx.prepare::<64>(true).unwrap().is_none());
        for stream in handles.into_iter().flatten() {
            let data = [stream.id() as u8; 8];
            rx.apply(&Frame::Stream {
                id: stream.id(),
                offset: 8,
                fin: true,
                data: &data,
            })
            .unwrap();
            assert!(app.read(stream, &mut output).unwrap().fin);
            assert_eq!(output, data);
            let mut production = app.take_production(stream).unwrap();
            assert_eq!(
                app.enqueue_prefix(&mut production, &data, true).unwrap(),
                (&data).len()
            );
        }
        for pn in 3..6 {
            let prepared = tx.prepare::<64>(false).unwrap().unwrap();
            let reservation = tx.reserve_transmission(&prepared, pn).unwrap();
            publication.commit(reservation).unwrap();
        }
        rx.core
            .numbers
            .borrow_mut()
            .acknowledge(&[packet(3), packet(4), packet(5)])
            .unwrap();
        for stream in handles.into_iter().flatten() {
            assert!(!app.send_complete(stream).unwrap());
        }
        while let Some(receipt) = reset.take_delivery().unwrap() {
            tx.record_delivery(receipt).unwrap();
        }
        for stream in handles.into_iter().flatten() {
            assert!(app.send_complete(stream).unwrap());
            assert!(app.receive_complete(stream).unwrap());
        }
    }

    #[test]
    fn publication_cancel_loss_late_ack_and_send_completion() {
        let scope = ApplicationKeyScope::new(9);
        let mut slots = [StreamSlot::<8>::EMPTY];
        let mut chunks = [SendChunk::<8>::EMPTY];
        let mut references = [PacketReference::EMPTY; 4];
        let mut core = StreamNumbers::new(
            &scope,
            Role::Client,
            local(Role::Server),
            local(Role::Client),
            &mut slots,
            &mut chunks,
            &mut references,
        )
        .unwrap();
        let Facets {
            mut app,
            mut rx,
            mut tx,
            mut publication,
            mut reset,
        } = core.split();
        let stream = app.open_local().unwrap();
        let mut production = app.take_production(stream).unwrap();
        assert_eq!(
            app.enqueue_prefix(&mut production, b"GET /\r\n", true)
                .unwrap(),
            (b"GET /\r\n").len()
        );
        let bytes = tx.prepare::<64>(false).unwrap().unwrap();
        let reservation = tx.reserve_transmission(&bytes, 0).unwrap();
        publication.cancel(reservation).unwrap();
        assert!(!app.send_complete(stream).unwrap());
        let bytes = tx.prepare::<64>(false).unwrap().unwrap();
        let reservation = tx.reserve_transmission(&bytes, 1).unwrap();
        publication.commit(reservation).unwrap();
        assert!(tx.prepare::<64>(false).unwrap().is_none());
        tx.lost(1).unwrap();
        let retransmission = tx.prepare::<64>(false).unwrap().unwrap();
        assert_eq!(bytes.bytes(), retransmission.bytes());
        let reservation = tx.reserve_transmission(&retransmission, 2).unwrap();
        publication.commit(reservation).unwrap();
        rx.core
            .numbers
            .borrow_mut()
            .acknowledge(&[packet(1)])
            .unwrap();
        while let Some(receipt) = reset.take_delivery().unwrap() {
            tx.record_delivery(receipt).unwrap();
        }
        assert!(app.send_complete(stream).unwrap());
        assert_eq!(app.queued_chunks().unwrap(), 0);
        assert!(tx.prepare::<64>(true).unwrap().is_none());
    }

    #[test]
    fn consume_replenishes_credit_and_control_retransmits_until_ack() {
        let scope = ApplicationKeyScope::new(10);
        let mut slots = [StreamSlot::<8>::EMPTY];
        let mut chunks = [SendChunk::<8>::EMPTY];
        let mut references = [PacketReference::EMPTY; 4];
        let mut core = StreamNumbers::new(
            &scope,
            Role::Server,
            local(Role::Client),
            local(Role::Server),
            &mut slots,
            &mut chunks,
            &mut references,
        )
        .unwrap();
        let Facets {
            mut app,
            mut rx,
            mut tx,
            mut publication,
            mut reset,
        } = core.split();
        rx.apply(&Frame::Stream {
            id: 0,
            offset: 0,
            fin: false,
            data: b"abcdefgh",
        })
        .unwrap();
        let stream = app.readable_stream().unwrap().unwrap();
        let mut sink = [0; 8];
        assert_eq!(
            app.read(stream, &mut sink).unwrap(),
            Read {
                len: 8,
                fin: false,
                reset: None
            }
        );
        assert_eq!(&sink, b"abcdefgh");
        let update = tx.prepare::<64>(false).unwrap().unwrap();
        let expected = [
            Frame::MaxData { maximum: 16 },
            Frame::MaxStreamData { id: 0, maximum: 16 },
        ];
        let mut encoded = [0; 64];
        let mut len = 0;
        for frame in expected {
            len += packet::encode_frame(&frame, &mut encoded[len..]).unwrap();
        }
        assert_eq!(update.bytes(), &encoded[..len]);
        let reservation = tx.reserve_transmission(&update, 0).unwrap();
        publication.commit(reservation).unwrap();
        assert!(tx.prepare::<64>(false).unwrap().is_none());
        tx.lost(0).unwrap();
        let resend = tx.prepare::<64>(false).unwrap().unwrap();
        assert_eq!(update.bytes(), resend.bytes());
        let reservation = tx.reserve_transmission(&resend, 1).unwrap();
        publication.commit(reservation).unwrap();
        rx.core
            .numbers
            .borrow_mut()
            .acknowledge(&[packet(0)])
            .unwrap();
        assert!(tx.prepare::<64>(true).unwrap().is_none());
        rx.apply(&Frame::Stream {
            id: 0,
            offset: 8,
            fin: true,
            data: b"ijklmnop",
        })
        .unwrap();
        assert!(!app.receive_complete(stream).unwrap());
        assert!(app.read(stream, &mut sink).unwrap().fin);
        assert_eq!(&sink, b"ijklmnop");
        assert!(app.receive_complete(stream).unwrap());
    }

    #[test]
    fn stop_while_adapter_pending_settles_then_reliably_resets() {
        let scope = ApplicationKeyScope::new(11);
        let mut slots = [StreamSlot::<8>::EMPTY];
        let mut chunks = [SendChunk::<8>::EMPTY];
        let mut references = [PacketReference::EMPTY; 4];
        let mut core = StreamNumbers::new(
            &scope,
            Role::Client,
            local(Role::Server),
            local(Role::Client),
            &mut slots,
            &mut chunks,
            &mut references,
        )
        .unwrap();
        let Facets {
            mut app,
            mut rx,
            mut tx,
            mut publication,
            mut reset,
        } = core.split();
        let stream = app.open_local().unwrap();
        let mut production = app.take_production(stream).unwrap();
        assert_eq!(
            app.enqueue_prefix(&mut production, b"hello", false)
                .unwrap(),
            (b"hello").len()
        );
        let prepared = tx.prepare::<64>(false).unwrap().unwrap();
        let reservation = tx.reserve_transmission(&prepared, 0).unwrap();
        let intent = rx.stop_intent(0, 7).unwrap();
        assert!(tx.prepare::<64>(false).unwrap().is_none());
        publication.commit(reservation).unwrap();
        assert!(
            tx.prepare::<64>(false).unwrap().is_none(),
            "adapter completion must not secretly apply the stop observation"
        );
        reset.apply(intent).unwrap();
        let reset_frame = tx.prepare::<64>(false).unwrap().unwrap();
        let mut encoded = [0; 64];
        let len = packet::encode_frame(
            &Frame::ResetStream {
                id: 0,
                error_code: 7,
                final_size: 5,
            },
            &mut encoded,
        )
        .unwrap();
        assert_eq!(reset_frame.bytes(), &encoded[..len]);
        let reservation = tx.reserve_transmission(&reset_frame, 1).unwrap();
        publication.commit(reservation).unwrap();
        assert!(!app.send_complete(stream).unwrap());
        rx.core
            .numbers
            .borrow_mut()
            .acknowledge(&[packet(1)])
            .unwrap();
        while let Some(receipt) = reset.take_delivery().unwrap() {
            tx.record_delivery(receipt).unwrap();
        }
        assert!(app.send_complete(stream).unwrap());
    }

    #[test]
    fn stream_limits_and_non_application_ack_are_rejected() {
        let scope = ApplicationKeyScope::new(12);
        let mut slots = [StreamSlot::<8>::EMPTY];
        let mut chunks = [SendChunk::<8>::EMPTY];
        let mut references = [PacketReference::EMPTY; 4];
        let mut core = StreamNumbers::new(
            &scope,
            Role::Server,
            local(Role::Client),
            local(Role::Server),
            &mut slots,
            &mut chunks,
            &mut references,
        )
        .unwrap();
        let Facets { mut rx, .. } = core.split();
        assert_eq!(
            rx.apply(&Frame::Stream {
                id: 4,
                offset: 0,
                fin: true,
                data: b"x"
            }),
            Err(Error::Streams(streams::Error::StreamLimit))
        );
        assert_eq!(
            rx.core
                .numbers
                .borrow_mut()
                .acknowledge(&[Some(PacketNumber {
                    space: PacketNumberSpace::Handshake,
                    value: 0
                })]),
            Err(Error::Binding)
        );
    }
    #[test]
    fn fin_delivery_waits_for_all_bytes_then_moves_once_to_the_observer() {
        let scope = ApplicationKeyScope::new(990);
        let mut slots = [StreamSlot::<8>::EMPTY];
        let mut chunks = [SendChunk::<8>::EMPTY; 2];
        let mut references = [PacketReference::EMPTY; 4];
        let mut core = StreamNumbers::new(
            &scope,
            Role::Client,
            local(Role::Server),
            local(Role::Client),
            &mut slots,
            &mut chunks,
            &mut references,
        )
        .unwrap();
        let Facets {
            mut app,
            mut rx,
            mut tx,
            mut publication,
            reset: mut effects,
        } = core.split();
        let stream = app.open_local().unwrap();
        let mut source = app.take_production(stream).unwrap();
        let allocation = actor_test_allocator::NoAlloc::start();
        app.enqueue_prefix(&mut source, b"abc", false).unwrap();
        app.enqueue_prefix(&mut source, b"", true).unwrap();
        for pn in 0..2 {
            let prepared = tx.prepare::<64>(false).unwrap().unwrap();
            let reservation = tx.reserve_transmission(&prepared, pn).unwrap();
            publication.commit(reservation).unwrap();
        }
        rx.core
            .numbers
            .borrow_mut()
            .acknowledge(&[packet(1)])
            .unwrap();
        assert!(effects.take_delivery().unwrap().is_none());
        assert!(!app.send_complete(stream).unwrap());
        rx.core
            .numbers
            .borrow_mut()
            .acknowledge(&[packet(0)])
            .unwrap();
        let receipt = effects.take_delivery().unwrap().unwrap();
        assert!(effects.take_delivery().unwrap().is_none());
        assert!(
            !app.send_complete(stream).unwrap(),
            "taking evidence does not mean the projected consumer received it"
        );
        tx.record_delivery(receipt).unwrap();
        assert!(app.send_complete(stream).unwrap());
        effects
            .apply(rx.stop_intent(stream.id(), 9).unwrap())
            .unwrap();
        assert!(
            tx.prepare::<64>(false).unwrap().is_none(),
            "late STOP cannot reopen a completed production"
        );
        assert!(effects.take_delivery().unwrap().is_none());
        allocation.finish();
    }
    #[test]
    fn delivered_receipt_cannot_cross_actual_tables() {
        let scope = ApplicationKeyScope::new(991);
        let mut sa = [StreamSlot::<8>::EMPTY];
        let mut ca = [SendChunk::<8>::EMPTY];
        let mut ra = [PacketReference::EMPTY; 2];
        let mut sb = [StreamSlot::<8>::EMPTY];
        let mut cb = [SendChunk::<8>::EMPTY];
        let mut rb = [PacketReference::EMPTY; 2];
        let mut a = StreamNumbers::new(
            &scope,
            Role::Client,
            local(Role::Server),
            local(Role::Client),
            &mut sa,
            &mut ca,
            &mut ra,
        )
        .unwrap();
        let mut b = StreamNumbers::new(
            &scope,
            Role::Client,
            local(Role::Server),
            local(Role::Client),
            &mut sb,
            &mut cb,
            &mut rb,
        )
        .unwrap();
        let Facets {
            mut app,
            rx,
            mut tx,
            mut publication,
            reset: mut effects,
        } = a.split();
        let Facets {
            app: mut other_app,
            tx: mut other_tx,
            ..
        } = b.split();
        let stream = app.open_local().unwrap();
        assert_eq!(stream, other_app.open_local().unwrap());
        let mut source = app.take_production(stream).unwrap();
        let allocation = actor_test_allocator::NoAlloc::start();
        app.enqueue_prefix(&mut source, b"", true).unwrap();
        let prepared = tx.prepare::<64>(false).unwrap().unwrap();
        let reservation = tx.reserve_transmission(&prepared, 0).unwrap();
        publication.commit(reservation).unwrap();
        rx.core
            .numbers
            .borrow_mut()
            .acknowledge(&[packet(0)])
            .unwrap();
        let receipt = effects.take_delivery().unwrap().unwrap();
        assert_eq!(other_tx.record_delivery(receipt), Err(Error::Binding));
        assert!(!app.send_complete(stream).unwrap());
        assert!(!other_app.send_complete(stream).unwrap());
        assert!(effects.take_delivery().unwrap().is_none());
        allocation.finish();
    }
}
