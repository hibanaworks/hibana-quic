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
    streams::{self, ChunkHandle, Limits, PacketReference, Role, SendChunk, SendQueue,
        StreamHandle, StreamSlot, StreamTable},
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
    fn from(value: streams::Error) -> Self { Self::Streams(value) }
}
impl From<packet::Error> for Error {
    fn from(value: packet::Error) -> Self { Self::Packet(value) }
}

struct Identity { generation: u64 }

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
        if slots.len() > MAX_LIVE_STREAMS { return Err(Error::Capacity); }
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
                streams: [StreamState::EMPTY; MAX_LIVE_STREAMS],
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
        }
    }

    pub const fn scope(&self) -> &'scope ApplicationKeyScope { self.scope }
}

pub struct Facets<'book, 'storage, 'scope, const RX: usize, const CHUNK: usize> {
    pub app: App<'book, 'storage, 'scope, RX, CHUNK>,
    pub rx: Rx<'book, 'storage, 'scope, RX, CHUNK>,
    pub tx: Tx<'book, 'storage, 'scope, RX, CHUNK>,
    pub publication: Publication<'book, 'storage, 'scope, RX, CHUNK>,
}

pub struct App<'book, 'storage, 'scope, const RX: usize, const CHUNK: usize> {
    core: &'book StreamNumbers<'storage, 'scope, RX, CHUNK>,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Read {
    pub len: usize,
    /// All bytes through FIN have been copied into the application's sink.
    pub fin: bool,
    pub reset: Option<u64>,
}

impl<const RX: usize, const CHUNK: usize> App<'_, '_, '_, RX, CHUNK> {
    /// Open a locally initiated bidirectional stream using authenticated peer credit.
    pub fn open_local(&mut self) -> Result<StreamHandle, Error> {
        let mut n = self.core.numbers.try_borrow_mut().map_err(|_| Error::Borrowed)?;
        let stream = n.table.open_local(true)?;
        n.register(stream)?;
        Ok(stream)
    }

    /// Copy one complete retransmittable chunk. Backpressure leaves its bytes
    /// with the caller; stream handles retain the table's generation binding.
    pub fn enqueue(&mut self, stream: StreamHandle, bytes: &[u8], fin: bool) -> Result<(), Error> {
        let mut n = self.core.numbers.try_borrow_mut().map_err(|_| Error::Borrowed)?;
        if n.state(stream)?.deferred_stop.is_some() { return Err(streams::Error::SendClosed.into()); }
        let Numbers { table, queue, .. } = &mut *n;
        queue.enqueue(table, stream, bytes, fin)?;
        Ok(())
    }

    /// Admit at most one chunk and the available peer credit. FIN is attached
    /// only when the complete supplied suffix fits.
    pub fn enqueue_prefix(&mut self, stream: StreamHandle, bytes: &[u8], fin: bool) -> Result<usize, Error> {
        let mut n = self.core.numbers.try_borrow_mut().map_err(|_| Error::Borrowed)?;
        if n.state(stream)?.deferred_stop.is_some() { return Err(streams::Error::SendClosed.into()); }
        let credit = n.table.send_credit(stream)?;
        let len = bytes.len().min(CHUNK).min(
            usize::try_from(credit.connection_available.min(credit.stream_available))
                .unwrap_or(usize::MAX),
        );
        if len == 0 && !bytes.is_empty() { return Err(streams::Error::FlowControl.into()); }
        let Numbers { table, queue, .. } = &mut *n;
        queue.enqueue(table, stream, &bytes[..len], fin && len == bytes.len())?;
        Ok(len)
    }

    /// Copy and consume a contiguous prefix without exposing a borrowed view.
    /// Freed storage schedules reliable MAX_DATA/MAX_STREAM_DATA updates.
    pub fn read(&mut self, stream: StreamHandle, output: &mut [u8]) -> Result<Read, Error> {
        let mut n = self.core.numbers.try_borrow_mut().map_err(|_| Error::Borrowed)?;
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
        if reset.is_some() { n.table.acknowledge_received_reset(stream)?; }
        if len != 0 || reset.is_some() { n.replenish_credit(stream)?; }
        Ok(Read { len, fin, reset })
    }

    /// Owned handles only: no table/view borrow crosses the caller's await.
    /// A consumed FIN/reset remains observable until the application retires it.
    pub fn ready_streams(&self) -> Result<[Option<StreamHandle>; MAX_LIVE_STREAMS], Error> {
        let n = self.core.numbers.try_borrow().map_err(|_| Error::Borrowed)?;
        let mut ready = [None; MAX_LIVE_STREAMS];
        let mut count = 0;
        for stream in n.table.live_handles() {
            let view = n.table.receive(stream)?;
            if !view.first.is_empty() || !view.second.is_empty() || view.fin || view.reset.is_some() {
                ready[count] = Some(stream);
                count += 1;
            }
        }
        Ok(ready)
    }

    pub fn readable_stream(&self) -> Result<Option<StreamHandle>, Error> {
        Ok(self.ready_streams()?.into_iter().flatten().next())
    }

    pub fn send_complete(&self, stream: StreamHandle) -> Result<bool, Error> {
        let n = self.core.numbers.try_borrow().map_err(|_| Error::Borrowed)?;
        Ok(n.table.sending_complete(stream)?)
    }

    pub fn receive_complete(&self, stream: StreamHandle) -> Result<bool, Error> {
        let n = self.core.numbers.try_borrow().map_err(|_| Error::Borrowed)?;
        let view = n.table.receive(stream)?;
        Ok(view.reset.is_some() || (view.fin && view.first.is_empty() && view.second.is_empty()))
    }

    pub fn queued_chunks(&self) -> Result<usize, Error> {
        let n = self.core.numbers.try_borrow().map_err(|_| Error::Borrowed)?;
        Ok(n.queue.queued_chunks())
    }
}

impl<const RX: usize, const CHUNK: usize> Rx<'_, '_, '_, RX, CHUNK> {
    /// The caller is the authenticated connection receive continuation, after
    /// whole-packet AEAD/frame/recovery validation. An arbitrary public caller
    /// cannot feed frames directly into this producer boundary.
    pub(super) fn apply(&mut self, frame: &Frame<'_>) -> Result<(), Error> {
        let mut n = self.core.numbers.try_borrow_mut().map_err(|_| Error::Borrowed)?;
        match *frame {
            Frame::Stream { id, offset, fin, data } => {
                let stream = n.accept_stream(id)?;
                n.table.on_stream(stream, offset, data, fin)?;
            }
            Frame::ResetStream { id, error_code, final_size } => {
                let stream = n.accept_stream(id)?;
                n.table.on_reset(stream, error_code, final_size)?;
            }
            Frame::StopSending { id, error_code } => {
                let stream = n.accept_stream(id)?;
                if error_code > streams::MAX_OFFSET { return Err(streams::Error::InvalidId.into()); }
                // Actual publication may be awaiting the adapter. Keep its
                // reservation valid, then reset as soon as it is settled.
                n.state_mut(stream)?.deferred_stop.get_or_insert(error_code);
                n.apply_stop(stream)?;
            }
            Frame::MaxData { maximum } => n.table.on_max_data(maximum)?,
            Frame::MaxStreamData { id, maximum } => {
                let stream = n.accept_stream(id)?;
                n.table.on_max_stream_data(stream, maximum)?;
            }
            Frame::MaxStreams { bidirectional, maximum } => {
                n.table.on_max_streams(bidirectional, maximum)?;
            }
            Frame::StreamDataBlocked { id, .. } => { n.accept_stream(id)?; }
            Frame::DataBlocked { .. } | Frame::StreamsBlocked { .. } => {},
            _ => return Err(Error::UnsupportedFrame),
        }
        Ok(())
    }

    /// Only actual newly acknowledged packet numbers returned by Recovery may
    /// enter here. The stream queue never interprets unvalidated ACK ranges.
    pub(super) fn acknowledge(&mut self, packets: &[Option<PacketNumber>]) -> Result<(), Error> {
        if packets.iter().flatten().any(|pn| pn.space != PacketNumberSpace::ApplicationData) {
            return Err(Error::Binding);
        }
        let contains = |pn| packets.iter().flatten().any(|packet| packet.value == pn);
        let mut n = self.core.numbers.try_borrow_mut().map_err(|_| Error::Borrowed)?;
        if n.controls.iter().any(|r| r.state == ReferenceState::Reserved && contains(r.packet)) {
            return Err(streams::Error::UnsentAcknowledgment.into());
        }
        let Numbers { table, queue, .. } = &mut *n;
        queue.on_packets_acked(table, contains)?;
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

    pub(super) fn lost(&mut self, packet_number: u64) -> Result<(), Error> {
        let mut n = self.core.numbers.try_borrow_mut().map_err(|_| Error::Borrowed)?;
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
        let mut n = self.core.numbers.try_borrow_mut().map_err(|_| Error::Borrowed)?;
        let Numbers { table, queue, .. } = &mut *n;
        queue.forget_lost_packet(table, packet_number)?;
        for r in &mut n.controls {
            if r.packet == packet_number && r.state == ReferenceState::Lost {
                r.state = ReferenceState::Free;
            }
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
    pub fn bytes(&self) -> &[u8] { &self.bytes[..self.len] }
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
    pub fn packet_number(&self) -> u64 { self.packet_number }
}

impl<'book, const RX: usize, const CHUNK: usize> Tx<'book, '_, '_, RX, CHUNK> {
    /// Prefer a pending STREAM chunk; on a PTO an outstanding range may be
    /// copied under a fresh packet number without declaring the old copy lost.
    /// Dirty control limits/reset are encoded before the chunk. A caller may
    /// prepend/append its own recovery-produced ACK when composing plaintext.
    pub fn prepare<const N: usize>(&self, probe: bool) -> Result<Option<Prepared<'book, N>>, Error> {
        let n = self.core.numbers.try_borrow().map_err(|_| Error::Borrowed)?;
        let chunk = n.queue.next_pending()
            .or_else(|| if probe { n.queue.probe_chunk() } else { None });
        let chunk = match chunk {
            Some(chunk) if n.state(n.queue.chunk(chunk)?.stream)?.deferred_stop.is_some() => None,
            other => other,
        };
        let controls = n.next_controls(probe);
        if chunk.is_none() && controls.is_empty() { return Ok(None); }
        let mut prepared = Prepared {
            identity: &self.core.identity, bytes: [0; N], len: 0, chunk, controls,
        };
        if let Some(maximum) = controls.max_data {
            prepared.append(&Frame::MaxData { maximum })?;
        }
        if let Some((stream, maximum)) = controls.max_stream_data {
            prepared.append(&Frame::MaxStreamData { id: stream.id(), maximum })?;
        }
        if let Some((_, reset)) = controls.reset {
            prepared.append(&Frame::ResetStream { id: reset.id, error_code: reset.error_code,
                final_size: reset.final_size })?;
        }
        if let Some(chunk) = chunk {
            let view = n.queue.chunk(chunk)?;
            prepared.append(&Frame::Stream { id: view.stream.id(), offset: view.offset,
                fin: view.fin, data: view.data })?;
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
        { return Err(Error::Binding); }
        let mut n = self.core.numbers.try_borrow_mut().map_err(|_| Error::Borrowed)?;
        if n.controls.iter().any(|r| r.state != ReferenceState::Free && r.packet == packet_number) {
            return Err(Error::Binding);
        }
        let control = if prepared.controls.is_empty() { None } else {
            Some(n.controls.iter().position(|r| r.state == ReferenceState::Free && r.generation != u64::MAX)
                .ok_or(Error::Capacity)?)
        };
        let stream = match prepared.chunk {
            Some(chunk) => {
                let handle = n.queue.chunk(chunk)?.stream;
                if n.state(handle)?.deferred_stop.is_some() { return Err(streams::Error::SendClosed.into()); }
                let reference = n.queue.reserve_transmission(chunk, packet_number)?;
                n.state_mut(handle)?.reserved_chunks += 1;
                Some((handle, reference))
            }
            None => None,
        };
        let control = control.map(|slot| {
            let generation = n.controls[slot].generation + 1;
            n.controls[slot] = ControlReference { generation, packet: packet_number,
                state: ReferenceState::Reserved, contents: prepared.controls };
            (slot, generation)
        });
        Ok(Transmission { identity: &self.core.identity, packet_number, stream, control })
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
        if !core::ptr::eq(transmission.identity, &self.core.identity) { return Err(Error::Binding); }
        let mut n = self.core.numbers.try_borrow_mut().map_err(|_| Error::Borrowed)?;
        if let Some((slot, generation)) = transmission.control {
            let r = n.controls.get(slot).ok_or(Error::Binding)?;
            if r.generation != generation || r.state != ReferenceState::Reserved
                || r.packet != transmission.packet_number { return Err(Error::Binding); }
        }
        if let Some((stream, reference)) = transmission.stream {
            let Numbers { table, queue, .. } = &mut *n;
            if published { queue.commit_transmission(table, reference)?; }
            else { queue.cancel_transmission(table, reference)?; }
            n.state_mut(stream)?.reserved_chunks -= 1;
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
                    n.table.reset_transmitted(stream)?;
                    n.state_mut(stream)?.reset_pending = false;
                    n.control_cursor = (stream.slot() + 1) % MAX_LIVE_STREAMS;
                }
            } else {
                n.controls[slot].state = ReferenceState::Free;
            }
        }
        if let Some((stream, _)) = transmission.stream { n.apply_stop(stream)?; }
        n.collect_controls();
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Credit { current: u64, acknowledged: u64, pending: bool }
impl Credit {
    const fn new(initial: u64) -> Self { Self { current: initial, acknowledged: initial, pending: false } }
    fn update(&mut self, maximum: u64) {
        if maximum > self.current { self.current = maximum; self.pending = true; }
    }
    fn next(self, probe: bool) -> Option<u64> {
        if self.pending || (probe && self.current > self.acknowledged) { Some(self.current) } else { None }
    }
    fn published(&mut self, value: Option<u64>) {
        if value == Some(self.current) { self.pending = false; }
    }
    fn acknowledge(&mut self, value: Option<u64>) {
        if let Some(value) = value { self.acknowledged = self.acknowledged.max(value); }
        if self.acknowledged >= self.current { self.pending = false; }
    }
    fn retry(&mut self, value: Option<u64>) {
        if value.is_some_and(|v| v > self.acknowledged) { self.pending = true; }
    }
}

#[derive(Clone, Copy)]
struct Controls { max_data: Option<u64>, max_stream_data: Option<(StreamHandle, u64)>, reset: Option<(StreamHandle, streams::Reset)> }
impl Controls {
    const EMPTY: Self = Self { max_data: None, max_stream_data: None, reset: None };
    fn is_empty(self) -> bool { self.max_data.is_none() && self.max_stream_data.is_none() && self.reset.is_none() }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum ReferenceState { Free, Reserved, Sent, Lost }
#[derive(Clone, Copy)]
struct ControlReference { generation: u64, packet: u64, state: ReferenceState, contents: Controls }
impl ControlReference {
    const EMPTY: Self = Self { generation: 0, packet: 0, state: ReferenceState::Free, contents: Controls::EMPTY };
}
#[derive(Clone, Copy)]
struct StreamState {
    handle: Option<StreamHandle>,
    credit: Credit,
    reset: Option<streams::Reset>,
    reset_pending: bool,
    reset_acked: bool,
    deferred_stop: Option<u64>,
    reserved_chunks: usize,
}
impl StreamState {
    const EMPTY: Self = Self { handle: None, credit: Credit::new(0), reset: None,
        reset_pending: false, reset_acked: false, deferred_stop: None, reserved_chunks: 0 };
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
        if state.handle != Some(stream) { return Err(streams::Error::StaleHandle.into()); }
        Ok(state)
    }
    fn state_mut(&mut self, stream: StreamHandle) -> Result<&mut StreamState, Error> {
        let state = self.streams.get_mut(stream.slot()).ok_or(Error::Binding)?;
        if state.handle != Some(stream) { return Err(streams::Error::StaleHandle.into()); }
        Ok(state)
    }
    fn register(&mut self, stream: StreamHandle) -> Result<(), Error> {
        if self.streams[stream.slot()].handle == Some(stream) { return Ok(()); }
        let local = self.table.local_limits();
        let local_bit = u64::from(self.role == Role::Server);
        let locally_initiated = stream.id() & 1 == local_bit;
        let maximum = if stream.id() & 2 != 0 {
            if locally_initiated { 0 } else { local.stream_data_uni }
        } else if locally_initiated { local.stream_data_bidi_local }
        else { local.stream_data_bidi_remote };
        self.streams[stream.slot()] = StreamState { handle: Some(stream),
            credit: Credit::new(maximum), ..StreamState::EMPTY };
        Ok(())
    }
    fn accept_stream(&mut self, id: u64) -> Result<StreamHandle, Error> {
        let stream = self.table.get_or_accept(id)?;
        // Implicit lower peer streams also get real per-slot control metadata.
        let mut handles = [None; MAX_LIVE_STREAMS];
        for (slot, h) in handles.iter_mut().zip(self.table.live_handles()) { *slot = Some(h); }
        for handle in handles.into_iter().flatten() { self.register(handle)?; }
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
    fn apply_stop(&mut self, stream: StreamHandle) -> Result<(), Error> {
        if self.state(stream)?.reserved_chunks != 0 { return Ok(()); }
        if let Some(error) = self.state(stream)?.deferred_stop {
            if let Some(reset) = self.queue.reset(&mut self.table, stream, error)? {
                let state = self.state_mut(stream)?;
                if state.reset.is_none() { state.reset = Some(reset); state.reset_pending = true; }
            }
            self.state_mut(stream)?.deferred_stop = None;
        }
        Ok(())
    }
    fn next_controls(&self, probe: bool) -> Controls {
        let mut controls = Controls { max_data: self.data_credit.next(probe), ..Controls::EMPTY };
        for offset in 0..MAX_LIVE_STREAMS {
            let state = self.streams[(self.control_cursor + offset) % MAX_LIVE_STREAMS];
            let Some(stream) = state.handle else { continue; };
            if controls.max_stream_data.is_none() {
                controls.max_stream_data = state.credit.next(probe).map(|maximum| (stream, maximum));
            }
            if controls.reset.is_none() && (state.reset_pending || (probe && !state.reset_acked)) {
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
            if self.state(stream)?.reset != Some(reset) { return Err(Error::Binding); }
            self.table.reset_acknowledged(stream)?;
            let state = self.state_mut(stream)?;
            state.reset_acked = true;
            state.reset_pending = false;
        }
        Ok(())
    }
    fn retry_control(&mut self, contents: Controls) {
        self.data_credit.retry(contents.max_data);
        if let Some((stream, maximum)) = contents.max_stream_data {
            if let Ok(state) = self.state_mut(stream) { state.credit.retry(Some(maximum)); }
        }
        if let Some((stream, _)) = contents.reset {
            if let Ok(state) = self.state_mut(stream) {
                if !state.reset_acked { state.reset_pending = true; }
            }
        }
    }
    fn collect_controls(&mut self) {
        for index in 0..CONTROL_CAPACITY {
            let r = self.controls[index];
            if matches!(r.state, ReferenceState::Sent | ReferenceState::Lost)
                && r.contents.max_data.is_none_or(|v| v <= self.data_credit.acknowledged)
                && r.contents.max_stream_data.is_none_or(|(stream, maximum)|
                    self.state(stream).is_ok_and(|s| maximum <= s.credit.acknowledged))
                && r.contents.reset.is_none_or(|(stream, _)| self.state(stream).is_ok_and(|s| s.reset_acked))
            { self.controls[index].state = ReferenceState::Free; }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local(role: Role) -> Limits {
        Limits { max_data: 8, max_streams_bidi: u64::from(role == Role::Server),
            stream_data_bidi_local: 8, stream_data_bidi_remote: 8, ..Limits::ZERO }
    }
    fn packet(pn: u64) -> Option<PacketNumber> {
        Some(PacketNumber { space: PacketNumberSpace::ApplicationData, value: pn })
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
            Limits { max_data: 24, ..local(Role::Client) },
            Limits { max_data: 24, max_streams_bidi: 3, ..local(Role::Server) },
            &mut slots,
            &mut chunks,
            &mut references,
        ).unwrap();
        let Facets { mut app, mut rx, mut tx, mut publication } = core.split();
        // The highest incoming ID materializes the two implicit lower streams.
        for id in [8, 0, 4] {
            rx.apply(&Frame::Stream { id, offset: 0, fin: false, data: b"12345678" }).unwrap();
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
            let frames = packet::FrameIter::new(prepared.bytes(), packet::EncryptionLevel::OneRtt,
                packet::ParseLimits::default()).unwrap();
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
        rx.acknowledge(&[packet(0), packet(1), packet(2)]).unwrap();
        assert!(tx.prepare::<64>(true).unwrap().is_none());
        for stream in handles.into_iter().flatten() {
            let data = [stream.id() as u8; 8];
            rx.apply(&Frame::Stream { id: stream.id(), offset: 8, fin: true, data: &data }).unwrap();
            assert!(app.read(stream, &mut output).unwrap().fin);
            assert_eq!(output, data);
            app.enqueue(stream, &data, true).unwrap();
        }
        for pn in 3..6 {
            let prepared = tx.prepare::<64>(false).unwrap().unwrap();
            let reservation = tx.reserve_transmission(&prepared, pn).unwrap();
            publication.commit(reservation).unwrap();
        }
        rx.acknowledge(&[packet(3), packet(4), packet(5)]).unwrap();
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
        let mut core = StreamNumbers::new(&scope, Role::Client, local(Role::Server),
            local(Role::Client), &mut slots, &mut chunks, &mut references).unwrap();
        let Facets { mut app, mut rx, mut tx, mut publication } = core.split();
        let stream = app.open_local().unwrap();
        app.enqueue(stream, b"GET /\r\n", true).unwrap();
        let bytes = tx.prepare::<64>(false).unwrap().unwrap();
        let reservation = tx.reserve_transmission(&bytes, 0).unwrap();
        publication.cancel(reservation).unwrap();
        assert!(!app.send_complete(stream).unwrap());
        let bytes = tx.prepare::<64>(false).unwrap().unwrap();
        let reservation = tx.reserve_transmission(&bytes, 1).unwrap();
        publication.commit(reservation).unwrap();
        assert!(tx.prepare::<64>(false).unwrap().is_none());
        rx.lost(1).unwrap();
        let retransmission = tx.prepare::<64>(false).unwrap().unwrap();
        assert_eq!(bytes.bytes(), retransmission.bytes());
        let reservation = tx.reserve_transmission(&retransmission, 2).unwrap();
        publication.commit(reservation).unwrap();
        rx.acknowledge(&[packet(1)]).unwrap();
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
        let mut core = StreamNumbers::new(&scope, Role::Server, local(Role::Client),
            local(Role::Server), &mut slots, &mut chunks, &mut references).unwrap();
        let Facets { mut app, mut rx, mut tx, mut publication } = core.split();
        rx.apply(&Frame::Stream { id: 0, offset: 0, fin: false, data: b"abcdefgh" }).unwrap();
        let stream = app.readable_stream().unwrap().unwrap();
        let mut sink = [0; 8];
        assert_eq!(app.read(stream, &mut sink).unwrap(), Read { len: 8, fin: false, reset: None });
        assert_eq!(&sink, b"abcdefgh");
        let update = tx.prepare::<64>(false).unwrap().unwrap();
        let expected = [Frame::MaxData { maximum: 16 }, Frame::MaxStreamData { id: 0, maximum: 16 }];
        let mut encoded = [0; 64];
        let mut len = 0;
        for frame in expected { len += packet::encode_frame(&frame, &mut encoded[len..]).unwrap(); }
        assert_eq!(update.bytes(), &encoded[..len]);
        let reservation = tx.reserve_transmission(&update, 0).unwrap();
        publication.commit(reservation).unwrap();
        assert!(tx.prepare::<64>(false).unwrap().is_none());
        rx.lost(0).unwrap();
        let resend = tx.prepare::<64>(false).unwrap().unwrap();
        assert_eq!(update.bytes(), resend.bytes());
        let reservation = tx.reserve_transmission(&resend, 1).unwrap();
        publication.commit(reservation).unwrap();
        rx.acknowledge(&[packet(0)]).unwrap();
        assert!(tx.prepare::<64>(true).unwrap().is_none());
        rx.apply(&Frame::Stream { id: 0, offset: 8, fin: true, data: b"ijklmnop" }).unwrap();
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
        let mut core = StreamNumbers::new(&scope, Role::Client, local(Role::Server),
            local(Role::Client), &mut slots, &mut chunks, &mut references).unwrap();
        let Facets { mut app, mut rx, mut tx, mut publication } = core.split();
        let stream = app.open_local().unwrap();
        app.enqueue(stream, b"hello", false).unwrap();
        let prepared = tx.prepare::<64>(false).unwrap().unwrap();
        let reservation = tx.reserve_transmission(&prepared, 0).unwrap();
        rx.apply(&Frame::StopSending { id: 0, error_code: 7 }).unwrap();
        assert!(tx.prepare::<64>(false).unwrap().is_none());
        publication.commit(reservation).unwrap();
        let reset = tx.prepare::<64>(false).unwrap().unwrap();
        let mut encoded = [0; 64];
        let len = packet::encode_frame(&Frame::ResetStream { id: 0, error_code: 7,
            final_size: 5 }, &mut encoded).unwrap();
        assert_eq!(reset.bytes(), &encoded[..len]);
        let reservation = tx.reserve_transmission(&reset, 1).unwrap();
        publication.commit(reservation).unwrap();
        assert!(!app.send_complete(stream).unwrap());
        rx.acknowledge(&[packet(1)]).unwrap();
        assert!(app.send_complete(stream).unwrap());
    }

    #[test]
    fn stream_limits_and_non_application_ack_are_rejected() {
        let scope = ApplicationKeyScope::new(12);
        let mut slots = [StreamSlot::<8>::EMPTY];
        let mut chunks = [SendChunk::<8>::EMPTY];
        let mut references = [PacketReference::EMPTY; 4];
        let mut core = StreamNumbers::new(&scope, Role::Server, local(Role::Client),
            local(Role::Server), &mut slots, &mut chunks, &mut references).unwrap();
        let Facets { mut rx, .. } = core.split();
        assert_eq!(rx.apply(&Frame::Stream { id: 4, offset: 0, fin: true, data: b"x" }),
            Err(Error::Streams(streams::Error::StreamLimit)));
        assert_eq!(rx.acknowledge(&[Some(PacketNumber { space: PacketNumberSpace::Handshake,
            value: 0 })]), Err(Error::Binding));
    }
}
