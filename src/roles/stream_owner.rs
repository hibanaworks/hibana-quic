//! Actual application ownership over projected stream roles.
//!
//! The owner holds the StreamTable, SendQueue, reliable controls, and optional
//! early request journal for its entire lifetime. Request/reply arenas contain
//! owned bounded values, never a borrowed mutable table. Authentication grants
//! bind their actual frame; accepted ACK grants originate in Recovery.
use super::{packet_authority, packet_protection::Descriptor, protocol_stream as p};
use crate::{
    accounting::PacketNumberSpace,
    early_send,
    mailbox::{Receiver, Sender},
    packet::{self, Frame},
    runtime,
    streams::{
        self, ChunkHandle, Limits, PacketReference, Role, SendChunk, SendQueue, StreamHandle,
        StreamSlot, StreamTable, Transmission,
    },
};
use core::cell::RefCell;
use hibana::{Endpoint, EndpointError};
use zeroize::Zeroize;
mod controls;
use controls::*;

/// Bounded owned bytes, independent of owner/arena borrows.
#[derive(Debug)]
pub struct Bytes<const N: usize> {
    bytes: [u8; N],
    len: usize,
}
impl<const N: usize> Bytes<N> {
    pub fn new(input: &[u8]) -> Result<Self, Fault> {
        if input.len() > N {
            return Err(Fault::Capacity);
        }
        let mut result = Self {
            bytes: [0; N],
            len: input.len(),
        };
        result.bytes[..input.len()].copy_from_slice(input);
        Ok(result)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
impl<const N: usize> Drop for Bytes<N> {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Distinct affine grants minted by the authenticated connection coordinator.
pub use super::connection_authority::{AppReady as PeerReady, EarlyReady};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
    Streams(streams::Error),
    Wire(packet::Error),
    Early(early_send::Error),
    Authority(packet_authority::Error),
    Busy,
    NotReady,
    Capacity,
    Stale,
    WrongGeneration,
    WrongSpace,
    SequenceExhausted,
}
impl From<streams::Error> for Fault {
    fn from(e: streams::Error) -> Self {
        Self::Streams(e)
    }
}
impl From<packet::Error> for Fault {
    fn from(e: packet::Error) -> Self {
        Self::Wire(e)
    }
}
impl From<early_send::Error> for Fault {
    fn from(e: early_send::Error) -> Self {
        Self::Early(e)
    }
}
impl From<packet_authority::Error> for Fault {
    fn from(e: packet_authority::Error) -> Self {
        Self::Authority(e)
    }
}

/// IDs may be retained for adapter callbacks; the owner verifies the entire live
/// reservation. Replaying an old ID cannot reserve or settle a later frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedId {
    generation: u64,
    sequence: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransmissionId {
    prepared: PreparedId,
    packet: u64,
}
impl TransmissionId {
    pub const fn prepared_id(self) -> PreparedId {
        self.prepared
    }
    pub const fn generation(self) -> u64 {
        self.prepared.generation
    }
    pub const fn packet_number(self) -> u64 {
        self.packet
    }
}
pub struct PreparedFrame<const N: usize> {
    id: PreparedId,
    bytes: Bytes<N>,
    early: bool,
    probe: bool,
}
impl<const N: usize> PreparedFrame<N> {
    pub const fn id(&self) -> PreparedId {
        self.id
    }
    pub fn bytes(&self) -> &[u8] {
        self.bytes.as_bytes()
    }
    pub const fn is_early(&self) -> bool {
        self.early
    }
    pub const fn is_probe(&self) -> bool {
        self.probe
    }
}
pub struct ReadResult<const N: usize> {
    pub bytes: Bytes<N>,
    pub fin: bool,
    pub reset: Option<u64>,
    pub remaining: usize,
}

pub const MAX_STREAM_VIEWS: usize = 32;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub ready: bool,
    pub closed: bool,
    pub pending_transmission: bool,
    pub live_count: usize,
    pub queued_chunks: usize,
    pub send_references: usize,
    pub control_count: usize,
    pub early_intent: bool,
    pub early_import_required: bool,
    pub probe_budget: u8,
    pub local_limits: Limits,
    pub peer_limits: Limits,
    pub receive_charged: u64,
    pub send_reserved: u64,
    handles: [Option<StreamHandle>; MAX_STREAM_VIEWS],
    pub handles_truncated: bool,
}
impl Snapshot {
    pub fn handles(&self) -> impl Iterator<Item = StreamHandle> + '_ {
        self.handles.iter().flatten().copied()
    }
}
/// Copied cursor page for stream tables larger than the inline snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandlePage {
    handles: [Option<StreamHandle>; MAX_STREAM_VIEWS],
    pub more: bool,
}
impl HandlePage {
    pub fn handles(&self) -> impl Iterator<Item = StreamHandle> + '_ {
        self.handles.iter().flatten().copied()
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamStatus {
    pub handle: StreamHandle,
    pub send_credit: streams::SendCredit,
    pub sending_complete: bool,
    pub receive_final_size: Option<u64>,
}

pub enum Command<const N: usize> {
    PeerReady(PeerReady),
    Probe(super::recovery_owner::StreamPtoGrant),
    EarlyReady(EarlyReady),
    EarlySendReady(super::tls_owner::EarlySendReady),
    DeliverEarly(super::early_owner::AppRelease<N>),
    Deliver(packet_authority::DeliveryGrant<N>),
    Acknowledge(super::recovery_owner::StreamAck),
    Lost(super::recovery_owner::LostPacket),
    Open {
        bidirectional: bool,
    },
    Send {
        stream: StreamHandle,
        bytes: Bytes<N>,
        fin: bool,
    },
    Read {
        stream: StreamHandle,
        maximum: usize,
    },
    Consume {
        stream: StreamHandle,
        count: usize,
    },
    AcknowledgeReset(StreamHandle),
    Reset {
        stream: StreamHandle,
        error_code: u64,
    },
    Stop {
        stream: StreamHandle,
        error_code: u64,
    },
    RetireStream(StreamHandle),
    Inspect {
        stream: Option<StreamHandle>,
    },
    Lookup {
        id: u64,
    },
    Handles {
        after_id: Option<u64>,
    },
    EnqueueEarly(Bytes<N>),
    InspectEarly(early_send::Handle),
    Prepare {
        probe: bool,
    },
    PrepareEarly {
        probe: bool,
    },
    Reserve {
        prepared: PreparedId,
        packet: u64,
    },
    CancelPrepared(PreparedId),
    AdapterComplete(super::datagram::StreamCompletion),
    CancelTransmission(super::datagram::StreamCancellation),
    Retire,
}
pub enum Outcome<const N: usize> {
    Installed,
    Applied,
    Opened(StreamHandle),
    Read(ReadResult<N>),
    ResetAcknowledged(u64),
    StreamRetired(u64),
    Inspected(Option<StreamStatus>),
    Found(StreamHandle),
    Handles(HandlePage),
    EarlyEnqueued(early_send::Handle),
    EarlyDelivered(super::early_owner::ReleaseCompletion),
    EarlyRejected {
        error: Fault,
        grant: super::early_owner::AppRelease<N>,
    },
    EarlyStreamId(u64),
    Prepared(Option<PreparedFrame<N>>),
    Reserved(TransmissionId),
    Rejected(Fault),
    Retired,
}
pub struct Reply<const N: usize> {
    pub descriptor: Descriptor,
    pub snapshot: Snapshot,
    pub outcome: Outcome<N>,
}

#[derive(Clone, Copy)]
enum Selection {
    Early(early_send::Handle),
    Stream(ChunkHandle),
    Control(usize),
}
#[derive(Clone, Copy)]
enum Reservation {
    Early(early_send::SendTicket),
    Stream(Transmission),
    Control(ControlReservation),
}
#[derive(Clone, Copy)]
enum PendingTx {
    Prepared(PreparedId, Selection, bool),
    Reserved(TransmissionId, Reservation, bool),
}

/// Caller-storage-backed numerical owner. Moving this into run_borrowed is the
/// ownership transfer: no public mutator or borrowed state view is available.
pub struct State<'s, const RX: usize, const TX: usize, const C: usize = 16, const R: usize = 64> {
    generation: u64,
    role: Role,
    peer_authority: Option<PeerReady>,
    early_authority: Option<EarlyReady>,
    probe_authority: Option<(super::recovery_owner::StreamPtoGrant, u8)>,
    closed: bool,
    table: StreamTable<'s, RX>,
    queue: SendQueue<'s, TX>,
    controls: Controls<C, R>,
    early: Option<early_send::Journal<'s, TX>>,
    early_slots: Option<&'s mut [early_send::RequestSlot<TX>]>,
    early_send_authority: Option<super::tls_owner::EarlySendReady>,
    pending: Option<PendingTx>,
    sequence: u64,
}
impl<'s, const RX: usize, const TX: usize, const C: usize, const R: usize> State<'s, RX, TX, C, R> {
    pub fn new(
        generation: u64,
        role: Role,
        local: Limits,
        slots: &'s mut [StreamSlot<RX>],
        chunks: &'s mut [SendChunk<TX>],
        references: &'s mut [PacketReference],
        queue_id: u64,
        mut early_slots: Option<&'s mut [early_send::RequestSlot<TX>]>,
    ) -> Result<Self, Fault> {
        if C < 2
            || R == 0
            || TX > 1024
            || (role != Role::Client && early_slots.is_some())
            || early_slots.as_ref().is_some_and(|slots| slots.is_empty())
        {
            return Err(streams::Error::InvalidConfiguration.into());
        }
        if let Some(slots) = early_slots.as_deref_mut() {
            for slot in slots {
                *slot = early_send::RequestSlot::EMPTY;
            }
        }
        Ok(Self {
            generation,
            role,
            peer_authority: None,
            early_authority: None,
            probe_authority: None,
            closed: false,
            table: StreamTable::new(slots, role, generation, local, Limits::ZERO)?,
            queue: SendQueue::new(queue_id, chunks, references)?,
            controls: Controls::new(),
            early: None,
            early_slots,
            early_send_authority: None,
            pending: None,
            sequence: 0,
        })
    }
    fn ready(&self) -> bool {
        self.peer_authority.is_some() && (self.early.is_none() || self.early_authority.is_some())
    }
    fn snapshot(&self) -> Snapshot {
        let mut handles = [None; MAX_STREAM_VIEWS];
        for (to, handle) in handles.iter_mut().zip(self.table.live_handles()) {
            *to = Some(handle);
        }
        Snapshot {
            ready: self.ready(),
            closed: self.closed,
            pending_transmission: self.pending.is_some(),
            live_count: self.table.live_count(),
            queued_chunks: self.queue.queued_chunks(),
            send_references: self.queue.active_references(),
            control_count: self
                .controls
                .entries
                .iter()
                .filter(|c| c.kind.is_some())
                .count(),
            early_intent: self.early.as_ref().is_some_and(|j| j.has_intent()),
            early_import_required: self.peer_authority.is_some()
                && self.early.is_some()
                && self.early_authority.is_none(),
            probe_budget: self
                .probe_authority
                .as_ref()
                .map_or(0, |(_, remaining)| *remaining),
            local_limits: self.table.local_limits(),
            peer_limits: self.table.peer_limits(),
            receive_charged: self.table.receive_charged(),
            send_reserved: self.table.send_reserved(),
            handles,
            handles_truncated: self.table.live_count() > MAX_STREAM_VIEWS,
        }
    }
    fn idle(&self) -> Result<(), Fault> {
        if self.closed {
            Err(Fault::NotReady)
        } else if self.pending.is_some() {
            Err(Fault::Busy)
        } else {
            Ok(())
        }
    }
    fn application_ready(&self) -> Result<(), Fault> {
        self.idle()?;
        if self.ready() {
            Ok(())
        } else {
            Err(Fault::NotReady)
        }
    }
    fn reconcile(&mut self) -> Result<(), Fault> {
        if self.early_authority.is_none() {
            return Ok(());
        }
        let Some(journal) = self.early.as_mut() else {
            return Ok(());
        };
        let Some(decision) = journal.decision() else {
            return Ok(());
        };
        loop {
            match journal.import_next(&mut self.table, &mut self.queue) {
                Ok(Some(_)) => {}
                Ok(None) => return Ok(()),
                Err(
                    streams::Error::FlowControl
                    | streams::Error::StreamLimit
                    | streams::Error::Capacity,
                ) if decision == early_send::Decision::Rejected => return Ok(()),
                Err(e) => return Err(e.into()),
            }
        }
    }
    fn peer_ready(&mut self, grant: PeerReady) -> Result<(), Fault> {
        self.idle()?;
        if grant.generation() != self.generation {
            return Err(Fault::WrongGeneration);
        }
        if self.peer_authority.is_some() {
            return Err(Fault::Stale);
        }
        self.table.apply_peer_initial_limits(grant.limits())?;
        self.peer_authority = Some(grant);
        Ok(())
    }
    fn early_ready(&mut self, grant: EarlyReady) -> Result<(), Fault> {
        self.idle()?;
        if grant.generation() != self.generation {
            return Err(Fault::WrongGeneration);
        }
        if self.early_authority.is_some()
            || Some(grant.limits()) != self.peer_authority.as_ref().map(PeerReady::limits)
        {
            return Err(Fault::Stale);
        }
        if let Some(journal) = self.early.as_mut() {
            journal.decide(grant.decision().ok_or(Fault::NotReady)?)?;
        }
        self.early_authority = Some(grant);
        self.reconcile()
    }
    fn deliver(&mut self, frame: Frame<'_>) -> Result<(), Fault> {
        self.idle()?;
        match frame {
            Frame::Stream {
                id,
                offset,
                fin,
                data,
            } => {
                let h = match self.table.get_or_accept(id) {
                    Ok(h) => h,
                    Err(streams::Error::Retired) => return Ok(()),
                    Err(e) => return Err(e.into()),
                };
                self.table.on_stream(h, offset, data, fin)?;
            }
            Frame::ResetStream {
                id,
                error_code,
                final_size,
            } => {
                let h = match self.table.get_or_accept(id) {
                    Ok(h) => h,
                    Err(streams::Error::Retired) => return Ok(()),
                    Err(e) => return Err(e.into()),
                };
                self.table.on_reset(h, error_code, final_size)?;
            }
            Frame::StopSending { id, error_code } => {
                let h = match self.table.get_or_accept(id) {
                    Ok(h) => h,
                    Err(streams::Error::Retired) => return Ok(()),
                    Err(e) => return Err(e.into()),
                };
                self.reset(h, error_code)?;
            }
            Frame::MaxData { maximum } => self.table.on_max_data(maximum)?,
            Frame::MaxStreamData { id, maximum } => {
                let h = match self.table.get_or_accept(id) {
                    Ok(h) => h,
                    Err(streams::Error::Retired) => return Ok(()),
                    Err(e) => return Err(e.into()),
                };
                self.table.on_max_stream_data(h, maximum)?;
            }
            Frame::MaxStreams {
                bidirectional,
                maximum,
            } => self.table.on_max_streams(bidirectional, maximum)?,
            Frame::DataBlocked { .. } | Frame::StreamsBlocked { .. } => {}
            Frame::StreamDataBlocked { id, .. } => {
                let h = match self.table.get_or_accept(id) {
                    Ok(h) => h,
                    Err(streams::Error::Retired) => return Ok(()),
                    Err(e) => return Err(e.into()),
                };
                self.table.stream_receive_capacity(h)?;
            }
            _ => return Err(streams::Error::StreamState.into()),
        }
        if self.ready() {
            self.reconcile()?;
        }
        Ok(())
    }
    fn reset(&mut self, stream: StreamHandle, error_code: u64) -> Result<(), Fault> {
        if self.table.sending_complete(stream)? {
            return Ok(());
        }
        self.controls.can_push(&[ControlKind::Reset {
            stream,
            error_code,
            final_size: 0,
        }])?;
        if let Some(reset) = self.queue.reset(&mut self.table, stream, error_code)? {
            self.controls.push(ControlKind::Reset {
                stream,
                error_code: reset.error_code,
                final_size: reset.final_size,
            })?;
        }
        Ok(())
    }
    fn consume(&mut self, stream: StreamHandle, count: usize) -> Result<(), Fault> {
        self.application_ready()?;
        let view = self.table.receive(stream)?;
        if count > view.first.len() + view.second.len() {
            return Err(streams::Error::ConsumeBeyondReady.into());
        }
        if count == 0 {
            return Ok(());
        }
        let data_limit = self
            .table
            .receive_data_capacity()
            .saturating_add(count as u64)
            .min(streams::MAX_OFFSET);
        let stream_limit = self
            .table
            .stream_receive_capacity(stream)?
            .saturating_add(count as u64)
            .min(streams::MAX_OFFSET);
        let kinds = [
            ControlKind::MaxData(data_limit),
            ControlKind::MaxStreamData {
                stream,
                maximum: stream_limit,
            },
        ];
        let n = if self.table.receive_final_size(stream)?.is_some() {
            1
        } else {
            2
        };
        self.controls.can_push(&kinds[..n])?;
        self.table.consume(stream, count)?;
        self.table.grant_max_data(data_limit)?;
        self.controls.push(kinds[0])?;
        if n == 2 {
            self.table.grant_max_stream_data(stream, stream_limit)?;
            self.controls.push(kinds[1])?;
        }
        Ok(())
    }
    fn retire_stream(&mut self, stream: StreamHandle) -> Result<(), Fault> {
        self.application_ready()?;
        let peer = (stream.id() & 1) != if self.role == Role::Client { 0 } else { 1 };
        let bidirectional = stream.id() & 2 == 0;
        let previous = if bidirectional {
            self.table.local_limits().max_streams_bidi
        } else {
            self.table.local_limits().max_streams_uni
        };
        let credit = (peer && previous < streams::MAX_STREAMS).then_some(ControlKind::MaxStreams {
            bidirectional,
            maximum: previous + 1,
        });
        if let Some(kind) = credit {
            self.controls.can_push(&[kind])?;
        }
        self.table.retire(stream)?;
        if let Some(kind) = credit {
            match self.table.grant_max_streams(bidirectional, previous + 1) {
                Ok(()) => self.controls.push(kind)?,
                Err(streams::Error::Capacity) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
    fn prepare<const N: usize>(
        &mut self,
        probe: bool,
        early: bool,
    ) -> Result<Option<PreparedFrame<N>>, Fault> {
        self.idle()?;
        if probe
            && self
                .probe_authority
                .as_ref()
                .is_none_or(|(_, remaining)| *remaining == 0)
        {
            return Err(Fault::NotReady);
        }
        let selection = if early {
            if self.peer_authority.is_some() || self.early_send_authority.is_none() {
                return Err(Fault::NotReady);
            }
            self.early
                .as_ref()
                .ok_or(Fault::NotReady)?
                .next_transmit(probe)
                .map(Selection::Early)
        } else {
            self.application_ready()?;
            self.reconcile()?;
            self.controls
                .next(probe)
                .map(Selection::Control)
                .or_else(|| {
                    self.queue
                        .next_pending()
                        .or_else(|| {
                            if probe {
                                self.queue.probe_chunk()
                            } else {
                                None
                            }
                        })
                        .map(Selection::Stream)
                })
        };
        let Some(selection) = selection else {
            return Ok(None);
        };
        let next = self
            .sequence
            .checked_add(1)
            .ok_or(Fault::SequenceExhausted)?;
        let mut bytes = Bytes {
            bytes: [0; N],
            len: 0,
        };
        let frame = match selection {
            Selection::Early(handle) => {
                let view = self.early.as_ref().ok_or(Fault::Stale)?.request(handle)?;
                Frame::Stream {
                    id: view.stream_id,
                    offset: 0,
                    fin: true,
                    data: view.bytes,
                }
            }
            Selection::Stream(handle) => {
                let view = self.queue.chunk(handle)?;
                Frame::Stream {
                    id: view.stream.id(),
                    offset: view.offset,
                    fin: view.fin,
                    data: view.data,
                }
            }
            Selection::Control(slot) => self.controls.entries[slot]
                .kind
                .ok_or(Fault::Stale)?
                .frame(),
        };
        bytes.len = packet::encode_frame(&frame, &mut bytes.bytes)?;
        let id = PreparedId {
            generation: self.generation,
            sequence: self.sequence,
        };
        self.sequence = next;
        self.pending = Some(PendingTx::Prepared(id, selection, probe));
        Ok(Some(PreparedFrame {
            id,
            bytes,
            early,
            probe,
        }))
    }
    fn reserve(&mut self, prepared: PreparedId, packet: u64) -> Result<TransmissionId, Fault> {
        if packet > streams::MAX_OFFSET {
            return Err(Fault::Streams(streams::Error::InvalidId));
        }
        let Some(PendingTx::Prepared(id, selection, probe)) = self.pending else {
            return Err(Fault::Stale);
        };
        if id != prepared {
            return Err(Fault::Stale);
        }
        let reservation = match selection {
            Selection::Early(handle) => Reservation::Early(
                self.early
                    .as_mut()
                    .ok_or(Fault::Stale)?
                    .reserve(handle, packet)?,
            ),
            Selection::Stream(handle) => {
                Reservation::Stream(self.queue.reserve_transmission(handle, packet)?)
            }
            Selection::Control(slot) => Reservation::Control(self.controls.reserve(slot, packet)?),
        };
        let id = TransmissionId { prepared, packet };
        self.pending = Some(PendingTx::Reserved(id, reservation, probe));
        Ok(id)
    }
    fn adapter_result(
        &mut self,
        transmission: TransmissionId,
        accepted: bool,
    ) -> Result<(), Fault> {
        let Some(PendingTx::Reserved(id, reservation, probe)) = self.pending else {
            return Err(Fault::Stale);
        };
        if id != transmission {
            return Err(Fault::Stale);
        }
        match reservation {
            Reservation::Early(ticket) => self
                .early
                .as_mut()
                .ok_or(Fault::Stale)?
                .adapter_result(ticket, accepted)?,
            Reservation::Stream(ticket) => {
                if accepted {
                    self.queue.commit_transmission(&mut self.table, ticket)?;
                } else {
                    self.queue.cancel_transmission(&mut self.table, ticket)?;
                }
            }
            Reservation::Control(ticket) => {
                self.controls.report(&mut self.table, ticket, accepted)?
            }
        }
        if accepted && probe {
            let (_, remaining) = self.probe_authority.as_mut().ok_or(Fault::NotReady)?;
            *remaining = remaining.checked_sub(1).ok_or(Fault::NotReady)?;
            if *remaining == 0 {
                self.probe_authority = None;
            }
        }
        self.pending = None;
        self.queue.release_acked_references(&mut self.table)?;
        Ok(())
    }
    fn close(&mut self) {
        self.table.close();
        if let Some(journal) = self.early.as_mut() {
            journal.retire();
        }
        self.pending = None;
        self.closed = true;
        self.peer_authority = None;
        self.early_authority = None;
        self.early_send_authority = None;
        if let Some(slots) = self.early_slots.as_deref_mut() {
            for slot in slots {
                *slot = early_send::RequestSlot::EMPTY;
            }
        }
        self.probe_authority = None;
    }
    fn execute<const N: usize, const P: usize, const E: usize>(
        &mut self,
        command: Command<N>,
        authority: &packet_authority::Arena<P, E>,
    ) -> Result<Outcome<N>, Fault> {
        match command {
            Command::PeerReady(grant) => self.peer_ready(grant)?,
            Command::Probe(grant) => {
                self.idle()?;
                if grant.generation() != self.generation {
                    return Err(Fault::WrongGeneration);
                }
                if grant.space() != PacketNumberSpace::ApplicationData {
                    return Err(Fault::WrongSpace);
                }
                let count = grant.packets();
                self.probe_authority = Some((grant, count));
            }
            Command::EarlySendReady(grant) => {
                self.idle()?;
                if grant.generation() != self.generation {
                    return Err(Fault::WrongGeneration);
                }
                if self.peer_authority.is_some()
                    || self.early_send_authority.is_some()
                    || self.role != Role::Client
                {
                    return Err(Fault::NotReady);
                }
                let slots = self.early_slots.take().ok_or(Fault::NotReady)?;
                self.early = Some(early_send::Journal::new(
                    self.generation,
                    grant.remembered_limits(),
                    slots,
                )?);
                self.early_send_authority = Some(grant);
            }
            Command::DeliverEarly(grant) => {
                let applied = (|| {
                    self.application_ready()?;
                    if grant.generation() != self.generation {
                        return Err(Fault::WrongGeneration);
                    }
                    self.deliver(grant.frame()?)
                })();
                return Ok(match applied {
                    Ok(()) => Outcome::EarlyDelivered(grant.complete()),
                    Err(error) => Outcome::EarlyRejected { error, grant },
                });
            }
            Command::EarlyReady(grant) => self.early_ready(grant)?,
            Command::Deliver(grant) => {
                self.idle()?;
                let (packet, frame) = authority.consume_delivery(grant)?;
                if packet.generation() != self.generation {
                    return Err(Fault::WrongGeneration);
                }
                if packet.space() != PacketNumberSpace::ApplicationData {
                    return Err(Fault::WrongSpace);
                }
                self.deliver(frame.as_frame())?;
            }
            Command::Acknowledge(grant) => {
                self.idle()?;
                let authentication = grant.authentication();
                if authentication.generation() != self.generation {
                    return Err(Fault::WrongGeneration);
                }
                if authentication.space() != PacketNumberSpace::ApplicationData {
                    return Err(Fault::WrongSpace);
                }
                let ranges = grant.ranges();
                // Validate reserved control references before mutating either domain.
                self.controls.validate_ack(ranges)?;
                self.queue.on_packets_acked(&mut self.table, |pn| {
                    ranges.iter().any(|r| r.start <= pn && pn <= r.end)
                })?;
                self.queue.release_acked_references(&mut self.table)?;
                self.controls.acknowledge(&mut self.table, ranges)?;
            }
            Command::Lost(grant) => {
                if grant.generation() != self.generation {
                    return Err(Fault::WrongGeneration);
                }
                if grant.packet().space != PacketNumberSpace::ApplicationData {
                    return Err(Fault::WrongSpace);
                }
                let packet = grant.packet().value;
                if let Some(journal) = self.early.as_mut() {
                    journal.packet_lost(packet);
                }
                self.queue.on_packet_lost(packet);
                self.controls.on_packet_lost(packet);
            }
            Command::Open { bidirectional } => {
                self.application_ready()?;
                if self.early.as_ref().is_some_and(|j| j.has_intent()) {
                    return Err(Fault::Busy);
                }
                return Ok(Outcome::Opened(self.table.open_local(bidirectional)?));
            }
            Command::Send { stream, bytes, fin } => {
                self.application_ready()?;
                if self
                    .early
                    .as_ref()
                    .is_some_and(|j| j.has_pending_stream(stream.id()))
                {
                    return Err(Fault::Busy);
                }
                self.queue
                    .enqueue(&mut self.table, stream, bytes.as_bytes(), fin)?;
            }
            Command::Read { stream, maximum } => {
                if self.closed || !self.ready() {
                    return Err(Fault::NotReady);
                }
                let view = self.table.receive(stream)?;
                let ready = view.first.len() + view.second.len();
                let len = ready.min(maximum).min(N);
                let first = len.min(view.first.len());
                let mut bytes = Bytes { bytes: [0; N], len };
                bytes.bytes[..first].copy_from_slice(&view.first[..first]);
                bytes.bytes[first..len].copy_from_slice(&view.second[..len - first]);
                return Ok(Outcome::Read(ReadResult {
                    bytes,
                    fin: view.fin && len == ready,
                    reset: view.reset,
                    remaining: ready - len,
                }));
            }
            Command::Consume { stream, count } => self.consume(stream, count)?,
            Command::AcknowledgeReset(stream) => {
                self.application_ready()?;
                let maximum = self.table.receive_data_capacity();
                let kind = ControlKind::MaxData(maximum);
                self.controls.can_push(&[kind])?;
                let code = self.table.acknowledge_received_reset(stream)?;
                self.table.grant_max_data(maximum)?;
                self.controls.push(kind)?;
                return Ok(Outcome::ResetAcknowledged(code));
            }
            Command::Reset { stream, error_code } => {
                self.application_ready()?;
                self.reset(stream, error_code)?;
            }
            Command::Stop { stream, error_code } => {
                self.application_ready()?;
                let stop = self.table.request_stop(stream, error_code)?;
                self.controls.push(ControlKind::Stop {
                    stream,
                    error_code: stop.error_code,
                })?;
            }
            Command::RetireStream(stream) => {
                self.retire_stream(stream)?;
                return Ok(Outcome::StreamRetired(stream.id()));
            }
            Command::Inspect { stream } => {
                return Ok(Outcome::Inspected(match stream {
                    Some(h) => Some(StreamStatus {
                        handle: h,
                        send_credit: self.table.send_credit(h)?,
                        sending_complete: self.table.sending_complete(h)?,
                        receive_final_size: self.table.receive_final_size(h)?,
                    }),
                    None => None,
                }));
            }
            Command::Lookup { id } => return Ok(Outcome::Found(self.table.lookup(id)?)),
            Command::Handles { after_id } => {
                let mut page = HandlePage {
                    handles: [None; MAX_STREAM_VIEWS],
                    more: false,
                };
                let mut after = after_id;
                for slot in &mut page.handles {
                    let next = self
                        .table
                        .live_handles()
                        .filter(|h| after.is_none_or(|id| h.id() > id))
                        .min_by_key(|h| h.id());
                    let Some(next) = next else {
                        break;
                    };
                    after = Some(next.id());
                    *slot = Some(next);
                }
                page.more = self
                    .table
                    .live_handles()
                    .any(|h| after.is_none_or(|id| h.id() > id));
                return Ok(Outcome::Handles(page));
            }
            Command::EnqueueEarly(bytes) => {
                self.idle()?;
                if self.ready() {
                    return Err(Fault::NotReady);
                }
                return Ok(Outcome::EarlyEnqueued(
                    self.early
                        .as_mut()
                        .ok_or(Fault::NotReady)?
                        .enqueue(bytes.as_bytes())?,
                ));
            }
            Command::InspectEarly(handle) => {
                return Ok(Outcome::EarlyStreamId(
                    self.early
                        .as_ref()
                        .ok_or(Fault::NotReady)?
                        .request(handle)?
                        .stream_id,
                ));
            }
            Command::Prepare { probe } => return self.prepare(probe, false).map(Outcome::Prepared),
            Command::PrepareEarly { probe } => {
                return self.prepare(probe, true).map(Outcome::Prepared);
            }
            Command::Reserve { prepared, packet } => {
                return self.reserve(prepared, packet).map(Outcome::Reserved);
            }
            Command::CancelPrepared(id) => {
                if !matches!(self.pending, Some(PendingTx::Prepared(actual, _, _)) if actual == id)
                {
                    return Err(Fault::Stale);
                }
                self.pending = None;
            }
            Command::AdapterComplete(grant) => {
                self.adapter_result(grant.transmission(), grant.accepted())?
            }
            Command::CancelTransmission(grant) => {
                self.adapter_result(grant.transmission(), false)?
            }
            Command::Retire => {
                self.close();
                return Ok(Outcome::Retired);
            }
        }
        Ok(Outcome::Applied)
    }
}
impl<const RX: usize, const TX: usize, const C: usize, const R: usize> Drop
    for State<'_, RX, TX, C, R>
{
    fn drop(&mut self) {
        self.close();
    }
}

struct Request<const N: usize> {
    descriptor: Descriptor,
    command: Command<N>,
}
/// Caller-owned single request/result arena. Every RefCell borrow ends before
/// any endpoint or mailbox await, including cancellation and result delivery.
pub struct Exchange<const N: usize> {
    request: RefCell<Option<Request<N>>>,
    reply: RefCell<Option<Reply<N>>>,
}
impl<const N: usize> Exchange<N> {
    pub const fn new() -> Self {
        Self {
            request: RefCell::new(None),
            reply: RefCell::new(None),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.request.borrow().is_none() && self.reply.borrow().is_none()
    }
    fn put_request(&self, request: Request<N>) -> Result<(), Error> {
        let mut slot = self.request.borrow_mut();
        if slot.is_some() || self.reply.borrow().is_some() {
            return Err(Error::OccupiedSlot);
        }
        *slot = Some(request);
        Ok(())
    }
    fn take_request(&self, descriptor: Descriptor) -> Result<Command<N>, Error> {
        let request = self.request.borrow_mut().take().ok_or(Error::MissingSlot)?;
        if request.descriptor != descriptor {
            return Err(Error::Correlation);
        }
        Ok(request.command)
    }
    fn put_reply(&self, reply: Reply<N>) -> Result<(), Error> {
        let mut slot = self.reply.borrow_mut();
        if slot.is_some() {
            return Err(Error::OccupiedSlot);
        }
        *slot = Some(reply);
        Ok(())
    }
    fn take_reply(&self, descriptor: Descriptor) -> Result<Reply<N>, Error> {
        let reply = self.reply.borrow_mut().take().ok_or(Error::MissingSlot)?;
        if reply.descriptor != descriptor {
            return Err(Error::Correlation);
        }
        Ok(reply)
    }
}
impl<const N: usize> Default for Exchange<N> {
    fn default() -> Self {
        Self::new()
    }
}
struct Clear<'a, const N: usize>(&'a Exchange<N>);
impl<const N: usize> Drop for Clear<'_, N> {
    fn drop(&mut self) {
        self.0.request.borrow_mut().take();
        self.0.reply.borrow_mut().take();
    }
}
#[derive(Debug)]
pub enum Error {
    Hibana(EndpointError),
    CommandsClosed,
    RepliesClosed,
    OccupiedSlot,
    MissingSlot,
    Correlation,
    UnexpectedCommand,
    AdmissionRejected,
    FrameCapacity,
    UnexpectedLabel(u8),
    SequenceExhausted,
}
impl From<EndpointError> for Error {
    fn from(e: EndpointError) -> Self {
        Self::Hibana(e)
    }
}
fn encode(d: Descriptor) -> [u8; 16] {
    let mut wire = [0; 16];
    wire[..8].copy_from_slice(&d.generation.to_be_bytes());
    wire[8..].copy_from_slice(&d.sequence.to_be_bytes());
    wire
}
fn same(actual: [u8; 16], expected: [u8; 16]) -> Result<(), Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(Error::Correlation)
    }
}
impl<const N: usize> Command<N> {
    fn label(&self) -> u8 {
        match self {
            Self::PeerReady(_) => p::PEER_READY,
            Self::Probe(_) => p::PROBE,
            Self::EarlyReady(_) => p::EARLY_READY,
            Self::EarlySendReady(_) => p::EARLY_SEND_READY,
            Self::DeliverEarly(_) => p::DELIVER_EARLY,
            Self::Deliver(_) => p::DELIVER,
            Self::Acknowledge(_) => p::ACKNOWLEDGE,
            Self::Lost(_) => p::LOST,
            Self::Open { .. } => p::OPEN,
            Self::Send { .. } => p::SEND,
            Self::Read { .. } => p::READ,
            Self::Consume { .. } => p::CONSUME,
            Self::AcknowledgeReset(_) => p::ACKNOWLEDGE_RESET,
            Self::Reset { .. } => p::RESET,
            Self::Stop { .. } => p::STOP,
            Self::RetireStream(_) => p::RETIRE_STREAM,
            Self::Inspect { .. } | Self::Lookup { .. } | Self::Handles { .. } => p::INSPECT,
            Self::EnqueueEarly(_) => p::ENQUEUE_EARLY,
            Self::InspectEarly(_) => p::INSPECT_EARLY,
            Self::Prepare { .. } => p::PREPARE,
            Self::PrepareEarly { .. } => p::PREPARE_EARLY,
            Self::Reserve { .. } => p::RESERVE,
            Self::CancelPrepared(_) => p::CANCEL_PREPARED,
            Self::AdapterComplete(grant) => {
                if grant.accepted() {
                    p::ADAPTER_ACCEPTED
                } else {
                    p::ADAPTER_REJECTED
                }
            }
            Self::CancelTransmission(_) => p::CANCEL_TRANSMISSION,
            Self::Retire => p::RETIRE_REQUESTED,
        }
    }
}
/// The outer session retains the endpoints until every composed role finishes.
/// State moves into the owner and is destroyed on cancellation or service error.
pub async fn run_borrowed<
    const CLIENT: u8,
    const OWNER: u8,
    const N: usize,
    const RX: usize,
    const TX: usize,
    const C: usize,
    const R: usize,
    const Q: usize,
    const REPLIES: usize,
    const P: usize,
    const E: usize,
>(
    client: &mut Endpoint<'_, CLIENT>,
    owner: &mut Endpoint<'_, OWNER>,
    state: State<'_, RX, TX, C, R>,
    commands: Receiver<'_, '_, Command<N>, Q>,
    replies: Sender<'_, '_, Reply<N>, REPLIES>,
    exchange: &mut Exchange<N>,
    authority: &packet_authority::Arena<P, E>,
) -> Result<(), Error> {
    if N < TX.saturating_add(25) {
        return Err(Error::FrameCapacity);
    }
    if !exchange.is_empty() {
        return Err(Error::OccupiedSlot);
    }
    let exchange = &*exchange;
    let _clear = Clear(exchange);
    let generation = state.generation;
    let mut command = core::pin::pin!(command_role(
        client, generation, commands, replies, exchange
    ));
    let mut owner = core::pin::pin!(stream_role(owner, state, exchange, authority));
    runtime::TaskSet::new([command.as_mut(), owner.as_mut()]).await
}

fn next_descriptor(generation: u64, sequence: &mut u64) -> Result<Descriptor, Error> {
    let descriptor = Descriptor {
        generation,
        sequence: *sequence,
    };
    *sequence = sequence.checked_add(1).ok_or(Error::SequenceExhausted)?;
    Ok(descriptor)
}
/// Publishes the owned result before allowing the projected continuation.
async fn client_result<const C: u8, const N: usize, const R: usize>(
    endpoint: &mut Endpoint<'_, C>,
    replies: &mut Sender<'_, '_, Reply<N>, R>,
    exchange: &Exchange<N>,
    descriptor: Descriptor,
) -> Result<(), Error> {
    replies
        .send(exchange.take_reply(descriptor)?)
        .await
        .map_err(|_| Error::RepliesClosed)?;
    endpoint.send::<p::ResultTaken>(&encode(descriptor)).await?;
    Ok(())
}
async fn client_operation_result<const C: u8, const N: usize, const R: usize>(
    endpoint: &mut Endpoint<'_, C>,
    replies: &mut Sender<'_, '_, Reply<N>, R>,
    exchange: &Exchange<N>,
    descriptor: Descriptor,
) -> Result<bool, Error> {
    let branch = endpoint.offer().await?;
    let (wire, applied) = match branch.label() {
        p::APPLIED => (branch.recv::<p::Applied>().await?, true),
        p::REJECTED => (branch.recv::<p::Rejected>().await?, false),
        label => return Err(Error::UnexpectedLabel(label)),
    };
    same(wire, encode(descriptor))?;
    client_result(endpoint, replies, exchange, descriptor).await?;
    Ok(applied)
}
async fn client_retirement<const C: u8, const N: usize, const R: usize>(
    endpoint: &mut Endpoint<'_, C>,
    replies: &mut Sender<'_, '_, Reply<N>, R>,
    exchange: &Exchange<N>,
    descriptor: Descriptor,
) -> Result<(), Error> {
    let wire = encode(descriptor);
    endpoint.send::<p::RetireRequested>(&wire).await?;
    same(endpoint.recv::<p::Retired>().await?, wire)?;
    replies
        .send(exchange.take_reply(descriptor)?)
        .await
        .map_err(|_| Error::RepliesClosed)?;
    endpoint.send::<p::RetirementAcknowledged>(&wire).await?;
    Ok(())
}
async fn client_routed_retirement<const C: u8, const N: usize, const R: usize>(
    endpoint: &mut Endpoint<'_, C>,
    replies: &mut Sender<'_, '_, Reply<N>, R>,
    exchange: &Exchange<N>,
    descriptor: Descriptor,
) -> Result<(), Error> {
    let wire = encode(descriptor);
    endpoint.send::<p::RetireRequested>(&wire).await?;
    let branch = endpoint.offer().await?;
    if branch.label() != p::RETIRED {
        return Err(Error::UnexpectedLabel(branch.label()));
    }
    same(branch.recv::<p::Retired>().await?, wire)?;
    replies
        .send(exchange.take_reply(descriptor)?)
        .await
        .map_err(|_| Error::RepliesClosed)?;
    endpoint.send::<p::RetirementAcknowledged>(&wire).await?;
    Ok(())
}
/// A successful preparation cannot escape this local side until the owner
/// explicitly seals reservation/cancellation and publication settlement.
async fn client_prepare<const C: u8, const N: usize, const Q: usize, const R: usize>(
    endpoint: &mut Endpoint<'_, C>,
    generation: u64,
    sequence: &mut u64,
    commands: &mut Receiver<'_, '_, Command<N>, Q>,
    replies: &mut Sender<'_, '_, Reply<N>, R>,
    exchange: &Exchange<N>,
    descriptor: Descriptor,
    early: bool,
) -> Result<(), Error> {
    let wire = encode(descriptor);
    if early {
        endpoint.send::<p::PrepareEarly>(&wire).await?;
    } else {
        endpoint.send::<p::Prepare>(&wire).await?;
    }
    let branch = endpoint.offer().await?;
    let prepared = match branch.label() {
        p::FRAME_PREPARED => {
            same(branch.recv::<p::FramePrepared>().await?, wire)?;
            true
        }
        p::NO_FRAME => {
            same(branch.recv::<p::NoFrame>().await?, wire)?;
            false
        }
        p::REJECTED => {
            same(branch.recv::<p::Rejected>().await?, wire)?;
            false
        }
        label => return Err(Error::UnexpectedLabel(label)),
    };
    client_result(endpoint, replies, exchange, descriptor).await?;
    if !prepared {
        return Ok(());
    }
    let reserved = loop {
        let command = commands.recv().await.map_err(|_| Error::CommandsClosed)?;
        let label = command.label();
        if !matches!(label, p::RESERVE | p::CANCEL_PREPARED) {
            return Err(Error::UnexpectedCommand);
        }
        let descriptor = next_descriptor(generation, sequence)?;
        let wire = encode(descriptor);
        exchange.put_request(Request {
            descriptor,
            command,
        })?;
        match label {
            p::RESERVE => endpoint.send::<p::Reserve>(&wire).await?,
            p::CANCEL_PREPARED => endpoint.send::<p::CancelPrepared>(&wire).await?,
            _ => return Err(Error::UnexpectedCommand),
        }
        if client_operation_result(endpoint, replies, exchange, descriptor).await? {
            break (label == p::RESERVE, wire);
        }
        runtime::yield_now().await;
    };
    let suffix = endpoint.offer().await?;
    match (reserved.0, suffix.label()) {
        (false, p::SELECTION_CANCELLED) => {
            same(suffix.recv::<p::SelectionCancelled>().await?, reserved.1)?;
            return Ok(());
        }
        (true, p::RESERVED) => same(suffix.recv::<p::Reserved>().await?, reserved.1)?,
        (_, label) => return Err(Error::UnexpectedLabel(label)),
    }
    let completed = loop {
        let command = commands.recv().await.map_err(|_| Error::CommandsClosed)?;
        let label = command.label();
        if !matches!(
            label,
            p::ADAPTER_ACCEPTED | p::ADAPTER_REJECTED | p::CANCEL_TRANSMISSION
        ) {
            return Err(Error::UnexpectedCommand);
        }
        let descriptor = next_descriptor(generation, sequence)?;
        let wire = encode(descriptor);
        exchange.put_request(Request {
            descriptor,
            command,
        })?;
        match label {
            p::ADAPTER_ACCEPTED => endpoint.send::<p::AdapterAccepted>(&wire).await?,
            p::ADAPTER_REJECTED => endpoint.send::<p::AdapterRejected>(&wire).await?,
            p::CANCEL_TRANSMISSION => endpoint.send::<p::CancelTransmission>(&wire).await?,
            _ => return Err(Error::UnexpectedCommand),
        }
        if client_operation_result(endpoint, replies, exchange, descriptor).await? {
            break wire;
        }
        runtime::yield_now().await;
    };
    same(endpoint.recv::<p::PublicationSettled>().await?, completed)?;
    Ok(())
}

async fn client_admission<const C: u8, const N: usize, const Q: usize, const R: usize>(
    endpoint: &mut Endpoint<'_, C>,
    generation: u64,
    sequence: &mut u64,
    commands: &mut Receiver<'_, '_, Command<N>, Q>,
    replies: &mut Sender<'_, '_, Reply<N>, R>,
    exchange: &Exchange<N>,
    descriptor: Descriptor,
) -> Result<(), Error> {
    let wire = encode(descriptor);
    endpoint.send::<p::PeerReady>(&wire).await?;
    let branch = endpoint.offer().await?;
    let early = match branch.label() {
        p::READY => {
            same(branch.recv::<p::Ready>().await?, wire)?;
            false
        }
        p::EARLY_REQUIRED => {
            same(branch.recv::<p::EarlyRequired>().await?, wire)?;
            true
        }
        label => return Err(Error::UnexpectedLabel(label)),
    };
    client_result(endpoint, replies, exchange, descriptor).await?;
    if early {
        let command = commands.recv().await.map_err(|_| Error::CommandsClosed)?;
        if !matches!(command, Command::EarlyReady(_)) {
            return Err(Error::UnexpectedCommand);
        }
        let descriptor = next_descriptor(generation, sequence)?;
        let wire = encode(descriptor);
        exchange.put_request(Request {
            descriptor,
            command,
        })?;
        endpoint.send::<p::EarlyReady>(&wire).await?;
        same(endpoint.recv::<p::EarlyApplied>().await?, wire)?;
        client_result(endpoint, replies, exchange, descriptor).await?;
    }
    Ok(())
}
async fn client_active<const C: u8, const N: usize, const Q: usize, const R: usize>(
    endpoint: &mut Endpoint<'_, C>,
    generation: u64,
    sequence: &mut u64,
    commands: &mut Receiver<'_, '_, Command<N>, Q>,
    replies: &mut Sender<'_, '_, Reply<N>, R>,
    exchange: &Exchange<N>,
) -> Result<(), Error> {
    loop {
        let command = commands.recv().await.map_err(|_| Error::CommandsClosed)?;
        let label = command.label();
        let descriptor = next_descriptor(generation, sequence)?;
        let wire = encode(descriptor);
        exchange.put_request(Request {
            descriptor,
            command,
        })?;
        match label {
            p::PROBE => endpoint.send::<p::Probe>(&wire).await?,
            p::DELIVER => endpoint.send::<p::Deliver>(&wire).await?,
            p::DELIVER_EARLY => endpoint.send::<p::DeliverEarly>(&wire).await?,
            p::ACKNOWLEDGE => endpoint.send::<p::Acknowledge>(&wire).await?,
            p::LOST => endpoint.send::<p::Lost>(&wire).await?,
            p::OPEN => endpoint.send::<p::Open>(&wire).await?,
            p::SEND => endpoint.send::<p::Send>(&wire).await?,
            p::READ => endpoint.send::<p::Read>(&wire).await?,
            p::CONSUME => endpoint.send::<p::Consume>(&wire).await?,
            p::ACKNOWLEDGE_RESET => endpoint.send::<p::AcknowledgeReset>(&wire).await?,
            p::RESET => endpoint.send::<p::Reset>(&wire).await?,
            p::STOP => endpoint.send::<p::Stop>(&wire).await?,
            p::RETIRE_STREAM => endpoint.send::<p::RetireStream>(&wire).await?,
            p::INSPECT => endpoint.send::<p::Inspect>(&wire).await?,
            p::PREPARE => {
                client_prepare(
                    endpoint, generation, sequence, commands, replies, exchange, descriptor, false,
                )
                .await?;
                continue;
            }
            p::RETIRE_REQUESTED => {
                return client_retirement(endpoint, replies, exchange, descriptor).await;
            }
            label => return Err(Error::UnexpectedLabel(label)),
        }
        client_operation_result(endpoint, replies, exchange, descriptor).await?;
        runtime::yield_now().await;
    }
}
async fn command_role<const C: u8, const N: usize, const Q: usize, const R: usize>(
    endpoint: &mut Endpoint<'_, C>,
    generation: u64,
    mut commands: Receiver<'_, '_, Command<N>, Q>,
    mut replies: Sender<'_, '_, Reply<N>, R>,
    exchange: &Exchange<N>,
) -> Result<(), Error> {
    let installed = Descriptor {
        generation,
        sequence: 0,
    };
    let wire = encode(installed);
    endpoint.send::<p::Install>(&wire).await?;
    same(endpoint.recv::<p::Installed>().await?, wire)?;
    replies
        .send(exchange.take_reply(installed)?)
        .await
        .map_err(|_| Error::RepliesClosed)?;
    let mut sequence = 1;
    // No early bytes can enter the Journal before the real TLS capability arrives.
    loop {
        let command = commands.recv().await.map_err(|_| Error::CommandsClosed)?;
        let label = command.label();
        let descriptor = next_descriptor(generation, &mut sequence)?;
        let wire = encode(descriptor);
        exchange.put_request(Request {
            descriptor,
            command,
        })?;
        match label {
            p::PROBE => endpoint.send::<p::Probe>(&wire).await?,
            p::DELIVER => endpoint.send::<p::Deliver>(&wire).await?,
            p::ACKNOWLEDGE => endpoint.send::<p::Acknowledge>(&wire).await?,
            p::LOST => endpoint.send::<p::Lost>(&wire).await?,
            p::INSPECT => endpoint.send::<p::Inspect>(&wire).await?,
            p::RETIRE_REQUESTED => {
                return client_routed_retirement(endpoint, &mut replies, exchange, descriptor)
                    .await;
            }
            p::PEER_READY => {
                client_admission(
                    endpoint,
                    generation,
                    &mut sequence,
                    &mut commands,
                    &mut replies,
                    exchange,
                    descriptor,
                )
                .await?;
                return client_active(
                    endpoint,
                    generation,
                    &mut sequence,
                    &mut commands,
                    &mut replies,
                    exchange,
                )
                .await;
            }
            p::EARLY_SEND_READY => {
                endpoint.send::<p::EarlySendReady>(&wire).await?;
                let branch = endpoint.offer().await?;
                if branch.label() != p::EARLY_SEND_INSTALLED {
                    return Err(Error::UnexpectedLabel(branch.label()));
                }
                same(branch.recv::<p::EarlySendInstalled>().await?, wire)?;
                client_result(endpoint, &mut replies, exchange, descriptor).await?;
                break;
            }
            label => return Err(Error::UnexpectedLabel(label)),
        }
        client_operation_result(endpoint, &mut replies, exchange, descriptor).await?;
        runtime::yield_now().await;
    }
    // Distinct early transmission scope, including complete reservation/UDP settlement.
    loop {
        let command = commands.recv().await.map_err(|_| Error::CommandsClosed)?;
        let label = command.label();
        let descriptor = next_descriptor(generation, &mut sequence)?;
        let wire = encode(descriptor);
        exchange.put_request(Request {
            descriptor,
            command,
        })?;
        match label {
            p::PROBE => endpoint.send::<p::Probe>(&wire).await?,
            p::DELIVER => endpoint.send::<p::Deliver>(&wire).await?,
            p::ACKNOWLEDGE => endpoint.send::<p::Acknowledge>(&wire).await?,
            p::LOST => endpoint.send::<p::Lost>(&wire).await?,
            p::INSPECT => endpoint.send::<p::Inspect>(&wire).await?,
            p::ENQUEUE_EARLY => endpoint.send::<p::EnqueueEarly>(&wire).await?,
            p::INSPECT_EARLY => endpoint.send::<p::InspectEarly>(&wire).await?,
            p::PREPARE_EARLY => {
                client_prepare(
                    endpoint,
                    generation,
                    &mut sequence,
                    &mut commands,
                    &mut replies,
                    exchange,
                    descriptor,
                    true,
                )
                .await?;
                continue;
            }
            p::RETIRE_REQUESTED => {
                return client_routed_retirement(endpoint, &mut replies, exchange, descriptor)
                    .await;
            }
            p::PEER_READY => {
                client_admission(
                    endpoint,
                    generation,
                    &mut sequence,
                    &mut commands,
                    &mut replies,
                    exchange,
                    descriptor,
                )
                .await?;
                break;
            }
            label => return Err(Error::UnexpectedLabel(label)),
        }
        client_operation_result(endpoint, &mut replies, exchange, descriptor).await?;
        runtime::yield_now().await;
    }
    client_active(
        endpoint,
        generation,
        &mut sequence,
        &mut commands,
        &mut replies,
        exchange,
    )
    .await
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum ResultBranch {
    Applied,
    Rejected,
    Prepared,
    NoFrame,
}
fn owner_execute<
    const N: usize,
    const RX: usize,
    const TX: usize,
    const C: usize,
    const R: usize,
    const P: usize,
    const E: usize,
>(
    state: &mut State<'_, RX, TX, C, R>,
    exchange: &Exchange<N>,
    authority: &packet_authority::Arena<P, E>,
    descriptor: Descriptor,
    label: u8,
) -> Result<ResultBranch, Error> {
    let command = exchange.take_request(descriptor)?;
    if command.label() != label {
        return Err(Error::UnexpectedCommand);
    }
    let outcome = match state.execute(command, authority) {
        Ok(value) => value,
        Err(error) => Outcome::Rejected(error),
    };
    let branch = match &outcome {
        Outcome::Rejected(_) | Outcome::EarlyRejected { .. } => ResultBranch::Rejected,
        Outcome::Prepared(Some(_)) => ResultBranch::Prepared,
        Outcome::Prepared(None) => ResultBranch::NoFrame,
        _ => ResultBranch::Applied,
    };
    exchange.put_reply(Reply {
        descriptor,
        snapshot: state.snapshot(),
        outcome,
    })?;
    Ok(branch)
}
async fn owner_operation_result<const O: u8>(
    endpoint: &mut Endpoint<'_, O>,
    wire: [u8; 16],
    result: ResultBranch,
) -> Result<(), Error> {
    if result == ResultBranch::Rejected {
        endpoint.send::<p::Rejected>(&wire).await?;
    } else {
        endpoint.send::<p::Applied>(&wire).await?;
    }
    same(endpoint.recv::<p::ResultTaken>().await?, wire)
}
async fn owner_retirement<
    const O: u8,
    const N: usize,
    const RX: usize,
    const TX: usize,
    const C: usize,
    const R: usize,
    const P: usize,
    const E: usize,
>(
    endpoint: &mut Endpoint<'_, O>,
    state: &mut State<'_, RX, TX, C, R>,
    exchange: &Exchange<N>,
    authority: &packet_authority::Arena<P, E>,
    descriptor: Descriptor,
) -> Result<(), Error> {
    if owner_execute(state, exchange, authority, descriptor, p::RETIRE_REQUESTED)?
        != ResultBranch::Applied
    {
        return Err(Error::UnexpectedCommand);
    }
    let wire = encode(descriptor);
    endpoint.send::<p::Retired>(&wire).await?;
    same(endpoint.recv::<p::RetirementAcknowledged>().await?, wire)
}
async fn owner_prepare<
    const O: u8,
    const N: usize,
    const RX: usize,
    const TX: usize,
    const C: usize,
    const R: usize,
    const P: usize,
    const E: usize,
>(
    endpoint: &mut Endpoint<'_, O>,
    state: &mut State<'_, RX, TX, C, R>,
    sequence: &mut u64,
    exchange: &Exchange<N>,
    authority: &packet_authority::Arena<P, E>,
    descriptor: Descriptor,
    label: u8,
) -> Result<(), Error> {
    let wire = encode(descriptor);
    let prepared = owner_execute(state, exchange, authority, descriptor, label)?;
    match prepared {
        ResultBranch::Prepared => endpoint.send::<p::FramePrepared>(&wire).await?,
        ResultBranch::NoFrame => endpoint.send::<p::NoFrame>(&wire).await?,
        ResultBranch::Rejected => endpoint.send::<p::Rejected>(&wire).await?,
        _ => return Err(Error::UnexpectedCommand),
    }
    same(endpoint.recv::<p::ResultTaken>().await?, wire)?;
    if prepared != ResultBranch::Prepared {
        return Ok(());
    }
    let reserved = loop {
        let branch = endpoint.offer().await?;
        let label = branch.label();
        let observed = match label {
            p::RESERVE => branch.recv::<p::Reserve>().await?,
            p::CANCEL_PREPARED => branch.recv::<p::CancelPrepared>().await?,
            label => return Err(Error::UnexpectedLabel(label)),
        };
        let descriptor = next_descriptor(state.generation, sequence)?;
        let wire = encode(descriptor);
        same(observed, wire)?;
        let result = owner_execute(state, exchange, authority, descriptor, label)?;
        owner_operation_result(endpoint, wire, result).await?;
        if result != ResultBranch::Rejected {
            break (label == p::RESERVE, wire);
        }
        runtime::yield_now().await;
    };
    if !reserved.0 {
        endpoint.send::<p::SelectionCancelled>(&reserved.1).await?;
        return Ok(());
    }
    endpoint.send::<p::Reserved>(&reserved.1).await?;
    let completed = loop {
        let branch = endpoint.offer().await?;
        let label = branch.label();
        let observed = match label {
            p::ADAPTER_ACCEPTED => branch.recv::<p::AdapterAccepted>().await?,
            p::ADAPTER_REJECTED => branch.recv::<p::AdapterRejected>().await?,
            p::CANCEL_TRANSMISSION => branch.recv::<p::CancelTransmission>().await?,
            label => return Err(Error::UnexpectedLabel(label)),
        };
        let descriptor = next_descriptor(state.generation, sequence)?;
        let wire = encode(descriptor);
        same(observed, wire)?;
        let result = owner_execute(state, exchange, authority, descriptor, label)?;
        owner_operation_result(endpoint, wire, result).await?;
        if result != ResultBranch::Rejected {
            break wire;
        }
        runtime::yield_now().await;
    };
    endpoint.send::<p::PublicationSettled>(&completed).await?;
    Ok(())
}

async fn owner_admission<
    const O: u8,
    const N: usize,
    const RX: usize,
    const TX: usize,
    const C: usize,
    const R: usize,
    const P: usize,
    const E: usize,
>(
    endpoint: &mut Endpoint<'_, O>,
    state: &mut State<'_, RX, TX, C, R>,
    sequence: &mut u64,
    exchange: &Exchange<N>,
    authority: &packet_authority::Arena<P, E>,
    descriptor: Descriptor,
) -> Result<(), Error> {
    let wire = encode(descriptor);
    if owner_execute(state, exchange, authority, descriptor, p::PEER_READY)?
        == ResultBranch::Rejected
    {
        return Err(Error::AdmissionRejected);
    }
    if state.early.is_some() {
        endpoint.send::<p::EarlyRequired>(&wire).await?;
        same(endpoint.recv::<p::ResultTaken>().await?, wire)?;
        let observed = endpoint.recv::<p::EarlyReady>().await?;
        let descriptor = next_descriptor(state.generation, sequence)?;
        let wire = encode(descriptor);
        same(observed, wire)?;
        if owner_execute(state, exchange, authority, descriptor, p::EARLY_READY)?
            == ResultBranch::Rejected
        {
            return Err(Error::AdmissionRejected);
        }
        endpoint.send::<p::EarlyApplied>(&wire).await?;
        same(endpoint.recv::<p::ResultTaken>().await?, wire)?;
    } else {
        endpoint.send::<p::Ready>(&wire).await?;
        same(endpoint.recv::<p::ResultTaken>().await?, wire)?;
    }
    Ok(())
}
async fn owner_active<
    const O: u8,
    const N: usize,
    const RX: usize,
    const TX: usize,
    const C: usize,
    const R: usize,
    const P: usize,
    const E: usize,
>(
    endpoint: &mut Endpoint<'_, O>,
    state: &mut State<'_, RX, TX, C, R>,
    sequence: &mut u64,
    exchange: &Exchange<N>,
    authority: &packet_authority::Arena<P, E>,
) -> Result<(), Error> {
    loop {
        let branch = endpoint.offer().await?;
        let label = branch.label();
        let observed = match label {
            p::PROBE => branch.recv::<p::Probe>().await?,
            p::DELIVER => branch.recv::<p::Deliver>().await?,
            p::DELIVER_EARLY => branch.recv::<p::DeliverEarly>().await?,
            p::ACKNOWLEDGE => branch.recv::<p::Acknowledge>().await?,
            p::LOST => branch.recv::<p::Lost>().await?,
            p::OPEN => branch.recv::<p::Open>().await?,
            p::SEND => branch.recv::<p::Send>().await?,
            p::READ => branch.recv::<p::Read>().await?,
            p::CONSUME => branch.recv::<p::Consume>().await?,
            p::ACKNOWLEDGE_RESET => branch.recv::<p::AcknowledgeReset>().await?,
            p::RESET => branch.recv::<p::Reset>().await?,
            p::STOP => branch.recv::<p::Stop>().await?,
            p::RETIRE_STREAM => branch.recv::<p::RetireStream>().await?,
            p::INSPECT => branch.recv::<p::Inspect>().await?,
            p::PREPARE => branch.recv::<p::Prepare>().await?,
            p::RETIRE_REQUESTED => branch.recv::<p::RetireRequested>().await?,
            label => return Err(Error::UnexpectedLabel(label)),
        };
        let descriptor = next_descriptor(state.generation, sequence)?;
        let wire = encode(descriptor);
        same(observed, wire)?;
        if label == p::RETIRE_REQUESTED {
            return owner_retirement(endpoint, state, exchange, authority, descriptor).await;
        }
        if label == p::PREPARE {
            owner_prepare(
                endpoint, state, sequence, exchange, authority, descriptor, label,
            )
            .await?;
            continue;
        }
        let result = owner_execute(state, exchange, authority, descriptor, label)?;
        owner_operation_result(endpoint, wire, result).await?;
        runtime::yield_now().await;
    }
}
async fn stream_role<
    const O: u8,
    const N: usize,
    const RX: usize,
    const TX: usize,
    const C: usize,
    const R: usize,
    const P: usize,
    const E: usize,
>(
    endpoint: &mut Endpoint<'_, O>,
    mut state: State<'_, RX, TX, C, R>,
    exchange: &Exchange<N>,
    authority: &packet_authority::Arena<P, E>,
) -> Result<(), Error> {
    let generation = state.generation;
    let installed = Descriptor {
        generation,
        sequence: 0,
    };
    let wire = encode(installed);
    same(endpoint.recv::<p::Install>().await?, wire)?;
    exchange.put_reply(Reply {
        descriptor: installed,
        snapshot: state.snapshot(),
        outcome: Outcome::Installed,
    })?;
    endpoint.send::<p::Installed>(&wire).await?;
    let mut sequence = 1;
    loop {
        let branch = endpoint.offer().await?;
        let label = branch.label();
        let observed = match label {
            p::PROBE => branch.recv::<p::Probe>().await?,
            p::DELIVER => branch.recv::<p::Deliver>().await?,
            p::ACKNOWLEDGE => branch.recv::<p::Acknowledge>().await?,
            p::LOST => branch.recv::<p::Lost>().await?,
            p::INSPECT => branch.recv::<p::Inspect>().await?,
            p::EARLY_SEND_READY => branch.recv::<p::EarlySendReady>().await?,
            p::PEER_READY => branch.recv::<p::PeerReady>().await?,
            p::RETIRE_REQUESTED => branch.recv::<p::RetireRequested>().await?,
            label => return Err(Error::UnexpectedLabel(label)),
        };
        let descriptor = next_descriptor(generation, &mut sequence)?;
        let wire = encode(descriptor);
        same(observed, wire)?;
        if label == p::RETIRE_REQUESTED {
            return owner_retirement(endpoint, &mut state, exchange, authority, descriptor).await;
        }
        if label == p::PEER_READY {
            owner_admission(
                endpoint,
                &mut state,
                &mut sequence,
                exchange,
                authority,
                descriptor,
            )
            .await?;
            return owner_active(endpoint, &mut state, &mut sequence, exchange, authority).await;
        }
        if label == p::EARLY_SEND_READY {
            if owner_execute(&mut state, exchange, authority, descriptor, label)?
                == ResultBranch::Rejected
            {
                return Err(Error::AdmissionRejected);
            }
            endpoint.send::<p::EarlySendInstalled>(&wire).await?;
            same(endpoint.recv::<p::ResultTaken>().await?, wire)?;
            break;
        }
        let result = owner_execute(&mut state, exchange, authority, descriptor, label)?;
        owner_operation_result(endpoint, wire, result).await?;
        runtime::yield_now().await;
    }
    loop {
        let branch = endpoint.offer().await?;
        let label = branch.label();
        let observed = match label {
            p::PROBE => branch.recv::<p::Probe>().await?,
            p::DELIVER => branch.recv::<p::Deliver>().await?,
            p::ACKNOWLEDGE => branch.recv::<p::Acknowledge>().await?,
            p::LOST => branch.recv::<p::Lost>().await?,
            p::INSPECT => branch.recv::<p::Inspect>().await?,
            p::ENQUEUE_EARLY => branch.recv::<p::EnqueueEarly>().await?,
            p::INSPECT_EARLY => branch.recv::<p::InspectEarly>().await?,
            p::PREPARE_EARLY => branch.recv::<p::PrepareEarly>().await?,
            p::PEER_READY => branch.recv::<p::PeerReady>().await?,
            p::RETIRE_REQUESTED => branch.recv::<p::RetireRequested>().await?,
            label => return Err(Error::UnexpectedLabel(label)),
        };
        let descriptor = next_descriptor(generation, &mut sequence)?;
        let wire = encode(descriptor);
        same(observed, wire)?;
        if label == p::RETIRE_REQUESTED {
            return owner_retirement(endpoint, &mut state, exchange, authority, descriptor).await;
        }
        if label == p::PEER_READY {
            owner_admission(
                endpoint,
                &mut state,
                &mut sequence,
                exchange,
                authority,
                descriptor,
            )
            .await?;
            break;
        }
        if label == p::PREPARE_EARLY {
            owner_prepare(
                endpoint,
                &mut state,
                &mut sequence,
                exchange,
                authority,
                descriptor,
                label,
            )
            .await?;
            continue;
        }
        let result = owner_execute(&mut state, exchange, authority, descriptor, label)?;
        owner_operation_result(endpoint, wire, result).await?;
        runtime::yield_now().await;
    }
    owner_active(endpoint, &mut state, &mut sequence, exchange, authority).await
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientError {
    Closed,
    Correlation,
    UnexpectedReply,
    SequenceExhausted,
    Rejected(Fault),
}
impl From<Fault> for ClientError {
    fn from(e: Fault) -> Self {
        Self::Rejected(e)
    }
}
/// Unique application capability. Dropping any suspended request closes both
/// halves; continuing with a partially applied command is never permitted.
pub struct Client<'c, 's, const N: usize, const Q: usize = 1, const R: usize = 1> {
    commands: Sender<'c, 's, Command<N>, Q>,
    replies: Receiver<'c, 's, Reply<N>, R>,
    generation: u64,
    sequence: u64,
    snapshot: Snapshot,
}
struct RequestPending<'a, 'c, 's, const N: usize, const Q: usize, const R: usize> {
    client: &'a mut Client<'c, 's, N, Q, R>,
    completed: bool,
}
impl<const N: usize, const Q: usize, const R: usize> Drop for RequestPending<'_, '_, '_, N, Q, R> {
    fn drop(&mut self) {
        if !self.completed {
            self.client.close();
        }
    }
}
impl<'c, 's, const N: usize, const Q: usize, const R: usize> Client<'c, 's, N, Q, R> {
    pub async fn connect(
        commands: Sender<'c, 's, Command<N>, Q>,
        mut replies: Receiver<'c, 's, Reply<N>, R>,
        generation: u64,
    ) -> Result<Self, ClientError> {
        let reply = replies.recv().await.map_err(|_| ClientError::Closed)?;
        if reply.descriptor
            != (Descriptor {
                generation,
                sequence: 0,
            })
        {
            return Err(ClientError::Correlation);
        }
        if !matches!(reply.outcome, Outcome::Installed) {
            return Err(ClientError::UnexpectedReply);
        }
        Ok(Self {
            commands,
            replies,
            generation,
            sequence: 1,
            snapshot: reply.snapshot,
        })
    }
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub const fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }
    pub fn close(&mut self) {
        self.commands.close();
        self.replies.close();
    }
    /// The reply is owned. Rejected numerical requests leave the capability
    /// usable; cancellation, correlation, and transport errors close it.
    pub async fn request(&mut self, command: Command<N>) -> Result<Outcome<N>, ClientError> {
        let expected = Descriptor {
            generation: self.generation,
            sequence: self.sequence,
        };
        let Some(next) = self.sequence.checked_add(1) else {
            self.close();
            return Err(ClientError::SequenceExhausted);
        };
        let mut pending = RequestPending {
            client: self,
            completed: false,
        };
        pending
            .client
            .commands
            .send(command)
            .await
            .map_err(|_| ClientError::Closed)?;
        let reply = pending
            .client
            .replies
            .recv()
            .await
            .map_err(|_| ClientError::Closed)?;
        if reply.descriptor != expected {
            return Err(ClientError::Correlation);
        }
        pending.client.sequence = next;
        pending.client.snapshot = reply.snapshot;
        pending.completed = true;
        Ok(reply.outcome)
    }
    async fn call(&mut self, command: Command<N>) -> Result<Outcome<N>, ClientError> {
        match self.request(command).await? {
            Outcome::Rejected(e) => Err(ClientError::Rejected(e)),
            outcome => Ok(outcome),
        }
    }
    fn unexpected<T>(&mut self) -> Result<T, ClientError> {
        self.close();
        Err(ClientError::UnexpectedReply)
    }
    async fn applied(&mut self, command: Command<N>) -> Result<(), ClientError> {
        match self.call(command).await? {
            Outcome::Applied => Ok(()),
            _ => self.unexpected(),
        }
    }
    pub async fn peer_ready(&mut self, grant: PeerReady) -> Result<(), ClientError> {
        self.applied(Command::PeerReady(grant)).await
    }
    pub async fn early_send_ready(
        &mut self,
        grant: super::tls_owner::EarlySendReady,
    ) -> Result<(), ClientError> {
        self.applied(Command::EarlySendReady(grant)).await
    }
    /// Failed admission returns the exact affine release for retry/cancellation;
    /// the early owner retains its original bytes until this completion arrives.
    pub async fn deliver_early(
        &mut self,
        grant: super::early_owner::AppRelease<N>,
    ) -> Result<
        Result<super::early_owner::ReleaseCompletion, (Fault, super::early_owner::AppRelease<N>)>,
        ClientError,
    > {
        match self.request(Command::DeliverEarly(grant)).await? {
            Outcome::EarlyDelivered(completion) => Ok(Ok(completion)),
            Outcome::EarlyRejected { error, grant } => Ok(Err((error, grant))),
            Outcome::Rejected(error) => Err(ClientError::Rejected(error)),
            _ => self.unexpected(),
        }
    }
    pub async fn early_ready(&mut self, grant: EarlyReady) -> Result<(), ClientError> {
        self.applied(Command::EarlyReady(grant)).await
    }
    pub async fn probe(
        &mut self,
        grant: super::recovery_owner::StreamPtoGrant,
    ) -> Result<(), ClientError> {
        self.applied(Command::Probe(grant)).await
    }
    pub async fn deliver(
        &mut self,
        grant: packet_authority::DeliveryGrant<N>,
    ) -> Result<(), ClientError> {
        self.applied(Command::Deliver(grant)).await
    }
    pub async fn acknowledge(
        &mut self,
        grant: super::recovery_owner::StreamAck,
    ) -> Result<(), ClientError> {
        self.applied(Command::Acknowledge(grant)).await
    }
    pub async fn lost(
        &mut self,
        grant: super::recovery_owner::LostPacket,
    ) -> Result<(), ClientError> {
        self.applied(Command::Lost(grant)).await
    }
    pub async fn open(&mut self, bidirectional: bool) -> Result<StreamHandle, ClientError> {
        match self.call(Command::Open { bidirectional }).await? {
            Outcome::Opened(handle) => Ok(handle),
            _ => self.unexpected(),
        }
    }
    pub async fn send(
        &mut self,
        stream: StreamHandle,
        bytes: &[u8],
        fin: bool,
    ) -> Result<(), ClientError> {
        let bytes = Bytes::new(bytes)?;
        self.applied(Command::Send { stream, bytes, fin }).await
    }
    pub async fn read(
        &mut self,
        stream: StreamHandle,
        maximum: usize,
    ) -> Result<ReadResult<N>, ClientError> {
        match self.call(Command::Read { stream, maximum }).await? {
            Outcome::Read(view) => Ok(view),
            _ => self.unexpected(),
        }
    }
    pub async fn consume(&mut self, stream: StreamHandle, count: usize) -> Result<(), ClientError> {
        self.applied(Command::Consume { stream, count }).await
    }
    pub async fn acknowledge_reset(&mut self, stream: StreamHandle) -> Result<u64, ClientError> {
        match self.call(Command::AcknowledgeReset(stream)).await? {
            Outcome::ResetAcknowledged(code) => Ok(code),
            _ => self.unexpected(),
        }
    }
    pub async fn reset(
        &mut self,
        stream: StreamHandle,
        error_code: u64,
    ) -> Result<(), ClientError> {
        self.applied(Command::Reset { stream, error_code }).await
    }
    pub async fn stop(&mut self, stream: StreamHandle, error_code: u64) -> Result<(), ClientError> {
        self.applied(Command::Stop { stream, error_code }).await
    }
    pub async fn retire_stream(&mut self, stream: StreamHandle) -> Result<u64, ClientError> {
        match self.call(Command::RetireStream(stream)).await? {
            Outcome::StreamRetired(id) => Ok(id),
            _ => self.unexpected(),
        }
    }
    pub async fn inspect(
        &mut self,
        stream: Option<StreamHandle>,
    ) -> Result<Option<StreamStatus>, ClientError> {
        match self.call(Command::Inspect { stream }).await? {
            Outcome::Inspected(status) => Ok(status),
            _ => self.unexpected(),
        }
    }
    pub async fn lookup(&mut self, id: u64) -> Result<StreamHandle, ClientError> {
        match self.call(Command::Lookup { id }).await? {
            Outcome::Found(handle) => Ok(handle),
            _ => self.unexpected(),
        }
    }
    pub async fn handles_after(
        &mut self,
        after_id: Option<u64>,
    ) -> Result<HandlePage, ClientError> {
        match self.call(Command::Handles { after_id }).await? {
            Outcome::Handles(page) => Ok(page),
            _ => self.unexpected(),
        }
    }
    pub async fn enqueue_early(&mut self, bytes: &[u8]) -> Result<early_send::Handle, ClientError> {
        let bytes = Bytes::new(bytes)?;
        match self.call(Command::EnqueueEarly(bytes)).await? {
            Outcome::EarlyEnqueued(handle) => Ok(handle),
            _ => self.unexpected(),
        }
    }
    pub async fn early_stream_id(
        &mut self,
        handle: early_send::Handle,
    ) -> Result<u64, ClientError> {
        match self.call(Command::InspectEarly(handle)).await? {
            Outcome::EarlyStreamId(id) => Ok(id),
            _ => self.unexpected(),
        }
    }
    /// A returned frame starts a projected transaction: reserve it or cancel
    /// the preparation, then settle the actual adapter/cancellation grant.
    /// Unrelated requests are illegal until this continuation finishes.
    pub async fn prepare(&mut self, probe: bool) -> Result<Option<PreparedFrame<N>>, ClientError> {
        match self.call(Command::Prepare { probe }).await? {
            Outcome::Prepared(frame) => Ok(frame),
            _ => self.unexpected(),
        }
    }
    /// Early-data preparation has its own bootstrap-only projected edge.
    pub async fn prepare_early(
        &mut self,
        probe: bool,
    ) -> Result<Option<PreparedFrame<N>>, ClientError> {
        match self.call(Command::PrepareEarly { probe }).await? {
            Outcome::Prepared(frame) => Ok(frame),
            _ => self.unexpected(),
        }
    }
    pub async fn reserve(
        &mut self,
        prepared: PreparedId,
        packet: u64,
    ) -> Result<TransmissionId, ClientError> {
        match self.call(Command::Reserve { prepared, packet }).await? {
            Outcome::Reserved(id) => Ok(id),
            _ => self.unexpected(),
        }
    }
    pub async fn cancel_prepared(&mut self, prepared: PreparedId) -> Result<(), ClientError> {
        self.applied(Command::CancelPrepared(prepared)).await
    }
    pub async fn adapter_complete(
        &mut self,
        grant: super::datagram::StreamCompletion,
    ) -> Result<(), ClientError> {
        self.applied(Command::AdapterComplete(grant)).await
    }
    pub async fn cancel_transmission(
        &mut self,
        grant: super::datagram::StreamCancellation,
    ) -> Result<(), ClientError> {
        self.applied(Command::CancelTransmission(grant)).await
    }
    pub async fn retire(mut self) -> Result<(), ClientError> {
        match self.call(Command::Retire).await? {
            Outcome::Retired => Ok(()),
            _ => self.unexpected(),
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) mod test_evidence;
