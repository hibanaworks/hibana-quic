//! Experimental bounded STREAM transport over the real encrypted handshake engine.
//!
//! Caller-owned receive windows and send chunks are reused across streams/files.
//! Peer limits are installed only from the engine's authenticated, CID-validated
//! transport parameters. `local_limits` MUST be the identical limits encoded in
//! the caller's TLS transport parameters; constructing this wrapper does not
//! rewrite an already-built TLS ClientHello/EncryptedExtensions message.
//!
//! Only one adapter report may be outstanding. Report it before receiving more
//! datagrams or changing stream state; Busy means retain/retry the operation.
//! The handshake engine owns authentication, typed-driver gates, PN allocation,
//! path/packet accounting, and encryption. This wrapper never publishes raw data.
//!
//! Reliable bounded numeric control records implement credit updates, STOP and
//! RESET retransmission. PTO probes retain data and use fresh packet numbers;
//! they do not declare all old packets lost. The engine reports exact packet/time
//! threshold losses back to the bounded data/control owners. Recovery and
//! congestion policy remain engine-owned; 0-RTT, migration and partial-chunk
//! packetization are not implemented here. Host interop and Pico execution require
//! separate evidence from this component's unit tests.

use crate::{
    accounting::PacketNumberSpace,
    handshake_endpoint::{self, ApplicationHandler, HandshakeEndpoint, Received, Side, Transmit},
    packet::{self, AckRanges, Frame},
    streams::{
        self, ChunkHandle, Limits, PacketReference, ReadView, Role, SendChunk, SendQueue,
        StreamHandle, StreamSlot, StreamTable, Transmission,
    },
    tls::Provider,
};

#[derive(Debug)]
pub enum Error {
    Engine(handshake_endpoint::Error),
    Early(crate::early_send::Error),
    Streams(streams::Error),
    Wire(packet::Error),
    Busy,
    NotReady,
    InvalidConfiguration,
}
impl From<handshake_endpoint::Error> for Error {
    fn from(e: handshake_endpoint::Error) -> Self {
        Self::Engine(e)
    }
}
impl From<streams::Error> for Error {
    fn from(e: streams::Error) -> Self {
        Self::Streams(e)
    }
}
impl From<packet::Error> for Error {
    fn from(e: packet::Error) -> Self {
        Self::Wire(e)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ControlKind {
    MaxData(u64),
    MaxStreamData {
        stream: StreamHandle,
        maximum: u64,
    },
    MaxStreams {
        bidirectional: bool,
        maximum: u64,
    },
    Reset {
        stream: StreamHandle,
        error_code: u64,
        final_size: u64,
    },
    Stop {
        stream: StreamHandle,
        error_code: u64,
    },
}
impl ControlKind {
    fn same_key(self, other: Self) -> bool {
        match (self, other) {
            (Self::MaxData(_), Self::MaxData(_)) => true,
            (Self::MaxStreamData { stream: a, .. }, Self::MaxStreamData { stream: b, .. })
            | (Self::Reset { stream: a, .. }, Self::Reset { stream: b, .. })
            | (Self::Stop { stream: a, .. }, Self::Stop { stream: b, .. }) => a == b,
            (
                Self::MaxStreams {
                    bidirectional: a, ..
                },
                Self::MaxStreams {
                    bidirectional: b, ..
                },
            ) => a == b,
            _ => false,
        }
    }
    fn frame(self) -> Frame<'static> {
        match self {
            Self::MaxData(maximum) => Frame::MaxData { maximum },
            Self::MaxStreamData { stream, maximum } => Frame::MaxStreamData {
                id: stream.id(),
                maximum,
            },
            Self::MaxStreams {
                bidirectional,
                maximum,
            } => Frame::MaxStreams {
                bidirectional,
                maximum,
            },
            Self::Reset {
                stream,
                error_code,
                final_size,
            } => Frame::ResetStream {
                id: stream.id(),
                error_code,
                final_size,
            },
            Self::Stop { stream, error_code } => Frame::StopSending {
                id: stream.id(),
                error_code,
            },
        }
    }
}
#[derive(Clone, Copy)]
struct Control {
    kind: Option<ControlKind>,
    generation: u64,
    pending: bool,
    delivered: bool,
}
impl Control {
    const EMPTY: Self = Self {
        kind: None,
        generation: 0,
        pending: false,
        delivered: false,
    };
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum RefState {
    Free,
    Reserved,
    Sent,
}
#[derive(Clone, Copy)]
struct ControlReference {
    slot: usize,
    generation: u64,
    packet: u64,
    state: RefState,
}
impl ControlReference {
    const EMPTY: Self = Self {
        slot: 0,
        generation: 0,
        packet: 0,
        state: RefState::Free,
    };
}
#[derive(Clone, Copy)]
struct ControlReservation {
    index: usize,
    slot: usize,
    generation: u64,
    packet: u64,
}

struct Controls<const N: usize, const REFS: usize> {
    entries: [Control; N],
    refs: [ControlReference; REFS],
}
impl<const N: usize, const REFS: usize> Controls<N, REFS> {
    fn new() -> Self {
        Self {
            entries: [Control::EMPTY; N],
            refs: [ControlReference::EMPTY; REFS],
        }
    }
    fn has_refs(&self, slot: usize) -> bool {
        self.refs.iter().any(|r| {
            r.state != RefState::Free
                && r.slot == slot
                && r.generation == self.entries[slot].generation
        })
    }
    fn replaceable(&self, kind: ControlKind) -> Option<usize> {
        self.entries.iter().enumerate().find_map(|(i, c)| {
            (c.kind.is_some_and(|k| k.same_key(kind)) && c.pending && !self.has_refs(i))
                .then_some(i)
        })
    }
    fn can_push(&self, kinds: &[ControlKind]) -> Result<(), streams::Error> {
        let need = kinds
            .iter()
            .filter(|k| self.replaceable(**k).is_none() && !self.already_reliable(**k))
            .count();
        let free = self
            .entries
            .iter()
            .filter(|c| c.kind.is_none() && c.generation < u64::MAX)
            .count();
        if need > free {
            Err(streams::Error::Capacity)
        } else {
            Ok(())
        }
    }
    fn already_reliable(&self, kind: ControlKind) -> bool {
        matches!(kind, ControlKind::Reset { .. } | ControlKind::Stop { .. })
            && self
                .entries
                .iter()
                .any(|c| c.kind.is_some_and(|k| k.same_key(kind)))
    }
    fn push(&mut self, kind: ControlKind) -> Result<(), streams::Error> {
        if self.already_reliable(kind) {
            return Ok(());
        }
        if let Some(i) = self.replaceable(kind) {
            self.entries[i].kind = Some(kind);
            return Ok(());
        }
        let i = self
            .entries
            .iter()
            .position(|c| c.kind.is_none() && c.generation < u64::MAX)
            .ok_or(streams::Error::Capacity)?;
        self.entries[i] = Control {
            kind: Some(kind),
            generation: self.entries[i].generation + 1,
            pending: true,
            delivered: false,
        };
        Ok(())
    }
    fn next(&self, probe: bool) -> Option<usize> {
        self.entries
            .iter()
            .position(|c| c.kind.is_some() && !c.delivered && c.pending)
            .or_else(|| {
                if probe {
                    self.entries
                        .iter()
                        .position(|c| c.kind.is_some() && !c.delivered)
                } else {
                    None
                }
            })
    }
    fn reserve(&mut self, slot: usize, packet: u64) -> Result<ControlReservation, streams::Error> {
        let c = self
            .entries
            .get(slot)
            .ok_or(streams::Error::StaleTransmission)?;
        if c.kind.is_none() || c.delivered {
            return Err(streams::Error::StaleTransmission);
        }
        let index = self
            .refs
            .iter()
            .position(|r| r.state == RefState::Free)
            .ok_or(streams::Error::Capacity)?;
        let r = ControlReference {
            slot,
            generation: c.generation,
            packet,
            state: RefState::Reserved,
        };
        self.refs[index] = r;
        Ok(ControlReservation {
            index,
            slot,
            generation: c.generation,
            packet,
        })
    }
    fn validate(&self, h: ControlReservation) -> Result<(), streams::Error> {
        let r = self
            .refs
            .get(h.index)
            .ok_or(streams::Error::StaleTransmission)?;
        if r.state != RefState::Reserved
            || r.slot != h.slot
            || r.generation != h.generation
            || r.packet != h.packet
        {
            return Err(streams::Error::StaleTransmission);
        }
        Ok(())
    }
    fn report<const RX: usize>(
        &mut self,
        table: &mut StreamTable<'_, RX>,
        h: ControlReservation,
        accepted: bool,
    ) -> Result<(), streams::Error> {
        self.validate(h)?;
        if accepted {
            if let Some(ControlKind::Reset { stream, .. }) = self.entries[h.slot].kind {
                table.reset_transmitted(stream)?;
            }
            self.refs[h.index].state = RefState::Sent;
            self.entries[h.slot].pending = false;
        } else {
            self.refs[h.index].state = RefState::Free;
            self.entries[h.slot].pending = true;
        }
        self.collect();
        Ok(())
    }
    fn acknowledge<const RX: usize>(
        &mut self,
        table: &mut StreamTable<'_, RX>,
        ranges: AckRanges<'_>,
    ) -> Result<(), streams::Error> {
        let contains = |pn| ranges.iter().any(|r| r.smallest <= pn && pn <= r.largest);
        if self
            .refs
            .iter()
            .any(|r| r.state == RefState::Reserved && contains(r.packet))
        {
            return Err(streams::Error::UnsentAcknowledgment);
        }
        for i in 0..self.refs.len() {
            let r = self.refs[i];
            if r.state == RefState::Sent && contains(r.packet) {
                let c = &mut self.entries[r.slot];
                if !c.delivered {
                    if let Some(ControlKind::Reset { stream, .. }) = c.kind {
                        table.reset_acknowledged(stream)?;
                    }
                    c.delivered = true;
                    c.pending = false;
                }
            }
        }
        // Once any copy is ACKed, other already-published control copies carry
        // no separate data-lifetime obligation. Old ACKs become harmless no-ops.
        for r in &mut self.refs {
            if r.state == RefState::Sent && self.entries[r.slot].delivered {
                r.state = RefState::Free;
            }
        }
        self.collect();
        Ok(())
    }
    fn collect(&mut self) {
        for i in 0..self.entries.len() {
            if self.entries[i].delivered && !self.has_refs(i) {
                self.entries[i].kind = None;
            }
        }
    }
    fn on_packet_lost(&mut self, packet: u64) {
        for r in &self.refs {
            if r.state == RefState::Sent && r.packet == packet {
                let control = &mut self.entries[r.slot];
                if !control.delivered {
                    control.pending = true;
                }
            }
        }
    }
}

struct Handler<
    'a,
    's,
    const RX: usize,
    const TX: usize,
    const CONTROLS: usize,
    const CONTROL_REFS: usize,
> {
    table: &'a mut StreamTable<'s, RX>,
    queue: &'a mut SendQueue<'s, TX>,
    controls: &'a mut Controls<CONTROLS, CONTROL_REFS>,
    early: &'a mut Option<crate::early_send::Journal<'s, TX>>,
}
impl<const RX: usize, const TX: usize, const C: usize, const R: usize> ApplicationHandler
    for Handler<'_, '_, RX, TX, C, R>
{
    fn early_decision(&mut self, decision: crate::early_send::Decision, limits: Limits) -> Result<(), streams::Error> {
        let Some(journal) = self.early.as_mut() else { return Ok(()); };
        self.table.apply_peer_initial_limits(limits)?;
        journal.decide(decision).map_err(|_| streams::Error::InvalidTransition)?;
        reconcile_intents(journal,self.table,self.queue)
    }
    fn frame(&mut self, frame: Frame<'_>) -> Result<(), streams::Error> {
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
                    Err(e) => return Err(e),
                };
                self.table.on_stream(h, offset, data, fin)
            }
            Frame::ResetStream {
                id,
                error_code,
                final_size,
            } => {
                let h = match self.table.get_or_accept(id) {
                    Ok(h) => h,
                    Err(streams::Error::Retired) => return Ok(()),
                    Err(e) => return Err(e),
                };
                self.table.on_reset(h, error_code, final_size)
            }
            Frame::StopSending { id, error_code } => {
                let h = match self.table.get_or_accept(id) {
                    Ok(h) => h,
                    Err(streams::Error::Retired) => return Ok(()),
                    Err(e) => return Err(e),
                };
                if self.table.sending_complete(h)? {
                    return Ok(());
                }
                self.controls.can_push(&[ControlKind::Reset {
                    stream: h,
                    error_code,
                    final_size: 0,
                }])?;
                if let Some(reset) = self.queue.reset(self.table, h, error_code)? {
                    self.controls.push(ControlKind::Reset {
                        stream: h,
                        error_code: reset.error_code,
                        final_size: reset.final_size,
                    })?;
                }
                Ok(())
            }
            Frame::MaxData { maximum } => self.table.on_max_data(maximum),
            Frame::MaxStreamData { id, maximum } => {
                let h = match self.table.get_or_accept(id) {
                    Ok(h) => h,
                    Err(streams::Error::Retired) => return Ok(()),
                    Err(e) => return Err(e),
                };
                self.table.on_max_stream_data(h, maximum)
            }
            Frame::MaxStreams {
                bidirectional,
                maximum,
            } => self.table.on_max_streams(bidirectional, maximum),
            Frame::DataBlocked { .. } | Frame::StreamsBlocked { .. } => Ok(()),
            Frame::StreamDataBlocked { id, .. } => {
                let h = match self.table.get_or_accept(id) {
                    Ok(h) => h,
                    Err(streams::Error::Retired) => return Ok(()),
                    Err(e) => return Err(e),
                };
                self.table.stream_receive_capacity(h).map(|_| ())
            }
            _ => Err(streams::Error::StreamState),
        }
    }
    fn acknowledged(&mut self, ranges: AckRanges<'_>) -> Result<(), streams::Error> {
        self.queue.on_packets_acked(self.table, |pn| {
            ranges.iter().any(|r| r.smallest <= pn && pn <= r.largest)
        })?;
        self.queue.release_acked_references(self.table)?;
        self.controls.acknowledge(self.table, ranges)
    }
}

fn reconcile_intents<const RX:usize,const TX:usize>(journal:&mut crate::early_send::Journal<'_,TX>,table:&mut StreamTable<'_,RX>,queue:&mut SendQueue<'_,TX>)->Result<(),streams::Error>{
    let Some(decision)=journal.decision()else{return Ok(())};
    loop { match journal.import_next(table,queue) {
        Ok(Some(_))=>{},Ok(None)=>return Ok(()),
        Err(streams::Error::FlowControl|streams::Error::StreamLimit|streams::Error::Capacity) if decision==crate::early_send::Decision::Rejected=>return Ok(()),
        Err(error)=>return Err(error),
    }}
}
#[derive(Clone, Copy)]
enum ApplicationReservation {
    Early(crate::early_send::SendTicket),
    Stream(Transmission),
    Control(ControlReservation),
}
#[derive(Clone, Copy)]
struct Pending {
    output: Transmit,
    application: Option<ApplicationReservation>,
}

/// One connection's encrypted stream owner. TX must be <=1024 bytes so a
/// complete chunk plus its STREAM/header/tag overhead fits ordinary QUIC MTUs.
pub struct TransportEndpoint<
    'r,
    's,
    T: Provider,
    const RX: usize,
    const TX: usize,
    const CONTROLS: usize = 16,
    const CONTROL_REFS: usize = 64,
> {
    engine: HandshakeEndpoint<'r, 's, T>,
    table: StreamTable<'s, RX>,
    queue: SendQueue<'s, TX>,
    early: Option<crate::early_send::Journal<'s, TX>>,
    controls: Controls<CONTROLS, CONTROL_REFS>,
    pending: Option<Pending>,
    application_probe: bool,
    now: u64,
}
impl<'r, 's, T: Provider, const RX: usize, const TX: usize, const C: usize, const R: usize>
    TransportEndpoint<'r, 's, T, RX, TX, C, R>
{
    pub fn new(
        engine: HandshakeEndpoint<'r, 's, T>,
        local_limits: Limits,
        slots: &'s mut [StreamSlot<RX>],
        send_chunks: &'s mut [SendChunk<TX>],
        send_references: &'s mut [PacketReference],
        queue_id: u64,
    ) -> Result<Self, Error> {
        if TX > 1024
            || TX > handshake_endpoint::MAX_APPLICATION_FRAME_BYTES.saturating_sub(25)
            || C < 2
            || R == 0
        {
            return Err(Error::InvalidConfiguration);
        }
        let role = if engine.side() == Side::Client {
            Role::Client
        } else {
            Role::Server
        };
        let table = StreamTable::new(slots, role, engine.generation(), local_limits, Limits::ZERO)?;
        let queue = SendQueue::new(queue_id, send_chunks, send_references)?;
        let mut result = Self {
            engine,
            table,
            queue,
            early: None,
            controls: Controls::new(),
            pending: None,
            application_probe: false,
            now: 0,
        };
        result.install_peer_limits()?;
        Ok(result)
    }
    pub fn configure_early_send(&mut self,slots:&'s mut [crate::early_send::RequestSlot<TX>])->Result<(),Error>{
        if self.engine.side()!=Side::Client||self.early.is_some()||self.pending.is_some()||self.table.live_count()!=0||self.engine.tls().early_status()!=crate::early_data::EarlyStatus::Offered{return Err(Error::InvalidConfiguration);}
        let limits=self.engine.tls().remembered_early_limits().ok_or(Error::InvalidConfiguration)?;
        self.early=Some(crate::early_send::Journal::new(self.engine.generation(),limits,slots).map_err(Error::Early)?);Ok(())
    }
    pub fn enqueue_early_request(&mut self,bytes:&[u8])->Result<crate::early_send::Handle,Error>{
        self.early.as_mut().ok_or(Error::InvalidConfiguration)?.enqueue(bytes).map_err(Error::Early)
    }
    pub fn early_stream_id(&self,handle:crate::early_send::Handle)->Result<u64,Error>{Ok(self.early.as_ref().ok_or(Error::InvalidConfiguration)?.request(handle).map_err(Error::Early)?.stream_id)}
    pub fn configure_early_receive(&mut self,policy:crate::early_data::ServerPolicy,slots:&'s mut [crate::early_data::QuarantineSlot<{handshake_endpoint::EARLY_REQUEST_BYTES}>])->Result<(),Error>{self.engine.configure_early_receive(policy,slots)?;Ok(())}
    fn transmit_early(&mut self,out:&mut[u8])->Result<Option<Transmit>,Error>{
        let Some(journal)=self.early.as_mut()else{return Ok(None)};
        let Some(handle)=journal.next_transmit(self.application_probe)else{return Ok(None)};
        let request=journal.request(handle).map_err(Error::Early)?;
        let mut encoded=[0u8;handshake_endpoint::MAX_APPLICATION_FRAME_BYTES];
        let n=packet::encode_frame(&Frame::Stream{id:request.stream_id,offset:0,fin:true,data:request.bytes},&mut encoded)?;
        let Some(output)=self.engine.transmit_early_application(&encoded[..n],out)?else{return Ok(None)};
        let ticket=match journal.reserve(handle,output.packet_number.value){Ok(t)=>t,Err(e)=>{self.engine.adapter_result(output,false,self.now)?;return Err(Error::Early(e))}};
        self.pending=Some(Pending{output,application:Some(ApplicationReservation::Early(ticket))});self.application_probe=false;Ok(Some(output))
    }
    fn install_peer_limits(&mut self) -> Result<(), Error> {
        if self.engine.is_retired() {
            self.table.close();
            return Err(Error::Engine(handshake_endpoint::Error::Retired));
        }
        if let Some(limits) = self.engine.verified_peer_limits() {
            self.table.apply_peer_initial_limits(limits)?;
        }
        if let Some(journal)=self.early.as_mut(){ reconcile_intents(journal,&mut self.table,&mut self.queue)?; }
        Ok(())
    }
    fn drain_losses(&mut self) {
        while let Some(packet) = self.engine.take_lost_application_packet() {
            if let Some(journal)=self.early.as_mut(){journal.packet_lost(packet);}
            self.queue.on_packet_lost(packet);
            self.controls.on_packet_lost(packet);
        }
    }
    fn idle(&self) -> Result<(), Error> {
        if self.pending.is_some() {
            Err(Error::Busy)
        } else {
            Ok(())
        }
    }
    fn ready(&mut self) -> Result<(), Error> {
        self.idle()?;
        self.install_peer_limits()?;
        if !self.engine.handshake_complete() {
            return Err(Error::NotReady);
        }
        Ok(())
    }
    fn retire_on_error(&mut self) {
        self.engine.retire();
        if let Some(journal)=self.early.as_mut(){journal.retire();}
        self.table.close();
    }
    /// Outstanding application-owned bytes/control references or an unreported
    /// adapter submission. TLS/control output should additionally be drained via
    /// transmit(); a false value alone is not a remote-delivery/close proof.
    pub fn pending_application_work(&self) -> bool {
        self.connection_state() == crate::lifecycle::State::Active
            && (self.pending.is_some()
                || self.early.as_ref().is_some_and(|j| j.has_intent())
                || self.queue.queued_chunks() != 0
                || self
                    .controls
                    .entries
                    .iter()
                    .any(|control| control.kind.is_some()))
    }
    pub fn receive_key_generation(&self) -> u64 {
        self.engine.tls().receive_key_generation()
    }
    pub fn negotiated_group(&self) -> Option<u16> {
        self.engine.tls().negotiated_group()
    }
    pub fn key_generation(&self) -> u64 {
        self.engine.tls().key_generation()
    }
    pub fn initiate_key_update(&mut self) -> Result<(), Error> {
        self.idle()?;
        self.engine.initiate_key_update()?;
        Ok(())
    }
    pub fn tls(&self) -> &T {
        self.engine.tls()
    }
    pub fn peer_close(&self) -> Option<handshake_endpoint::PeerClose> {
        self.engine.peer_close()
    }
    pub fn close_deadline(&self) -> Option<u64> {
        self.engine.close_deadline()
    }
    pub fn connection_state(&self) -> crate::lifecycle::State {
        self.engine.connection_state()
    }
    pub fn initiate_close(&mut self, reason: crate::lifecycle::CloseReason) -> Result<(), Error> {
        self.idle()?;
        self.engine.close(reason)?;
        self.table.close();
        Ok(())
    }
    pub fn transmit_permitted(&mut self, output: Transmit, now: u64) -> Result<bool, Error> {
        if self.pending.is_none_or(|pending| pending.output != output) {
            return Ok(false);
        }
        let permitted = self.engine.transmit_permitted(output, now)?;
        if !permitted && self.engine.connection_state() == crate::lifecycle::State::Closed {
            self.pending = None;
            self.table.close();
        }
        Ok(permitted)
    }
    pub fn handshake_complete(&self) -> bool {
        self.engine.handshake_complete()
    }
    pub fn is_retired(&self) -> bool {
        self.engine.is_retired()
    }
    pub fn streams(&self) -> &StreamTable<'s, RX> {
        &self.table
    }
    pub fn open(&mut self, bidirectional: bool) -> Result<StreamHandle, Error> {
        self.ready()?;
        if self.early.as_ref().is_some_and(|j| j.has_intent()) { return Err(Error::Busy); }
        Ok(self.table.open_local(bidirectional)?)
    }
    pub fn send(&mut self, stream: StreamHandle, bytes: &[u8], fin: bool) -> Result<(), Error> {
        self.ready()?;
        self.queue.enqueue(&mut self.table, stream, bytes, fin)?;
        Ok(())
    }
    pub fn read(&self, stream: StreamHandle) -> Result<ReadView<'_>, Error> {
        Ok(self.table.receive(stream)?)
    }
    /// Bytes are consumed only after room for both required reliable credit
    /// updates is guaranteed. On Capacity the application must retry this call,
    /// without delivering the same bytes again to its own consumer.
    pub fn consume(&mut self, stream: StreamHandle, count: usize) -> Result<(), Error> {
        self.ready()?;
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
    pub fn acknowledge_reset(&mut self, stream: StreamHandle) -> Result<u64, Error> {
        self.ready()?;
        let limit = self.table.receive_data_capacity();
        let kind = ControlKind::MaxData(limit);
        self.controls.can_push(&[kind])?;
        let error = self.table.acknowledge_received_reset(stream)?;
        self.table.grant_max_data(limit)?;
        self.controls.push(kind)?;
        Ok(error)
    }
    pub fn reset(&mut self, stream: StreamHandle, error_code: u64) -> Result<(), Error> {
        self.ready()?;
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
    pub fn stop(&mut self, stream: StreamHandle, error_code: u64) -> Result<(), Error> {
        self.ready()?;
        let stop = self.table.request_stop(stream, error_code)?;
        self.controls.push(ControlKind::Stop {
            stream,
            error_code: stop.error_code,
        })?;
        Ok(())
    }
    pub fn retire_stream(&mut self, stream: StreamHandle) -> Result<(), Error> {
        self.ready()?;
        let peer_initiated = (stream.id() & 1)
            != if self.engine.side() == Side::Client {
                0
            } else {
                1
            };
        let bidirectional = stream.id() & 2 == 0;
        let previous = if bidirectional {
            self.table.local_limits().max_streams_bidi
        } else {
            self.table.local_limits().max_streams_uni
        };
        let new_credit = if peer_initiated && previous < streams::MAX_STREAMS {
            Some(ControlKind::MaxStreams {
                bidirectional,
                maximum: previous + 1,
            })
        } else {
            None
        };
        if let Some(kind) = new_credit {
            self.controls.can_push(&[kind])?;
        }
        self.table.retire(stream)?;
        self.engine.stream_retired(stream.id())?;
        if let Some(kind) = new_credit {
            match self.table.grant_max_streams(bidirectional, previous + 1) {
                Ok(()) => self.controls.push(kind)?,
                Err(streams::Error::Capacity) => {} // A generation-exhausted slot cannot be promised again.
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
    pub fn enable_ecn(&mut self) -> Result<(), Error> {
        self.idle()?;
        self.engine.enable_ecn()?;
        Ok(())
    }
    pub fn path_identity(&self) -> crate::ecn::PathIdentity {
        self.engine.path_identity()
    }
    pub fn ecn_snapshot(&self) -> crate::ecn::Snapshot {
        self.engine.ecn_snapshot()
    }
    pub fn receive(&mut self, datagram: &[u8], scratch: &mut [u8]) -> Result<Received, Error> {
        self.receive_with_metadata(
            datagram,
            scratch,
            crate::ecn::Metadata {
                path: self.path_identity(),
                codepoint: None,
            },
        )
    }
    pub fn receive_with_metadata(
        &mut self,
        datagram: &[u8],
        scratch: &mut [u8],
        metadata: crate::ecn::Metadata,
    ) -> Result<Received, Error> {
        self.idle()?;
        if self.connection_state() == crate::lifecycle::State::Active {
            self.install_peer_limits()?;
        }
        let mut handler = Handler {
            table: &mut self.table,
            queue: &mut self.queue,
            controls: &mut self.controls,
            early: &mut self.early,
        };
        let result = self
            .engine
            .receive_with_metadata(datagram, scratch, metadata, &mut handler);
        self.drain_losses();
        if self.connection_state() != crate::lifecycle::State::Active {
            self.table.close();
        }
        let report = result?;
        if self.connection_state() == crate::lifecycle::State::Active {
            self.install_peer_limits()?;
        }
        Ok(report)
    }
    pub fn timer(&mut self, now: u64) -> Result<(), Error> {
        if self.connection_state() == crate::lifecycle::State::Active {
            // An unsubmitted output must not pin a connection past idle expiry.
            // Recovery remains serialized with its adapter completion while active.
            if self.engine.poll_idle_timeout(now)? {
                self.pending = None;
                self.table.close();
                self.now = now;
                return Ok(());
            }
            self.idle()?;
        }
        self.engine.timer(now)?;
        self.drain_losses();
        self.now = now;
        if self.connection_state() == crate::lifecycle::State::Closed {
            self.pending = None;
            self.table.close();
        }
        self.application_probe |= self.engine.take_application_probe();
        Ok(())
    }
    pub fn next_deadline(&self) -> Option<u64> {
        self.engine.next_deadline()
    }
    pub fn transmit(&mut self, out: &mut [u8]) -> Result<Option<Transmit>, Error> {
        self.idle()?;
        if self.connection_state() == crate::lifecycle::State::Active {
            self.install_peer_limits()?;
        }
        let engine_output = self.engine.transmit(out)?;
        self.drain_losses();
        if let Some(output) = engine_output {
            self.pending = Some(Pending {
                output,
                application: None,
            });
            return Ok(Some(output));
        }
        if !self.engine.handshake_complete() {
            if matches!(self.engine.tls().early_status(),crate::early_data::EarlyStatus::Offered|crate::early_data::EarlyStatus::AcceptedPendingFinished) && self.engine.tls().has_early_keys() && !self.engine.tls().has_keys(crate::tls::Level::OneRtt) { return self.transmit_early(out); }
            return Ok(None);
        }
        self.install_peer_limits()?;
        self.application_probe |= self.engine.take_application_probe();
        let control = self.controls.next(self.application_probe);
        let chunk: Option<ChunkHandle> = if control.is_none() {
            self.queue.next_pending().or_else(|| {
                if self.application_probe {
                    self.queue.probe_chunk()
                } else {
                    None
                }
            })
        } else {
            None
        };
        let mut plaintext = [0u8; handshake_endpoint::MAX_APPLICATION_FRAME_BYTES];
        let length = if let Some(index) = control {
            packet::encode_frame(
                &self.controls.entries[index]
                    .kind
                    .ok_or(streams::Error::InvalidTransition)?
                    .frame(),
                &mut plaintext,
            )?
        } else if let Some(chunk) = chunk {
            let view = self.queue.chunk(chunk)?;
            packet::encode_frame(
                &Frame::Stream {
                    id: view.stream.id(),
                    offset: view.offset,
                    fin: view.fin,
                    data: view.data,
                },
                &mut plaintext,
            )?
        } else {
            return Ok(None);
        };
        let application_output = self
            .engine
            .transmit_application(&plaintext[..length], out)?;
        self.drain_losses();
        let Some(output) = application_output else {
            return Ok(None);
        };
        if output.packet_number.space != PacketNumberSpace::ApplicationData {
            self.retire_on_error();
            return Err(Error::InvalidConfiguration);
        }
        let reference = if let Some(control) = control {
            self.controls
                .reserve(control, output.packet_number.value)
                .map(ApplicationReservation::Control)
        } else {
            self.queue
                .reserve_transmission(
                    chunk.ok_or(streams::Error::InvalidTransition)?,
                    output.packet_number.value,
                )
                .map(ApplicationReservation::Stream)
        };
        let reference = match reference {
            Ok(r) => r,
            Err(streams::Error::Capacity) => {
                self.engine.adapter_result(output, false, self.now)?;
                self.drain_losses();
                return Ok(None);
            }
            Err(e) => {
                self.engine.adapter_result(output, false, self.now)?;
                self.drain_losses();
                return Err(e.into());
            }
        };
        self.application_probe = false;
        self.pending = Some(Pending {
            output,
            application: Some(reference),
        });
        Ok(Some(output))
    }
    pub fn adapter_result(
        &mut self,
        output: Transmit,
        accepted: bool,
        now: u64,
    ) -> Result<(), Error> {
        let pending = self.pending.ok_or(Error::Busy)?;
        if pending.output != output {
            return Err(Error::Busy);
        }
        if let Err(error) = self.engine.adapter_result(output, accepted, now) {
            if self.engine.connection_state() == crate::lifecycle::State::Closed {
                self.pending = None;
                self.table.close();
            }
            return Err(error.into());
        }
        self.drain_losses();
        let result = match pending.application {
            Some(ApplicationReservation::Early(reference)) => {
                self.early.as_mut().ok_or(streams::Error::InvalidTransition)?.adapter_result(reference,accepted).map_err(|_|streams::Error::InvalidTransition)
            }
            Some(ApplicationReservation::Stream(reference)) => {
                if accepted {
                    self.queue.commit_transmission(&mut self.table, reference)
                } else {
                    self.queue.cancel_transmission(&mut self.table, reference)
                }
            }
            Some(ApplicationReservation::Control(reference)) => {
                self.controls.report(&mut self.table, reference, accepted)
            }
            None => Ok(()),
        };
        self.pending = None;
        self.now = now;
        if let Err(e) = result {
            self.retire_on_error();
            return Err(e.into());
        }
        if self.connection_state() == crate::lifecycle::State::Active {
            self.queue.release_acked_references(&mut self.table)?;
        }
        Ok(())
    }
    /// Immediate local teardown without a wire close. Use initiate_close for
    /// normal protocol shutdown and drive Closing/Draining to its deadline.
    pub fn close(&mut self) -> Result<(), Error> {
        self.idle()?;
        self.retire_on_error();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{AckRange, AckRanges};
    fn table<'a>(slots: &'a mut [StreamSlot<8>]) -> StreamTable<'a, 8> {
        StreamTable::new(
            slots,
            Role::Client,
            1,
            Limits::ZERO,
            Limits {
                max_data: 100,
                max_streams_uni: 1,
                stream_data_uni: 100,
                ..Limits::ZERO
            },
        )
        .unwrap()
    }
    #[test]
    fn controls_retransmit_until_any_copy_is_acked() {
        let mut slots = [StreamSlot::EMPTY];
        let mut table = table(&mut slots);
        let mut controls = Controls::<2, 3>::new();
        controls.push(ControlKind::MaxData(100)).unwrap();
        let first = controls.reserve(0, 7).unwrap();
        controls.report(&mut table, first, true).unwrap();
        assert_eq!(controls.next(false), None);
        assert_eq!(controls.next(true), Some(0));
        let second = controls.reserve(0, 9).unwrap();
        controls.report(&mut table, second, true).unwrap();
        let ranges = [AckRange {
            smallest: 7,
            largest: 7,
        }];
        controls
            .acknowledge(&mut table, AckRanges::new(&ranges).unwrap())
            .unwrap();
        assert!(controls.entries[0].kind.is_none());
        assert!(controls.refs.iter().all(|r| r.state == RefState::Free));
        assert_eq!(controls.next(true), None);
    }
    #[test]
    fn old_control_ack_does_not_release_newer_credit() {
        let mut slots = [StreamSlot::EMPTY];
        let mut table = table(&mut slots);
        let mut controls = Controls::<2, 3>::new();
        controls.push(ControlKind::MaxData(100)).unwrap();
        let first = controls.reserve(0, 7).unwrap();
        controls.report(&mut table, first, true).unwrap();
        controls.push(ControlKind::MaxData(200)).unwrap();
        let second = controls.reserve(1, 8).unwrap();
        controls.report(&mut table, second, true).unwrap();
        controls
            .acknowledge(
                &mut table,
                AckRanges::new(&[AckRange {
                    smallest: 7,
                    largest: 7,
                }])
                .unwrap(),
            )
            .unwrap();
        assert_eq!(controls.entries[1].kind, Some(ControlKind::MaxData(200)));
        assert_eq!(controls.next(true), Some(1));
    }
    #[test]
    fn control_capacity_and_adapter_rejection_keep_pending_value() {
        let mut slots = [StreamSlot::EMPTY];
        let mut table = table(&mut slots);
        let mut controls = Controls::<1, 1>::new();
        controls.push(ControlKind::MaxData(100)).unwrap();
        controls.push(ControlKind::MaxData(200)).unwrap(); // Coalesce only unsent state.
        let tx = controls.reserve(0, 1).unwrap();
        assert_eq!(
            controls.push(ControlKind::MaxData(300)),
            Err(streams::Error::Capacity)
        );
        assert_eq!(
            controls.acknowledge(
                &mut table,
                AckRanges::new(&[AckRange {
                    smallest: 1,
                    largest: 1
                }])
                .unwrap()
            ),
            Err(streams::Error::UnsentAcknowledgment)
        );
        controls.report(&mut table, tx, false).unwrap();
        assert_eq!(controls.next(false), Some(0));
        assert_eq!(controls.entries[0].kind, Some(ControlKind::MaxData(200)));
    }
}
