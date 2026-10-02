//! Bounded stream transport kernels for RFC 9000 §§2–4, 19.4–19.14.
//!
//! Inputs must already be packet-authenticated and legal at their encryption
//! level. This module does not drive packets, retransmit control frames, or make
//! network loss an internal contract failure. It has no TLS or application policy.
//!
//! `StreamTable` borrows real receive storage. Advertised byte/stream credit is
//! constrained by that storage and never shrinks. Every lower implicit peer
//! stream is materialized before advancing its class's *opened* prefix. Together
//! with the explicit live table, this identifies retired IDs exactly, including
//! holes in retirement order; there is no lossy retirement high-water mark.
//! Final-size history is discarded only on retirement, as permitted by §4.5.
//!
//! `SendQueue` copies accepted application chunks into caller-owned slots and
//! holds them while packet references remain. Loss retains late-ACK eligibility;
//! callers may explicitly forget lost references once recovery stops tracking
//! them. Reserve transmission metadata before publishing a packet, commit after
//! adapter acceptance, and cancel on a pre-publication failure. Packet numbers
//! and connection generations must never be reused by the integration layer.
//! Control-frame (RESET_STREAM/STOP_SENDING/MAX_*) retransmission remains the
//! caller's responsibility. All storage and metadata are bounded; no heap/unsafe.
//! One SendQueue owns all send chunks for a StreamTable. A chunk is one complete
//! retransmittable STREAM range: choose BYTES to fit the path packet budget;
//! partial-chunk packetization is not implemented. Large files use many chunks.
//! The endpoint's single owner must settle reserved outputs before closing or
//! replacing its table. A readable byte view is not permission to bypass the
//! endpoint's authenticated-state, generation, congestion or publication gates.

pub const MAX_OFFSET: u64 = (1 << 62) - 1;
pub const MAX_STREAMS: u64 = 1 << 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidConfiguration,
    InvalidId,
    StreamState,
    StreamLimit,
    NotOpened,
    Retired,
    StaleHandle,
    Closed,
    Capacity,
    GenerationExhausted,
    FlowControl,
    FinalSize,
    OffsetOverflow,
    ConflictingOverlap,
    ConsumeBeyondReady,
    InvalidCredit,
    SendClosed,
    ChunkTooLarge,
    StaleChunk,
    StaleTransmission,
    InvalidTransition,
    UnsentAcknowledgment,
    NotTerminal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}
impl Role {
    fn bit(self) -> u64 {
        if self == Self::Client { 0 } else { 1 }
    }
}

/// Transport-parameter values relative to the endpoint advertising them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_data: u64,
    pub max_streams_bidi: u64,
    pub max_streams_uni: u64,
    pub stream_data_bidi_local: u64,
    pub stream_data_bidi_remote: u64,
    pub stream_data_uni: u64,
}
impl Limits {
    pub const ZERO: Self = Self {
        max_data: 0,
        max_streams_bidi: 0,
        max_streams_uni: 0,
        stream_data_bidi_local: 0,
        stream_data_bidi_remote: 0,
        stream_data_uni: 0,
    };
    fn valid(self) -> bool {
        self.max_data <= MAX_OFFSET
            && self.max_streams_bidi <= MAX_STREAMS
            && self.max_streams_uni <= MAX_STREAMS
            && self.stream_data_bidi_local <= MAX_OFFSET
            && self.stream_data_bidi_remote <= MAX_OFFSET
            && self.stream_data_uni <= MAX_OFFSET
    }
}

/// Private fields prevent accidentally manufacturing a current stream lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamHandle {
    connection: u64,
    slot: usize,
    generation: u64,
    id: u64,
}
impl StreamHandle {
    pub fn id(self) -> u64 {
        self.id
    }
    pub fn slot(self) -> usize {
        self.slot
    }
}

#[derive(Clone, Copy)]
struct State {
    id: u64,
    live: bool,
    generation: u64,
    receive_limit: u64,
    receive_highest: u64,
    receive_final: Option<u64>,
    receive_reset: Option<u64>,
    reset_read: bool,
    consumed: u64,
    head: usize,
    send_limit: u64,
    send_end: u64,
    send_emitted: u64,
    send_final: Option<u64>,
    send_fin_acked: bool,
    send_reset: Option<u64>,
    reset_transmitted: bool,
    reset_acked: bool,
    pending_chunks: usize,
    unacked_chunks: usize,
}
impl State {
    const EMPTY: Self = Self {
        id: 0,
        live: false,
        generation: 0,
        receive_limit: 0,
        receive_highest: 0,
        receive_final: None,
        receive_reset: None,
        reset_read: false,
        consumed: 0,
        head: 0,
        send_limit: 0,
        send_end: 0,
        send_emitted: 0,
        send_final: None,
        send_fin_acked: false,
        send_reset: None,
        reset_transmitted: false,
        reset_acked: false,
        pending_chunks: 0,
        unacked_chunks: 0,
    };
}

/// Caller-owned storage, reusable after both directions become terminal.
/// Initialize large arrays in static storage with `[const { StreamSlot::EMPTY }; N]`
/// where appropriate; `new` resets metadata in place rather than moving an arena.
pub struct StreamSlot<const RX: usize> {
    state: State,
    bytes: [u8; RX],
    present: [bool; RX],
}
impl<const RX: usize> StreamSlot<RX> {
    pub const EMPTY: Self = Self {
        state: State::EMPTY,
        bytes: [0; RX],
        present: [false; RX],
    };
    fn index(&self, relative: usize) -> usize {
        let tail = RX - self.state.head;
        if relative < tail {
            self.state.head + relative
        } else {
            relative - tail
        }
    }
    fn ready_len(&self) -> usize {
        if self.state.receive_reset.is_some() {
            return 0;
        }
        (0..RX).take_while(|i| self.present[self.index(*i)]).count()
    }
}

/// Read view is valid only while the table is borrowed. A FIN is ready when the
/// returned contiguous bytes end exactly at the final size; consume them first.
pub struct ReadView<'a> {
    pub first: &'a [u8],
    pub second: &'a [u8],
    pub fin: bool,
    pub reset: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reset {
    pub id: u64,
    pub error_code: u64,
    pub final_size: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StopSending {
    pub id: u64,
    pub error_code: u64,
}

/// Snapshot for backpressure and DATA_BLOCKED / STREAM_DATA_BLOCKED generation.
/// Re-query after MAX_* updates; creating a notification does not grant credit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendCredit {
    pub connection_limit: u64,
    pub connection_available: u64,
    pub stream_limit: u64,
    pub stream_available: u64,
}

pub struct StreamTable<'a, const RX: usize> {
    slots: &'a mut [StreamSlot<RX>],
    role: Role,
    connection: u64,
    local: Limits,
    peer: Limits,
    opened: [u64; 4],
    retired: [u64; 4],
    receive_charged: u64,
    receive_released: u64,
    send_reserved: u64,
    closed: bool,
}

impl<'a, const RX: usize> StreamTable<'a, RX> {
    /// `connection` must be fresh for the lifetime of any old handles/events.
    pub fn new(
        slots: &'a mut [StreamSlot<RX>],
        role: Role,
        connection: u64,
        local: Limits,
        peer: Limits,
    ) -> Result<Self, Error> {
        let capacity = (RX as u64)
            .checked_mul(slots.len() as u64)
            .ok_or(Error::InvalidConfiguration)?;
        if RX == 0
            || slots.is_empty()
            || !local.valid()
            || !peer.valid()
            || local.stream_data_bidi_local > RX as u64
            || local.stream_data_bidi_remote > RX as u64
            || local.stream_data_uni > RX as u64
            || local.max_data > capacity
            || local
                .max_streams_bidi
                .checked_add(local.max_streams_uni)
                .filter(|v| *v <= slots.len() as u64)
                .is_none()
        {
            return Err(Error::InvalidConfiguration);
        }
        for slot in slots.iter_mut() {
            slot.state = State::EMPTY;
            slot.present.fill(false);
        }
        Ok(Self {
            slots,
            role,
            connection,
            local,
            peer,
            opened: [0; 4],
            retired: [0; 4],
            receive_charged: 0,
            receive_released: 0,
            send_reserved: 0,
            closed: false,
        })
    }
    fn check_open(&self) -> Result<(), Error> {
        if self.closed {
            Err(Error::Closed)
        } else {
            Ok(())
        }
    }
    fn is_local(&self, id: u64) -> bool {
        id & 1 == self.role.bit()
    }
    fn can_send(&self, id: u64) -> bool {
        id & 2 == 0 || self.is_local(id)
    }
    fn can_receive(&self, id: u64) -> bool {
        id & 2 == 0 || !self.is_local(id)
    }
    fn handle_at(&self, index: usize) -> StreamHandle {
        let s = self.slots[index].state;
        StreamHandle {
            connection: self.connection,
            slot: index,
            generation: s.generation,
            id: s.id,
        }
    }
    fn validate(&self, h: StreamHandle) -> Result<usize, Error> {
        self.check_open()?;
        let slot = self.slots.get(h.slot).ok_or(Error::StaleHandle)?;
        if h.connection != self.connection
            || !slot.state.live
            || slot.state.id != h.id
            || slot.state.generation != h.generation
        {
            return Err(Error::StaleHandle);
        }
        Ok(h.slot)
    }
    pub fn lookup(&self, id: u64) -> Result<StreamHandle, Error> {
        self.check_open()?;
        if id > MAX_OFFSET {
            return Err(Error::InvalidId);
        }
        if let Some(index) = self
            .slots
            .iter()
            .position(|s| s.state.live && s.state.id == id)
        {
            return Ok(self.handle_at(index));
        }
        if id / 4 < self.opened[(id & 3) as usize] {
            Err(Error::Retired)
        } else {
            Err(Error::NotOpened)
        }
    }
    pub fn live_handles(&self) -> impl Iterator<Item = StreamHandle> + '_ {
        self.slots
            .iter()
            .enumerate()
            .filter(|(_, s)| s.state.live)
            .map(|(i, _)| self.handle_at(i))
    }
    pub fn live_count(&self) -> usize {
        self.slots.iter().filter(|s| s.state.live).count()
    }
    pub fn cumulative_opened(&self, first_id: u8) -> Result<u64, Error> {
        self.opened
            .get(first_id as usize)
            .copied()
            .ok_or(Error::InvalidId)
    }
    pub fn receive_charged(&self) -> u64 {
        self.receive_charged
    }
    pub fn send_reserved(&self) -> u64 {
        self.send_reserved
    }
    pub fn local_limits(&self) -> Limits {
        self.local
    }
    pub fn peer_limits(&self) -> Limits {
        self.peer
    }
    /// Install authenticated initial transport parameters. Larger MAX_* credit
    /// already received is preserved. This is idempotent; the connection owner
    /// must never use unauthenticated or different-connection parameters here.
    pub fn apply_peer_initial_limits(&mut self, limits: Limits) -> Result<(), Error> {
        self.check_open()?;
        if !limits.valid() {
            return Err(Error::InvalidCredit);
        }
        self.peer.max_data = self.peer.max_data.max(limits.max_data);
        self.peer.max_streams_bidi = self.peer.max_streams_bidi.max(limits.max_streams_bidi);
        self.peer.max_streams_uni = self.peer.max_streams_uni.max(limits.max_streams_uni);
        self.peer.stream_data_bidi_local = self
            .peer
            .stream_data_bidi_local
            .max(limits.stream_data_bidi_local);
        self.peer.stream_data_bidi_remote = self
            .peer
            .stream_data_bidi_remote
            .max(limits.stream_data_bidi_remote);
        self.peer.stream_data_uni = self.peer.stream_data_uni.max(limits.stream_data_uni);
        let role = self.role.bit();
        for slot in self.slots.iter_mut().filter(|s| s.state.live) {
            let id = slot.state.id;
            let locally_initiated = id & 1 == role;
            let initial = if id & 2 != 0 {
                if locally_initiated {
                    self.peer.stream_data_uni
                } else {
                    0
                }
            } else if locally_initiated {
                self.peer.stream_data_bidi_remote
            } else {
                self.peer.stream_data_bidi_local
            };
            slot.state.send_limit = slot.state.send_limit.max(initial);
        }
        Ok(())
    }
    pub fn receive_final_size(&self, h: StreamHandle) -> Result<Option<u64>, Error> {
        let index = self.validate(h)?;
        Ok(self.slots[index].state.receive_final)
    }
    pub fn sending_complete(&self, h: StreamHandle) -> Result<bool, Error> {
        let index = self.validate(h)?;
        if !self.can_send(h.id) {
            return Err(Error::StreamState);
        }
        let s = self.slots[index].state;
        Ok(s.reset_acked || (s.send_fin_acked && s.unacked_chunks == 0))
    }
    pub fn send_credit(&self, h: StreamHandle) -> Result<SendCredit, Error> {
        let i = self.validate(h)?;
        if !self.can_send(h.id) {
            return Err(Error::StreamState);
        }
        let s = self.slots[i].state;
        if s.send_final.is_some() || s.send_reset.is_some() {
            return Err(Error::SendClosed);
        }
        Ok(SendCredit {
            connection_limit: self.peer.max_data,
            connection_available: self.peer.max_data - self.send_reserved,
            stream_limit: s.send_limit,
            stream_available: s.send_limit - s.send_end,
        })
    }

    fn peer_promised_slots(&self, bidi: u64, uni: u64) -> Result<u64, Error> {
        let peer_bit = 1 - self.role.bit();
        bidi.checked_sub(self.retired[peer_bit as usize])
            .and_then(|b| {
                uni.checked_sub(self.retired[(peer_bit | 2) as usize])
                    .and_then(|u| b.checked_add(u))
            })
            .ok_or(Error::InvalidCredit)
    }
    fn reusable_slots(&self) -> u64 {
        self.slots
            .iter()
            .filter(|s| s.state.live || s.state.generation < u64::MAX)
            .count() as u64
    }
    fn local_live_count(&self) -> u64 {
        self.slots
            .iter()
            .filter(|s| s.state.live && self.is_local(s.state.id))
            .count() as u64
    }
    fn allocate(&mut self, id: u64) -> Result<StreamHandle, Error> {
        let index = self
            .slots
            .iter()
            .position(|s| !s.state.live && s.state.generation < u64::MAX)
            .ok_or(Error::Capacity)?;
        let locally_initiated = self.is_local(id);
        let (receive_limit, send_limit) = if id & 2 != 0 {
            (
                if locally_initiated {
                    0
                } else {
                    self.local.stream_data_uni
                },
                if locally_initiated {
                    self.peer.stream_data_uni
                } else {
                    0
                },
            )
        } else if locally_initiated {
            (
                self.local.stream_data_bidi_local,
                self.peer.stream_data_bidi_remote,
            )
        } else {
            (
                self.local.stream_data_bidi_remote,
                self.peer.stream_data_bidi_local,
            )
        };
        let slot = &mut self.slots[index];
        slot.state = State {
            id,
            live: true,
            generation: slot.state.generation + 1,
            receive_limit,
            send_limit,
            ..State::EMPTY
        };
        slot.present.fill(false);
        Ok(self.handle_at(index))
    }
    pub fn open_local(&mut self, bidirectional: bool) -> Result<StreamHandle, Error> {
        self.check_open()?;
        let class = self.role.bit() | if bidirectional { 0 } else { 2 };
        let count = self.opened[class as usize];
        let limit = if bidirectional {
            self.peer.max_streams_bidi
        } else {
            self.peer.max_streams_uni
        };
        if count >= limit {
            return Err(Error::StreamLimit);
        }
        let promises =
            self.peer_promised_slots(self.local.max_streams_bidi, self.local.max_streams_uni)?;
        if promises + self.local_live_count() >= self.reusable_slots() {
            return Err(Error::Capacity);
        }
        let handle = self.allocate(count * 4 + class)?;
        self.opened[class as usize] += 1;
        Ok(handle)
    }
    /// Frames for an already-open local stream are allowed; only the peer may
    /// implicitly open peer-initiated streams. Every lower ID gets real storage.
    pub fn get_or_accept(&mut self, id: u64) -> Result<StreamHandle, Error> {
        match self.lookup(id) {
            Ok(h) => return Ok(h),
            Err(Error::NotOpened) => {}
            Err(e) => return Err(e),
        }
        if self.is_local(id) {
            return Err(Error::StreamState);
        }
        let class = (id & 3) as usize;
        let count = id / 4 + 1;
        let limit = if id & 2 == 0 {
            self.local.max_streams_bidi
        } else {
            self.local.max_streams_uni
        };
        if count > limit {
            return Err(Error::StreamLimit);
        }
        let needed = count - self.opened[class];
        let available = self
            .slots
            .iter()
            .filter(|s| !s.state.live && s.state.generation < u64::MAX)
            .count() as u64;
        if needed > available {
            return Err(Error::Capacity);
        }
        // Preflight above ensures the entire implicit prefix can be committed.
        for index in self.opened[class]..count {
            self.allocate(index * 4 + class as u64)?;
        }
        self.opened[class] = count;
        self.lookup(id)
    }
    /// Received MAX_* values are monotonic: reordered smaller values are ignored.
    pub fn on_max_data(&mut self, maximum: u64) -> Result<(), Error> {
        self.check_open()?;
        if maximum > MAX_OFFSET {
            return Err(Error::InvalidCredit);
        }
        self.peer.max_data = self.peer.max_data.max(maximum);
        Ok(())
    }
    pub fn on_max_streams(&mut self, bidirectional: bool, maximum: u64) -> Result<(), Error> {
        self.check_open()?;
        if maximum > MAX_STREAMS {
            return Err(Error::InvalidCredit);
        }
        let value = if bidirectional {
            &mut self.peer.max_streams_bidi
        } else {
            &mut self.peer.max_streams_uni
        };
        *value = (*value).max(maximum);
        Ok(())
    }
    pub fn on_max_stream_data(&mut self, h: StreamHandle, maximum: u64) -> Result<(), Error> {
        let i = self.validate(h)?;
        if !self.can_send(h.id) {
            return Err(Error::StreamState);
        }
        if maximum > MAX_OFFSET {
            return Err(Error::InvalidCredit);
        }
        self.slots[i].state.send_limit = self.slots[i].state.send_limit.max(maximum);
        Ok(())
    }
    /// Returns the largest safe MAX_DATA given cumulative released capacity.
    pub fn receive_data_capacity(&self) -> u64 {
        self.receive_released
            .saturating_add((RX as u64).saturating_mul(self.slots.len() as u64))
            .min(MAX_OFFSET)
    }
    pub fn grant_max_data(&mut self, maximum: u64) -> Result<(), Error> {
        self.check_open()?;
        if maximum < self.local.max_data || maximum > self.receive_data_capacity() {
            return Err(Error::InvalidCredit);
        }
        self.local.max_data = maximum;
        Ok(())
    }
    pub fn stream_receive_capacity(&self, h: StreamHandle) -> Result<u64, Error> {
        let i = self.validate(h)?;
        if !self.can_receive(h.id) {
            return Err(Error::StreamState);
        }
        Ok(self.slots[i]
            .state
            .consumed
            .saturating_add(RX as u64)
            .min(MAX_OFFSET))
    }
    pub fn grant_max_stream_data(&mut self, h: StreamHandle, maximum: u64) -> Result<(), Error> {
        let capacity = self.stream_receive_capacity(h)?;
        let s = &mut self.slots[h.slot].state;
        if maximum < s.receive_limit || maximum > capacity || s.receive_final.is_some() {
            return Err(Error::InvalidCredit);
        }
        s.receive_limit = maximum;
        Ok(())
    }
    pub fn grant_max_streams(&mut self, bidirectional: bool, maximum: u64) -> Result<(), Error> {
        self.check_open()?;
        let old = if bidirectional {
            self.local.max_streams_bidi
        } else {
            self.local.max_streams_uni
        };
        if maximum < old || maximum > MAX_STREAMS {
            return Err(Error::InvalidCredit);
        }
        let bidi = if bidirectional {
            maximum
        } else {
            self.local.max_streams_bidi
        };
        let uni = if bidirectional {
            self.local.max_streams_uni
        } else {
            maximum
        };
        if self
            .peer_promised_slots(bidi, uni)?
            .checked_add(self.local_live_count())
            .filter(|n| *n <= self.reusable_slots())
            .is_none()
        {
            return Err(Error::Capacity);
        }
        if bidirectional {
            self.local.max_streams_bidi = maximum;
        } else {
            self.local.max_streams_uni = maximum;
        }
        Ok(())
    }
    fn validate_receive_end(
        &self,
        h: StreamHandle,
        end: u64,
        terminal: bool,
    ) -> Result<(usize, u64), Error> {
        let i = self.validate(h)?;
        if !self.can_receive(h.id) {
            return Err(Error::StreamState);
        }
        let s = self.slots[i].state;
        if end > MAX_OFFSET {
            return Err(Error::OffsetOverflow);
        }
        if s.receive_final
            .is_some_and(|n| end > n || (terminal && end != n))
            || (terminal && end < s.receive_highest)
        {
            return Err(Error::FinalSize);
        }
        if end > s.receive_limit {
            return Err(Error::FlowControl);
        }
        let charged = self
            .receive_charged
            .checked_add(end.saturating_sub(s.receive_highest))
            .ok_or(Error::FlowControl)?;
        if charged > self.local.max_data {
            return Err(Error::FlowControl);
        }
        Ok((i, charged))
    }
    /// Validate byte ranges, final size, both flow limits and overlap before any
    /// state changes. Retransmissions of consumed data are ignored.
    pub fn on_stream(
        &mut self,
        h: StreamHandle,
        offset: u64,
        data: &[u8],
        fin: bool,
    ) -> Result<(), Error> {
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(Error::OffsetOverflow)?;
        let (i, charged) = self.validate_receive_end(h, end, fin)?;
        let slot = &mut self.slots[i];
        let s = slot.state;
        if offset > MAX_OFFSET {
            return Err(Error::OffsetOverflow);
        }
        if s.receive_reset.is_none() && end > s.consumed {
            if end - s.consumed > RX as u64 {
                return Err(Error::Capacity);
            }
            let start = offset.max(s.consumed);
            let skip = (start - offset) as usize;
            let relative = (start - s.consumed) as usize;
            for (n, byte) in data[skip..].iter().enumerate() {
                let index = slot.index(relative + n);
                if slot.present[index] && slot.bytes[index] != *byte {
                    return Err(Error::ConflictingOverlap);
                }
            }
            for (n, byte) in data[skip..].iter().enumerate() {
                let index = slot.index(relative + n);
                slot.bytes[index] = *byte;
                slot.present[index] = true;
            }
        }
        slot.state.receive_highest = s.receive_highest.max(end);
        if fin {
            slot.state.receive_final = Some(end);
        }
        self.receive_charged = charged;
        Ok(())
    }
    pub fn on_reset(
        &mut self,
        h: StreamHandle,
        error_code: u64,
        final_size: u64,
    ) -> Result<(), Error> {
        if error_code > MAX_OFFSET {
            return Err(Error::InvalidId);
        }
        let (i, charged) = self.validate_receive_end(h, final_size, true)?;
        let slot = &mut self.slots[i];
        if slot.state.receive_reset.is_none() {
            self.receive_released += final_size - slot.state.consumed;
            slot.state.consumed = final_size;
            slot.state.receive_reset = Some(error_code);
            slot.present.fill(false);
        }
        slot.state.receive_final = Some(final_size);
        slot.state.receive_highest = final_size;
        self.receive_charged = charged;
        Ok(())
    }
    pub fn receive(&self, h: StreamHandle) -> Result<ReadView<'_>, Error> {
        let i = self.validate(h)?;
        if !self.can_receive(h.id) {
            return Err(Error::StreamState);
        }
        let slot = &self.slots[i];
        let ready = slot.ready_len();
        let first = ready.min(RX - slot.state.head);
        Ok(ReadView {
            first: &slot.bytes[slot.state.head..slot.state.head + first],
            second: &slot.bytes[..ready - first],
            fin: slot.state.receive_reset.is_none()
                && slot.state.receive_final == Some(slot.state.consumed + ready as u64),
            reset: slot.state.receive_reset,
        })
    }
    pub fn consume(&mut self, h: StreamHandle, count: usize) -> Result<(), Error> {
        let i = self.validate(h)?;
        if !self.can_receive(h.id) {
            return Err(Error::StreamState);
        }
        let slot = &mut self.slots[i];
        if count > slot.ready_len() {
            return Err(Error::ConsumeBeyondReady);
        }
        for n in 0..count {
            let index = slot.index(n);
            slot.present[index] = false;
        }
        if count < RX {
            slot.state.head = slot.index(count);
        }
        slot.state.consumed += count as u64;
        self.receive_released += count as u64;
        Ok(())
    }
    pub fn acknowledge_received_reset(&mut self, h: StreamHandle) -> Result<u64, Error> {
        let i = self.validate(h)?;
        let s = &mut self.slots[i].state;
        let error = s.receive_reset.ok_or(Error::InvalidTransition)?;
        s.reset_read = true;
        Ok(error)
    }
    pub fn request_stop(&self, h: StreamHandle, error_code: u64) -> Result<StopSending, Error> {
        self.validate(h)?;
        if !self.can_receive(h.id) {
            return Err(Error::StreamState);
        }
        if error_code > MAX_OFFSET {
            return Err(Error::InvalidId);
        }
        let slot = &self.slots[h.slot];
        if slot.state.receive_reset.is_some()
            || slot.state.receive_final == Some(slot.state.consumed + slot.ready_len() as u64)
        {
            return Err(Error::InvalidTransition);
        }
        Ok(StopSending {
            id: h.id,
            error_code,
        })
    }
    fn reserve_send(&mut self, h: StreamHandle, length: usize, fin: bool) -> Result<u64, Error> {
        let i = self.validate(h)?;
        if !self.can_send(h.id) {
            return Err(Error::StreamState);
        }
        let s = self.slots[i].state;
        if s.send_final.is_some() || s.send_reset.is_some() {
            return Err(Error::SendClosed);
        }
        let end = s
            .send_end
            .checked_add(length as u64)
            .filter(|n| *n <= MAX_OFFSET)
            .ok_or(Error::OffsetOverflow)?;
        let reserved = self
            .send_reserved
            .checked_add(length as u64)
            .ok_or(Error::FlowControl)?;
        if end > s.send_limit || reserved > self.peer.max_data {
            return Err(Error::FlowControl);
        }
        let pending = s.pending_chunks.checked_add(1).ok_or(Error::Capacity)?;
        let unacked = s.unacked_chunks.checked_add(1).ok_or(Error::Capacity)?;
        let state = &mut self.slots[i].state;
        state.send_end = end;
        state.pending_chunks = pending;
        state.unacked_chunks = unacked;
        if fin {
            state.send_final = Some(end);
        }
        self.send_reserved = reserved;
        Ok(s.send_end)
    }
    fn sent(&mut self, h: StreamHandle, end: u64) -> Result<(), Error> {
        let i = self.validate(h)?;
        let s = &mut self.slots[i].state;
        if s.send_reset.is_some() || end > s.send_end {
            return Err(Error::SendClosed);
        }
        s.send_emitted = s.send_emitted.max(end);
        Ok(())
    }
    fn chunk_acked(&mut self, h: StreamHandle, fin: bool) -> Result<(), Error> {
        let i = self.validate(h)?;
        self.slots[i].state.unacked_chunks = self.slots[i]
            .state
            .unacked_chunks
            .checked_sub(1)
            .ok_or(Error::InvalidTransition)?;
        if fin {
            self.slots[i].state.send_fin_acked = true;
        }
        Ok(())
    }
    fn chunk_released(&mut self, h: StreamHandle) -> Result<(), Error> {
        let i = self.validate(h)?;
        self.slots[i].state.pending_chunks = self.slots[i]
            .state
            .pending_chunks
            .checked_sub(1)
            .ok_or(Error::InvalidTransition)?;
        Ok(())
    }
    fn begin_reset(&mut self, h: StreamHandle, error_code: u64) -> Result<Option<Reset>, Error> {
        let i = self.validate(h)?;
        if !self.can_send(h.id) {
            return Err(Error::StreamState);
        }
        if error_code > MAX_OFFSET {
            return Err(Error::InvalidId);
        }
        let s = &mut self.slots[i].state;
        if s.reset_acked || (s.send_fin_acked && s.unacked_chunks == 0) {
            return Ok(None);
        }
        if let Some(error) = s.send_reset {
            return Ok(Some(Reset {
                id: h.id,
                error_code: error,
                final_size: s.send_emitted,
            }));
        }
        self.send_reserved -= s.send_end - s.send_emitted;
        s.send_end = s.send_emitted;
        s.send_final = Some(s.send_emitted);
        s.send_reset = Some(error_code);
        s.unacked_chunks = 0;
        Ok(Some(Reset {
            id: h.id,
            error_code,
            final_size: s.send_emitted,
        }))
    }
    pub fn reset_transmitted(&mut self, h: StreamHandle) -> Result<(), Error> {
        let i = self.validate(h)?;
        let s = &mut self.slots[i].state;
        if s.send_reset.is_none() {
            return Err(Error::InvalidTransition);
        }
        s.reset_transmitted = true;
        Ok(())
    }
    pub fn reset_acknowledged(&mut self, h: StreamHandle) -> Result<(), Error> {
        let i = self.validate(h)?;
        let s = &mut self.slots[i].state;
        if !s.reset_transmitted {
            return Err(Error::UnsentAcknowledgment);
        }
        s.reset_acked = true;
        Ok(())
    }
    pub fn retire(&mut self, h: StreamHandle) -> Result<(), Error> {
        let i = self.validate(h)?;
        let s = self.slots[i].state;
        let receive_done = !self.can_receive(h.id)
            || if s.receive_reset.is_some() {
                s.reset_read
            } else {
                s.receive_final == Some(s.consumed)
            };
        let send_done = !self.can_send(h.id)
            || (s.pending_chunks == 0
                && if s.send_reset.is_some() {
                    s.reset_acked
                } else {
                    s.send_fin_acked
                });
        if !receive_done || !send_done {
            return Err(Error::NotTerminal);
        }
        self.retired[(h.id & 3) as usize] += 1;
        self.slots[i].state.live = false;
        self.slots[i].present.fill(false);
        Ok(())
    }
    pub fn close(&mut self) {
        self.closed = true;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkHandle {
    queue: u64,
    slot: usize,
    generation: u64,
}
#[derive(Clone, Copy)]
struct ChunkState {
    generation: u64,
    stream: Option<StreamHandle>,
    offset: u64,
    length: usize,
    fin: bool,
    acked: bool,
    pending: bool,
}
impl ChunkState {
    const EMPTY: Self = Self {
        generation: 0,
        stream: None,
        offset: 0,
        length: 0,
        fin: false,
        acked: false,
        pending: false,
    };
}
pub struct SendChunk<const BYTES: usize> {
    state: ChunkState,
    bytes: [u8; BYTES],
}
impl<const BYTES: usize> SendChunk<BYTES> {
    pub const EMPTY: Self = Self {
        state: ChunkState::EMPTY,
        bytes: [0; BYTES],
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReferenceState {
    Free,
    Reserved,
    Sent,
    Lost,
}
#[derive(Clone, Copy)]
pub struct PacketReference {
    generation: u64,
    chunk: usize,
    chunk_generation: u64,
    packet: u64,
    state: ReferenceState,
}
impl PacketReference {
    pub const EMPTY: Self = Self {
        generation: 0,
        chunk: 0,
        chunk_generation: 0,
        packet: 0,
        state: ReferenceState::Free,
    };
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transmission {
    queue: u64,
    slot: usize,
    generation: u64,
}
pub struct ChunkView<'a> {
    pub stream: StreamHandle,
    pub offset: u64,
    pub fin: bool,
    pub data: &'a [u8],
}

/// One queue may hold chunks for multiple live streams. `queue` must be unique
/// while descriptors can arrive; this object cannot be cloned or rebound.
pub struct SendQueue<'a, const BYTES: usize> {
    queue: u64,
    chunks: &'a mut [SendChunk<BYTES>],
    references: &'a mut [PacketReference],
    cursor: usize,
}
impl<'a, const BYTES: usize> SendQueue<'a, BYTES> {
    pub fn new(
        queue: u64,
        chunks: &'a mut [SendChunk<BYTES>],
        references: &'a mut [PacketReference],
    ) -> Result<Self, Error> {
        if BYTES == 0 || chunks.is_empty() || references.is_empty() {
            return Err(Error::InvalidConfiguration);
        }
        for c in chunks.iter_mut() {
            c.state = ChunkState::EMPTY;
        }
        references.fill(PacketReference::EMPTY);
        Ok(Self {
            queue,
            chunks,
            references,
            cursor: 0,
        })
    }
    fn validate_chunk(&self, h: ChunkHandle) -> Result<usize, Error> {
        let chunk = self.chunks.get(h.slot).ok_or(Error::StaleChunk)?;
        if h.queue != self.queue
            || chunk.state.stream.is_none()
            || chunk.state.generation != h.generation
        {
            return Err(Error::StaleChunk);
        }
        Ok(h.slot)
    }
    fn validate_transmission(&self, h: Transmission) -> Result<usize, Error> {
        let reference = self
            .references
            .get(h.slot)
            .ok_or(Error::StaleTransmission)?;
        if h.queue != self.queue
            || reference.state == ReferenceState::Free
            || reference.generation != h.generation
        {
            return Err(Error::StaleTransmission);
        }
        Ok(h.slot)
    }
    fn handle(&self, slot: usize) -> ChunkHandle {
        ChunkHandle {
            queue: self.queue,
            slot,
            generation: self.chunks[slot].state.generation,
        }
    }
    pub fn queued_chunks(&self) -> usize {
        self.chunks
            .iter()
            .filter(|c| c.state.stream.is_some())
            .count()
    }
    pub fn active_references(&self) -> usize {
        self.references
            .iter()
            .filter(|r| r.state != ReferenceState::Free)
            .count()
    }
    /// Backpressure is returned before accepting/copying bytes or reserving flow
    /// credit. Empty chunks are permitted only when carrying FIN.
    pub fn enqueue<const RX: usize>(
        &mut self,
        table: &mut StreamTable<'_, RX>,
        stream: StreamHandle,
        data: &[u8],
        fin: bool,
    ) -> Result<ChunkHandle, Error> {
        if data.len() > BYTES {
            return Err(Error::ChunkTooLarge);
        }
        if data.is_empty() && !fin {
            return Err(Error::InvalidTransition);
        }
        let slot = self
            .chunks
            .iter()
            .position(|c| c.state.stream.is_none() && c.state.generation < u64::MAX)
            .ok_or(Error::Capacity)?;
        let offset = table.reserve_send(stream, data.len(), fin)?;
        let chunk = &mut self.chunks[slot];
        chunk.bytes[..data.len()].copy_from_slice(data);
        chunk.state = ChunkState {
            generation: chunk.state.generation + 1,
            stream: Some(stream),
            offset,
            length: data.len(),
            fin,
            acked: false,
            pending: true,
        };
        Ok(self.handle(slot))
    }
    /// Reconcile a complete early request after the authenticated TLS decision.
    /// The early journal retains its bytes until this succeeds. Import in stream
    /// order before any ordinary stream opens or 1-RTT ACK is processed. Rejected
    /// early data supplies no accepted references and is queued for fresh send.
    /// Every capacity/credit/ID check precedes any table or queue mutation.
    pub(crate) fn import_early_request<const RX: usize>(
        &mut self,
        table: &mut StreamTable<'_, RX>,
        connection: u64,
        stream_id: u64,
        bytes: &[u8],
        accepted_packets: &[Option<u64>],
        lost_packets: &[bool],
    ) -> Result<(StreamHandle, ChunkHandle), Error> {
        table.check_open()?;
        if table.connection != connection
            || table.role != Role::Client
            || stream_id != table.opened[0] * 4
        {
            return Err(Error::InvalidTransition);
        }
        if bytes.is_empty() || bytes.len() > BYTES {
            return Err(Error::ChunkTooLarge);
        }
        if table.opened[0] >= table.peer.max_streams_bidi {
            return Err(Error::StreamLimit);
        }
        if bytes.len() as u64 > table.peer.stream_data_bidi_remote
            || table
                .send_reserved
                .checked_add(bytes.len() as u64)
                .filter(|n| *n <= table.peer.max_data)
                .is_none()
        {
            return Err(Error::FlowControl);
        }
        let promises =
            table.peer_promised_slots(table.local.max_streams_bidi, table.local.max_streams_uni)?;
        if promises + table.local_live_count() >= table.reusable_slots()
            || !table
                .slots
                .iter()
                .any(|s| !s.state.live && s.state.generation < u64::MAX)
            || !self
                .chunks
                .iter()
                .any(|c| c.state.stream.is_none() && c.state.generation < u64::MAX)
        {
            return Err(Error::Capacity);
        }
        if accepted_packets.len() != lost_packets.len() {
            return Err(Error::InvalidTransition);
        }
        let count = accepted_packets.iter().flatten().count();
        if count
            > self
                .references
                .iter()
                .filter(|r| r.state == ReferenceState::Free && r.generation < u64::MAX)
                .count()
        {
            return Err(Error::Capacity);
        }
        for (i, packet) in accepted_packets.iter().enumerate() {
            if let Some(packet) = packet
                && (*packet > MAX_OFFSET
                    || accepted_packets[..i]
                        .iter()
                        .any(|old| old == &Some(*packet)))
            {
                return Err(Error::InvalidId);
            }
        }
        // The preflight above covers every failure condition of these local
        // operations; there is no intervening callback or external mutation.
        let stream = table.open_local(true)?;
        let chunk = self.enqueue(table, stream, bytes, true)?;
        for packet in accepted_packets.iter().flatten() {
            let reference = self.reserve_transmission(chunk, *packet)?;
            self.commit_transmission(table, reference)?;
        }
        for (packet, lost) in accepted_packets.iter().zip(lost_packets) {
            if let Some(packet) = packet
                && *lost
            {
                self.on_packet_lost(*packet);
            }
        }
        Ok((stream, chunk))
    }

    pub fn next_pending(&self) -> Option<ChunkHandle> {
        self.chunks
            .iter()
            .enumerate()
            .cycle()
            .skip(self.cursor)
            .take(self.chunks.len())
            .find(|(i, c)| {
                c.state.stream.is_some()
                    && c.state.pending
                    && !c.state.acked
                    && !self
                        .references
                        .iter()
                        .any(|r| r.state == ReferenceState::Reserved && r.chunk == *i)
            })
            .map(|(i, _)| i)
            .map(|i| self.handle(i))
    }
    /// An outstanding STREAM range for a fresh-PN PTO probe. A PTO alone does
    /// not declare the old packet lost or release its accounting.
    pub fn probe_chunk(&self) -> Option<ChunkHandle> {
        self.references.iter().find_map(|r| {
            let c = self.chunks[r.chunk].state;
            if matches!(r.state, ReferenceState::Sent | ReferenceState::Lost)
                && c.stream.is_some()
                && !c.acked
            {
                Some(self.handle(r.chunk))
            } else {
                None
            }
        })
    }
    pub fn chunk(&self, h: ChunkHandle) -> Result<ChunkView<'_>, Error> {
        let i = self.validate_chunk(h)?;
        let c = &self.chunks[i];
        if c.state.acked {
            return Err(Error::SendClosed);
        }
        Ok(ChunkView {
            stream: c.state.stream.ok_or(Error::StaleChunk)?,
            offset: c.state.offset,
            fin: c.state.fin,
            data: &c.bytes[..c.state.length],
        })
    }
    /// Reserving a second packet for the same chunk supports probes and
    /// retransmission. Duplicate references for the same chunk/PN are rejected.
    pub fn reserve_transmission(
        &mut self,
        chunk: ChunkHandle,
        packet_number: u64,
    ) -> Result<Transmission, Error> {
        let i = self.validate_chunk(chunk)?;
        if packet_number > MAX_OFFSET {
            return Err(Error::InvalidId);
        }
        if self.chunks[i].state.acked {
            return Err(Error::SendClosed);
        }
        if self.references.iter().any(|r| {
            r.state != ReferenceState::Free
                && r.packet == packet_number
                && r.chunk == i
                && r.chunk_generation == chunk.generation
        }) {
            return Err(Error::InvalidTransition);
        }
        let slot = self
            .references
            .iter()
            .position(|r| r.state == ReferenceState::Free && r.generation < u64::MAX)
            .ok_or(Error::Capacity)?;
        let r = &mut self.references[slot];
        *r = PacketReference {
            generation: r.generation + 1,
            chunk: i,
            chunk_generation: chunk.generation,
            packet: packet_number,
            state: ReferenceState::Reserved,
        };
        Ok(Transmission {
            queue: self.queue,
            slot,
            generation: r.generation,
        })
    }
    /// Call after adapter acceptance, under the same active table's single owner.
    /// Do not close or replace the table between reservation and the adapter
    /// report. Reset rejects outstanding reservations; an ACK for another copy
    /// does not invalidate a packet that was already accepted by the adapter.
    pub fn commit_transmission<const RX: usize>(
        &mut self,
        table: &mut StreamTable<'_, RX>,
        transmission: Transmission,
    ) -> Result<(), Error> {
        let i = self.validate_transmission(transmission)?;
        let r = self.references[i];
        if r.state != ReferenceState::Reserved {
            return Err(Error::InvalidTransition);
        }
        let c = self.chunks[r.chunk].state;
        // An ACK for another copy may arrive while this packet is reserved.
        // Committing its actual publication remains valid; keep the reference
        // until recovery settles it, even though the bytes are already ACKed.
        table.sent(
            c.stream.ok_or(Error::StaleChunk)?,
            c.offset + c.length as u64,
        )?;
        self.references[i].state = ReferenceState::Sent;
        self.chunks[r.chunk].state.pending = false;
        self.cursor = if r.chunk + 1 == self.chunks.len() {
            0
        } else {
            r.chunk + 1
        };
        Ok(())
    }
    pub fn cancel_transmission<const RX: usize>(
        &mut self,
        table: &mut StreamTable<'_, RX>,
        transmission: Transmission,
    ) -> Result<(), Error> {
        let i = self.validate_transmission(transmission)?;
        if self.references[i].state != ReferenceState::Reserved {
            return Err(Error::InvalidTransition);
        }
        table.validate(
            self.chunks[self.references[i].chunk]
                .state
                .stream
                .ok_or(Error::StaleChunk)?,
        )?;
        self.references[i].state = ReferenceState::Free;
        self.collect(table)
    }
    pub fn on_packet_acked<const RX: usize>(
        &mut self,
        table: &mut StreamTable<'_, RX>,
        packet_number: u64,
    ) -> Result<usize, Error> {
        self.on_packets_acked(table, |pn| pn == packet_number)
    }
    /// Match already validated ACK ranges against the bounded reference table.
    /// The predicate must be stable for this call. This never enumerates the
    /// potentially enormous packet-number intervals named by an ACK frame.
    pub fn on_packets_acked<const RX: usize>(
        &mut self,
        table: &mut StreamTable<'_, RX>,
        contains: impl Fn(u64) -> bool,
    ) -> Result<usize, Error> {
        if self
            .references
            .iter()
            .any(|r| contains(r.packet) && r.state == ReferenceState::Reserved)
        {
            return Err(Error::UnsentAcknowledgment);
        }
        // Preflight all stream handles before effects.
        for r in self
            .references
            .iter()
            .filter(|r| contains(r.packet) && r.state != ReferenceState::Free)
        {
            table.validate(self.chunks[r.chunk].state.stream.ok_or(Error::StaleChunk)?)?;
        }
        let mut count = 0;
        for r in self
            .references
            .iter_mut()
            .filter(|r| contains(r.packet) && r.state != ReferenceState::Free)
        {
            let c = &mut self.chunks[r.chunk].state;
            if !c.acked {
                table.chunk_acked(c.stream.ok_or(Error::StaleChunk)?, c.fin)?;
            }
            c.acked = true;
            c.pending = false;
            r.state = ReferenceState::Free;
            count += 1;
        }
        self.collect(table)?;
        Ok(count)
    }
    /// Loss is not acknowledgment: retain bytes and late-ACK metadata.
    pub fn on_packet_lost(&mut self, packet_number: u64) -> usize {
        let mut count = 0;
        for r in self
            .references
            .iter_mut()
            .filter(|r| r.packet == packet_number && r.state == ReferenceState::Sent)
        {
            r.state = ReferenceState::Lost;
            if !self.chunks[r.chunk].state.acked {
                self.chunks[r.chunk].state.pending = true;
            }
            count += 1;
        }
        count
    }
    /// Recovery explicitly stops tracking a lost PN. Future ACKs for this old
    /// packet cannot release bytes, but retransmission ACKs still can.
    pub fn forget_lost_packet<const RX: usize>(
        &mut self,
        table: &mut StreamTable<'_, RX>,
        packet_number: u64,
    ) -> Result<usize, Error> {
        for r in self
            .references
            .iter()
            .filter(|r| r.packet == packet_number && r.state == ReferenceState::Lost)
        {
            table.validate(self.chunks[r.chunk].state.stream.ok_or(Error::StaleChunk)?)?;
        }
        let mut count = 0;
        for r in self
            .references
            .iter_mut()
            .filter(|r| r.packet == packet_number && r.state == ReferenceState::Lost)
        {
            r.state = ReferenceState::Free;
            count += 1;
        }
        self.collect(table)?;
        Ok(count)
    }
    fn collect<const RX: usize>(&mut self, table: &mut StreamTable<'_, RX>) -> Result<(), Error> {
        for i in 0..self.chunks.len() {
            let c = self.chunks[i].state;
            if let Some(stream) = c.stream
                && c.acked
                && !self.references.iter().any(|r| {
                    r.state != ReferenceState::Free
                        && r.chunk == i
                        && r.chunk_generation == c.generation
                })
            {
                table.chunk_released(stream)?;
                self.chunks[i].state.stream = None;
            }
        }
        Ok(())
    }
    /// Once any copy of a range is ACKed, bytes are no longer needed by the
    /// other already-published copies. Revoke those data references explicitly;
    /// this does not ACK/lose/remove packet-level congestion accounting. Pending
    /// adapter reports stay valid because Reserved references are retained.
    pub fn release_acked_references<const RX: usize>(
        &mut self,
        table: &mut StreamTable<'_, RX>,
    ) -> Result<usize, Error> {
        for c in self
            .chunks
            .iter()
            .filter(|c| c.state.stream.is_some() && c.state.acked)
        {
            table.validate(c.state.stream.ok_or(Error::StaleChunk)?)?;
        }
        let mut released = 0;
        for r in self.references.iter_mut() {
            if matches!(r.state, ReferenceState::Sent | ReferenceState::Lost)
                && self.chunks[r.chunk].state.acked
            {
                r.state = ReferenceState::Free;
                released += 1;
            }
        }
        self.collect(table)?;
        Ok(released)
    }
    /// Handles an application reset or authenticated STOP_SENDING. Any already
    /// published range remains charged; never-published tail reservations are
    /// returned. Existing packet references retain their buffers until settled.
    pub fn reset<const RX: usize>(
        &mut self,
        table: &mut StreamTable<'_, RX>,
        stream: StreamHandle,
        error_code: u64,
    ) -> Result<Option<Reset>, Error> {
        // A reserved packet could be published concurrently by the adapter; the
        // single owner must cancel those reservations before initiating reset.
        if self.references.iter().any(|r| {
            r.state == ReferenceState::Reserved && self.chunks[r.chunk].state.stream == Some(stream)
        }) {
            return Err(Error::InvalidTransition);
        }
        let reset = table.begin_reset(stream, error_code)?;
        if reset.is_some() {
            for c in self
                .chunks
                .iter_mut()
                .filter(|c| c.state.stream == Some(stream))
            {
                c.state.acked = true;
                c.state.pending = false;
            }
            self.collect(table)?;
        }
        Ok(reset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn limits(max_bidi: u64, max_uni: u64) -> Limits {
        Limits {
            max_data: 64,
            max_streams_bidi: max_bidi,
            max_streams_uni: max_uni,
            stream_data_bidi_local: 8,
            stream_data_bidi_remote: 8,
            stream_data_uni: 8,
        }
    }
    fn local_limits(max_bidi: u64, max_uni: u64) -> Limits {
        Limits {
            max_data: 8,
            ..limits(max_bidi, max_uni)
        }
    }

    #[test]
    fn implicit_prefix_is_real_and_retirement_holes_are_preserved() {
        let mut slots = [const { StreamSlot::<8>::EMPTY }; 3];
        let mut table = StreamTable::new(
            &mut slots,
            Role::Server,
            1,
            local_limits(0, 3),
            limits(10, 10),
        )
        .unwrap();
        let last = table.get_or_accept(10).unwrap();
        assert_eq!(last.id(), 10);
        assert_eq!(table.live_count(), 3);
        assert_eq!(table.cumulative_opened(2), Ok(3));
        let first = table.lookup(2).unwrap();
        let middle = table.lookup(6).unwrap();
        table.on_reset(middle, 7, 0).unwrap();
        table.acknowledge_received_reset(middle).unwrap();
        table.retire(middle).unwrap();
        assert_eq!(table.lookup(6), Err(Error::Retired));
        assert_eq!(table.lookup(2), Ok(first));
        assert_eq!(table.lookup(10), Ok(last));
        table.grant_max_streams(false, 4).unwrap();
        let next = table.get_or_accept(14).unwrap();
        assert_eq!(next.slot(), middle.slot());
        assert_ne!(next.generation, middle.generation);
        assert_eq!(table.get_or_accept(6), Err(Error::Retired));
        assert!(matches!(table.receive(middle), Err(Error::StaleHandle)));
        assert_eq!(table.lookup(2), Ok(first));
    }

    #[test]
    fn one_live_slot_handles_1999_cumulative_streams() {
        let mut slots = [StreamSlot::<8>::EMPTY];
        let mut table = StreamTable::new(
            &mut slots,
            Role::Server,
            1,
            local_limits(0, 1),
            limits(0, 0),
        )
        .unwrap();
        for index in 0..1999u64 {
            let h = table.get_or_accept(index * 4 + 2).unwrap();
            table.on_stream(h, 0, b"x", true).unwrap();
            assert_eq!(table.receive(h).unwrap().first, b"x");
            table.consume(h, 1).unwrap();
            table.retire(h).unwrap();
            assert_eq!(table.live_count(), 0);
            assert_eq!(table.get_or_accept(h.id()), Err(Error::Retired));
            table.grant_max_data(table.receive_data_capacity()).unwrap();
            table.grant_max_streams(false, index + 2).unwrap();
        }
        assert_eq!(table.cumulative_opened(2), Ok(1999));
        assert_eq!(table.receive_charged(), 1999);
    }

    #[test]
    fn stream_id_permissions_and_class_limits() {
        let mut slots = [const { StreamSlot::<8>::EMPTY }; 3];
        let mut table = StreamTable::new(
            &mut slots,
            Role::Client,
            1,
            local_limits(1, 1),
            limits(1, 1),
        )
        .unwrap();
        assert_eq!(table.get_or_accept(0), Err(Error::StreamState));
        assert_eq!(table.get_or_accept(5), Err(Error::StreamLimit));
        let local_uni = table.open_local(false).unwrap();
        assert_eq!(local_uni.id(), 2);
        assert_eq!(table.open_local(true), Err(Error::Capacity)); // Preserve promised peer slots.
        let remote_bidi = table.get_or_accept(1).unwrap();
        let remote_uni = table.get_or_accept(3).unwrap();
        assert_eq!(
            table.on_stream(local_uni, 0, b"", true),
            Err(Error::StreamState)
        );
        assert_eq!(table.on_reset(local_uni, 0, 0), Err(Error::StreamState));
        assert_eq!(
            table.on_max_stream_data(remote_uni, 8),
            Err(Error::StreamState)
        );
        assert_eq!(table.request_stop(local_uni, 0), Err(Error::StreamState));
        assert_eq!(
            table.request_stop(remote_bidi, 5),
            Ok(StopSending {
                id: 1,
                error_code: 5
            })
        );
        assert_eq!(table.open_local(false), Err(Error::StreamLimit));
        assert_eq!(table.get_or_accept(MAX_OFFSET + 1), Err(Error::InvalidId));
    }

    #[test]
    fn receive_reorders_duplicates_consumes_and_wraps() {
        let mut slots = [StreamSlot::<8>::EMPTY];
        let mut table = StreamTable::new(
            &mut slots,
            Role::Server,
            1,
            local_limits(0, 1),
            limits(0, 0),
        )
        .unwrap();
        let h = table.get_or_accept(2).unwrap();
        table.on_stream(h, 4, b"efgh", false).unwrap();
        assert!(table.receive(h).unwrap().first.is_empty());
        table.on_stream(h, 0, b"abcd", false).unwrap();
        table.on_stream(h, 2, b"cdef", false).unwrap();
        assert_eq!(table.receive_charged(), 8);
        assert_eq!(table.receive(h).unwrap().first, b"abcdefgh");
        table.consume(h, 6).unwrap();
        table.grant_max_stream_data(h, 14).unwrap();
        table.grant_max_data(14).unwrap();
        table.on_stream(h, 8, b"ijklmn", true).unwrap();
        let view = table.receive(h).unwrap();
        assert_eq!(view.first, b"gh");
        assert_eq!(view.second, b"ijklmn");
        assert!(view.fin);
        table.consume(h, 8).unwrap();
        assert!(table.receive(h).unwrap().fin);
        table.retire(h).unwrap();
    }

    #[test]
    fn receive_errors_and_overlaps_are_transactional() {
        let mut slots = [StreamSlot::<8>::EMPTY];
        let mut table = StreamTable::new(
            &mut slots,
            Role::Server,
            1,
            local_limits(0, 1),
            limits(0, 0),
        )
        .unwrap();
        let h = table.get_or_accept(2).unwrap();
        table.on_stream(h, 3, b"d", false).unwrap();
        assert_eq!(
            table.on_stream(h, 0, b"abcX", true),
            Err(Error::ConflictingOverlap)
        );
        assert_eq!(table.receive_charged(), 4);
        assert_eq!(table.slots[h.slot].state.receive_final, None);
        assert_eq!(table.on_stream(h, 8, b"x", false), Err(Error::FlowControl));
        assert_eq!(table.receive_charged(), 4);
        assert_eq!(
            table.on_stream(h, MAX_OFFSET, &[1], false),
            Err(Error::OffsetOverflow)
        );
        assert_eq!(table.consume(h, 1), Err(Error::ConsumeBeyondReady));
        table.on_stream(h, 0, b"abc", false).unwrap();
        assert_eq!(table.receive(h).unwrap().first, b"abcd");
        table.consume(h, 4).unwrap();
        table.on_stream(h, 0, b"xxxx", false).unwrap(); // Consumed retransmission ignored.
        assert!(table.receive(h).unwrap().first.is_empty());
        assert_eq!(table.receive_charged(), 4);
    }

    #[test]
    fn fin_reset_final_size_and_connection_credit() {
        let mut slots = [const { StreamSlot::<8>::EMPTY }; 2];
        let mut table = StreamTable::new(
            &mut slots,
            Role::Server,
            1,
            local_limits(0, 2),
            limits(0, 0),
        )
        .unwrap();
        let a = table.get_or_accept(2).unwrap();
        let b = table.get_or_accept(6).unwrap();
        table.on_stream(a, 0, b"abcd", true).unwrap();
        table.on_stream(b, 0, b"ab", false).unwrap();
        assert_eq!(table.on_reset(b, 9, 5), Err(Error::FlowControl));
        assert_eq!(table.receive_charged(), 6);
        assert_eq!(table.receive(b).unwrap().reset, None);
        assert_eq!(table.on_stream(a, 4, b"x", false), Err(Error::FinalSize));
        assert_eq!(table.on_reset(a, 9, 3), Err(Error::FinalSize));
        assert_eq!(table.on_reset(a, 9, 5), Err(Error::FinalSize));
        table.on_reset(b, 9, 4).unwrap();
        assert_eq!(table.receive_charged(), 8);
        assert_eq!(table.receive(b).unwrap().reset, Some(9));
        assert!(table.receive(b).unwrap().first.is_empty());
        assert_eq!(table.retire(b), Err(Error::NotTerminal));
        assert_eq!(table.acknowledge_received_reset(b), Ok(9));
        table.on_reset(b, 99, 4).unwrap();
        assert_eq!(table.receive_charged(), 8);
        table.on_stream(b, 0, b"abcd", false).unwrap(); // Discarded after reset.
        table.retire(b).unwrap();
        table.consume(a, 4).unwrap();
        table.retire(a).unwrap();
        assert_eq!(table.receive_data_capacity(), 24);
    }

    #[test]
    fn zero_length_fin_is_terminal_and_cannot_change() {
        let mut slots = [StreamSlot::<8>::EMPTY];
        let mut table = StreamTable::new(
            &mut slots,
            Role::Server,
            1,
            local_limits(0, 1),
            limits(0, 0),
        )
        .unwrap();
        let h = table.get_or_accept(2).unwrap();
        table.on_stream(h, 0, b"", true).unwrap();
        assert!(table.receive(h).unwrap().fin);
        assert_eq!(table.on_stream(h, 0, b"x", false), Err(Error::FinalSize));
        assert_eq!(table.request_stop(h, 1), Err(Error::InvalidTransition));
        table.retire(h).unwrap();
    }

    #[test]
    fn receive_grants_never_outstrip_reserved_real_capacity() {
        let mut slots = [const { StreamSlot::<8>::EMPTY }; 2];
        let mut table = StreamTable::new(
            &mut slots,
            Role::Server,
            1,
            local_limits(0, 2),
            limits(1, 1),
        )
        .unwrap();
        let h = table.get_or_accept(2).unwrap();
        assert_eq!(table.grant_max_stream_data(h, 9), Err(Error::InvalidCredit));
        assert_eq!(table.grant_max_stream_data(h, 7), Err(Error::InvalidCredit));
        assert_eq!(table.grant_max_data(17), Err(Error::InvalidCredit));
        assert_eq!(table.grant_max_data(7), Err(Error::InvalidCredit));
        assert_eq!(table.grant_max_streams(false, 3), Err(Error::Capacity));
        assert_eq!(table.grant_max_streams(false, 1), Err(Error::InvalidCredit));
        table.on_stream(h, 0, b"abcd", false).unwrap();
        table.consume(h, 3).unwrap();
        table.grant_max_stream_data(h, 11).unwrap();
        table.grant_max_data(19).unwrap();
        assert_eq!(table.grant_max_data(20), Err(Error::InvalidCredit));
    }

    #[test]
    fn received_credit_is_monotonic_and_directional() {
        let mut slots = [StreamSlot::<8>::EMPTY];
        let mut peer = limits(1, 1);
        peer.max_data = 0;
        peer.stream_data_bidi_remote = 2;
        let mut table =
            StreamTable::new(&mut slots, Role::Client, 1, local_limits(0, 0), peer).unwrap();
        let h = table.open_local(true).unwrap();
        assert_eq!(table.slots[h.slot].state.send_limit, 2);
        table.on_max_data(100).unwrap();
        table.on_max_data(50).unwrap();
        table.on_max_streams(true, 7).unwrap();
        table.on_max_streams(true, 2).unwrap();
        table.on_max_stream_data(h, 99).unwrap();
        table.on_max_stream_data(h, 1).unwrap();
        assert_eq!(table.peer_limits().max_data, 100);
        assert_eq!(table.peer_limits().max_streams_bidi, 7);
        assert_eq!(table.slots[h.slot].state.send_limit, 99);
        assert_eq!(
            table.on_max_streams(true, MAX_STREAMS + 1),
            Err(Error::InvalidCredit)
        );
        assert_eq!(table.on_max_data(MAX_OFFSET + 1), Err(Error::InvalidCredit));
    }

    #[test]
    fn send_chunk_loss_retransmission_late_ack_preserves_ownership() {
        let mut slots = [StreamSlot::<8>::EMPTY];
        let mut table = StreamTable::new(
            &mut slots,
            Role::Client,
            7,
            local_limits(0, 0),
            limits(0, 3),
        )
        .unwrap();
        let stream = table.open_local(false).unwrap();
        let mut chunks = [SendChunk::<8>::EMPTY];
        let mut refs = [PacketReference::EMPTY; 2];
        let mut queue = SendQueue::new(1, &mut chunks, &mut refs).unwrap();
        let chunk = queue.enqueue(&mut table, stream, b"hello", true).unwrap();
        assert_eq!(queue.chunk(chunk).unwrap().data, b"hello");
        assert_eq!(queue.chunk(chunk).unwrap().offset, 0);
        let first = queue.reserve_transmission(chunk, 10).unwrap();
        assert_eq!(
            queue.on_packet_acked(&mut table, 10),
            Err(Error::UnsentAcknowledgment)
        );
        queue.commit_transmission(&mut table, first).unwrap();
        assert_eq!(queue.on_packet_lost(10), 1);
        assert_eq!(queue.on_packet_lost(10), 0);
        assert_eq!(queue.next_pending(), Some(chunk));
        let second = queue.reserve_transmission(chunk, 11).unwrap();
        queue.commit_transmission(&mut table, second).unwrap();
        assert_eq!(queue.on_packet_acked(&mut table, 10), Ok(1)); // Late ACK after loss.
        assert_eq!(queue.queued_chunks(), 1); // Other packet still owns a reference.
        assert_eq!(table.retire(stream), Err(Error::NotTerminal));
        assert_eq!(queue.on_packet_acked(&mut table, 11), Ok(1));
        assert_eq!(queue.queued_chunks(), 0);
        assert_eq!(queue.on_packet_acked(&mut table, 11), Ok(0));
        assert!(matches!(queue.chunk(chunk), Err(Error::StaleChunk)));
        table.retire(stream).unwrap();
        assert_eq!(table.lookup(stream.id()), Err(Error::Retired));
        let next = table.open_local(false).unwrap();
        let reused = queue.enqueue(&mut table, next, b"next", true).unwrap();
        assert_ne!(reused.generation, chunk.generation);
        assert_eq!(
            queue.reserve_transmission(chunk, 12),
            Err(Error::StaleChunk)
        );
        assert_eq!(table.send_reserved(), 9); // ACK is not a flow-credit refund.
    }

    #[test]
    fn send_backpressure_and_cancel_are_transactional() {
        let mut slots = [StreamSlot::<8>::EMPTY];
        let mut table = StreamTable::new(
            &mut slots,
            Role::Client,
            1,
            local_limits(0, 0),
            limits(0, 1),
        )
        .unwrap();
        let stream = table.open_local(false).unwrap();
        let mut chunks = [SendChunk::<4>::EMPTY];
        let mut refs = [PacketReference::EMPTY];
        let mut queue = SendQueue::new(1, &mut chunks, &mut refs).unwrap();
        assert_eq!(
            queue.enqueue(&mut table, stream, b"abcde", false),
            Err(Error::ChunkTooLarge)
        );
        assert_eq!(table.send_reserved(), 0);
        let chunk = queue.enqueue(&mut table, stream, b"abcd", false).unwrap();
        assert_eq!(
            queue.enqueue(&mut table, stream, b"e", false),
            Err(Error::Capacity)
        );
        assert_eq!(table.send_reserved(), 4);
        let reservation = queue.reserve_transmission(chunk, 0).unwrap();
        assert_eq!(queue.reserve_transmission(chunk, 1), Err(Error::Capacity));
        queue.cancel_transmission(&mut table, reservation).unwrap();
        assert_eq!(queue.next_pending(), Some(chunk));
        assert_eq!(
            queue.commit_transmission(&mut table, reservation),
            Err(Error::StaleTransmission)
        );
        let sent = queue.reserve_transmission(chunk, 1).unwrap();
        queue.commit_transmission(&mut table, sent).unwrap();
        assert_eq!(
            queue.cancel_transmission(&mut table, sent),
            Err(Error::InvalidTransition)
        );
        queue.on_packet_acked(&mut table, 1).unwrap();
        let next = queue.enqueue(&mut table, stream, b"efgh", false).unwrap();
        assert_eq!(queue.chunk(next).unwrap().offset, 4);
    }

    #[test]
    fn flow_credit_checks_precede_application_acceptance() {
        let mut slots = [StreamSlot::<8>::EMPTY];
        let mut peer = limits(0, 1);
        peer.max_data = 3;
        let mut table =
            StreamTable::new(&mut slots, Role::Client, 1, local_limits(0, 0), peer).unwrap();
        let h = table.open_local(false).unwrap();
        let mut chunks = [const { SendChunk::<8>::EMPTY }; 2];
        let mut refs = [PacketReference::EMPTY];
        let mut q = SendQueue::new(1, &mut chunks, &mut refs).unwrap();
        assert_eq!(
            q.enqueue(&mut table, h, b"abcd", false),
            Err(Error::FlowControl)
        );
        assert_eq!(q.queued_chunks(), 0);
        assert_eq!(table.send_reserved(), 0);
        table.on_max_data(100).unwrap();
        q.enqueue(&mut table, h, b"abcdefgh", false).unwrap();
        assert_eq!(
            q.enqueue(&mut table, h, b"i", false),
            Err(Error::FlowControl)
        );
        table.on_max_stream_data(h, 9).unwrap();
        q.enqueue(&mut table, h, b"i", true).unwrap();
        assert_eq!(table.send_reserved(), 9);
    }

    #[test]
    fn stop_reset_uses_published_final_size_and_releases_only_unsent_tail() {
        let mut slots = [StreamSlot::<8>::EMPTY];
        let mut table = StreamTable::new(
            &mut slots,
            Role::Client,
            1,
            local_limits(0, 0),
            limits(0, 1),
        )
        .unwrap();
        let stream = table.open_local(false).unwrap();
        let mut chunks = [const { SendChunk::<4>::EMPTY }; 2];
        let mut refs = [PacketReference::EMPTY; 2];
        let mut q = SendQueue::new(1, &mut chunks, &mut refs).unwrap();
        let first = q.enqueue(&mut table, stream, b"abcd", false).unwrap();
        let second = q.enqueue(&mut table, stream, b"efgh", true).unwrap();
        let reserved = q.reserve_transmission(first, 1).unwrap();
        assert_eq!(
            q.reset(&mut table, stream, 42),
            Err(Error::InvalidTransition)
        );
        q.commit_transmission(&mut table, reserved).unwrap();
        assert_eq!(
            q.reset(&mut table, stream, 42),
            Ok(Some(Reset {
                id: stream.id(),
                error_code: 42,
                final_size: 4
            }))
        );
        assert_eq!(table.send_reserved(), 4);
        assert!(matches!(q.chunk(second), Err(Error::StaleChunk)));
        assert_eq!(q.queued_chunks(), 1);
        assert_eq!(
            q.enqueue(&mut table, stream, b"x", false),
            Err(Error::SendClosed)
        );
        assert_eq!(
            table.reset_acknowledged(stream),
            Err(Error::UnsentAcknowledgment)
        );
        table.reset_transmitted(stream).unwrap();
        table.reset_acknowledged(stream).unwrap();
        assert_eq!(table.retire(stream), Err(Error::NotTerminal));
        q.on_packet_lost(1);
        q.forget_lost_packet(&mut table, 1).unwrap();
        table.retire(stream).unwrap();
    }

    #[test]
    fn ack_while_another_copy_is_reserved_can_still_commit_actual_publication() {
        let mut slots = [StreamSlot::<8>::EMPTY];
        let mut table = StreamTable::new(
            &mut slots,
            Role::Client,
            1,
            local_limits(0, 0),
            limits(0, 1),
        )
        .unwrap();
        let stream = table.open_local(false).unwrap();
        let mut chunks = [SendChunk::<4>::EMPTY];
        let mut refs = [PacketReference::EMPTY; 2];
        let mut q = SendQueue::new(1, &mut chunks, &mut refs).unwrap();
        let chunk = q.enqueue(&mut table, stream, b"abcd", true).unwrap();
        let first = q.reserve_transmission(chunk, 1).unwrap();
        q.commit_transmission(&mut table, first).unwrap();
        let second = q.reserve_transmission(chunk, 2).unwrap();
        q.on_packet_acked(&mut table, 1).unwrap();
        assert_eq!(q.queued_chunks(), 1);
        q.commit_transmission(&mut table, second).unwrap();
        q.on_packet_acked(&mut table, 2).unwrap();
        table.retire(stream).unwrap();
    }

    #[test]
    fn fin_ack_does_not_imply_earlier_chunks_were_acked() {
        let mut slots = [StreamSlot::<8>::EMPTY];
        let mut table = StreamTable::new(
            &mut slots,
            Role::Client,
            1,
            local_limits(0, 0),
            limits(0, 1),
        )
        .unwrap();
        let stream = table.open_local(false).unwrap();
        let mut chunks = [const { SendChunk::<4>::EMPTY }; 2];
        let mut refs = [PacketReference::EMPTY; 2];
        let mut q = SendQueue::new(1, &mut chunks, &mut refs).unwrap();
        let a = q.enqueue(&mut table, stream, b"abcd", false).unwrap();
        let b = q.enqueue(&mut table, stream, b"", true).unwrap();
        let ra = q.reserve_transmission(a, 1).unwrap();
        q.commit_transmission(&mut table, ra).unwrap();
        let rb = q.reserve_transmission(b, 2).unwrap();
        q.commit_transmission(&mut table, rb).unwrap();
        q.on_packet_acked(&mut table, 2).unwrap();
        assert_eq!(table.retire(stream), Err(Error::NotTerminal));
        assert!(q.reset(&mut table, stream, 42).unwrap().is_some());
    }

    #[test]
    fn invalid_configuration_and_connection_closure() {
        let mut slots = [StreamSlot::<8>::EMPTY];
        assert!(matches!(
            StreamTable::new(
                &mut slots,
                Role::Server,
                1,
                local_limits(1, 1),
                limits(0, 0)
            ),
            Err(Error::InvalidConfiguration)
        ));
        let mut table = StreamTable::new(
            &mut slots,
            Role::Server,
            1,
            local_limits(0, 1),
            limits(0, 0),
        )
        .unwrap();
        let h = table.get_or_accept(2).unwrap();
        table.close();
        assert_eq!(table.on_stream(h, 0, b"x", false), Err(Error::Closed));
        assert_eq!(table.lookup(2), Err(Error::Closed));
        assert_eq!(table.on_max_data(10), Err(Error::Closed));
    }
    #[test]
    fn five_mebibyte_stream_uses_sixty_four_byte_windows() {
        const TOTAL: u64 = 5 * 1024 * 1024;
        let offered = Limits {
            max_data: 64,
            max_streams_uni: 1,
            stream_data_uni: 64,
            ..Limits::ZERO
        };
        let mut client_slots = [StreamSlot::<64>::EMPTY];
        let mut server_slots = [StreamSlot::<64>::EMPTY];
        let mut client =
            StreamTable::new(&mut client_slots, Role::Client, 1, Limits::ZERO, offered).unwrap();
        let mut server =
            StreamTable::new(&mut server_slots, Role::Server, 1, offered, Limits::ZERO).unwrap();
        let tx = client.open_local(false).unwrap();
        let rx = server.get_or_accept(tx.id()).unwrap();
        let mut chunks = [SendChunk::<64>::EMPTY];
        let mut refs = [PacketReference::EMPTY];
        let mut queue = SendQueue::new(1, &mut chunks, &mut refs).unwrap();
        let mut offset = 0;
        let mut pn = 0;
        while offset < TOTAL {
            let data = [pn as u8; 64];
            let fin = offset + 64 == TOTAL;
            let chunk = queue.enqueue(&mut client, tx, &data, fin).unwrap();
            let reservation = queue.reserve_transmission(chunk, pn).unwrap();
            queue.commit_transmission(&mut client, reservation).unwrap();
            let view = queue.chunk(chunk).unwrap();
            assert_eq!(view.offset, offset);
            server
                .on_stream(rx, view.offset, view.data, view.fin)
                .unwrap();
            let received = server.receive(rx).unwrap();
            assert_eq!(received.first, &data);
            assert!(received.second.is_empty());
            assert_eq!(received.fin, fin);
            server.consume(rx, 64).unwrap();
            queue.on_packet_acked(&mut client, pn).unwrap();
            offset += 64;
            pn += 1;
            if !fin {
                let credit = server.stream_receive_capacity(rx).unwrap();
                server.grant_max_stream_data(rx, credit).unwrap();
                server
                    .grant_max_data(server.receive_data_capacity())
                    .unwrap();
                client.on_max_stream_data(tx, credit).unwrap();
                client.on_max_data(server.local_limits().max_data).unwrap();
            }
        }
        assert_eq!(server.receive_charged(), TOTAL);
        assert_eq!(client.send_reserved(), TOTAL);
        assert_eq!(queue.queued_chunks(), 0);
        client.retire(tx).unwrap();
        server.retire(rx).unwrap();
    }

    #[test]
    fn future_stream_credit_cannot_reuse_exhausted_generations() {
        let mut slots = [StreamSlot::<8>::EMPTY];
        let mut table = StreamTable::new(
            &mut slots,
            Role::Server,
            1,
            local_limits(0, 1),
            limits(0, 0),
        )
        .unwrap();
        let h = table.get_or_accept(2).unwrap();
        table.on_stream(h, 0, b"", true).unwrap();
        table.retire(h).unwrap();
        table.slots[h.slot].state.generation = u64::MAX;
        assert_eq!(table.grant_max_streams(false, 2), Err(Error::Capacity));
    }

    #[test]
    fn bidirectional_terminal_halves_are_independent() {
        let mut slots = [StreamSlot::<8>::EMPTY];
        let mut table = StreamTable::new(
            &mut slots,
            Role::Client,
            1,
            local_limits(0, 0),
            limits(1, 0),
        )
        .unwrap();
        let h = table.open_local(true).unwrap();
        table.on_reset(h, 8, 0).unwrap();
        table.acknowledge_received_reset(h).unwrap();
        assert_eq!(table.retire(h), Err(Error::NotTerminal));
        let mut chunks = [SendChunk::<8>::EMPTY];
        let mut refs = [PacketReference::EMPTY];
        let mut q = SendQueue::new(1, &mut chunks, &mut refs).unwrap();
        let chunk = q.enqueue(&mut table, h, b"outgoing", true).unwrap();
        let tx = q.reserve_transmission(chunk, 0).unwrap();
        q.commit_transmission(&mut table, tx).unwrap();
        q.on_packet_acked(&mut table, 0).unwrap();
        table.retire(h).unwrap();
    }
    #[test]
    fn stop_after_all_bytes_acked_is_ignored_even_with_old_packet_references() {
        let mut slots = [StreamSlot::<8>::EMPTY];
        let mut table = StreamTable::new(
            &mut slots,
            Role::Client,
            1,
            local_limits(0, 0),
            limits(0, 1),
        )
        .unwrap();
        let stream = table.open_local(false).unwrap();
        let mut chunks = [SendChunk::<8>::EMPTY];
        let mut refs = [PacketReference::EMPTY; 2];
        let mut queue = SendQueue::new(1, &mut chunks, &mut refs).unwrap();
        let chunk = queue.enqueue(&mut table, stream, b"hello", true).unwrap();
        let first = queue.reserve_transmission(chunk, 1).unwrap();
        assert_eq!(queue.next_pending(), None);
        queue.commit_transmission(&mut table, first).unwrap();
        let second = queue.reserve_transmission(chunk, 2).unwrap();
        queue.commit_transmission(&mut table, second).unwrap();
        queue.on_packet_acked(&mut table, 1).unwrap();
        assert_eq!(queue.reset(&mut table, stream, 42), Ok(None));
        assert_eq!(table.retire(stream), Err(Error::NotTerminal));
        queue.on_packet_lost(2);
        queue.forget_lost_packet(&mut table, 2).unwrap();
        table.retire(stream).unwrap();
    }
    #[test]
    fn authenticated_initial_limits_preserve_larger_already_received_credit() {
        let mut slots = [const { StreamSlot::<8>::EMPTY }; 2];
        let mut table = StreamTable::new(
            &mut slots,
            Role::Server,
            1,
            local_limits(1, 0),
            Limits::ZERO,
        )
        .unwrap();
        let peer = table.get_or_accept(0).unwrap();
        assert_eq!(table.send_credit(peer).unwrap().stream_available, 0);
        table.on_max_stream_data(peer, 99).unwrap();
        table.on_max_data(100).unwrap();
        table.apply_peer_initial_limits(limits(1, 1)).unwrap();
        assert_eq!(table.send_credit(peer).unwrap().stream_available, 99);
        assert_eq!(table.send_credit(peer).unwrap().connection_available, 100);
        let local = table.open_local(true).unwrap();
        assert_eq!(local.id(), 1);
        assert_eq!(table.send_credit(local).unwrap().stream_available, 8);
    }

    #[test]
    fn acknowledged_reference_release_keeps_pending_adapter_report_valid() {
        let mut slots = [StreamSlot::<8>::EMPTY];
        let mut table = StreamTable::new(
            &mut slots,
            Role::Client,
            1,
            local_limits(0, 0),
            limits(0, 1),
        )
        .unwrap();
        let stream = table.open_local(false).unwrap();
        let mut chunks = [SendChunk::<8>::EMPTY];
        let mut refs = [PacketReference::EMPTY; 3];
        let mut q = SendQueue::new(1, &mut chunks, &mut refs).unwrap();
        let h = q.enqueue(&mut table, stream, b"abc", true).unwrap();
        let one = q.reserve_transmission(h, 1).unwrap();
        q.commit_transmission(&mut table, one).unwrap();
        let two = q.reserve_transmission(h, 2).unwrap();
        q.commit_transmission(&mut table, two).unwrap();
        let three = q.reserve_transmission(h, 3).unwrap();
        q.on_packet_acked(&mut table, 1).unwrap();
        assert_eq!(q.release_acked_references(&mut table), Ok(1));
        assert_eq!(q.queued_chunks(), 1);
        q.commit_transmission(&mut table, three).unwrap();
        assert_eq!(q.release_acked_references(&mut table), Ok(1));
        assert_eq!(q.queued_chunks(), 0);
        assert_eq!(q.on_packet_acked(&mut table, 2), Ok(0));
        table.retire(stream).unwrap();
    }

    #[test]
    fn round_robin_prevents_reused_low_slot_starving_lost_data() {
        let mut slots = [StreamSlot::<8>::EMPTY];
        let mut table = StreamTable::new(
            &mut slots,
            Role::Client,
            1,
            local_limits(0, 0),
            limits(0, 1),
        )
        .unwrap();
        let stream = table.open_local(false).unwrap();
        let mut chunks = [const { SendChunk::<8>::EMPTY }; 3];
        let mut refs = [PacketReference::EMPTY; 4];
        let mut q = SendQueue::new(1, &mut chunks, &mut refs).unwrap();
        let a = q.enqueue(&mut table, stream, b"a", false).unwrap();
        let lost = q.enqueue(&mut table, stream, b"b", false).unwrap();
        let c = q.enqueue(&mut table, stream, b"c", false).unwrap();
        for (pn, h) in [a, lost, c].into_iter().enumerate() {
            let r = q.reserve_transmission(h, pn as u64).unwrap();
            q.commit_transmission(&mut table, r).unwrap();
        }
        q.on_packet_acked(&mut table, 0).unwrap();
        q.on_packet_acked(&mut table, 2).unwrap();
        q.on_packet_lost(1);
        let x = q.enqueue(&mut table, stream, b"x", false).unwrap();
        assert_eq!(q.next_pending(), Some(x));
        let r = q.reserve_transmission(x, 3).unwrap();
        q.commit_transmission(&mut table, r).unwrap();
        q.on_packet_acked(&mut table, 3).unwrap();
        q.enqueue(&mut table, stream, b"y", false).unwrap();
        assert_eq!(q.next_pending(), Some(lost));
    }
}
