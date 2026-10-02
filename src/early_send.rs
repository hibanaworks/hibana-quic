//! Caller-owned complete-request intent journal for a restricted 0-RTT client.
//!
//! Early handles are not ordinary stream handles. Before Finished the journal
//! owns bytes, speculative stream IDs, and accepted packet references. Rejection
//! invalidates that epoch but retains request intent for replay under fresh
//! authenticated limits. Acceptance imports IDs/offsets/FIN and references into
//! the ordinary stream owner BEFORE any 1-RTT ACK or stream allocation. This
//! kernel performs no TLS, packet protection, PN allocation, ACK or congestion
//! mutation; actual engine integration must supply those checked facts.
use crate::{early_data::RememberedLimits, packet::MAX_VARINT};
use zeroize::Zeroize;
pub const REFERENCES_PER_REQUEST: usize = 8;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Capacity,
    Limits,
    State,
    Stale,
    Busy,
    PacketNumber,
    Exhausted,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    Accepted,
    Rejected,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Handle {
    connection: u64,
    epoch: u64,
    slot: usize,
    serial: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendTicket {
    handle: Handle,
    serial: u64,
    packet: u64,
    reference: usize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImportTicket {
    handle: Handle,
    decision: Decision,
    stream_id: u64,
    offset: usize,
}
impl ImportTicket {
    pub fn generation(self) -> u64 {
        self.handle.connection
    }
    pub fn stream_id(self) -> u64 {
        self.stream_id
    }
}

/// Narrow post-Finished authority handed to the transport handler. It exposes
/// only checked intent import, never the internal endpoints or arbitrary driver
/// operations. Completion means the attempted operation finished, not that a
/// capacity/flow-control rejection transferred bytes.
pub struct ImportAuthority<'a, 'r> {
    driver: &'a mut crate::driver::Driver<'r>,
}
impl<'a, 'r> ImportAuthority<'a, 'r> {
    pub(crate) fn new(driver: &'a mut crate::driver::Driver<'r>) -> Self {
        Self { driver }
    }
    pub fn import_next<const B: usize, const RX: usize, const TX: usize>(
        &mut self,
        journal: &mut Journal<'_, B>,
        table: &mut crate::streams::StreamTable<'_, RX>,
        queue: &mut crate::streams::SendQueue<'_, TX>,
    ) -> Result<Option<crate::streams::StreamHandle>, crate::streams::Error> {
        let Some(view) = journal
            .next_import()
            .map_err(|_| crate::streams::Error::InvalidTransition)?
        else {
            return Ok(None);
        };
        let grant = self
            .driver
            .begin_early_intent_import(view.ticket)
            .map_err(|_| crate::streams::Error::InvalidTransition)?;
        let stream_id = view.ticket.stream_id();
        let result = journal.import_next(table, queue);
        let request_complete = result.is_ok() && !journal.has_pending_stream(stream_id);
        self.driver
            .finish_early_intent_import(grant, request_complete)
            .map_err(|_| crate::streams::Error::InvalidTransition)?;
        result
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Offering,
    Importing(Decision),
    Complete,
    Retired,
}
pub struct RequestSlot<const BYTES: usize> {
    live: bool,
    serial: u64,
    stream: u64,
    len: usize,
    bytes: [u8; BYTES],
    packets: [Option<u64>; REFERENCES_PER_REQUEST],
    lost: [bool; REFERENCES_PER_REQUEST],
    replay_offset: usize,
    replay_stream: Option<crate::streams::StreamHandle>,
}
impl<const BYTES: usize> RequestSlot<BYTES> {
    pub const EMPTY: Self = Self {
        live: false,
        serial: 0,
        stream: 0,
        len: 0,
        bytes: [0; BYTES],
        packets: [None; REFERENCES_PER_REQUEST],
        lost: [false; REFERENCES_PER_REQUEST],
        replay_offset: 0,
        replay_stream: None,
    };
    fn clear(&mut self) {
        self.bytes.zeroize();
        self.live = false;
        self.len = 0;
        self.packets.fill(None);
        self.lost.fill(false);
        self.replay_offset = 0;
        self.replay_stream = None;
    }
}
pub struct RequestView<'a> {
    pub stream_id: u64,
    pub bytes: &'a [u8],
}
pub struct ImportView<'a> {
    pub ticket: ImportTicket,
    pub decision: Decision,
    pub stream_id: u64,
    pub bytes: &'a [u8],
    pub accepted_packets: &'a [Option<u64>; REFERENCES_PER_REQUEST],
    pub lost_packets: &'a [bool; REFERENCES_PER_REQUEST],
}
pub struct Journal<'a, const BYTES: usize> {
    slots: &'a mut [RequestSlot<BYTES>],
    connection: u64,
    epoch: u64,
    next_serial: Option<u64>,
    next_stream: u64,
    charged: u64,
    limits: RememberedLimits,
    phase: Phase,
    pending: Option<SendTicket>,
    last_packet: Option<u64>,
}
impl<'a, const BYTES: usize> Journal<'a, BYTES> {
    /// Connection identity must not be reused while any prior journal or
    /// ordinary stream handle/callback for that connection can still exist.
    pub fn new(
        connection: u64,
        limits: RememberedLimits,
        slots: &'a mut [RequestSlot<BYTES>],
    ) -> Result<Self, Error> {
        if BYTES == 0 || slots.is_empty() {
            return Err(Error::Capacity);
        }
        for s in slots.iter_mut() {
            s.clear();
        }
        Ok(Self {
            slots,
            connection,
            epoch: 1,
            next_serial: Some(1),
            next_stream: 0,
            charged: 0,
            limits,
            phase: Phase::Offering,
            pending: None,
            last_packet: None,
        })
    }
    pub fn is_offering(&self)->bool{self.phase==Phase::Offering}
    pub fn decision(&self) -> Option<Decision> {
        match self.phase {
            Phase::Importing(d) => Some(d),
            _ => None,
        }
    }
    pub fn has_pending_stream(&self, id: u64) -> bool {
        self.slots.iter().any(|s| s.live && s.stream == id)
    }
    pub fn has_intent(&self) -> bool {
        self.slots.iter().any(|s| s.live)
    }
    pub fn next_transmit(&self, probe: bool) -> Option<Handle> {
        if self.phase != Phase::Offering || self.pending.is_some() {
            return None;
        }
        self.slots
            .iter()
            .enumerate()
            .find(|(_, s)| {
                s.live
                    && (probe
                        || !s
                            .packets
                            .iter()
                            .enumerate()
                            .any(|(i, p)| p.is_some() && !s.lost[i]))
            })
            .map(|(i, _)| self.handle(i))
    }
    fn serial(&mut self) -> Result<u64, Error> {
        let id = self.next_serial.ok_or(Error::Exhausted)?;
        self.next_serial = id.checked_add(1);
        Ok(id)
    }
    fn handle(&self, slot: usize) -> Handle {
        Handle {
            connection: self.connection,
            epoch: self.epoch,
            slot,
            serial: self.slots[slot].serial,
        }
    }
    fn validate(&self, h: Handle) -> Result<usize, Error> {
        let s = self.slots.get(h.slot).ok_or(Error::Stale)?;
        if h.connection != self.connection
            || h.epoch != self.epoch
            || !s.live
            || h.serial != s.serial
        {
            return Err(Error::Stale);
        }
        Ok(h.slot)
    }
    /// Admit a complete replay-safe bidirectional request at offset zero + FIN.
    /// Semantic replay safety (e.g. HQ GET only) is the application's policy.
    pub fn enqueue(&mut self, bytes: &[u8]) -> Result<Handle, Error> {
        if self.phase != Phase::Offering {
            return Err(Error::State);
        }
        if bytes.is_empty() || bytes.len() > BYTES {
            return Err(Error::Capacity);
        }
        let limits = self.limits.stream_limits();
        let charged = self
            .charged
            .checked_add(bytes.len() as u64)
            .ok_or(Error::Limits)?;
        if self.next_stream / 4 >= limits.max_streams_bidi
            || bytes.len() as u64 > limits.stream_data_bidi_remote
            || charged > limits.max_data
        {
            return Err(Error::Limits);
        }
        let i = self
            .slots
            .iter()
            .position(|s| !s.live)
            .ok_or(Error::Capacity)?;
        let serial = self.serial()?;
        let next = self
            .next_stream
            .checked_add(4)
            .filter(|n| *n <= MAX_VARINT)
            .ok_or(Error::Exhausted)?;
        let s = &mut self.slots[i];
        s.live = true;
        s.serial = serial;
        s.stream = self.next_stream;
        s.len = bytes.len();
        s.bytes[..bytes.len()].copy_from_slice(bytes);
        self.next_stream = next;
        self.charged = charged;
        Ok(self.handle(i))
    }
    pub fn request(&self, h: Handle) -> Result<RequestView<'_>, Error> {
        if self.phase != Phase::Offering {
            return Err(Error::State);
        }
        let s = &self.slots[self.validate(h)?];
        Ok(RequestView {
            stream_id: s.stream,
            bytes: &s.bytes[..s.len],
        })
    }
    /// Pass the actual PN from the single shared ApplicationData allocator.
    /// This monotonic check does not allocate or rewind that owner.
    pub fn reserve(&mut self, h: Handle, packet: u64) -> Result<SendTicket, Error> {
        if self.phase != Phase::Offering {
            return Err(Error::State);
        }
        let i = self.validate(h)?;
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        if packet > MAX_VARINT || self.last_packet.is_some_and(|p| packet <= p) {
            return Err(Error::PacketNumber);
        }
        let reference = self.slots[i]
            .packets
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let serial = self.serial()?;
        let t = SendTicket {
            handle: h,
            serial,
            packet,
            reference,
        };
        self.pending = Some(t);
        self.last_packet = Some(packet);
        Ok(t)
    }
    pub fn adapter_result(&mut self, t: SendTicket, accepted: bool) -> Result<(), Error> {
        let i = self.validate(t.handle)?;
        if self.pending != Some(t) {
            return Err(Error::Stale);
        }
        if accepted {
            self.slots[i].packets[t.reference] = Some(t.packet);
        }
        self.pending = None;
        Ok(())
    }
    /// Carry exact loss state across accepted-early reconciliation. Lost
    /// references remain eligible for a late authenticated ACK; intent survives.
    pub fn packet_lost(&mut self, packet: u64) -> usize {
        let mut count = 0;
        for slot in self.slots.iter_mut().filter(|s| s.live) {
            for (index, pn) in slot.packets.iter().enumerate() {
                if *pn == Some(packet) && !slot.lost[index] {
                    slot.lost[index] = true;
                    count += 1;
                }
            }
        }
        count
    }

    /// Call only after the real TLS decision and authenticated parameters are
    /// known. In-flight adapter ownership must be reconciled first. Rejection
    /// is not loss and cannot free any ordinary queue's bytes.
    pub fn decide(&mut self, decision: Decision) -> Result<(), Error> {
        if self.phase != Phase::Offering {
            return Err(Error::State);
        }
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        let epoch = self.epoch.checked_add(1).ok_or(Error::Exhausted)?;
        if decision == Decision::Rejected {
            for s in self.slots.iter_mut() {
                s.packets.fill(None);
                s.lost.fill(false);
            }
        }
        self.epoch = epoch;
        self.phase = Phase::Importing(decision);
        Ok(())
    }
    /// Import in original stream order. Rejected intent can encounter smaller
    /// new credit: leave it owned here until ordinary flow credit permits it.
    pub fn next_import(&self) -> Result<Option<ImportView<'_>>, Error> {
        let Phase::Importing(decision) = self.phase else {
            return if self.phase == Phase::Complete {
                Ok(None)
            } else {
                Err(Error::State)
            };
        };
        let Some((i, s)) = self
            .slots
            .iter()
            .enumerate()
            .filter(|(_, s)| s.live)
            .min_by_key(|(_, s)| s.stream)
        else {
            return Ok(None);
        };
        Ok(Some(ImportView {
            ticket: ImportTicket {
                handle: self.handle(i),
                decision,
                stream_id: s.stream,
                offset: s.replay_offset,
            },
            decision,
            stream_id: s.stream,
            bytes: &s.bytes[s.replay_offset..s.len],
            accepted_packets: &s.packets,
            lost_packets: &s.lost,
        }))
    }
    /// Commit only after the ordinary table/queue owns all bytes and (when
    /// accepted) every exact original packet reference. A failed import must
    /// not call this. Replayed stale import descriptors cannot free new intent.
    pub fn complete_import(&mut self, t: ImportTicket) -> Result<(), Error> {
        let expected = self.next_import()?.ok_or(Error::Stale)?.ticket;
        if expected != t {
            return Err(Error::Stale);
        }
        let i = self.validate(t.handle)?;
        self.slots[i].clear();
        if !self.slots.iter().any(|s| s.live) {
            self.phase = Phase::Complete;
        }
        Ok(())
    }
    /// Atomically copy the next intent into the ordinary client stream owner.
    /// New authenticated limits already belong to `table`. A capacity/credit
    /// error leaves this journal and the table/queue unchanged.
    pub fn import_next<const RX: usize, const TX: usize>(
        &mut self,
        table: &mut crate::streams::StreamTable<'_, RX>,
        queue: &mut crate::streams::SendQueue<'_, TX>,
    ) -> Result<Option<crate::streams::StreamHandle>, crate::streams::Error> {
        let Some(view) = self
            .next_import()
            .map_err(|_| crate::streams::Error::InvalidTransition)?
        else {
            return Ok(None);
        };
        let ticket = view.ticket;
        if view.decision == Decision::Rejected {
            let slot = ticket.handle.slot;
            let existing = self.slots[slot].replay_stream;
            let (stream, n) = queue.import_replay_prefix(
                table,
                self.connection,
                view.stream_id,
                existing,
                view.bytes,
            )?;
            let remaining = view.bytes.len();
            if n == remaining {
                self.complete_import(ticket)
                    .map_err(|_| crate::streams::Error::InvalidTransition)?;
            } else {
                let state = &mut self.slots[slot];
                let start = state.replay_offset;
                state.bytes[start..start + n].zeroize();
                state.replay_offset += n;
                state.replay_stream = Some(stream);
            }
            return Ok(Some(stream));
        }
        let (stream, _) = queue.import_early_request(
            table,
            self.connection,
            view.stream_id,
            view.bytes,
            view.accepted_packets,
            view.lost_packets,
        )?;
        self.complete_import(ticket)
            .map_err(|_| crate::streams::Error::InvalidTransition)?;
        Ok(Some(stream))
    }

    pub fn retire(&mut self) {
        for s in self.slots.iter_mut() {
            s.clear();
        }
        self.pending = None;
        self.phase = Phase::Retired;
    }
}
impl<const BYTES: usize> Drop for Journal<'_, BYTES> {
    fn drop(&mut self) {
        self.retire();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn limits() -> RememberedLimits {
        RememberedLimits::from_authenticated_server_parameters(&[
            0, 0, 15, 0, 4, 1, 32, 6, 1, 16, 8, 1, 2,
        ])
        .unwrap()
    }
    #[test]
    fn rejected_intent_keeps_bytes_but_not_credit_handles_or_packet_refs() {
        let mut slots = [const { RequestSlot::<16>::EMPTY }; 2];
        let mut j = Journal::new(7, limits(), &mut slots).unwrap();
        let a = j.enqueue(b"GET /a").unwrap();
        let b = j.enqueue(b"GET /b").unwrap();
        let t = j.reserve(a, 0).unwrap();
        assert_eq!(j.decide(Decision::Rejected), Err(Error::Busy));
        j.adapter_result(t, true).unwrap();
        j.decide(Decision::Rejected).unwrap();
        assert!(j.request(a).is_err());
        assert!(j.reserve(b, 1).is_err());
        let v = j.next_import().unwrap().unwrap();
        assert_eq!(v.stream_id, 0);
        assert_eq!(v.bytes, b"GET /a");
        assert!(v.accepted_packets.iter().all(Option::is_none));
        let t = v.ticket;
        j.complete_import(t).unwrap();
        assert_eq!(j.complete_import(t), Err(Error::Stale));
        let v = j.next_import().unwrap().unwrap();
        assert_eq!(v.stream_id, 4);
        assert_eq!(v.bytes, b"GET /b");
        let t = v.ticket;
        j.complete_import(t).unwrap();
        assert!(j.next_import().unwrap().is_none());
    }
    #[test]
    fn accepted_import_preserves_exact_packet_refs_and_rejects_copied_completion() {
        let mut slots = [RequestSlot::<16>::EMPTY];
        let mut j = Journal::new(8, limits(), &mut slots).unwrap();
        let h = j.enqueue(b"GET /").unwrap();
        let a = j.reserve(h, 5).unwrap();
        j.adapter_result(a, false).unwrap();
        assert_eq!(j.adapter_result(a, true), Err(Error::Stale));
        assert_eq!(j.reserve(h, 5), Err(Error::PacketNumber));
        let b = j.reserve(h, 6).unwrap();
        j.adapter_result(b, true).unwrap();
        let c = j.reserve(h, 9).unwrap();
        j.adapter_result(c, true).unwrap();
        j.decide(Decision::Accepted).unwrap();
        let v = j.next_import().unwrap().unwrap();
        assert_eq!(v.accepted_packets[..3], [Some(6), Some(9), None]);
        assert_eq!(v.bytes, b"GET /");
    }
    #[test]
    fn capacity_failure_is_atomic_and_foreign_handles_cannot_authorize() {
        let mut a = [RequestSlot::<16>::EMPTY];
        let mut b = [RequestSlot::<16>::EMPTY];
        let mut x = Journal::new(9, limits(), &mut a).unwrap();
        let mut y = Journal::new(10, limits(), &mut b).unwrap();
        let h = x.enqueue(b"GET /").unwrap();
        assert!(x.enqueue(b"second").is_err());
        let own = y.enqueue(b"GET /").unwrap();
        assert_eq!(y.reserve(h, 0), Err(Error::Stale));
        let t = y.reserve(own, 0).unwrap();
        y.adapter_result(t, true).unwrap();
        assert_eq!(x.request(h).unwrap().bytes, b"GET /");
    }
    #[test]
    fn reference_capacity_backpressures_without_losing_intent() {
        let mut a = [RequestSlot::<16>::EMPTY];
        let mut j = Journal::new(11, limits(), &mut a).unwrap();
        let h = j.enqueue(b"GET /").unwrap();
        for pn in 0..REFERENCES_PER_REQUEST as u64 {
            let t = j.reserve(h, pn).unwrap();
            j.adapter_result(t, true).unwrap();
        }
        assert_eq!(j.reserve(h, 9), Err(Error::Capacity));
        assert_eq!(j.request(h).unwrap().bytes, b"GET /");
        j.decide(Decision::Rejected).unwrap();
        assert_eq!(j.next_import().unwrap().unwrap().bytes, b"GET /");
    }
    #[test]
    fn accepted_and_rejected_import_use_real_stream_queue_without_old_handle_revival() {
        use crate::streams::{
            Limits, PacketReference, Role, SendChunk, SendQueue, StreamSlot, StreamTable,
        };
        for accepted in [false, true] {
            let mut intents = [RequestSlot::<16>::EMPTY];
            let mut journal = Journal::new(44, limits(), &mut intents).unwrap();
            let early = journal.enqueue(b"GET /").unwrap();
            let sent = journal.reserve(early, 7).unwrap();
            journal.adapter_result(sent, true).unwrap();
            journal
                .decide(if accepted {
                    Decision::Accepted
                } else {
                    Decision::Rejected
                })
                .unwrap();
            let mut slots = [const { StreamSlot::<16>::EMPTY }; 2];
            let local = Limits {
                max_data: 32,
                stream_data_bidi_local: 16,
                stream_data_bidi_remote: 16,
                stream_data_uni: 0,
                max_streams_bidi: 0,
                max_streams_uni: 0,
            };
            let mut table = StreamTable::new(
                &mut slots,
                Role::Client,
                44,
                local,
                limits().stream_limits(),
            )
            .unwrap();
            let mut chunks = [SendChunk::<16>::EMPTY];
            let mut refs = [PacketReference::EMPTY; 8];
            let mut queue = SendQueue::new(44, &mut chunks, &mut refs).unwrap();
            let stream = journal
                .import_next(&mut table, &mut queue)
                .unwrap()
                .unwrap();
            assert_eq!(stream.id(), 0);
            assert_eq!(table.send_reserved(), 5);
            assert!(journal.request(early).is_err());
            assert!(journal.next_import().unwrap().is_none());
            if accepted {
                assert!(queue.next_pending().is_none());
                assert_eq!(queue.on_packet_acked(&mut table, 7).unwrap(), 1);
            } else {
                assert!(queue.next_pending().is_some());
                assert_eq!(queue.on_packet_acked(&mut table, 7).unwrap(), 0);
                assert_eq!(queue.queued_chunks(), 1);
            }
        }
    }
    #[test]
    fn rejected_request_with_smaller_fresh_credit_remains_owned_until_credit_update() {
        use crate::streams::{
            Error as StreamError, Limits, PacketReference, Role, SendChunk, SendQueue, StreamSlot,
            StreamTable,
        };
        let mut intents = [RequestSlot::<16>::EMPTY];
        let mut journal = Journal::new(45, limits(), &mut intents).unwrap();
        journal.enqueue(b"GET /").unwrap();
        journal.decide(Decision::Rejected).unwrap();
        let mut slots = [const { StreamSlot::<16>::EMPTY }; 2];
        let local = Limits {
            max_data: 32,
            stream_data_bidi_local: 16,
            stream_data_bidi_remote: 16,
            stream_data_uni: 0,
            max_streams_bidi: 0,
            max_streams_uni: 0,
        };
        let mut peer = limits().stream_limits();
        peer.max_data = 0;
        let mut table = StreamTable::new(&mut slots, Role::Client, 45, local, peer).unwrap();
        let mut chunks = [SendChunk::<16>::EMPTY];
        let mut refs = [PacketReference::EMPTY; 8];
        let mut queue = SendQueue::new(45, &mut chunks, &mut refs).unwrap();
        assert_eq!(
            journal.import_next(&mut table, &mut queue),
            Err(StreamError::FlowControl)
        );
        assert_eq!(table.live_count(), 0);
        assert_eq!(table.send_reserved(), 0);
        assert_eq!(journal.next_import().unwrap().unwrap().bytes, b"GET /");
        table.on_max_data(16).unwrap();
        assert!(
            journal
                .import_next(&mut table, &mut queue)
                .unwrap()
                .is_some()
        );
        assert_eq!(queue.queued_chunks(), 1);
    }
    #[test]
    fn foreign_connection_import_is_atomic_and_does_not_release_owned_intent() {
        use crate::streams::{
            Error as StreamError, Limits, PacketReference, Role, SendChunk, SendQueue, StreamSlot,
            StreamTable,
        };
        let mut intents = [RequestSlot::<16>::EMPTY];
        let mut journal = Journal::new(44, limits(), &mut intents).unwrap();
        let h = journal.enqueue(b"GET /").unwrap();
        let sent = journal.reserve(h, 7).unwrap();
        journal.adapter_result(sent, true).unwrap();
        journal.decide(Decision::Accepted).unwrap();
        let mut slots = [const { StreamSlot::<16>::EMPTY }; 2];
        let local = Limits {
            max_data: 32,
            stream_data_bidi_local: 16,
            stream_data_bidi_remote: 16,
            stream_data_uni: 0,
            max_streams_bidi: 0,
            max_streams_uni: 0,
        };
        let mut table = StreamTable::new(
            &mut slots,
            Role::Client,
            45,
            local,
            limits().stream_limits(),
        )
        .unwrap();
        let mut chunks = [SendChunk::<16>::EMPTY];
        let mut refs = [PacketReference::EMPTY; 8];
        let mut queue = SendQueue::new(99, &mut chunks, &mut refs).unwrap();
        assert_eq!(
            journal.import_next(&mut table, &mut queue),
            Err(StreamError::InvalidTransition)
        );
        assert_eq!(table.live_count(), 0);
        assert_eq!(table.send_reserved(), 0);
        assert_eq!(queue.queued_chunks(), 0);
        assert_eq!(queue.active_references(), 0);
        let v = journal.next_import().unwrap().unwrap();
        assert_eq!(v.bytes, b"GET /");
        assert_eq!(v.accepted_packets[0], Some(7));
    }
    #[test]
    fn rejected_request_replays_in_prefixes_when_new_credit_is_smaller() {
        use crate::streams::{
            Error as StreamError, Limits, PacketReference, Role, SendChunk, SendQueue, StreamSlot,
            StreamTable,
        };
        let mut intents = [RequestSlot::<16>::EMPTY];
        let mut journal = Journal::new(46, limits(), &mut intents).unwrap();
        journal.enqueue(b"GET /").unwrap();
        journal.decide(Decision::Rejected).unwrap();
        let mut slots = [const { StreamSlot::<16>::EMPTY }; 2];
        let local = Limits {
            max_data: 32,
            stream_data_bidi_local: 16,
            stream_data_bidi_remote: 16,
            stream_data_uni: 0,
            max_streams_bidi: 0,
            max_streams_uni: 0,
        };
        let mut peer = limits().stream_limits();
        peer.max_data = 4;
        peer.stream_data_bidi_remote = 4;
        let mut table = StreamTable::new(&mut slots, Role::Client, 46, local, peer).unwrap();
        let mut chunks = [const { SendChunk::<16>::EMPTY }; 2];
        let mut refs = [PacketReference::EMPTY; 8];
        let mut queue = SendQueue::new(46, &mut chunks, &mut refs).unwrap();
        let h = journal
            .import_next(&mut table, &mut queue)
            .unwrap()
            .unwrap();
        assert_eq!(table.send_reserved(), 4);
        let first = queue.next_pending().unwrap();
        let view = queue.chunk(first).unwrap();
        assert_eq!(view.data, b"GET ");
        assert!(!view.fin);
        assert_eq!(journal.next_import().unwrap().unwrap().bytes, b"/");
        assert_eq!(
            journal.import_next(&mut table, &mut queue),
            Err(StreamError::FlowControl)
        );
        let sent = queue.reserve_transmission(first, 9).unwrap();
        queue.commit_transmission(&mut table, sent).unwrap();
        table.on_max_data(8).unwrap();
        table.on_max_stream_data(h, 8).unwrap();
        assert_eq!(
            journal.import_next(&mut table, &mut queue).unwrap(),
            Some(h)
        );
        let last = queue.chunk(queue.next_pending().unwrap()).unwrap();
        assert_eq!(last.offset, 4);
        assert_eq!(last.data, b"/");
        assert!(last.fin);
        assert!(!journal.has_intent());
        assert_eq!(table.cumulative_opened(0).unwrap(), 1);
    }
    #[test]
    fn accepted_lost_reference_remains_retransmittable_and_late_ack_eligible_after_import() {
        use crate::streams::{
            Limits, PacketReference, Role, SendChunk, SendQueue, StreamSlot, StreamTable,
        };
        let mut intents = [RequestSlot::<16>::EMPTY];
        let mut journal = Journal::new(47, limits(), &mut intents).unwrap();
        let h = journal.enqueue(b"GET /").unwrap();
        let t = journal.reserve(h, 7).unwrap();
        journal.adapter_result(t, true).unwrap();
        assert_eq!(journal.packet_lost(7), 1);
        assert_eq!(journal.packet_lost(7), 0);
        journal.decide(Decision::Accepted).unwrap();
        let mut slots = [const { StreamSlot::<16>::EMPTY }; 2];
        let local = Limits {
            max_data: 32,
            stream_data_bidi_local: 16,
            stream_data_bidi_remote: 16,
            stream_data_uni: 0,
            max_streams_bidi: 0,
            max_streams_uni: 0,
        };
        let mut table = StreamTable::new(
            &mut slots,
            Role::Client,
            47,
            local,
            limits().stream_limits(),
        )
        .unwrap();
        let mut chunks = [SendChunk::<16>::EMPTY];
        let mut refs = [PacketReference::EMPTY; 8];
        let mut queue = SendQueue::new(47, &mut chunks, &mut refs).unwrap();
        journal.import_next(&mut table, &mut queue).unwrap();
        assert_eq!(
            queue.chunk(queue.next_pending().unwrap()).unwrap().data,
            b"GET /"
        );
        assert_eq!(queue.on_packet_acked(&mut table, 7).unwrap(), 1);
        assert!(queue.next_pending().is_none());
    }
}
