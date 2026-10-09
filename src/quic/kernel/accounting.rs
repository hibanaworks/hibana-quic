//! Bounded packet-number, sent-packet, and path-reservation accounting kernels.
//!
//! These are single-owner Sans-I/O building blocks, not a loss detector, a
//! congestion controller, or a complete recovery implementation. ACK input must
//! already have passed packet authentication. Stream-data ownership is separate:
//! declaring a packet lost does not authorize freeing its retransmission data.
//!
//! References: RFC 9000 sections 8.1, 12.3, 13.1; RFC 9002 section 7.2.

use crate::quic::ecn::{Codepoint, MarkedPackets, PathIdentity};

pub const MAX_PACKET_NUMBER: u64 = (1_u64 << 62) - 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PacketNumberSpace {
    Initial = 0,
    Handshake = 1,
    ApplicationData = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketKind {
    Initial,
    Handshake,
    ZeroRtt,
    OneRtt,
}

impl PacketKind {
    pub const fn space(self) -> PacketNumberSpace {
        match self {
            Self::Initial => PacketNumberSpace::Initial,
            Self::Handshake => PacketNumberSpace::Handshake,
            Self::ZeroRtt | Self::OneRtt => PacketNumberSpace::ApplicationData,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketNumber {
    pub space: PacketNumberSpace,
    pub value: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountingError {
    PacketNumberExhausted,
    Full,
    Overflow,
    InvalidReservation,
    InvalidState,
    InvalidClassification,
    UnsentPacket,
    InvalidAckRange,
    TooManyAckRanges,
    /// Old history was explicitly reclaimed. This is not evidence of a peer
    /// protocol violation; do not map it to an unsent-packet transport error.
    HistoryUnavailable,
    OutstandingPackets,
    AmplificationLimited,
    ReservationIdExhausted,
    Retired,
}

/// One allocator per connection, retained across Retry and key changes.
///
/// No reset, rewind, Clone, or Copy operation exists. Allocated numbers are
/// burned even if packet construction or adapter submission subsequently fails.
pub struct PacketNumberAllocator {
    next: [u64; 3],
}

impl PacketNumberAllocator {
    pub const fn new() -> Self {
        Self { next: [0; 3] }
    }

    pub fn allocate(&mut self, kind: PacketKind) -> Result<PacketNumber, AccountingError> {
        let space = kind.space();
        let next = &mut self.next[space as usize];
        if *next > MAX_PACKET_NUMBER {
            return Err(AccountingError::PacketNumberExhausted);
        }
        let packet = PacketNumber {
            space,
            value: *next,
        };
        // MAX_PACKET_NUMBER + 1 is representable in u64 and is an exhausted
        // sentinel, never an allocated packet number.
        *next += 1;
        Ok(packet)
    }

    pub fn next(&self, space: PacketNumberSpace) -> Option<u64> {
        let value = self.next[space as usize];
        (value <= MAX_PACKET_NUMBER).then_some(value)
    }
}

impl Default for PacketNumberAllocator {
    fn default() -> Self {
        Self::new()
    }
}

/// A reservation is a descriptor, not a Rust-only linear capability. Copies
/// are checked against a unique live record when completing or cancelling it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendReservation {
    connection_generation: u64,
    slot: usize,
    packet: PacketNumber,
}

impl SendReservation {
    pub const fn packet(self) -> PacketNumber {
        self.packet
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PacketState {
    Reserved,
    Sent,
    Lost,
    Acknowledged,
    Cancelled,
}

#[derive(Clone, Copy, Debug)]
struct SentRecord {
    packet: PacketNumber,
    kind: PacketKind,
    bytes: u64,
    in_flight: bool,
    ack_eliciting: bool,
    sent_at: Option<u64>,
    ecn: Codepoint,
    path: Option<PathIdentity>,
    state: PacketState,
}

fn remember_retired_sent_time(bounds: &mut [Option<u64>; 3], record: SentRecord) {
    if matches!(
        record.state,
        PacketState::Sent | PacketState::Lost | PacketState::Acknowledged
    ) && let Some(at) = record.sent_at
    {
        let bound = &mut bounds[record.packet.space as usize];
        *bound = Some(bound.map_or(at, |old| old.max(at)));
    }
}

/// Immutable, copyable recovery metadata for an outstanding accepted packet.
/// The snapshot does not authorize subtracting flight bytes: apply ACK/loss or
/// key discard through the owning ledger, which checks the current state again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SentPacket {
    pub packet: PacketNumber,
    pub bytes: u64,
    pub in_flight: bool,
    pub ack_eliciting: bool,
    pub sent_at: u64,
    pub ecn: Codepoint,
    /// Actual adapter-accepted path. None is legacy/unavailable evidence, never
    /// an instruction to attribute this packet to the current active path.
    pub path: Option<PathIdentity>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AckRange {
    pub start: u64,
    pub end: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AckSummary {
    pub newly_acknowledged: usize,
    pub previously_lost: usize,
    pub bytes_removed_from_flight: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LossOutcome {
    NewlyLost { bytes_removed_from_flight: u64 },
    AlreadyHandled,
}

/// An inline bounded ledger owned by its caller. The connection-generation
/// value must never be reused while stale completions can arrive. There must be
/// exactly one sent ledger per connection. It is deliberately not cloneable.
///
/// Terminal records occupy capacity until `forget_before` or
/// `reclaim_completed_prefix` is called. This explicit backpressure avoids
/// silently forgetting an unsent/cancelled PN and later accepting a forged ACK
/// for it. ACK portions below the retained floor are ignored; retained portions
/// are still validated and applied atomically. Under pressure, accepted
/// non-in-flight records can be compressed into exact PN runs; those runs
/// validate historical ACKs without minting new delivery or key receipts.
pub struct SentLedger<const CAPACITY: usize> {
    connection_generation: u64,
    allocator: PacketNumberAllocator,
    records: [Option<SentRecord>; CAPACITY],
    // Exact accepted, non-in-flight PN runs. These retain validation evidence,
    // not delivery, RTT, congestion or key-update authority.
    ack_history: [Option<(PacketNumberSpace, AckRange)>; CAPACITY],
    floor: [u64; 3],
    bytes_in_flight: u64,
    reserved_in_flight: u64,
    ecn_accepted: [MarkedPackets; 3],
    retired_sent_upper_bound: [Option<u64>; 3],
    retired: bool,
}

impl<const CAPACITY: usize> SentLedger<CAPACITY> {
    pub const fn new(connection_generation: u64) -> Self {
        Self {
            connection_generation,
            allocator: PacketNumberAllocator::new(),
            records: [None; CAPACITY],
            ack_history: [None; CAPACITY],
            floor: [0; 3],
            bytes_in_flight: 0,
            reserved_in_flight: 0,
            ecn_accepted: [MarkedPackets { ect0: 0, ect1: 0 }; 3],
            retired_sent_upper_bound: [None; 3],
            retired: false,
        }
    }

    /// Compress only actually accepted ACK-only records. Outstanding eliciting
    /// packets and reservations remain owned records. A lost peer ACK must not
    /// pin a growing tail of ACK-only records and consume all recovery slots.
    /// Run insertion is transactional: a fragmented history that cannot fit
    /// leaves the ledger unchanged. Returned identities have no live receipt.
    pub(crate) fn compact_ack_history(
        &mut self,
    ) -> Result<[Option<PacketNumber>; CAPACITY], AccountingError> {
        self.ensure_active()?;
        let mut history = self.ack_history;
        let mut removed = [None; CAPACITY];
        for (index, record) in self.records.iter().enumerate() {
            let Some(record) = record else { continue };
            if record.in_flight || record.state != PacketState::Sent {
                continue;
            }
            let space = record.packet.space;
            let mut range = AckRange {
                start: record.packet.value,
                end: record.packet.value,
            };
            // Existing runs are disjoint and non-adjacent. The singleton can
            // join at most its left and right neighbors, without filling gaps.
            for entry in &mut history {
                if let Some((other_space, other)) = *entry
                    && other_space == space
                    && range.start <= other.end.saturating_add(1)
                    && other.start <= range.end.saturating_add(1)
                {
                    range.start = range.start.min(other.start);
                    range.end = range.end.max(other.end);
                    *entry = None;
                }
            }
            let slot = history
                .iter_mut()
                .find(|entry| entry.is_none())
                .ok_or(AccountingError::Full)?;
            *slot = Some((space, range));
            removed[index] = Some(record.packet);
        }
        self.ack_history = history;
        for (index, packet) in removed.iter().enumerate() {
            if packet.is_some() {
                let record = self.records[index]
                    .take()
                    .expect("selected retained record");
                remember_retired_sent_time(&mut self.retired_sent_upper_bound, record);
            }
        }
        Ok(removed)
    }

    fn forget_ack_history_before(&mut self, space: PacketNumberSpace, exclusive: u64) {
        for entry in &mut self.ack_history {
            if let Some((other_space, range)) = entry
                && *other_space == space
            {
                if range.end < exclusive {
                    *entry = None;
                } else {
                    range.start = range.start.max(exclusive);
                }
            }
        }
    }

    /// Immediate reservation capacity, excluding retained terminal history.
    /// Used to avoid arming an already-due optional probe that cannot be queued.
    pub fn remaining_capacity(&self) -> usize {
        if self.retired {
            0
        } else {
            self.records.iter().filter(|r| r.is_none()).count()
        }
    }

    /// Reserve a history slot and its future in-flight counter capacity before
    /// exposing any packet to the adapter. `in_flight` is a caller-supplied RFC
    /// 9002 classification (ACK-eliciting or containing PADDING), not merely
    /// whether the datagram has bytes. A false classification must therefore
    /// carry no retransmittable payload: accepted ACK-only records may be
    /// reclaimed by `reclaim_completed_prefix`. Congestion-window checks belong
    /// upstream. This compatibility API conservatively treats every in-flight
    /// packet as ACK-eliciting. Use `reserve_classified` for precise PTO/RTT
    /// inputs, particularly for ACK+PADDING packets.
    pub fn reserve(
        &mut self,
        kind: PacketKind,
        bytes: u64,
        in_flight: bool,
    ) -> Result<SendReservation, AccountingError> {
        self.reserve_classified(kind, bytes, in_flight, in_flight)
    }

    /// Reserve with independent congestion-accounting and ACK-eliciting facts.
    /// PADDING makes a packet in-flight but does not elicit ACKs. ACK-eliciting
    /// packets must be in-flight; rejecting a contradictory classification burns
    /// neither a slot nor a packet number.
    pub fn reserve_classified(
        &mut self,
        kind: PacketKind,
        bytes: u64,
        in_flight: bool,
        ack_eliciting: bool,
    ) -> Result<SendReservation, AccountingError> {
        self.ensure_active()?;
        if ack_eliciting && !in_flight {
            return Err(AccountingError::InvalidClassification);
        }
        let slot = self
            .records
            .iter()
            .position(Option::is_none)
            .ok_or(AccountingError::Full)?;
        let reservation_bytes = if in_flight { bytes } else { 0 };
        let reserved = self
            .reserved_in_flight
            .checked_add(reservation_bytes)
            .ok_or(AccountingError::Overflow)?;
        self.bytes_in_flight
            .checked_add(reserved)
            .ok_or(AccountingError::Overflow)?;
        let packet = self.allocator.allocate(kind)?;
        self.reserved_in_flight = reserved;
        self.records[slot] = Some(SentRecord {
            packet,
            kind,
            bytes,
            in_flight,
            ack_eliciting,
            sent_at: None,
            ecn: Codepoint::NotEct,
            path: None,
            state: PacketState::Reserved,
        });
        Ok(SendReservation {
            connection_generation: self.connection_generation,
            slot,
            packet,
        })
    }

    /// Irreversible adapter acceptance moves the reservation into sent history.
    /// A later socket/network loss must use `declare_lost`, never `cancel`.
    /// The timestamp is injected monotonic time; this kernel does not read time.
    pub fn adapter_accepted(
        &mut self,
        reservation: SendReservation,
        sent_at: u64,
    ) -> Result<(), AccountingError> {
        self.adapter_accepted_ecn(reservation, sent_at, Codepoint::NotEct)
    }

    /// Commit the actual per-packet IP marking only after adapter acceptance.
    /// Original marking survives loss/reclaim in cumulative per-space counters.
    pub fn adapter_accepted_ecn(
        &mut self,
        reservation: SendReservation,
        sent_at: u64,
        ecn: Codepoint,
    ) -> Result<(), AccountingError> {
        self.accepted_metadata(reservation, sent_at, ecn, None)
    }

    /// Commit the original path only after the carrier actually accepts this
    /// packet on that exact path. Migration never rewrites this attribution.
    /// The path owner/typed reservation establishes the address binding; this
    /// ledger independently rejects stale connection generations.
    pub fn adapter_accepted_on_path(
        &mut self,
        reservation: SendReservation,
        sent_at: u64,
        ecn: Codepoint,
        path: PathIdentity,
    ) -> Result<(), AccountingError> {
        if path.connection_generation != self.connection_generation {
            return Err(AccountingError::InvalidReservation);
        }
        self.accepted_metadata(reservation, sent_at, ecn, Some(path))
    }

    fn accepted_metadata(
        &mut self,
        reservation: SendReservation,
        sent_at: u64,
        ecn: Codepoint,
        path: Option<PathIdentity>,
    ) -> Result<(), AccountingError> {
        let record = *self.reservation(reservation)?;
        if record.state != PacketState::Reserved {
            return Err(AccountingError::InvalidState);
        }
        if ecn == Codepoint::Ce {
            return Err(AccountingError::InvalidClassification);
        }
        let mut counts = self.ecn_accepted[record.packet.space as usize];
        let count = match ecn {
            Codepoint::Ect0 => Some(&mut counts.ect0),
            Codepoint::Ect1 => Some(&mut counts.ect1),
            _ => None,
        };
        if let Some(count) = count {
            *count = count
                .checked_add(1)
                .filter(|n| *n <= MAX_PACKET_NUMBER)
                .ok_or(AccountingError::Overflow)?;
        }
        if record.in_flight {
            self.reserved_in_flight -= record.bytes;
            // reserve checked the sum of all pending and actual flight bytes.
            self.bytes_in_flight += record.bytes;
        }
        self.records[reservation.slot] = Some(SentRecord {
            state: PacketState::Sent,
            sent_at: Some(sent_at),
            ecn,
            path,
            ..record
        });
        self.ecn_accepted[record.packet.space as usize] = counts;
        Ok(())
    }
    /// Original packet protection kind; 0-RTT and 1-RTT share a PN space but
    /// an ACK of early traffic must not grant a 1-RTT key-update authority.
    pub fn sent_kind(&self, packet: PacketNumber) -> Option<PacketKind> {
        if self.retired {
            return None;
        }
        self.records
            .iter()
            .flatten()
            .find(|r| r.packet == packet)
            .map(|r| r.kind)
    }

    pub fn accepted_ecn_counts(&self, space: PacketNumberSpace) -> MarkedPackets {
        self.ecn_accepted[space as usize]
    }

    /// Cancel only after the adapter is known not to have accepted the packet.
    /// Dropping an application future alone is not that evidence. PN remains
    /// burned and its cancelled history record remains distinguishable.
    pub fn cancel(&mut self, reservation: SendReservation) -> Result<(), AccountingError> {
        let record = *self.reservation(reservation)?;
        if record.state != PacketState::Reserved {
            return Err(AccountingError::InvalidState);
        }
        if record.in_flight {
            self.reserved_in_flight -= record.bytes;
        }
        self.records[reservation.slot] = Some(SentRecord {
            state: PacketState::Cancelled,
            ..record
        });
        Ok(())
    }

    /// Validate an authenticated ACK without consuming or acknowledging any
    /// record. This supports a single owner's typed authorization step between
    /// validation and release. It is a fact about the current ledger, not a
    /// durable capability; `acknowledge` always revalidates before mutation.
    ///
    /// Ranges must be
    /// nonempty, ascending and disjoint; convert the wire's descending ranges
    /// first. Work is bounded by CAPACITY, never by the largest packet number.
    /// Old portions below the retained floor are ignored. Invalid/unsent
    /// retained portions have no accounting effects, including when an earlier
    /// range would otherwise acknowledge valid packets.
    pub fn validate_ack(
        &self,
        space: PacketNumberSpace,
        ranges: &[AckRange],
    ) -> Result<(), AccountingError> {
        self.ensure_active()?;
        if ranges.is_empty() {
            return Err(AccountingError::InvalidAckRange);
        }
        if ranges.len() > CAPACITY {
            return Err(AccountingError::TooManyAckRanges);
        }
        let mut previous_end = None;
        for range in ranges {
            if range.start > range.end
                || range.end > MAX_PACKET_NUMBER
                || previous_end.is_some_and(|end| range.start <= end)
            {
                return Err(AccountingError::InvalidAckRange);
            }
            previous_end = Some(range.end);
            let floor = self.floor[space as usize];
            if range.end < floor {
                continue;
            }
            let retained = AckRange {
                start: range.start.max(floor),
                end: range.end,
            };
            let mut matched = 0_u64;
            for (other_space, history) in self.ack_history.iter().flatten() {
                if *other_space == space {
                    let start = retained.start.max(history.start);
                    let end = retained.end.min(history.end);
                    if start <= end {
                        matched += end - start + 1;
                    }
                }
            }
            for record in self.records.iter().flatten() {
                if record.packet.space == space && contains(retained, record.packet.value) {
                    if matches!(record.state, PacketState::Reserved | PacketState::Cancelled) {
                        return Err(AccountingError::UnsentPacket);
                    }
                    matched += 1;
                }
            }
            if matched != retained.end - retained.start + 1 {
                return Err(AccountingError::UnsentPacket);
            }
        }
        Ok(())
    }

    /// Revalidate and apply a fully authenticated ACK atomically. Validation
    /// failure has no accounting effects. Requirements and old-prefix handling
    /// are shared with `validate_ack`; this method never trusts a previous call.
    pub fn acknowledge(
        &mut self,
        space: PacketNumberSpace,
        ranges: &[AckRange],
    ) -> Result<AckSummary, AccountingError> {
        self.validate_ack(space, ranges)?;
        let mut summary = AckSummary::default();
        for record in self.records.iter_mut().flatten() {
            if record.packet.space != space
                || !ranges
                    .iter()
                    .any(|range| contains(*range, record.packet.value))
                || record.state == PacketState::Acknowledged
            {
                continue;
            }
            summary.newly_acknowledged += 1;
            if record.state == PacketState::Lost {
                summary.previously_lost += 1;
            } else if record.in_flight {
                summary.bytes_removed_from_flight += record.bytes;
            }
            record.state = PacketState::Acknowledged;
        }
        self.bytes_in_flight -= summary.bytes_removed_from_flight;
        Ok(summary)
    }

    pub fn declare_lost(&mut self, packet: PacketNumber) -> Result<LossOutcome, AccountingError> {
        self.ensure_active()?;
        if packet.value < self.floor[packet.space as usize] {
            return Err(AccountingError::HistoryUnavailable);
        }
        let record = self
            .records
            .iter_mut()
            .flatten()
            .find(|record| record.packet == packet)
            .ok_or(AccountingError::UnsentPacket)?;
        match record.state {
            PacketState::Reserved | PacketState::Cancelled => Err(AccountingError::UnsentPacket),
            PacketState::Lost | PacketState::Acknowledged => Ok(LossOutcome::AlreadyHandled),
            PacketState::Sent => {
                let removed = if record.in_flight { record.bytes } else { 0 };
                self.bytes_in_flight -= removed;
                record.state = PacketState::Lost;
                Ok(LossOutcome::NewlyLost {
                    bytes_removed_from_flight: removed,
                })
            }
        }
    }

    /// Snapshot each outstanding Sent record, including non-ack-eliciting
    /// in-flight PADDING packets. Lost, acknowledged, reserved and cancelled
    /// records are excluded. Ordering is storage-slot order, not PN order.
    /// Materialize the bounded snapshots or end the iterator borrow before
    /// applying mutations; its items are copies, never mutable record aliases.
    pub fn outstanding_sent(&self) -> impl Iterator<Item = SentPacket> + '_ {
        self.records.iter().flatten().filter_map(|record| {
            if self.retired || record.state != PacketState::Sent {
                return None;
            }
            record.sent_at.map(|sent_at| SentPacket {
                packet: record.packet,
                bytes: record.bytes,
                in_flight: record.in_flight,
                ack_eliciting: record.ack_eliciting,
                ecn: record.ecn,
                path: record.path,
                sent_at,
            })
        })
    }

    /// Snapshot every retained, not-yet-ACKed accepted packet (Sent or Lost).
    /// Lost packets retain original ACK-eliciting classification and send time
    /// for late-ACK RTT sampling, but `in_flight` is false because their bytes
    /// have already been removed. Summing bytes where this flag is true cannot
    /// double-count a late ACK. Acknowledged, Reserved and Cancelled are excluded.
    /// Ordering is storage-slot order. Copies do not grant accounting authority.
    pub fn unacknowledged_sent(&self) -> impl Iterator<Item = SentPacket> + '_ {
        self.records.iter().flatten().filter_map(|record| {
            if self.retired || !matches!(record.state, PacketState::Sent | PacketState::Lost) {
                return None;
            }
            record.sent_at.map(|sent_at| SentPacket {
                packet: record.packet,
                bytes: record.bytes,
                in_flight: record.state == PacketState::Sent && record.in_flight,
                ack_eliciting: record.ack_eliciting,
                ecn: record.ecn,
                path: record.path,
                sent_at,
            })
        })
    }

    /// Retained metadata for any actually accepted packet, including Lost and
    /// Acknowledged. Use `is_new_ack` separately: metadata presence alone does
    /// not prove a new ACK. This permits correct RTT eligibility checks for a
    /// late ACK of a Lost packet without re-counting its in-flight bytes.
    /// This historical lookup retains the original `in_flight` classification;
    /// use `unacknowledged_sent` for whether the bytes are currently counted.
    pub fn sent_packet(&self, packet: PacketNumber) -> Option<SentPacket> {
        if self.retired {
            return None;
        }
        let record = self.records.iter().flatten().find(|record| {
            record.packet == packet
                && matches!(
                    record.state,
                    PacketState::Sent | PacketState::Lost | PacketState::Acknowledged
                )
        })?;
        Some(SentPacket {
            packet: record.packet,
            bytes: record.bytes,
            in_flight: record.in_flight,
            ack_eliciting: record.ack_eliciting,
            ecn: record.ecn,
            path: record.path,
            sent_at: record.sent_at?,
        })
    }

    /// Read before applying an ACK frame to decide whether its exact largest
    /// packet is newly acknowledged. Aggregate ACK counts cannot answer this.
    /// A late ACK of Lost is new; a repeated ACK of Acknowledged is not.
    pub fn is_new_ack(&self, packet: PacketNumber) -> bool {
        !self.retired
            && self.records.iter().flatten().any(|record| {
                record.packet == packet
                    && matches!(record.state, PacketState::Sent | PacketState::Lost)
            })
    }

    /// Count retained, actually accepted later packets through largest_acked
    /// in the candidate's space. Cancelled/reserved PNs never contribute to the
    /// packet threshold. Missing/reclaimed history undercounts conservatively;
    /// an unknown, unsent, retired or invalid candidate returns zero.
    ///
    /// This is local evidence, not ACK validation. The caller must first have
    /// validated the ACK that established largest_acked. The candidate itself
    /// may be Sent, Lost or Acknowledged, but never merely allocated.
    pub fn count_later_sent(&self, packet: PacketNumber, largest_acked: u64) -> u64 {
        self.count_later_sent_matching(packet, largest_acked, None)
    }

    /// As `count_later_sent`, restricted to the candidate's immutable accepted
    /// path. An old or missing path is never replaced by today's active path.
    pub fn count_later_sent_on_path(
        &self,
        packet: PacketNumber,
        largest_acked: u64,
        path: PathIdentity,
    ) -> u64 {
        if self.sent_path(packet) != Some(path) {
            return 0;
        }
        self.count_later_sent_matching(packet, largest_acked, Some(path))
    }

    fn count_later_sent_matching(
        &self,
        packet: PacketNumber,
        largest_acked: u64,
        path: Option<PathIdentity>,
    ) -> u64 {
        let index = packet.space as usize;
        if self.retired
            || packet.value < self.floor[index]
            || largest_acked > MAX_PACKET_NUMBER
            || largest_acked <= packet.value
            || !self.records.iter().flatten().any(|record| {
                record.packet == packet
                    && matches!(
                        record.state,
                        PacketState::Sent | PacketState::Lost | PacketState::Acknowledged
                    )
            })
        {
            return 0;
        }
        self.records
            .iter()
            .flatten()
            .filter(|record| {
                record.packet.space == packet.space
                    && path.is_none_or(|p| record.path == Some(p))
                    && record.packet.value > packet.value
                    && record.packet.value <= largest_acked
                    && matches!(
                        record.state,
                        PacketState::Sent | PacketState::Lost | PacketState::Acknowledged
                    )
            })
            .count() as u64
    }

    /// Reject only the early-data epoch after authenticated TLS rejection.
    /// This is neither ACK nor network loss: retained application intent must
    /// be replayed under newly authenticated limits by its separate owner.
    /// Outstanding early adapter reservations fail atomically. Packet numbers
    /// remain burned; one-RTT records in the shared space are never discarded.
    /// Cancelled history rejects ACKs for retained rejected early packets.
    pub fn reject_zero_rtt(&mut self) -> Result<u64, AccountingError> {
        self.ensure_active()?;
        if self
            .records
            .iter()
            .flatten()
            .any(|r| r.kind == PacketKind::ZeroRtt && r.state == PacketState::Reserved)
        {
            return Err(AccountingError::OutstandingPackets);
        }
        let removed: u64 = self
            .records
            .iter()
            .flatten()
            .filter(|r| {
                r.kind == PacketKind::ZeroRtt && r.state == PacketState::Sent && r.in_flight
            })
            .map(|r| r.bytes)
            .sum();
        for record in self.records.iter_mut().flatten() {
            if record.kind == PacketKind::ZeroRtt {
                record.state = PacketState::Cancelled;
            }
        }
        self.bytes_in_flight -= removed;
        Ok(removed)
    }

    /// Drop all history for discarded packet-space keys and return the flight
    /// bytes removed. This is not a congestion-loss event. Pending Reserved
    /// submissions make the operation fail atomically: resolve adapter ownership
    /// first. Other spaces and their reservations remain untouched.
    ///
    /// The allocator is retained. If the connection later uses this space again
    /// (for example after Retry), its next PN is strictly after every allocation
    /// before this discard. Old ACKs become ignored history below the new floor.
    pub fn discard_space(&mut self, space: PacketNumberSpace) -> Result<u64, AccountingError> {
        self.ensure_active()?;
        if self
            .records
            .iter()
            .flatten()
            .any(|record| record.packet.space == space && record.state == PacketState::Reserved)
        {
            return Err(AccountingError::OutstandingPackets);
        }
        let removed: u64 = self
            .records
            .iter()
            .flatten()
            .filter(|record| {
                record.packet.space == space
                    && record.state == PacketState::Sent
                    && record.in_flight
            })
            .map(|record| record.bytes)
            .sum();
        // A subset of the invariant-tracked bytes_in_flight cannot overflow
        // the sum or underflow this subtraction. Lost bytes were removed before.
        for entry in &mut self.records {
            if let Some(record) = *entry
                && record.packet.space == space
            {
                remember_retired_sent_time(&mut self.retired_sent_upper_bound, record);
                *entry = None;
            }
        }
        self.bytes_in_flight -= removed;
        self.floor[space as usize] = self.allocator.next[space as usize];
        self.forget_ack_history_before(space, self.floor[space as usize]);
        Ok(removed)
    }

    /// Explicitly reclaim terminal records below `exclusive`. No outstanding
    /// send or reservation may be forgotten. Lost packet data, if still needed
    /// for retransmission, must remain in a separate stream-data owner.
    pub fn forget_before(
        &mut self,
        space: PacketNumberSpace,
        exclusive: u64,
    ) -> Result<(), AccountingError> {
        self.ensure_active()?;
        let index = space as usize;
        if exclusive < self.floor[index] || exclusive > self.allocator.next[index] {
            return Err(AccountingError::InvalidAckRange);
        }
        for record in self.records.iter().flatten() {
            if record.packet.space == space
                && record.packet.value < exclusive
                && matches!(record.state, PacketState::Reserved | PacketState::Sent)
            {
                return Err(AccountingError::OutstandingPackets);
            }
        }
        for entry in &mut self.records {
            if let Some(record) = *entry
                && record.packet.space == space
                && record.packet.value < exclusive
            {
                remember_retired_sent_time(&mut self.retired_sent_upper_bound, record);
                *entry = None;
            }
        }
        self.floor[index] = exclusive;
        self.forget_ack_history_before(space, exclusive);
        Ok(())
    }

    /// Reclaim the locally known, contiguous completed prefix of one PN space
    /// and return its new exclusive floor. No peer-provided number controls this
    /// operation, and it never resets or rewinds the packet-number allocator.
    ///
    /// Acknowledged, Lost and Cancelled records can be removed. An accepted
    /// Sent record with `in_flight == false` can also be removed: the caller's
    /// classification must mean ACK-only/non-retransmittable contents, with no
    /// remaining packet-level delivery obligation. Any stream retransmission
    /// data for a Lost packet remains the separate stream owner's responsibility.
    ///
    /// Stop at Reserved or in-flight Sent records, even if later records are
    /// complete. Missing local history also stops the scan conservatively.
    /// Scanning and removal are bounded by this ledger's capacity; no work is
    /// proportional to an arbitrary numeric packet-number gap. Retirement is
    /// rejected before any mutation. Old ACK prefixes remain harmlessly ignored.
    pub fn reclaim_completed_prefix(
        &mut self,
        space: PacketNumberSpace,
    ) -> Result<u64, AccountingError> {
        self.ensure_active()?;
        let mut exclusive = self.floor[space as usize];
        for _ in 0..CAPACITY.saturating_mul(2) {
            if let Some((_, range)) = self.ack_history.iter().flatten().find(|(other, range)| {
                *other == space && range.start <= exclusive && exclusive <= range.end
            }) {
                exclusive = range.end + 1;
                continue;
            }
            let Some(record) =
                self.records.iter().flatten().find(|record| {
                    record.packet.space == space && record.packet.value == exclusive
                })
            else {
                break;
            };
            if record.state == PacketState::Reserved
                || (record.state == PacketState::Sent && record.in_flight)
            {
                break;
            }
            // Every matching record was allocated at <= MAX_PACKET_NUMBER;
            // one past that maximum is an in-range u64 exhaustion sentinel.
            exclusive += 1;
        }
        for entry in &mut self.records {
            if let Some(record) = *entry
                && record.packet.space == space
                && record.packet.value < exclusive
            {
                remember_retired_sent_time(&mut self.retired_sent_upper_bound, record);
                *entry = None;
            }
        }
        self.floor[space as usize] = exclusive;
        self.forget_ack_history_before(space, exclusive);
        Ok(exclusive)
    }

    pub fn bytes_in_flight(&self) -> u64 {
        self.bytes_in_flight
    }
    /// Count only outstanding accepted packets proven to belong to this path.
    /// Reservations and legacy/unavailable path metadata are excluded. Enable
    /// path-aware accounting before sending; do not relabel older unknown sends.
    pub fn bytes_in_flight_on_path(&self, path: PathIdentity) -> u64 {
        self.outstanding_sent()
            .filter(|p| p.path == Some(path) && p.in_flight)
            .map(|p| p.bytes)
            .sum()
    }
    pub fn sent_path(&self, packet: PacketNumber) -> Option<PathIdentity> {
        self.sent_packet(packet).and_then(|p| p.path)
    }
    pub fn reserved_in_flight(&self) -> u64 {
        self.reserved_in_flight
    }
    pub fn retained_records(&self) -> usize {
        self.records.iter().flatten().count()
    }
    pub fn next_packet_number(&self, space: PacketNumberSpace) -> Option<u64> {
        self.allocator.next(space)
    }

    /// Congestion-only evidence, never an RTT sample or acceptance proof.
    /// Retained records return the exact timestamp. Below the history floor,
    /// return the maximum accepted send time removed from that PN space. This
    /// can conservatively cause an extra reduction for an older retired packet,
    /// but cannot hide a retired send that was genuinely after recovery began.
    /// This aggregate is per PN space, not per path. It cannot establish path
    /// attribution after reclamation; do not apply it to a new path by default.
    pub fn congestion_sent_at_upper_bound(&self, packet: PacketNumber) -> Option<u64> {
        if self.retired {
            return None;
        }
        self.sent_at(packet).or_else(|| {
            (packet.value < self.floor[packet.space as usize])
                .then_some(self.retired_sent_upper_bound[packet.space as usize])
                .flatten()
        })
    }

    pub fn sent_at(&self, packet: PacketNumber) -> Option<u64> {
        self.records
            .iter()
            .flatten()
            .find(|record| record.packet == packet)
            .and_then(|record| record.sent_at)
    }

    /// Reject all subsequent input and completions for this connection.
    pub fn retire(&mut self) {
        self.retired = true;
    }

    fn ensure_active(&self) -> Result<(), AccountingError> {
        if self.retired {
            Err(AccountingError::Retired)
        } else {
            Ok(())
        }
    }

    fn reservation(&self, reservation: SendReservation) -> Result<&SentRecord, AccountingError> {
        self.ensure_active()?;
        if reservation.connection_generation != self.connection_generation {
            return Err(AccountingError::InvalidReservation);
        }
        let record = self
            .records
            .get(reservation.slot)
            .and_then(Option::as_ref)
            .ok_or(AccountingError::InvalidReservation)?;
        if record.packet != reservation.packet {
            return Err(AccountingError::InvalidReservation);
        }
        Ok(record)
    }
}

fn contains(range: AckRange, number: u64) -> bool {
    range.start <= number && number <= range.end
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathReservation {
    path: u64,
    generation: u64,
    slot: usize,
    serial: u64,
    bytes: u64,
}

impl PathReservation {
    pub const fn bytes(self) -> u64 {
        self.bytes
    }
}

/// Per-path anti-amplification accounting, including outstanding reservations.
///
/// One owner supplies accepted *UDP datagram* bytes, including coalesced packets
/// and padding, rather than counting individual packets again. Credit input is
/// received datagram bytes attributed to this path under RFC 9000 section 8.1.
/// A caller issues unique `(path, generation)` pairs and does not reconstruct a
/// budget with an old pair. Migration creates a new budget, not a connection.
pub struct PathBudget<const CAPACITY: usize> {
    path: u64,
    generation: u64,
    received: u64,
    accepted: u64,
    reserved: u64,
    validated: bool,
    next_serial: Option<u64>,
    reservations: [Option<PathReservation>; CAPACITY],
    retired: bool,
}

impl<const CAPACITY: usize> PathBudget<CAPACITY> {
    pub const fn new(path: u64, generation: u64) -> Self {
        Self {
            path,
            generation,
            received: 0,
            accepted: 0,
            reserved: 0,
            validated: false,
            next_serial: Some(0),
            reservations: [None; CAPACITY],
            retired: false,
        }
    }

    pub fn record_received(&mut self, bytes: u64) -> Result<(), AccountingError> {
        self.ensure_active()?;
        self.received = self
            .received
            .checked_add(bytes)
            .ok_or(AccountingError::Overflow)?;
        Ok(())
    }

    /// Called only after the path owner establishes address validation by the
    /// protocol, never merely because a source address was observed.
    pub fn mark_validated(&mut self) -> Result<(), AccountingError> {
        self.ensure_active()?;
        self.validated = true;
        Ok(())
    }

    pub fn reserve(&mut self, bytes: u64) -> Result<PathReservation, AccountingError> {
        self.ensure_active()?;
        let total = self
            .accepted
            .checked_add(self.reserved)
            .and_then(|sum| sum.checked_add(bytes))
            .ok_or(AccountingError::Overflow)?;
        if !self.validated && total > self.received.saturating_mul(3) {
            return Err(AccountingError::AmplificationLimited);
        }
        let slot = self
            .reservations
            .iter()
            .position(Option::is_none)
            .ok_or(AccountingError::Full)?;
        let serial = self
            .next_serial
            .ok_or(AccountingError::ReservationIdExhausted)?;
        let reservation = PathReservation {
            path: self.path,
            generation: self.generation,
            slot,
            serial,
            bytes,
        };
        self.next_serial = serial.checked_add(1);
        self.reserved += bytes; // Checked with accepted above.
        self.reservations[slot] = Some(reservation);
        Ok(reservation)
    }

    /// A failure before adapter acceptance refunds only this pending amount.
    pub fn cancel(&mut self, reservation: PathReservation) -> Result<(), AccountingError> {
        self.check_reservation(reservation)?;
        self.reserved -= reservation.bytes;
        self.reservations[reservation.slot] = None;
        Ok(())
    }

    /// Accounting remains charged after adapter acceptance, regardless of
    /// subsequent network loss or cancellation of an application future.
    pub fn adapter_accepted(
        &mut self,
        reservation: PathReservation,
    ) -> Result<(), AccountingError> {
        self.check_reservation(reservation)?;
        self.reserved -= reservation.bytes;
        self.accepted += reservation.bytes; // Checked when reserved.
        self.reservations[reservation.slot] = None;
        Ok(())
    }

    pub fn received_bytes(&self) -> u64 {
        self.received
    }
    pub fn accepted_bytes(&self) -> u64 {
        self.accepted
    }
    pub fn reserved_bytes(&self) -> u64 {
        self.reserved
    }
    pub fn is_validated(&self) -> bool {
        self.validated
    }

    pub fn available_bytes(&self) -> u64 {
        let limit = if self.validated {
            u64::MAX
        } else {
            self.received.saturating_mul(3)
        };
        limit - self.accepted - self.reserved
    }

    pub fn retire(&mut self) {
        self.retired = true;
    }

    fn ensure_active(&self) -> Result<(), AccountingError> {
        if self.retired {
            Err(AccountingError::Retired)
        } else {
            Ok(())
        }
    }

    fn check_reservation(&self, reservation: PathReservation) -> Result<(), AccountingError> {
        self.ensure_active()?;
        if reservation.path != self.path
            || reservation.generation != self.generation
            || self.reservations.get(reservation.slot).copied().flatten() != Some(reservation)
        {
            return Err(AccountingError::InvalidReservation);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP: PacketNumberSpace = PacketNumberSpace::ApplicationData;

    #[test]
    fn compact_ack_history_preserves_exact_validation_for_all_small_histories() {
        // Exhaustive five-packet histories: accepted ACK-only, accepted data,
        // cancelled, or still reserved. Compare every bounded wire ACK interval.
        for pattern in 0..1024u32 {
            let mut original = SentLedger::<5>::new(1);
            let mut compact = SentLedger::<5>::new(1);
            for index in 0..5 {
                let state = (pattern >> (index * 2)) & 3;
                for ledger in [&mut original, &mut compact] {
                    let r = ledger.reserve(PacketKind::OneRtt, 10, state == 1).unwrap();
                    match state {
                        0 | 1 => ledger.adapter_accepted(r, index as u64).unwrap(),
                        2 => ledger.cancel(r).unwrap(),
                        _ => {}
                    }
                }
            }
            compact.compact_ack_history().unwrap();
            assert_eq!(original.bytes_in_flight(), compact.bytes_in_flight());
            assert_eq!(original.reserved_in_flight(), compact.reserved_in_flight());
            for start in 0..7 {
                for end in start..7 {
                    let range = [AckRange { start, end }];
                    assert_eq!(
                        original.validate_ack(APP, &range),
                        compact.validate_ack(APP, &range),
                        "pattern={pattern} ACK={start}..={end}"
                    );
                }
            }
        }
    }

    #[test]
    fn compact_ack_history_does_not_pin_an_outstanding_packet_or_invent_receipts() {
        let mut ledger = SentLedger::<4>::new(1);
        let outstanding = ledger.reserve(PacketKind::OneRtt, 50, true).unwrap();
        ledger.adapter_accepted(outstanding, 1).unwrap();
        for pn in 1..=256 {
            if ledger.remaining_capacity() == 0 {
                ledger.compact_ack_history().unwrap();
            }
            let ack = ledger.reserve(PacketKind::OneRtt, 10, false).unwrap();
            assert_eq!(ack.packet().value, pn);
            ledger.adapter_accepted(ack, pn + 1).unwrap();
            assert_eq!(ledger.reclaim_completed_prefix(APP).unwrap(), 0);
        }
        ledger.compact_ack_history().unwrap();
        assert_eq!(ledger.ack_history.iter().flatten().count(), 1);
        assert_eq!(ledger.bytes_in_flight(), 50);
        let historical = ledger
            .acknowledge(APP, &[AckRange { start: 1, end: 256 }])
            .unwrap();
        assert_eq!(historical.newly_acknowledged, 0);
        assert_eq!(historical.bytes_removed_from_flight, 0);
        assert!(
            ledger
                .sent_at(PacketNumber {
                    space: APP,
                    value: 200
                })
                .is_none()
        );
        assert_eq!(
            ledger
                .acknowledge(APP, &[AckRange { start: 0, end: 256 }])
                .unwrap()
                .bytes_removed_from_flight,
            50
        );
        assert_eq!(ledger.reclaim_completed_prefix(APP).unwrap(), 257);
        assert!(ledger.ack_history.iter().all(Option::is_none));
        assert!(
            ledger
                .validate_ack(
                    APP,
                    &[AckRange {
                        start: 257,
                        end: 257
                    }]
                )
                .is_err()
        );
    }

    #[test]
    fn compact_ack_history_is_space_local_and_discarded_only_at_retirement() {
        let mut ledger = SentLedger::<4>::new(1);
        let sent = ledger.reserve(PacketKind::OneRtt, 10, false).unwrap();
        ledger.adapter_accepted(sent, 3).unwrap();
        ledger.compact_ack_history().unwrap();
        let range = [AckRange { start: 0, end: 0 }];
        assert!(ledger.validate_ack(APP, &range).is_ok());
        assert_eq!(
            ledger.validate_ack(PacketNumberSpace::Initial, &range),
            Err(AccountingError::UnsentPacket)
        );
        assert_eq!(ledger.discard_space(APP).unwrap(), 0);
        assert!(ledger.ack_history.iter().all(Option::is_none));
        assert!(ledger.validate_ack(APP, &range).is_ok()); // old prefix, no grant
        assert_eq!(
            ledger.acknowledge(APP, &range).unwrap().newly_acknowledged,
            0
        );
        ledger.retire();
        assert!(matches!(
            ledger.compact_ack_history(),
            Err(AccountingError::Retired)
        ));
    }

    fn ack<const N: usize>(
        ledger: &mut SentLedger<N>,
        packet: PacketNumber,
    ) -> Result<AckSummary, AccountingError> {
        ledger.acknowledge(
            packet.space,
            &[AckRange {
                start: packet.value,
                end: packet.value,
            }],
        )
    }

    #[test]
    fn packet_threshold_counts_exact_original_path_and_generation() {
        let old = PathIdentity {
            connection_generation: 9,
            slot: 0,
            path_generation: 1,
        };
        let current = PathIdentity {
            path_generation: 2,
            ..old
        };
        let mut ledger = SentLedger::<8>::new(9);
        let candidate = ledger.reserve(PacketKind::OneRtt, 100, true).unwrap();
        ledger
            .adapter_accepted_on_path(candidate, 0, Codepoint::NotEct, old)
            .unwrap();
        let mut largest = 0;
        for i in 1..=3 {
            let sent = ledger.reserve(PacketKind::OneRtt, 100, true).unwrap();
            ledger
                .adapter_accepted_on_path(sent, i, Codepoint::NotEct, current)
                .unwrap();
            largest = sent.packet().value;
        }
        assert_eq!(ledger.count_later_sent(candidate.packet(), largest), 3);
        assert_eq!(
            ledger.count_later_sent_on_path(candidate.packet(), largest, old),
            0
        );
        assert_eq!(
            ledger.count_later_sent_on_path(candidate.packet(), largest, current),
            0
        );
        let same = ledger.reserve(PacketKind::OneRtt, 100, true).unwrap();
        ledger
            .adapter_accepted_on_path(same, 4, Codepoint::NotEct, old)
            .unwrap();
        assert_eq!(
            ledger.count_later_sent_on_path(candidate.packet(), same.packet().value, old),
            1
        );
        ledger.declare_lost(same.packet()).unwrap();
        ack(&mut ledger, same.packet()).unwrap();
        assert_eq!(
            ledger.count_later_sent_on_path(candidate.packet(), same.packet().value, old),
            1
        );
        assert_eq!(ledger.sent_path(candidate.packet()), Some(old));
    }

    #[test]
    fn original_path_survives_loss_and_late_ack_without_affecting_new_path_flight() {
        let old = PathIdentity {
            connection_generation: 9,
            slot: 1,
            path_generation: 1,
        };
        let new = PathIdentity {
            path_generation: 2,
            ..old
        };
        let mut ledger = SentLedger::<8>::new(9);
        let a = ledger.reserve(PacketKind::OneRtt, 100, true).unwrap();
        let b = ledger.reserve(PacketKind::OneRtt, 200, true).unwrap();
        ledger
            .adapter_accepted_on_path(a, 10, Codepoint::Ect0, old)
            .unwrap();
        ledger
            .adapter_accepted_on_path(b, 20, Codepoint::NotEct, new)
            .unwrap();
        assert_eq!(ledger.bytes_in_flight_on_path(old), 100);
        assert_eq!(ledger.bytes_in_flight_on_path(new), 200);
        ledger.declare_lost(a.packet()).unwrap();
        assert_eq!(ledger.bytes_in_flight_on_path(old), 0);
        assert_eq!(ledger.bytes_in_flight_on_path(new), 200);
        let lost = ledger
            .unacknowledged_sent()
            .find(|p| p.packet == a.packet())
            .unwrap();
        assert_eq!(lost.path, Some(old));
        assert!(!lost.in_flight);
        let summary = ledger
            .acknowledge(
                APP,
                &[AckRange {
                    start: a.packet().value,
                    end: b.packet().value,
                }],
            )
            .unwrap();
        assert_eq!(summary.previously_lost, 1);
        assert_eq!(summary.bytes_removed_from_flight, 200);
        assert_eq!(ledger.sent_path(a.packet()), Some(old));
        assert_eq!(ledger.sent_path(b.packet()), Some(new));
        assert_eq!(ledger.bytes_in_flight_on_path(new), 0);
        assert_eq!(ledger.sent_packet(a.packet()).unwrap().ecn, Codepoint::Ect0);
    }

    #[test]
    fn stale_path_generation_connection_and_legacy_absence_never_gain_attribution() {
        let path = PathIdentity {
            connection_generation: 9,
            slot: 0,
            path_generation: 1,
        };
        let mut ledger = SentLedger::<4>::new(9);
        let pending = ledger.reserve(PacketKind::OneRtt, 100, true).unwrap();
        assert_eq!(
            ledger.adapter_accepted_on_path(
                pending,
                1,
                Codepoint::Ect0,
                PathIdentity {
                    connection_generation: 8,
                    ..path
                }
            ),
            Err(AccountingError::InvalidReservation)
        );
        assert_eq!(ledger.bytes_in_flight(), 0);
        assert_eq!(ledger.reserved_in_flight(), 100);
        assert_eq!(ledger.sent_path(pending.packet()), None);
        ledger
            .adapter_accepted_ecn(pending, 2, Codepoint::Ect0)
            .unwrap();
        assert_eq!(ledger.sent_packet(pending.packet()).unwrap().path, None);
        assert_eq!(ledger.bytes_in_flight_on_path(path), 0);
        assert_eq!(
            ledger.adapter_accepted_on_path(pending, 3, Codepoint::Ect0, path),
            Err(AccountingError::InvalidState)
        );
        assert_eq!(ledger.sent_path(pending.packet()), None);
    }

    #[test]
    fn reclaimed_ack_only_history_has_no_invented_active_path() {
        let old = PathIdentity {
            connection_generation: 9,
            slot: 0,
            path_generation: 1,
        };
        let mut ledger = SentLedger::<4>::new(9);
        let packet = ledger
            .reserve_classified(PacketKind::OneRtt, 30, false, false)
            .unwrap();
        ledger
            .adapter_accepted_on_path(packet, 5, Codepoint::NotEct, old)
            .unwrap();
        assert_eq!(ledger.sent_path(packet.packet()), Some(old));
        ledger.reclaim_completed_prefix(APP).unwrap();
        assert_eq!(ledger.sent_path(packet.packet()), None);
        assert_eq!(
            ledger.congestion_sent_at_upper_bound(packet.packet()),
            Some(5)
        );
        assert_eq!(ledger.bytes_in_flight_on_path(old), 0);
        assert_eq!(
            ledger.bytes_in_flight_on_path(PathIdentity {
                path_generation: 2,
                ..old
            }),
            0
        );
    }

    #[test]
    fn early_rejection_preserves_one_rtt_path_metadata_in_shared_space() {
        let path = PathIdentity {
            connection_generation: 9,
            slot: 0,
            path_generation: 1,
        };
        let mut ledger = SentLedger::<4>::new(9);
        let early = ledger.reserve(PacketKind::ZeroRtt, 100, true).unwrap();
        let later = ledger.reserve(PacketKind::OneRtt, 200, true).unwrap();
        ledger
            .adapter_accepted_on_path(early, 1, Codepoint::NotEct, path)
            .unwrap();
        ledger
            .adapter_accepted_on_path(later, 2, Codepoint::NotEct, path)
            .unwrap();
        assert_eq!(ledger.reject_zero_rtt().unwrap(), 100);
        assert_eq!(ledger.sent_path(early.packet()), None);
        assert_eq!(ledger.sent_path(later.packet()), Some(path));
        assert_eq!(ledger.bytes_in_flight_on_path(path), 200);
        assert_eq!(ledger.next_packet_number(APP), Some(2));
    }

    #[test]
    fn congestion_bounds_are_space_local_monotone_and_not_exact_rtt_samples() {
        let mut ledger = SentLedger::<4>::new(7);
        let initial = ledger.reserve(PacketKind::Initial, 10, false).unwrap();
        ledger.adapter_accepted(initial, 100).unwrap();
        ledger
            .reclaim_completed_prefix(PacketNumberSpace::Initial)
            .unwrap();
        let cancelled = ledger.reserve(PacketKind::OneRtt, 10, false).unwrap();
        ledger.cancel(cancelled).unwrap();
        ledger
            .reclaim_completed_prefix(PacketNumberSpace::ApplicationData)
            .unwrap();
        assert_eq!(
            ledger.congestion_sent_at_upper_bound(cancelled.packet()),
            None
        );
        let lost = ledger.reserve(PacketKind::OneRtt, 10, true).unwrap();
        ledger.adapter_accepted(lost, 20).unwrap();
        ledger.declare_lost(lost.packet()).unwrap();
        ledger
            .forget_before(PacketNumberSpace::ApplicationData, lost.packet().value + 1)
            .unwrap();
        assert_eq!(ledger.sent_at(lost.packet()), None);
        assert_eq!(
            ledger.congestion_sent_at_upper_bound(lost.packet()),
            Some(20)
        );
        assert_eq!(
            ledger.congestion_sent_at_upper_bound(initial.packet()),
            Some(100)
        );
        let retained = ledger.reserve(PacketKind::OneRtt, 10, true).unwrap();
        ledger.adapter_accepted(retained, 30).unwrap();
        assert_eq!(
            ledger.congestion_sent_at_upper_bound(retained.packet()),
            Some(30)
        );
        ledger
            .discard_space(PacketNumberSpace::ApplicationData)
            .unwrap();
        assert_eq!(ledger.sent_at(retained.packet()), None);
        assert_eq!(
            ledger.congestion_sent_at_upper_bound(retained.packet()),
            Some(30)
        );
        ledger.retire();
        assert_eq!(
            ledger.congestion_sent_at_upper_bound(retained.packet()),
            None
        );
    }
    #[test]
    fn ecn_commits_only_on_acceptance_and_survives_loss_and_reclaim() {
        let mut ledger = SentLedger::<4>::new(7);
        let cancelled = ledger.reserve(PacketKind::OneRtt, 10, true).unwrap();
        ledger.cancel(cancelled).unwrap();
        assert_eq!(
            ledger.accepted_ecn_counts(PacketNumberSpace::ApplicationData),
            MarkedPackets::default()
        );
        let accepted = ledger.reserve(PacketKind::OneRtt, 20, true).unwrap();
        ledger
            .adapter_accepted_ecn(accepted, 10, Codepoint::Ect0)
            .unwrap();
        assert_eq!(
            ledger.adapter_accepted_ecn(accepted, 11, Codepoint::Ect0),
            Err(AccountingError::InvalidState)
        );
        ledger.declare_lost(accepted.packet()).unwrap();
        assert_eq!(
            ledger.unacknowledged_sent().next().unwrap().ecn,
            Codepoint::Ect0
        );
        ledger
            .acknowledge(
                PacketNumberSpace::ApplicationData,
                &[AckRange {
                    start: accepted.packet().value,
                    end: accepted.packet().value,
                }],
            )
            .unwrap();
        ledger
            .reclaim_completed_prefix(PacketNumberSpace::ApplicationData)
            .unwrap();
        assert_eq!(
            ledger.accepted_ecn_counts(PacketNumberSpace::ApplicationData),
            MarkedPackets { ect0: 1, ect1: 0 }
        );
        assert_eq!(
            ledger.accepted_ecn_counts(PacketNumberSpace::Handshake),
            MarkedPackets::default()
        );
    }
    #[test]
    fn ecn_overflow_and_ce_reject_before_flight_mutation() {
        let mut ledger = SentLedger::<2>::new(7);
        let reservation = ledger.reserve(PacketKind::OneRtt, 10, true).unwrap();
        assert_eq!(
            ledger.adapter_accepted_ecn(reservation, 1, Codepoint::Ce),
            Err(AccountingError::InvalidClassification)
        );
        ledger.ecn_accepted[2].ect0 = MAX_PACKET_NUMBER;
        assert_eq!(
            ledger.adapter_accepted_ecn(reservation, 1, Codepoint::Ect0),
            Err(AccountingError::Overflow)
        );
        assert_eq!(ledger.bytes_in_flight(), 0);
        assert_eq!(ledger.reserved_in_flight(), 10);
        ledger.adapter_accepted(reservation, 2).unwrap();
        assert_eq!(
            ledger.sent_packet(reservation.packet()).unwrap().ecn,
            Codepoint::NotEct
        );
    }
    #[test]
    fn spaces_are_separate_and_zero_one_rtt_share_a_counter() {
        let mut pns = PacketNumberAllocator::new();
        assert_eq!(pns.allocate(PacketKind::Initial).unwrap().value, 0);
        assert_eq!(pns.allocate(PacketKind::Handshake).unwrap().value, 0);
        assert_eq!(
            pns.allocate(PacketKind::ZeroRtt).unwrap(),
            PacketNumber {
                space: APP,
                value: 0
            }
        );
        assert_eq!(
            pns.allocate(PacketKind::OneRtt).unwrap(),
            PacketNumber {
                space: APP,
                value: 1
            }
        );
        assert_eq!(pns.allocate(PacketKind::Initial).unwrap().value, 1);
    }

    #[test]
    fn packet_number_exhaustion_does_not_wrap() {
        let mut pns = PacketNumberAllocator::new();
        pns.next[0] = MAX_PACKET_NUMBER;
        assert_eq!(
            pns.allocate(PacketKind::Initial).unwrap().value,
            MAX_PACKET_NUMBER
        );
        assert_eq!(
            pns.allocate(PacketKind::Initial),
            Err(AccountingError::PacketNumberExhausted)
        );
        assert_eq!(pns.next(PacketNumberSpace::Initial), None);
        assert_eq!(pns.allocate(PacketKind::Handshake).unwrap().value, 0);
    }

    #[test]
    fn cancelled_and_retry_repacketized_numbers_are_never_reused() {
        let mut ledger = SentLedger::<2>::new(1);
        let first = ledger.reserve(PacketKind::Initial, 1200, true).unwrap();
        assert_eq!(ledger.bytes_in_flight(), 0);
        assert_eq!(ledger.reserved_in_flight(), 1200);
        ledger.cancel(first).unwrap();
        assert_eq!(
            ack(&mut ledger, first.packet()),
            Err(AccountingError::UnsentPacket)
        );
        ledger.forget_before(PacketNumberSpace::Initial, 1).unwrap();
        // Retry changes crypto/header state upstream; this same connection
        // allocator is retained and a newly packetized Initial gets PN 1.
        let retry = ledger.reserve(PacketKind::Initial, 1200, true).unwrap();
        assert_eq!(retry.packet().value, 1);
        assert_eq!(
            ledger.adapter_accepted(first, 1),
            Err(AccountingError::InvalidReservation)
        );
        ledger.adapter_accepted(retry, 2).unwrap();
        assert_eq!(ledger.sent_at(retry.packet()), Some(2));
    }

    #[test]
    fn duplicate_ack_and_loss_never_double_subtract() {
        for loss_first in [true, false] {
            let mut ledger = SentLedger::<1>::new(1);
            let reservation = ledger.reserve(PacketKind::OneRtt, 1200, true).unwrap();
            ledger.adapter_accepted(reservation, 10).unwrap();
            let packet = reservation.packet();
            if loss_first {
                assert_eq!(
                    ledger.declare_lost(packet),
                    Ok(LossOutcome::NewlyLost {
                        bytes_removed_from_flight: 1200
                    })
                );
                assert_eq!(ledger.declare_lost(packet), Ok(LossOutcome::AlreadyHandled));
            }
            let summary = ack(&mut ledger, packet).unwrap();
            assert_eq!(summary.newly_acknowledged, 1);
            assert_eq!(summary.previously_lost, usize::from(loss_first));
            assert_eq!(
                summary.bytes_removed_from_flight,
                if loss_first { 0 } else { 1200 }
            );
            assert_eq!(ledger.declare_lost(packet), Ok(LossOutcome::AlreadyHandled));
            assert_eq!(ack(&mut ledger, packet), Ok(AckSummary::default()));
            assert_eq!(ledger.bytes_in_flight(), 0);
            assert_eq!(ledger.reserved_in_flight(), 0);
        }
    }

    #[test]
    fn cancellation_after_acceptance_is_rejected() {
        let mut ledger = SentLedger::<1>::new(1);
        let r = ledger.reserve(PacketKind::OneRtt, 200, true).unwrap();
        assert_eq!(
            ack(&mut ledger, r.packet()),
            Err(AccountingError::UnsentPacket)
        );
        assert_eq!(
            ledger.declare_lost(r.packet()),
            Err(AccountingError::UnsentPacket)
        );
        ledger.adapter_accepted(r, 10).unwrap();
        assert_eq!(ledger.cancel(r), Err(AccountingError::InvalidState));
        assert_eq!(
            ledger.adapter_accepted(r, 11),
            Err(AccountingError::InvalidState)
        );
        assert_eq!(ledger.bytes_in_flight(), 200);
    }

    #[test]
    fn ack_ranges_validate_atomically_without_iterating_packet_number_gaps() {
        let mut ledger = SentLedger::<3>::new(1);
        let a = ledger.reserve(PacketKind::OneRtt, 10, true).unwrap();
        let gap = ledger.reserve(PacketKind::OneRtt, 20, true).unwrap();
        let b = ledger.reserve(PacketKind::OneRtt, 30, true).unwrap();
        ledger.adapter_accepted(a, 0).unwrap();
        ledger.cancel(gap).unwrap();
        ledger.adapter_accepted(b, 0).unwrap();
        assert_eq!(
            ledger.acknowledge(APP, &[AckRange { start: 0, end: 2 }]),
            Err(AccountingError::UnsentPacket)
        );
        assert_eq!(ledger.bytes_in_flight(), 40);
        assert_eq!(
            ledger.acknowledge(
                APP,
                &[AckRange { start: 0, end: 0 }, AckRange { start: 9, end: 9 }]
            ),
            Err(AccountingError::UnsentPacket)
        );
        assert_eq!(ledger.bytes_in_flight(), 40);
        assert_eq!(
            ledger.acknowledge(
                APP,
                &[AckRange {
                    start: 0,
                    end: MAX_PACKET_NUMBER
                }]
            ),
            Err(AccountingError::UnsentPacket)
        );
        let result = ledger
            .acknowledge(
                APP,
                &[AckRange { start: 0, end: 0 }, AckRange { start: 2, end: 2 }],
            )
            .unwrap();
        assert_eq!(result.newly_acknowledged, 2);
        assert_eq!(result.bytes_removed_from_flight, 40);
    }

    #[test]
    fn malformed_ack_ranges_leave_flight_unchanged() {
        let mut ledger = SentLedger::<2>::new(1);
        let r = ledger.reserve(PacketKind::OneRtt, 10, true).unwrap();
        ledger.adapter_accepted(r, 0).unwrap();
        for range in [
            AckRange { start: 2, end: 1 },
            AckRange {
                start: 0,
                end: u64::MAX,
            },
        ] {
            assert_eq!(
                ledger.acknowledge(APP, &[range]),
                Err(AccountingError::InvalidAckRange)
            );
        }
        assert_eq!(
            ledger.acknowledge(APP, &[]),
            Err(AccountingError::InvalidAckRange)
        );
        let repeated = [AckRange { start: 0, end: 0 }; 2];
        assert_eq!(
            ledger.acknowledge(APP, &repeated),
            Err(AccountingError::InvalidAckRange)
        );
        assert_eq!(
            ledger.acknowledge(APP, &[AckRange { start: 0, end: 0 }; 3]),
            Err(AccountingError::TooManyAckRanges)
        );
        assert_eq!(ledger.bytes_in_flight(), 10);
    }

    #[test]
    fn ack_prevalidation_is_read_only_and_rejects_malformed_frames_atomically() {
        let mut ledger = SentLedger::<3>::new(1);
        let sent = ledger.reserve(PacketKind::OneRtt, 100, true).unwrap();
        ledger.adapter_accepted(sent, 10).unwrap();
        let cancelled = ledger.reserve(PacketKind::OneRtt, 200, true).unwrap();
        ledger.cancel(cancelled).unwrap();
        let _pending = ledger.reserve(PacketKind::OneRtt, 300, true).unwrap();
        let valid = [AckRange { start: 0, end: 0 }];
        for _ in 0..2 {
            assert_eq!(ledger.validate_ack(APP, &valid), Ok(()));
            assert!(ledger.is_new_ack(sent.packet()));
            assert_eq!(ledger.bytes_in_flight(), 100);
            assert_eq!(ledger.reserved_in_flight(), 300);
            assert_eq!(ledger.retained_records(), 3);
            assert_eq!(ledger.next_packet_number(APP), Some(3));
        }
        for (invalid, expected) in [
            (
                AckRange { start: 2, end: 1 },
                AccountingError::InvalidAckRange,
            ),
            (
                AckRange {
                    start: 0,
                    end: u64::MAX,
                },
                AccountingError::InvalidAckRange,
            ),
            (AckRange { start: 0, end: 1 }, AccountingError::UnsentPacket),
            (AckRange { start: 2, end: 2 }, AccountingError::UnsentPacket),
            (AckRange { start: 9, end: 9 }, AccountingError::UnsentPacket),
        ] {
            assert_eq!(ledger.validate_ack(APP, &[invalid]), Err(expected));
            assert_eq!(ledger.acknowledge(APP, &[invalid]), Err(expected));
            assert!(ledger.is_new_ack(sent.packet()));
            assert_eq!(ledger.bytes_in_flight(), 100);
            assert_eq!(ledger.reserved_in_flight(), 300);
        }
        let mixed = [valid[0], AckRange { start: 9, end: 9 }];
        assert_eq!(
            ledger.validate_ack(APP, &mixed),
            Err(AccountingError::UnsentPacket)
        );
        assert!(ledger.is_new_ack(sent.packet()));
        assert_eq!(
            ledger
                .acknowledge(APP, &valid)
                .unwrap()
                .bytes_removed_from_flight,
            100
        );
        assert!(!ledger.is_new_ack(sent.packet()));
        assert_eq!(ledger.validate_ack(APP, &valid), Ok(()));
        assert_eq!(ledger.acknowledge(APP, &valid), Ok(AckSummary::default()));
    }

    #[test]
    fn previous_ack_validation_does_not_bypass_later_retirement() {
        let mut ledger = SentLedger::<1>::new(1);
        let sent = ledger.reserve(PacketKind::OneRtt, 100, true).unwrap();
        ledger.adapter_accepted(sent, 0).unwrap();
        let range = [AckRange { start: 0, end: 0 }];
        ledger.validate_ack(APP, &range).unwrap();
        ledger.retire();
        assert_eq!(
            ledger.validate_ack(APP, &range),
            Err(AccountingError::Retired)
        );
        assert_eq!(
            ledger.acknowledge(APP, &range),
            Err(AccountingError::Retired)
        );
        assert_eq!(ledger.bytes_in_flight(), 100);
    }

    #[test]
    fn bounded_history_returns_backpressure_and_ignores_old_ack() {
        let mut ledger = SentLedger::<1>::new(1);
        let r = ledger.reserve(PacketKind::OneRtt, 10, true).unwrap();
        assert_eq!(
            ledger.forget_before(APP, 1),
            Err(AccountingError::OutstandingPackets)
        );
        ledger.adapter_accepted(r, 0).unwrap();
        assert_eq!(
            ledger.forget_before(APP, 1),
            Err(AccountingError::OutstandingPackets)
        );
        ack(&mut ledger, r.packet()).unwrap();
        assert_eq!(
            ledger.reserve(PacketKind::OneRtt, 10, true),
            Err(AccountingError::Full)
        );
        ledger.forget_before(APP, 1).unwrap();
        assert_eq!(ledger.retained_records(), 0);
        assert_eq!(ack(&mut ledger, r.packet()), Ok(AckSummary::default()));
        assert_eq!(
            ledger
                .reserve(PacketKind::OneRtt, 10, true)
                .unwrap()
                .packet()
                .value,
            1
        );
    }

    #[test]
    fn mixed_old_and_new_ack_processes_retained_suffix_atomically() {
        let mut ledger = SentLedger::<2>::new(1);
        let old = ledger.reserve(PacketKind::OneRtt, 10, true).unwrap();
        ledger.adapter_accepted(old, 0).unwrap();
        ack(&mut ledger, old.packet()).unwrap();
        ledger.forget_before(APP, 1).unwrap();
        let current = ledger.reserve(PacketKind::OneRtt, 20, true).unwrap();
        ledger.adapter_accepted(current, 1).unwrap();
        let cancelled = ledger.reserve(PacketKind::OneRtt, 30, true).unwrap();
        ledger.cancel(cancelled).unwrap();
        assert_eq!(
            ledger.acknowledge(APP, &[AckRange { start: 0, end: 2 }]),
            Err(AccountingError::UnsentPacket)
        );
        assert_eq!(ledger.bytes_in_flight(), 20);
        assert_eq!(
            ledger.acknowledge(APP, &[AckRange { start: 0, end: 3 }]),
            Err(AccountingError::UnsentPacket)
        );
        assert_eq!(ledger.bytes_in_flight(), 20);
        let summary = ledger
            .acknowledge(APP, &[AckRange { start: 0, end: 1 }])
            .unwrap();
        assert_eq!(summary.newly_acknowledged, 1);
        assert_eq!(summary.bytes_removed_from_flight, 20);
        assert_eq!(ledger.bytes_in_flight(), 0);
        assert_eq!(
            ledger.acknowledge(APP, &[AckRange { start: 0, end: 1 }]),
            Ok(AckSummary::default())
        );
    }

    #[test]
    fn automatic_reclamation_reuses_tiny_history_without_reusing_numbers() {
        let mut ledger = SentLedger::<1>::new(1);
        for number in 0..256_u64 {
            let locally_cancelled = number % 2 == 0;
            let reservation = ledger
                .reserve(PacketKind::OneRtt, 1200, locally_cancelled)
                .unwrap();
            assert_eq!(reservation.packet().value, number);
            // Even ACK-only construction is still pending until the adapter
            // reports acceptance, so no Reserved descriptor can be reclaimed.
            assert_eq!(ledger.reclaim_completed_prefix(APP), Ok(number));
            assert_eq!(ledger.retained_records(), 1);
            if locally_cancelled {
                ledger.cancel(reservation).unwrap();
            } else {
                ledger.adapter_accepted(reservation, number).unwrap();
            }
            assert_eq!(ledger.reclaim_completed_prefix(APP), Ok(number + 1));
            assert_eq!(ledger.retained_records(), 0);
            assert_eq!(ledger.bytes_in_flight(), 0);
            assert_eq!(ledger.reserved_in_flight(), 0);
            assert_eq!(ledger.next_packet_number(APP), Some(number + 1));
            assert_eq!(
                ledger.adapter_accepted(reservation, number),
                Err(AccountingError::InvalidReservation)
            );
            assert_eq!(
                ack(&mut ledger, reservation.packet()),
                Ok(AckSummary::default())
            );
        }
    }

    #[test]
    fn reclamation_never_crosses_pending_or_in_flight_data() {
        let mut ledger = SentLedger::<3>::new(1);
        let data = ledger.reserve(PacketKind::OneRtt, 1200, true).unwrap();
        let ack_only = ledger.reserve(PacketKind::OneRtt, 80, false).unwrap();
        ledger.adapter_accepted(ack_only, 0).unwrap();
        let completed = ledger.reserve(PacketKind::OneRtt, 900, true).unwrap();
        ledger.adapter_accepted(completed, 0).unwrap();
        ack(&mut ledger, completed.packet()).unwrap();

        assert_eq!(ledger.reclaim_completed_prefix(APP), Ok(0));
        assert_eq!(ledger.retained_records(), 3);
        ledger.adapter_accepted(data, 1).unwrap();
        assert_eq!(ledger.reclaim_completed_prefix(APP), Ok(0));
        assert_eq!(ledger.bytes_in_flight(), 1200);
        assert_eq!(ledger.retained_records(), 3);
        ledger.declare_lost(data.packet()).unwrap();
        assert_eq!(ledger.reclaim_completed_prefix(APP), Ok(3));
        assert_eq!(ledger.bytes_in_flight(), 0);
        assert_eq!(ledger.retained_records(), 0);
        assert_eq!(
            ledger
                .reserve(PacketKind::OneRtt, 1200, true)
                .unwrap()
                .packet()
                .value,
            3
        );
    }

    #[test]
    fn reclamation_is_space_local_and_retirement_failure_is_atomic() {
        let mut ledger = SentLedger::<2>::new(1);
        let initial = ledger.reserve(PacketKind::Initial, 1200, true).unwrap();
        let app = ledger.reserve(PacketKind::OneRtt, 80, false).unwrap();
        ledger.adapter_accepted(app, 0).unwrap();
        assert_eq!(ledger.reclaim_completed_prefix(APP), Ok(1));
        assert_eq!(
            ledger.reclaim_completed_prefix(PacketNumberSpace::Initial),
            Ok(0)
        );
        assert_eq!(ledger.retained_records(), 1);
        ledger.cancel(initial).unwrap();
        ledger.retire();
        assert_eq!(
            ledger.reclaim_completed_prefix(PacketNumberSpace::Initial),
            Err(AccountingError::Retired)
        );
        assert_eq!(ledger.retained_records(), 1);
        assert_eq!(ledger.floor[PacketNumberSpace::Initial as usize], 0);
    }

    #[test]
    fn recovery_snapshots_and_exact_new_ack_state_are_distinct() {
        let mut ledger = SentLedger::<6>::new(1);
        let sent = ledger.reserve(PacketKind::Initial, 100, true).unwrap();
        ledger.adapter_accepted(sent, 10).unwrap();
        let lost = ledger.reserve(PacketKind::OneRtt, 200, true).unwrap();
        ledger.adapter_accepted(lost, 20).unwrap();
        ledger.declare_lost(lost.packet()).unwrap();
        let ack_only = ledger.reserve(PacketKind::Initial, 40, false).unwrap();
        ledger.adapter_accepted(ack_only, 30).unwrap();
        let acked = ledger.reserve(PacketKind::Initial, 300, true).unwrap();
        ledger.adapter_accepted(acked, 40).unwrap();
        ack(&mut ledger, acked.packet()).unwrap();
        let cancelled = ledger.reserve(PacketKind::Initial, 15, true).unwrap();
        ledger.cancel(cancelled).unwrap();
        let pending = ledger.reserve(PacketKind::OneRtt, 20, true).unwrap();
        assert_eq!(ledger.outstanding_sent().count(), 2);
        assert_eq!(
            ledger
                .outstanding_sent()
                .find(|p| p.packet == sent.packet()),
            Some(SentPacket {
                packet: sent.packet(),
                bytes: 100,
                in_flight: true,
                ack_eliciting: true,
                sent_at: 10,
                ecn: Codepoint::NotEct,
                path: None,
            })
        );
        assert!(
            !ledger
                .outstanding_sent()
                .find(|p| p.packet == ack_only.packet())
                .unwrap()
                .in_flight
        );
        assert!(ledger.is_new_ack(sent.packet()));
        assert!(ledger.is_new_ack(lost.packet()));
        assert!(ledger.sent_packet(lost.packet()).unwrap().ack_eliciting);
        assert_eq!(ledger.sent_packet(lost.packet()).unwrap().sent_at, 20);
        assert!(!ledger.is_new_ack(acked.packet()));
        assert!(ledger.sent_packet(acked.packet()).is_some());
        assert!(!ledger.is_new_ack(cancelled.packet()));
        assert_eq!(ledger.sent_packet(cancelled.packet()), None);
        assert!(!ledger.is_new_ack(pending.packet()));
        assert_eq!(ledger.sent_packet(pending.packet()), None);
        ack(&mut ledger, lost.packet()).unwrap();
        assert!(!ledger.is_new_ack(lost.packet()));
        ledger.retire();
        assert_eq!(ledger.outstanding_sent().count(), 0);
        assert!(!ledger.is_new_ack(sent.packet()));
    }

    #[test]
    fn padding_only_is_in_flight_but_not_ack_eliciting() {
        let mut ledger = SentLedger::<3>::new(1);
        assert_eq!(
            ledger.reserve_classified(PacketKind::OneRtt, 100, false, true),
            Err(AccountingError::InvalidClassification)
        );
        assert_eq!(ledger.next_packet_number(APP), Some(0));
        assert_eq!(ledger.retained_records(), 0);
        let padding = ledger
            .reserve_classified(PacketKind::Initial, 1200, true, false)
            .unwrap();
        ledger.adapter_accepted(padding, 0).unwrap();
        let ack_only = ledger
            .reserve_classified(PacketKind::OneRtt, 80, false, false)
            .unwrap();
        ledger.adapter_accepted(ack_only, 1).unwrap();
        assert_eq!(ledger.bytes_in_flight(), 1200);
        assert_eq!(
            ledger
                .outstanding_sent()
                .filter(|packet| packet.ack_eliciting)
                .count(),
            0
        );
        let snapshot = ledger
            .outstanding_sent()
            .find(|p| p.packet == padding.packet())
            .unwrap();
        assert!(snapshot.in_flight);
        assert!(!snapshot.ack_eliciting);
        let crypto = ledger
            .reserve_classified(PacketKind::OneRtt, 500, true, true)
            .unwrap();
        ledger.adapter_accepted(crypto, 2).unwrap();
        assert_eq!(
            ledger
                .outstanding_sent()
                .filter(|packet| packet.ack_eliciting)
                .count(),
            1
        );
        assert_eq!(ledger.bytes_in_flight(), 1700);
    }

    #[test]
    fn late_lost_ack_keeps_rtt_classification_without_counting_flight_twice() {
        let mut ledger = SentLedger::<3>::new(1);
        let sent = ledger
            .reserve_classified(PacketKind::OneRtt, 100, true, true)
            .unwrap();
        ledger.adapter_accepted(sent, 10).unwrap();
        let lost = ledger
            .reserve_classified(PacketKind::OneRtt, 200, true, true)
            .unwrap();
        ledger.adapter_accepted(lost, 20).unwrap();
        ledger.declare_lost(lost.packet()).unwrap();
        let padding = ledger
            .reserve_classified(PacketKind::Initial, 1200, true, false)
            .unwrap();
        ledger.adapter_accepted(padding, 30).unwrap();
        assert_eq!(ledger.outstanding_sent().count(), 2);
        assert_eq!(ledger.unacknowledged_sent().count(), 3);
        let snapshot = ledger
            .unacknowledged_sent()
            .find(|packet| packet.packet == lost.packet())
            .unwrap();
        assert!(!snapshot.in_flight);
        assert!(snapshot.ack_eliciting);
        assert_eq!(snapshot.sent_at, 20);
        assert_eq!(snapshot.bytes, 200);
        assert_eq!(
            ledger
                .unacknowledged_sent()
                .filter(|p| p.in_flight)
                .map(|p| p.bytes)
                .sum::<u64>(),
            1300
        );
        let range = [AckRange { start: 1, end: 1 }];
        ledger.validate_ack(APP, &range).unwrap();
        assert!(ledger.is_new_ack(lost.packet()));
        let summary = ledger.acknowledge(APP, &range).unwrap();
        assert_eq!(summary.newly_acknowledged, 1);
        assert_eq!(summary.previously_lost, 1);
        assert_eq!(summary.bytes_removed_from_flight, 0);
        assert_eq!(ledger.bytes_in_flight(), 1300);
        assert_eq!(ledger.unacknowledged_sent().count(), 2);
        assert!(
            ledger
                .unacknowledged_sent()
                .all(|packet| packet.packet != lost.packet())
        );
        assert_eq!(ledger.acknowledge(APP, &range), Ok(AckSummary::default()));
        ledger.retire();
        assert_eq!(ledger.unacknowledged_sent().count(), 0);
    }

    #[test]
    fn later_sent_count_excludes_holes_other_spaces_and_reclaimed_history() {
        let mut ledger = SentLedger::<7>::new(1);
        let candidate = ledger.reserve(PacketKind::Initial, 100, true).unwrap();
        ledger.adapter_accepted(candidate, 0).unwrap();
        let cancelled = ledger.reserve(PacketKind::Initial, 100, true).unwrap();
        ledger.cancel(cancelled).unwrap();
        let pending = ledger.reserve(PacketKind::Initial, 100, true).unwrap();
        let later = ledger.reserve(PacketKind::Initial, 100, true).unwrap();
        ledger.adapter_accepted(later, 3).unwrap();
        let lost = ledger.reserve(PacketKind::Initial, 100, true).unwrap();
        ledger.adapter_accepted(lost, 4).unwrap();
        ledger.declare_lost(lost.packet()).unwrap();
        let acknowledged = ledger.reserve(PacketKind::Initial, 100, true).unwrap();
        ledger.adapter_accepted(acknowledged, 5).unwrap();
        ack(&mut ledger, acknowledged.packet()).unwrap();
        let other = ledger.reserve(PacketKind::Handshake, 100, true).unwrap();
        ledger.adapter_accepted(other, 6).unwrap();
        assert_eq!(ledger.count_later_sent(candidate.packet(), 5), 3);
        assert_eq!(ledger.count_later_sent(candidate.packet(), 4), 2);
        assert_eq!(ledger.count_later_sent(candidate.packet(), 2), 0);
        assert_eq!(ledger.count_later_sent(cancelled.packet(), 5), 0);
        assert_eq!(ledger.count_later_sent(pending.packet(), 5), 0);
        assert_eq!(ledger.count_later_sent(candidate.packet(), u64::MAX), 0);
        ack(&mut ledger, candidate.packet()).unwrap();
        ledger
            .reclaim_completed_prefix(PacketNumberSpace::Initial)
            .unwrap();
        assert_eq!(ledger.count_later_sent(candidate.packet(), 5), 0);
        assert_eq!(ledger.count_later_sent(later.packet(), 5), 2);
    }

    #[test]
    fn discarded_space_releases_each_flight_byte_once_and_preserves_pn() {
        let mut ledger = SentLedger::<7>::new(1);
        let sent = ledger.reserve(PacketKind::Initial, 100, true).unwrap();
        ledger.adapter_accepted(sent, 0).unwrap();
        let lost = ledger.reserve(PacketKind::Initial, 200, true).unwrap();
        ledger.adapter_accepted(lost, 1).unwrap();
        ledger.declare_lost(lost.packet()).unwrap();
        let acknowledged = ledger.reserve(PacketKind::Initial, 300, true).unwrap();
        ledger.adapter_accepted(acknowledged, 2).unwrap();
        ack(&mut ledger, acknowledged.packet()).unwrap();
        let cancelled = ledger.reserve(PacketKind::Initial, 400, true).unwrap();
        ledger.cancel(cancelled).unwrap();
        let ack_only = ledger.reserve(PacketKind::Initial, 20, false).unwrap();
        ledger.adapter_accepted(ack_only, 4).unwrap();
        let other = ledger.reserve(PacketKind::Handshake, 500, true).unwrap();
        ledger.adapter_accepted(other, 5).unwrap();
        let pending_other = ledger.reserve(PacketKind::OneRtt, 50, true).unwrap();
        assert_eq!(ledger.discard_space(PacketNumberSpace::Initial), Ok(100));
        assert_eq!(ledger.bytes_in_flight(), 500);
        assert_eq!(ledger.reserved_in_flight(), 50);
        assert_eq!(ledger.retained_records(), 2);
        assert_eq!(ledger.discard_space(PacketNumberSpace::Initial), Ok(0));
        assert_eq!(
            ledger.declare_lost(sent.packet()),
            Err(AccountingError::HistoryUnavailable)
        );
        assert_eq!(ack(&mut ledger, sent.packet()), Ok(AckSummary::default()));
        let next = ledger.reserve(PacketKind::Initial, 100, true).unwrap();
        assert_eq!(next.packet().value, 5);
        assert_eq!(
            ledger.adapter_accepted(sent, 6),
            Err(AccountingError::InvalidReservation)
        );
        ledger.cancel(pending_other).unwrap();
    }

    #[test]
    fn discarded_space_rejects_pending_ownership_without_mutation() {
        let mut ledger = SentLedger::<3>::new(1);
        let sent = ledger.reserve(PacketKind::Initial, 100, true).unwrap();
        ledger.adapter_accepted(sent, 0).unwrap();
        let pending = ledger.reserve(PacketKind::Initial, 200, true).unwrap();
        let other = ledger.reserve(PacketKind::Handshake, 300, true).unwrap();
        ledger.adapter_accepted(other, 1).unwrap();
        assert_eq!(
            ledger.discard_space(PacketNumberSpace::Initial),
            Err(AccountingError::OutstandingPackets)
        );
        assert_eq!(ledger.bytes_in_flight(), 400);
        assert_eq!(ledger.reserved_in_flight(), 200);
        assert_eq!(ledger.retained_records(), 3);
        assert_eq!(ledger.floor[0], 0);
        assert_eq!(
            ledger.next_packet_number(PacketNumberSpace::Initial),
            Some(2)
        );
        assert!(ledger.is_new_ack(sent.packet()));
        ledger.cancel(pending).unwrap();
        assert_eq!(ledger.discard_space(PacketNumberSpace::Initial), Ok(100));
        ledger.retire();
        assert_eq!(
            ledger.discard_space(PacketNumberSpace::Handshake),
            Err(AccountingError::Retired)
        );
        assert_eq!(ledger.bytes_in_flight(), 300);
    }

    #[test]
    fn discarded_space_handles_maximum_bytes_and_exhausted_number() {
        let mut ledger = SentLedger::<1>::new(1);
        ledger.allocator.next[0] = MAX_PACKET_NUMBER;
        let last = ledger.reserve(PacketKind::Initial, u64::MAX, true).unwrap();
        ledger.adapter_accepted(last, 0).unwrap();
        assert_eq!(
            ledger.discard_space(PacketNumberSpace::Initial),
            Ok(u64::MAX)
        );
        assert_eq!(ledger.bytes_in_flight(), 0);
        assert_eq!(ledger.next_packet_number(PacketNumberSpace::Initial), None);
        assert_eq!(
            ledger.reserve(PacketKind::Initial, 1, true),
            Err(AccountingError::PacketNumberExhausted)
        );
        assert_eq!(ack(&mut ledger, last.packet()), Ok(AckSummary::default()));
    }

    #[test]
    fn non_flight_packets_and_reservation_overflow_are_explicit() {
        let mut ledger = SentLedger::<3>::new(1);
        let a = ledger.reserve(PacketKind::OneRtt, u64::MAX, true).unwrap();
        assert_eq!(
            ledger.reserve(PacketKind::OneRtt, 1, true),
            Err(AccountingError::Overflow)
        );
        // Failed reservation did not consume a PN or table slot.
        let b = ledger.reserve(PacketKind::OneRtt, 5, false).unwrap();
        assert_eq!(b.packet().value, 1);
        ledger.adapter_accepted(a, 0).unwrap();
        ledger.adapter_accepted(b, 0).unwrap();
        assert_eq!(
            ack(&mut ledger, b.packet())
                .unwrap()
                .bytes_removed_from_flight,
            0
        );
        assert_eq!(ledger.bytes_in_flight(), u64::MAX);
        ack(&mut ledger, a.packet()).unwrap();
        assert_eq!(ledger.bytes_in_flight(), 0);
    }

    #[test]
    fn retired_and_different_connection_completions_are_rejected() {
        let mut ledger = SentLedger::<1>::new(1);
        let r = ledger.reserve(PacketKind::OneRtt, 10, true).unwrap();
        let mut next_connection = SentLedger::<1>::new(2);
        next_connection
            .reserve(PacketKind::OneRtt, 10, true)
            .unwrap();
        assert_eq!(
            next_connection.adapter_accepted(r, 0),
            Err(AccountingError::InvalidReservation)
        );
        ledger.retire();
        assert_eq!(ledger.adapter_accepted(r, 0), Err(AccountingError::Retired));
        assert_eq!(ledger.cancel(r), Err(AccountingError::Retired));
    }

    #[test]
    fn amplification_accounts_for_simultaneous_reservations() {
        let mut path = PathBudget::<3>::new(1, 1);
        assert_eq!(path.reserve(1), Err(AccountingError::AmplificationLimited));
        path.record_received(1200).unwrap();
        let a = path.reserve(1200).unwrap();
        let b = path.reserve(2400).unwrap();
        assert_eq!(path.available_bytes(), 0);
        assert_eq!(path.reserve(1), Err(AccountingError::AmplificationLimited));
        path.adapter_accepted(a).unwrap();
        assert_eq!(path.accepted_bytes(), 1200);
        assert_eq!(path.reserved_bytes(), 2400);
        assert_eq!(path.cancel(a), Err(AccountingError::InvalidReservation));
        path.cancel(b).unwrap();
        assert_eq!(path.available_bytes(), 2400);
        assert_eq!(path.cancel(b), Err(AccountingError::InvalidReservation));
        let c = path.reserve(2400).unwrap();
        assert_eq!(
            path.adapter_accepted(b),
            Err(AccountingError::InvalidReservation)
        );
        path.adapter_accepted(c).unwrap();
        assert_eq!(path.accepted_bytes(), 3600);
        assert_eq!(path.available_bytes(), 0);
    }

    #[test]
    fn paths_generations_and_retirement_are_isolated() {
        let mut old = PathBudget::<1>::new(1, 1);
        old.record_received(10).unwrap();
        let r = old.reserve(20).unwrap();
        for (id, generation) in [(2, 1), (1, 2)] {
            let mut other = PathBudget::<1>::new(id, generation);
            other.record_received(10).unwrap();
            other.reserve(20).unwrap();
            assert_eq!(
                other.adapter_accepted(r),
                Err(AccountingError::InvalidReservation)
            );
        }
        old.retire();
        assert_eq!(old.cancel(r), Err(AccountingError::Retired));
        assert_eq!(old.adapter_accepted(r), Err(AccountingError::Retired));
    }

    #[test]
    fn validated_path_and_saturated_amplification_limit_remain_overflow_safe() {
        let mut path = PathBudget::<2>::new(1, 1);
        path.record_received(u64::MAX).unwrap();
        assert_eq!(path.record_received(1), Err(AccountingError::Overflow));
        let r = path.reserve(u64::MAX).unwrap();
        assert_eq!(path.reserve(1), Err(AccountingError::Overflow));
        path.adapter_accepted(r).unwrap();
        assert_eq!(path.available_bytes(), 0);
        let mut validated = PathBudget::<1>::new(2, 1);
        validated.mark_validated().unwrap();
        let r = validated.reserve(100_000).unwrap();
        validated.adapter_accepted(r).unwrap();
        assert_eq!(validated.accepted_bytes(), 100_000);
    }

    #[test]
    fn path_serials_never_wrap_and_zero_capacity_is_backpressure() {
        let mut path = PathBudget::<1>::new(1, 1);
        path.mark_validated().unwrap();
        path.next_serial = Some(u64::MAX);
        let r = path.reserve(1).unwrap();
        path.cancel(r).unwrap();
        assert_eq!(
            path.reserve(1),
            Err(AccountingError::ReservationIdExhausted)
        );
        let mut empty = PathBudget::<0>::new(1, 1);
        assert_eq!(empty.reserve(0), Err(AccountingError::Full));
        let mut ledger = SentLedger::<0>::new(1);
        assert_eq!(
            ledger.reserve(PacketKind::Initial, 0, false),
            Err(AccountingError::Full)
        );
    }

    #[test]
    fn exhaustive_short_completion_sequences_preserve_flight_invariant() {
        // Every sequence of six accept/cancel/ACK/loss events, including
        // duplicates and wrong order. Invalid operations leave state intact.
        for mut sequence in 0..4096_u32 {
            let mut ledger = SentLedger::<1>::new(1);
            let r = ledger.reserve(PacketKind::OneRtt, 17, true).unwrap();
            for _ in 0..6 {
                match sequence % 4 {
                    0 => {
                        let _ = ledger.adapter_accepted(r, 0);
                    }
                    1 => {
                        let _ = ledger.cancel(r);
                    }
                    2 => {
                        let _ = ack(&mut ledger, r.packet());
                    }
                    _ => {
                        let _ = ledger.declare_lost(r.packet());
                    }
                }
                sequence /= 4;
                let record = ledger.records[0].unwrap();
                assert_eq!(
                    ledger.bytes_in_flight(),
                    if record.state == PacketState::Sent {
                        17
                    } else {
                        0
                    }
                );
                assert_eq!(
                    ledger.reserved_in_flight(),
                    if record.state == PacketState::Reserved {
                        17
                    } else {
                        0
                    }
                );
            }
        }
    }

    #[test]
    fn exhaustive_path_completion_sequences_preserve_amplification_invariant() {
        // Two live reservations, all accept/cancel orderings and repetitions.
        for mut sequence in 0..4096_u32 {
            let mut path = PathBudget::<2>::new(1, 1);
            path.record_received(10).unwrap();
            let a = path.reserve(11).unwrap();
            let b = path.reserve(19).unwrap();
            for _ in 0..6 {
                match sequence % 4 {
                    0 => {
                        let _ = path.adapter_accepted(a);
                    }
                    1 => {
                        let _ = path.cancel(a);
                    }
                    2 => {
                        let _ = path.adapter_accepted(b);
                    }
                    _ => {
                        let _ = path.cancel(b);
                    }
                }
                sequence /= 4;
                let expected_reserved: u64 =
                    path.reservations.iter().flatten().map(|r| r.bytes).sum();
                assert_eq!(path.reserved_bytes(), expected_reserved);
                assert!(path.accepted_bytes() + path.reserved_bytes() <= 30);
                assert_eq!(
                    path.available_bytes() + path.accepted_bytes() + path.reserved_bytes(),
                    30
                );
            }
        }
    }
    #[test]
    fn early_rejection_preserves_one_rtt_and_never_rewinds_shared_packet_numbers() {
        let mut ledger = SentLedger::<8>::new(900);
        let early = ledger.reserve(PacketKind::ZeroRtt, 1200, true).unwrap();
        ledger.adapter_accepted(early, 1).unwrap();
        let one = ledger.reserve(PacketKind::OneRtt, 600, true).unwrap();
        ledger.adapter_accepted(one, 2).unwrap();
        let pending = ledger.reserve(PacketKind::ZeroRtt, 1200, true).unwrap();
        assert_eq!(
            ledger.reject_zero_rtt(),
            Err(AccountingError::OutstandingPackets)
        );
        assert_eq!(ledger.bytes_in_flight(), 1800);
        ledger.cancel(pending).unwrap();
        assert_eq!(ledger.reject_zero_rtt().unwrap(), 1200);
        assert_eq!(ledger.bytes_in_flight(), 600);
        assert_eq!(ledger.reject_zero_rtt().unwrap(), 0);
        assert_eq!(
            ledger.acknowledge(
                PacketNumberSpace::ApplicationData,
                &[AckRange { start: 0, end: 0 }]
            ),
            Err(AccountingError::UnsentPacket)
        );
        assert_eq!(
            ledger
                .acknowledge(
                    PacketNumberSpace::ApplicationData,
                    &[AckRange { start: 1, end: 1 }]
                )
                .unwrap()
                .bytes_removed_from_flight,
            600
        );
        let next = ledger.reserve(PacketKind::OneRtt, 10, true).unwrap();
        assert_eq!(next.packet().value, 3);
    }
}
