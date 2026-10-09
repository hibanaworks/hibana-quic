//! Fixed CRYPTO retransmission ownership. Data survives packet loss and is freed
//! only after an authenticated ACK covers a sent reference, or terminal discard.
//! Acknowledgment during an unreported adapter submission cannot recycle storage.
use crate::quic::imp::kernel::accounting::AckRange;
use crate::quic::imp::kernel::accounting::PacketNumber;
use crate::quic::imp::kernel::accounting::PacketNumberSpace;
use hibana_tls::endpoint::Level;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Full,
    TooLarge,
    Invalid,
    Exhausted,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlightId {
    slot: usize,
    generation: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reference {
    slot: usize,
    serial: u64,
}
#[derive(Clone, Copy)]
struct Flight<const B: usize> {
    generation: u64,
    active: bool,
    acknowledged: bool,
    level: Level,
    offset: u64,
    len: usize,
    control: bool,
    retransmit: bool,
    bytes: [u8; B],
}
impl<const B: usize> Flight<B> {
    const EMPTY: Self = Self {
        generation: 0,
        active: false,
        acknowledged: false,
        level: Level::Initial,
        offset: 0,
        len: 0,
        control: false,
        retransmit: false,
        bytes: [0; B],
    };
}
#[derive(Clone, Copy)]
struct RefEntry {
    serial: u64,
    flight: FlightId,
    packet: PacketNumber,
    sent_at: Option<u64>,
}
/// Caller-owned inline fixed storage. Const capacities bound all scans.
pub struct FlightStore<const F: usize, const B: usize, const R: usize> {
    flights: [Flight<B>; F],
    references: [Option<RefEntry>; R],
    serial: u64,
}
impl<const F: usize, const B: usize, const R: usize> Default for FlightStore<F, B, R> {
    fn default() -> Self {
        Self::new()
    }
}
impl<const F: usize, const B: usize, const R: usize> FlightStore<F, B, R> {
    pub const fn new() -> Self {
        Self {
            flights: [Flight::EMPTY; F],
            references: [None; R],
            serial: 0,
        }
    }
    pub fn append(&mut self, level: Level, offset: u64, bytes: &[u8]) -> Result<FlightId, Error> {
        if bytes.len() > B
            || bytes.is_empty()
            || offset
                .checked_add(bytes.len() as u64)
                .is_none_or(|end| end > crate::quic::imp::kernel::packet::MAX_VARINT)
        {
            return Err(Error::TooLarge);
        }
        let index = self
            .flights
            .iter()
            .position(|f| !f.active)
            .ok_or(Error::Full)?;
        let f = &mut self.flights[index];
        let generation = f.generation.checked_add(1).ok_or(Error::Exhausted)?;
        f.bytes[..bytes.len()].copy_from_slice(bytes);
        f.generation = generation;
        f.active = true;
        f.acknowledged = false;
        f.level = level;
        f.offset = offset;
        f.len = bytes.len();
        f.control = false;
        f.retransmit = false;
        Ok(FlightId {
            slot: index,
            generation,
        })
    }
    pub fn append_handshake_done(&mut self) -> Result<FlightId, Error> {
        self.append_handshake_done_token(None)
    }
    pub(crate) fn append_handshake_done_token(
        &mut self,
        token: Option<&[u8]>,
    ) -> Result<FlightId, Error> {
        let mut bytes = [0; B];
        if B == 0 {
            return Err(Error::TooLarge);
        }
        bytes[0] = 0x1e;
        let mut len = 1;
        if let Some(token) = token {
            len += crate::quic::imp::kernel::packet::encode_frame(
                &crate::quic::imp::kernel::packet::Frame::NewToken { token },
                &mut bytes[len..],
            )
            .map_err(|_| Error::TooLarge)?;
        }
        let id = self.append(Level::OneRtt, 0, &bytes[..len])?;
        self.flights[id.slot].control = true;
        Ok(id)
    }
    pub fn is_handshake_done(&self, id: FlightId) -> Result<bool, Error> {
        Ok(self.checked(id)?.control)
    }
    fn checked(&self, id: FlightId) -> Result<&Flight<B>, Error> {
        let f = self.flights.get(id.slot).ok_or(Error::Invalid)?;
        if !f.active || f.generation != id.generation {
            return Err(Error::Invalid);
        }
        Ok(f)
    }
    pub fn data(&self, id: FlightId) -> Result<(Level, u64, &[u8]), Error> {
        let f = self.checked(id)?;
        Ok((f.level, f.offset, &f.bytes[..f.len]))
    }
    pub fn reserve(&mut self, id: FlightId, packet: PacketNumber) -> Result<Reference, Error> {
        if self.checked(id)?.acknowledged
            || packet.space != level_space(self.checked(id)?.level)
            || packet.value > crate::quic::imp::kernel::packet::MAX_VARINT
        {
            return Err(Error::Invalid);
        }
        if self.references.iter().flatten().any(|r| r.packet == packet) {
            return Err(Error::Invalid);
        }
        let slot = self
            .references
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Full)?;
        let next = self.serial.checked_add(1).ok_or(Error::Exhausted)?;
        let serial = self.serial;
        self.serial = next;
        self.references[slot] = Some(RefEntry {
            serial,
            flight: id,
            packet,
            sent_at: None,
        });
        Ok(Reference { slot, serial })
    }
    fn reference(&self, r: Reference) -> Result<RefEntry, Error> {
        let e = self
            .references
            .get(r.slot)
            .and_then(|e| *e)
            .ok_or(Error::Invalid)?;
        if e.serial != r.serial {
            return Err(Error::Invalid);
        }
        Ok(e)
    }
    pub fn accepted(&mut self, r: Reference, now: u64) -> Result<(), Error> {
        let e = self.reference(r)?;
        if e.sent_at.is_some() {
            return Err(Error::Invalid);
        }
        self.flights[e.flight.slot].retransmit = false;
        self.references[r.slot]
            .as_mut()
            .ok_or(Error::Invalid)?
            .sent_at = Some(now);
        self.collect();
        Ok(())
    }
    pub fn cancelled(&mut self, r: Reference) -> Result<(), Error> {
        let e = self.reference(r)?;
        if e.sent_at.is_some() {
            return Err(Error::Invalid);
        }
        self.references[r.slot] = None;
        self.collect();
        Ok(())
    }
    /// The sent ledger must first validate the entire authenticated ACK. This
    /// method is a data-ownership effect, not independent ACK validation.
    pub fn acknowledge(&mut self, space: PacketNumberSpace, ranges: &[AckRange]) {
        for e in self.references.iter().flatten() {
            if e.sent_at.is_some()
                && e.packet.space == space
                && ranges
                    .iter()
                    .any(|r| r.start <= e.packet.value && e.packet.value <= r.end)
            {
                self.flights[e.flight.slot].acknowledged = true;
            }
        }
        self.collect();
    }
    fn collect(&mut self) {
        for slot in 0..F {
            if !self.flights[slot].active || !self.flights[slot].acknowledged {
                continue;
            }
            let id = FlightId {
                slot,
                generation: self.flights[slot].generation,
            };
            if self
                .references
                .iter()
                .flatten()
                .any(|r| r.flight == id && r.sent_at.is_none())
            {
                continue;
            }
            for e in &mut self.references {
                if e.is_some_and(|r| r.flight == id) {
                    *e = None
                }
            }
            let f = &mut self.flights[slot];
            f.bytes.fill(0);
            f.active = false;
            f.len = 0;
        }
    }
    /// Choose retained, unacknowledged data in this space for a PTO probe. This
    /// does not mark any packet lost, decrement flight, or reset its packet number.
    pub fn probe(&self, space: PacketNumberSpace) -> Option<FlightId> {
        self.flights
            .iter()
            .enumerate()
            .filter(|(_, f)| f.active && !f.acknowledged && level_space(f.level) == space)
            .find_map(|(slot, f)| {
                let id = FlightId {
                    slot,
                    generation: f.generation,
                };
                if self
                    .references
                    .iter()
                    .flatten()
                    .any(|r| r.flight == id && r.sent_at.is_none())
                    || !self
                        .references
                        .iter()
                        .flatten()
                        .any(|r| r.flight == id && r.sent_at.is_some())
                {
                    None
                } else {
                    Some(id)
                }
            })
    }
    pub fn latest_sent_at(&self, space: PacketNumberSpace) -> Option<u64> {
        self.references
            .iter()
            .flatten()
            .filter(|r| r.packet.space == space && !self.flights[r.flight.slot].acknowledged)
            .filter_map(|r| r.sent_at)
            .max()
    }
    pub fn sent_at(&self, packet: PacketNumber) -> Option<u64> {
        self.references
            .iter()
            .flatten()
            .find(|r| r.packet == packet)
            .and_then(|r| r.sent_at)
    }
    pub fn mark_lost(&mut self, packet: PacketNumber) {
        for e in self.references.iter().flatten() {
            if e.packet == packet {
                self.flights[e.flight.slot].retransmit = true;
            }
        }
    }
    /// Retained control bytes with no reserved or accepted packet reference.
    /// Publication/cancellation changes the actual reference table; callers do
    /// not maintain a second initial-send flag alongside that ownership.
    pub(crate) fn unsent_control(&self) -> Option<FlightId> {
        self.flights.iter().enumerate().find_map(|(slot, f)| {
            let id = FlightId {
                slot,
                generation: f.generation,
            };
            (f.active
                && f.control
                && !f.acknowledged
                && !self.references.iter().flatten().any(|r| r.flight == id))
            .then_some(id)
        })
    }
    pub fn next_lost(&self) -> Option<FlightId> {
        self.flights.iter().enumerate().find_map(|(slot, f)| {
            let id = FlightId {
                slot,
                generation: f.generation,
            };
            if f.active
                && !f.acknowledged
                && f.retransmit
                && !self
                    .references
                    .iter()
                    .flatten()
                    .any(|r| r.flight == id && r.sent_at.is_none())
            {
                Some(id)
            } else {
                None
            }
        })
    }
    /// Retry restarts packet recovery, not the TLS transcript. Detach every old
    /// accepted packet reference and requeue retained data at its original offset.
    /// Pending adapter ownership rejects the entire operation without mutation.
    /// Packet-number monotonicity remains the sent ledger's responsibility.
    pub fn requeue_space(&mut self, space: PacketNumberSpace) -> Result<(), Error> {
        if self
            .references
            .iter()
            .flatten()
            .any(|r| r.packet.space == space && r.sent_at.is_none())
        {
            return Err(Error::Invalid);
        }
        for entry in &mut self.references {
            if entry.is_some_and(|r| r.packet.space == space) {
                *entry = None;
            }
        }
        for flight in &mut self.flights {
            if flight.active && !flight.acknowledged && level_space(flight.level) == space {
                flight.retransmit = true;
            }
        }
        Ok(())
    }

    pub fn discard_space(&mut self, space: PacketNumberSpace) -> Result<(), Error> {
        if self
            .references
            .iter()
            .flatten()
            .any(|r| r.packet.space == space && r.sent_at.is_none())
        {
            return Err(Error::Invalid);
        }
        for e in &mut self.references {
            if e.is_some_and(|r| r.packet.space == space) {
                *e = None
            }
        }
        for f in &mut self.flights {
            if level_space(f.level) == space {
                f.bytes.fill(0);
                f.active = false;
                f.len = 0;
                f.retransmit = false;
            }
        }
        Ok(())
    }
    pub fn active_flights(&self) -> usize {
        self.flights.iter().filter(|f| f.active).count()
    }
    pub fn discard(&mut self) {
        for f in &mut self.flights {
            f.bytes.fill(0);
            f.active = false;
            f.len = 0;
        }
        self.references.fill(None);
    }
}
fn level_space(level: Level) -> PacketNumberSpace {
    match level {
        Level::Initial => PacketNumberSpace::Initial,
        Level::Handshake => PacketNumberSpace::Handshake,
        Level::OneRtt => PacketNumberSpace::ApplicationData,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn handshake_control_owns_token_bytes_across_loss() {
        let mut store = FlightStore::<1, 64, 4>::new();
        let mut token = [9; 32];
        let id = store.append_handshake_done_token(Some(&token)).unwrap();
        token.fill(0);
        let (_, _, data) = store.data(id).unwrap();
        assert_eq!(&data[..3], &[0x1e, 7, 32]);
        assert_eq!(&data[3..], &[9; 32]);
        assert!(store.is_handshake_done(id).unwrap());
        store.discard();
        assert!(store.data(id).is_err());
    }
    fn pn(value: u64) -> PacketNumber {
        PacketNumber {
            space: PacketNumberSpace::Initial,
            value,
        }
    }
    #[test]
    fn lost_packet_does_not_release_data_and_ack_of_retransmission_does() {
        let mut s = FlightStore::<1, 16, 4>::new();
        let id = s.append(Level::Initial, 0, b"hello").unwrap();
        let r = s.reserve(id, pn(0)).unwrap();
        s.accepted(r, 10).unwrap();
        assert_eq!(s.probe(PacketNumberSpace::Initial), Some(id));
        let r = s.reserve(id, pn(1)).unwrap();
        s.accepted(r, 100).unwrap();
        assert_eq!(s.data(id).unwrap().2, b"hello");
        s.acknowledge(PacketNumberSpace::Initial, &[AckRange { start: 1, end: 1 }]);
        assert_eq!(s.active_flights(), 0);
        assert!(s.data(id).is_err());
    }
    #[test]
    fn ack_during_pending_adapter_does_not_recycle_lease() {
        let mut s = FlightStore::<1, 16, 4>::new();
        let id = s.append(Level::Initial, 0, b"hello").unwrap();
        let r = s.reserve(id, pn(0)).unwrap();
        s.accepted(r, 10).unwrap();
        let pending = s.reserve(id, pn(1)).unwrap();
        s.acknowledge(PacketNumberSpace::Initial, &[AckRange { start: 0, end: 0 }]);
        assert_eq!(s.active_flights(), 1);
        assert_eq!(s.append(Level::Initial, 5, b"new"), Err(Error::Full));
        s.cancelled(pending).unwrap();
        assert_eq!(s.active_flights(), 0);
        let next = s.append(Level::Initial, 5, b"new").unwrap();
        assert_ne!(id, next);
        assert!(s.data(id).is_err());
    }
    #[test]
    fn initial_control_publication_uses_actual_reference_ownership() {
        let mut s = FlightStore::<2, 32, 4>::new();
        s.append(Level::Handshake, 0, b"crypto").unwrap();
        assert_eq!(s.unsent_control(), None);
        let id = s.append_handshake_done().unwrap();
        assert_eq!(s.unsent_control(), Some(id));
        let packet = PacketNumber {
            space: PacketNumberSpace::ApplicationData,
            value: 0,
        };
        let pending = s.reserve(id, packet).unwrap();
        assert_eq!(
            s.unsent_control(),
            None,
            "a pending adapter owns the reference"
        );
        s.cancelled(pending).unwrap();
        assert_eq!(s.unsent_control(), Some(id));
        let packet = PacketNumber {
            space: PacketNumberSpace::ApplicationData,
            value: 1,
        };
        let accepted = s.reserve(id, packet).unwrap();
        s.accepted(accepted, 10).unwrap();
        assert_eq!(s.unsent_control(), None);
        s.mark_lost(packet);
        assert_eq!(
            s.unsent_control(),
            None,
            "loss uses the retransmission ledger"
        );
        assert_eq!(s.next_lost(), Some(id));
        s.acknowledge(
            PacketNumberSpace::ApplicationData,
            &[AckRange { start: 1, end: 1 }],
        );
        assert_eq!(s.unsent_control(), None);
        let next = s.append_handshake_done().unwrap();
        assert_ne!(id, next);
        assert_eq!(s.unsent_control(), Some(next));
    }

    #[test]
    fn cancellation_preserves_unsent_data_and_duplicate_callbacks_fail() {
        let mut s = FlightStore::<1, 8, 1>::new();
        let id = s.append(Level::Handshake, 0, b"hs").unwrap();
        let r = s
            .reserve(
                id,
                PacketNumber {
                    space: PacketNumberSpace::Handshake,
                    value: 1,
                },
            )
            .unwrap();
        s.cancelled(r).unwrap();
        assert!(s.cancelled(r).is_err());
        assert_eq!(s.data(id).unwrap().2, b"hs");
    }
    #[test]
    fn retry_requeues_bytes_and_offsets_without_old_packet_authority() {
        let mut s = FlightStore::<3, 16, 3>::new();
        let first = s.append(Level::Initial, 0, b"first").unwrap();
        let second = s.append(Level::Initial, 5, b"second").unwrap();
        let other = s.append(Level::Handshake, 0, b"other").unwrap();
        let r = s.reserve(first, pn(0)).unwrap();
        s.accepted(r, 1).unwrap();
        let r = s.reserve(second, pn(1)).unwrap();
        s.accepted(r, 2).unwrap();
        let hp = PacketNumber {
            space: PacketNumberSpace::Handshake,
            value: 0,
        };
        let hr = s.reserve(other, hp).unwrap();
        s.accepted(hr, 3).unwrap();
        s.requeue_space(PacketNumberSpace::Initial).unwrap();
        s.requeue_space(PacketNumberSpace::Initial).unwrap();
        assert_eq!(s.data(first).unwrap(), (Level::Initial, 0, &b"first"[..]));
        assert_eq!(s.data(second).unwrap(), (Level::Initial, 5, &b"second"[..]));
        assert_eq!(s.sent_at(pn(0)), None);
        assert_eq!(s.sent_at(hp), Some(3));
        s.acknowledge(PacketNumberSpace::Initial, &[AckRange { start: 0, end: 1 }]);
        assert_eq!(s.active_flights(), 3);
        assert_eq!(s.next_lost(), Some(first));
        let r = s.reserve(first, pn(2)).unwrap();
        s.accepted(r, 4).unwrap();
        assert_eq!(s.next_lost(), Some(second));
    }
    #[test]
    fn retry_pending_adapter_rejection_is_atomic() {
        let mut s = FlightStore::<2, 16, 2>::new();
        let first = s.append(Level::Initial, 0, b"first").unwrap();
        let second = s.append(Level::Initial, 5, b"second").unwrap();
        let r = s.reserve(first, pn(0)).unwrap();
        s.accepted(r, 1).unwrap();
        let pending = s.reserve(second, pn(1)).unwrap();
        assert_eq!(
            s.requeue_space(PacketNumberSpace::Initial),
            Err(Error::Invalid)
        );
        assert_eq!(s.sent_at(pn(0)), Some(1));
        assert_eq!(s.next_lost(), None);
        s.cancelled(pending).unwrap();
        s.requeue_space(PacketNumberSpace::Initial).unwrap();
        assert_eq!(s.next_lost(), Some(first));
        assert_eq!(s.accepted(r, 3), Err(Error::Invalid));
    }
}
