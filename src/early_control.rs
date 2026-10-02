//! Bounded deferred effects from authenticated 0-RTT packets.
//!
//! `prepare` validates the entire packet and reserves all control slots before
//! any write. Keep its exclusive store borrow while preflighting STREAM state;
//! commit only after every packet effect can be admitted. The owner marks the
//! packet seen only after these commits. Capacity failure therefore means an
//! unacknowledged packet with no partial effects, not a transport violation.
//!
//! This store is not an authenticator: the caller supplies successful AEAD and
//! replay admission, and invokes `finished` only after verified peer Finished.
//! The real driver supplies separate buffer/release authorities around these
//! mutations. Allocate one store per fresh connection generation. Retained path
//! and destination CID identify the original packet, never the release path.
//!
//! CONNECTION_CLOSE is an immediate terminal exception: RFC 9000 section10.2
//! does not require waiting for Finished. `terminal_close` validates the whole
//! packet then returns the original borrowed close frame; the owner handles it
//! under a distinct authenticated early terminal authority without delivering
//! quarantined bytes. Close error codes and the complete reason are preserved.
//! This store rejects a close with TerminalClose rather than deferring it.
//!
//! Other control values are canonically re-encoded without information loss.
use crate::handshake_endpoint::NetworkReceiveContext;
use crate::packet::{self, EncryptionLevel, Frame, FrameIter, ParseLimits};
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Packet(packet::Error),
    Capacity,
    TerminalClose,
    State,
    StaleGeneration,
    StaleRelease,
    Exhausted,
}
impl From<packet::Error> for Error {
    fn from(value: packet::Error) -> Self {
        match value {
            packet::Error::LimitExceeded(_) => Self::Capacity,
            error => Self::Packet(error),
        }
    }
}

pub struct Slot<const BYTES: usize> {
    bytes: [u8; BYTES],
    len: usize,
    context: Option<NetworkReceiveContext>,
    revision: u64,
}
impl<const BYTES: usize> Slot<BYTES> {
    pub const EMPTY: Self = Self {
        bytes: [0; BYTES],
        len: 0,
        context: None,
        revision: 0,
    };
    fn clear(&mut self) {
        self.bytes.zeroize();
        self.len = 0;
        self.context = None;
        self.revision = 0;
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Holding,
    Finished,
    Retired,
}

/// An opaque, current FIFO view. Copying one does not bypass either the store's
/// current-head check or the driver's monotonic revision and generation checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlTicket {
    generation: u64,
    revision: u64,
    slot: usize,
}
impl ControlTicket {
    pub const fn generation(self) -> u64 {
        self.generation
    }
    pub const fn revision(self) -> u64 {
        self.revision
    }
}
pub struct ReleaseView<'a> {
    pub ticket: ControlTicket,
    pub frame: Frame<'a>,
    pub context: NetworkReceiveContext,
}

pub struct Store<'s, const BYTES: usize> {
    generation: u64,
    slots: &'s mut [Slot<BYTES>],
    head: usize,
    count: usize,
    next_revision: u64,
    state: State,
}
impl<'s, const BYTES: usize> Store<'s, BYTES> {
    pub fn new(generation: u64, slots: &'s mut [Slot<BYTES>]) -> Result<Self, Error> {
        if BYTES == 0 || slots.is_empty() {
            return Err(Error::Capacity);
        }
        for slot in slots.iter_mut() {
            slot.clear();
        }
        Ok(Self {
            generation,
            slots,
            head: 0,
            count: 0,
            next_revision: 0,
            state: State::Holding,
        })
    }
    pub const fn pending(&self) -> usize {
        self.count
    }
    /// No writes occur here. The returned owner prevents another admission from
    /// consuming the capacity while the caller validates other packet effects.
    pub fn prepare<'a, 'p>(
        &'a mut self,
        payload: &'p [u8],
        context: NetworkReceiveContext,
    ) -> Result<PreparedPacket<'a, 'p, 's, BYTES>, Error> {
        if self.state == State::Retired {
            return Err(Error::State);
        }
        if context.path.connection_generation != self.generation {
            return Err(Error::StaleGeneration);
        }
        if terminal_close(payload)?.is_some() {
            return Err(Error::TerminalClose);
        }
        let mut controls = 0usize;
        for frame in FrameIter::new(payload, EncryptionLevel::ZeroRtt, ParseLimits::default())? {
            let frame = frame?;
            if deferred(&frame) {
                if packet::frame_encoded_len(&frame)? > BYTES {
                    return Err(Error::Capacity);
                }
                controls = controls.checked_add(1).ok_or(Error::Exhausted)?;
            }
        }
        if controls > self.slots.len() - self.count {
            return Err(Error::Capacity);
        }
        self.next_revision
            .checked_add(controls as u64)
            .ok_or(Error::Exhausted)?;
        Ok(PreparedPacket {
            store: self,
            payload,
            context,
            controls,
        })
    }
    pub fn finished(&mut self, generation: u64) -> Result<(), Error> {
        if generation != self.generation {
            return Err(Error::StaleGeneration);
        }
        if self.state != State::Holding {
            return Err(Error::State);
        }
        self.state = State::Finished;
        Ok(())
    }
    /// Read-only FIFO views for receiving-time policy simulation. This does
    /// not grant permission to apply an effect; mutation still requires the
    /// distinct post-Finished driver release authority.
    pub fn pending_frames(
        &self,
    ) -> impl Iterator<Item = Result<(Frame<'_>, NetworkReceiveContext), Error>> + '_ {
        (0..self.count).map(move |n| {
            let slot = &self.slots[(self.head + n) % self.slots.len()];
            let mut frames = FrameIter::new(
                &slot.bytes[..slot.len],
                EncryptionLevel::ZeroRtt,
                ParseLimits::default(),
            )?;
            let frame = frames.next().ok_or(Error::State)??;
            if frames.next().is_some() || !deferred(&frame) {
                return Err(Error::State);
            }
            Ok((frame, slot.context.ok_or(Error::State)?))
        })
    }
    pub fn next_release(&self) -> Result<Option<ReleaseView<'_>>, Error> {
        if self.state != State::Finished {
            return Err(Error::State);
        }
        if self.count == 0 {
            return Ok(None);
        }
        let slot = &self.slots[self.head];
        let mut frames = FrameIter::new(
            &slot.bytes[..slot.len],
            EncryptionLevel::ZeroRtt,
            ParseLimits::default(),
        )?;
        let frame = frames.next().ok_or(Error::State)??;
        if frames.next().is_some() || !deferred(&frame) {
            return Err(Error::State);
        }
        Ok(Some(ReleaseView {
            ticket: ControlTicket {
                generation: self.generation,
                revision: slot.revision,
                slot: self.head,
            },
            frame,
            context: slot.context.ok_or(Error::State)?,
        }))
    }
    pub fn complete_release(&mut self, ticket: ControlTicket) -> Result<(), Error> {
        let current = self.next_release()?.ok_or(Error::StaleRelease)?.ticket;
        if current != ticket {
            return Err(Error::StaleRelease);
        }
        self.slots[self.head].clear();
        self.head = (self.head + 1) % self.slots.len();
        self.count -= 1;
        Ok(())
    }
    pub fn retire(&mut self) {
        for slot in self.slots.iter_mut() {
            slot.clear();
        }
        self.count = 0;
        self.state = State::Retired;
    }
}
impl<const BYTES: usize> Drop for Store<'_, BYTES> {
    fn drop(&mut self) {
        self.retire();
    }
}

pub struct PreparedPacket<'a, 'p, 's, const BYTES: usize> {
    store: &'a mut Store<'s, BYTES>,
    payload: &'p [u8],
    context: NetworkReceiveContext,
    controls: usize,
}
impl<const BYTES: usize> PreparedPacket<'_, '_, '_, BYTES> {
    pub const fn control_count(&self) -> usize {
        self.controls
    }
    /// Complete byte validation and slot reservation already occurred against
    /// this same immutable payload. Dropping an uncommitted plan writes nothing.
    pub fn commit(self) -> Result<(), Error> {
        let mut staged = 0usize;
        let result = (|| -> Result<(), Error> {
            for frame in FrameIter::new(
                self.payload,
                EncryptionLevel::ZeroRtt,
                ParseLimits::default(),
            )? {
                let frame = frame?;
                if !deferred(&frame) {
                    continue;
                }
                let index = (self.store.head + self.store.count + staged) % self.store.slots.len();
                let slot = &mut self.store.slots[index];
                // Clear even an impossible encoder failure before returning.
                let len = match packet::encode_frame(&frame, &mut slot.bytes) {
                    Ok(len) => len,
                    Err(error) => {
                        slot.clear();
                        return Err(error.into());
                    }
                };
                slot.len = len;
                slot.context = Some(self.context);
                slot.revision = self.store.next_revision + staged as u64;
                staged += 1;
            }
            if staged != self.controls {
                return Err(Error::State);
            }
            Ok(())
        })();
        if let Err(error) = result {
            for n in 0..staged {
                let index = (self.store.head + self.store.count + n) % self.store.slots.len();
                self.store.slots[index].clear();
            }
            return Err(error);
        }
        self.store.count += staged;
        self.store.next_revision += staged as u64;
        Ok(())
    }
}
/// Only call after successful AEAD in an accepted early epoch. A malformed or
/// forbidden tail prevents even an earlier close from granting terminal action.
/// The caller may discard the optional reason under its documented policy,
/// but must preserve the error code and triggering frame type.
pub fn terminal_close(payload: &[u8]) -> Result<Option<Frame<'_>>, Error> {
    let mut close = None;
    for frame in FrameIter::new(payload, EncryptionLevel::ZeroRtt, ParseLimits::default())? {
        let frame = frame?;
        if matches!(frame, Frame::ConnectionClose { .. }) && close.is_none() {
            close = Some(frame);
        }
    }
    Ok(close)
}
fn deferred(frame: &Frame<'_>) -> bool {
    !matches!(
        frame,
        Frame::Padding { .. } | Frame::Ping | Frame::Stream { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{connection_id::Cid, path::PathIdentity};
    fn context(generation: u64, slot: u8) -> NetworkReceiveContext {
        NetworkReceiveContext {
            path: PathIdentity {
                connection_generation: generation,
                slot: u16::from(slot),
                path_generation: 3,
            },
            destination: Cid::new(&[slot + 1; 8]).unwrap(),
        }
    }
    #[test]
    fn whole_packet_capacity_and_malformed_tail_leave_no_partial_admission() {
        let mut slots = [Slot::<32>::EMPTY];
        let mut store = Store::new(7, &mut slots).unwrap();
        assert!(matches!(
            store.prepare(&[0x10, 1, 0x10, 2], context(7, 0)),
            Err(Error::Capacity)
        ));
        assert_eq!(store.pending(), 0);
        assert!(matches!(
            store.prepare(&[1; 257], context(7, 0)),
            Err(Error::Capacity)
        ));
        assert!(store.prepare(&[0x10, 1, 0x11], context(7, 0)).is_err());
        assert_eq!(store.pending(), 0);
        {
            let plan = store.prepare(&[0x10, 1], context(7, 0)).unwrap();
            assert_eq!(plan.control_count(), 1);
        }
        assert_eq!(store.pending(), 0);
        assert!(matches!(store.next_release(), Err(Error::State)));
    }
    #[test]
    fn fifo_release_retains_original_context_and_rejects_stale_and_late_tickets() {
        let mut slots = [const { Slot::<64>::EMPTY }; 2];
        let mut store = Store::new(7, &mut slots).unwrap();
        store
            .prepare(&[0x10, 1], context(7, 0))
            .unwrap()
            .commit()
            .unwrap();
        store
            .prepare(&[0x14, 2], context(7, 1))
            .unwrap()
            .commit()
            .unwrap();
        {
            let mut pending = store.pending_frames();
            let (frame, original) = pending.next().unwrap().unwrap();
            assert!(matches!(frame, Frame::MaxData { maximum: 1 }));
            assert_eq!(original, context(7, 0));
            let (_, original) = pending.next().unwrap().unwrap();
            assert_eq!(original, context(7, 1));
            assert!(pending.next().is_none());
        }
        store.finished(7).unwrap();
        let first = store.next_release().unwrap().unwrap();
        assert_eq!(first.context, context(7, 0));
        assert!(matches!(first.frame, Frame::MaxData { maximum: 1 }));
        let ticket = first.ticket;
        store.complete_release(ticket).unwrap();
        assert_eq!(store.complete_release(ticket), Err(Error::StaleRelease));
        let second = store.next_release().unwrap().unwrap();
        assert_eq!(second.context, context(7, 1));
        assert!(matches!(second.frame, Frame::DataBlocked { limit: 2 }));
        let second = second.ticket;
        store.complete_release(second).unwrap();
        store
            .prepare(&[0x10, 3], context(7, 1))
            .unwrap()
            .commit()
            .unwrap();
        assert_eq!(store.next_release().unwrap().unwrap().ticket.revision(), 2);
        assert_eq!(store.complete_release(ticket), Err(Error::StaleRelease));
        store.retire();
        assert!(matches!(
            store.prepare(&[1], context(7, 0)),
            Err(Error::State)
        ));
        drop(store);
        assert!(
            slots
                .iter()
                .all(|s| s.bytes == [0; 64] && s.context.is_none())
        );
    }
    #[test]
    fn all_legal_controls_roundtrip_and_forbidden_frames_never_enter_store() {
        let token = [9; 16];
        let challenge = [8; 8];
        let frames = [
            Frame::ResetStream {
                id: 0,
                error_code: 3,
                final_size: 4,
            },
            Frame::StopSending {
                id: 0,
                error_code: 5,
            },
            Frame::MaxData { maximum: 10 },
            Frame::MaxStreamData { id: 0, maximum: 11 },
            Frame::MaxStreams {
                bidirectional: true,
                maximum: 12,
            },
            Frame::MaxStreams {
                bidirectional: false,
                maximum: 13,
            },
            Frame::DataBlocked { limit: 14 },
            Frame::StreamDataBlocked { id: 0, limit: 15 },
            Frame::StreamsBlocked {
                bidirectional: true,
                limit: 16,
            },
            Frame::StreamsBlocked {
                bidirectional: false,
                limit: 17,
            },
            Frame::NewConnectionId {
                sequence: 1,
                retire_prior_to: 0,
                id: b"some cid",
                reset_token: &token,
            },
            Frame::RetireConnectionId { sequence: 0 },
            Frame::PathChallenge { data: &challenge },
        ];
        let mut slots = [const { Slot::<128>::EMPTY }; 13];
        let mut store = Store::new(8, &mut slots).unwrap();
        let mut packet = [0; 512];
        let mut len = 0;
        for frame in &frames {
            len += packet::encode_frame(frame, &mut packet[len..]).unwrap();
        }
        store
            .prepare(&packet[..len], context(8, 0))
            .unwrap()
            .commit()
            .unwrap();
        store.finished(8).unwrap();
        for expected in frames {
            let view = store.next_release().unwrap().unwrap();
            assert_eq!(view.frame, expected);
            let ticket = view.ticket;
            store.complete_release(ticket).unwrap();
        }
        for bytes in [
            &[2, 0, 0, 0, 0][..],
            &[6, 0, 0],
            &[7, 1, 1],
            &[0x1b, 0, 0, 0, 0, 0, 0, 0, 0],
            &[0x1e],
        ] {
            assert!(store.prepare(bytes, context(8, 0)).is_err());
            assert_eq!(store.pending(), 0);
        }
    }
    #[test]
    fn terminal_close_is_immediate_preserves_fields_and_validates_the_entire_packet() {
        let mut slots = [Slot::<8>::EMPTY];
        let mut store = Store::new(9, &mut slots).unwrap();
        let mut packet = [0; 64];
        let len = packet::encode_frame(
            &Frame::ConnectionClose {
                error_code: 900,
                frame_type: None,
                reason: b"retained entire",
            },
            &mut packet,
        )
        .unwrap();
        assert!(matches!(
            store.prepare(&packet[..len], context(9, 0)),
            Err(Error::TerminalClose)
        ));
        assert_eq!(
            terminal_close(&packet[..len]).unwrap(),
            Some(Frame::ConnectionClose {
                error_code: 900,
                frame_type: None,
                reason: b"retained entire",
            })
        );
        packet[len] = 0x1e;
        assert!(terminal_close(&packet[..len + 1]).is_err());
        assert_eq!(store.pending(), 0);
        assert!(matches!(
            store.prepare(&[1], context(8, 0)),
            Err(Error::StaleGeneration)
        ));
        assert_eq!(store.finished(8), Err(Error::StaleGeneration));
        store.finished(9).unwrap();
        assert!(store.next_release().unwrap().is_none());
    }
    #[test]
    fn foreign_generation_and_exhausted_revision_cannot_reuse_a_slot() {
        let mut first_slots = [Slot::<8>::EMPTY];
        let mut first = Store::new(10, &mut first_slots).unwrap();
        first
            .prepare(&[0x10, 1], context(10, 0))
            .unwrap()
            .commit()
            .unwrap();
        first.finished(10).unwrap();
        let old = first.next_release().unwrap().unwrap().ticket;
        let mut new_slots = [Slot::<8>::EMPTY];
        let mut new = Store::new(11, &mut new_slots).unwrap();
        new.prepare(&[0x10, 1], context(11, 0))
            .unwrap()
            .commit()
            .unwrap();
        new.finished(11).unwrap();
        assert_eq!(new.complete_release(old), Err(Error::StaleRelease));
        let current = new.next_release().unwrap().unwrap().ticket;
        new.complete_release(current).unwrap();
        new.next_revision = u64::MAX;
        assert!(matches!(
            new.prepare(&[0x10, 2], context(11, 0)),
            Err(Error::Exhausted)
        ));
        assert_eq!(new.pending(), 0);
    }
}
