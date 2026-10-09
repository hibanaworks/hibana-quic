//! Bounded policy and quarantine primitives for the 0-RTT integration.
//!
//! These helpers do not negotiate TLS, authenticate tickets/packets, allocate
//! packet numbers, acknowledge data, or establish Finished. Their caller must
//! supply those checked facts. No application bytes are exposed until finish.
//! Replay claims are burned before accepting early data and are not rolled back.
//! The actual TLS and Early roles supply those capabilities; these numerical
//! kernels do not manufacture them or interpret copied status as authority.

use hibana_tls::secret::Erase;

pub mod global;
pub mod owner;
#[cfg(test)]
mod owner_tests;

const MAX: u64 = (1 << 62) - 1;
pub use hibana_tls::early::*;

// RESET final size has the same high-water/final-size effect as an empty FIN
// at that offset, but no payload bytes or application FIN are released.
struct StreamEffect<'a> {
    id: u64,
    offset: u64,
    fin: bool,
    data: &'a [u8],
}
fn stream_effect(frame: crate::quic::kernel::packet::Frame<'_>) -> Result<Option<StreamEffect<'_>>, Error> {
    use crate::quic::kernel::packet::Frame;
    let effect = match frame {
        Frame::Stream {
            id,
            offset,
            fin,
            data,
        } => StreamEffect {
            id,
            offset,
            fin,
            data,
        },
        Frame::ResetStream { id, final_size, .. } => StreamEffect {
            id,
            offset: final_size,
            fin: true,
            data: &[],
        },
        Frame::StopSending { id, .. } | Frame::MaxStreamData { id, .. } => {
            if id & 3 != 0 {
                return Err(Error::StreamId);
            }
            StreamEffect {
                id,
                offset: 0,
                fin: false,
                data: &[],
            }
        }
        Frame::StreamDataBlocked { id, .. } => StreamEffect {
            id,
            offset: 0,
            fin: false,
            data: &[],
        },
        _ => return Ok(None),
    };
    Ok(Some(effect))
}
fn packet_admission_error(error: crate::quic::kernel::packet::Error) -> Error {
    match error {
        crate::quic::kernel::packet::Error::LimitExceeded(_) => Error::Capacity,
        error => Error::Packet(error),
    }
}
fn early_packet_frames(payload: &[u8]) -> Result<crate::quic::kernel::packet::FrameIter<'_>, Error> {
    crate::quic::kernel::packet::FrameIter::new(
        payload,
        crate::quic::kernel::packet::EncryptionLevel::ZeroRtt,
        crate::quic::kernel::packet::ParseLimits {
            max_frames: 128,
            ..crate::quic::kernel::packet::ParseLimits::default()
        },
    )
    .map_err(packet_admission_error)
}

/// Caller-owned byte/coverage storage. Its complete memory cost is bounded by
/// two BYTES arrays plus metadata; there is no allocator or self-reference.
pub struct QuarantineSlot<const BYTES: usize> {
    id: Option<u64>,
    highest: u64,
    final_size: Option<u64>,
    delivered_end: Option<u64>,
    delivered_final_size: Option<u64>,
    reset_final_size: Option<u64>,
    bytes: [u8; BYTES],
    present: [u8; BYTES],
}
impl<const BYTES: usize> QuarantineSlot<BYTES> {
    pub const EMPTY: Self = Self {
        id: None,
        highest: 0,
        final_size: None,
        delivered_end: None,
        delivered_final_size: None,
        reset_final_size: None,
        bytes: [0; BYTES],
        present: [0; BYTES],
    };
    pub(crate) fn clear(&mut self) {
        self.bytes.erase();
        self.present.fill(0);
        self.id = None;
        self.highest = 0;
        self.final_size = None;
        self.delivered_end = None;
        self.delivered_final_size = None;
        self.reset_final_size = None;
    }
}
/// A checked descriptor for one contiguous buffered range. It can be completed
/// only once and only in this connection/claim/revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReleaseTicket {
    issuer: [u8; 16],
    generation: u64,
    claim: u64,
    revision: u64,
    slot: usize,
    offset: usize,
    len: usize,
    fin: bool,
}
pub(crate) struct ReleaseView<'a> {
    pub ticket: ReleaseTicket,
    pub stream_id: u64,
    pub offset: u64,
    pub bytes: &'a [u8],
    pub fin: bool,
}
pub(crate) struct HeldBytes<'a, const BYTES: usize> {
    slots: &'a mut [QuarantineSlot<BYTES>],
    limits: RememberedLimits,
    issuer: [u8; 16],
    generation: u64,
    claim: u64,
    revision: u64,
    charged: u64,
}
impl<'a, const BYTES: usize> HeldBytes<'a, BYTES> {
    /// All remembered receive credits are backed before TLS advertises early
    /// acceptance. Consume the already-committed replay claim into this owner.
    pub(crate) fn new(
        policy: ServerPolicy,
        limits: RememberedLimits,
        claim: ReplayClaim,
        slots: &'a mut [QuarantineSlot<BYTES>],
    ) -> Result<Self, Error> {
        policy.check_capacity::<BYTES>(limits, slots.len())?;
        for slot in slots.iter_mut() {
            slot.clear();
        }
        let (issuer, generation, serial) = claim.into_parts();
        Ok(Self {
            slots,
            limits,
            issuer,
            generation,
            claim: serial,
            revision: 0,
            charged: 0,
        })
    }
    #[cfg(test)]
    pub(crate) fn charged(&self) -> u64 {
        self.charged
    }
    /// Read-only whole-packet admission check. At most 128 decoded frames are
    /// examined with bounded pairwise passes; there is no storage clone. A
    /// Capacity error means valid local resource pressure: drop without ACK or
    /// mutation. StreamId/FlowControl/FinalSize/ConflictingOverlap are protocol
    /// failures, and Packet retains malformed/forbidden-frame diagnostics.
    ///
    /// Hold all other owners unchanged between this check and the sequential
    /// STREAM/RESET_STREAM commits. Also reserve deferred control capacity before any commit.
    pub(crate) fn preflight_authenticated_packet(
        &self,
        generation: u64,
        payload: &[u8],
    ) -> Result<(), Error> {
        if generation != self.generation {
            return Err(Error::StaleGeneration);
        }
        // Validate even a malformed tail before considering any admission.
        for frame in early_packet_frames(payload)? {
            frame.map_err(packet_admission_error)?;
        }
        let mut unique_new = 0;
        let mut charged = self.charged;
        for (index, frame) in early_packet_frames(payload)?.enumerate() {
            let Some(StreamEffect {
                id,
                offset,
                fin,
                data,
            }) = stream_effect(frame.map_err(packet_admission_error)?)?
            else {
                continue;
            };
            if id > MAX || id & 1 != 0 {
                return Err(Error::StreamId);
            }
            let uni = id & 2 != 0;
            if id / 4 + 1
                > if uni {
                    self.limits.stream_limits().max_streams_uni
                } else {
                    self.limits.stream_limits().max_streams_bidi
                }
            {
                return Err(Error::FlowControl);
            }
            let end = offset
                .checked_add(data.len() as u64)
                .ok_or(Error::FlowControl)?;
            let limit = if uni {
                self.limits.stream_limits().stream_data_uni
            } else {
                self.limits.stream_limits().stream_data_bidi_remote
            };
            if end > limit || end > BYTES as u64 {
                return Err(Error::FlowControl);
            }
            let slot = self.slots.iter().find(|slot| slot.id == Some(id));
            let old_highest = slot.map_or(0, |slot| slot.highest);
            if slot.is_some_and(|slot| {
                slot.final_size
                    .is_some_and(|size| end > size || fin && end != size)
            }) || fin && end < old_highest
            {
                return Err(Error::FinalSize);
            }
            let start = usize::try_from(offset).map_err(|_| Error::FlowControl)?;
            if slot.is_some_and(|slot| {
                data.iter()
                    .enumerate()
                    .any(|(i, byte)| slot.present[start + i] == 1 && slot.bytes[start + i] != *byte)
            }) {
                return Err(Error::ConflictingOverlap);
            }
            let mut first = true;
            let mut highest = end.max(old_highest);
            for (other_index, other) in early_packet_frames(payload)?.enumerate() {
                let Some(StreamEffect {
                    id: other_id,
                    offset: other_offset,
                    fin: other_fin,
                    data: other_data,
                }) = stream_effect(other.map_err(packet_admission_error)?)?
                else {
                    continue;
                };
                if other_id != id || other_index == index {
                    continue;
                }
                let other_end = other_offset
                    .checked_add(other_data.len() as u64)
                    .ok_or(Error::FlowControl)?;
                first &= other_index > index;
                highest = highest.max(other_end);
                if fin && (other_end > end || other_fin && other_end != end)
                    || other_fin && end > other_end
                {
                    return Err(Error::FinalSize);
                }
                let overlap_start = offset.max(other_offset);
                let overlap_end = end.min(other_end);
                for byte_offset in overlap_start..overlap_end {
                    let released = slot.is_some_and(|slot| {
                        slot.reset_final_size.is_some() || slot.present[byte_offset as usize] == 2
                    });
                    if !released
                        && data[(byte_offset - offset) as usize]
                            != other_data[(byte_offset - other_offset) as usize]
                    {
                        return Err(Error::ConflictingOverlap);
                    }
                }
            }
            if first {
                unique_new += usize::from(slot.is_none());
                charged = charged
                    .checked_add(highest - old_highest)
                    .ok_or(Error::FlowControl)?;
                if charged > self.limits.max_data() {
                    return Err(Error::FlowControl);
                }
            }
        }
        if unique_new > self.slots.iter().filter(|slot| slot.id.is_none()).count() {
            return Err(Error::Capacity);
        }
        Ok(())
    }
    /// Supply only authenticated and whole-packet-validated client STREAM data.
    /// Authentication failure must never call this. Every local error is atomic.
    pub(crate) fn buffer_authenticated_stream(
        &mut self,
        generation: u64,
        stream_id: u64,
        offset: u64,
        bytes: &[u8],
        fin: bool,
    ) -> Result<(), Error> {
        if generation != self.generation {
            return Err(Error::StaleGeneration);
        }
        if stream_id > MAX || stream_id & 1 != 0 {
            return Err(Error::StreamId);
        }
        let uni = stream_id & 2 != 0;
        let count = stream_id / 4 + 1;
        if count
            > if uni {
                self.limits.stream_limits().max_streams_uni
            } else {
                self.limits.stream_limits().max_streams_bidi
            }
        {
            return Err(Error::FlowControl);
        }
        let limit = if uni {
            self.limits.stream_limits().stream_data_uni
        } else {
            self.limits.stream_limits().stream_data_bidi_remote
        };
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or(Error::FlowControl)?;
        if end > limit || end > BYTES as u64 {
            return Err(Error::FlowControl);
        }
        let index = self
            .slots
            .iter()
            .position(|s| s.id == Some(stream_id))
            .or_else(|| self.slots.iter().position(|s| s.id.is_none()))
            .ok_or(Error::Capacity)?;
        let slot = &self.slots[index];
        if slot
            .final_size
            .is_some_and(|size| end > size || fin && end != size)
            || fin && end < slot.highest
        {
            return Err(Error::FinalSize);
        }
        if slot.reset_final_size.is_some() {
            return Ok(());
        }
        let start = usize::try_from(offset).map_err(|_| Error::FlowControl)?;
        if bytes
            .iter()
            .enumerate()
            .any(|(i, b)| slot.present[start + i] == 1 && slot.bytes[start + i] != *b)
        {
            return Err(Error::ConflictingOverlap);
        }
        let charged = self
            .charged
            .checked_add(end.saturating_sub(slot.highest))
            .ok_or(Error::FlowControl)?;
        if charged > self.limits.max_data() {
            return Err(Error::FlowControl);
        }
        let slot = &mut self.slots[index];
        slot.id = Some(stream_id);
        slot.highest = slot.highest.max(end);
        for (i, b) in bytes.iter().enumerate() {
            if slot.present[start + i] != 2 {
                slot.bytes[start + i] = *b;
                slot.present[start + i] = 1;
            }
        }
        if fin {
            slot.final_size = Some(end);
        }
        self.charged = charged;
        Ok(())
    }
    /// Admit RESET_STREAM against remembered credit before marking its early
    /// packet seen. Its final size charges the same receive high-water ledger as
    /// STREAM, while all withheld bytes are wiped. The deferred control store
    /// separately retains its actual error code for the post-Finished table
    /// transition. Later valid STREAM frames cannot revive discarded data.
    pub(crate) fn buffer_authenticated_reset(
        &mut self,
        generation: u64,
        stream_id: u64,
        final_size: u64,
    ) -> Result<(), Error> {
        self.buffer_authenticated_stream(generation, stream_id, final_size, &[], true)?;
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| slot.id == Some(stream_id))
            .ok_or(Error::State)?;
        slot.reset_final_size = Some(final_size);
        slot.bytes.erase();
        slot.present.fill(2);
        Ok(())
    }
    /// Reserve remembered stream identity/credit for a deferred control before
    /// admission. Non-stream controls have no quarantine accounting effect.
    /// MAX_STREAM_DATA grants our sending credit; its numeric maximum does not
    /// consume this receive ledger. The authenticated referenced stream does.
    pub(crate) fn buffer_authenticated_control(
        &mut self,
        generation: u64,
        frame: crate::quic::kernel::packet::Frame<'_>,
    ) -> Result<(), Error> {
        if generation != self.generation {
            return Err(Error::StaleGeneration);
        }
        if matches!(frame, crate::quic::kernel::packet::Frame::Stream { .. }) {
            return Ok(());
        }
        if let crate::quic::kernel::packet::Frame::ResetStream { id, final_size, .. } = frame {
            return self.buffer_authenticated_reset(generation, id, final_size);
        }
        if let Some(StreamEffect {
            id,
            offset,
            fin,
            data,
        }) = stream_effect(frame)?
        {
            self.buffer_authenticated_stream(generation, id, offset, data, fin)?;
        }
        Ok(())
    }
    pub(crate) fn next_release(&self) -> Result<Option<ReleaseView<'_>>, Error> {
        for (index, slot) in self.slots.iter().enumerate() {
            let Some(id) = slot.id else { continue };
            if slot.reset_final_size.is_some() {
                continue;
            }
            let final_size_unreleased =
                slot.final_size.is_some() && slot.delivered_final_size != slot.final_size;
            let marker_unreleased = slot.delivered_end.is_none_or(|end| slot.highest > end);
            let range = if let Some(start) = slot.present.iter().position(|p| *p == 1) {
                let len = slot.present[start..]
                    .iter()
                    .take_while(|p| **p == 1)
                    .count();
                Some((
                    start,
                    len,
                    final_size_unreleased && slot.final_size == Some((start + len) as u64),
                ))
            } else if final_size_unreleased || marker_unreleased {
                Some((slot.highest as usize, 0, final_size_unreleased))
            } else {
                None
            };
            if let Some((offset, len, fin)) = range {
                return Ok(Some(ReleaseView {
                    ticket: ReleaseTicket {
                        issuer: self.issuer,
                        generation: self.generation,
                        claim: self.claim,
                        revision: self.revision,
                        slot: index,
                        offset,
                        len,
                        fin,
                    },
                    stream_id: id,
                    offset: offset as u64,
                    bytes: &slot.bytes[offset..offset + len],
                    fin,
                }));
            }
        }
        Ok(None)
    }
    /// Complete only after the ordinary authenticated stream table accepts the
    /// range. Backpressure leaves bytes owned here. No ACK/loss event is implied.
    pub(crate) fn complete_release(&mut self, ticket: ReleaseTicket) -> Result<(), Error> {
        let expected = self.next_release()?.ok_or(Error::StaleRelease)?.ticket;
        if expected != ticket {
            return Err(Error::StaleRelease);
        }
        let revision = self.revision.checked_add(1).ok_or(Error::Exhausted)?;
        let slot = &mut self.slots[ticket.slot];
        slot.bytes[ticket.offset..ticket.offset + ticket.len].erase();
        slot.present[ticket.offset..ticket.offset + ticket.len].fill(2);
        slot.delivered_end = Some(
            slot.delivered_end
                .unwrap_or(0)
                .max((ticket.offset + ticket.len) as u64),
        );
        if ticket.fin {
            slot.delivered_final_size = Some((ticket.offset + ticket.len) as u64);
        }
        self.revision = revision;
        Ok(())
    }
}
impl<const BYTES: usize> Drop for HeldBytes<'_, BYTES> {
    fn drop(&mut self) {
        for slot in self.slots.iter_mut() {
            slot.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Syntactically valid server parameters, including required connection IDs.
    const PARAMS: &[u8] = &[
        0, 0, 15, 0, 4, 1, 16, 5, 1, 8, 6, 1, 8, 7, 1, 8, 8, 1, 1, 9, 1, 1,
    ];
    const POLICY: ServerPolicy = ServerPolicy::BufferedReplaySafeRequests {
        max_bytes: 16,
        max_streams: 2,
    };
    fn limits() -> RememberedLimits {
        RememberedLimits::from_authenticated_server_parameters(PARAMS).unwrap()
    }
    fn claim<const N: usize>(storage: &mut ReplayStorage<N>, generation: u64) -> ReplayClaim {
        ReplayLedger::bind([1; 16], storage)
            .unwrap()
            .claim_after_authentication([1; 16], [2; 12], 1000, 10, generation)
            .unwrap()
    }
    #[test]
    fn held_byte_kernel_releases_actual_ranges_once() {
        let mut replay = ReplayStorage::<1>::new();
        let mut slots = [QuarantineSlot::<8>::EMPTY, QuarantineSlot::EMPTY];
        let mut q = HeldBytes::new(POLICY, limits(), claim(&mut replay, 7), &mut slots).unwrap();
        q.buffer_authenticated_stream(7, 0, 3, b"def", true)
            .unwrap();
        q.buffer_authenticated_stream(7, 0, 0, b"abc", false)
            .unwrap();
        q.buffer_authenticated_stream(7, 0, 0, b"abc", false)
            .unwrap();
        assert_eq!(q.charged(), 6);

        let view = q.next_release().unwrap().unwrap();
        assert_eq!(
            (view.stream_id, view.offset, view.bytes, view.fin),
            (0, 0, &b"abcdef"[..], true)
        );
        let ticket = view.ticket;
        q.complete_release(ticket).unwrap();
        assert!(q.next_release().unwrap().is_none());
        assert_eq!(q.complete_release(ticket), Err(Error::StaleRelease));
        assert_eq!(
            q.buffer_authenticated_stream(7, 0, 6, b"x", false),
            Err(Error::FinalSize)
        );
    }
    #[test]
    fn late_ranges_preserve_delivered_byte_history() {
        let mut replay = ReplayStorage::<1>::new();
        let mut slots = [QuarantineSlot::<8>::EMPTY, QuarantineSlot::EMPTY];
        let mut q = HeldBytes::new(POLICY, limits(), claim(&mut replay, 1), &mut slots).unwrap();
        q.buffer_authenticated_stream(1, 0, 0, b"abc", false)
            .unwrap();

        let first = q.next_release().unwrap().unwrap().ticket;
        q.complete_release(first).unwrap();
        q.buffer_authenticated_stream(1, 0, 0, b"abc", false)
            .unwrap();
        assert_eq!(q.charged(), 3);
        assert!(q.next_release().unwrap().is_none());
        q.buffer_authenticated_stream(1, 0, 3, b"def", true)
            .unwrap();
        let late = q.next_release().unwrap().unwrap();
        assert_eq!((late.offset, late.bytes, late.fin), (3, &b"def"[..], true));
        let second = late.ticket;
        q.complete_release(second).unwrap();
        q.buffer_authenticated_stream(1, 0, 0, b"abcdef", true)
            .unwrap();
        assert_eq!(q.charged(), 6);
        assert!(q.next_release().unwrap().is_none());
        assert_eq!(
            q.buffer_authenticated_stream(1, 0, 0, b"abcd", true),
            Err(Error::FinalSize)
        );
        assert_eq!(q.complete_release(first), Err(Error::StaleRelease));
        // Released payload is wiped; ordinary delivered-stream history handles
        // duplicate bytes while this quarantine preserves offsets/final size.
        q.buffer_authenticated_stream(1, 0, 0, b"xxxxxx", true)
            .unwrap();
        assert!(q.next_release().unwrap().is_none());
    }

    #[test]
    fn sparse_ranges_and_empty_offset_markers_survive_handoff() {
        let mut replay = ReplayStorage::<1>::new();
        let mut slots = [QuarantineSlot::<8>::EMPTY, QuarantineSlot::EMPTY];
        let mut q = HeldBytes::new(POLICY, limits(), claim(&mut replay, 1), &mut slots).unwrap();
        q.buffer_authenticated_stream(1, 0, 2, b"cd", false)
            .unwrap();
        q.buffer_authenticated_stream(1, 0, 7, b"", false).unwrap();
        q.buffer_authenticated_stream(1, 2, 0, b"", true).unwrap();

        let view = q.next_release().unwrap().unwrap();
        assert_eq!((view.offset, view.bytes, view.fin), (2, &b"cd"[..], false));
        let a = view.ticket;
        q.complete_release(a).unwrap();
        let view = q.next_release().unwrap().unwrap();
        assert_eq!((view.offset, view.bytes, view.fin), (7, &b""[..], false));
        let b = view.ticket;
        q.complete_release(b).unwrap();
        let view = q.next_release().unwrap().unwrap();
        assert_eq!(
            (view.stream_id, view.offset, view.bytes, view.fin),
            (2, 0, &b""[..], true)
        );
        let c = view.ticket;
        q.complete_release(c).unwrap();
        assert!(q.next_release().unwrap().is_none());
    }
    #[test]
    fn failed_overlap_final_size_and_flow_updates_leave_state_unchanged() {
        let mut replay = ReplayStorage::<1>::new();
        let mut slots = [QuarantineSlot::<8>::EMPTY, QuarantineSlot::EMPTY];
        let mut q = HeldBytes::new(POLICY, limits(), claim(&mut replay, 1), &mut slots).unwrap();
        q.buffer_authenticated_stream(1, 0, 0, b"abc", false)
            .unwrap();
        for (id, offset, bytes, fin, error) in [
            (0, 1, &b"xy"[..], false, Error::ConflictingOverlap),
            (0, 1, &b"b"[..], true, Error::FinalSize),
            (0, 8, &b"x"[..], false, Error::FlowControl),
            (4, 0, &b"x"[..], false, Error::FlowControl),
            (1, 0, &b"x"[..], false, Error::StreamId),
        ] {
            assert_eq!(
                q.buffer_authenticated_stream(1, id, offset, bytes, fin),
                Err(error)
            );
            assert_eq!(q.charged(), 3);
        }

        assert_eq!(q.next_release().unwrap().unwrap().bytes, b"abc");
    }
    #[test]
    fn dropping_held_bytes_wipes_without_refunding_replay() {
        let mut replay = ReplayStorage::<1>::new();
        let mut slots = [QuarantineSlot::<8>::EMPTY, QuarantineSlot::EMPTY];
        {
            let mut q =
                HeldBytes::new(POLICY, limits(), claim(&mut replay, 1), &mut slots).unwrap();
            q.buffer_authenticated_stream(1, 0, 0, b"secret", true)
                .unwrap();
        }
        assert!(
            slots
                .iter()
                .all(|s| s.bytes == [0; 8] && s.present == [0; 8])
        );
        let mut ledger = ReplayLedger::bind([1; 16], &mut replay).unwrap();
        assert!(matches!(
            ledger.claim_after_authentication([1; 16], [2; 12], 1000, 11, 2),
            Err(Error::Replay)
        ));
    }
    #[test]
    fn restarted_key_epoch_cannot_complete_old_release_even_if_caller_reuses_generation() {
        let mut first_storage = ReplayStorage::<1>::new();
        let mut second_storage = ReplayStorage::<1>::new();
        let a_claim = claim(&mut first_storage, 7);
        let b_claim = ReplayLedger::bind([9; 16], &mut second_storage)
            .unwrap()
            .claim_after_authentication([9; 16], [2; 12], 1000, 10, 7)
            .unwrap();
        let mut a_slots = [QuarantineSlot::<8>::EMPTY, QuarantineSlot::EMPTY];
        let mut b_slots = [QuarantineSlot::<8>::EMPTY, QuarantineSlot::EMPTY];
        let mut a = HeldBytes::new(POLICY, limits(), a_claim, &mut a_slots).unwrap();
        let mut b = HeldBytes::new(POLICY, limits(), b_claim, &mut b_slots).unwrap();
        a.buffer_authenticated_stream(7, 0, 0, b"a", true).unwrap();
        b.buffer_authenticated_stream(7, 0, 0, b"b", true).unwrap();

        assert_eq!(
            b.complete_release(a.next_release().unwrap().unwrap().ticket),
            Err(Error::StaleRelease)
        );
    }

    #[test]
    fn foreign_release_descriptor_and_generation_are_rejected() {
        let mut replay = ReplayStorage::<2>::new();
        let mut a_slots = [QuarantineSlot::<8>::EMPTY, QuarantineSlot::EMPTY];
        let mut b_slots = [QuarantineSlot::<8>::EMPTY, QuarantineSlot::EMPTY];
        let a_claim = claim(&mut replay, 1);
        let b_claim = ReplayLedger::bind([1; 16], &mut replay)
            .unwrap()
            .claim_after_authentication([1; 16], [3; 12], 1000, 10, 2)
            .unwrap();
        let mut a = HeldBytes::new(POLICY, limits(), a_claim, &mut a_slots).unwrap();
        let mut b = HeldBytes::new(POLICY, limits(), b_claim, &mut b_slots).unwrap();
        a.buffer_authenticated_stream(1, 0, 0, b"a", true).unwrap();
        b.buffer_authenticated_stream(2, 0, 0, b"b", true).unwrap();

        let ticket = a.next_release().unwrap().unwrap().ticket;
        assert_eq!(b.complete_release(ticket), Err(Error::StaleRelease));
        assert_eq!(
            b.buffer_authenticated_stream(1, 0, 0, b"x", false),
            Err(Error::StaleGeneration)
        );
    }
    #[test]
    fn packet_preflight_validates_cross_frame_high_water_final_size_and_overlap_atomically() {
        use crate::quic::kernel::packet::{self, Frame};
        let mut replay = ReplayStorage::<1>::new();
        let mut slots = [QuarantineSlot::<8>::EMPTY, QuarantineSlot::EMPTY];
        let mut q = HeldBytes::new(POLICY, limits(), claim(&mut replay, 7), &mut slots).unwrap();
        let cases = [
            (
                [
                    Frame::Stream {
                        id: 0,
                        offset: 0,
                        fin: false,
                        data: b"ab",
                    },
                    Frame::Stream {
                        id: 0,
                        offset: 1,
                        fin: false,
                        data: b"X",
                    },
                ],
                Err(Error::ConflictingOverlap),
            ),
            (
                [
                    Frame::Stream {
                        id: 0,
                        offset: 0,
                        fin: true,
                        data: b"ab",
                    },
                    Frame::Stream {
                        id: 0,
                        offset: 2,
                        fin: false,
                        data: b"c",
                    },
                ],
                Err(Error::FinalSize),
            ),
            (
                [
                    Frame::Stream {
                        id: 0,
                        offset: 0,
                        fin: true,
                        data: b"ab",
                    },
                    Frame::Stream {
                        id: 0,
                        offset: 0,
                        fin: true,
                        data: b"a",
                    },
                ],
                Err(Error::FinalSize),
            ),
            (
                [
                    Frame::Stream {
                        id: 0,
                        offset: 3,
                        fin: true,
                        data: b"def",
                    },
                    Frame::Stream {
                        id: 0,
                        offset: 0,
                        fin: false,
                        data: b"abc",
                    },
                ],
                Ok(()),
            ),
        ];
        for (frames, expected) in cases {
            let mut bytes = [0; 64];
            let mut n = 0;
            for frame in frames {
                n += packet::encode_frame(&frame, &mut bytes[n..]).unwrap();
            }
            assert_eq!(q.preflight_authenticated_packet(7, &bytes[..n]), expected);
            assert_eq!(q.charged(), 0);
            assert!(q.slots.iter().all(|s| s.id.is_none()));
            if expected.is_ok() {
                for frame in frames {
                    let Frame::Stream {
                        id,
                        offset,
                        fin,
                        data,
                    } = frame
                    else {
                        unreachable!()
                    };
                    q.buffer_authenticated_stream(7, id, offset, data, fin)
                        .unwrap();
                }
            }
        }
        assert_eq!(q.charged(), 6);
        let mut bytes = [0; 64];
        let n = packet::encode_frame(
            &Frame::Stream {
                id: 0,
                offset: 0,
                fin: true,
                data: b"abcdef",
            },
            &mut bytes,
        )
        .unwrap();
        q.preflight_authenticated_packet(7, &bytes[..n]).unwrap();

        let release = q.next_release().unwrap().unwrap().ticket;
        q.complete_release(release).unwrap();
        let n = packet::encode_frame(
            &Frame::Stream {
                id: 0,
                offset: 0,
                fin: true,
                data: b"xxxxxx",
            },
            &mut bytes,
        )
        .unwrap();
        q.preflight_authenticated_packet(7, &bytes[..n]).unwrap();
        assert_eq!(q.charged(), 6);
    }
    #[test]
    fn packet_preflight_bounds_frames_and_preserves_protocol_error_classification() {
        let mut replay = ReplayStorage::<1>::new();
        let mut slots = [QuarantineSlot::<8>::EMPTY, QuarantineSlot::EMPTY];
        let q = HeldBytes::new(POLICY, limits(), claim(&mut replay, 7), &mut slots).unwrap();
        assert_eq!(
            q.preflight_authenticated_packet(7, &[1; 129]),
            Err(Error::Capacity)
        );
        assert!(matches!(
            q.preflight_authenticated_packet(7, &[1, 0x1e]),
            Err(Error::Packet(_))
        ));
        assert_eq!(
            q.preflight_authenticated_packet(8, &[1]),
            Err(Error::StaleGeneration)
        );
        let mut bytes = [0; 64];
        let n = crate::quic::kernel::packet::encode_frame(
            &crate::quic::kernel::packet::Frame::Stream {
                id: 0,
                offset: 8,
                fin: false,
                data: b"x",
            },
            &mut bytes,
        )
        .unwrap();
        assert_eq!(
            q.preflight_authenticated_packet(7, &bytes[..n]),
            Err(Error::FlowControl)
        );
        assert_eq!(q.charged(), 0);
    }
    #[test]
    fn packet_preflight_charges_each_stream_maximum_once_then_all_commits_succeed() {
        use crate::quic::kernel::packet::{self, Frame};
        let mut replay = ReplayStorage::<1>::new();
        let mut slots = [QuarantineSlot::<8>::EMPTY, QuarantineSlot::EMPTY];
        let mut q = HeldBytes::new(POLICY, limits(), claim(&mut replay, 7), &mut slots).unwrap();
        let frames = [
            Frame::Stream {
                id: 0,
                offset: 4,
                fin: true,
                data: b"efgh",
            },
            Frame::Stream {
                id: 0,
                offset: 0,
                fin: false,
                data: b"abcdef",
            },
            Frame::Stream {
                id: 2,
                offset: 0,
                fin: true,
                data: b"12345678",
            },
            Frame::Stream {
                id: 0,
                offset: 0,
                fin: true,
                data: b"abcdefgh",
            },
        ];
        let mut bytes = [0; 128];
        let mut n = 0;
        for frame in frames {
            n += packet::encode_frame(&frame, &mut bytes[n..]).unwrap();
        }
        q.preflight_authenticated_packet(7, &bytes[..n]).unwrap();
        assert_eq!(q.charged(), 0);
        for frame in frames {
            let Frame::Stream {
                id,
                offset,
                fin,
                data,
            } = frame
            else {
                unreachable!()
            };
            q.buffer_authenticated_stream(7, id, offset, data, fin)
                .unwrap();
        }
        assert_eq!(q.charged(), 16);
        q.preflight_authenticated_packet(7, &bytes[..n]).unwrap();
    }
    #[test]
    fn successful_pair_preflight_guarantees_both_sequential_stream_commits() {
        use crate::quic::kernel::packet::{self, Frame};
        let mut admitted = 0;
        // Exhaustive bounded pairs vary both offsets/lengths/FINs, overlap
        // contents and same-versus-distinct streams. This checks the admission
        // implication against the actual mutating implementation.
        for encoded_case in 0usize..(9 * 9 * 4 * 4 * 2 * 2 * 2 * 2) {
            let mut case = encoded_case;
            let mut take = |radix| {
                let value = case % radix;
                case /= radix;
                value
            };
            let offsets = [take(9), take(9)];
            let lengths = [take(4), take(4)];
            let fins = [take(2) != 0, take(2) != 0];
            let conflict = take(2) != 0;
            let other_stream = take(2) != 0;
            let mut data = [[0; 4]; 2];
            for which in 0..2 {
                for (i, byte) in data[which].iter_mut().take(lengths[which]).enumerate() {
                    *byte = b'a' + (offsets[which] + i) as u8;
                }
            }
            if conflict {
                data[1][0] ^= 1;
            }
            let frames = [
                Frame::Stream {
                    id: 0,
                    offset: offsets[0] as u64,
                    fin: fins[0],
                    data: &data[0][..lengths[0]],
                },
                Frame::Stream {
                    id: if other_stream { 2 } else { 0 },
                    offset: offsets[1] as u64,
                    fin: fins[1],
                    data: &data[1][..lengths[1]],
                },
            ];
            let mut payload = [0; 32];
            let mut n = 0;
            for frame in frames {
                n += packet::encode_frame(&frame, &mut payload[n..]).unwrap();
            }
            let mut replay = ReplayStorage::<1>::new();
            let mut slots = [QuarantineSlot::<8>::EMPTY, QuarantineSlot::EMPTY];
            let mut q =
                HeldBytes::new(POLICY, limits(), claim(&mut replay, 7), &mut slots).unwrap();
            let result = q.preflight_authenticated_packet(7, &payload[..n]);
            assert_eq!(q.charged(), 0);
            assert!(q.slots.iter().all(|slot| slot.id.is_none()));
            if result.is_ok() {
                admitted += 1;
                for frame in frames {
                    let Frame::Stream {
                        id,
                        offset,
                        fin,
                        data,
                    } = frame
                    else {
                        unreachable!()
                    };
                    q.buffer_authenticated_stream(7, id, offset, data, fin)
                        .unwrap();
                }
            }
        }
        assert!(admitted > 1000);
    }
    #[test]
    fn reset_admission_uses_remembered_credit_and_final_size_without_releasing_withheld_data() {
        use crate::quic::kernel::packet::{self, Frame};
        let mut replay = ReplayStorage::<1>::new();
        let mut slots = [QuarantineSlot::<8>::EMPTY, QuarantineSlot::EMPTY];
        let mut q = HeldBytes::new(POLICY, limits(), claim(&mut replay, 7), &mut slots).unwrap();
        let mut payload = [0; 64];
        for frame in [
            Frame::ResetStream {
                id: 0,
                error_code: 1,
                final_size: 9,
            },
            Frame::ResetStream {
                id: 4,
                error_code: 2,
                final_size: 0,
            },
        ] {
            let n = packet::encode_frame(&frame, &mut payload).unwrap();
            assert_eq!(
                q.preflight_authenticated_packet(7, &payload[..n]),
                Err(Error::FlowControl)
            );
            assert_eq!(q.charged(), 0);
        }
        q.buffer_authenticated_stream(7, 0, 0, b"secret", false)
            .unwrap();
        assert_eq!(q.buffer_authenticated_reset(7, 0, 5), Err(Error::FinalSize));
        q.buffer_authenticated_reset(7, 0, 8).unwrap();
        assert_eq!(q.charged(), 8);
        assert!(q.slots[0].bytes.iter().all(|byte| *byte == 0));
        q.buffer_authenticated_stream(7, 0, 0, b"ignored!", true)
            .unwrap();
        assert!(q.slots[0].bytes.iter().all(|byte| *byte == 0));
        assert_eq!(q.buffer_authenticated_reset(7, 0, 7), Err(Error::FinalSize));
        let n = packet::encode_frame(
            &Frame::ResetStream {
                id: 0,
                error_code: 3,
                final_size: 7,
            },
            &mut payload,
        )
        .unwrap();
        assert_eq!(
            q.preflight_authenticated_packet(7, &payload[..n]),
            Err(Error::FinalSize)
        );
        q.buffer_authenticated_reset(7, 2, 8).unwrap();
        assert_eq!(q.charged(), 16);

        assert!(q.next_release().unwrap().is_none());
    }
    #[test]
    fn reset_and_stream_pair_preflight_matches_real_commits_in_both_orders() {
        use crate::quic::kernel::packet::{self, Frame};
        let mut admitted = 0;
        for final_size in 0..10 {
            for offset in 0..10 {
                for len in 0..4 {
                    for fin in [false, true] {
                        for reset_first in [false, true] {
                            let stream = Frame::Stream {
                                id: 0,
                                offset,
                                fin,
                                data: &b"abcd"[..len],
                            };
                            let reset = Frame::ResetStream {
                                id: 0,
                                error_code: 3,
                                final_size,
                            };
                            let frames = if reset_first {
                                [reset, stream]
                            } else {
                                [stream, reset]
                            };
                            let mut payload = [0; 32];
                            let mut n = 0;
                            for frame in frames {
                                n += packet::encode_frame(&frame, &mut payload[n..]).unwrap();
                            }
                            let mut replay = ReplayStorage::<1>::new();
                            let mut slots = [QuarantineSlot::<8>::EMPTY, QuarantineSlot::EMPTY];
                            let mut q =
                                HeldBytes::new(POLICY, limits(), claim(&mut replay, 7), &mut slots)
                                    .unwrap();
                            let result = q.preflight_authenticated_packet(7, &payload[..n]);
                            assert_eq!(q.charged(), 0);
                            if result.is_ok() {
                                admitted += 1;
                                for frame in frames {
                                    match frame {
                                        Frame::Stream {
                                            id,
                                            offset,
                                            fin,
                                            data,
                                        } => q
                                            .buffer_authenticated_stream(7, id, offset, data, fin)
                                            .unwrap(),
                                        Frame::ResetStream { id, final_size, .. } => {
                                            q.buffer_authenticated_reset(7, id, final_size).unwrap()
                                        }
                                        _ => unreachable!(),
                                    }
                                }
                                assert_eq!(q.charged(), final_size);

                                assert!(q.next_release().unwrap().is_none());
                            }
                        }
                    }
                }
            }
        }
        assert!(admitted > 100);
    }
    #[test]
    fn deferred_stream_controls_enforce_remembered_count_and_direction_before_finished() {
        use crate::quic::kernel::packet::{self, Frame};
        let mut replay = ReplayStorage::<1>::new();
        let mut slots = [QuarantineSlot::<8>::EMPTY, QuarantineSlot::EMPTY];
        let mut q = HeldBytes::new(POLICY, limits(), claim(&mut replay, 7), &mut slots).unwrap();
        let mut payload = [0; 64];
        for id in [1, 2, 3, 4, 6] {
            for frame in [
                Frame::StopSending { id, error_code: 1 },
                Frame::MaxStreamData { id, maximum: 900 },
            ] {
                let n = packet::encode_frame(&frame, &mut payload).unwrap();
                assert!(q.preflight_authenticated_packet(7, &payload[..n]).is_err());
                assert!(q.buffer_authenticated_control(7, frame).is_err());
                assert!(q.slots.iter().all(|slot| slot.id.is_none()));
            }
        }
        for id in [1, 3, 4, 6] {
            let frame = Frame::StreamDataBlocked { id, limit: 8 };
            let n = packet::encode_frame(&frame, &mut payload).unwrap();
            assert!(q.preflight_authenticated_packet(7, &payload[..n]).is_err());
            assert!(q.buffer_authenticated_control(7, frame).is_err());
        }
        for frame in [
            Frame::StopSending {
                id: 0,
                error_code: 1,
            },
            Frame::MaxStreamData {
                id: 0,
                maximum: 900,
            },
            Frame::StreamDataBlocked { id: 2, limit: 8 },
        ] {
            let n = packet::encode_frame(&frame, &mut payload).unwrap();
            q.preflight_authenticated_packet(7, &payload[..n]).unwrap();
            q.buffer_authenticated_control(7, frame).unwrap();
        }
        // Control references open remembered stream identities but do not
        // consume receive bytes; a MAX_STREAM_DATA maximum grants send credit.
        assert_eq!(q.charged(), 0);
        assert_eq!(q.slots.iter().filter(|slot| slot.id.is_some()).count(), 2);
        // Release ordering belongs to the projected owner, not this byte kernel.

        for id in [0, 2] {
            let view = q.next_release().unwrap().unwrap();
            assert_eq!(view.stream_id, id);
            assert!(view.bytes.is_empty() && !view.fin);
            let ticket = view.ticket;
            q.complete_release(ticket).unwrap();
        }
    }
}
