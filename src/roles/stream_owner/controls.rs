//! Reliable bounded control numerics owned exclusively by StreamState.
use super::*;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ControlKind {
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
    pub(super) fn same_key(self, other: Self) -> bool {
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
    pub(super) fn frame(self) -> Frame<'static> {
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
pub(super) struct Control {
    pub(super) kind: Option<ControlKind>,
    pub(super) generation: u64,
    pub(super) pending: bool,
    pub(super) delivered: bool,
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
pub(super) enum RefState {
    Free,
    Reserved,
    Sent,
}
#[derive(Clone, Copy)]
pub(super) struct ControlReference {
    pub(super) slot: usize,
    pub(super) generation: u64,
    pub(super) packet: u64,
    pub(super) state: RefState,
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
pub(super) struct ControlReservation {
    pub(super) index: usize,
    pub(super) slot: usize,
    pub(super) generation: u64,
    pub(super) packet: u64,
}

pub(super) struct Controls<const N: usize, const REFS: usize> {
    pub(super) entries: [Control; N],
    pub(super) refs: [ControlReference; REFS],
}
impl<const N: usize, const REFS: usize> Controls<N, REFS> {
    pub(super) fn new() -> Self {
        Self {
            entries: [Control::EMPTY; N],
            refs: [ControlReference::EMPTY; REFS],
        }
    }
    pub(super) fn has_refs(&self, slot: usize) -> bool {
        self.refs.iter().any(|r| {
            r.state != RefState::Free
                && r.slot == slot
                && r.generation == self.entries[slot].generation
        })
    }
    pub(super) fn replaceable(&self, kind: ControlKind) -> Option<usize> {
        self.entries.iter().enumerate().find_map(|(i, c)| {
            (c.kind.is_some_and(|k| k.same_key(kind)) && c.pending && !self.has_refs(i))
                .then_some(i)
        })
    }
    pub(super) fn can_push(&self, kinds: &[ControlKind]) -> Result<(), streams::Error> {
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
    pub(super) fn already_reliable(&self, kind: ControlKind) -> bool {
        matches!(kind, ControlKind::Reset { .. } | ControlKind::Stop { .. })
            && self
                .entries
                .iter()
                .any(|c| c.kind.is_some_and(|k| k.same_key(kind)))
    }
    pub(super) fn push(&mut self, kind: ControlKind) -> Result<(), streams::Error> {
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
    pub(super) fn next(&self, probe: bool) -> Option<usize> {
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
    pub(super) fn reserve(
        &mut self,
        slot: usize,
        packet: u64,
    ) -> Result<ControlReservation, streams::Error> {
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
    pub(super) fn validate(&self, h: ControlReservation) -> Result<(), streams::Error> {
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
    pub(super) fn report<const RX: usize>(
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
    pub(super) fn validate_ack(
        &self,
        ranges: &[crate::accounting::AckRange],
    ) -> Result<(), streams::Error> {
        if self.refs.iter().any(|r| {
            r.state == RefState::Reserved
                && ranges
                    .iter()
                    .any(|range| range.start <= r.packet && r.packet <= range.end)
        }) {
            Err(streams::Error::UnsentAcknowledgment)
        } else {
            Ok(())
        }
    }
    pub(super) fn acknowledge<const RX: usize>(
        &mut self,
        table: &mut StreamTable<'_, RX>,
        ranges: &[crate::accounting::AckRange],
    ) -> Result<(), streams::Error> {
        let contains = |pn| ranges.iter().any(|r| r.start <= pn && pn <= r.end);
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
    pub(super) fn collect(&mut self) {
        for i in 0..self.entries.len() {
            if self.entries[i].delivered && !self.has_refs(i) {
                self.entries[i].kind = None;
            }
        }
    }
    pub(super) fn on_packet_lost(&mut self, packet: u64) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounting::AckRange;
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
        let ranges = [AckRange { start: 7, end: 7 }];
        controls.acknowledge(&mut table, &ranges).unwrap();
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
            .acknowledge(&mut table, &[AckRange { start: 7, end: 7 }])
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
            controls.acknowledge(&mut table, &[AckRange { start: 1, end: 1 }]),
            Err(streams::Error::UnsentAcknowledgment)
        );
        controls.report(&mut table, tx, false).unwrap();
        assert_eq!(controls.next(false), Some(0));
        assert_eq!(controls.entries[0].kind, Some(ControlKind::MaxData(200)));
    }
}
