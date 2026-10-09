//! Bounded stream accounting operations; no protocol ordering.
use super::*;

impl<const RX: usize, const CHUNK: usize> Numbers<'_, RX, CHUNK> {
    pub(super) fn state(&self, stream: StreamHandle) -> Result<&StreamState, Error> {
        let state = self.streams.get(stream.slot()).ok_or(Error::Binding)?;
        if state.handle != Some(stream) {
            return Err(streams::Error::StaleHandle.into());
        }
        Ok(state)
    }
    pub(super) fn state_mut(&mut self, stream: StreamHandle) -> Result<&mut StreamState, Error> {
        let state = self.streams.get_mut(stream.slot()).ok_or(Error::Binding)?;
        if state.handle != Some(stream) {
            return Err(streams::Error::StaleHandle.into());
        }
        Ok(state)
    }
    pub(super) fn register(&mut self, stream: StreamHandle) -> Result<(), Error> {
        if self.streams[stream.slot()].handle == Some(stream) {
            return Ok(());
        }
        let local = self.table.local_limits();
        let local_bit = u64::from(self.role == Role::Server);
        let locally_initiated = stream.id() & 1 == local_bit;
        let maximum = if stream.id() & 2 != 0 {
            if locally_initiated {
                0
            } else {
                local.stream_data_uni
            }
        } else if locally_initiated {
            local.stream_data_bidi_local
        } else {
            local.stream_data_bidi_remote
        };
        self.streams[stream.slot()] = StreamState {
            handle: Some(stream),
            production: self.table.can_send(stream.id()).then_some(stream),
            input_release: self.table.can_receive(stream.id()).then_some(stream),
            credit: Credit::new(maximum),
            ..StreamState::EMPTY
        };
        Ok(())
    }
    pub(super) fn accept_stream(&mut self, id: u64) -> Result<StreamHandle, Error> {
        let stream = self.table.get_or_accept(id)?;
        // Implicit lower peer streams also get real per-slot control metadata.
        let mut handles = [None; MAX_LIVE_STREAMS];
        for (slot, h) in handles.iter_mut().zip(self.table.live_handles()) {
            *slot = Some(h);
        }
        for handle in handles.into_iter().flatten() {
            self.register(handle)?;
        }
        Ok(stream)
    }
    pub(super) fn replenish_credit(&mut self, stream: StreamHandle) -> Result<(), Error> {
        let data = self.table.receive_data_capacity();
        if self
            .data_credit
            .should_update(data, self.table.receive_window_capacity())
        {
            self.table.grant_max_data(data)?;
            self.data_credit.update(data);
        }
        if self.table.receive_final_size(stream)?.is_none() {
            let maximum = self.table.stream_receive_capacity(stream)?;
            if self.state(stream)?.credit.should_update(maximum, RX as u64) {
                self.table.grant_max_stream_data(stream, maximum)?;
                self.state_mut(stream)?.credit.update(maximum);
            }
        }
        Ok(())
    }
    /// Only actual newly acknowledged packet numbers returned by Recovery may
    /// enter here. The stream queue never interprets unvalidated ACK ranges.
    pub(super) fn acknowledge(&mut self, packets: &[Option<PacketNumber>]) -> Result<(), Error> {
        if packets
            .iter()
            .flatten()
            .any(|pn| pn.space != PacketNumberSpace::ApplicationData)
        {
            return Err(Error::Binding);
        }
        let contains = |pn| packets.iter().flatten().any(|packet| packet.value == pn);
        let n = self;
        if n.controls
            .iter()
            .any(|r| r.state == ReferenceState::Reserved && contains(r.packet))
        {
            return Err(streams::Error::UnsentAcknowledgment.into());
        }
        let Numbers {
            table,
            queue,
            streams,
            ..
        } = &mut *n;
        queue.on_packets_acked(table, contains, |stream, final_size| {
            let state = &mut streams[stream.slot()];
            if state.reset.is_none() && state.delivered.is_none() {
                state.terminal = Some(TerminalEvidence {
                    stream,
                    final_size,
                    reset: None,
                });
            }
        })?;
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
        let n = self;
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

    pub(super) fn next_controls(&self, probe: bool) -> Controls {
        let mut controls = Controls {
            max_data: self.data_credit.next(probe),
            max_streams_bidi: self.bidi_credit.next(probe),
            ..Controls::EMPTY
        };
        for offset in 0..MAX_LIVE_STREAMS {
            let state = &self.streams[(self.control_cursor + offset) % MAX_LIVE_STREAMS];
            let Some(stream) = state.handle else {
                continue;
            };
            if controls.max_stream_data.is_none() {
                controls.max_stream_data =
                    state.credit.next(probe).map(|maximum| (stream, maximum));
            }
            if controls.reset.is_none()
                && (probe
                    || !self.controls.iter().any(|reference| {
                        matches!(
                            reference.state,
                            ReferenceState::Reserved | ReferenceState::Sent
                        ) && reference
                            .contents
                            .reset
                            .is_some_and(|(handle, _)| handle == stream)
                    }))
            {
                controls.reset = state.reset.map(|reset| (stream, reset));
            }
        }
        controls
    }
    pub(super) fn acknowledge_control(&mut self, contents: Controls) -> Result<(), Error> {
        self.data_credit.acknowledge(contents.max_data);
        self.bidi_credit.acknowledge(contents.max_streams_bidi);
        if let Some((stream, maximum)) = contents.max_stream_data {
            self.state_mut(stream)?.credit.acknowledge(Some(maximum));
        }
        if let Some((stream, reset)) = contents.reset {
            if self
                .state(stream)?
                .reset
                .is_some_and(|retained| retained != reset)
            {
                return Err(Error::Binding);
            }
            let state = self.state_mut(stream)?;
            if state.reset.take().is_some() {
                state.terminal = Some(TerminalEvidence {
                    stream,
                    final_size: reset.final_size,
                    reset: Some(reset.error_code),
                });
            }
        }
        Ok(())
    }
    pub(super) fn retry_control(&mut self, contents: Controls) {
        self.data_credit.retry(contents.max_data);
        self.bidi_credit.retry(contents.max_streams_bidi);
        if let Some((stream, maximum)) = contents.max_stream_data
            && let Ok(state) = self.state_mut(stream)
        {
            state.credit.retry(Some(maximum));
        }
    }

    pub(super) fn collect_controls(&mut self) {
        for index in 0..CONTROL_CAPACITY {
            let r = self.controls[index];
            if matches!(r.state, ReferenceState::Sent | ReferenceState::Lost)
                && r.contents
                    .max_data
                    .is_none_or(|v| v <= self.data_credit.acknowledged)
                && r.contents
                    .max_streams_bidi
                    .is_none_or(|v| v <= self.bidi_credit.acknowledged)
                && r.contents.max_stream_data.is_none_or(|(stream, maximum)| {
                    self.state(stream)
                        .is_ok_and(|s| maximum <= s.credit.acknowledged)
                })
                && r.contents
                    .reset
                    .is_none_or(|(stream, _)| self.state(stream).is_ok_and(|s| s.reset.is_none()))
            {
                self.controls[index].state = ReferenceState::Free;
            }
        }
    }
}
