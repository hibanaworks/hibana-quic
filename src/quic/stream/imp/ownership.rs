//! Bounded stream ownership operations; no protocol ordering.
use super::*;

impl<'book, const RX: usize, const CHUNK: usize> FrameEffects<'book, '_, '_, RX, CHUNK> {
    pub(in crate::quic) fn reclaim(
        &mut self,
        joined: crate::quic::application::local::reclaim::Joined<'book>,
    ) -> Result<(), Error> {
        let (source, input, delivery) = joined.into_parts();
        let origin = source.origin();
        if !origin.same(input.origin())
            || !origin.same(delivery.origin())
            || !core::ptr::eq(origin.identity, &self.core.identity)
        {
            return Err(Error::Binding);
        }
        let mut n = self
            .core
            .numbers
            .try_borrow_mut()
            .map_err(|_| Error::Borrowed)?;
        n.state(origin.stream)?;
        n.table.reclaim_storage(origin.stream)?;
        // Only the actual three-way reclaim releases backing storage for a
        // further peer stream. Publish the resulting credit through the same
        // retained control flight as other flow-control updates.
        if origin.stream.id() & 3 == u64::from(n.role == Role::Client)
            && n.bidi_credit.current < streams::MAX_STREAMS
        {
            let maximum = n.bidi_credit.current + 1;
            n.table.grant_max_streams(true, maximum)?;
            n.bidi_credit.update(maximum);
        }
        // Old per-stream credit/control copies are no longer applicable; the
        // recovery ledger retains packet accounting independently for late ACKs.
        for reference in &mut n.controls {
            if reference
                .contents
                .max_stream_data
                .is_some_and(|(s, _)| s == origin.stream)
            {
                reference.contents.max_stream_data = None;
            }
            if reference
                .contents
                .reset
                .is_some_and(|(s, _)| s == origin.stream)
            {
                reference.contents.reset = None;
            }
            if reference.contents.is_empty() {
                reference.state = ReferenceState::Free;
            }
        }
        n.streams[origin.slot()] = StreamState::EMPTY;
        Ok(())
    }
    pub(in crate::quic) fn apply_loss(
        &mut self,
        grant: crate::quic::recovery::ApplicationLoss<'_>,
    ) -> Result<(), Error> {
        if !core::ptr::eq(grant.scope(), self.core.scope) {
            return Err(Error::Binding);
        }
        let packet = grant.packet();
        if packet.space != PacketNumberSpace::ApplicationData {
            return Err(Error::Binding);
        }
        self.core
            .numbers
            .try_borrow_mut()
            .map_err(|_| Error::Borrowed)?
            .lost(packet.value)
    }
    pub(in crate::quic) fn take_delivery(&mut self) -> Result<Option<Delivered<'book>>, Error> {
        let mut n = self
            .core
            .numbers
            .try_borrow_mut()
            .map_err(|_| Error::Borrowed)?;
        for index in 0..MAX_LIVE_STREAMS {
            let Some(evidence) = n.streams[index].terminal.as_ref() else {
                continue;
            };
            if n.table.unacknowledged_chunks(evidence.stream)? == 0 {
                let evidence = n.streams[index].terminal.take().ok_or(Error::Binding)?;
                return Ok(Some(Delivered {
                    identity: &self.core.identity,
                    evidence,
                }));
            }
        }
        Ok(None)
    }
    pub(in crate::quic) fn acknowledge(
        &mut self,
        grant: crate::quic::recovery::FrameAcknowledgments<'_>,
    ) -> Result<(), Error> {
        if !core::ptr::eq(grant.scope(), self.core.scope) {
            return Err(Error::Binding);
        }
        self.core
            .numbers
            .try_borrow_mut()
            .map_err(|_| Error::Borrowed)?
            .acknowledge(grant.packets())
    }
    pub(in crate::quic) fn apply(&mut self, intent: StopIntent<'_>) -> Result<(), Error> {
        if !core::ptr::eq(intent.identity, &self.core.identity) {
            return Err(Error::Binding);
        }
        let mut n = self
            .core
            .numbers
            .try_borrow_mut()
            .map_err(|_| Error::Borrowed)?;
        let state = n.state(intent.stream)?;
        if state.delivered.is_some()
            || (state.terminal.is_some() && n.table.unacknowledged_chunks(intent.stream)? == 0)
        {
            return Ok(());
        }
        let Numbers { table, queue, .. } = &mut *n;
        if let Some(reset) = queue.reset(table, intent.stream, intent.error_code)? {
            let state = n.state_mut(intent.stream)?;
            if state.reset.is_none() {
                state.reset = Some(reset);
                state.terminal = None;
            }
        }
        Ok(())
    }
}

impl<const RX: usize, const CHUNK: usize> Publication<'_, '_, '_, RX, CHUNK> {
    /// Call only after the adapter confirms publication. Dropping or cancelling
    /// its pending future cannot be treated as successful transmission.
    pub fn commit(&mut self, transmission: Transmission<'_>) -> Result<(), Error> {
        self.settle(transmission, true)
    }
    pub fn cancel(&mut self, transmission: Transmission<'_>) -> Result<(), Error> {
        self.settle(transmission, false)
    }
    fn settle(&mut self, transmission: Transmission<'_>, published: bool) -> Result<(), Error> {
        if !core::ptr::eq(transmission.identity, &self.core.identity) {
            return Err(Error::Binding);
        }
        let mut n = self
            .core
            .numbers
            .try_borrow_mut()
            .map_err(|_| Error::Borrowed)?;
        if let Some((slot, generation)) = transmission.control {
            let r = n.controls.get(slot).ok_or(Error::Binding)?;
            if r.generation != generation
                || r.state != ReferenceState::Reserved
                || r.packet != transmission.packet_number
            {
                return Err(Error::Binding);
            }
        }
        if let Some((_stream, reference)) = transmission.stream {
            let Numbers { table, queue, .. } = &mut *n;
            if published {
                queue.commit_transmission(table, reference)?;
            } else {
                queue.cancel_transmission(table, reference)?;
            }
        }
        if let Some((slot, _)) = transmission.control {
            let contents = n.controls[slot].contents;
            if published {
                n.controls[slot].state = ReferenceState::Sent;
                n.data_credit.published(contents.max_data);
                n.bidi_credit.published(contents.max_streams_bidi);
                if let Some((stream, maximum)) = contents.max_stream_data {
                    n.state_mut(stream)?.credit.published(Some(maximum));
                    n.control_cursor = (stream.slot() + 1) % MAX_LIVE_STREAMS;
                }
                if let Some((stream, _)) = contents.reset {
                    n.control_cursor = (stream.slot() + 1) % MAX_LIVE_STREAMS;
                }
            } else {
                n.controls[slot].state = ReferenceState::Free;
            }
        }
        n.collect_controls();
        Ok(())
    }
}
