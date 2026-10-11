//! Bounded stream transmit operations; no protocol ordering.
use super::*;

impl<'book, const RX: usize, const CHUNK: usize> Tx<'book, '_, '_, RX, CHUNK> {
    /// Cancel a reservation which TX could not seal/transfer to the adapter.
    /// Accepted packets can be committed only through the publication facet.
    pub(in crate::quic) fn cancel_transmission(
        &mut self,
        transmission: Transmission<'_>,
    ) -> Result<(), Error> {
        Publication { core: self.core }.cancel(transmission)
    }

    // Recovery-driven arithmetic is also available to the transmit facet.
    // It never grants permission to authenticate or apply peer frames.
    pub(in crate::quic) fn reclaimable(&self, origin: Origin<'_>) -> Result<bool, Error> {
        if !core::ptr::eq(origin.identity, &self.core.identity) {
            return Err(Error::Binding);
        }
        let n = self
            .core
            .numbers
            .try_borrow()
            .map_err(|_| Error::Borrowed)?;
        Ok(n.table.retained_chunks(origin.stream)? == 0)
    }
    pub(in crate::quic) fn record_delivery(
        &mut self,
        receipt: Delivered<'book>,
    ) -> Result<DeliveryReleased<'book>, Error> {
        if !core::ptr::eq(receipt.identity, &self.core.identity) {
            return Err(Error::Binding);
        }
        let mut n = self
            .core
            .numbers
            .try_borrow_mut()
            .map_err(|_| Error::Borrowed)?;
        let state = n.state_mut(receipt.evidence.stream)?;
        if state.delivered.is_some() {
            return Err(Error::Binding);
        }
        state.delivered = Some(DeliveryRecord {
            final_size: receipt.evidence.final_size,
            reset: receipt.evidence.reset,
        });
        Ok(DeliveryReleased {
            origin: Origin {
                identity: receipt.identity,
                stream: receipt.evidence.stream,
            },
        })
    }

    /// Only call when Recovery has explicitly stopped retaining this lost PN.
    pub(in crate::quic) fn forget_lost(&mut self, packet_number: u64) -> Result<(), Error> {
        let mut n = self
            .core
            .numbers
            .try_borrow_mut()
            .map_err(|_| Error::Borrowed)?;
        let Numbers { table, queue, .. } = &mut *n;
        queue.forget_lost_packet(table, packet_number)?;
        for r in &mut n.controls {
            if r.packet == packet_number && r.state == ReferenceState::Lost {
                r.state = ReferenceState::Free;
            }
        }
        Ok(())
    }

    /// Prefer a pending STREAM chunk; on a PTO an outstanding range may be
    /// copied under a fresh packet number without declaring the old copy lost.
    /// Dirty control limits/reset are encoded before the chunk. A caller may
    /// prepend/append its own recovery-produced ACK when composing plaintext.
    pub fn prepare<const N: usize>(
        &self,
        probe: bool,
    ) -> Result<Option<Prepared<'book, N>>, Error> {
        let n = self
            .core
            .numbers
            .try_borrow()
            .map_err(|_| Error::Borrowed)?;
        let chunk = n
            .queue
            .next_pending()
            .or_else(|| if probe { n.queue.probe_chunk() } else { None });
        let controls = n.next_controls(probe);
        if chunk.is_none() && controls.is_empty() {
            return Ok(None);
        }
        let mut prepared = Prepared {
            identity: &self.core.identity,
            bytes: [0; N],
            len: 0,
            chunk,
            controls,
        };
        if let Some(maximum) = controls.max_data {
            prepared.append(&Frame::MaxData { maximum })?;
        }
        if let Some(maximum) = controls.max_streams_bidi {
            prepared.append(&Frame::MaxStreams {
                bidirectional: true,
                maximum,
            })?;
        }
        if let Some((stream, maximum)) = controls.max_stream_data {
            prepared.append(&Frame::MaxStreamData {
                id: stream.id(),
                maximum,
            })?;
        }
        if let Some((_, reset)) = controls.reset {
            prepared.append(&Frame::ResetStream {
                id: reset.id,
                error_code: reset.error_code,
                final_size: reset.final_size,
            })?;
        }
        if let Some(chunk) = chunk {
            let view = n.queue.chunk(chunk)?;
            prepared.append(&Frame::Stream {
                id: view.stream.id(),
                offset: view.offset,
                fin: view.fin,
                data: view.data,
            })?;
        }
        Ok(Some(prepared))
    }

    /// Bind the exact selected chunk/control frames to the actual packet number
    /// allocated by Recovery before handing bytes to the adapter.
    pub fn reserve_transmission<const N: usize>(
        &mut self,
        prepared: &Prepared<'book, N>,
        packet_number: u64,
    ) -> Result<Transmission<'book>, Error> {
        if !core::ptr::eq(prepared.identity, &self.core.identity)
            || prepared.identity.generation != self.core.scope.connection_generation()
            || packet_number > streams::MAX_OFFSET
        {
            return Err(Error::Binding);
        }
        let mut n = self
            .core
            .numbers
            .try_borrow_mut()
            .map_err(|_| Error::Borrowed)?;
        if n.controls
            .iter()
            .any(|r| r.state != ReferenceState::Free && r.packet == packet_number)
        {
            return Err(Error::Binding);
        }
        let control = if prepared.controls.is_empty() {
            None
        } else {
            Some(
                n.controls
                    .iter()
                    .position(|r| r.state == ReferenceState::Free && r.generation != u64::MAX)
                    .ok_or(Error::Capacity)?,
            )
        };
        let stream = match prepared.chunk {
            Some(chunk) => {
                let handle = n.queue.chunk(chunk)?.stream;
                n.state(handle)?;
                let reference = n.queue.reserve_transmission(chunk, packet_number)?;
                Some((handle, reference))
            }
            None => None,
        };
        let control = control.map(|slot| {
            let generation = n.controls[slot].generation + 1;
            n.controls[slot] = ControlReference {
                generation,
                packet: packet_number,
                state: ReferenceState::Reserved,
                contents: prepared.controls,
            };
            (slot, generation)
        });
        Ok(Transmission {
            identity: &self.core.identity,
            packet_number,
            stream,
            control,
        })
    }
}
