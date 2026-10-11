//! Direct projected locals for the early-byte lifetime. No phase discriminator.
use super::global as p;
use super::imp::{EarlyStatus, Error, HeldBytes, QuarantineSlot, ServerPolicy};
use crate::quic::imp::kernel::packet::EncryptionLevel;
use crate::quic::imp::kernel::packet::Frame;
use crate::quic::imp::kernel::packet::FrameIter;
use crate::quic::imp::kernel::packet::ParseLimits;
use hibana::Endpoint;
use hibana_tls::schedule::Side;
use hibana_tls::secret::Erase;

use crate::quic::early_data::Failure;

use crate::quic::early_data::{Admission, ControlBlock, Exchange, Range, StoredPacket};
pub async fn run<'scope, const BYTES: usize, const PACKET: usize>(
    endpoint: &mut Endpoint<'_, { p::OWNER }>,
    admission: Admission<'scope>,
    policy: ServerPolicy,
    slots: &mut [QuarantineSlot<BYTES>],
    exchange: &Exchange<'scope, PACKET>,
) -> Result<(), Failure> {
    let (scope, limits, claim) = admission.into_parts();
    let generation = claim.generation();
    let mut held = HeldBytes::new(policy, limits, claim, slots)?;
    let mut deferred = hibana_tls::secret::Secret::new([0u8; PACKET]);
    let mut deferred_len = 0usize;
    loop {
        let offered = endpoint.offer().await?;
        match offered.label() {
            0 => {
                let packet = offered.recv::<p::Packet>().await?;
                let input = exchange.input.take().map_err(|_| Failure::Binding)?;
                if !core::ptr::eq(input.scope, scope)
                    || input.generation != generation
                    || input.packet != packet
                    || input.len > PACKET
                {
                    return Err(Failure::Binding);
                }
                match held.preflight_authenticated_packet(generation, &input.bytes[..input.len]) {
                    Ok(()) => {}
                    Err(Error::Capacity) => {
                        endpoint.send::<p::PacketDropped>(&packet).await?;
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                }
                // Retain every non-data control before committing either ledger.
                // Capacity pressure drops the complete packet without admitting it.
                let extra_len = match super::imp::codec::retain_control(
                    &input.bytes[..input.len],
                    &mut deferred[deferred_len..],
                ) {
                    Ok(len) => len,
                    Err(crate::quic::imp::kernel::packet::Error::BufferTooShort) => {
                        endpoint.send::<p::PacketDropped>(&packet).await?;
                        continue;
                    }
                    Err(error) => return Err(Error::Packet(error).into()),
                };
                let mut ack_eliciting = false;
                for frame in FrameIter::new(
                    &input.bytes[..input.len],
                    EncryptionLevel::ZeroRtt,
                    ParseLimits {
                        max_frames: 128,
                        ..ParseLimits::default()
                    },
                )
                .map_err(Error::Packet)?
                {
                    let frame = frame.map_err(Error::Packet)?;
                    ack_eliciting |= frame.ack_eliciting();
                    match frame {
                        Frame::Stream {
                            id,
                            offset,
                            fin,
                            data,
                        } => held.buffer_authenticated_stream(generation, id, offset, data, fin)?,
                        other => held.buffer_authenticated_control(generation, other)?,
                    }
                }
                deferred_len += extra_len;
                exchange
                    .stored
                    .put(StoredPacket {
                        scope: input.scope,
                        generation: input.generation,
                        packet: input.packet,
                        ack_eliciting,
                        ecn: input.ecn,
                    })
                    .map_err(|_| Failure::Binding)?;
                endpoint.send::<p::PacketStored>(&packet).await?;
            }
            3 => {
                let id = offered.recv::<p::InputEnd>().await?;
                if id != generation {
                    return Err(Failure::Binding);
                }
                endpoint.send::<p::InputEnded>(&generation).await?;
                break;
            }
            _ => return Err(Failure::Binding),
        }
    }
    let offered = endpoint.offer().await?;
    match offered.label() {
        6 => {
            if offered.recv::<p::Verified>().await? != generation {
                return Err(Failure::Binding);
            }
            let finished = exchange.finished.take().map_err(|_| Failure::Binding)?;
            if !core::ptr::eq(finished.scope(), scope)
                || finished.side() != Side::Server
                || finished.early_status() != EarlyStatus::Accepted
                || finished.early_generation() != Some(generation)
            {
                return Err(Failure::Binding);
            }
            exchange
                .returned_finished
                .put(finished)
                .map_err(|_| Failure::Binding)?;
            endpoint.send::<p::VerifiedTaken>(&generation).await?;
            if deferred_len != 0 {
                let mut bytes = [0; PACKET];
                bytes[..deferred_len].copy_from_slice(&deferred[..deferred_len]);
                exchange
                    .controls
                    .put(ControlBlock {
                        bytes,
                        len: deferred_len,
                    })
                    .map_err(|_| Failure::Binding)?;
                endpoint.send::<p::Controls>(&generation).await?;
                if endpoint.recv::<p::ControlsApplied>().await? != generation
                    || !exchange.controls.is_empty()
                {
                    return Err(Failure::Binding);
                }
                deferred.erase();
            }

            while let Some(view) = held.next_release()? {
                if view.bytes.len() > PACKET {
                    return Err(Error::Capacity.into());
                }
                let mut bytes = [0; PACKET];
                bytes[..view.bytes.len()].copy_from_slice(view.bytes);
                let id = view.stream_id;
                let ticket = view.ticket;
                exchange
                    .output
                    .put(Range {
                        id,
                        offset: view.offset,
                        fin: view.fin,
                        bytes,
                        len: view.bytes.len(),
                    })
                    .map_err(|_| Failure::Binding)?;
                endpoint.send::<p::Range>(&id).await?;
                if endpoint.recv::<p::RangeApplied>().await? != id || !exchange.output.is_empty() {
                    return Err(Failure::Binding);
                }
                held.complete_release(ticket)?;
            }
            endpoint.send::<p::Released>(&generation).await?;
            if endpoint.recv::<p::ReleaseSeen>().await? != generation {
                return Err(Failure::Binding);
            }
            drop(held);
        }
        8 => {
            if offered.recv::<p::Reject>().await? != generation {
                return Err(Failure::Binding);
            }
            drop(held);
            endpoint.send::<p::Discarded>(&generation).await?;
            if endpoint.recv::<p::DiscardSeen>().await? != generation {
                return Err(Failure::Binding);
            }
        }
        9 => {
            if offered.recv::<p::Cancel>().await? != generation {
                return Err(Failure::Binding);
            }
            drop(held);
            endpoint.send::<p::Discarded>(&generation).await?;
            if endpoint.recv::<p::DiscardSeen>().await? != generation {
                return Err(Failure::Binding);
            }
        }
        _ => return Err(Failure::Binding),
    }
    endpoint.send::<p::Retired>(&generation).await?;
    Ok(())
}
