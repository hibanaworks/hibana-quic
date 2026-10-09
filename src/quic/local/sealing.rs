//! packet role or packet arithmetic; endpoint exchanges stay explicit.
use super::*;
pub(super) fn limited(error: &recovery::Error) -> bool {
    matches!(
        error,
        recovery::Error::CongestionLimited
            | recovery::Error::Accounting(
                crate::quic::kernel::accounting::AccountingError::AmplificationLimited
            )
    )
}
#[allow(clippy::too_many_arguments)]
pub(in crate::quic) fn prepare<'book, 'scope, const N: usize>(
    keys: &mut WriteKeys<'_, 'scope>,
    book: &mut recovery::Tx<'book, 'scope, N>,
    config: Config<'_>,
    peer: &ConnectionId,
    level: Level,
    frame: Frame<'_>,
    flight: Option<crate::quic::kernel::flights::FlightId>,
    probe: bool,
    ack: Option<recovery::AckSnapshot<'book>>,
    now: u64,
) -> Result<Option<wire::Datagram<'book, N>>, Error> {
    if level == Level::OneRtt {
        let keys = keys.application.as_mut().ok_or(Error::Binding)?;
        let mut plaintext = hibana_tls::secret::Secret::new([0u8; N]);
        let len = packet::encode_frame(&frame, &mut plaintext[..])?;
        let bytes = (1 + peer.bytes().len() + 4 + len + 16) as u64;
        let reservation = if let Some(flight) = flight {
            book.reserve_application_crypto(
                &plaintext[..len],
                keys.generation(),
                bytes,
                flight,
                probe,
                now,
            )
        } else {
            book.reserve_application(&plaintext[..len], keys.generation(), bytes, probe, now)
        };
        let reservation = match reservation {
            Ok(value) => value,
            Err(error) if limited(&error) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        return match super::application_wire::seal(
            keys,
            reservation,
            peer.bytes(),
            &plaintext[..len],
        ) {
            Ok(packet) => Ok(Some(wire::Datagram::from_application(packet, ack))),
            Err((error, reservation)) => {
                book.cancel(reservation)?;
                Err(error)
            }
        };
    }
    let ack_eliciting = frame.ack_eliciting();
    let mut ack = ack;
    // An Initial PTO is already authorized by the recovery owner. Include
    // genuinely received ACK-only ranges in this eliciting packet so the peer
    // can detect missing ServerHello packets. This never schedules an ACK in
    // response to an ACK, adds probe credit, or resets the PTO timer.
    let plain = if probe && level == Level::Initial && ack.is_none() {
        if let Some(snapshot) = book.ack_for_packet(level) {
            let extra = Frame::Ack {
                delay: snapshot.encoded_delay(now)?,
                ranges: packet::AckRanges::new(snapshot.ranges())?,
                ecn: snapshot.ecn(),
            };
            match PlainPacket::<N>::with_extra(config, peer, level, frame, Some(extra)) {
                Ok(plain) => {
                    ack = Some(snapshot);
                    plain
                }
                Err(Error::Capacity | Error::Packet(packet::Error::BufferTooShort)) => {
                    PlainPacket::<N>::new(config, peer, level, frame)?
                }
                Err(error) => return Err(error),
            }
        } else {
            PlainPacket::<N>::new(config, peer, level, frame)?
        }
    } else {
        PlainPacket::<N>::new(config, peer, level, frame)?
    };
    let reservation = match book.reserve(
        level,
        plain.len() as u64,
        flight,
        ack_eliciting,
        plain.padded(),
        probe,
        now,
    ) {
        Ok(r) => r,
        Err(e) if limited(&e) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    match plain.seal(keys, reservation, ack) {
        Ok(d) => Ok(Some(d)),
        Err((e, r)) => {
            book.cancel(r)?;
            Err(e)
        }
    }
}
pub(super) enum RecoveryPacket {
    Acknowledgment(crate::quic::kernel::accounting::PacketNumberSpace),
    Probe(crate::quic::kernel::accounting::PacketNumberSpace),
}
pub(super) fn prepare_recovery_packet<'scope, 'book, const N: usize, const P: usize>(
    slots: &Storage<'scope, 'book, N, P>,
    keys: &mut WriteKeys<'_, 'scope>,
    book: &mut recovery::Tx<'book, 'scope, N>,
    config: Config<'_>,
    clock: &impl Clock,
) -> Result<Option<RecoveryPacket>, Error> {
    let peer = *slots.peer.borrow();
    if let Some(ack) = book.pending_ack() {
        let level = ack.level();
        if (level != Level::Initial || keys.initial.available())
            && (level != Level::Handshake || keys.handshake.is_some())
        {
            let frame = Frame::Ack {
                delay: ack.encoded_delay(clock.now())?,
                ranges: packet::AckRanges::new(ack.ranges())?,
                ecn: ack.ecn(),
            };
            // Initial ACK datagrams are already padded to 1200 bytes. Carry
            // retained ServerHello CRYPTO in that padding budget while the peer
            // is still missing it, rather than leaving key availability to an
            // exponentially delayed standalone probe. No loss/acceptance is
            // invented and this remains the existing Hibana ACK publication.
            let flight = if level == Level::Initial {
                book.initial_for_ack()
            } else {
                None
            };
            let data = flight.map(|id| book.flight_data(id)).transpose()?;
            let extra = data.as_ref().map(|data| Frame::Crypto {
                offset: data.offset(),
                data: data.bytes(),
            });
            let (plain, flight) =
                match PlainPacket::<N>::with_extra(config, &peer, level, frame, extra) {
                    Ok(plain) if plain.len() <= 1200 || flight.is_none() => (plain, flight),
                    _ => (PlainPacket::<N>::new(config, &peer, level, frame)?, None),
                };
            let reservation = match book.reserve(
                level,
                plain.len() as u64,
                flight,
                flight.is_some(),
                plain.padded(),
                false,
                clock.now(),
            ) {
                Ok(r) => Some(r),
                Err(e) if limited(&e) => None,
                Err(e) => return Err(e.into()),
            };
            if let Some(r) = reservation {
                let d = match plain.seal(keys, r, Some(ack)) {
                    Ok(d) => d,
                    Err((e, r)) => {
                        book.cancel(r)?;
                        return Err(e);
                    }
                };
                let space = d.reservation.packet().space;
                slots.datagram.put(d)?;
                return Ok(Some(RecoveryPacket::Acknowledgment(space)));
            }
        }
    }
    if let Some((flight, probe)) = book.next_retransmit() {
        let data = book.flight_data(flight)?;
        if data.level() == Level::Initial && !keys.initial.available() {
            return Ok(None);
        }
        if let Some(d) = prepare(
            keys,
            book,
            config,
            &peer,
            data.level(),
            Frame::Crypto {
                offset: data.offset(),
                data: data.bytes(),
            },
            Some(flight),
            probe,
            None,
            clock.now(),
        )? {
            let space = d.reservation.packet().space;
            slots.datagram.put(d)?;
            return Ok(Some(RecoveryPacket::Probe(space)));
        }
    } else if let Some(level) = book.pending_probe() {
        if level == Level::Initial && !keys.initial.available() {
            return Ok(None);
        }
        if let Some(d) = prepare(
            keys,
            book,
            config,
            &peer,
            level,
            Frame::Ping,
            None,
            true,
            None,
            clock.now(),
        )? {
            let space = d.reservation.packet().space;
            slots.datagram.put(d)?;
            return Ok(Some(RecoveryPacket::Probe(space)));
        }
    }
    Ok(None)
}
