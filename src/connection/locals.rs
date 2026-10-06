//! Direct packet RX, recovery/TX and publication local continuations.
//! TLS input ordering is projected from bounded_tls::protocol.
use super::protocol as p;
use super::wire::{PlainPacket, WriteKeys};
use super::*;
use crate::{
    crypto::directional::ApplicationKeyScope,
    packet::{self, Frame, FrameIter, Header, LongType, PacketIter, ParseLimits},
    parameters::{Parameters, Peer},
};
use core::{future::Future, pin::pin};
use hibana::g::Message;
struct ReceiveWire<'keys, 'scope, 'buf, const N: usize> {
    initial: &'keys initial::Keys<'scope>,
    handshake: Option<ReceivePacketKey<'scope>>,
    integrity: IntegrityBudget,
    reassembly: [CryptoBuffer<'buf>; 2],
    largest: [Option<u64>; 2],
    datagram: [u8; N],
    len: usize,
    offset: usize,
    opened: [u8; N],
}
impl<'scope, const N: usize> ReceiveWire<'_, 'scope, '_, N> {
    async fn packet<const P: usize>(
        &mut self,
        io: &mut impl DatagramRx,
        slots: &Storage<'scope, '_, N, P>,
        config: Config<'_>,
        book: &mut recovery::Rx<'_, 'scope, N>,
        clock: &impl Clock,
    ) -> Result<bool, Error> {
        if self.offset >= self.len {
            let len = io.receive(&mut self.datagram).await?;
            if len > N {
                return Err(Error::Capacity);
            }
            self.len = len;
            self.offset = 0;
            book.received_datagram(len as u64)?;
            slots.schedule.changed()?;
        }
        let untrusted = match PacketIter::new(
            &self.datagram[self.offset..self.len],
            config.local_connection_id.len(),
            1,
        )?
        .next()
        {
            Some(Ok(packet)) => packet,
            _ => {
                self.offset = self.len;
                return Ok(true);
            }
        };
        self.offset += untrusted.bytes.len();
        let (level, index, pn_offset, source_id) = match untrusted.header {
            Header::Long {
                kind,
                destination_id,
                source_id,
                packet_number_offset,
                ..
            } => {
                if destination_id != config.local_connection_id
                    && !(config.side == Side::Server
                        && matches!(kind, LongType::Initial | LongType::ZeroRtt)
                        && destination_id
                            == config
                                .retry_source_id
                                .unwrap_or(config.original_destination_id))
                {
                    return Ok(true);
                }
                match kind {
                    LongType::Initial if config.side != Side::Server || self.len >= 1200 => {
                        (Level::Initial, 0, packet_number_offset, source_id)
                    }
                    LongType::Handshake => (Level::Handshake, 1, packet_number_offset, source_id),
                    LongType::ZeroRtt if config.side == Side::Server => {
                        if source_id == slots.peer.borrow().bytes()
                            && let Some(pending) = slots.early_packets.borrow_mut().as_mut()
                        {
                            pending.retain_packet(untrusted.bytes);
                        }
                        return Ok(true);
                    }
                    _ => return Ok(true),
                }
            }
            Header::Short { destination_id, .. } => {
                if destination_id == config.local_connection_id {
                    slots.retain_application(untrusted.bytes)?;
                }
                return Ok(true);
            }
            _ => return Ok(true),
        };
        // Both Initial key access and AEAD end before the retirement edge can await.
        let (authentication, header_len, pn) = {
            let initial_key = self.initial.read();
            let key = if index == 0 {
                match initial_key.as_ref() {
                    Some(key) => key,
                    None => return Ok(true),
                }
            } else {
                match self.handshake.as_ref() {
                    Some(key) => key,
                    None => return Ok(true),
                }
            };
            self.opened[..untrusted.bytes.len()].copy_from_slice(untrusted.bytes);
            let bytes = &mut self.opened[..untrusted.bytes.len()];
            let pn_len = match key.unprotect_header(bytes, pn_offset) {
                Ok(len) => len,
                Err(_) => return Ok(true),
            };
            let (truncated, _) =
                packet::decode_truncated_packet_number(bytes[0], &bytes[pn_offset..])?;
            let pn = packet::restore_packet_number(truncated, pn_len as u8, self.largest[index])?;
            let (header, payload) = bytes.split_at_mut(pn_offset + pn_len);
            let authentication =
                match key.open_authenticated(pn, header, payload, &mut self.integrity) {
                    Ok(receipt) => receipt,
                    Err(crypto::Error::AuthenticationFailed) => return Ok(true),
                    Err(error) => return Err(error.into()),
                };
            packet::validate_reserved_bits(header[0])?;
            (authentication, pn_offset + pn_len, pn)
        };
        let plaintext = &self.opened[header_len..header_len + authentication.len()];
        if self.largest.iter().any(Option::is_some) || config.side == Side::Server {
            if slots.peer.borrow().bytes() != source_id {
                return Err(Error::Binding);
            }
        } else {
            *slots.peer.borrow_mut() = ConnectionId::new(source_id)?;
        }
        self.largest[index] = Some(self.largest[index].map_or(pn, |last| last.max(pn)));
        let outcome = book.apply_packet(authentication, plaintext, clock.now())?;
        slots.schedule.changed()?;
        if !outcome.duplicate {
            for frame in FrameIter::new(
                plaintext,
                if level == Level::Initial {
                    packet::EncryptionLevel::Initial
                } else {
                    packet::EncryptionLevel::Handshake
                },
                ParseLimits::default(),
            )? {
                match frame? {
                    Frame::Crypto { offset, data } => {
                        self.reassembly[index].insert(offset, data)?
                    }
                    Frame::Padding { .. } | Frame::Ping | Frame::Ack { .. } => {}
                    _ => return Err(Error::UnsupportedFrame),
                }
            }
        }
        Ok(true)
    }
}
#[allow(clippy::too_many_arguments)]
pub(super) async fn receive<'scope, const N: usize, const P: usize>(
    endpoint: &mut Endpoint<'_, { p::RX }>,
    stop: &mut Endpoint<'_, { p::RECEIVE_STOP }>,
    io: &mut impl DatagramRx,
    message: &crate::bounded_tls::locals::MessageSlot<'_>,
    slots: &Storage<'scope, '_, N, P>,
    config: Config<'_>,
    initial: &initial::Keys<'scope>,
    exchange: &initial::Exchange<'scope>,
    mut initial_endpoint: Option<&mut Endpoint<'_, { p::INITIAL_EVENT }>>,
    integrity: IntegrityBudget,
    reassembly: [CryptoBuffer<'_>; 2],
    book: &mut recovery::Rx<'_, 'scope, N>,
    clock: &impl Clock,
) -> Result<ReceiveContinuation<'scope, P>, Error> {
    let mut wire = ReceiveWire {
        initial,
        handshake: None,
        integrity,
        reassembly,
        largest: [None; 2],
        datagram: [0; N],
        len: 0,
        offset: 0,
        opened: [0; N],
    };
    use crate::bounded_tls::{locals as direct, protocol as tls};
    struct Input<F>(F);
    impl<F> direct::MessageInput for Input<F>
    where
        F: for<'a> core::ops::AsyncFnMut(Level, &'a mut [u8]) -> Result<usize, direct::Error>,
    {
        async fn read_message(
            &mut self,
            level: Level,
            bytes: &mut [u8],
        ) -> Result<usize, direct::Error> {
            (self.0)(level, bytes).await
        }
    }
    let mut input = Input(async |level: Level, bytes: &mut [u8]| {
        let index = match level {
            Level::Initial => 0,
            Level::Handshake => 1,
            _ => return Err(direct::Error::Binding),
        };
        if index == 1 && wire.handshake.is_none() {
            wire.handshake = Some(
                slots
                    .read_handshake
                    .take()
                    .map_err(|_| direct::Error::Binding)?,
            );
        }
        let mut used = 0;
        let mut target = 4;
        loop {
            let (ready, _) = wire.reassembly[index].ready();
            if !ready.is_empty() {
                if target > bytes.len() {
                    return Err(direct::Error::Capacity);
                }
                let n = ready.len().min(target - used);
                bytes[used..used + n].copy_from_slice(&ready[..n]);
                wire.reassembly[index]
                    .consume(n)
                    .map_err(|_| direct::Error::Binding)?;
                used += n;
                if used == 4 && target == 4 {
                    target = 4
                        + ((bytes[1] as usize) << 16)
                        + ((bytes[2] as usize) << 8)
                        + bytes[3] as usize;
                }
                if target > bytes.len() {
                    return Err(direct::Error::Capacity);
                }
                if used == target {
                    return Ok(used);
                }
            } else {
                wire.packet(io, slots, config, book, clock)
                    .await
                    .map_err(|_| direct::Error::Binding)?;
                if let Some(endpoint) = initial_endpoint.as_deref_mut()
                    && let Some(evidence) = book.take_initial_retirement()
                {
                    async {
                        let scope = evidence.scope();
                        let event = evidence.event();
                        exchange.event.put(evidence)?;
                        match event {
                            recovery::InitialRetirementEvent::ClientHandshakeAccepted => {
                                endpoint.send::<p::ClientInitialRetire>(&()).await?
                            }
                            recovery::InitialRetirementEvent::ServerHandshakeAuthenticated => {
                                endpoint.send::<p::ServerInitialRetire>(&()).await?
                            }
                        }
                        endpoint.recv::<p::InitialRetired>().await?;
                        let proof = exchange.retired.take()?;
                        if !core::ptr::eq(proof.scope(), scope) || proof.event() != event {
                            return Err(Error::Binding);
                        }
                        Ok::<(), Error>(())
                    }
                    .await
                    .map_err(|_| direct::Error::Binding)?;
                }
                crate::runtime::yield_now().await;
            }
        }
    });
    let (application, finished, peer) = {
        // The stop role is independent and must receive from the beginning.
        // Otherwise its queued message can block the TLS completion message
        // needed by RX on a bounded carrier.
        let mut stopping = pin!(stop.recv::<p::StopReceive>());
        let first = {
            let mut tls_input = pin!(async {
                let selected = endpoint.offer().await?;
                match config.side {
                    Side::Client => {
                        selected.recv::<tls::ClientStart>().await?;
                        direct::client_input(endpoint, message, &mut input)
                            .await
                            .map_err(Error::Transcript)?;
                    }
                    Side::Server => {
                        selected.recv::<tls::ServerStart>().await?;
                        direct::server_input(endpoint, message, &mut input)
                            .await
                            .map_err(Error::Transcript)?;
                    }
                }
                Ok::<(), Error>(())
            });
            let first = poll_fn(|cx| {
                if let Poll::Ready(result) = stopping.as_mut().poll(cx) {
                    return Poll::Ready(
                        result
                            .map(core::ops::ControlFlow::Break)
                            .map_err(Error::from),
                    );
                }
                tls_input
                    .as_mut()
                    .poll(cx)
                    .map(|result| result.map(core::ops::ControlFlow::Continue))
            })
            .await?;
            // Receiving the stop does not abandon an in-flight TLS exchange.
            // Consume its actual completion before returning owned keys.
            if let core::ops::ControlFlow::Break(_) = first {
                tls_input.await?;
            }
            first
        };
        drop(input);
        let application = slots.read_application.take()?;
        let finished = slots.finished.take()?;
        let peer = *slots.peer.borrow();
        if !finished
            .receipt()
            .authenticates_peer_parameters(finished.parameters())
        {
            return Err(Error::Binding);
        }
        let parameters = Parameters::parse(
            finished.parameters(),
            if config.side == Side::Client {
                Peer::Server
            } else {
                Peer::Client
            },
            &mut [0; 64],
        )
        .map_err(|_| Error::Binding)?;
        parameters
            .verify_connection_ids(
                peer.bytes(),
                if config.side == Side::Client {
                    Some(config.original_destination_id)
                } else {
                    None
                },
                if config.side == Side::Client {
                    config.retry_source_id
                } else {
                    None
                },
            )
            .map_err(|_| Error::Binding)?;
        // Keep the projected stop receive alive across every packet poll. A
        // pending native receive is cancelled only after that message is read.
        match first {
            core::ops::ControlFlow::Break(()) => (),
            core::ops::ControlFlow::Continue(()) => {
                let mut draining = pin!(async {
                    loop {
                        // TLS input has completed. Once the handoff slot owns
                        // application ciphertext, stop taking more native input
                        // merely to discard it. The independently polled
                        // StopReceive still joins this finite role. Applying this
                        // backpressure before TLS completion would be incorrect:
                        // a reordered short packet must not block Finished.
                        if slots.pending_application.borrow().is_some() {
                            core::future::pending::<()>().await;
                        }
                        wire.packet(io, slots, config, book, clock).await?;
                        if let Some(endpoint) = initial_endpoint.as_deref_mut()
                            && let Some(evidence) = book.take_initial_retirement()
                        {
                            async {
                                let scope = evidence.scope();
                                let event = evidence.event();
                                exchange.event.put(evidence)?;
                                match event {
        recovery::InitialRetirementEvent::ClientHandshakeAccepted => {
            endpoint.send::<p::ClientInitialRetire>(&()).await?
        }
        recovery::InitialRetirementEvent::ServerHandshakeAuthenticated => {
            endpoint.send::<p::ServerInitialRetire>(&()).await?
        }
    }
                                endpoint.recv::<p::InitialRetired>().await?;
                                let proof = exchange.retired.take()?;
                                if !core::ptr::eq(proof.scope(), scope) || proof.event() != event {
                                    return Err(Error::Binding);
                                }
                                Ok::<(), Error>(())
                            }
                            .await?;
                        }
                        crate::runtime::yield_now().await;
                    }
                    #[allow(unreachable_code)]
                    Ok::<(), Error>(())
                });
                poll_fn(|cx| {
                    if let Poll::Ready(result) = stopping.as_mut().poll(cx) {
                        return Poll::Ready(result.map_err(Error::from));
                    }
                    match draining.as_mut().poll(cx) {
                        Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => Poll::Ready(Err(Error::Binding)),
                        Poll::Pending => Poll::Pending,
                    }
                })
                .await?
            }
        };
        (application, finished, peer)
    };
    // A received stop cancels the next native wait, not bytes already owned
    // by this role. Preserve coalesced application ciphertext before handoff.
    while wire.offset < wire.len {
        wire.packet(io, slots, config, book, clock).await?;
        if let Some(endpoint) = initial_endpoint.as_deref_mut()
            && let Some(evidence) = book.take_initial_retirement()
        {
            async {
                let scope = evidence.scope();
                let event = evidence.event();
                exchange.event.put(evidence)?;
                match event {
                    recovery::InitialRetirementEvent::ClientHandshakeAccepted => {
                        endpoint.send::<p::ClientInitialRetire>(&()).await?
                    }
                    recovery::InitialRetirementEvent::ServerHandshakeAuthenticated => {
                        endpoint.send::<p::ServerInitialRetire>(&()).await?
                    }
                }
                endpoint.recv::<p::InitialRetired>().await?;
                let proof = exchange.retired.take()?;
                if !core::ptr::eq(proof.scope(), scope) || proof.event() != event {
                    return Err(Error::Binding);
                }
                Ok::<(), Error>(())
            }
            .await?;
        }
    }
    stop.send::<p::ReceiveStopped>(&()).await?;
    endpoint.send::<p::ReceiveComplete>(&()).await?;
    endpoint.recv::<p::ReceiveContinuation>().await?;
    // Recovery reconciliation: the last pre-loss peer field is now initialized.
    // This and the bounded packet-loop yields above require fresh validation.
    let verified_consumed = [wire.reassembly[0].consumed(), wire.reassembly[1].consumed()];
    Ok(ReceiveContinuation {
        verified_consumed,
        initial: None,
        handshake: wire.handshake.ok_or(Error::Binding)?,
        application,
        integrity: wire.integrity,
        finished,
        largest_received: wire.largest,
        peer,
    })
}
fn limited(error: &recovery::Error) -> bool {
    matches!(
        error,
        recovery::Error::CongestionLimited
            | recovery::Error::Accounting(crate::accounting::AccountingError::AmplificationLimited)
    )
}
#[allow(clippy::too_many_arguments)]
fn prepare<'book, 'scope, const N: usize>(
    keys: &mut WriteKeys<'_, 'scope>,
    book: &mut recovery::Tx<'book, 'scope, N>,
    config: Config<'_>,
    peer: &ConnectionId,
    level: Level,
    frame: Frame<'_>,
    flight: Option<crate::flights::FlightId>,
    probe: bool,
    ack: Option<recovery::AckSnapshot<'book>>,
    now: u64,
) -> Result<Option<wire::Datagram<'book, N>>, Error> {
    if level == Level::OneRtt {
        let keys = keys.application.as_mut().ok_or(Error::Binding)?;
        let mut plaintext = zeroize::Zeroizing::new([0u8; N]);
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
    let plain = PlainPacket::<N>::new(config, peer, level, frame)?;
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
enum RecoveryPacket {
    Acknowledgment(crate::accounting::PacketNumberSpace),
    Probe(crate::accounting::PacketNumberSpace),
}
fn prepare_recovery_packet<'scope, 'book, const N: usize, const P: usize>(
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
                delay: 0,
                ranges: packet::AckRanges::new(ack.ranges())?,
                ecn: None,
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

#[allow(clippy::too_many_arguments)]
pub(super) async fn transmit<'scope, 'book, const N: usize, const P: usize>(
    endpoint: &mut Endpoint<'_, { p::TX }>,
    output: &mut Endpoint<'_, { p::TX_WIRE }>,
    slots: &Storage<'scope, 'book, N, P>,
    config: Config<'_>,
    scope: &'scope ApplicationKeyScope,
    initial: &initial::Keys<'scope>,
    keys: &RefCell<WriteKeys<'_, 'scope>>,
    book: &mut recovery::Tx<'book, 'scope, N>,
    clock: &impl Clock,
) -> Result<TransmitContinuation<'scope>, Error> {
    // InitialTransmit: the projected source and publication exchanges are explicit.
    'initial: {
        loop {
            if let Some(packet) = {
                let mut owned = keys.borrow_mut();
                prepare_recovery_packet::<N, P>(slots, &mut owned, book, config, clock)?
            } {
                match packet {
                    RecoveryPacket::Acknowledgment(space) => {
                        let is_initial = space == crate::accounting::PacketNumberSpace::Initial;
                        output.send::<p::InitialAckDatagram>(&()).await?;
                        let result = output.offer().await.map_err(|error| Error::EndpointAt {
                            role: p::TX_WIRE,
                            expected_label: p::InitialAckAccepted::LOGICAL_LABEL,
                            error,
                        })?;
                        let accepted = match result.label() {
                            label if label == p::InitialAckAccepted::LOGICAL_LABEL => {
                                result.recv::<p::InitialAckAccepted>().await?;
                                true
                            }
                            label if label == p::InitialAckRejected::LOGICAL_LABEL => {
                                result.recv::<p::InitialAckRejected>().await?;
                                false
                            }
                            label => return Err(Error::UnexpectedLabel(label)),
                        };
                        output.send::<p::InitialAckSettled>(&()).await?;
                        crate::runtime::yield_now().await;
                        if !accepted && (!is_initial || initial.available()) {
                            return Err(Error::Io(IoError::Rejected));
                        }
                    }
                    RecoveryPacket::Probe(space) => {
                        let is_initial = space == crate::accounting::PacketNumberSpace::Initial;
                        output.send::<p::InitialProbeDatagram>(&()).await?;
                        let result = output.offer().await.map_err(|error| Error::EndpointAt {
                            role: p::TX_WIRE,
                            expected_label: p::InitialProbeAccepted::LOGICAL_LABEL,
                            error,
                        })?;
                        let accepted = match result.label() {
                            label if label == p::InitialProbeAccepted::LOGICAL_LABEL => {
                                result.recv::<p::InitialProbeAccepted>().await?;
                                true
                            }
                            label if label == p::InitialProbeRejected::LOGICAL_LABEL => {
                                result.recv::<p::InitialProbeRejected>().await?;
                                false
                            }
                            label => return Err(Error::UnexpectedLabel(label)),
                        };
                        output.send::<p::InitialProbeSettled>(&()).await?;
                        crate::runtime::yield_now().await;
                        if !accepted && (!is_initial || initial.available()) {
                            return Err(Error::Io(IoError::Rejected));
                        }
                    }
                };
                continue;
            }
            let revision = slots.schedule.revision.get();
            endpoint.send::<p::InitialRequest>(&()).await?;
            let response = endpoint.offer().await.map_err(|error| Error::EndpointAt {
                role: p::TX,
                expected_label: p::InitialFlight::LOGICAL_LABEL,
                error,
            })?;
            if response.label() == p::InitialBoundary::LOGICAL_LABEL {
                response.recv::<p::InitialBoundary>().await?;
                output.send::<p::InitialWireBoundary>(&()).await?;
                output.recv::<p::InitialWireBoundarySeen>().await?;
                endpoint.send::<p::InitialPhaseSettled>(&()).await?;

                break 'initial;
            }
            match response.label() {
                label if label == p::InitialFlight::LOGICAL_LABEL => {
                    response.recv::<p::InitialFlight>().await?;
                    let flight = slots.flight.take()?;
                    endpoint.send::<p::InitialTaken>(&()).await?;
                    let mut offset = 0;
                    while offset < flight.bytes().len() {
                        if flight.level() == Level::Initial && !initial.available() {
                            break;
                        }
                        let count = (flight.bytes().len() - offset).min(N - 128);
                        let at = flight.offset() + offset as u64;
                        let bytes = &flight.bytes()[offset..offset + count];
                        let retained = book.store_crypto(flight.level(), at, bytes)?;
                        loop {
                            if flight.level() == Level::Initial && !initial.available() {
                                break;
                            }
                            let revision = slots.schedule.revision.get();
                            let peer = *slots.peer.borrow();
                            let prepared_space = {
                                match prepare(
                                    &mut keys.borrow_mut(),
                                    book,
                                    config,
                                    &peer,
                                    flight.level(),
                                    Frame::Crypto {
                                        offset: at,
                                        data: bytes,
                                    },
                                    Some(retained),
                                    false,
                                    None,
                                    clock.now(),
                                )? {
                                    Some(d) => {
                                        let space = d.reservation.packet().space;
                                        slots.datagram.put(d)?;
                                        Some(space)
                                    }
                                    None => None,
                                }
                            };
                            if let Some(space) = prepared_space {
                                {
                                    let is_initial =
                                        space == crate::accounting::PacketNumberSpace::Initial;
                                    output.send::<p::InitialDataDatagram>(&()).await?;
                                    let result = output.offer().await.map_err(|error| {
                                        Error::EndpointAt {
                                            role: p::TX_WIRE,
                                            expected_label: p::InitialDataAccepted::LOGICAL_LABEL,
                                            error,
                                        }
                                    })?;
                                    let accepted = match result.label() {
                                        label if label == p::InitialDataAccepted::LOGICAL_LABEL => {
                                            result.recv::<p::InitialDataAccepted>().await?;
                                            true
                                        }
                                        label if label == p::InitialDataRejected::LOGICAL_LABEL => {
                                            result.recv::<p::InitialDataRejected>().await?;
                                            false
                                        }
                                        label => return Err(Error::UnexpectedLabel(label)),
                                    };
                                    output.send::<p::InitialDataSettled>(&()).await?;
                                    crate::runtime::yield_now().await;
                                    if !accepted && (!is_initial || initial.available()) {
                                        return Err(Error::Io(IoError::Rejected));
                                    }
                                }
                                break;
                            }
                            if let Some(packet) = {
                                let mut owned = keys.borrow_mut();
                                prepare_recovery_packet::<N, P>(
                                    slots, &mut owned, book, config, clock,
                                )?
                            } {
                                match packet {
                                    RecoveryPacket::Acknowledgment(space) => {
                                        let is_initial =
                                            space == crate::accounting::PacketNumberSpace::Initial;
                                        output.send::<p::InitialAckDatagram>(&()).await?;
                                        let result = output.offer().await.map_err(|error| {
                                            Error::EndpointAt {
                                                role: p::TX_WIRE,
                                                expected_label:
                                                    p::InitialAckAccepted::LOGICAL_LABEL,
                                                error,
                                            }
                                        })?;
                                        let accepted = match result.label() {
                                            label
                                                if label
                                                    == p::InitialAckAccepted::LOGICAL_LABEL =>
                                            {
                                                result.recv::<p::InitialAckAccepted>().await?;
                                                true
                                            }
                                            label
                                                if label
                                                    == p::InitialAckRejected::LOGICAL_LABEL =>
                                            {
                                                result.recv::<p::InitialAckRejected>().await?;
                                                false
                                            }
                                            label => return Err(Error::UnexpectedLabel(label)),
                                        };
                                        output.send::<p::InitialAckSettled>(&()).await?;
                                        crate::runtime::yield_now().await;
                                        if !accepted && (!is_initial || initial.available()) {
                                            return Err(Error::Io(IoError::Rejected));
                                        }
                                    }
                                    RecoveryPacket::Probe(space) => {
                                        let is_initial =
                                            space == crate::accounting::PacketNumberSpace::Initial;
                                        output.send::<p::InitialProbeDatagram>(&()).await?;
                                        let result = output.offer().await.map_err(|error| {
                                            Error::EndpointAt {
                                                role: p::TX_WIRE,
                                                expected_label:
                                                    p::InitialProbeAccepted::LOGICAL_LABEL,
                                                error,
                                            }
                                        })?;
                                        let accepted = match result.label() {
                                            label
                                                if label
                                                    == p::InitialProbeAccepted::LOGICAL_LABEL =>
                                            {
                                                result.recv::<p::InitialProbeAccepted>().await?;
                                                true
                                            }
                                            label
                                                if label
                                                    == p::InitialProbeRejected::LOGICAL_LABEL =>
                                            {
                                                result.recv::<p::InitialProbeRejected>().await?;
                                                false
                                            }
                                            label => return Err(Error::UnexpectedLabel(label)),
                                        };
                                        output.send::<p::InitialProbeSettled>(&()).await?;
                                        crate::runtime::yield_now().await;
                                        if !accepted && (!is_initial || initial.available()) {
                                            return Err(Error::Io(IoError::Rejected));
                                        }
                                    }
                                }
                            } else {
                                slots.schedule.wait_changed(1, revision).await;
                            }
                        }
                        offset += count;
                    }
                }
                label if label == p::InitialIdle::LOGICAL_LABEL => {
                    response.recv::<p::InitialIdle>().await?;
                    endpoint.send::<p::InitialTaken>(&()).await?;
                    slots.schedule.wait_changed(1, revision).await;
                }
                label => return Err(Error::UnexpectedLabel(label)),
            }

            crate::runtime::yield_now().await;
        }
    }
    endpoint.recv::<p::WriteHandshake>().await?;
    let handshake = slots.write_handshake.take()?;
    if !core::ptr::eq(scope, handshake.scope()) {
        return Err(Error::Binding);
    }
    keys.borrow_mut().handshake = Some(handshake);
    slots.schedule.changed()?;

    // HandshakeTransmit: the projected source and publication exchanges are explicit.
    'handshake: {
        loop {
            if let Some(packet) = {
                let mut owned = keys.borrow_mut();
                prepare_recovery_packet::<N, P>(slots, &mut owned, book, config, clock)?
            } {
                match packet {
                    RecoveryPacket::Acknowledgment(space) => {
                        let is_initial = space == crate::accounting::PacketNumberSpace::Initial;
                        output.send::<p::HandshakeAckDatagram>(&()).await?;
                        let result = output.offer().await.map_err(|error| Error::EndpointAt {
                            role: p::TX_WIRE,
                            expected_label: p::HandshakeAckAccepted::LOGICAL_LABEL,
                            error,
                        })?;
                        let accepted = match result.label() {
                            label if label == p::HandshakeAckAccepted::LOGICAL_LABEL => {
                                result.recv::<p::HandshakeAckAccepted>().await?;
                                true
                            }
                            label if label == p::HandshakeAckRejected::LOGICAL_LABEL => {
                                result.recv::<p::HandshakeAckRejected>().await?;
                                false
                            }
                            label => return Err(Error::UnexpectedLabel(label)),
                        };
                        output.send::<p::HandshakeAckSettled>(&()).await?;
                        crate::runtime::yield_now().await;
                        if !accepted && (!is_initial || initial.available()) {
                            return Err(Error::Io(IoError::Rejected));
                        }
                    }
                    RecoveryPacket::Probe(space) => {
                        let is_initial = space == crate::accounting::PacketNumberSpace::Initial;
                        output.send::<p::HandshakeProbeDatagram>(&()).await?;
                        let result = output.offer().await.map_err(|error| Error::EndpointAt {
                            role: p::TX_WIRE,
                            expected_label: p::HandshakeProbeAccepted::LOGICAL_LABEL,
                            error,
                        })?;
                        let accepted = match result.label() {
                            label if label == p::HandshakeProbeAccepted::LOGICAL_LABEL => {
                                result.recv::<p::HandshakeProbeAccepted>().await?;
                                true
                            }
                            label if label == p::HandshakeProbeRejected::LOGICAL_LABEL => {
                                result.recv::<p::HandshakeProbeRejected>().await?;
                                false
                            }
                            label => return Err(Error::UnexpectedLabel(label)),
                        };
                        output.send::<p::HandshakeProbeSettled>(&()).await?;
                        crate::runtime::yield_now().await;
                        if !accepted && (!is_initial || initial.available()) {
                            return Err(Error::Io(IoError::Rejected));
                        }
                    }
                };
                continue;
            }
            let revision = slots.schedule.revision.get();
            endpoint.send::<p::HandshakeRequest>(&()).await?;
            let response = endpoint.offer().await.map_err(|error| Error::EndpointAt {
                role: p::TX,
                expected_label: p::HandshakeFlight::LOGICAL_LABEL,
                error,
            })?;
            if response.label() == p::HandshakeBoundary::LOGICAL_LABEL {
                response.recv::<p::HandshakeBoundary>().await?;
                output.send::<p::HandshakeWireBoundary>(&()).await?;
                output.recv::<p::HandshakeWireBoundarySeen>().await?;
                endpoint.send::<p::HandshakePhaseSettled>(&()).await?;

                break 'handshake;
            }
            match response.label() {
                label if label == p::HandshakeFlight::LOGICAL_LABEL => {
                    response.recv::<p::HandshakeFlight>().await?;
                    let flight = slots.flight.take()?;
                    endpoint.send::<p::HandshakeTaken>(&()).await?;
                    let mut offset = 0;
                    while offset < flight.bytes().len() {
                        if flight.level() == Level::Initial && !initial.available() {
                            break;
                        }
                        let count = (flight.bytes().len() - offset).min(N - 128);
                        let at = flight.offset() + offset as u64;
                        let bytes = &flight.bytes()[offset..offset + count];
                        let retained = book.store_crypto(flight.level(), at, bytes)?;
                        loop {
                            if flight.level() == Level::Initial && !initial.available() {
                                break;
                            }
                            let revision = slots.schedule.revision.get();
                            let peer = *slots.peer.borrow();
                            let prepared_space = {
                                match prepare(
                                    &mut keys.borrow_mut(),
                                    book,
                                    config,
                                    &peer,
                                    flight.level(),
                                    Frame::Crypto {
                                        offset: at,
                                        data: bytes,
                                    },
                                    Some(retained),
                                    false,
                                    None,
                                    clock.now(),
                                )? {
                                    Some(d) => {
                                        let space = d.reservation.packet().space;
                                        slots.datagram.put(d)?;
                                        Some(space)
                                    }
                                    None => None,
                                }
                            };
                            if let Some(space) = prepared_space {
                                {
                                    let is_initial =
                                        space == crate::accounting::PacketNumberSpace::Initial;
                                    output.send::<p::HandshakeDataDatagram>(&()).await?;
                                    let result = output.offer().await.map_err(|error| {
                                        Error::EndpointAt {
                                            role: p::TX_WIRE,
                                            expected_label: p::HandshakeDataAccepted::LOGICAL_LABEL,
                                            error,
                                        }
                                    })?;
                                    let accepted = match result.label() {
                                        label
                                            if label == p::HandshakeDataAccepted::LOGICAL_LABEL =>
                                        {
                                            result.recv::<p::HandshakeDataAccepted>().await?;
                                            true
                                        }
                                        label
                                            if label == p::HandshakeDataRejected::LOGICAL_LABEL =>
                                        {
                                            result.recv::<p::HandshakeDataRejected>().await?;
                                            false
                                        }
                                        label => return Err(Error::UnexpectedLabel(label)),
                                    };
                                    output.send::<p::HandshakeDataSettled>(&()).await?;
                                    crate::runtime::yield_now().await;
                                    if !accepted && (!is_initial || initial.available()) {
                                        return Err(Error::Io(IoError::Rejected));
                                    }
                                }
                                break;
                            }
                            if let Some(packet) = {
                                let mut owned = keys.borrow_mut();
                                prepare_recovery_packet::<N, P>(
                                    slots, &mut owned, book, config, clock,
                                )?
                            } {
                                match packet {
                                    RecoveryPacket::Acknowledgment(space) => {
                                        let is_initial =
                                            space == crate::accounting::PacketNumberSpace::Initial;
                                        output.send::<p::HandshakeAckDatagram>(&()).await?;
                                        let result = output.offer().await.map_err(|error| {
                                            Error::EndpointAt {
                                                role: p::TX_WIRE,
                                                expected_label:
                                                    p::HandshakeAckAccepted::LOGICAL_LABEL,
                                                error,
                                            }
                                        })?;
                                        let accepted = match result.label() {
                                            label
                                                if label
                                                    == p::HandshakeAckAccepted::LOGICAL_LABEL =>
                                            {
                                                result.recv::<p::HandshakeAckAccepted>().await?;
                                                true
                                            }
                                            label
                                                if label
                                                    == p::HandshakeAckRejected::LOGICAL_LABEL =>
                                            {
                                                result.recv::<p::HandshakeAckRejected>().await?;
                                                false
                                            }
                                            label => return Err(Error::UnexpectedLabel(label)),
                                        };
                                        output.send::<p::HandshakeAckSettled>(&()).await?;
                                        crate::runtime::yield_now().await;
                                        if !accepted && (!is_initial || initial.available()) {
                                            return Err(Error::Io(IoError::Rejected));
                                        }
                                    }
                                    RecoveryPacket::Probe(space) => {
                                        let is_initial =
                                            space == crate::accounting::PacketNumberSpace::Initial;
                                        output.send::<p::HandshakeProbeDatagram>(&()).await?;
                                        let result = output.offer().await.map_err(|error| {
                                            Error::EndpointAt {
                                                role: p::TX_WIRE,
                                                expected_label:
                                                    p::HandshakeProbeAccepted::LOGICAL_LABEL,
                                                error,
                                            }
                                        })?;
                                        let accepted = match result.label() {
                                            label
                                                if label
                                                    == p::HandshakeProbeAccepted::LOGICAL_LABEL =>
                                            {
                                                result.recv::<p::HandshakeProbeAccepted>().await?;
                                                true
                                            }
                                            label
                                                if label
                                                    == p::HandshakeProbeRejected::LOGICAL_LABEL =>
                                            {
                                                result.recv::<p::HandshakeProbeRejected>().await?;
                                                false
                                            }
                                            label => return Err(Error::UnexpectedLabel(label)),
                                        };
                                        output.send::<p::HandshakeProbeSettled>(&()).await?;
                                        crate::runtime::yield_now().await;
                                        if !accepted && (!is_initial || initial.available()) {
                                            return Err(Error::Io(IoError::Rejected));
                                        }
                                    }
                                }
                            } else {
                                slots.schedule.wait_changed(1, revision).await;
                            }
                        }
                        offset += count;
                    }
                }
                label if label == p::HandshakeIdle::LOGICAL_LABEL => {
                    response.recv::<p::HandshakeIdle>().await?;
                    endpoint.send::<p::HandshakeTaken>(&()).await?;
                    slots.schedule.wait_changed(1, revision).await;
                }
                label => return Err(Error::UnexpectedLabel(label)),
            }

            crate::runtime::yield_now().await;
        }
    }
    endpoint.recv::<p::WriteApplication>().await?;
    let application = slots.write_application.take()?;
    if !core::ptr::eq(scope, application.scope()) {
        return Err(Error::Binding);
    }
    keys.borrow_mut().application = Some(application);

    // ApplicationTransmit: the projected source and publication exchanges are explicit.
    'application: {
        loop {
            if let Some(packet) = {
                let mut owned = keys.borrow_mut();
                prepare_recovery_packet::<N, P>(slots, &mut owned, book, config, clock)?
            } {
                match packet {
                    RecoveryPacket::Acknowledgment(space) => {
                        let is_initial = space == crate::accounting::PacketNumberSpace::Initial;
                        output.send::<p::ApplicationAckDatagram>(&()).await?;
                        let result = output.offer().await.map_err(|error| Error::EndpointAt {
                            role: p::TX_WIRE,
                            expected_label: p::ApplicationAckAccepted::LOGICAL_LABEL,
                            error,
                        })?;
                        let accepted = match result.label() {
                            label if label == p::ApplicationAckAccepted::LOGICAL_LABEL => {
                                result.recv::<p::ApplicationAckAccepted>().await?;
                                true
                            }
                            label if label == p::ApplicationAckRejected::LOGICAL_LABEL => {
                                result.recv::<p::ApplicationAckRejected>().await?;
                                false
                            }
                            label => return Err(Error::UnexpectedLabel(label)),
                        };
                        output.send::<p::ApplicationAckSettled>(&()).await?;
                        crate::runtime::yield_now().await;
                        if !accepted && (!is_initial || initial.available()) {
                            return Err(Error::Io(IoError::Rejected));
                        }
                    }
                    RecoveryPacket::Probe(space) => {
                        let is_initial = space == crate::accounting::PacketNumberSpace::Initial;
                        output.send::<p::ApplicationProbeDatagram>(&()).await?;
                        let result = output.offer().await.map_err(|error| Error::EndpointAt {
                            role: p::TX_WIRE,
                            expected_label: p::ApplicationProbeAccepted::LOGICAL_LABEL,
                            error,
                        })?;
                        let accepted = match result.label() {
                            label if label == p::ApplicationProbeAccepted::LOGICAL_LABEL => {
                                result.recv::<p::ApplicationProbeAccepted>().await?;
                                true
                            }
                            label if label == p::ApplicationProbeRejected::LOGICAL_LABEL => {
                                result.recv::<p::ApplicationProbeRejected>().await?;
                                false
                            }
                            label => return Err(Error::UnexpectedLabel(label)),
                        };
                        output.send::<p::ApplicationProbeSettled>(&()).await?;
                        crate::runtime::yield_now().await;
                        if !accepted && (!is_initial || initial.available()) {
                            return Err(Error::Io(IoError::Rejected));
                        }
                    }
                };
                continue;
            }
            let revision = slots.schedule.revision.get();
            endpoint.send::<p::ApplicationRequest>(&()).await?;
            let response = endpoint.offer().await.map_err(|error| Error::EndpointAt {
                role: p::TX,
                expected_label: p::ApplicationFlight::LOGICAL_LABEL,
                error,
            })?;
            if response.label() == p::ApplicationBoundary::LOGICAL_LABEL {
                response.recv::<p::ApplicationBoundary>().await?;
                output.send::<p::ApplicationWireBoundary>(&()).await?;
                output.recv::<p::ApplicationWireBoundarySeen>().await?;
                endpoint.send::<p::ApplicationPhaseSettled>(&()).await?;

                break 'application;
            }
            match response.label() {
                label if label == p::ApplicationFlight::LOGICAL_LABEL => {
                    response.recv::<p::ApplicationFlight>().await?;
                    let flight = slots.flight.take()?;
                    endpoint.send::<p::ApplicationTaken>(&()).await?;
                    let mut offset = 0;
                    while offset < flight.bytes().len() {
                        if flight.level() == Level::Initial && !initial.available() {
                            break;
                        }
                        let count = (flight.bytes().len() - offset).min(N - 128);
                        let at = flight.offset() + offset as u64;
                        let bytes = &flight.bytes()[offset..offset + count];
                        let retained = book.store_crypto(flight.level(), at, bytes)?;
                        loop {
                            if flight.level() == Level::Initial && !initial.available() {
                                break;
                            }
                            let revision = slots.schedule.revision.get();
                            let peer = *slots.peer.borrow();
                            let prepared_space = {
                                match prepare(
                                    &mut keys.borrow_mut(),
                                    book,
                                    config,
                                    &peer,
                                    flight.level(),
                                    Frame::Crypto {
                                        offset: at,
                                        data: bytes,
                                    },
                                    Some(retained),
                                    false,
                                    None,
                                    clock.now(),
                                )? {
                                    Some(d) => {
                                        let space = d.reservation.packet().space;
                                        slots.datagram.put(d)?;
                                        Some(space)
                                    }
                                    None => None,
                                }
                            };
                            if let Some(space) = prepared_space {
                                {
                                    let is_initial =
                                        space == crate::accounting::PacketNumberSpace::Initial;
                                    output.send::<p::ApplicationDataDatagram>(&()).await?;
                                    let result = output.offer().await.map_err(|error| {
                                        Error::EndpointAt {
                                            role: p::TX_WIRE,
                                            expected_label:
                                                p::ApplicationDataAccepted::LOGICAL_LABEL,
                                            error,
                                        }
                                    })?;
                                    let accepted = match result.label() {
                                        label
                                            if label
                                                == p::ApplicationDataAccepted::LOGICAL_LABEL =>
                                        {
                                            result.recv::<p::ApplicationDataAccepted>().await?;
                                            true
                                        }
                                        label
                                            if label
                                                == p::ApplicationDataRejected::LOGICAL_LABEL =>
                                        {
                                            result.recv::<p::ApplicationDataRejected>().await?;
                                            false
                                        }
                                        label => return Err(Error::UnexpectedLabel(label)),
                                    };
                                    output.send::<p::ApplicationDataSettled>(&()).await?;
                                    crate::runtime::yield_now().await;
                                    if !accepted && (!is_initial || initial.available()) {
                                        return Err(Error::Io(IoError::Rejected));
                                    }
                                }
                                break;
                            }
                            if let Some(packet) = {
                                let mut owned = keys.borrow_mut();
                                prepare_recovery_packet::<N, P>(
                                    slots, &mut owned, book, config, clock,
                                )?
                            } {
                                match packet {
                                    RecoveryPacket::Acknowledgment(space) => {
                                        let is_initial =
                                            space == crate::accounting::PacketNumberSpace::Initial;
                                        output.send::<p::ApplicationAckDatagram>(&()).await?;
                                        let result = output.offer().await.map_err(|error| {
                                            Error::EndpointAt {
                                                role: p::TX_WIRE,
                                                expected_label:
                                                    p::ApplicationAckAccepted::LOGICAL_LABEL,
                                                error,
                                            }
                                        })?;
                                        let accepted = match result.label() {
                                            label
                                                if label
                                                    == p::ApplicationAckAccepted::LOGICAL_LABEL =>
                                            {
                                                result.recv::<p::ApplicationAckAccepted>().await?;
                                                true
                                            }
                                            label
                                                if label
                                                    == p::ApplicationAckRejected::LOGICAL_LABEL =>
                                            {
                                                result.recv::<p::ApplicationAckRejected>().await?;
                                                false
                                            }
                                            label => return Err(Error::UnexpectedLabel(label)),
                                        };
                                        output.send::<p::ApplicationAckSettled>(&()).await?;
                                        crate::runtime::yield_now().await;
                                        if !accepted && (!is_initial || initial.available()) {
                                            return Err(Error::Io(IoError::Rejected));
                                        }
                                    }
                                    RecoveryPacket::Probe(space) => {
                                        let is_initial =
                                            space == crate::accounting::PacketNumberSpace::Initial;
                                        output.send::<p::ApplicationProbeDatagram>(&()).await?;
                                        let result = output.offer().await.map_err(|error| {
                                            Error::EndpointAt {
                                                role: p::TX_WIRE,
                                                expected_label:
                                                    p::ApplicationProbeAccepted::LOGICAL_LABEL,
                                                error,
                                            }
                                        })?;
                                        let accepted = match result.label() {
        label if label == p::ApplicationProbeAccepted::LOGICAL_LABEL => {
            result.recv::<p::ApplicationProbeAccepted>().await?;
            true
        }
        label if label == p::ApplicationProbeRejected::LOGICAL_LABEL => {
            result.recv::<p::ApplicationProbeRejected>().await?;
            false
        }
        label => return Err(Error::UnexpectedLabel(label)),
    };
                                        output.send::<p::ApplicationProbeSettled>(&()).await?;
                                        crate::runtime::yield_now().await;
                                        if !accepted && (!is_initial || initial.available()) {
                                            return Err(Error::Io(IoError::Rejected));
                                        }
                                    }
                                }
                            } else {
                                slots.schedule.wait_changed(1, revision).await;
                            }
                        }
                        offset += count;
                    }
                }
                label if label == p::ApplicationIdle::LOGICAL_LABEL => {
                    response.recv::<p::ApplicationIdle>().await?;
                    endpoint.send::<p::ApplicationTaken>(&()).await?;
                    slots.schedule.wait_changed(1, revision).await;
                }
                label => return Err(Error::UnexpectedLabel(label)),
            }

            crate::runtime::yield_now().await;
        }
    }
    loop {
        let revision = slots.schedule.revision.get();
        if let Some(packet) = {
            let mut owned = keys.borrow_mut();
            prepare_recovery_packet::<N, P>(slots, &mut owned, book, config, clock)?
        } {
            match packet {
                RecoveryPacket::Acknowledgment(space) => {
                    let is_initial = space == crate::accounting::PacketNumberSpace::Initial;
                    output.send::<p::DrainAckDatagram>(&()).await?;
                    let result = output.offer().await.map_err(|error| Error::EndpointAt {
                        role: p::TX_WIRE,
                        expected_label: p::DrainAckAccepted::LOGICAL_LABEL,
                        error,
                    })?;
                    let accepted = match result.label() {
                        label if label == p::DrainAckAccepted::LOGICAL_LABEL => {
                            result.recv::<p::DrainAckAccepted>().await?;
                            true
                        }
                        label if label == p::DrainAckRejected::LOGICAL_LABEL => {
                            result.recv::<p::DrainAckRejected>().await?;
                            false
                        }
                        label => return Err(Error::UnexpectedLabel(label)),
                    };
                    output.send::<p::DrainAckSettled>(&()).await?;
                    crate::runtime::yield_now().await;
                    if !accepted && (!is_initial || initial.available()) {
                        return Err(Error::Io(IoError::Rejected));
                    }
                }
                RecoveryPacket::Probe(space) => {
                    let is_initial = space == crate::accounting::PacketNumberSpace::Initial;
                    output.send::<p::DrainProbeDatagram>(&()).await?;
                    let result = output.offer().await.map_err(|error| Error::EndpointAt {
                        role: p::TX_WIRE,
                        expected_label: p::DrainProbeAccepted::LOGICAL_LABEL,
                        error,
                    })?;
                    let accepted = match result.label() {
                        label if label == p::DrainProbeAccepted::LOGICAL_LABEL => {
                            result.recv::<p::DrainProbeAccepted>().await?;
                            true
                        }
                        label if label == p::DrainProbeRejected::LOGICAL_LABEL => {
                            result.recv::<p::DrainProbeRejected>().await?;
                            false
                        }
                        label => return Err(Error::UnexpectedLabel(label)),
                    };
                    output.send::<p::DrainProbeSettled>(&()).await?;
                    crate::runtime::yield_now().await;
                    if !accepted && (!is_initial || initial.available()) {
                        return Err(Error::Io(IoError::Rejected));
                    }
                }
            };
            continue;
        } // Unacknowledged Handshake CRYPTO must transfer to the application roles:
        // HANDSHAKE_DONE confirms it even when the explicit Finished ACK was lost.
        if book.pending_ack().is_none() {
            break;
        }
        slots.schedule.wait_changed(1, revision).await;
    }
    output.send::<p::HandshakeRecoveryTransferred>(&()).await?;
    // Stop prefix input at its explicit handoff boundary, before unrelated
    // timer/adapter retirement can prolong that finite receive ownership.
    output.send::<p::StopReceive>(&()).await?;
    output.recv::<p::ReceiveStopped>().await?;
    output.send::<p::StopTimer>(&()).await?;
    output.recv::<p::TimerStopped>().await?;
    endpoint.send::<p::TransmitComplete>(&()).await?;
    endpoint.recv::<p::TransmitContinuation>().await?;
    output.send::<p::AdapterComplete>(&()).await?;
    output.recv::<p::AdapterRetired>().await?;
    let (handshake, application) = {
        let mut owned = keys.borrow_mut();
        (
            owned.handshake.take().ok_or(Error::Binding)?,
            owned.application.take().ok_or(Error::Binding)?,
        )
    };
    Ok(TransmitContinuation {
        initial: None,
        handshake,
        application,
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn publish<'scope, 'book, const N: usize, const P: usize>(
    endpoint: &mut Endpoint<'_, { p::UDP }>,
    io: &mut impl DatagramTx,
    slots: &Storage<'scope, 'book, N, P>,
    initial: &initial::Keys<'scope>,
    exchange: &initial::Exchange<'scope>,
    mut initial_endpoint: Option<&mut Endpoint<'_, { p::INITIAL_EVENT }>>,
    issuer: &mut publication_gate::Issuer<'_, 'scope>,
    outcome: &Outcome,
    book: &mut recovery::Publication<'book, 'scope, N>,
) -> Result<(), Error> {
    // InitialTransmit: actual UDP acceptance selects the declared reply.
    'initial: {
        loop {
            let input = endpoint.offer().await.map_err(|error| Error::EndpointAt {
                role: p::UDP,
                expected_label: p::InitialDataDatagram::LOGICAL_LABEL,
                error,
            })?;
            match input.label() {
                label if label == p::InitialAckDatagram::LOGICAL_LABEL => {
                    input.recv::<p::InitialAckDatagram>().await?;
                    {
                        let wire::Datagram {
                            sealed,
                            reservation,
                            acknowledgment,
                        } = slots.datagram.take()?;
                        let permit = match issuer.begin() {
                            Ok(p) => p,
                            Err(e) => {
                                book.cancel(reservation)?;
                                return Err(e.into());
                            }
                        };
                        if !core::ptr::eq(permit.scope(), reservation.scope()) {
                            book.cancel(reservation)?;
                            return Err(Error::Binding);
                        }
                        let is_initial = reservation.packet().space
                            == crate::accounting::PacketNumberSpace::Initial;
                        let result = if is_initial {
                            initial.submit(permit.submit(io.send(sealed.bytes()))).await
                        } else {
                            Some(permit.submit(io.send(sealed.bytes())).await)
                        };
                        let accepted_at = match result {
                            Some(Ok(Ok(at))) => Some(at),
                            _ => None,
                        };
                        book.settle(recovery::Completion::from_adapter(reservation, accepted_at))?;
                        if accepted_at.is_some()
                            && let Some(ack) = acknowledgment
                        {
                            book.acknowledgment_sent(ack)?;
                        }
                        slots.schedule.changed()?;
                        if let Some(endpoint) = initial_endpoint.as_deref_mut()
                            && let Some(evidence) = book.take_initial_retirement()
                        {
                            async {
                                let scope = evidence.scope();
                                let event = evidence.event();
                                exchange.event.put(evidence)?;
                                match event {
        recovery::InitialRetirementEvent::ClientHandshakeAccepted => {
            endpoint.send::<p::ClientInitialRetire>(&()).await?
        }
        recovery::InitialRetirementEvent::ServerHandshakeAuthenticated => {
            endpoint.send::<p::ServerInitialRetire>(&()).await?
        }
    }
                                endpoint.recv::<p::InitialRetired>().await?;
                                let proof = exchange.retired.take()?;
                                if !core::ptr::eq(proof.scope(), scope) || proof.event() != event {
                                    return Err(Error::Binding);
                                }
                                Ok::<(), Error>(())
                            }
                            .await?;
                        }
                        outcome.set(accepted_at.is_some())?;
                        match outcome.resolver::<{ p::ADAPTER_RESULT }>().decide()? {
                            DecisionArm::Left => {
                                endpoint.send::<p::InitialAckAccepted>(&()).await?
                            }
                            DecisionArm::Right => {
                                endpoint.send::<p::InitialAckRejected>(&()).await?
                            }
                        };
                        endpoint.recv::<p::InitialAckSettled>().await?;
                        outcome.clear();
                        match result {
                            None | Some(Ok(Ok(_))) => Ok::<(), Error>(()),
                            Some(_) if is_initial && !initial.available() => Ok(()),
                            Some(Ok(Err(e))) => Err(e.into()),
                            Some(Err(e)) => Err(e.into()),
                        }?;
                    }
                }
                label if label == p::InitialProbeDatagram::LOGICAL_LABEL => {
                    input.recv::<p::InitialProbeDatagram>().await?;
                    {
                        let wire::Datagram {
                            sealed,
                            reservation,
                            acknowledgment,
                        } = slots.datagram.take()?;
                        let permit = match issuer.begin() {
                            Ok(p) => p,
                            Err(e) => {
                                book.cancel(reservation)?;
                                return Err(e.into());
                            }
                        };
                        if !core::ptr::eq(permit.scope(), reservation.scope()) {
                            book.cancel(reservation)?;
                            return Err(Error::Binding);
                        }
                        let is_initial = reservation.packet().space
                            == crate::accounting::PacketNumberSpace::Initial;
                        let result = if is_initial {
                            initial.submit(permit.submit(io.send(sealed.bytes()))).await
                        } else {
                            Some(permit.submit(io.send(sealed.bytes())).await)
                        };
                        let accepted_at = match result {
                            Some(Ok(Ok(at))) => Some(at),
                            _ => None,
                        };
                        book.settle(recovery::Completion::from_adapter(reservation, accepted_at))?;
                        if accepted_at.is_some()
                            && let Some(ack) = acknowledgment
                        {
                            book.acknowledgment_sent(ack)?;
                        }
                        slots.schedule.changed()?;
                        if let Some(endpoint) = initial_endpoint.as_deref_mut()
                            && let Some(evidence) = book.take_initial_retirement()
                        {
                            async {
                                let scope = evidence.scope();
                                let event = evidence.event();
                                exchange.event.put(evidence)?;
                                match event {
        recovery::InitialRetirementEvent::ClientHandshakeAccepted => {
            endpoint.send::<p::ClientInitialRetire>(&()).await?
        }
        recovery::InitialRetirementEvent::ServerHandshakeAuthenticated => {
            endpoint.send::<p::ServerInitialRetire>(&()).await?
        }
    }
                                endpoint.recv::<p::InitialRetired>().await?;
                                let proof = exchange.retired.take()?;
                                if !core::ptr::eq(proof.scope(), scope) || proof.event() != event {
                                    return Err(Error::Binding);
                                }
                                Ok::<(), Error>(())
                            }
                            .await?;
                        }
                        outcome.set(accepted_at.is_some())?;
                        match outcome.resolver::<{ p::ADAPTER_RESULT }>().decide()? {
                            DecisionArm::Left => {
                                endpoint.send::<p::InitialProbeAccepted>(&()).await?
                            }
                            DecisionArm::Right => {
                                endpoint.send::<p::InitialProbeRejected>(&()).await?
                            }
                        };
                        endpoint.recv::<p::InitialProbeSettled>().await?;
                        outcome.clear();
                        match result {
                            None | Some(Ok(Ok(_))) => Ok::<(), Error>(()),
                            Some(_) if is_initial && !initial.available() => Ok(()),
                            Some(Ok(Err(e))) => Err(e.into()),
                            Some(Err(e)) => Err(e.into()),
                        }?;
                    }
                }
                label if label == p::InitialDataDatagram::LOGICAL_LABEL => {
                    input.recv::<p::InitialDataDatagram>().await?;
                    {
                        let wire::Datagram {
                            sealed,
                            reservation,
                            acknowledgment,
                        } = slots.datagram.take()?;
                        let permit = match issuer.begin() {
                            Ok(p) => p,
                            Err(e) => {
                                book.cancel(reservation)?;
                                return Err(e.into());
                            }
                        };
                        if !core::ptr::eq(permit.scope(), reservation.scope()) {
                            book.cancel(reservation)?;
                            return Err(Error::Binding);
                        }
                        let is_initial = reservation.packet().space
                            == crate::accounting::PacketNumberSpace::Initial;
                        let result = if is_initial {
                            initial.submit(permit.submit(io.send(sealed.bytes()))).await
                        } else {
                            Some(permit.submit(io.send(sealed.bytes())).await)
                        };
                        let accepted_at = match result {
                            Some(Ok(Ok(at))) => Some(at),
                            _ => None,
                        };
                        book.settle(recovery::Completion::from_adapter(reservation, accepted_at))?;
                        if accepted_at.is_some()
                            && let Some(ack) = acknowledgment
                        {
                            book.acknowledgment_sent(ack)?;
                        }
                        slots.schedule.changed()?;
                        if let Some(endpoint) = initial_endpoint.as_deref_mut()
                            && let Some(evidence) = book.take_initial_retirement()
                        {
                            async {
                                let scope = evidence.scope();
                                let event = evidence.event();
                                exchange.event.put(evidence)?;
                                match event {
        recovery::InitialRetirementEvent::ClientHandshakeAccepted => {
            endpoint.send::<p::ClientInitialRetire>(&()).await?
        }
        recovery::InitialRetirementEvent::ServerHandshakeAuthenticated => {
            endpoint.send::<p::ServerInitialRetire>(&()).await?
        }
    }
                                endpoint.recv::<p::InitialRetired>().await?;
                                let proof = exchange.retired.take()?;
                                if !core::ptr::eq(proof.scope(), scope) || proof.event() != event {
                                    return Err(Error::Binding);
                                }
                                Ok::<(), Error>(())
                            }
                            .await?;
                        }
                        outcome.set(accepted_at.is_some())?;
                        match outcome.resolver::<{ p::ADAPTER_RESULT }>().decide()? {
                            DecisionArm::Left => {
                                endpoint.send::<p::InitialDataAccepted>(&()).await?
                            }
                            DecisionArm::Right => {
                                endpoint.send::<p::InitialDataRejected>(&()).await?
                            }
                        };
                        endpoint.recv::<p::InitialDataSettled>().await?;
                        outcome.clear();
                        match result {
                            None | Some(Ok(Ok(_))) => Ok::<(), Error>(()),
                            Some(_) if is_initial && !initial.available() => Ok(()),
                            Some(Ok(Err(e))) => Err(e.into()),
                            Some(Err(e)) => Err(e.into()),
                        }?;
                    }
                }
                label if label == p::InitialWireBoundary::LOGICAL_LABEL => {
                    input.recv::<p::InitialWireBoundary>().await?;
                    endpoint.send::<p::InitialWireBoundarySeen>(&()).await?;
                    break 'initial;
                }
                label => return Err(Error::UnexpectedLabel(label)),
            }
            crate::runtime::yield_now().await;
        }
    }

    // HandshakeTransmit: actual UDP acceptance selects the declared reply.
    'handshake: {
        loop {
            let input = endpoint.offer().await.map_err(|error| Error::EndpointAt {
                role: p::UDP,
                expected_label: p::HandshakeDataDatagram::LOGICAL_LABEL,
                error,
            })?;
            match input.label() {
                label if label == p::HandshakeAckDatagram::LOGICAL_LABEL => {
                    input.recv::<p::HandshakeAckDatagram>().await?;
                    {
                        let wire::Datagram {
                            sealed,
                            reservation,
                            acknowledgment,
                        } = slots.datagram.take()?;
                        let permit = match issuer.begin() {
                            Ok(p) => p,
                            Err(e) => {
                                book.cancel(reservation)?;
                                return Err(e.into());
                            }
                        };
                        if !core::ptr::eq(permit.scope(), reservation.scope()) {
                            book.cancel(reservation)?;
                            return Err(Error::Binding);
                        }
                        let is_initial = reservation.packet().space
                            == crate::accounting::PacketNumberSpace::Initial;
                        let result = if is_initial {
                            initial.submit(permit.submit(io.send(sealed.bytes()))).await
                        } else {
                            Some(permit.submit(io.send(sealed.bytes())).await)
                        };
                        let accepted_at = match result {
                            Some(Ok(Ok(at))) => Some(at),
                            _ => None,
                        };
                        book.settle(recovery::Completion::from_adapter(reservation, accepted_at))?;
                        if accepted_at.is_some()
                            && let Some(ack) = acknowledgment
                        {
                            book.acknowledgment_sent(ack)?;
                        }
                        slots.schedule.changed()?;
                        if let Some(endpoint) = initial_endpoint.as_deref_mut()
                            && let Some(evidence) = book.take_initial_retirement()
                        {
                            async {
                                let scope = evidence.scope();
                                let event = evidence.event();
                                exchange.event.put(evidence)?;
                                match event {
        recovery::InitialRetirementEvent::ClientHandshakeAccepted => {
            endpoint.send::<p::ClientInitialRetire>(&()).await?
        }
        recovery::InitialRetirementEvent::ServerHandshakeAuthenticated => {
            endpoint.send::<p::ServerInitialRetire>(&()).await?
        }
    }
                                endpoint.recv::<p::InitialRetired>().await?;
                                let proof = exchange.retired.take()?;
                                if !core::ptr::eq(proof.scope(), scope) || proof.event() != event {
                                    return Err(Error::Binding);
                                }
                                Ok::<(), Error>(())
                            }
                            .await?;
                        }
                        outcome.set(accepted_at.is_some())?;
                        match outcome.resolver::<{ p::ADAPTER_RESULT }>().decide()? {
                            DecisionArm::Left => {
                                endpoint.send::<p::HandshakeAckAccepted>(&()).await?
                            }
                            DecisionArm::Right => {
                                endpoint.send::<p::HandshakeAckRejected>(&()).await?
                            }
                        };
                        endpoint.recv::<p::HandshakeAckSettled>().await?;
                        outcome.clear();
                        match result {
                            None | Some(Ok(Ok(_))) => Ok::<(), Error>(()),
                            Some(_) if is_initial && !initial.available() => Ok(()),
                            Some(Ok(Err(e))) => Err(e.into()),
                            Some(Err(e)) => Err(e.into()),
                        }?;
                    }
                }
                label if label == p::HandshakeProbeDatagram::LOGICAL_LABEL => {
                    input.recv::<p::HandshakeProbeDatagram>().await?;
                    {
                        let wire::Datagram {
                            sealed,
                            reservation,
                            acknowledgment,
                        } = slots.datagram.take()?;
                        let permit = match issuer.begin() {
                            Ok(p) => p,
                            Err(e) => {
                                book.cancel(reservation)?;
                                return Err(e.into());
                            }
                        };
                        if !core::ptr::eq(permit.scope(), reservation.scope()) {
                            book.cancel(reservation)?;
                            return Err(Error::Binding);
                        }
                        let is_initial = reservation.packet().space
                            == crate::accounting::PacketNumberSpace::Initial;
                        let result = if is_initial {
                            initial.submit(permit.submit(io.send(sealed.bytes()))).await
                        } else {
                            Some(permit.submit(io.send(sealed.bytes())).await)
                        };
                        let accepted_at = match result {
                            Some(Ok(Ok(at))) => Some(at),
                            _ => None,
                        };
                        book.settle(recovery::Completion::from_adapter(reservation, accepted_at))?;
                        if accepted_at.is_some()
                            && let Some(ack) = acknowledgment
                        {
                            book.acknowledgment_sent(ack)?;
                        }
                        slots.schedule.changed()?;
                        if let Some(endpoint) = initial_endpoint.as_deref_mut()
                            && let Some(evidence) = book.take_initial_retirement()
                        {
                            async {
                                let scope = evidence.scope();
                                let event = evidence.event();
                                exchange.event.put(evidence)?;
                                match event {
        recovery::InitialRetirementEvent::ClientHandshakeAccepted => {
            endpoint.send::<p::ClientInitialRetire>(&()).await?
        }
        recovery::InitialRetirementEvent::ServerHandshakeAuthenticated => {
            endpoint.send::<p::ServerInitialRetire>(&()).await?
        }
    }
                                endpoint.recv::<p::InitialRetired>().await?;
                                let proof = exchange.retired.take()?;
                                if !core::ptr::eq(proof.scope(), scope) || proof.event() != event {
                                    return Err(Error::Binding);
                                }
                                Ok::<(), Error>(())
                            }
                            .await?;
                        }
                        outcome.set(accepted_at.is_some())?;
                        match outcome.resolver::<{ p::ADAPTER_RESULT }>().decide()? {
                            DecisionArm::Left => {
                                endpoint.send::<p::HandshakeProbeAccepted>(&()).await?
                            }
                            DecisionArm::Right => {
                                endpoint.send::<p::HandshakeProbeRejected>(&()).await?
                            }
                        };
                        endpoint.recv::<p::HandshakeProbeSettled>().await?;
                        outcome.clear();
                        match result {
                            None | Some(Ok(Ok(_))) => Ok::<(), Error>(()),
                            Some(_) if is_initial && !initial.available() => Ok(()),
                            Some(Ok(Err(e))) => Err(e.into()),
                            Some(Err(e)) => Err(e.into()),
                        }?;
                    }
                }
                label if label == p::HandshakeDataDatagram::LOGICAL_LABEL => {
                    input.recv::<p::HandshakeDataDatagram>().await?;
                    {
                        let wire::Datagram {
                            sealed,
                            reservation,
                            acknowledgment,
                        } = slots.datagram.take()?;
                        let permit = match issuer.begin() {
                            Ok(p) => p,
                            Err(e) => {
                                book.cancel(reservation)?;
                                return Err(e.into());
                            }
                        };
                        if !core::ptr::eq(permit.scope(), reservation.scope()) {
                            book.cancel(reservation)?;
                            return Err(Error::Binding);
                        }
                        let is_initial = reservation.packet().space
                            == crate::accounting::PacketNumberSpace::Initial;
                        let result = if is_initial {
                            initial.submit(permit.submit(io.send(sealed.bytes()))).await
                        } else {
                            Some(permit.submit(io.send(sealed.bytes())).await)
                        };
                        let accepted_at = match result {
                            Some(Ok(Ok(at))) => Some(at),
                            _ => None,
                        };
                        book.settle(recovery::Completion::from_adapter(reservation, accepted_at))?;
                        if accepted_at.is_some()
                            && let Some(ack) = acknowledgment
                        {
                            book.acknowledgment_sent(ack)?;
                        }
                        slots.schedule.changed()?;
                        if let Some(endpoint) = initial_endpoint.as_deref_mut()
                            && let Some(evidence) = book.take_initial_retirement()
                        {
                            async {
                                let scope = evidence.scope();
                                let event = evidence.event();
                                exchange.event.put(evidence)?;
                                match event {
        recovery::InitialRetirementEvent::ClientHandshakeAccepted => {
            endpoint.send::<p::ClientInitialRetire>(&()).await?
        }
        recovery::InitialRetirementEvent::ServerHandshakeAuthenticated => {
            endpoint.send::<p::ServerInitialRetire>(&()).await?
        }
    }
                                endpoint.recv::<p::InitialRetired>().await?;
                                let proof = exchange.retired.take()?;
                                if !core::ptr::eq(proof.scope(), scope) || proof.event() != event {
                                    return Err(Error::Binding);
                                }
                                Ok::<(), Error>(())
                            }
                            .await?;
                        }
                        outcome.set(accepted_at.is_some())?;
                        match outcome.resolver::<{ p::ADAPTER_RESULT }>().decide()? {
                            DecisionArm::Left => {
                                endpoint.send::<p::HandshakeDataAccepted>(&()).await?
                            }
                            DecisionArm::Right => {
                                endpoint.send::<p::HandshakeDataRejected>(&()).await?
                            }
                        };
                        endpoint.recv::<p::HandshakeDataSettled>().await?;
                        outcome.clear();
                        match result {
                            None | Some(Ok(Ok(_))) => Ok::<(), Error>(()),
                            Some(_) if is_initial && !initial.available() => Ok(()),
                            Some(Ok(Err(e))) => Err(e.into()),
                            Some(Err(e)) => Err(e.into()),
                        }?;
                    }
                }
                label if label == p::HandshakeWireBoundary::LOGICAL_LABEL => {
                    input.recv::<p::HandshakeWireBoundary>().await?;
                    endpoint.send::<p::HandshakeWireBoundarySeen>(&()).await?;
                    break 'handshake;
                }
                label => return Err(Error::UnexpectedLabel(label)),
            }
            crate::runtime::yield_now().await;
        }
    }

    // ApplicationTransmit: actual UDP acceptance selects the declared reply.
    'application: {
        loop {
            let input = endpoint.offer().await.map_err(|error| Error::EndpointAt {
                role: p::UDP,
                expected_label: p::ApplicationDataDatagram::LOGICAL_LABEL,
                error,
            })?;
            match input.label() {
                label if label == p::ApplicationAckDatagram::LOGICAL_LABEL => {
                    input.recv::<p::ApplicationAckDatagram>().await?;
                    {
                        let wire::Datagram {
                            sealed,
                            reservation,
                            acknowledgment,
                        } = slots.datagram.take()?;
                        let permit = match issuer.begin() {
                            Ok(p) => p,
                            Err(e) => {
                                book.cancel(reservation)?;
                                return Err(e.into());
                            }
                        };
                        if !core::ptr::eq(permit.scope(), reservation.scope()) {
                            book.cancel(reservation)?;
                            return Err(Error::Binding);
                        }
                        let is_initial = reservation.packet().space
                            == crate::accounting::PacketNumberSpace::Initial;
                        let result = if is_initial {
                            initial.submit(permit.submit(io.send(sealed.bytes()))).await
                        } else {
                            Some(permit.submit(io.send(sealed.bytes())).await)
                        };
                        let accepted_at = match result {
                            Some(Ok(Ok(at))) => Some(at),
                            _ => None,
                        };
                        book.settle(recovery::Completion::from_adapter(reservation, accepted_at))?;
                        if accepted_at.is_some()
                            && let Some(ack) = acknowledgment
                        {
                            book.acknowledgment_sent(ack)?;
                        }
                        slots.schedule.changed()?;
                        if let Some(endpoint) = initial_endpoint.as_deref_mut()
                            && let Some(evidence) = book.take_initial_retirement()
                        {
                            async {
                                let scope = evidence.scope();
                                let event = evidence.event();
                                exchange.event.put(evidence)?;
                                match event {
        recovery::InitialRetirementEvent::ClientHandshakeAccepted => {
            endpoint.send::<p::ClientInitialRetire>(&()).await?
        }
        recovery::InitialRetirementEvent::ServerHandshakeAuthenticated => {
            endpoint.send::<p::ServerInitialRetire>(&()).await?
        }
    }
                                endpoint.recv::<p::InitialRetired>().await?;
                                let proof = exchange.retired.take()?;
                                if !core::ptr::eq(proof.scope(), scope) || proof.event() != event {
                                    return Err(Error::Binding);
                                }
                                Ok::<(), Error>(())
                            }
                            .await?;
                        }
                        outcome.set(accepted_at.is_some())?;
                        match outcome.resolver::<{ p::ADAPTER_RESULT }>().decide()? {
                            DecisionArm::Left => {
                                endpoint.send::<p::ApplicationAckAccepted>(&()).await?
                            }
                            DecisionArm::Right => {
                                endpoint.send::<p::ApplicationAckRejected>(&()).await?
                            }
                        };
                        endpoint.recv::<p::ApplicationAckSettled>().await?;
                        outcome.clear();
                        match result {
                            None | Some(Ok(Ok(_))) => Ok::<(), Error>(()),
                            Some(_) if is_initial && !initial.available() => Ok(()),
                            Some(Ok(Err(e))) => Err(e.into()),
                            Some(Err(e)) => Err(e.into()),
                        }?;
                    }
                }
                label if label == p::ApplicationProbeDatagram::LOGICAL_LABEL => {
                    input.recv::<p::ApplicationProbeDatagram>().await?;
                    {
                        let wire::Datagram {
                            sealed,
                            reservation,
                            acknowledgment,
                        } = slots.datagram.take()?;
                        let permit = match issuer.begin() {
                            Ok(p) => p,
                            Err(e) => {
                                book.cancel(reservation)?;
                                return Err(e.into());
                            }
                        };
                        if !core::ptr::eq(permit.scope(), reservation.scope()) {
                            book.cancel(reservation)?;
                            return Err(Error::Binding);
                        }
                        let is_initial = reservation.packet().space
                            == crate::accounting::PacketNumberSpace::Initial;
                        let result = if is_initial {
                            initial.submit(permit.submit(io.send(sealed.bytes()))).await
                        } else {
                            Some(permit.submit(io.send(sealed.bytes())).await)
                        };
                        let accepted_at = match result {
                            Some(Ok(Ok(at))) => Some(at),
                            _ => None,
                        };
                        book.settle(recovery::Completion::from_adapter(reservation, accepted_at))?;
                        if accepted_at.is_some()
                            && let Some(ack) = acknowledgment
                        {
                            book.acknowledgment_sent(ack)?;
                        }
                        slots.schedule.changed()?;
                        if let Some(endpoint) = initial_endpoint.as_deref_mut()
                            && let Some(evidence) = book.take_initial_retirement()
                        {
                            async {
                                let scope = evidence.scope();
                                let event = evidence.event();
                                exchange.event.put(evidence)?;
                                match event {
        recovery::InitialRetirementEvent::ClientHandshakeAccepted => {
            endpoint.send::<p::ClientInitialRetire>(&()).await?
        }
        recovery::InitialRetirementEvent::ServerHandshakeAuthenticated => {
            endpoint.send::<p::ServerInitialRetire>(&()).await?
        }
    }
                                endpoint.recv::<p::InitialRetired>().await?;
                                let proof = exchange.retired.take()?;
                                if !core::ptr::eq(proof.scope(), scope) || proof.event() != event {
                                    return Err(Error::Binding);
                                }
                                Ok::<(), Error>(())
                            }
                            .await?;
                        }
                        outcome.set(accepted_at.is_some())?;
                        match outcome.resolver::<{ p::ADAPTER_RESULT }>().decide()? {
                            DecisionArm::Left => {
                                endpoint.send::<p::ApplicationProbeAccepted>(&()).await?
                            }
                            DecisionArm::Right => {
                                endpoint.send::<p::ApplicationProbeRejected>(&()).await?
                            }
                        };
                        endpoint.recv::<p::ApplicationProbeSettled>().await?;
                        outcome.clear();
                        match result {
                            None | Some(Ok(Ok(_))) => Ok::<(), Error>(()),
                            Some(_) if is_initial && !initial.available() => Ok(()),
                            Some(Ok(Err(e))) => Err(e.into()),
                            Some(Err(e)) => Err(e.into()),
                        }?;
                    }
                }
                label if label == p::ApplicationDataDatagram::LOGICAL_LABEL => {
                    input.recv::<p::ApplicationDataDatagram>().await?;
                    {
                        let wire::Datagram {
                            sealed,
                            reservation,
                            acknowledgment,
                        } = slots.datagram.take()?;
                        let permit = match issuer.begin() {
                            Ok(p) => p,
                            Err(e) => {
                                book.cancel(reservation)?;
                                return Err(e.into());
                            }
                        };
                        if !core::ptr::eq(permit.scope(), reservation.scope()) {
                            book.cancel(reservation)?;
                            return Err(Error::Binding);
                        }
                        let is_initial = reservation.packet().space
                            == crate::accounting::PacketNumberSpace::Initial;
                        let result = if is_initial {
                            initial.submit(permit.submit(io.send(sealed.bytes()))).await
                        } else {
                            Some(permit.submit(io.send(sealed.bytes())).await)
                        };
                        let accepted_at = match result {
                            Some(Ok(Ok(at))) => Some(at),
                            _ => None,
                        };
                        book.settle(recovery::Completion::from_adapter(reservation, accepted_at))?;
                        if accepted_at.is_some()
                            && let Some(ack) = acknowledgment
                        {
                            book.acknowledgment_sent(ack)?;
                        }
                        slots.schedule.changed()?;
                        if let Some(endpoint) = initial_endpoint.as_deref_mut()
                            && let Some(evidence) = book.take_initial_retirement()
                        {
                            async {
                                let scope = evidence.scope();
                                let event = evidence.event();
                                exchange.event.put(evidence)?;
                                match event {
        recovery::InitialRetirementEvent::ClientHandshakeAccepted => {
            endpoint.send::<p::ClientInitialRetire>(&()).await?
        }
        recovery::InitialRetirementEvent::ServerHandshakeAuthenticated => {
            endpoint.send::<p::ServerInitialRetire>(&()).await?
        }
    }
                                endpoint.recv::<p::InitialRetired>().await?;
                                let proof = exchange.retired.take()?;
                                if !core::ptr::eq(proof.scope(), scope) || proof.event() != event {
                                    return Err(Error::Binding);
                                }
                                Ok::<(), Error>(())
                            }
                            .await?;
                        }
                        outcome.set(accepted_at.is_some())?;
                        match outcome.resolver::<{ p::ADAPTER_RESULT }>().decide()? {
                            DecisionArm::Left => {
                                endpoint.send::<p::ApplicationDataAccepted>(&()).await?
                            }
                            DecisionArm::Right => {
                                endpoint.send::<p::ApplicationDataRejected>(&()).await?
                            }
                        };
                        endpoint.recv::<p::ApplicationDataSettled>().await?;
                        outcome.clear();
                        match result {
                            None | Some(Ok(Ok(_))) => Ok::<(), Error>(()),
                            Some(_) if is_initial && !initial.available() => Ok(()),
                            Some(Ok(Err(e))) => Err(e.into()),
                            Some(Err(e)) => Err(e.into()),
                        }?;
                    }
                }
                label if label == p::ApplicationWireBoundary::LOGICAL_LABEL => {
                    input.recv::<p::ApplicationWireBoundary>().await?;
                    endpoint.send::<p::ApplicationWireBoundarySeen>(&()).await?;
                    break 'application;
                }
                label => return Err(Error::UnexpectedLabel(label)),
            }
            crate::runtime::yield_now().await;
        }
    }
    loop {
        let input = endpoint.offer().await.map_err(|error| Error::EndpointAt {
            role: p::UDP,
            expected_label: p::DrainAckDatagram::LOGICAL_LABEL,
            error,
        })?;
        match input.label() {
            label if label == p::DrainAckDatagram::LOGICAL_LABEL => {
                input.recv::<p::DrainAckDatagram>().await?;
                {
                    let wire::Datagram {
                        sealed,
                        reservation,
                        acknowledgment,
                    } = slots.datagram.take()?;
                    let permit = match issuer.begin() {
                        Ok(p) => p,
                        Err(e) => {
                            book.cancel(reservation)?;
                            return Err(e.into());
                        }
                    };
                    if !core::ptr::eq(permit.scope(), reservation.scope()) {
                        book.cancel(reservation)?;
                        return Err(Error::Binding);
                    }
                    let is_initial =
                        reservation.packet().space == crate::accounting::PacketNumberSpace::Initial;
                    let result = if is_initial {
                        initial.submit(permit.submit(io.send(sealed.bytes()))).await
                    } else {
                        Some(permit.submit(io.send(sealed.bytes())).await)
                    };
                    let accepted_at = match result {
                        Some(Ok(Ok(at))) => Some(at),
                        _ => None,
                    };
                    book.settle(recovery::Completion::from_adapter(reservation, accepted_at))?;
                    if accepted_at.is_some()
                        && let Some(ack) = acknowledgment
                    {
                        book.acknowledgment_sent(ack)?;
                    }
                    slots.schedule.changed()?;
                    if let Some(endpoint) = initial_endpoint.as_deref_mut()
                        && let Some(evidence) = book.take_initial_retirement()
                    {
                        async {
                            let scope = evidence.scope();
                            let event = evidence.event();
                            exchange.event.put(evidence)?;
                            match event {
                                recovery::InitialRetirementEvent::ClientHandshakeAccepted => {
                                    endpoint.send::<p::ClientInitialRetire>(&()).await?
                                }
                                recovery::InitialRetirementEvent::ServerHandshakeAuthenticated => {
                                    endpoint.send::<p::ServerInitialRetire>(&()).await?
                                }
                            }
                            endpoint.recv::<p::InitialRetired>().await?;
                            let proof = exchange.retired.take()?;
                            if !core::ptr::eq(proof.scope(), scope) || proof.event() != event {
                                return Err(Error::Binding);
                            }
                            Ok::<(), Error>(())
                        }
                        .await?;
                    }
                    outcome.set(accepted_at.is_some())?;
                    match outcome.resolver::<{ p::ADAPTER_RESULT }>().decide()? {
                        DecisionArm::Left => endpoint.send::<p::DrainAckAccepted>(&()).await?,
                        DecisionArm::Right => endpoint.send::<p::DrainAckRejected>(&()).await?,
                    };
                    endpoint.recv::<p::DrainAckSettled>().await?;
                    outcome.clear();
                    match result {
                        None | Some(Ok(Ok(_))) => Ok::<(), Error>(()),
                        Some(_) if is_initial && !initial.available() => Ok(()),
                        Some(Ok(Err(e))) => Err(e.into()),
                        Some(Err(e)) => Err(e.into()),
                    }?;
                }
            }
            label if label == p::DrainProbeDatagram::LOGICAL_LABEL => {
                input.recv::<p::DrainProbeDatagram>().await?;
                {
                    let wire::Datagram {
                        sealed,
                        reservation,
                        acknowledgment,
                    } = slots.datagram.take()?;
                    let permit = match issuer.begin() {
                        Ok(p) => p,
                        Err(e) => {
                            book.cancel(reservation)?;
                            return Err(e.into());
                        }
                    };
                    if !core::ptr::eq(permit.scope(), reservation.scope()) {
                        book.cancel(reservation)?;
                        return Err(Error::Binding);
                    }
                    let is_initial =
                        reservation.packet().space == crate::accounting::PacketNumberSpace::Initial;
                    let result = if is_initial {
                        initial.submit(permit.submit(io.send(sealed.bytes()))).await
                    } else {
                        Some(permit.submit(io.send(sealed.bytes())).await)
                    };
                    let accepted_at = match result {
                        Some(Ok(Ok(at))) => Some(at),
                        _ => None,
                    };
                    book.settle(recovery::Completion::from_adapter(reservation, accepted_at))?;
                    if accepted_at.is_some()
                        && let Some(ack) = acknowledgment
                    {
                        book.acknowledgment_sent(ack)?;
                    }
                    slots.schedule.changed()?;
                    if let Some(endpoint) = initial_endpoint.as_deref_mut()
                        && let Some(evidence) = book.take_initial_retirement()
                    {
                        async {
                            let scope = evidence.scope();
                            let event = evidence.event();
                            exchange.event.put(evidence)?;
                            match event {
                                recovery::InitialRetirementEvent::ClientHandshakeAccepted => {
                                    endpoint.send::<p::ClientInitialRetire>(&()).await?
                                }
                                recovery::InitialRetirementEvent::ServerHandshakeAuthenticated => {
                                    endpoint.send::<p::ServerInitialRetire>(&()).await?
                                }
                            }
                            endpoint.recv::<p::InitialRetired>().await?;
                            let proof = exchange.retired.take()?;
                            if !core::ptr::eq(proof.scope(), scope) || proof.event() != event {
                                return Err(Error::Binding);
                            }
                            Ok::<(), Error>(())
                        }
                        .await?;
                    }
                    outcome.set(accepted_at.is_some())?;
                    match outcome.resolver::<{ p::ADAPTER_RESULT }>().decide()? {
                        DecisionArm::Left => endpoint.send::<p::DrainProbeAccepted>(&()).await?,
                        DecisionArm::Right => endpoint.send::<p::DrainProbeRejected>(&()).await?,
                    };
                    endpoint.recv::<p::DrainProbeSettled>().await?;
                    outcome.clear();
                    match result {
                        None | Some(Ok(Ok(_))) => Ok::<(), Error>(()),
                        Some(_) if is_initial && !initial.available() => Ok(()),
                        Some(Ok(Err(e))) => Err(e.into()),
                        Some(Err(e)) => Err(e.into()),
                    }?;
                }
            }
            label if label == p::HandshakeRecoveryTransferred::LOGICAL_LABEL => {
                input.recv::<p::HandshakeRecoveryTransferred>().await?;
                break;
            }
            label => return Err(Error::UnexpectedLabel(label)),
        }
    }
    endpoint.recv::<p::AdapterComplete>().await?;
    endpoint.send::<p::AdapterRetired>(&()).await?;
    Ok(())
}
