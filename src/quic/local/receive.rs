//! receive role or packet arithmetic; endpoint exchanges stay explicit.
use super::*;
struct ReceiveWire<'keys, 'scope, 'buf, const N: usize> {
    initial: &'keys initial::Keys<'scope>,
    handshake: Option<ReceivePacketKey<'scope>>,
    integrity: IntegrityBudget,
    reassembly: [CryptoBuffer<'buf>; 2],
    largest: [Option<u64>; 2],
    datagram: [u8; N],
    len: usize,
    received_at: u64,
    ecn: Option<crate::quic::ecn::Codepoint>,
    path: Option<crate::quic::path::Address>,
    offset: usize,
    opened: [u8; N],
    // One owned ciphertext packet, not a TLS/protocol phase flag. It cannot
    // produce ACK or CRYPTO effects until the real Handshake key arrives.
    pending_handshake: Option<([u8; N], ReceivedDatagram, u64)>,
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
            let (received, received_at) = if self.handshake.is_some()
                && let Some((bytes, received, received_at)) = self.pending_handshake.take()
            {
                self.datagram = bytes;
                (received, received_at)
            } else {
                let received = io.receive(&mut self.datagram).await?;
                if config.initial_path.is_some() && received.path != config.initial_path {
                    return Ok(true);
                }
                if received.len > N {
                    return Err(Error::Capacity);
                }
                book.received_datagram(received.len as u64)?;
                slots.schedule.changed()?;
                (received, clock.now())
            };
            if config.initial_path.is_some() && received.path != config.initial_path {
                return Ok(true);
            }

            let len = received.len;
            self.received_at = received_at;
            self.ecn = received.ecn;
            self.path = received.path;
            if len > N {
                return Err(Error::Capacity);
            }
            self.len = len;
            self.offset = 0;
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
        let (level, index, pn_offset, source_id, wire_version) = match untrusted.header {
            Header::Long {
                version,
                kind,
                destination_id,
                source_id,
                packet_number_offset,
                ..
            } => {
                if version != config.version
                    && !(kind == LongType::Initial
                        && version == crate::quic::kernel::version::Version::V1)
                {
                    return Ok(true);
                }
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
                        (Level::Initial, 0, packet_number_offset, source_id, version)
                    }
                    LongType::Handshake => (
                        Level::Handshake,
                        1,
                        packet_number_offset,
                        source_id,
                        version,
                    ),
                    LongType::ZeroRtt if config.side == Side::Server => {
                        if source_id == slots.peer.borrow().bytes()
                            && let Some(pending) = slots.early_packets.borrow_mut().as_mut()
                        {
                            pending.retain_packet(untrusted.bytes, self.ecn);
                        }
                        return Ok(true);
                    }
                    _ => return Ok(true),
                }
            }
            Header::Short { destination_id, .. } => {
                if destination_id == config.local_connection_id {
                    slots.retain_application(
                        untrusted.bytes,
                        self.ecn,
                        self.path,
                        self.received_at,
                    )?;
                }
                return Ok(true);
            }
            _ => return Ok(true),
        };
        // Both Initial key access and AEAD end before the retirement edge can await.
        let (authentication, header_len, pn) = {
            let initial_key = self.initial.read_version(wire_version);
            let key = if index == 0 {
                match initial_key.as_ref() {
                    Some(key) => key,
                    None => return Ok(true),
                }
            } else {
                match self.handshake.as_ref() {
                    Some(key) => key,
                    None => {
                        // A reordered server flight can precede ServerHello.
                        // Retain one bounded packet while continuing to read
                        // Initial input; never block the key-producing input.
                        if self.pending_handshake.is_none() {
                            let mut bytes = [0; N];
                            bytes[..untrusted.bytes.len()].copy_from_slice(untrusted.bytes);
                            self.pending_handshake = Some((
                                bytes,
                                ReceivedDatagram {
                                    len: untrusted.bytes.len(),
                                    ecn: self.ecn,
                                    path: self.path,
                                },
                                self.received_at,
                            ));
                        }
                        return Ok(true);
                    }
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
        let outcome = book.apply_packet(
            authentication,
            plaintext,
            self.received_at,
            clock.now(),
            self.ecn,
        )?;
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
pub(in crate::quic) async fn receive<'scope, const N: usize, const P: usize>(
    endpoint: &mut Endpoint<'_, { p::RX }>,
    stop: &mut Endpoint<'_, { p::RECEIVE_STOP }>,
    io: &mut impl DatagramRx,
    message: &crate::tls::handshake::local::MessageSlot<'_>,
    slots: &Storage<'scope, '_, N, P>,
    config: Config<'_>,
    initial: &initial::Keys<'scope>,
    exchange: &initial::Exchange<'scope>,
    mut initial_endpoint: Option<&mut Endpoint<'_, { p::INITIAL_EVENT }>>,
    integrity: IntegrityBudget,
    first_response: Option<&retry_client::Response<N>>,
    pending_handshake: Option<([u8; N], ReceivedDatagram, u64)>,
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
        received_at: 0,
        ecn: None,
        path: None,
        offset: 0,
        opened: [0; N],
        pending_handshake,
    };
    if let Some(first) = first_response {
        if first.received.len > N {
            return Err(Error::Capacity);
        }
        wire.datagram[..first.received.len].copy_from_slice(&first.bytes[..first.received.len]);
        wire.len = first.received.len;
        wire.received_at = clock.now();
        wire.ecn = first.received.ecn;
        wire.path = first.received.path;
    }
    use crate::tls::handshake::{global as tls, local as direct};
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
        retry_source: config.retry_source_id.map(ConnectionId::new).transpose()?,
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
