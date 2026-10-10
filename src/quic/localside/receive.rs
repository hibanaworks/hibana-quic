//! Handshake receive role: physical input, TLS exchanges and owned retirement.
use super::*;
use crate::quic::imp::handshake_wire::HandshakePackets;

async fn receive_packet<'scope, const N: usize, const P: usize>(
    wire: &mut HandshakePackets<'_, 'scope, '_, N>,
    io: &mut impl DatagramRx,
    slots: &Storage<'scope, '_, N, P>,
    config: Config<'_>,
    book: &mut recovery::Rx<'_, 'scope, N>,
    clock: &impl Clock,
) -> Result<(), Error> {
    if wire.offset >= wire.len {
        let (received, received_at) = if wire.handshake.is_some()
            && let Some((bytes, received, received_at)) = wire.pending_handshake.take()
        {
            wire.datagram = bytes;
            (received, received_at)
        } else {
            let received = io.receive(&mut wire.datagram).await?;
            if config.initial_path.is_some() && received.path != config.initial_path {
                return Ok(());
            }
            if received.len > N {
                return Err(Error::Capacity);
            }
            book.received_datagram(received.len as u64)?;
            slots.schedule.changed()?;
            (received, clock.now())
        };
        if config.initial_path.is_some() && received.path != config.initial_path {
            return Ok(());
        }

        let len = received.len;
        wire.received_at = received_at;
        wire.ecn = received.ecn;
        wire.path = received.path;
        if len > N {
            return Err(Error::Capacity);
        }
        wire.len = len;
        wire.offset = 0;
    }
    wire.apply(slots, config, book, clock)
}
#[allow(clippy::too_many_arguments)]
pub(in crate::quic) async fn receive<'scope, const N: usize, const P: usize>(
    endpoint: &mut Endpoint<'_, { p::RX }>,
    stop: &mut Endpoint<'_, { p::RECEIVE_STOP }>,
    io: &mut impl DatagramRx,
    message: &hibana_tls::handshake::MessageSlot<'_>,
    slots: &Storage<'scope, '_, N, P>,
    config: Config<'_>,
    initial: &crate::quic::imp::initial::Keys<'scope>,
    exchange: &crate::quic::imp::initial::Exchange<'scope>,
    mut initial_endpoint: Option<&mut Endpoint<'_, { p::INITIAL_EVENT }>>,
    integrity: IntegrityBudget,
    first_response: Option<&crate::quic::retry::imp::client_packet::Response<N>>,
    pending_handshake: Option<([u8; N], ReceivedDatagram, u64)>,
    reassembly: [CryptoBuffer<'_>; 2],
    book: &mut recovery::Rx<'_, 'scope, N>,
    clock: &impl Clock,
) -> Result<ReceiveContinuation<'scope, P>, Error> {
    let mut wire = HandshakePackets {
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
    use hibana_tls::handshake::global as tls;
    use hibana_tls::handshake::localside as direct;
    let mut input = async |level: Level, bytes: &mut [u8]| {
        let index = match level {
            Level::Initial => 0,
            Level::Handshake => 1,
            _ => return Err(hibana_tls::handshake::Error::Binding),
        };
        if index == 1 && wire.handshake.is_none() {
            wire.handshake = Some(
                slots
                    .read_handshake
                    .take()
                    .map_err(|_| hibana_tls::handshake::Error::Binding)?,
            );
        }
        let mut used = 0;
        let mut target = 4;
        loop {
            let (ready, _) = wire.reassembly[index].ready();
            if !ready.is_empty() {
                if target > bytes.len() {
                    return Err(hibana_tls::handshake::Error::Capacity);
                }
                let n = ready.len().min(target - used);
                bytes[used..used + n].copy_from_slice(&ready[..n]);
                wire.reassembly[index]
                    .consume(n)
                    .map_err(|_| hibana_tls::handshake::Error::Binding)?;
                used += n;
                if used == 4 && target == 4 {
                    target = 4
                        + ((bytes[1] as usize) << 16)
                        + ((bytes[2] as usize) << 8)
                        + bytes[3] as usize;
                }
                if target > bytes.len() {
                    return Err(hibana_tls::handshake::Error::Capacity);
                }
                if used == target {
                    return Ok(used);
                }
            } else {
                receive_packet(&mut wire, io, slots, config, book, clock)
                    .await
                    .map_err(|_| hibana_tls::handshake::Error::Binding)?;
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
                    .map_err(|_| hibana_tls::handshake::Error::Binding)?;
                }
                crate::runtime::yield_now().await;
            }
        }
    };
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
                        direct::input::client_input(endpoint, message, &mut input)
                            .await
                            .map_err(Error::Transcript)?;
                    }
                    Side::Server => {
                        selected.recv::<tls::ServerStart>().await?;
                        direct::input::server_input(endpoint, message, &mut input)
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
                        receive_packet(&mut wire, io, slots, config, book, clock).await?;
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
        receive_packet(&mut wire, io, slots, config, book, clock).await?;
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
