//! The application receive continuation owns authentication and frame effects.
//! Plaintext, affine key transitions and stream handles remain local; only the
//! declared key, delivery and termination edges cross async role boundaries.
use super::{CloseKind, Control, Error, global as p, io, keys, reset, termination};
use crate::{
    accounting::AccountingError,
    crypto::{
        self,
        directional::{AuthenticatedRead, ScopedHandshakeConfirmation, ValidatedKeyAck},
    },
    handshake::CryptoBuffer,
    packet::{self, Frame, FrameIter, Header, LongType, PacketIter, ParseLimits},
    quic::{
        self, Clock, Config, DatagramRx, ReceiveMaterial, Side, application_stream,
        application_wire, recovery,
        tls::{CryptoInput, Transcript},
    },
    streams,
    tls::Level,
};
use core::cell::RefCell;
use hibana::Endpoint;
use zeroize::Zeroizing;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run<
    'streams,
    'owner,
    'scope,
    const N: usize,
    const RX: usize,
    const CHUNK: usize,
    B,
>(
    receive: &mut Endpoint<'_, { p::RECEIVE }>,
    rx_keys: &mut Endpoint<'_, { p::RX_KEYS }>,
    peer_event: &mut Endpoint<'_, { p::PEER_EVENT }>,
    mut material: ReceiveMaterial<'scope>,
    config: Config<'_>,
    transcript: &mut Transcript<'scope, '_, '_>,
    mut crypto: CryptoBuffer<'_>,
    book: &mut recovery::Rx<'_, 'scope, N>,
    streams: &mut application_stream::Rx<'streams, '_, 'scope, RX, CHUNK>,
    reset: &reset::Exchange<'streams>,
    acknowledgments: &super::acknowledgments::Exchange<'scope>,
    app: &RefCell<application_stream::App<'_, '_, 'scope, RX, CHUNK>>,
    state: &io::State<'_, CHUNK, B>,
    mut keys: keys::RxControl<'_, 'owner, 'scope>,
    control: &Control<'_, 'scope>,
    clock: &impl Clock,
    socket: &mut impl DatagramRx,
    termination: &termination::Exchange<'_, '_, 'scope>,
    initial_confirmation: Option<recovery::HandshakeConfirmed<'scope>>,
    key_update_target: u64,
    responses: &crate::path::responses::Responses,
    local_ids: &RefCell<Option<crate::path::ids::Ids<'_, 'scope>>>,
    peer_ids: &RefCell<Option<crate::path::peer_ids::Peers<'_, 'scope>>>,
    paths: &crate::path::validation::Paths<'_>,
    mut pending_application: Option<([u8; N], quic::ReceivedDatagram)>,
) -> Result<(), Error> {
    let scope = material.application.scope();
    if !core::ptr::eq(scope, transcript.scope())
        || material
            .initial
            .as_ref()
            .is_some_and(|key| !core::ptr::eq(scope, key.scope()))
        || !core::ptr::eq(scope, material.handshake.scope())
        || crypto.consumed() != transcript.received_offset(Level::OneRtt)
    {
        return Err(Error::Binding);
    }
    if let Some(confirmation) = initial_confirmation {
        async {
            let endpoint = &mut *rx_keys;
            let keys = &mut keys;
            let material = &mut material;
            let book = &mut *book;

            loop {
                let revision = control.revision();
                match book.retire_handshake(&confirmation) {
                    Ok(_) => break,
                    Err(recovery::Error::Accounting(AccountingError::OutstandingPackets)) => {
                        control.wait(3, revision).await;
                        // A concurrent terminal permission makes wait immediately
                        // ready. The old-space adapter still has to settle its
                        // cancellation before recovery and key retirement can finish.
                        crate::runtime::yield_now().await;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            async {
                let endpoint = &mut *endpoint;
                let confirmation = ScopedHandshakeConfirmation::from_connection(confirmation);

                keys.exchange.confirmation.put(confirmation)?;
                endpoint.send::<p::Confirmed>(&()).await?;
                let response = endpoint.offer().await?;
                let accepted = match response.label() {
                    18 => {
                        response.recv::<p::ConfirmationApplied>().await?;
                        true
                    }
                    19 => {
                        response.recv::<p::ConfirmationFailed>().await?;
                        false
                    }
                    label => {
                        return Err(keys::Error::UnexpectedLabel(label));
                    }
                };
                let result = keys.exchange.confirmation_applied.take()?;
                keys::check_result(&result, accepted)?;

                result
            }
            .await?;
            if let Some(mut initial) = material.initial.take() {
                initial.discard();
            }
            material.handshake.discard();
            control.changed()?;
            Ok::<(), Error>(())
        }
        .await?;
    }
    let mut datagram = [0; N];
    let mut largest = None;
    let delivery_result = async {
        // A Finished-gated early bridge may already have retained request bytes.
        async {
            let endpoint = &mut *receive;

            // A sink error asks the independent completion lane to close. Do not keep
            // redispatching that same ready stream while that lane is being scheduled.
            while !control.stopping() {
                let ready = app
                    .try_borrow()
                    .map_err(|_| Error::Binding)?
                    .ready_streams()?;
                let Some(stream) = ready
                    .into_iter()
                    .flatten()
                    .find(|stream| !state.is_complete(stream.id()))
                else {
                    break;
                };
                let id = stream.id();
                endpoint.send::<p::ReceivedData>(&id).await?;
                let result = endpoint.offer().await?;
                match result.label() {
                    7 => check(result.recv::<p::ReceivedMore>().await?, id)?,
                    8 => check(result.recv::<p::ReceivedFin>().await?, id)?,
                    219 => {
                        check(result.recv::<p::ReceivedInterrupted>().await?, id)?;
                        if !control.stopping() {
                            return Err(Error::Binding);
                        }
                    }
                    217 => {
                        check(result.recv::<p::ReceivedFailed>().await?, id)?;
                        return Err(Error::Application);
                    }
                    label => return Err(Error::UnexpectedLabel(label)),
                }
                crate::runtime::yield_now().await;
            }
            Ok::<(), Error>(())
        }
        .await?;
        // Bounded opportunistic batching: flush ready streams before actually
        // waiting for input. At datagram boundaries, flush after a window-backed
        // burst (at least sixty-four datagrams) or a one-millisecond work budget
        // (not a hard real-time guarantee).
        // Pending receive IO stays pinned/owned during delivery; no batching cancel.
        let burst_limit = (RX / N.max(1)).max(64);
        let mut burst = 0usize;
        let mut burst_started = 0u64;
        async {
            while !control.stopping() {
                let retained = pending_application.take();
                let already_accounted = retained.is_some();
                let result = if let Some((bytes, len)) = retained {
                    datagram = bytes;
                    Some(Ok(len))
                } else {
                    crate::runtime::on_pending(
                        control.until_stop(3, socket.receive(&mut datagram)),
                        async {
                            let endpoint = &mut *receive;

                            // A sink error asks the independent completion lane to close. Do not keep
                            // redispatching that same ready stream while that lane is being scheduled.
                            while !control.stopping() {
                                let ready = app
                                    .try_borrow()
                                    .map_err(|_| Error::Binding)?
                                    .ready_streams()?;
                                let Some(stream) = ready
                                    .into_iter()
                                    .flatten()
                                    .find(|stream| !state.is_complete(stream.id()))
                                else {
                                    break;
                                };
                                let id = stream.id();
                                endpoint.send::<p::ReceivedData>(&id).await?;
                                let result = endpoint.offer().await?;
                                match result.label() {
                                    7 => check(result.recv::<p::ReceivedMore>().await?, id)?,
                                    8 => check(result.recv::<p::ReceivedFin>().await?, id)?,
                                    219 => {
                                        check(result.recv::<p::ReceivedInterrupted>().await?, id)?;
                                        if !control.stopping() {
                                            return Err(Error::Binding);
                                        }
                                    }
                                    217 => {
                                        check(result.recv::<p::ReceivedFailed>().await?, id)?;
                                        return Err(Error::Application);
                                    }
                                    label => return Err(Error::UnexpectedLabel(label)),
                                }
                                crate::runtime::yield_now().await;
                            }
                            burst = 0;
                            Ok::<(), Error>(())
                        },
                    )
                    .await?
                };
                let Some(result) = result else {
                    break;
                };
                if burst == 0 {
                    burst_started = clock.now();
                }
                burst += 1;
                let received = result.map_err(quic::Error::from)?;
                let len = received.len;
                if len > N {
                    return Err(Error::Capacity);
                }
                // The prefix counted the complete UDP datagram before retaining this
                // short packet, including any coalesced Handshake bytes.
                if !already_accounted {
                    book.received_datagram(len as u64)?;
                }
                control.changed()?;
                let mut offset = 0;
                while offset < len && !control.stopping() {
                    // Parse one bounded packet at a time; all pre-AEAD syntax errors
                    // discard the remainder because its next boundary is untrusted.
                    let packet = match PacketIter::new(
                        &datagram[offset..len],
                        config.local_connection_id.len(),
                        1,
                    )
                    .ok()
                    .and_then(|mut packets| packets.next())
                    {
                        Some(Ok(packet)) => packet,
                        _ => break,
                    };
                    if packet.bytes.is_empty() {
                        break;
                    }
                    offset += packet.bytes.len();
                    let result = match packet.header {
                        Header::Short {
                            destination_id: destination,
                            ..
                        } => {
                            async {
                                let endpoint = &mut *rx_keys;
                                let keys = &mut keys;
                                let material = &mut material;
                                let packet = packet.bytes;
                                let transcript = &mut *transcript;
                                let reassembly = &mut crypto;
                                let book = &mut *book;
                                let streams = &mut *streams;
                                let largest = &mut largest;

                                let now = clock.now();
                                let pto = book.pto_duration_us()?;
                                material.application.maintain(now, pto)?;
                                if !local_ids
                                    .borrow()
                                    .as_ref()
                                    .map_or(destination == config.local_connection_id, |ids| {
                                        ids.routes(destination)
                                    })
                                {
                                    return Ok(None);
                                }
                                let mut opened = match application_wire::open::<N>(
                                    &mut material.application,
                                    &mut material.integrity,
                                    packet,
                                    destination,
                                    *largest,
                                    now,
                                    pto,
                                ) {
                                    Ok(opened) => opened,
                                    Err(error) if discard_before_authentication(&error) => {
                                        return Ok(None);
                                    }
                                    Err(error) => return Err(error.into()),
                                };
                                let receipt = match opened.take_receipt().ok_or(Error::Binding)? {
                                    AuthenticatedRead::Ready(receipt) => receipt,
                                    AuthenticatedRead::PeerUpdate(authenticated) => {
                                        let installed = async {
                                            let endpoint = &mut *endpoint;

                                            keys.exchange.peer_update.put(keys::PeerUpdate {
                                                authenticated,
                                                now,
                                                pto,
                                            })?;
                                            endpoint.send::<p::PeerUpdate>(&()).await?;
                                            let response = endpoint.offer().await?;
                                            let accepted = match response.label() {
                                                12 => {
                                                    response.recv::<p::WriteInstalled>().await?;
                                                    true
                                                }
                                                13 => {
                                                    response.recv::<p::UpdateFailed>().await?;
                                                    false
                                                }
                                                label => {
                                                    return Err(keys::Error::UnexpectedLabel(
                                                        label,
                                                    ));
                                                }
                                            };
                                            let result = keys.exchange.write_installed.take()?;
                                            keys::check_result(&result, accepted)?;

                                            result
                                        }
                                        .await?;
                                        material.application.accept_write_epoch(installed)?
                                    }
                                };
                                *largest = Some(largest.map_or(opened.packet_number(), |last| {
                                    last.max(opened.packet_number())
                                }));
                                // Installing a peer key epoch crosses a real choreography await. TX and
                                // timer roles may have advanced the shared recovery clock meanwhile. Read
                                // the actual clock again at this synchronous commit; the earlier timestamp
                                // belongs to packet authentication, not to a later recovery mutation.
                                let outcome = match book.apply_application_packet(
                                    receipt,
                                    opened.plaintext(),
                                    clock.now(),
                                    received.ecn,
                                ) {
                                    Ok(outcome) => outcome,
                                    // Expired sent history is not evidence that the peer ACKed an unsent
                                    // packet. Discard this packet without manufacturing any frame grant.
                                    Err(recovery::Error::Accounting(
                                        AccountingError::HistoryUnavailable,
                                    )) => return Ok(None),
                                    Err(error) => return Err(error.into()),
                                };
                                if let Some(grant) = outcome.frame_acks {
                                    acknowledgments.deliver(grant, control)?;
                                }
                                for grant in outcome.key_acks.into_iter().flatten() {
                                    async {
                                        let endpoint = &mut *endpoint;
                                        let validated =
                                            ValidatedKeyAck::from_connection_ack(grant)?;

                                        keys.exchange.key_ack.put(keys::KeyAck {
                                            validated,
                                            now,
                                            pto,
                                        })?;
                                        endpoint.send::<p::KeyAck>(&()).await?;
                                        let response = endpoint.offer().await?;
                                        let accepted = match response.label() {
                                            15 => {
                                                response.recv::<p::KeyAckApplied>().await?;
                                                true
                                            }
                                            16 => {
                                                response.recv::<p::KeyAckFailed>().await?;
                                                false
                                            }
                                            label => {
                                                return Err(keys::Error::UnexpectedLabel(label));
                                            }
                                        };
                                        let result = keys.exchange.key_ack_applied.take()?;
                                        keys::check_result(&result, accepted)?;

                                        result
                                    }
                                    .await?;
                                }
                                if let Some(confirmation) = outcome.confirmation {
                                    async {
                                        let endpoint = &mut *endpoint;
                                        let keys = &mut *keys;
                                        let material = &mut *material;
                                        let book = &mut *book;

                                        loop {
                                            let revision = control.revision();
                                            match book.retire_handshake(&confirmation) {
                                                Ok(_) => break,
                                                Err(recovery::Error::Accounting(
                                                    AccountingError::OutstandingPackets,
                                                )) => {
                                                    control.wait(3, revision).await;
                                                    // A concurrent terminal permission makes wait immediately
                                                    // ready. The old-space adapter still has to settle its
                                                    // cancellation before recovery and key retirement can finish.
                                                    crate::runtime::yield_now().await;
                                                }
                                                Err(error) => return Err(error.into()),
                                            }
                                        }
                                        async {
                                            let endpoint = &mut *endpoint;
                                            let confirmation =
                                                ScopedHandshakeConfirmation::from_connection(
                                                    confirmation,
                                                );

                                            keys.exchange.confirmation.put(confirmation)?;
                                            endpoint.send::<p::Confirmed>(&()).await?;
                                            let response = endpoint.offer().await?;
                                            let accepted = match response.label() {
                                                18 => {
                                                    response
                                                        .recv::<p::ConfirmationApplied>()
                                                        .await?;
                                                    true
                                                }
                                                19 => {
                                                    response
                                                        .recv::<p::ConfirmationFailed>()
                                                        .await?;
                                                    false
                                                }
                                                label => {
                                                    return Err(keys::Error::UnexpectedLabel(
                                                        label,
                                                    ));
                                                }
                                            };
                                            let result =
                                                keys.exchange.confirmation_applied.take()?;
                                            keys::check_result(&result, accepted)?;

                                            result
                                        }
                                        .await?;
                                        if let Some(mut initial) = material.initial.take() {
                                            initial.discard();
                                        }
                                        material.handshake.discard();
                                        control.changed()?;
                                        Ok::<(), Error>(())
                                    }
                                    .await?;
                                }
                                if outcome.duplicate {
                                    return Ok(None);
                                }
                                let mut non_probing = false;
                                for frame in received_frames(
                                    opened.plaintext(),
                                    packet::EncryptionLevel::OneRtt,
                                )? {
                                    if !matches!(
                                        frame?,
                                        Frame::Padding { .. }
                                            | Frame::PathChallenge { .. }
                                            | Frame::PathResponse { .. }
                                            | Frame::NewConnectionId { .. }
                                    ) {
                                        non_probing = true;
                                    }
                                }
                                paths.observe(
                                    received.path,
                                    opened.packet_number(),
                                    packet.len(),
                                    non_probing,
                                )?;
                                for frame in received_frames(
                                    opened.plaintext(),
                                    packet::EncryptionLevel::OneRtt,
                                )? {
                                    let frame = frame?;
                                    match frame {
                                        Frame::Stream { .. }
                                        | Frame::ResetStream { .. }
                                        | Frame::MaxData { .. }
                                        | Frame::MaxStreamData { .. }
                                        | Frame::MaxStreams { .. }
                                        | Frame::DataBlocked { .. }
                                        | Frame::StreamDataBlocked { .. }
                                        | Frame::StreamsBlocked { .. } => streams.apply(&frame)?,
                                        Frame::StopSending { id, error_code } => {
                                            match streams.stop_intent(id, error_code) {
                                                Ok(intent) => {
                                                    reset.observe(intent)?;
                                                    control.changed()?;
                                                }
                                                Err(application_stream::Error::Streams(
                                                    streams::Error::Retired,
                                                )) => {}
                                                Err(error) => return Err(error.into()),
                                            }
                                        }
                                        Frame::Crypto { offset, data } => {
                                            reassembly
                                                .insert(offset, data)
                                                .map_err(quic::Error::from)?;
                                            loop {
                                                let (first, _) = reassembly.ready();
                                                if first.is_empty() {
                                                    break;
                                                }
                                                let count = first.len().min(N);
                                                let input = CryptoInput::<N>::new(
                                                    material.application.scope(),
                                                    Level::OneRtt,
                                                    reassembly.consumed(),
                                                    &first[..count],
                                                )
                                                .map_err(quic::Error::from)?;
                                                transcript
                                                    .receive(input)
                                                    .map_err(quic::Error::from)?;
                                                reassembly
                                                    .consume(count)
                                                    .map_err(quic::Error::from)?;
                                            }
                                        }
                                        Frame::ConnectionClose {
                                            error_code,
                                            frame_type,
                                            ..
                                        } => {
                                            return Ok(Some((frame_type.is_none(), error_code)));
                                        }
                                        Frame::NewToken { .. } if config.side == Side::Client => {
                                            // This fixed-path request session does not save resumption or
                                            // address-validation tokens for a future connection.
                                        }
                                        Frame::NewConnectionId {
                                            sequence,
                                            retire_prior_to,
                                            id,
                                            reset_token,
                                        } => {
                                            if let Some(peers) = peer_ids.borrow_mut().as_mut() {
                                                peers
                                                    .receive(
                                                        sequence,
                                                        retire_prior_to,
                                                        id,
                                                        *reset_token,
                                                    )
                                                    .map_err(|_| Error::Binding)?;
                                            } else if retire_prior_to != 0 {
                                                return Err(Error::Binding);
                                            }
                                            control.changed()?;
                                        }
                                        Frame::RetireConnectionId { sequence } => {
                                            local_ids
                                                .borrow_mut()
                                                .as_mut()
                                                .ok_or(Error::Binding)?
                                                .retire(sequence, destination)
                                                .map_err(|_| Error::Binding)?;
                                            control.changed()?;
                                        }
                                        Frame::PathChallenge { data } => {
                                            responses
                                                .observe(*data, received.path)
                                                .map_err(|_| Error::Capacity)?;
                                            control.changed()?;
                                        }
                                        Frame::PathResponse { data } => {
                                            paths.response(
                                                received.path,
                                                opened.packet_number(),
                                                *data,
                                            )?;
                                            control.changed()?;
                                        }
                                        Frame::Padding { .. }
                                        | Frame::Ping
                                        | Frame::Ack { .. }
                                        | Frame::HandshakeDone => {}
                                        Frame::NewToken { .. } => {
                                            return Err(quic::Error::UnsupportedFrame.into());
                                        }
                                    }
                                }
                                if key_update_target != 0
                                    && keys.local_update_due(key_update_target, clock.now())?
                                {
                                    let update_pto = book.pto_duration_us()?;
                                    async {
                                        let endpoint = &mut *endpoint;
                                        let read = &mut material.application;
                                        let now = clock.now();
                                        let pto = update_pto;

                                        read.maintain(now, pto)?;
                                        let ready = read.prepare_local_update()?;
                                        keys.exchange
                                            .local_update
                                            .put(keys::LocalUpdateRequest { ready, now, pto })?;
                                        endpoint.send::<p::LocalUpdate>(&()).await?;
                                        let offered = endpoint.offer().await?;
                                        let accepted = match offered.label() {
                                            206 => {
                                                offered.recv::<p::LocalInstalled>().await?;
                                                true
                                            }
                                            207 => {
                                                offered.recv::<p::LocalRejected>().await?;
                                                false
                                            }
                                            label => {
                                                return Err(keys::Error::UnexpectedLabel(label));
                                            }
                                        };
                                        let result = keys.exchange.local_result.take()?;
                                        if result.is_ok() != accepted {
                                            return Err(keys::Error::Binding);
                                        }
                                        let result = match result {
                                            Ok(installed) => read
                                                .accept_local_write_epoch(installed)
                                                .map_err(keys::Error::Crypto),
                                            Err(rejected) => {
                                                read.cancel_local_update(rejected.ready)?;
                                                Err(keys::Error::Crypto(rejected.error))
                                            }
                                        };
                                        endpoint.send::<p::LocalSettled>(&()).await?;

                                        result
                                    }
                                    .await?;
                                    control.changed()?;
                                }
                                Ok(None)
                            }
                            .await
                        }
                        Header::Long { .. } if !book.snapshot().handshake_confirmed => old::<N>(
                            &mut material,
                            packet,
                            len,
                            config,
                            transcript,
                            book,
                            clock.now(),
                            received.ecn,
                        ),
                        _ => Ok(None),
                    };
                    match result {
                        Ok(Some((application, code))) => {
                            // Preserve delivery of already authenticated buffered FINs
                            // before publishing the actual peer-close observation.
                            async {
                                let endpoint = &mut *receive;

                                // A sink error asks the independent completion lane to close. Do not keep
                                // redispatching that same ready stream while that lane is being scheduled.
                                while !control.stopping() {
                                    let ready = app
                                        .try_borrow()
                                        .map_err(|_| Error::Binding)?
                                        .ready_streams()?;
                                    let Some(stream) = ready
                                        .into_iter()
                                        .flatten()
                                        .find(|stream| !state.is_complete(stream.id()))
                                    else {
                                        break;
                                    };
                                    let id = stream.id();
                                    endpoint.send::<p::ReceivedData>(&id).await?;
                                    let result = endpoint.offer().await?;
                                    match result.label() {
                                        7 => check(result.recv::<p::ReceivedMore>().await?, id)?,
                                        8 => check(result.recv::<p::ReceivedFin>().await?, id)?,
                                        219 => {
                                            check(
                                                result.recv::<p::ReceivedInterrupted>().await?,
                                                id,
                                            )?;
                                            if !control.stopping() {
                                                return Err(Error::Binding);
                                            }
                                        }
                                        217 => {
                                            check(result.recv::<p::ReceivedFailed>().await?, id)?;
                                            return Err(Error::Application);
                                        }
                                        label => return Err(Error::UnexpectedLabel(label)),
                                    }
                                    crate::runtime::yield_now().await;
                                }
                                Ok::<(), Error>(())
                            }
                            .await?;

                            termination.check_scope(scope)?;
                            termination
                                .peer
                                .put(termination::Permission {
                                    scope,
                                    kind: if application {
                                        CloseKind::PeerApplication { code }
                                    } else {
                                        CloseKind::Peer { code }
                                    },
                                })
                                .map_err(|_| Error::Binding)?;

                            peer_event.send::<p::PeerClose>(&()).await?;
                            control.revoke()?;
                            peer_event.recv::<p::PeerSeen>().await?;
                            return Ok::<(), Error>(());
                        }
                        Ok(None) => {}
                        Err(error) => {
                            let code = protocol_code(&error);
                            control.record_protocol_error(error);

                            termination.check_scope(scope)?;
                            termination
                                .peer
                                .put(termination::Permission {
                                    scope,
                                    kind: CloseKind::Local {
                                        application: false,
                                        code,
                                    },
                                })
                                .map_err(|_| Error::Binding)?;

                            peer_event.send::<p::PeerFailed>(&()).await?;
                            control.revoke()?;
                            peer_event.recv::<p::PeerSeen>().await?;
                            return Ok::<(), Error>(());
                        }
                    }
                    control.changed()?;
                    // Let the adapter consume retained ACK grants before another
                    // packet can add more evidence to the bounded receipt slot.
                    if !acknowledgments.pending.is_empty() {
                        async {
                            let endpoint = &mut *receive;

                            // A sink error asks the independent completion lane to close. Do not keep
                            // redispatching that same ready stream while that lane is being scheduled.
                            while !control.stopping() {
                                let ready = app
                                    .try_borrow()
                                    .map_err(|_| Error::Binding)?
                                    .ready_streams()?;
                                let Some(stream) = ready
                                    .into_iter()
                                    .flatten()
                                    .find(|stream| !state.is_complete(stream.id()))
                                else {
                                    break;
                                };
                                let id = stream.id();
                                endpoint.send::<p::ReceivedData>(&id).await?;
                                let result = endpoint.offer().await?;
                                match result.label() {
                                    7 => check(result.recv::<p::ReceivedMore>().await?, id)?,
                                    8 => check(result.recv::<p::ReceivedFin>().await?, id)?,
                                    219 => {
                                        check(result.recv::<p::ReceivedInterrupted>().await?, id)?;
                                        if !control.stopping() {
                                            return Err(Error::Binding);
                                        }
                                    }
                                    217 => {
                                        check(result.recv::<p::ReceivedFailed>().await?, id)?;
                                        return Err(Error::Application);
                                    }
                                    label => return Err(Error::UnexpectedLabel(label)),
                                }
                                crate::runtime::yield_now().await;
                            }
                            Ok::<(), Error>(())
                        }
                        .await?;
                        burst = 0;
                        crate::runtime::yield_now().await;
                    }
                }
                if burst >= burst_limit || clock.now().saturating_sub(burst_started) >= 1_000 {
                    async {
                        let endpoint = &mut *receive;

                        // A sink error asks the independent completion lane to close. Do not keep
                        // redispatching that same ready stream while that lane is being scheduled.
                        while !control.stopping() {
                            let ready = app
                                .try_borrow()
                                .map_err(|_| Error::Binding)?
                                .ready_streams()?;
                            let Some(stream) = ready
                                .into_iter()
                                .flatten()
                                .find(|stream| !state.is_complete(stream.id()))
                            else {
                                break;
                            };
                            let id = stream.id();
                            endpoint.send::<p::ReceivedData>(&id).await?;
                            let result = endpoint.offer().await?;
                            match result.label() {
                                7 => check(result.recv::<p::ReceivedMore>().await?, id)?,
                                8 => check(result.recv::<p::ReceivedFin>().await?, id)?,
                                219 => {
                                    check(result.recv::<p::ReceivedInterrupted>().await?, id)?;
                                    if !control.stopping() {
                                        return Err(Error::Binding);
                                    }
                                }
                                217 => {
                                    check(result.recv::<p::ReceivedFailed>().await?, id)?;
                                    return Err(Error::Application);
                                }
                                label => return Err(Error::UnexpectedLabel(label)),
                            }
                            crate::runtime::yield_now().await;
                        }
                        Ok::<(), Error>(())
                    }
                    .await?;
                    burst = 0;
                    crate::runtime::yield_now().await;
                }
            }

            if !termination.peer.is_empty() {
                return Err(Error::Binding);
            }

            peer_event.send::<p::PeerCancelled>(&()).await?;
            peer_event.recv::<p::PeerSeen>().await?;
            Ok::<(), Error>(())
        }
        .await?;
        Ok::<(), Error>(())
    }
    .await;
    match delivery_result {
        Ok(()) => {}
        Err(Error::Application) => {
            // Only a consumed ReceivedFailed branch reaches this application
            // close permission. The sink does not fabricate successful FIN.
            termination.check_scope(scope)?;
            termination
                .peer
                .put(termination::Permission {
                    scope,
                    kind: CloseKind::Local {
                        application: true,
                        code: termination.protocol.failure_code(),
                    },
                })
                .map_err(|_| Error::Binding)?;

            peer_event.send::<p::PeerApplicationFailed>(&()).await?;
            control.revoke()?;
            peer_event.recv::<p::PeerSeen>().await?;
        }
        Err(error) => return Err(error),
    }
    receive.send::<p::ReceiveRetire>(&()).await?;
    receive.recv::<p::ReceiveRetired>().await?;
    material.application.discard();
    if let Some(mut initial) = material.initial.take() {
        initial.discard();
    }
    material.handshake.discard();
    Ok(async {
        let endpoint = rx_keys;

        endpoint.send::<p::KeysRetire>(&()).await?;
        endpoint.recv::<p::KeysRetired>().await?;
        Ok::<(), keys::Error>(())
    }
    .await?)
}

#[allow(clippy::too_many_arguments)]
fn old<'book, 'scope, const N: usize>(
    material: &mut ReceiveMaterial<'scope>,
    packet: packet::Packet<'_>,
    datagram_len: usize,
    config: Config<'_>,
    transcript: &Transcript<'scope, '_, '_>,
    book: &mut recovery::Rx<'book, 'scope, N>,
    now: u64,
    ecn: Option<crate::ecn::Codepoint>,
) -> Result<Option<(bool, u64)>, Error> {
    let Header::Long {
        version,
        kind,
        destination_id,
        source_id,
        packet_number_offset,
        ..
    } = packet.header
    else {
        return Ok(None);
    };
    if kind == LongType::Handshake && version != config.version {
        return Ok(None);
    }
    if destination_id != config.local_connection_id
        && !(config.side == Side::Server
            && kind == LongType::Initial
            && destination_id
                == config
                    .retry_source_id
                    .unwrap_or(config.original_destination_id))
    {
        return Ok(None);
    }
    let (index, level, encryption) = match kind {
        LongType::Initial if config.side != Side::Server || datagram_len >= 1200 => {
            (0, Level::Initial, packet::EncryptionLevel::Initial)
        }
        LongType::Handshake => (1, Level::Handshake, packet::EncryptionLevel::Handshake),
        _ => return Ok(None),
    };
    if packet.bytes.len() > N {
        return Ok(None);
    }
    let key = if index == 0 {
        // Initial retirement has its own finite projected lane in the prefix.
        // Once that lane consumes the key, late Initial packets are discarded.
        let Some(initial) = material.initial.as_ref() else {
            return Ok(None);
        };
        initial
    } else {
        &material.handshake
    };
    let mut opened = Zeroizing::new([0u8; N]);
    opened[..packet.bytes.len()].copy_from_slice(packet.bytes);
    let bytes = &mut opened[..packet.bytes.len()];
    let pn_len = match key.unprotect_header(bytes, packet_number_offset) {
        Ok(len) => len,
        Err(_) => return Ok(None),
    };
    let truncated =
        match packet::decode_truncated_packet_number(bytes[0], &bytes[packet_number_offset..]) {
            Ok((truncated, _)) => truncated,
            Err(_) => return Ok(None),
        };
    let pn = match packet::restore_packet_number(
        truncated,
        pn_len as u8,
        material.largest_received[index],
    ) {
        Ok(pn) => pn,
        Err(_) => return Ok(None),
    };
    let (header, payload) = bytes.split_at_mut(packet_number_offset + pn_len);
    let receipt = match key.open_authenticated(pn, header, payload, &mut material.integrity) {
        Ok(receipt) => receipt,
        Err(crypto::Error::AuthenticationFailed) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    packet::validate_reserved_bits(header[0])?;
    if source_id != material.peer_connection_id() {
        return Err(Error::Binding);
    }
    let plaintext = &payload[..receipt.len()];
    if plaintext.is_empty() {
        return Err(packet::Error::EmptyPayload.into());
    }
    material.largest_received[index] =
        Some(material.largest_received[index].map_or(pn, |last| last.max(pn)));
    let outcome = match book.apply_packet(receipt, plaintext, now, ecn) {
        Ok(outcome) => outcome,
        Err(recovery::Error::Accounting(AccountingError::HistoryUnavailable)) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !outcome.duplicate {
        for frame in received_frames(plaintext, encryption)? {
            match frame? {
                Frame::Crypto { offset, data } => {
                    let end = offset
                        .checked_add(data.len() as u64)
                        .ok_or(Error::Capacity)?;
                    if end > transcript.received_offset(level) {
                        // Finished is a finite boundary. New Initial/Handshake
                        // transcript bytes cannot re-enter completed TLS.
                        return Err(quic::Error::UnsupportedFrame.into());
                    }
                }
                Frame::ConnectionClose {
                    error_code,
                    frame_type,
                    ..
                } => return Ok(Some((frame_type.is_none(), error_code))),
                Frame::Padding { .. } | Frame::Ping | Frame::Ack { .. } => {}
                _ => return Err(quic::Error::UnsupportedFrame.into()),
            }
        }
    }
    Ok(None)
}

/// Keep the effect pass bounded identically to recovery's complete preflight.
/// The caller retains the exact authenticated plaintext throughout both passes;
/// no copied packet number or frame alone grants application delivery.
fn received_frames(
    plaintext: &[u8],
    level: packet::EncryptionLevel,
) -> Result<FrameIter<'_>, Error> {
    Ok(FrameIter::new(
        plaintext,
        level,
        ParseLimits {
            max_bytes: plaintext.len(),
            max_frames: 256,
            max_ack_ranges: recovery::ACK_CAPACITY,
        },
    )?)
}

fn discard_before_authentication(error: &quic::Error) -> bool {
    matches!(
        error,
        quic::Error::Binding
            | quic::Error::Capacity
            | quic::Error::Crypto(
                crypto::Error::AuthenticationFailed
                    | crypto::Error::InvalidPacketNumber
                    | crypto::Error::InvalidHeader
                    | crypto::Error::BufferTooSmall
                    | crypto::Error::PacketTooLarge
            )
            | quic::Error::Packet(
                packet::Error::Truncated
                    | packet::Error::BufferTooShort
                    | packet::Error::InvalidPacketNumber
                    | packet::Error::InvalidFixedBit
                    | packet::Error::InvalidLength
                    | packet::Error::InvalidConnectionIdLength
            )
    )
}

fn protocol_code(error: &Error) -> u64 {
    match error {
        Error::Streams(application_stream::Error::Streams(streams::Error::FlowControl)) => 0x3,
        Error::Streams(application_stream::Error::Streams(streams::Error::StreamLimit)) => 0x4,
        Error::Streams(application_stream::Error::Streams(streams::Error::FinalSize)) => 0x6,
        Error::Streams(_) => 0x5,
        Error::Crypto(crypto::Error::KeyUpdateError)
        | Error::Connection(quic::Error::Crypto(crypto::Error::KeyUpdateError)) => 0xe,
        Error::Crypto(crypto::Error::IntegrityLimit | crypto::Error::ConfidentialityLimit)
        | Error::Connection(quic::Error::Crypto(
            crypto::Error::IntegrityLimit | crypto::Error::ConfidentialityLimit,
        )) => 0xf,
        Error::Packet(packet::Error::ReservedBits | packet::Error::EmptyPayload)
        | Error::Connection(quic::Error::Packet(
            packet::Error::ReservedBits | packet::Error::EmptyPayload,
        )) => 0xa,
        Error::Packet(_) | Error::Recovery(recovery::Error::Packet(_)) => 0x7,
        Error::Recovery(recovery::Error::Accounting(AccountingError::UnsentPacket)) => 0xa,
        _ => 0xa,
    }
}

fn check(actual: u64, expected: u64) -> Result<(), Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(Error::Binding)
    }
}
