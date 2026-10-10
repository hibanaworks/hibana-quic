//! The application receive continuation owns authentication and frame effects.
//! Plaintext, affine key transitions and stream handles remain local; only the
//! declared key, delivery and termination edges cross async role boundaries.
use super::{CloseKind, Control, Error, global as p, keys, reset, termination};
use crate::crypto::directional::AuthenticatedRead;
use crate::crypto::directional::ScopedHandshakeConfirmation;
use crate::crypto::directional::ValidatedKeyAck;
use crate::quic;
use crate::quic::Clock;
use crate::quic::Config;
use crate::quic::DatagramRx;
use crate::quic::ReceiveMaterial;
use crate::quic::Side;
use crate::quic::application::imp::frame::{
    discard_before_authentication, protocol_code, receive_handshake_packet, received_frames,
};
use crate::quic::application::imp::stream;
use crate::quic::imp::application_wire;
use crate::quic::imp::crypto_buffer::CryptoBuffer;
use crate::quic::imp::kernel::accounting::AccountingError;
use crate::quic::imp::kernel::packet;
use crate::quic::imp::kernel::packet::Frame;
use crate::quic::imp::kernel::packet::Header;
use crate::quic::imp::kernel::packet::PacketIter;
use crate::quic::imp::kernel::streams;
use crate::quic::imp::recovery;
use crate::quic::imp::tls::CryptoInput;
use crate::quic::imp::tls::Transcript;
use core::cell::RefCell;
use hibana::Endpoint;
use hibana_tls::quic::Level;
use hibana_tls::secret::Secret;

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
    finished: &hibana_tls::handshake::keys::FinishedAuthenticated<'scope>,
    mut crypto: CryptoBuffer<'_>,
    book: &mut recovery::Rx<'_, 'scope, N>,
    streams: &mut stream::Rx<'streams, '_, 'scope, RX, CHUNK>,
    reset: &reset::Exchange<'streams>,
    acknowledgments: &super::acknowledgments::Exchange<'scope>,
    app: &RefCell<stream::App<'_, '_, 'scope, RX, CHUNK>>,
    state: &crate::quic::application::imp::io::Exchange<'_, CHUNK, B>,
    mut keys: crate::quic::application::imp::keys::RxControl<'_, 'owner, 'scope>,
    control: &Control<'_, 'scope>,
    clock: &impl Clock,
    socket: &mut impl DatagramRx,
    termination: &termination::Exchange<'_, '_, 'scope>,
    initial_confirmation: Option<recovery::HandshakeConfirmed<'scope>>,
    key_update_target: u64,
    responses: &crate::quic::path::imp::responses::Responses,
    local_ids: &RefCell<Option<crate::quic::path::imp::ids::Ids<'_, 'scope>>>,
    peer_ids: &RefCell<Option<crate::quic::path::imp::peer_ids::Peers<'_, 'scope>>>,
    paths: &crate::quic::path::imp::observations::Paths<'_>,
    mut pending_application: Option<([u8; N], quic::ReceivedDatagram, u64)>,
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
                        return Err(crate::quic::application::imp::keys::Error::UnexpectedLabel(
                            label,
                        ));
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
    let mut packet_outcome = recovery::ApplicationOutcome::default();
    let mut datagram = Secret::new([0; N]);
    let mut largest = None;
    let delivery_result = async {
        // A Finished-gated early bridge may already have retained request bytes.
        async {
            let endpoint = &mut *receive;

            // A sink error asks the independent completion lane to close. Do not keep
            // redispatching that same ready stream while that lane is being scheduled.
            while !control.stopping() {
                let Some(stream) = app.try_borrow().map_err(|_| Error::Binding)?
                    .find_readable_stream(|stream| !state.is_complete(stream.id()))?
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
                let already_accounted = pending_application.is_some();
                let retained_at = pending_application.as_ref().map(|(_, _, at)| *at);
                let result = if let Some((bytes, len, _)) = pending_application.as_ref() {
                    datagram.copy_from_slice(bytes);
                    let received = *len;
                    pending_application = None;
                    Some(Ok(received))
                } else {
                    let mut receiving = core::pin::pin!(socket.receive(&mut *datagram));
                    crate::runtime::on_pending(
                        control.until_stop(3, receiving.as_mut()),
                        async {
                            let endpoint = &mut *receive;

                            // A sink error asks the independent completion lane to close. Do not keep
                            // redispatching that same ready stream while that lane is being scheduled.
                            while !control.stopping() {
                                let Some(stream) = app.try_borrow().map_err(|_| Error::Binding)?
                    .find_readable_stream(|stream| !state.is_complete(stream.id()))?
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
                let received_at = retained_at.unwrap_or_else(|| clock.now());
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
                            let mut destination_copy = [0; 20];
                            let destination_len = destination.len();
                            destination_copy[..destination_len].copy_from_slice(destination);
                            let packet_start = offset - packet.bytes.len();
                            async {
                                let endpoint = &mut *rx_keys;
                                let keys = &mut keys;
                                let material = &mut material;
                                let destination = &destination_copy[..destination_len];
                                let packet = &mut datagram[packet_start..offset];
                                let packet_len = packet.len();
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
                                let opened = match application_wire::open::<N>(
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
                                let plaintext = opened.plaintext();
                                let packet_number = opened.packet_number();
                                let receipt = match opened {
                                    AuthenticatedRead::Ready(receipt) => receipt,
                                    AuthenticatedRead::PeerUpdate(authenticated, plaintext) => {
                                        let installed = async {
                                            let endpoint = &mut *endpoint;

                                            keys.exchange.peer_update.put(crate::quic::application::imp::keys::PeerUpdate {
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
                                                    return Err(crate::quic::application::imp::keys::Error::UnexpectedLabel(
                                                        label,
                                                    ));
                                                }
                                            };
                                            let result = keys.exchange.write_installed.take()?;
                                            keys::check_result(&result, accepted)?;

                                            result
                                        }
                                        .await?;
                                        material.application.accept_write_epoch(installed, plaintext)?
                                    }
                                };
                                *largest = Some(largest.map_or(receipt.packet_number(), |last| {
                                    last.max(receipt.packet_number())
                                }));
                                // Installing a peer key epoch crosses a real choreography await. TX and
                                // timer roles may have advanced the shared recovery clock meanwhile. Read
                                // the actual clock again at this synchronous commit; the earlier timestamp
                                // belongs to packet authentication, not to a later recovery mutation.
                                let outcome = match book.apply_application_packet(
                                    receipt,
                                    received_at,
                                    clock.now(),
                                    received.ecn,
                                    &mut packet_outcome,
                                ) {
                                    Ok(outcome) => outcome,
                                    // Expired sent history is not evidence that the peer ACKed an unsent
                                    // packet. Discard this packet without manufacturing any frame grant.
                                    Err(recovery::Error::Accounting(
                                        AccountingError::HistoryUnavailable,
                                    )) => return Ok(None),
                                    Err(error) => return Err(error.into()),
                                };
                                if outcome.frame_acks.is_some() {
                                    let grant = outcome.frame_acks.take().ok_or(Error::Binding)?;
                                    acknowledgments.deliver(grant, control)?;
                                }
                                for grant in outcome.key_acks.iter_mut().filter_map(Option::take) {
                                    async {
                                        let endpoint = &mut *endpoint;
                                        let validated =
                                            ValidatedKeyAck::from_connection_ack(grant)?;

                                        keys.exchange.key_ack.put(crate::quic::application::imp::keys::KeyAck {
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
                                                return Err(crate::quic::application::imp::keys::Error::UnexpectedLabel(label));
                                            }
                                        };
                                        let result = keys.exchange.key_ack_applied.take()?;
                                        keys::check_result(&result, accepted)?;

                                        result
                                    }
                                    .await?;
                                }
                                if let Some(confirmation) = outcome.confirmation.take() {
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
                                                    return Err(crate::quic::application::imp::keys::Error::UnexpectedLabel(
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
                                    plaintext,
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
                                    packet_number,
                                    packet_len,
                                    non_probing,
                                )?;
                                for frame in received_frames(
                                    plaintext,
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
                                                Err(stream::Error::Streams(
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
                                                    .receive(finished, input)
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
                                                packet_number,
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
                                            .put(crate::quic::application::imp::keys::LocalUpdateRequest { ready, now, pto })?;
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
                                                return Err(crate::quic::application::imp::keys::Error::UnexpectedLabel(label));
                                            }
                                        };
                                        let result = keys.exchange.local_result.take()?;
                                        if result.is_ok() != accepted {
                                            return Err(crate::quic::application::imp::keys::Error::Binding);
                                        }
                                        let result = match result {
                                            Ok(installed) => read
                                                .accept_local_write_epoch(installed)
                                                .map_err(crate::quic::application::imp::keys::Error::Crypto),
                                            Err(rejected) => {
                                                read.cancel_local_update(rejected.ready)?;
                                                Err(crate::quic::application::imp::keys::Error::Crypto(rejected.error))
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
                        Header::Long { .. } if !book.snapshot().handshake_confirmed => receive_handshake_packet::<N>(
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
                                    let Some(stream) = app.try_borrow().map_err(|_| Error::Binding)?
                    .find_readable_stream(|stream| !state.is_complete(stream.id()))?
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
                                let Some(stream) = app.try_borrow().map_err(|_| Error::Binding)?
                    .find_readable_stream(|stream| !state.is_complete(stream.id()))?
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
                            let Some(stream) = app.try_borrow().map_err(|_| Error::Binding)?
                    .find_readable_stream(|stream| !state.is_complete(stream.id()))?
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
        Ok::<(), crate::quic::application::imp::keys::Error>(())
    }
    .await?)
}

fn check(actual: u64, expected: u64) -> Result<(), Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(Error::Binding)
    }
}
