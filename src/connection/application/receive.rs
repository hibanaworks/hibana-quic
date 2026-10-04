//! The application receive continuation owns authentication and frame effects.
//! Plaintext, affine key transitions and stream handles remain local; only the
//! declared key, delivery and termination edges cross async role boundaries.
use super::{Control, Error, io, keys, protocol as p, termination};
use crate::{
    accounting::AccountingError,
    connection::{
        self, Clock, Config, DatagramRx, ReceiveMaterial, Side, application_stream,
        application_wire, recovery,
        tls::{CryptoInput, Transcript},
    },
    crypto::{
        self,
        directional::{AuthenticatedRead, ScopedHandshakeConfirmation, ValidatedKeyAck},
    },
    handshake::CryptoBuffer,
    packet::{self, Frame, FrameIter, Header, LongType, PacketIter, ParseLimits},
    streams,
    tls::Level,
};
use core::cell::RefCell;
use hibana::Endpoint;
use zeroize::Zeroizing;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run<'owner, 'scope, const N: usize, const RX: usize, const CHUNK: usize>(
    receive: &mut Endpoint<'_, { p::RECEIVE }>,
    rx_keys: &mut Endpoint<'_, { p::RX_KEYS }>,
    peer_event: &mut Endpoint<'_, { p::PEER_EVENT }>,
    mut material: ReceiveMaterial<'scope>,
    config: Config<'_>,
    transcript: &mut Transcript<'scope, '_, '_>,
    mut crypto: CryptoBuffer<'_>,
    book: &mut recovery::Rx<'_, 'scope, N>,
    streams: &mut application_stream::Rx<'_, '_, 'scope, RX, CHUNK>,
    app: &RefCell<application_stream::App<'_, '_, 'scope, RX, CHUNK>>,
    state: &io::State<'_, CHUNK>,
    mut keys: keys::RxControl<'_, 'owner, 'scope>,
    control: &Control<'_, 'scope>,
    clock: &impl Clock,
    socket: &mut impl DatagramRx,
    termination: &termination::Exchange<'_, '_, 'scope>,
    initial_confirmation: Option<recovery::HandshakeConfirmed<'scope>>,
) -> Result<keys::KeysQuiesced<'owner, 'scope>, Error> {
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
    let mut confirmed = false;
    if let Some(confirmation) = initial_confirmation {
        confirm(
            rx_keys,
            &mut keys,
            &mut material,
            book,
            control,
            confirmation,
        )
        .await?;
        confirmed = true;
    }
    let mut datagram = [0; N];
    let mut largest = None;
    let mut peer_reported = false;
    'receive: while !control.stopping() {
        let Some(result) = control.until_stop(3, socket.receive(&mut datagram)).await else {
            break;
        };
        let len = result.map_err(connection::Error::from)?;
        if len > N {
            return Err(Error::Capacity);
        }
        book.received_datagram(len as u64)?;
        control.changed()?;
        let mut offset = 0;
        while offset < len && !control.stopping() {
            // Parse one bounded packet at a time; all pre-AEAD syntax errors
            // discard the remainder because its next boundary is untrusted.
            let packet =
                match PacketIter::new(&datagram[offset..len], config.local_connection_id.len(), 1)
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
                Header::Short { .. } => {
                    application::<N, RX, CHUNK>(
                        rx_keys,
                        &mut keys,
                        &mut material,
                        packet.bytes,
                        config,
                        transcript,
                        &mut crypto,
                        book,
                        streams,
                        control,
                        clock.now(),
                        &mut largest,
                        &mut confirmed,
                    )
                    .await
                }
                Header::Long { .. } if !confirmed => old::<N>(
                    &mut material,
                    packet,
                    len,
                    config,
                    transcript,
                    book,
                    clock.now(),
                ),
                _ => Ok(None),
            };
            match result {
                Ok(Some(code)) => {
                    termination::peer_close(peer_event, termination, scope, code).await?;
                    peer_reported = true;
                    break 'receive;
                }
                Ok(None) => {}
                Err(error) => {
                    let code = protocol_code(&error);
                    control.record_protocol_error(error);
                    termination::protocol_failed(peer_event, termination, scope, code).await?;
                    peer_reported = true;
                    break 'receive;
                }
            }
            control.changed()?;
            notify_ready(receive, control, state, app).await?;
            // A socket with immediately ready buffered packets must still let
            // TX, the adapter and the deadline role make bounded progress.
            crate::runtime::yield_now().await;
        }
        crate::runtime::yield_now().await;
    }
    if !peer_reported {
        termination::cancel_peer(peer_event, termination).await?;
    }
    receive.send::<p::ReceiveRetire>(&0).await?;
    check(receive.recv::<p::ReceiveRetired>().await?, 0)?;
    material.application.discard();
    if let Some(mut initial) = material.initial.take() {
        initial.discard();
    }
    material.handshake.discard();
    Ok(keys.retire(rx_keys).await?)
}

#[allow(clippy::too_many_arguments)]
async fn application<'scope, const N: usize, const RX: usize, const CHUNK: usize>(
    endpoint: &mut Endpoint<'_, { p::RX_KEYS }>,
    keys: &mut keys::RxControl<'_, '_, 'scope>,
    material: &mut ReceiveMaterial<'scope>,
    packet: &[u8],
    config: Config<'_>,
    transcript: &mut Transcript<'scope, '_, '_>,
    reassembly: &mut CryptoBuffer<'_>,
    book: &mut recovery::Rx<'_, 'scope, N>,
    streams: &mut application_stream::Rx<'_, '_, 'scope, RX, CHUNK>,
    control: &Control<'_, 'scope>,
    now: u64,
    largest: &mut Option<u64>,
    confirmed: &mut bool,
) -> Result<Option<u64>, Error> {
    let pto = book.pto_duration_us()?;
    material.application.maintain(now, pto)?;
    let mut opened = match application_wire::open::<N>(
        &mut material.application,
        &mut material.integrity,
        packet,
        config.local_connection_id,
        *largest,
        now,
        pto,
    ) {
        Ok(opened) => opened,
        Err(error) if discard_before_authentication(&error) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let receipt = match opened.take_receipt().ok_or(Error::Binding)? {
        AuthenticatedRead::Ready(receipt) => receipt,
        AuthenticatedRead::PeerUpdate(authenticated) => {
            let installed = keys.peer_update(endpoint, authenticated, now, pto).await?;
            material.application.accept_write_epoch(installed)?
        }
    };
    *largest = Some(largest.map_or(opened.packet_number(), |last| {
        last.max(opened.packet_number())
    }));
    let outcome = match book.apply_application_packet(receipt, opened.plaintext(), now) {
        Ok(outcome) => outcome,
        // Expired sent history is not evidence that the peer ACKed an unsent
        // packet. Discard this packet without manufacturing any frame grant.
        Err(recovery::Error::Accounting(AccountingError::HistoryUnavailable)) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    streams.acknowledge(&outcome.packets)?;
    for grant in outcome.key_acks.into_iter().flatten() {
        keys.acknowledge(
            endpoint,
            ValidatedKeyAck::from_connection_ack(grant)?,
            now,
            pto,
        )
        .await?;
    }
    if let Some(confirmation) = outcome.confirmation {
        confirm(endpoint, keys, material, book, control, confirmation).await?;
        *confirmed = true;
    }
    if outcome.duplicate {
        return Ok(None);
    }
    for frame in received_frames(opened.plaintext(), packet::EncryptionLevel::OneRtt)? {
        let frame = frame?;
        match frame {
            Frame::Stream { .. }
            | Frame::ResetStream { .. }
            | Frame::StopSending { .. }
            | Frame::MaxData { .. }
            | Frame::MaxStreamData { .. }
            | Frame::MaxStreams { .. }
            | Frame::DataBlocked { .. }
            | Frame::StreamDataBlocked { .. }
            | Frame::StreamsBlocked { .. } => streams.apply(&frame)?,
            Frame::Crypto { offset, data } => {
                reassembly
                    .insert(offset, data)
                    .map_err(connection::Error::from)?;
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
                    .map_err(connection::Error::from)?;
                    transcript.receive(input).map_err(connection::Error::from)?;
                    reassembly.consume(count).map_err(connection::Error::from)?;
                }
            }
            Frame::ConnectionClose { error_code, .. } => return Ok(Some(error_code)),
            Frame::NewToken { .. } if config.side == Side::Client => {
                // This fixed-path request session does not save resumption or
                // address-validation tokens for a future connection.
            }
            Frame::NewConnectionId {
                retire_prior_to: 0, ..
            } => {
                // Additional peer CIDs are optional on this fixed path. The
                // current handshake-selected CID remains valid at sequence 0.
            }
            Frame::Padding { .. }
            | Frame::Ping
            | Frame::Ack { .. }
            | Frame::HandshakeDone
            | Frame::PathResponse { .. } => {}
            Frame::NewToken { .. }
            | Frame::NewConnectionId { .. }
            | Frame::RetireConnectionId { .. }
            | Frame::PathChallenge { .. } => {
                return Err(connection::Error::UnsupportedFrame.into());
            }
        }
    }
    Ok(None)
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
) -> Result<Option<u64>, Error> {
    let Header::Long {
        kind,
        destination_id,
        source_id,
        packet_number_offset,
        ..
    } = packet.header
    else {
        return Ok(None);
    };
    if destination_id != config.local_connection_id
        && !(config.side == Side::Server
            && kind == LongType::Initial
            && destination_id == config.original_destination_id)
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
    let outcome = match book.apply_packet(receipt, plaintext, now) {
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
                        return Err(connection::Error::UnsupportedFrame.into());
                    }
                }
                Frame::ConnectionClose { error_code, .. } => return Ok(Some(error_code)),
                Frame::Padding { .. } | Frame::Ping | Frame::Ack { .. } => {}
                _ => return Err(connection::Error::UnsupportedFrame.into()),
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

async fn confirm<'scope, const N: usize>(
    endpoint: &mut Endpoint<'_, { p::RX_KEYS }>,
    keys: &mut keys::RxControl<'_, '_, 'scope>,
    material: &mut ReceiveMaterial<'scope>,
    book: &mut recovery::Rx<'_, 'scope, N>,
    control: &Control<'_, 'scope>,
    confirmation: recovery::HandshakeConfirmed<'scope>,
) -> Result<(), Error> {
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
    keys.confirm(
        endpoint,
        ScopedHandshakeConfirmation::from_connection(confirmation),
    )
    .await?;
    if let Some(mut initial) = material.initial.take() {
        initial.discard();
    }
    material.handshake.discard();
    control.changed()?;
    Ok(())
}

async fn notify_ready<const RX: usize, const CHUNK: usize>(
    endpoint: &mut Endpoint<'_, { p::RECEIVE }>,
    control: &Control<'_, '_>,
    state: &io::State<'_, CHUNK>,
    app: &RefCell<application_stream::App<'_, '_, '_, RX, CHUNK>>,
) -> Result<(), Error> {
    // A sink error asks the independent completion lane to close. Do not keep
    // redispatching that same ready stream while that lane is being scheduled.
    while !control.stopping() && !control.failed() {
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
            label => return Err(Error::UnexpectedLabel(label)),
        }
        crate::runtime::yield_now().await;
    }
    Ok(())
}

fn discard_before_authentication(error: &connection::Error) -> bool {
    matches!(
        error,
        connection::Error::Binding
            | connection::Error::Capacity
            | connection::Error::Crypto(
                crypto::Error::AuthenticationFailed
                    | crypto::Error::InvalidPacketNumber
                    | crypto::Error::InvalidHeader
                    | crypto::Error::BufferTooSmall
                    | crypto::Error::PacketTooLarge
            )
            | connection::Error::Packet(
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
        | Error::Connection(connection::Error::Crypto(crypto::Error::KeyUpdateError)) => 0xe,
        Error::Crypto(crypto::Error::IntegrityLimit | crypto::Error::ConfidentialityLimit)
        | Error::Connection(connection::Error::Crypto(
            crypto::Error::IntegrityLimit | crypto::Error::ConfidentialityLimit,
        )) => 0xf,
        Error::Packet(packet::Error::ReservedBits | packet::Error::EmptyPayload)
        | Error::Connection(connection::Error::Packet(
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
