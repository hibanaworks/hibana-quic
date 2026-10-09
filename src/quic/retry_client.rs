//! Finite client Initial/Retry prefix. TLS and packet-number owners survive
//! the actual Retry branch. Native effects settle before rekeying; ordinary
//! handshake roles start only after the first authenticated server Initial.
use super::*;
use crate::{
    quic::kernel::packet::{self, Frame, Header, LongType, PacketIter},
    quic::retry::{self, client_global as p},
};
use core::ops::ControlFlow;
use hibana::g::Message;
const TOKEN_CAPACITY: usize = 512;
pub(super) struct RetryData {
    pub source: ConnectionId,
    token: [u8; TOKEN_CAPACITY],
    len: usize,
}
impl RetryData {
    pub fn token(&self) -> &[u8] {
        &self.token[..self.len]
    }
}
pub(super) struct Response<const N: usize> {
    pub bytes: [u8; N],
    pub received: ReceivedDatagram,
    pub retry: Option<RetryData>,
}

// Retained ciphertext has no authenticated protocol effects. The same bounded
// owner moves from the Retry prefix into the ordinary receive continuation.
pub(super) fn retain_handshake<const N: usize>(
    pending: &mut Option<([u8; N], ReceivedDatagram, u64)>,
    bytes: &[u8],
    received: ReceivedDatagram,
    config: Config<'_>,
    received_at: u64,
) {
    if pending.is_some() {
        return;
    }
    let Ok(packets) = PacketIter::new(bytes, config.local_connection_id.len(), 16) else {
        return;
    };
    for packet in packets {
        let Ok(packet) = packet else {
            break;
        };
        if let Header::Long {
            version,
            kind: LongType::Handshake,
            destination_id,
            ..
        } = packet.header
            && version == config.version
            && destination_id == config.local_connection_id
            && packet.bytes.len() <= N
        {
            let mut retained = [0; N];
            retained[..packet.bytes.len()].copy_from_slice(packet.bytes);
            *pending = Some((
                retained,
                ReceivedDatagram {
                    len: packet.bytes.len(),
                    ..received
                },
                received_at,
            ));
            break;
        }
    }
}

// Packet validation only. No progression or communication is hidden here.
fn authenticated_initial<const N: usize>(
    bytes: &[u8],
    config: Config<'_>,
    keys: &initial::Keys<'_>,
    integrity: &mut IntegrityBudget,
) -> Result<bool, Error> {
    let Some(Ok(packet)) = PacketIter::new(bytes, config.local_connection_id.len(), 1)
        .ok()
        .and_then(|mut packets| packets.next())
    else {
        return Ok(false);
    };
    let Header::Long {
        version,
        kind: LongType::Initial,
        destination_id,
        packet_number_offset,
        ..
    } = packet.header
    else {
        return Ok(false);
    };
    if (version != config.version && version != crate::quic::kernel::version::Version::V1)
        || destination_id != config.local_connection_id
        || packet.bytes.len() > N
    {
        return Ok(false);
    }
    let mut opened = [0; N];
    opened[..packet.bytes.len()].copy_from_slice(packet.bytes);
    let bytes = &mut opened[..packet.bytes.len()];
    let guard = keys.read_version(version);
    let key = guard.as_ref().ok_or(Error::Binding)?;
    let pn_len = match key.unprotect_header(bytes, packet_number_offset) {
        Ok(n) => n,
        Err(_) => return Ok(false),
    };
    let (truncated, _) =
        packet::decode_truncated_packet_number(bytes[0], &bytes[packet_number_offset..])?;
    let pn = packet::restore_packet_number(truncated, pn_len as u8, None)?;
    let (header, payload) = bytes.split_at_mut(packet_number_offset + pn_len);
    match key.open_authenticated(pn, header, payload, integrity) {
        Ok(_) => Ok(packet::validate_reserved_bits(header[0]).is_ok()),
        Err(crypto::Error::AuthenticationFailed) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run<'book, 'scope, const N: usize>(
    owner: &mut Endpoint<'_, { p::OWNER }>,
    native: &mut Endpoint<'_, { p::IO }>,
    source: &mut Transcript<'scope, '_, '_>,
    config: Config<'_>,
    early: bool,
    initial: &initial::Keys<'scope>,
    tx: &mut recovery::Tx<'book, 'scope, N>,
    rx: &mut recovery::Rx<'book, 'scope, N>,
    clock_book: &mut recovery::Clock<'book, 'scope, N>,
    publication: &mut recovery::Publication<'book, 'scope, N>,
    receive_io: &mut impl DatagramRx,
    send_io: &mut impl DatagramTx,
    clock: &impl Clock,
    issuer: &mut publication_gate::Issuer<'_, 'scope>,
    integrity: &mut IntegrityBudget,
    pending_handshake: &mut Option<([u8; N], ReceivedDatagram, u64)>,
) -> Result<Option<Response<N>>, Error> {
    let datagram = Inbox::<wire::Datagram<'book, N>>::new();
    let observation = Inbox::<([u8; N], ReceivedDatagram)>::new();
    let deadline_at = Inbox::<u64>::new();
    let mut response = None;
    {
        let mut driver = core::pin::pin!(async {
            if config.side != Side::Client || early {
                owner.send::<p::Skip>(&()).await?;
                owner.recv::<p::Skipped>().await?;
                return Ok::<(), Error>(());
            }
            let peer = ConnectionId::new(config.peer_connection_id)?;
            let mut keys = wire::WriteKeys {
                initial,
                handshake: None,
                application: None,
            };
            let mut flight = source.transmit::<N>()?.ok_or(Error::Binding)?;
            loop {
                if flight.level() != Level::Initial {
                    return Err(Error::Binding);
                }
                for (index, bytes) in flight
                    .bytes()
                    .chunks(
                        N.checked_sub(128 + TOKEN_CAPACITY)
                            .filter(|n| *n > 0)
                            .ok_or(Error::Capacity)?,
                    )
                    .enumerate()
                {
                    let offset = flight.offset() + (index * (N - 128 - TOKEN_CAPACITY)) as u64;
                    let id = tx.store_crypto(Level::Initial, offset, bytes)?;
                    let packet = local::prepare(
                        &mut keys,
                        tx,
                        config,
                        &peer,
                        Level::Initial,
                        Frame::Crypto {
                            offset,
                            data: bytes,
                        },
                        Some(id),
                        false,
                        None,
                        clock.now(),
                    )?
                    .ok_or(Error::Capacity)?;
                    datagram.put(packet)?;
                    owner.send::<p::Packet>(&()).await?;
                    let verdict = owner.offer().await?;
                    match verdict.label() {
                        label if label == p::Accepted::LOGICAL_LABEL => {
                            verdict.recv::<p::Accepted>().await?;
                        }
                        label if label == p::Rejected::LOGICAL_LABEL => {
                            verdict.recv::<p::Rejected>().await?;
                            owner.send::<p::Settled>(&()).await?;
                            return Err(Error::Io(IoError::Rejected));
                        }
                        label => return Err(Error::UnexpectedLabel(label)),
                    }
                    owner.send::<p::Settled>(&()).await?;
                }
                match source.transmit::<N>()? {
                    Some(next) => flight = next,
                    None => break,
                }
            }
            let retry = loop {
                while let Some((id, probe)) = tx.next_retransmit() {
                    let flight = tx.flight_data(id)?;
                    if flight.level() != Level::Initial {
                        return Err(Error::Binding);
                    }
                    let packet = local::prepare(
                        &mut keys,
                        tx,
                        config,
                        &peer,
                        Level::Initial,
                        Frame::Crypto {
                            offset: flight.offset(),
                            data: flight.bytes(),
                        },
                        Some(id),
                        probe,
                        None,
                        clock.now(),
                    )?
                    .ok_or(Error::Capacity)?;
                    datagram.put(packet)?;
                    owner.send::<p::Packet>(&()).await?;
                    let verdict = owner.offer().await?;
                    match verdict.label() {
                        label if label == p::Accepted::LOGICAL_LABEL => {
                            verdict.recv::<p::Accepted>().await?;
                        }
                        label if label == p::Rejected::LOGICAL_LABEL => {
                            verdict.recv::<p::Rejected>().await?;
                            owner.send::<p::Settled>(&()).await?;
                            return Err(Error::Io(IoError::Rejected));
                        }
                        label => return Err(Error::UnexpectedLabel(label)),
                    }
                    owner.send::<p::Settled>(&()).await?;
                }
                let deadline = clock_book
                    .update(clock.now(), [true, false])?
                    .ok_or(Error::Binding)?;
                deadline_at.put(deadline.at())?;
                owner.send::<p::Listen>(&()).await?;
                let verdict = owner.offer().await?;
                let (bytes, received) = match verdict.label() {
                    label if label == p::Observed::LOGICAL_LABEL => {
                        verdict.recv::<p::Observed>().await?;
                        let result = observation.take()?;
                        owner.send::<p::Taken>(&()).await?;
                        result
                    }
                    label if label == p::Expired::LOGICAL_LABEL => {
                        verdict.recv::<p::Expired>().await?;
                        owner.send::<p::Taken>(&()).await?;
                        clock_book.expire(deadline, clock.now())?;
                        continue;
                    }
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                let len = received.len;
                rx.received_datagram(len as u64)?;
                let mut scratch = [0; N];
                if let Ok(checked) = retry::validate_retry(
                    config.original_destination_id,
                    config.local_connection_id,
                    &bytes[..len],
                    TOKEN_CAPACITY,
                    &mut scratch,
                ) {
                    let mut token = [0; TOKEN_CAPACITY];
                    token[..checked.token().len()].copy_from_slice(checked.token());
                    break RetryData {
                        source: ConnectionId::new(checked.source_id())?,
                        token,
                        len: checked.token().len(),
                    };
                }
                retain_handshake(
                    pending_handshake,
                    &bytes[..len],
                    received,
                    config,
                    clock.now(),
                );
                if authenticated_initial::<N>(&bytes[..len], config, initial, integrity)? {
                    owner.send::<p::Quiesce>(&()).await?;
                    owner.recv::<p::Quiescent>().await?;
                    owner.send::<p::Bypass>(&()).await?;
                    owner.recv::<p::Bypassed>().await?;
                    owner.send::<p::Proceed>(&()).await?;
                    owner.recv::<p::Joined>().await?;
                    response = Some(Response {
                        bytes,
                        received,
                        retry: None,
                    });
                    return Ok(());
                }
            };
            owner.send::<p::Quiesce>(&()).await?;
            owner.recv::<p::Quiescent>().await?;
            owner.send::<p::Rekey>(&()).await?;
            owner.recv::<p::Rekeyed>().await?;
            // Retry creates a new Initial binding; old ciphertext cannot cross it.
            *pending_handshake = None;
            tx.retry_initial(clock.now())?;
            initial.replace_for_retry(retry.source.bytes())?;
            let peer = retry.source;
            let config = Config {
                retry_source_id: Some(retry.source.bytes()),
                initial_token: retry.token(),
                peer_connection_id: retry.source.bytes(),
                ..config
            };
            let (bytes, received) = loop {
                while let Some((id, probe)) = tx.next_retransmit() {
                    let flight = tx.flight_data(id)?;
                    if flight.level() != Level::Initial {
                        return Err(Error::Binding);
                    }
                    let packet = local::prepare(
                        &mut keys,
                        tx,
                        config,
                        &peer,
                        Level::Initial,
                        Frame::Crypto {
                            offset: flight.offset(),
                            data: flight.bytes(),
                        },
                        Some(id),
                        probe,
                        None,
                        clock.now(),
                    )?
                    .ok_or(Error::Capacity)?;
                    datagram.put(packet)?;
                    owner.send::<p::RetriedPacket>(&()).await?;
                    let verdict = owner.offer().await?;
                    match verdict.label() {
                        label if label == p::RetriedAccepted::LOGICAL_LABEL => {
                            verdict.recv::<p::RetriedAccepted>().await?;
                        }
                        label if label == p::RetriedRejected::LOGICAL_LABEL => {
                            verdict.recv::<p::RetriedRejected>().await?;
                            owner.send::<p::RetriedSettled>(&()).await?;
                            return Err(Error::Io(IoError::Rejected));
                        }
                        label => return Err(Error::UnexpectedLabel(label)),
                    }
                    owner.send::<p::RetriedSettled>(&()).await?;
                }
                let deadline = clock_book
                    .update(clock.now(), [true, false])?
                    .ok_or(Error::Binding)?;
                deadline_at.put(deadline.at())?;
                owner.send::<p::RetriedListen>(&()).await?;
                let verdict = owner.offer().await?;
                let (bytes, received) = match verdict.label() {
                    label if label == p::RetriedObserved::LOGICAL_LABEL => {
                        verdict.recv::<p::RetriedObserved>().await?;
                        let result = observation.take()?;
                        owner.send::<p::RetriedTaken>(&()).await?;
                        result
                    }
                    label if label == p::RetriedExpired::LOGICAL_LABEL => {
                        verdict.recv::<p::RetriedExpired>().await?;
                        owner.send::<p::RetriedTaken>(&()).await?;
                        clock_book.expire(deadline, clock.now())?;
                        continue;
                    }
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                let len = received.len;
                rx.received_datagram(len as u64)?;
                retain_handshake(
                    pending_handshake,
                    &bytes[..len],
                    received,
                    config,
                    clock.now(),
                );
                if authenticated_initial::<N>(&bytes[..len], config, initial, integrity)? {
                    break (bytes, received);
                }
                // There is no Retry branch in this projected continuation.
            };
            owner.send::<p::RetriedQuiesce>(&()).await?;
            owner.recv::<p::RetriedQuiescent>().await?;
            owner.send::<p::Proceed>(&()).await?;
            owner.recv::<p::Joined>().await?;
            response = Some(Response {
                bytes,
                received,
                retry: Some(retry),
            });
            Ok(())
        });
        let mut io = core::pin::pin!(async {
            let first = native.offer().await?;
            if first.label() == p::Skip::LOGICAL_LABEL {
                first.recv::<p::Skip>().await?;
                native.send::<p::Skipped>(&()).await?;
                return Ok(());
            }
            first.recv::<p::Packet>().await?;
            let packet = datagram.take()?;
            let permit = match issuer.begin() {
                Ok(p) => p,
                Err(e) => {
                    publication.cancel(packet.reservation)?;
                    return Err(e.into());
                }
            };
            if !core::ptr::eq(permit.scope(), packet.reservation.scope()) {
                publication.cancel(packet.reservation)?;
                return Err(Error::Binding);
            }
            let result = permit
                .submit(send_io.send(packet.sealed.bytes(), crate::quic::ecn::Codepoint::NotEct))
                .await;
            let accepted = match result {
                Ok(Ok(at)) => Some(at),
                _ => None,
            };
            publication.settle(recovery::Completion::from_adapter(
                packet.reservation,
                accepted,
                crate::quic::ecn::Codepoint::NotEct,
            ))?;
            if accepted.is_some() {
                native.send::<p::Accepted>(&()).await?;
            } else {
                native.send::<p::Rejected>(&()).await?;
            }
            native.recv::<p::Settled>().await?;
            loop {
                let branch = native.offer().await?;
                match branch.label() {
                    label if label == p::Packet::LOGICAL_LABEL => {
                        branch.recv::<p::Packet>().await?;
                        let packet = datagram.take()?;
                        let permit = match issuer.begin() {
                            Ok(p) => p,
                            Err(e) => {
                                publication.cancel(packet.reservation)?;
                                return Err(e.into());
                            }
                        };
                        if !core::ptr::eq(permit.scope(), packet.reservation.scope()) {
                            publication.cancel(packet.reservation)?;
                            return Err(Error::Binding);
                        }
                        let result =
                            permit
                                .submit(send_io.send(
                                    packet.sealed.bytes(),
                                    crate::quic::ecn::Codepoint::NotEct,
                                ))
                                .await;
                        let accepted = match result {
                            Ok(Ok(at)) => Some(at),
                            _ => None,
                        };
                        publication.settle(recovery::Completion::from_adapter(
                            packet.reservation,
                            accepted,
                            crate::quic::ecn::Codepoint::NotEct,
                        ))?;
                        if accepted.is_some() {
                            native.send::<p::Accepted>(&()).await?;
                        } else {
                            native.send::<p::Rejected>(&()).await?;
                        }
                        native.recv::<p::Settled>().await?;
                    }
                    label if label == p::Listen::LOGICAL_LABEL => {
                        branch.recv::<p::Listen>().await?;
                        let at = deadline_at.take()?;
                        let mut bytes = [0; N];
                        match crate::runtime::select(
                            receive_io.receive(&mut bytes),
                            clock.wait_until(at),
                        )
                        .await
                        {
                            ControlFlow::Break(result) => {
                                let received = result?;
                                if config.initial_path.is_some()
                                    && received.path != config.initial_path
                                {
                                    continue;
                                }

                                if received.len > N {
                                    return Err(Error::Capacity);
                                }
                                observation.put((bytes, received))?;
                                native.send::<p::Observed>(&()).await?;
                            }
                            ControlFlow::Continue(()) => {
                                native.send::<p::Expired>(&()).await?;
                            }
                        }
                        native.recv::<p::Taken>().await?;
                    }
                    label if label == p::Quiesce::LOGICAL_LABEL => {
                        branch.recv::<p::Quiesce>().await?;
                        native.send::<p::Quiescent>(&()).await?;
                        break;
                    }
                    label => return Err(Error::UnexpectedLabel(label)),
                }
            }
            let branch = native.offer().await?;
            match branch.label() {
                label if label == p::Rekey::LOGICAL_LABEL => {
                    branch.recv::<p::Rekey>().await?;
                    native.send::<p::Rekeyed>(&()).await?;
                    loop {
                        let branch = native.offer().await?;
                        match branch.label() {
                            label if label == p::RetriedPacket::LOGICAL_LABEL => {
                                branch.recv::<p::RetriedPacket>().await?;
                                let packet = datagram.take()?;
                                let permit = match issuer.begin() {
                                    Ok(p) => p,
                                    Err(e) => {
                                        publication.cancel(packet.reservation)?;
                                        return Err(e.into());
                                    }
                                };
                                if !core::ptr::eq(permit.scope(), packet.reservation.scope()) {
                                    publication.cancel(packet.reservation)?;
                                    return Err(Error::Binding);
                                }
                                let result = permit
                                    .submit(send_io.send(
                                        packet.sealed.bytes(),
                                        crate::quic::ecn::Codepoint::NotEct,
                                    ))
                                    .await;
                                let accepted = match result {
                                    Ok(Ok(at)) => Some(at),
                                    _ => None,
                                };
                                publication.settle(recovery::Completion::from_adapter(
                                    packet.reservation,
                                    accepted,
                                    crate::quic::ecn::Codepoint::NotEct,
                                ))?;
                                if accepted.is_some() {
                                    native.send::<p::RetriedAccepted>(&()).await?;
                                } else {
                                    native.send::<p::RetriedRejected>(&()).await?;
                                }
                                native.recv::<p::RetriedSettled>().await?;
                            }
                            label if label == p::RetriedListen::LOGICAL_LABEL => {
                                branch.recv::<p::RetriedListen>().await?;
                                let at = deadline_at.take()?;
                                let mut bytes = [0; N];
                                match crate::runtime::select(
                                    receive_io.receive(&mut bytes),
                                    clock.wait_until(at),
                                )
                                .await
                                {
                                    ControlFlow::Break(result) => {
                                        let received = result?;
                                        if config.initial_path.is_some()
                                            && received.path != config.initial_path
                                        {
                                            continue;
                                        }

                                        if config.initial_path.is_some()
                                            && received.path != config.initial_path
                                        {
                                            continue;
                                        }

                                        if received.len > N {
                                            return Err(Error::Capacity);
                                        }
                                        observation.put((bytes, received))?;
                                        native.send::<p::RetriedObserved>(&()).await?;
                                    }
                                    ControlFlow::Continue(()) => {
                                        native.send::<p::RetriedExpired>(&()).await?;
                                    }
                                }
                                native.recv::<p::RetriedTaken>().await?;
                            }
                            label if label == p::RetriedQuiesce::LOGICAL_LABEL => {
                                branch.recv::<p::RetriedQuiesce>().await?;
                                native.send::<p::RetriedQuiescent>(&()).await?;
                                break;
                            }
                            label => return Err(Error::UnexpectedLabel(label)),
                        }
                    }
                }
                label if label == p::Bypass::LOGICAL_LABEL => {
                    branch.recv::<p::Bypass>().await?;
                    native.send::<p::Bypassed>(&()).await?;
                }
                label => return Err(Error::UnexpectedLabel(label)),
            }
            native.recv::<p::Proceed>().await?;
            native.send::<p::Joined>(&()).await?;
            Ok::<(), Error>(())
        });
        crate::runtime::TaskSet::new([driver.as_mut(), io.as_mut()]).await?;
    }
    Ok(response)
}
