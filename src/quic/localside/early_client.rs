//! Projected TLS_TX/TX_WIRE/UDP execution for the client early-data prefix.
use super::{
    Clock, Config, DatagramTx, Outcome, Side, global as p, publication_gate, recovery,
    tls::{CryptoFlight, Inbox, Transcript},
    wire,
};
use super::{Endpoints, Error};
use crate::quic::early_data::imp::EarlyStatus;
use crate::quic::imp::early_requests::Requests;
use crate::quic::imp::kernel::packet::Frame;
use core::pin::pin;
use hibana::{g::Message, runtime::resolver::DecisionArm};
use hibana_tls::handshake::keys::EarlyKeyMaterial;
use hibana_tls::handshake::keys::TransmitPacketKey;
use hibana_tls::quic::Level;
use hibana_tls::secret::Erase;

/// One finite projected prefix. Normal handshakes traverse the explicit Skip
/// edges; an enabled client sends ClientHello before any early datagram.
#[allow(clippy::too_many_arguments)]
pub(in crate::quic) async fn run<'book, 'scope, const N: usize>(
    endpoints: &mut Endpoints<'_>,
    source: &mut Transcript<'scope, '_, '_>,
    requests: Option<&mut Requests<'_, 'scope>>,
    config: Config<'_>,
    initial: &crate::quic::imp::initial::Keys<'scope>,
    tx: &mut recovery::Tx<'book, 'scope, N>,
    publication: &mut recovery::Publication<'book, 'scope, N>,
    io: &mut impl DatagramTx,
    clock: &impl Clock,
    issuer: &mut publication_gate::Issuer<'_, 'scope>,
    outcome: &Outcome,
) -> Result<(), Error> {
    let enabled = requests.is_some();
    let prepared = Inbox::<(CryptoFlight<N>, TransmitPacketKey<'scope>)>::new();
    let datagrams = Inbox::<wire::Datagram<'book, N>>::new();
    let scope = source.scope();
    let mut prepare = pin!(async {
        if !enabled {
            endpoints.tls_tx.send::<p::EarlySkip>(&()).await?;
            endpoints.tls_tx.send::<p::EarlyContinue>(&()).await?;
            return Ok(());
        }
        if config.side != Side::Client || source.early_status() != EarlyStatus::Offered {
            return Err(Error::Binding);
        }
        let EarlyKeyMaterial::Transmit(key) = source.take_early_key()? else {
            return Err(Error::Binding);
        };
        let flight = source.transmit::<N>()?.ok_or(Error::Binding)?;
        if flight.level() != Level::Initial || flight.offset() != 0 {
            return Err(Error::Binding);
        }
        prepared.put((flight, key))?;
        endpoints.tls_tx.send::<p::EarlyStart>(&()).await?;
        endpoints.tls_tx.recv::<p::EarlyDone>().await?;
        endpoints.tls_tx.send::<p::EarlyContinue>(&()).await?;
        Ok(())
    });
    let mut wire = pin!(async {
        let edge = endpoints.tx_wire.offer().await?;
        if edge.label() == p::EarlySkip::LOGICAL_LABEL {
            edge.recv::<p::EarlySkip>().await?;
            endpoints.tx_wire.send::<p::EarlySkip>(&()).await?;
            return Ok(());
        }
        edge.recv::<p::EarlyStart>().await?;
        let requests = requests.ok_or(Error::Binding)?;
        if !core::ptr::eq(requests.scope(), scope) {
            return Err(Error::Binding);
        }
        let (flight, mut key) = prepared.take()?;
        endpoints.tx_wire.send::<p::EarlyStart>(&()).await?;
        let flight_id = tx.store_crypto(Level::Initial, flight.offset(), flight.bytes())?;
        let peer = super::ConnectionId::new(config.peer_connection_id)?;
        let plain = wire::PlainPacket::<N>::new(
            config,
            &peer,
            Level::Initial,
            Frame::Crypto {
                offset: flight.offset(),
                data: flight.bytes(),
            },
        )?;
        let reservation = tx.reserve(
            Level::Initial,
            plain.len() as u64,
            Some(flight_id),
            true,
            plain.padded(),
            false,
            clock.now(),
        )?;
        let initial_packet = match initial.seal(plain, reservation, None) {
            Ok(packet) => packet,
            Err((error, reservation)) => {
                tx.cancel(reservation)?;
                return Err(error);
            }
        };
        async {
            let endpoint = &mut endpoints.tx_wire;
            let slot = &datagrams;
            let packet = initial_packet;

            slot.put(packet)?;
            endpoint.send::<p::EarlyInitialDatagram>(&()).await?;
            let edge = endpoint.offer().await?;
            let accepted = if edge.label() == p::EarlyInitialAccepted::LOGICAL_LABEL {
                edge.recv::<p::EarlyInitialAccepted>().await?;
                true
            } else {
                edge.recv::<p::EarlyInitialRejected>().await?;
                false
            };
            endpoint.send::<p::EarlyInitialSettled>(&()).await?;
            if accepted {
                Ok::<(), Error>(())
            } else {
                Err(Error::Io(super::IoError::Rejected))
            }
        }
        .await?;
        for index in 0..requests.len() {
            let mut plaintext = [0; N];
            let Some(len) = requests.encode(index, &mut plaintext)? else {
                break;
            };
            let size = super::early_wire::encoded_len(
                config.peer_connection_id,
                config.local_connection_id,
                len,
            )?;
            if size > N || size as u64 > requests.max_udp_payload() {
                break;
            }
            let reservation =
                match tx.reserve_early(&key, &plaintext[..len], size as u64, clock.now()) {
                    Ok(reservation) => reservation,
                    Err(
                        recovery::Error::CongestionLimited
                        | recovery::Error::Accounting(
                            crate::quic::imp::kernel::accounting::AccountingError::Full,
                        ),
                    ) => break,
                    Err(error) => return Err(error.into()),
                };
            let pn = reservation.packet().value;
            let sealed = match super::early_wire::seal::<N>(
                &mut key,
                reservation,
                config.peer_connection_id,
                config.local_connection_id,
                &plaintext[..len],
            ) {
                Ok(packet) => packet,
                Err((error, reservation)) => {
                    tx.cancel(reservation)?;
                    return Err(error);
                }
            };
            async {
                let endpoint = &mut endpoints.tx_wire;
                let slot = &datagrams;
                let packet = wire::Datagram::from_early(sealed);

                slot.put(packet)?;
                endpoint.send::<p::EarlyPacketDatagram>(&()).await?;
                let edge = endpoint.offer().await?;
                let accepted = if edge.label() == p::EarlyPacketAccepted::LOGICAL_LABEL {
                    edge.recv::<p::EarlyPacketAccepted>().await?;
                    true
                } else {
                    edge.recv::<p::EarlyPacketRejected>().await?;
                    false
                };
                endpoint.send::<p::EarlyPacketSettled>(&()).await?;
                if accepted {
                    Ok::<(), Error>(())
                } else {
                    Err(Error::Io(super::IoError::Rejected))
                }
            }
            .await?;
            requests.accepted(index, pn, &plaintext[..len])?;
            plaintext.erase();
        }
        drop(key);
        endpoints.tx_wire.send::<p::EarlyEnd>(&()).await?;
        endpoints.tx_wire.send::<p::EarlyDone>(&()).await?;
        Ok(())
    });
    let mut publish = pin!(async {
        let edge = endpoints.udp.offer().await?;
        if edge.label() == p::EarlySkip::LOGICAL_LABEL {
            edge.recv::<p::EarlySkip>().await?;
            return Ok(());
        }
        edge.recv::<p::EarlyStart>().await?;
        endpoints.udp.recv::<p::EarlyInitialDatagram>().await?;
        async {
            let endpoint = &mut endpoints.udp;
            let slot = &datagrams;
            let io = &mut *io;
            let book = &mut *publication;
            let issuer = &mut *issuer;

            let packet = slot.take()?;
            let permit = match issuer.begin() {
                Ok(permit) => permit,
                Err(error) => {
                    book.cancel(packet.reservation)?;
                    return Err(error.into());
                }
            };
            if !core::ptr::eq(permit.scope(), packet.reservation.scope()) {
                book.cancel(packet.reservation)?;
                return Err(Error::Binding);
            }
            let result = permit
                .submit(io.send(packet.sealed.bytes(), crate::io::Codepoint::NotEct))
                .await;
            let accepted = match result {
                Ok(Ok(time)) => Some(time),
                _ => None,
            };
            book.settle(recovery::Completion::from_adapter(
                packet.reservation,
                accepted,
                crate::io::Codepoint::NotEct,
            ))?;
            outcome.set(accepted.is_some())?;
            match outcome.resolver::<{ p::ADAPTER_RESULT }>().decide()? {
                DecisionArm::Left => endpoint.send::<p::EarlyInitialAccepted>(&()).await?,
                DecisionArm::Right => endpoint.send::<p::EarlyInitialRejected>(&()).await?,
            }
            endpoint.recv::<p::EarlyInitialSettled>().await?;
            outcome.clear();
            match result {
                Ok(Ok(_)) => Ok::<(), Error>(()),
                Ok(Err(error)) => Err(error.into()),
                Err(error) => Err(error.into()),
            }
        }
        .await?;
        loop {
            let edge = endpoints.udp.offer().await?;
            if edge.label() == p::EarlyEnd::LOGICAL_LABEL {
                edge.recv::<p::EarlyEnd>().await?;
                return Ok(());
            }
            edge.recv::<p::EarlyPacketDatagram>().await?;
            async {
                let endpoint = &mut endpoints.udp;
                let slot = &datagrams;
                let io = &mut *io;
                let book = &mut *publication;
                let issuer = &mut *issuer;

                let packet = slot.take()?;
                let permit = match issuer.begin() {
                    Ok(permit) => permit,
                    Err(error) => {
                        book.cancel(packet.reservation)?;
                        return Err(error.into());
                    }
                };
                if !core::ptr::eq(permit.scope(), packet.reservation.scope()) {
                    book.cancel(packet.reservation)?;
                    return Err(Error::Binding);
                }
                let result = permit
                    .submit(io.send(packet.sealed.bytes(), crate::io::Codepoint::NotEct))
                    .await;
                let accepted = match result {
                    Ok(Ok(time)) => Some(time),
                    _ => None,
                };
                book.settle(recovery::Completion::from_adapter(
                    packet.reservation,
                    accepted,
                    crate::io::Codepoint::NotEct,
                ))?;
                outcome.set(accepted.is_some())?;
                match outcome.resolver::<{ p::ADAPTER_RESULT }>().decide()? {
                    DecisionArm::Left => endpoint.send::<p::EarlyPacketAccepted>(&()).await?,
                    DecisionArm::Right => endpoint.send::<p::EarlyPacketRejected>(&()).await?,
                }
                endpoint.recv::<p::EarlyPacketSettled>().await?;
                outcome.clear();
                match result {
                    Ok(Ok(_)) => Ok::<(), Error>(()),
                    Ok(Err(error)) => Err(error.into()),
                    Err(error) => Err(error.into()),
                }
            }
            .await?;
        }
    });
    let mut resume = pin!(async {
        endpoints.tx.recv::<p::EarlyContinue>().await?;
        Ok::<(), Error>(())
    });
    crate::runtime::TaskSet::new([
        prepare.as_mut(),
        wire.as_mut(),
        publish.as_mut(),
        resume.as_mut(),
    ])
    .await
}

/// Retain each request before acknowledging it to the application source.
pub(in crate::quic) async fn prepare(
    requests: &mut Requests<'_, '_>,
    input: &mut impl crate::quic::application::ClientRequests,
) -> Result<(), Error> {
    use hibana_tls::secret::Erase;
    if requests.len() != 0 {
        return Err(Error::Binding);
    }
    for index in 0..requests.capacity() {
        let Some(len) = input
            .next(requests.input_buffer(index)?)
            .await
            .map_err(|_| Error::Tls(hibana_tls::quic::Error::InvalidInput))?
        else {
            return Ok(());
        };
        requests.retain_input(index, len)?;
        input
            .started(index as u64 * 4)
            .map_err(|_| Error::Tls(hibana_tls::quic::Error::InvalidInput))?;
    }
    let mut excess = [0; crate::quic::application::MAX_REQUEST_BYTES];
    let more = input
        .next(&mut excess)
        .await
        .map_err(|_| Error::Tls(hibana_tls::quic::Error::InvalidInput));
    excess.erase();
    if more?.is_some() {
        Err(Error::Capacity)
    } else {
        Ok(())
    }
}
