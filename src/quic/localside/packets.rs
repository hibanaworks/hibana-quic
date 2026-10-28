//! Use delegated packet-write keys while receiving CRYPTO and publishing packets.
use super::*;
use crate::quic::imp::sealing::prepare_pending_packet;
use core::ops::ControlFlow;

#[allow(clippy::too_many_arguments)]
pub(in crate::quic) async fn packets<'r, 'scope, 'book, const N: usize, const P: usize>(
    endpoint: &mut Endpoint<'r, { p::TX_WIRE }>,
    slots: &Storage<'scope, 'book, N, P>,
    scope: &'scope ApplicationKeyScope,
    initial: &crate::quic::imp::initial::Keys<'scope>,
    keys: &RefCell<WriteKeys<'_, 'scope>>,
    book: &mut recovery::Tx<'book, 'scope, N>,
    config: Config<'_>,
    clock: &impl Clock,
) -> Result<TransmitContinuation<'scope>, Error> {
    use hibana_tls::handshake::global::owned as tls;
    let mut packet_keys = endpoint.recv::<p::PacketKeys<'_>>().await?;
    let book = RefCell::new(book);
    {
        let [mut packet_keys] = packet_keys.par()?;
        {
            let [mut input, mut output] = packet_keys.par().map_err(|error| Error::EndpointAt {
                role: p::WRITE_KEYS,
                expected_label: p::InitialFlight::LOGICAL_LABEL,
                error,
            })?;
            let mut received = pin!(async {
                loop {
                    input.send::<p::InitialTaken>(&()).await?;
                    let response = input.offer().await.map_err(|error| Error::EndpointAt {
                        role: p::WRITE_KEYS,
                        expected_label: p::InitialFlight::LOGICAL_LABEL,
                        error,
                    })?;
                    match response.label() {
                        label if label == p::InitialFlight::LOGICAL_LABEL => {
                            response.recv::<p::InitialFlight>().await?;
                            let flight = slots.flight.take()?;
                            let mut offset = 0;
                            while offset < flight.bytes().len() {
                                if flight.level() == Level::Initial && !initial.available() {
                                    break;
                                }
                                let revision = slots.schedule.revision.get();
                                let count = (flight.bytes().len() - offset)
                                    .min(N.saturating_sub(128 + config.initial_token.len()));
                                if count == 0 {
                                    return Err(Error::Binding);
                                }
                                let retained = book.borrow_mut().store_crypto(
                                    flight.level(),
                                    flight.offset() + offset as u64,
                                    &flight.bytes()[offset..offset + count],
                                );
                                match retained {
                                    Ok(_) => {
                                        offset += count;
                                        slots.schedule.changed()?;
                                        crate::runtime::yield_now().await;
                                    }
                                    Err(recovery::Error::Flight(
                                        crate::quic::imp::kernel::flights::Error::Full,
                                    )) => {
                                        slots.schedule.wait_changed(1, revision).await;
                                    }
                                    Err(error) => return Err(error.into()),
                                }
                            }
                        }
                        label if label == p::InitialBoundary::LOGICAL_LABEL => {
                            response.recv::<p::InitialBoundary>().await?;
                            break;
                        }
                        label => return Err(Error::UnexpectedLabel(label)),
                    }
                    crate::runtime::yield_now().await;
                }
                Ok::<(), Error>(())
            });
            loop {
                let revision = slots.schedule.revision.get();
                let packet = prepare_pending_packet(
                    slots,
                    &mut keys.borrow_mut(),
                    &mut book.borrow_mut(),
                    config,
                    clock,
                )?;
                if let Some(packet) = packet {
                    let mut published = pin!(async {
                        match packet {
                            RecoveryPacket::Data(space) => {
                                output.send::<p::InitialDataDatagram>(&()).await?;
                                let result =
                                    output.offer().await.map_err(|error| Error::EndpointAt {
                                        role: p::WRITE_KEYS,
                                        expected_label: p::InitialDataAccepted::LOGICAL_LABEL,
                                        error,
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
                                if !accepted && (space != crate::quic::imp::kernel::accounting::PacketNumberSpace::Initial || initial.available()) {
        return Err(Error::Io(IoError::Rejected));
    }
                            }
                            RecoveryPacket::Acknowledgment(space) => {
                                output.send::<p::InitialAckDatagram>(&()).await?;
                                let result =
                                    output.offer().await.map_err(|error| Error::EndpointAt {
                                        role: p::WRITE_KEYS,
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
                                if !accepted && (space != crate::quic::imp::kernel::accounting::PacketNumberSpace::Initial || initial.available()) {
        return Err(Error::Io(IoError::Rejected));
    }
                            }
                            RecoveryPacket::Probe(space) => {
                                output.send::<p::InitialProbeDatagram>(&()).await?;
                                let result =
                                    output.offer().await.map_err(|error| Error::EndpointAt {
                                        role: p::WRITE_KEYS,
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
                                if !accepted && (space != crate::quic::imp::kernel::accounting::PacketNumberSpace::Initial || initial.available()) {
        return Err(Error::Io(IoError::Rejected));
    }
                            }
                        }
                        Ok::<(), Error>(())
                    });
                    match crate::runtime::select(received.as_mut(), published.as_mut()).await {
                        ControlFlow::Break(result) => {
                            result?;
                            published.await?;
                            break;
                        }
                        ControlFlow::Continue(result) => result?,
                    }
                } else {
                    match crate::runtime::select(
                        received.as_mut(),
                        slots.schedule.wait_changed(1, revision),
                    )
                    .await
                    {
                        ControlFlow::Break(result) => {
                            result?;
                            break;
                        }
                        ControlFlow::Continue(()) => {}
                    }
                }
                crate::runtime::yield_now().await;
            }
            loop {
                let Some(packet) = prepare_pending_packet(
                    slots,
                    &mut keys.borrow_mut(),
                    &mut book.borrow_mut(),
                    config,
                    clock,
                )?
                else {
                    if book.borrow().unsent_crypto().is_none() {
                        break;
                    }
                    let revision = slots.schedule.revision.get();
                    slots.schedule.wait_changed(1, revision).await;
                    continue;
                };
                match packet {
                    RecoveryPacket::Data(space) => {
                        output.send::<p::InitialDataDatagram>(&()).await?;
                        let result = output.offer().await.map_err(|error| Error::EndpointAt {
                            role: p::WRITE_KEYS,
                            expected_label: p::InitialDataAccepted::LOGICAL_LABEL,
                            error,
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
                        if !accepted
                            && (space
                                != crate::quic::imp::kernel::accounting::PacketNumberSpace::Initial
                                || initial.available())
                        {
                            return Err(Error::Io(IoError::Rejected));
                        }
                    }
                    RecoveryPacket::Acknowledgment(space) => {
                        output.send::<p::InitialAckDatagram>(&()).await?;
                        let result = output.offer().await.map_err(|error| Error::EndpointAt {
                            role: p::WRITE_KEYS,
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
                        if !accepted
                            && (space
                                != crate::quic::imp::kernel::accounting::PacketNumberSpace::Initial
                                || initial.available())
                        {
                            return Err(Error::Io(IoError::Rejected));
                        }
                    }
                    RecoveryPacket::Probe(space) => {
                        output.send::<p::InitialProbeDatagram>(&()).await?;
                        let result = output.offer().await.map_err(|error| Error::EndpointAt {
                            role: p::WRITE_KEYS,
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
                        if !accepted
                            && (space
                                != crate::quic::imp::kernel::accounting::PacketNumberSpace::Initial
                                || initial.available())
                        {
                            return Err(Error::Io(IoError::Rejected));
                        }
                    }
                }
                crate::runtime::yield_now().await;
            }
            output.send::<p::InitialWireBoundary>(&()).await?;
            output.recv::<p::InitialWireBoundarySeen>().await?;
        }
        packet_keys.send::<p::InitialPhaseSettled>(&()).await?;
        {
            let [mut packet_keys] = packet_keys.par()?;
            {
                let [mut input, mut output] =
                    packet_keys.par().map_err(|error| Error::EndpointAt {
                        role: p::WRITE_KEYS,
                        expected_label: p::HandshakeFlight::LOGICAL_LABEL,
                        error,
                    })?;
                let mut received = pin!(async {
                    loop {
                        input.send::<p::HandshakeTaken>(&()).await?;
                        let response = input.offer().await.map_err(|error| Error::EndpointAt {
                            role: p::WRITE_KEYS,
                            expected_label: p::HandshakeFlight::LOGICAL_LABEL,
                            error,
                        })?;
                        match response.label() {
                            label if label == p::HandshakeFlight::LOGICAL_LABEL => {
                                response.recv::<p::HandshakeFlight>().await?;
                                let flight = slots.flight.take()?;
                                let mut offset = 0;
                                while offset < flight.bytes().len() {
                                    if flight.level() == Level::Initial && !initial.available() {
                                        break;
                                    }
                                    let revision = slots.schedule.revision.get();
                                    let count = (flight.bytes().len() - offset)
                                        .min(N.saturating_sub(128 + config.initial_token.len()));
                                    if count == 0 {
                                        return Err(Error::Binding);
                                    }
                                    let retained = book.borrow_mut().store_crypto(
                                        flight.level(),
                                        flight.offset() + offset as u64,
                                        &flight.bytes()[offset..offset + count],
                                    );
                                    match retained {
                                        Ok(_) => {
                                            offset += count;
                                            slots.schedule.changed()?;
                                            crate::runtime::yield_now().await;
                                        }
                                        Err(recovery::Error::Flight(
                                            crate::quic::imp::kernel::flights::Error::Full,
                                        )) => {
                                            slots.schedule.wait_changed(1, revision).await;
                                        }
                                        Err(error) => return Err(error.into()),
                                    }
                                }
                            }
                            label if label == p::HandshakeIdle::LOGICAL_LABEL => {
                                response.recv::<p::HandshakeIdle>().await?;
                            }
                            label if label == p::HandshakeBoundary::LOGICAL_LABEL => {
                                response.recv::<p::HandshakeBoundary>().await?;
                                break;
                            }
                            label => return Err(Error::UnexpectedLabel(label)),
                        }
                        crate::runtime::yield_now().await;
                    }
                    Ok::<(), Error>(())
                });
                loop {
                    let revision = slots.schedule.revision.get();
                    let packet = prepare_pending_packet(
                        slots,
                        &mut keys.borrow_mut(),
                        &mut book.borrow_mut(),
                        config,
                        clock,
                    )?;
                    if let Some(packet) = packet {
                        let mut published = pin!(async {
                            match packet {
                                RecoveryPacket::Data(space) => {
                                    output.send::<p::HandshakeDataDatagram>(&()).await?;
                                    let result = output.offer().await.map_err(|error| {
                                        Error::EndpointAt {
                                            role: p::WRITE_KEYS,
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
                                    if !accepted && (space != crate::quic::imp::kernel::accounting::PacketNumberSpace::Initial || initial.available()) {
        return Err(Error::Io(IoError::Rejected));
    }
                                }
                                RecoveryPacket::Acknowledgment(space) => {
                                    output.send::<p::HandshakeAckDatagram>(&()).await?;
                                    let result = output.offer().await.map_err(|error| {
                                        Error::EndpointAt {
                                            role: p::WRITE_KEYS,
                                            expected_label: p::HandshakeAckAccepted::LOGICAL_LABEL,
                                            error,
                                        }
                                    })?;
                                    let accepted = match result.label() {
                                        label
                                            if label == p::HandshakeAckAccepted::LOGICAL_LABEL =>
                                        {
                                            result.recv::<p::HandshakeAckAccepted>().await?;
                                            true
                                        }
                                        label
                                            if label == p::HandshakeAckRejected::LOGICAL_LABEL =>
                                        {
                                            result.recv::<p::HandshakeAckRejected>().await?;
                                            false
                                        }
                                        label => return Err(Error::UnexpectedLabel(label)),
                                    };
                                    output.send::<p::HandshakeAckSettled>(&()).await?;
                                    if !accepted && (space != crate::quic::imp::kernel::accounting::PacketNumberSpace::Initial || initial.available()) {
        return Err(Error::Io(IoError::Rejected));
    }
                                }
                                RecoveryPacket::Probe(space) => {
                                    output.send::<p::HandshakeProbeDatagram>(&()).await?;
                                    let result = output.offer().await.map_err(|error| {
                                        Error::EndpointAt {
                                            role: p::WRITE_KEYS,
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
                                    if !accepted && (space != crate::quic::imp::kernel::accounting::PacketNumberSpace::Initial || initial.available()) {
        return Err(Error::Io(IoError::Rejected));
    }
                                }
                            }
                            Ok::<(), Error>(())
                        });
                        match crate::runtime::select(received.as_mut(), published.as_mut()).await {
                            ControlFlow::Break(result) => {
                                result?;
                                published.await?;
                                break;
                            }
                            ControlFlow::Continue(result) => result?,
                        }
                    } else {
                        match crate::runtime::select(
                            received.as_mut(),
                            slots.schedule.wait_changed(1, revision),
                        )
                        .await
                        {
                            ControlFlow::Break(result) => {
                                result?;
                                break;
                            }
                            ControlFlow::Continue(()) => {}
                        }
                    }
                    crate::runtime::yield_now().await;
                }
                loop {
                    let Some(packet) = prepare_pending_packet(
                        slots,
                        &mut keys.borrow_mut(),
                        &mut book.borrow_mut(),
                        config,
                        clock,
                    )?
                    else {
                        if book.borrow().unsent_crypto().is_none() {
                            break;
                        }
                        let revision = slots.schedule.revision.get();
                        slots.schedule.wait_changed(1, revision).await;
                        continue;
                    };
                    match packet {
                        RecoveryPacket::Data(space) => {
                            output.send::<p::HandshakeDataDatagram>(&()).await?;
                            let result =
                                output.offer().await.map_err(|error| Error::EndpointAt {
                                    role: p::WRITE_KEYS,
                                    expected_label: p::HandshakeDataAccepted::LOGICAL_LABEL,
                                    error,
                                })?;
                            let accepted = match result.label() {
                                label if label == p::HandshakeDataAccepted::LOGICAL_LABEL => {
                                    result.recv::<p::HandshakeDataAccepted>().await?;
                                    true
                                }
                                label if label == p::HandshakeDataRejected::LOGICAL_LABEL => {
                                    result.recv::<p::HandshakeDataRejected>().await?;
                                    false
                                }
                                label => return Err(Error::UnexpectedLabel(label)),
                            };
                            output.send::<p::HandshakeDataSettled>(&()).await?;
                            if !accepted
                            && (space
                                != crate::quic::imp::kernel::accounting::PacketNumberSpace::Initial
                                || initial.available())
                        {
                            return Err(Error::Io(IoError::Rejected));
                        }
                        }
                        RecoveryPacket::Acknowledgment(space) => {
                            output.send::<p::HandshakeAckDatagram>(&()).await?;
                            let result =
                                output.offer().await.map_err(|error| Error::EndpointAt {
                                    role: p::WRITE_KEYS,
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
                            if !accepted
                            && (space
                                != crate::quic::imp::kernel::accounting::PacketNumberSpace::Initial
                                || initial.available())
                        {
                            return Err(Error::Io(IoError::Rejected));
                        }
                        }
                        RecoveryPacket::Probe(space) => {
                            output.send::<p::HandshakeProbeDatagram>(&()).await?;
                            let result =
                                output.offer().await.map_err(|error| Error::EndpointAt {
                                    role: p::WRITE_KEYS,
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
                            if !accepted
                            && (space
                                != crate::quic::imp::kernel::accounting::PacketNumberSpace::Initial
                                || initial.available())
                        {
                            return Err(Error::Io(IoError::Rejected));
                        }
                        }
                    }
                    crate::runtime::yield_now().await;
                }
                output.send::<p::HandshakeWireBoundary>(&()).await?;
                output.recv::<p::HandshakeWireBoundarySeen>().await?;
            }
            packet_keys.send::<p::HandshakePhaseSettled>(&()).await?;
        }
        let material = endpoint.recv::<p::WriteApplication<'_>>().await?;
        let application = slots.write_application.take()?;
        if !core::ptr::eq(scope, application.scope()) {
            return Err(Error::Binding);
        }
        keys.borrow_mut().application = Some(application);
        slots.schedule.changed()?;
        {
            let [mut input, mut output] = packet_keys.par().map_err(|error| Error::EndpointAt {
                role: p::WRITE_KEYS,
                expected_label: p::ApplicationFlight::LOGICAL_LABEL,
                error,
            })?;
            let mut received = pin!(async {
                {
                    let mut returning = pin!(async {
                        endpoint.send::<tls::Keys<'_>>(material).await?;
                        Ok::<(), Error>(())
                    });
                    let mut source = pin!(async {
                        loop {
                            input.send::<p::ApplicationTaken>(&()).await?;
                            let response =
                                input.offer().await.map_err(|error| Error::EndpointAt {
                                    role: p::WRITE_KEYS,
                                    expected_label: p::ApplicationFlight::LOGICAL_LABEL,
                                    error,
                                })?;
                            match response.label() {
                                label if label == p::ApplicationFlight::LOGICAL_LABEL => {
                                    response.recv::<p::ApplicationFlight>().await?;
                                    let flight = slots.flight.take()?;
                                    let mut offset = 0;
                                    while offset < flight.bytes().len() {
                                        if flight.level() == Level::Initial && !initial.available()
                                        {
                                            break;
                                        }
                                        let revision = slots.schedule.revision.get();
                                        let count = (flight.bytes().len() - offset).min(
                                            N.saturating_sub(128 + config.initial_token.len()),
                                        );
                                        if count == 0 {
                                            return Err(Error::Binding);
                                        }
                                        let retained = book.borrow_mut().store_crypto(
                                            flight.level(),
                                            flight.offset() + offset as u64,
                                            &flight.bytes()[offset..offset + count],
                                        );
                                        match retained {
                                            Ok(_) => {
                                                offset += count;
                                                slots.schedule.changed()?;
                                                crate::runtime::yield_now().await;
                                            }
                                            Err(recovery::Error::Flight(
                                                crate::quic::imp::kernel::flights::Error::Full,
                                            )) => {
                                                slots.schedule.wait_changed(1, revision).await;
                                            }
                                            Err(error) => return Err(error.into()),
                                        }
                                    }
                                }
                                label if label == p::ApplicationIdle::LOGICAL_LABEL => {
                                    response.recv::<p::ApplicationIdle>().await?;
                                }
                                label if label == p::ApplicationInputEnd::LOGICAL_LABEL => {
                                    response.recv::<p::ApplicationInputEnd>().await?;
                                    break;
                                }
                                label => return Err(Error::UnexpectedLabel(label)),
                            }
                            crate::runtime::yield_now().await;
                        }
                        Ok::<(), Error>(())
                    });
                    crate::runtime::TaskSet::new([returning.as_mut(), source.as_mut()]).await?;
                }
                input.recv::<p::ApplicationBoundary>().await?;
                Ok::<(), Error>(())
            });
            loop {
                let revision = slots.schedule.revision.get();
                let packet = prepare_pending_packet(
                    slots,
                    &mut keys.borrow_mut(),
                    &mut book.borrow_mut(),
                    config,
                    clock,
                )?;
                if let Some(packet) = packet {
                    let mut published = pin!(async {
                        match packet {
                            RecoveryPacket::Data(space) => {
                                output.send::<p::ApplicationDataDatagram>(&()).await?;
                                let result =
                                    output.offer().await.map_err(|error| Error::EndpointAt {
                                        role: p::WRITE_KEYS,
                                        expected_label: p::ApplicationDataAccepted::LOGICAL_LABEL,
                                        error,
                                    })?;
                                let accepted = match result.label() {
                                    label if label == p::ApplicationDataAccepted::LOGICAL_LABEL => {
                                        result.recv::<p::ApplicationDataAccepted>().await?;
                                        true
                                    }
                                    label if label == p::ApplicationDataRejected::LOGICAL_LABEL => {
                                        result.recv::<p::ApplicationDataRejected>().await?;
                                        false
                                    }
                                    label => return Err(Error::UnexpectedLabel(label)),
                                };
                                output.send::<p::ApplicationDataSettled>(&()).await?;
                                if !accepted && (space != crate::quic::imp::kernel::accounting::PacketNumberSpace::Initial || initial.available()) {
        return Err(Error::Io(IoError::Rejected));
    }
                            }
                            RecoveryPacket::Acknowledgment(space) => {
                                output.send::<p::ApplicationAckDatagram>(&()).await?;
                                let result =
                                    output.offer().await.map_err(|error| Error::EndpointAt {
                                        role: p::WRITE_KEYS,
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
                                if !accepted && (space != crate::quic::imp::kernel::accounting::PacketNumberSpace::Initial || initial.available()) {
        return Err(Error::Io(IoError::Rejected));
    }
                            }
                            RecoveryPacket::Probe(space) => {
                                output.send::<p::ApplicationProbeDatagram>(&()).await?;
                                let result =
                                    output.offer().await.map_err(|error| Error::EndpointAt {
                                        role: p::WRITE_KEYS,
                                        expected_label: p::ApplicationProbeAccepted::LOGICAL_LABEL,
                                        error,
                                    })?;
                                let accepted = match result.label() {
                                    label
                                        if label == p::ApplicationProbeAccepted::LOGICAL_LABEL =>
                                    {
                                        result.recv::<p::ApplicationProbeAccepted>().await?;
                                        true
                                    }
                                    label
                                        if label == p::ApplicationProbeRejected::LOGICAL_LABEL =>
                                    {
                                        result.recv::<p::ApplicationProbeRejected>().await?;
                                        false
                                    }
                                    label => return Err(Error::UnexpectedLabel(label)),
                                };
                                output.send::<p::ApplicationProbeSettled>(&()).await?;
                                if !accepted && (space != crate::quic::imp::kernel::accounting::PacketNumberSpace::Initial || initial.available()) {
        return Err(Error::Io(IoError::Rejected));
    }
                            }
                        }
                        Ok::<(), Error>(())
                    });
                    match crate::runtime::select(received.as_mut(), published.as_mut()).await {
                        ControlFlow::Break(result) => {
                            result?;
                            published.await?;
                            break;
                        }
                        ControlFlow::Continue(result) => result?,
                    }
                } else {
                    match crate::runtime::select(
                        received.as_mut(),
                        slots.schedule.wait_changed(1, revision),
                    )
                    .await
                    {
                        ControlFlow::Break(result) => {
                            result?;
                            break;
                        }
                        ControlFlow::Continue(()) => {}
                    }
                }
                crate::runtime::yield_now().await;
            }
            loop {
                let Some(packet) = prepare_pending_packet(
                    slots,
                    &mut keys.borrow_mut(),
                    &mut book.borrow_mut(),
                    config,
                    clock,
                )?
                else {
                    if book.borrow().unsent_crypto().is_none() {
                        break;
                    }
                    let revision = slots.schedule.revision.get();
                    slots.schedule.wait_changed(1, revision).await;
                    continue;
                };
                match packet {
                    RecoveryPacket::Data(space) => {
                        output.send::<p::ApplicationDataDatagram>(&()).await?;
                        let result = output.offer().await.map_err(|error| Error::EndpointAt {
                            role: p::WRITE_KEYS,
                            expected_label: p::ApplicationDataAccepted::LOGICAL_LABEL,
                            error,
                        })?;
                        let accepted = match result.label() {
                            label if label == p::ApplicationDataAccepted::LOGICAL_LABEL => {
                                result.recv::<p::ApplicationDataAccepted>().await?;
                                true
                            }
                            label if label == p::ApplicationDataRejected::LOGICAL_LABEL => {
                                result.recv::<p::ApplicationDataRejected>().await?;
                                false
                            }
                            label => return Err(Error::UnexpectedLabel(label)),
                        };
                        output.send::<p::ApplicationDataSettled>(&()).await?;
                        if !accepted
                            && (space
                                != crate::quic::imp::kernel::accounting::PacketNumberSpace::Initial
                                || initial.available())
                        {
                            return Err(Error::Io(IoError::Rejected));
                        }
                    }
                    RecoveryPacket::Acknowledgment(space) => {
                        output.send::<p::ApplicationAckDatagram>(&()).await?;
                        let result = output.offer().await.map_err(|error| Error::EndpointAt {
                            role: p::WRITE_KEYS,
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
                        if !accepted
                            && (space
                                != crate::quic::imp::kernel::accounting::PacketNumberSpace::Initial
                                || initial.available())
                        {
                            return Err(Error::Io(IoError::Rejected));
                        }
                    }
                    RecoveryPacket::Probe(space) => {
                        output.send::<p::ApplicationProbeDatagram>(&()).await?;
                        let result = output.offer().await.map_err(|error| Error::EndpointAt {
                            role: p::WRITE_KEYS,
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
                        if !accepted
                            && (space
                                != crate::quic::imp::kernel::accounting::PacketNumberSpace::Initial
                                || initial.available())
                        {
                            return Err(Error::Io(IoError::Rejected));
                        }
                    }
                }
                crate::runtime::yield_now().await;
            }
            output.send::<p::ApplicationWireBoundary>(&()).await?;
            output.recv::<p::ApplicationWireBoundarySeen>().await?;
        }
        packet_keys.send::<p::ApplicationPhaseSettled>(&()).await?;
        loop {
            let revision = slots.schedule.revision.get();
            let packet = prepare_pending_packet(
                slots,
                &mut keys.borrow_mut(),
                &mut book.borrow_mut(),
                config,
                clock,
            )?;
            if let Some(packet) = packet {
                let output = &mut packet_keys;
                match packet {
                    RecoveryPacket::Data(space) => {
                        output.send::<p::DrainProbeDatagram>(&()).await?;
                        let result = output.offer().await.map_err(|error| Error::EndpointAt {
                            role: p::WRITE_KEYS,
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
                        if !accepted
                            && (space
                                != crate::quic::imp::kernel::accounting::PacketNumberSpace::Initial
                                || initial.available())
                        {
                            return Err(Error::Io(IoError::Rejected));
                        }
                    }
                    RecoveryPacket::Acknowledgment(space) => {
                        output.send::<p::DrainAckDatagram>(&()).await?;
                        let result = output.offer().await.map_err(|error| Error::EndpointAt {
                            role: p::WRITE_KEYS,
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
                        if !accepted
                            && (space
                                != crate::quic::imp::kernel::accounting::PacketNumberSpace::Initial
                                || initial.available())
                        {
                            return Err(Error::Io(IoError::Rejected));
                        }
                    }
                    RecoveryPacket::Probe(space) => {
                        output.send::<p::DrainProbeDatagram>(&()).await?;
                        let result = output.offer().await.map_err(|error| Error::EndpointAt {
                            role: p::WRITE_KEYS,
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
                        if !accepted
                            && (space
                                != crate::quic::imp::kernel::accounting::PacketNumberSpace::Initial
                                || initial.available())
                        {
                            return Err(Error::Io(IoError::Rejected));
                        }
                    }
                }
                crate::runtime::yield_now().await;
            } else if book.borrow().pending_ack().is_none() {
                break;
            } else {
                slots.schedule.wait_changed(1, revision).await;
            }
        }
        packet_keys
            .send::<p::HandshakeRecoveryTransferred>(&())
            .await?;
        packet_keys.send::<p::StopReceive>(&()).await?;
        packet_keys.recv::<p::ReceiveStopped>().await?;
        packet_keys.send::<p::StopTimer>(&()).await?;
        packet_keys.recv::<p::TimerStopped>().await?;
        packet_keys.send::<p::TransmitComplete>(&()).await?;
        packet_keys.recv::<p::TransmitContinuation>().await?;
        packet_keys.send::<p::AdapterComplete>(&()).await?;
        packet_keys.recv::<p::AdapterRetired>().await?;
    }
    endpoint.send::<p::PacketKeys<'_>>(packet_keys).await?;
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
