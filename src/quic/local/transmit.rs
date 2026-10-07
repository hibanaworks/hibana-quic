//! transmit role or packet arithmetic; endpoint exchanges stay explicit.
use super::*;
#[allow(clippy::too_many_arguments)]
pub(in crate::quic) async fn transmit<'scope, 'book, const N: usize, const P: usize>(
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
                    if config.side == Side::Server {
                        initial.select_write_version(
                            config.version,
                            config
                                .retry_source_id
                                .unwrap_or(config.original_destination_id),
                            config.side,
                        )?;
                    }
                    endpoint.send::<p::InitialTaken>(&()).await?;
                    let mut offset = 0;
                    while offset < flight.bytes().len() {
                        if flight.level() == Level::Initial && !initial.available() {
                            break;
                        }
                        let count = (flight.bytes().len() - offset)
                            .min(N.saturating_sub(128 + config.initial_token.len()));
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
    initial.select_write_version(
        config.version,
        config
            .retry_source_id
            .unwrap_or(config.original_destination_id),
        config.side,
    )?;
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
                        let count = (flight.bytes().len() - offset)
                            .min(N.saturating_sub(128 + config.initial_token.len()));
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
                        let count = (flight.bytes().len() - offset)
                            .min(N.saturating_sub(128 + config.initial_token.len()));
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
