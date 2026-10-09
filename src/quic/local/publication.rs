//! publication role or packet arithmetic; endpoint exchanges stay explicit.
use super::*;
#[allow(clippy::too_many_arguments)]
pub(in crate::quic) async fn publish<'scope, 'book, const N: usize, const P: usize>(
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
                            == crate::quic::imp::kernel::accounting::PacketNumberSpace::Initial;
                        let result = if is_initial {
                            initial
                                .submit(permit.submit(io.send(
                                    sealed.bytes(),
                                    crate::quic::ecn::imp::Codepoint::NotEct,
                                )))
                                .await
                        } else {
                            Some(
                                permit
                                    .submit(io.send(
                                        sealed.bytes(),
                                        crate::quic::ecn::imp::Codepoint::NotEct,
                                    ))
                                    .await,
                            )
                        };
                        let accepted_at = match result {
                            Some(Ok(Ok(at))) => Some(at),
                            _ => None,
                        };
                        book.settle(recovery::Completion::from_adapter(
                            reservation,
                            accepted_at,
                            crate::quic::ecn::imp::Codepoint::NotEct,
                        ))?;
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
                            == crate::quic::imp::kernel::accounting::PacketNumberSpace::Initial;
                        let result = if is_initial {
                            initial
                                .submit(permit.submit(io.send(
                                    sealed.bytes(),
                                    crate::quic::ecn::imp::Codepoint::NotEct,
                                )))
                                .await
                        } else {
                            Some(
                                permit
                                    .submit(io.send(
                                        sealed.bytes(),
                                        crate::quic::ecn::imp::Codepoint::NotEct,
                                    ))
                                    .await,
                            )
                        };
                        let accepted_at = match result {
                            Some(Ok(Ok(at))) => Some(at),
                            _ => None,
                        };
                        book.settle(recovery::Completion::from_adapter(
                            reservation,
                            accepted_at,
                            crate::quic::ecn::imp::Codepoint::NotEct,
                        ))?;
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
                            == crate::quic::imp::kernel::accounting::PacketNumberSpace::Initial;
                        let result = if is_initial {
                            initial
                                .submit(permit.submit(io.send(
                                    sealed.bytes(),
                                    crate::quic::ecn::imp::Codepoint::NotEct,
                                )))
                                .await
                        } else {
                            Some(
                                permit
                                    .submit(io.send(
                                        sealed.bytes(),
                                        crate::quic::ecn::imp::Codepoint::NotEct,
                                    ))
                                    .await,
                            )
                        };
                        let accepted_at = match result {
                            Some(Ok(Ok(at))) => Some(at),
                            _ => None,
                        };
                        book.settle(recovery::Completion::from_adapter(
                            reservation,
                            accepted_at,
                            crate::quic::ecn::imp::Codepoint::NotEct,
                        ))?;
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
                            == crate::quic::imp::kernel::accounting::PacketNumberSpace::Initial;
                        let result = if is_initial {
                            initial
                                .submit(permit.submit(io.send(
                                    sealed.bytes(),
                                    crate::quic::ecn::imp::Codepoint::NotEct,
                                )))
                                .await
                        } else {
                            Some(
                                permit
                                    .submit(io.send(
                                        sealed.bytes(),
                                        crate::quic::ecn::imp::Codepoint::NotEct,
                                    ))
                                    .await,
                            )
                        };
                        let accepted_at = match result {
                            Some(Ok(Ok(at))) => Some(at),
                            _ => None,
                        };
                        book.settle(recovery::Completion::from_adapter(
                            reservation,
                            accepted_at,
                            crate::quic::ecn::imp::Codepoint::NotEct,
                        ))?;
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
                            == crate::quic::imp::kernel::accounting::PacketNumberSpace::Initial;
                        let result = if is_initial {
                            initial
                                .submit(permit.submit(io.send(
                                    sealed.bytes(),
                                    crate::quic::ecn::imp::Codepoint::NotEct,
                                )))
                                .await
                        } else {
                            Some(
                                permit
                                    .submit(io.send(
                                        sealed.bytes(),
                                        crate::quic::ecn::imp::Codepoint::NotEct,
                                    ))
                                    .await,
                            )
                        };
                        let accepted_at = match result {
                            Some(Ok(Ok(at))) => Some(at),
                            _ => None,
                        };
                        book.settle(recovery::Completion::from_adapter(
                            reservation,
                            accepted_at,
                            crate::quic::ecn::imp::Codepoint::NotEct,
                        ))?;
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
                            == crate::quic::imp::kernel::accounting::PacketNumberSpace::Initial;
                        let result = if is_initial {
                            initial
                                .submit(permit.submit(io.send(
                                    sealed.bytes(),
                                    crate::quic::ecn::imp::Codepoint::NotEct,
                                )))
                                .await
                        } else {
                            Some(
                                permit
                                    .submit(io.send(
                                        sealed.bytes(),
                                        crate::quic::ecn::imp::Codepoint::NotEct,
                                    ))
                                    .await,
                            )
                        };
                        let accepted_at = match result {
                            Some(Ok(Ok(at))) => Some(at),
                            _ => None,
                        };
                        book.settle(recovery::Completion::from_adapter(
                            reservation,
                            accepted_at,
                            crate::quic::ecn::imp::Codepoint::NotEct,
                        ))?;
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
                            == crate::quic::imp::kernel::accounting::PacketNumberSpace::Initial;
                        let result = if is_initial {
                            initial
                                .submit(permit.submit(io.send(
                                    sealed.bytes(),
                                    crate::quic::ecn::imp::Codepoint::NotEct,
                                )))
                                .await
                        } else {
                            Some(
                                permit
                                    .submit(io.send(
                                        sealed.bytes(),
                                        crate::quic::ecn::imp::Codepoint::NotEct,
                                    ))
                                    .await,
                            )
                        };
                        let accepted_at = match result {
                            Some(Ok(Ok(at))) => Some(at),
                            _ => None,
                        };
                        book.settle(recovery::Completion::from_adapter(
                            reservation,
                            accepted_at,
                            crate::quic::ecn::imp::Codepoint::NotEct,
                        ))?;
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
                            == crate::quic::imp::kernel::accounting::PacketNumberSpace::Initial;
                        let result = if is_initial {
                            initial
                                .submit(permit.submit(io.send(
                                    sealed.bytes(),
                                    crate::quic::ecn::imp::Codepoint::NotEct,
                                )))
                                .await
                        } else {
                            Some(
                                permit
                                    .submit(io.send(
                                        sealed.bytes(),
                                        crate::quic::ecn::imp::Codepoint::NotEct,
                                    ))
                                    .await,
                            )
                        };
                        let accepted_at = match result {
                            Some(Ok(Ok(at))) => Some(at),
                            _ => None,
                        };
                        book.settle(recovery::Completion::from_adapter(
                            reservation,
                            accepted_at,
                            crate::quic::ecn::imp::Codepoint::NotEct,
                        ))?;
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
                            == crate::quic::imp::kernel::accounting::PacketNumberSpace::Initial;
                        let result = if is_initial {
                            initial
                                .submit(permit.submit(io.send(
                                    sealed.bytes(),
                                    crate::quic::ecn::imp::Codepoint::NotEct,
                                )))
                                .await
                        } else {
                            Some(
                                permit
                                    .submit(io.send(
                                        sealed.bytes(),
                                        crate::quic::ecn::imp::Codepoint::NotEct,
                                    ))
                                    .await,
                            )
                        };
                        let accepted_at = match result {
                            Some(Ok(Ok(at))) => Some(at),
                            _ => None,
                        };
                        book.settle(recovery::Completion::from_adapter(
                            reservation,
                            accepted_at,
                            crate::quic::ecn::imp::Codepoint::NotEct,
                        ))?;
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
                    let is_initial = reservation.packet().space
                        == crate::quic::imp::kernel::accounting::PacketNumberSpace::Initial;
                    let result = if is_initial {
                        initial
                            .submit(permit.submit(
                                io.send(sealed.bytes(), crate::quic::ecn::imp::Codepoint::NotEct),
                            ))
                            .await
                    } else {
                        Some(
                            permit
                                .submit(
                                    io.send(
                                        sealed.bytes(),
                                        crate::quic::ecn::imp::Codepoint::NotEct,
                                    ),
                                )
                                .await,
                        )
                    };
                    let accepted_at = match result {
                        Some(Ok(Ok(at))) => Some(at),
                        _ => None,
                    };
                    book.settle(recovery::Completion::from_adapter(
                        reservation,
                        accepted_at,
                        crate::quic::ecn::imp::Codepoint::NotEct,
                    ))?;
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
                    let is_initial = reservation.packet().space
                        == crate::quic::imp::kernel::accounting::PacketNumberSpace::Initial;
                    let result = if is_initial {
                        initial
                            .submit(permit.submit(
                                io.send(sealed.bytes(), crate::quic::ecn::imp::Codepoint::NotEct),
                            ))
                            .await
                    } else {
                        Some(
                            permit
                                .submit(
                                    io.send(
                                        sealed.bytes(),
                                        crate::quic::ecn::imp::Codepoint::NotEct,
                                    ),
                                )
                                .await,
                        )
                    };
                    let accepted_at = match result {
                        Some(Ok(Ok(at))) => Some(at),
                        _ => None,
                    };
                    book.settle(recovery::Completion::from_adapter(
                        reservation,
                        accepted_at,
                        crate::quic::ecn::imp::Codepoint::NotEct,
                    ))?;
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
