//! Literal unconfirmed local continuations. The projected arm set owns phase admission.
use super::*;
use crate::roles::protocol_tls_phases::unconfirmed as p;

pub(super) async fn command<
    const C: u8,
    const N: usize,
    const P: usize,
    const Q: usize,
    const R: usize,
>(
    endpoint: &mut Endpoint<'_, C>,
    generation: u64,
    commands: &mut Receiver<'_, '_, Command<N>, Q>,
    replies: &mut Sender<'_, '_, Reply<N, P>, R>,
    exchange: &Exchange<N, P>,
    next: &mut u64,
    retirement_reply: &mut Option<Reply<N, P>>,
) -> Result<CommandExit, Error> {
    let mut sequence = *next;
    loop {
        let command = commands.recv().await.map_err(|_| Error::CommandsClosed)?;
        let descriptor = Descriptor {
            generation,
            sequence,
        };
        let wire = encode(descriptor);
        let mut advance = false;
        match command {
            command @ Command::ReceiveCrypto { .. } => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::CryptoInput>(&wire).await?;
                let branch = endpoint.offer().await?;
                let observed = match branch.label() {
                    p::CRYPTO_ACCEPTED => branch.recv::<p::CryptoAccepted>().await?,
                    p::CRYPTO_REJECTED => branch.recv::<p::CryptoRejected>().await?,
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                same(observed, wire)?;
            }
            command @ Command::TakeCryptoFlight { .. } => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::CryptoFlightRequested>(&wire).await?;
                let branch = endpoint.offer().await?;
                let observed = match branch.label() {
                    p::FLIGHT_READY => branch.recv::<p::FlightReady>().await?,
                    p::AWAIT_INPUT => branch.recv::<p::AwaitInput>().await?,
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                same(observed, wire)?;
            }
            command @ Command::MaintainKeys { .. } => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::MaintainKeys>(&wire).await?;
                let branch = endpoint.offer().await?;
                let observed = match branch.label() {
                    p::KEYS_MAINTAINED => branch.recv::<p::KeysMaintained>().await?,
                    p::MAINTENANCE_REJECTED => branch.recv::<p::MaintenanceRejected>().await?,
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                same(observed, wire)?;
            }
            command @ Command::LoanIntegrity => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::LoanIntegrity>(&wire).await?;
                let branch = endpoint.offer().await?;
                let granted = match branch.label() {
                    p::INTEGRITY_GRANTED => {
                        same(branch.recv::<p::IntegrityGranted>().await?, wire)?;
                        true
                    }
                    p::LOAN_UNAVAILABLE => {
                        same(branch.recv::<p::LoanUnavailable>().await?, wire)?;
                        false
                    }
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                let reply = exchange.take_reply(descriptor)?;
                endpoint.send::<p::ResultTaken>(&wire).await?;
                replies
                    .send(reply)
                    .await
                    .map_err(|_| Error::RepliesClosed)?;
                sequence = sequence.checked_add(1).ok_or(Error::SequenceExhausted)?;
                if granted {
                    // No crypto operation can be admitted in the middle of the loan. The owner
                    // is parked at the corresponding typed Return, with an exhausted budget.
                    let command = commands.recv().await.map_err(|_| Error::CommandsClosed)?;
                    let command @ Command::ReturnIntegrity(_) = command else {
                        return Err(Error::UnexpectedCommand);
                    };
                    let returned = Descriptor {
                        generation,
                        sequence,
                    };
                    let returned_wire = encode(returned);
                    exchange.put_request(Request {
                        descriptor: returned,
                        command,
                    })?;
                    endpoint
                        .send::<p::IntegrityReturned>(&returned_wire)
                        .await?;
                    same(
                        endpoint.recv::<p::IntegrityRestored>().await?,
                        returned_wire,
                    )?;
                    let reply = exchange.take_reply(returned)?;
                    endpoint.send::<p::ResultTaken>(&returned_wire).await?;
                    replies
                        .send(reply)
                        .await
                        .map_err(|_| Error::RepliesClosed)?;
                    sequence = sequence.checked_add(1).ok_or(Error::SequenceExhausted)?;
                }
                runtime::yield_now().await;
                continue;
            }
            command @ Command::OpenEarly(_) => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::OpenEarly>(&wire).await?;
                let branch = endpoint.offer().await?;
                let observed = match branch.label() {
                    p::EARLY_OPENED => branch.recv::<p::EarlyOpened>().await?,
                    p::EARLY_OPEN_REJECTED => branch.recv::<p::EarlyOpenRejected>().await?,
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                same(observed, wire)?;
            }
            command @ Command::SealEarly(_) => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::SealEarly>(&wire).await?;
                let branch = endpoint.offer().await?;
                let observed = match branch.label() {
                    p::EARLY_SEALED => branch.recv::<p::EarlySealed>().await?,
                    p::EARLY_SEAL_REJECTED => branch.recv::<p::EarlySealRejected>().await?,
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                same(observed, wire)?;
            }
            command @ Command::EarlyHeaderMask { .. } => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::EarlyHeaderMask>(&wire).await?;
                let branch = endpoint.offer().await?;
                let observed = match branch.label() {
                    p::HEADER_MASK_READY => branch.recv::<p::HeaderMaskReady>().await?,
                    p::HEADER_MASK_REJECTED => branch.recv::<p::HeaderMaskRejected>().await?,
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                same(observed, wire)?;
            }
            command @ Command::TakeEarlyReplayClaim => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::TakeEarlyReplayClaim>(&wire).await?;
                let branch = endpoint.offer().await?;
                let observed = match branch.label() {
                    p::EARLY_REPLAY_CLAIM_READY => {
                        branch.recv::<p::EarlyReplayClaimReady>().await?
                    }
                    p::NO_EARLY_REPLAY_CLAIM => branch.recv::<p::NoEarlyReplayClaim>().await?,
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                same(observed, wire)?;
            }
            command @ Command::DiscardEarly => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::DiscardEarly>(&wire).await?;
                same(endpoint.recv::<p::EarlyDiscarded>().await?, wire)?;
            }
            command @ Command::OpenHandshake(_) => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::OpenHandshake>(&wire).await?;
                let branch = endpoint.offer().await?;
                let observed = match branch.label() {
                    p::HANDSHAKE_OPENED => branch.recv::<p::HandshakeOpened>().await?,
                    p::HANDSHAKE_OPEN_REJECTED => branch.recv::<p::HandshakeOpenRejected>().await?,
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                same(observed, wire)?;
            }
            command @ Command::SealHandshake(_) => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::SealHandshake>(&wire).await?;
                let branch = endpoint.offer().await?;
                let observed = match branch.label() {
                    p::HANDSHAKE_SEALED => branch.recv::<p::HandshakeSealed>().await?,
                    p::HANDSHAKE_SEAL_REJECTED => branch.recv::<p::HandshakeSealRejected>().await?,
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                same(observed, wire)?;
            }
            command @ Command::HeaderMask {
                level: Level::Handshake,
                ..
            } => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::HandshakeHeaderMask>(&wire).await?;
                let branch = endpoint.offer().await?;
                let observed = match branch.label() {
                    p::HEADER_MASK_READY => branch.recv::<p::HeaderMaskReady>().await?,
                    p::HEADER_MASK_REJECTED => branch.recv::<p::HeaderMaskRejected>().await?,
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                same(observed, wire)?;
            }
            command @ Command::OpenOneRtt { .. } => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::OpenOneRtt>(&wire).await?;
                let branch = endpoint.offer().await?;
                let observed = match branch.label() {
                    p::ONE_RTT_OPENED => branch.recv::<p::OneRttOpened>().await?,
                    p::ONE_RTT_OPEN_REJECTED => branch.recv::<p::OneRttOpenRejected>().await?,
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                same(observed, wire)?;
            }
            command @ Command::SealOneRtt(_) => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::SealOneRtt>(&wire).await?;
                let branch = endpoint.offer().await?;
                let observed = match branch.label() {
                    p::ONE_RTT_SEALED => branch.recv::<p::OneRttSealed>().await?,
                    p::ONE_RTT_SEAL_REJECTED => branch.recv::<p::OneRttSealRejected>().await?,
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                same(observed, wire)?;
            }
            command @ Command::HeaderMask {
                level: Level::OneRtt,
                ..
            } => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::OneRttHeaderMask>(&wire).await?;
                let branch = endpoint.offer().await?;
                let observed = match branch.label() {
                    p::HEADER_MASK_READY => branch.recv::<p::HeaderMaskReady>().await?,
                    p::HEADER_MASK_REJECTED => branch.recv::<p::HeaderMaskRejected>().await?,
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                same(observed, wire)?;
            }
            command @ Command::ValidatedAck { .. } => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::ValidatedAck>(&wire).await?;
                let branch = endpoint.offer().await?;
                let observed = match branch.label() {
                    p::ACK_APPLIED => branch.recv::<p::AckApplied>().await?,
                    p::ACK_REJECTED => branch.recv::<p::AckRejected>().await?,
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                same(observed, wire)?;
            }
            command @ Command::ConfirmHandshake => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::ConfirmHandshake>(&wire).await?;
                let branch = endpoint.offer().await?;
                let observed = match branch.label() {
                    p::HANDSHAKE_CONFIRMED => {
                        advance = true;
                        branch.recv::<p::HandshakeConfirmed>().await?
                    }
                    p::CONFIRMATION_REJECTED => branch.recv::<p::ConfirmationRejected>().await?,
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                same(observed, wire)?;
            }
            command @ Command::Retire => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                commands.close();
                endpoint.send::<p::RetireRequested>(&wire).await?;
                same(endpoint.recv::<p::RetirementPrepared>().await?, wire)?;
                if retirement_reply.is_some() {
                    return Err(Error::OccupiedSlot);
                }
                *retirement_reply = Some(exchange.take_reply(descriptor)?);
                endpoint.send::<p::ResultTaken>(&wire).await?;
                return Ok(CommandExit::Retiring(wire));
            }
            _ => return Err(Error::UnexpectedCommand),
        }
        let reply = exchange.take_reply(descriptor)?;
        endpoint.send::<p::ResultTaken>(&wire).await?;
        replies
            .send(reply)
            .await
            .map_err(|_| Error::RepliesClosed)?;
        sequence = sequence.checked_add(1).ok_or(Error::SequenceExhausted)?;
        if advance {
            *next = sequence;
            return Ok(CommandExit::Advanced(wire));
        }
        runtime::yield_now().await;
    }
}

pub(super) async fn provider<T: Provider, const O: u8, const N: usize, const P: usize>(
    endpoint: &mut Endpoint<'_, O>,
    generation: u64,
    provider: &mut T,
    exchange: &Exchange<N, P>,
) -> Result<OwnerExit, Error> {
    loop {
        let branch = endpoint.offer().await?;
        let completed;
        let mut advance = None;
        match branch.label() {
            p::CRYPTO_INPUT => {
                let wire = branch.recv::<p::CryptoInput>().await?;
                completed = wire;
                // All large packet/transcript locals die before suspension.
                let succeeded = {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::ReceiveCrypto { level, bytes } = command else {
                        return Err(Error::UnexpectedCommand);
                    };
                    let was_handshaking = provider.is_handshaking();
                    match provider.receive(level, bytes.as_bytes()) {
                        Ok(()) => {
                            let finished = (was_handshaking && !provider.is_handshaking())
                                .then(|| FinishedReceipt::from_provider(descriptor, provider));
                            exchange.put_reply(
                                provider,
                                descriptor,
                                Outcome::CryptoAccepted { finished },
                            )?;
                            true
                        }
                        Err(e) => {
                            exchange.put_reply(provider, descriptor, Outcome::Failed(e))?;
                            false
                        }
                    }
                };
                if succeeded {
                    endpoint.send::<p::CryptoAccepted>(&wire).await?;
                } else {
                    endpoint.send::<p::CryptoRejected>(&wire).await?;
                }
            }
            p::FLIGHT_REQUESTED => {
                let wire = branch.recv::<p::CryptoFlightRequested>().await?;
                completed = wire;
                // All large packet/transcript locals die before suspension.
                let succeeded = {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::TakeCryptoFlight { max_len } = command else {
                        return Err(Error::UnexpectedCommand);
                    };
                    let mut bytes = Bytes {
                        bytes: [0; N],
                        len: 0,
                    };
                    if max_len > N {
                        return Err(Error::PacketBounds);
                    }
                    match provider.transmit(&mut bytes.bytes[..max_len]) {
                        Ok(Some(output)) => {
                            if output.len > N {
                                return Err(Error::PacketBounds);
                            }
                            bytes.len = output.len;
                            exchange.put_reply(
                                provider,
                                descriptor,
                                Outcome::CryptoOutput {
                                    level: output.level,
                                    bytes,
                                },
                            )?;
                            true
                        }
                        Ok(None) => {
                            exchange.put_reply(provider, descriptor, Outcome::NoCryptoOutput)?;
                            false
                        }
                        Err(e) => {
                            exchange.put_reply(provider, descriptor, Outcome::Failed(e))?;
                            false
                        }
                    }
                };
                if succeeded {
                    endpoint.send::<p::FlightReady>(&wire).await?;
                } else {
                    endpoint.send::<p::AwaitInput>(&wire).await?;
                }
            }
            p::MAINTAIN_KEYS => {
                let wire = branch.recv::<p::MaintainKeys>().await?;
                completed = wire;
                // All large packet/transcript locals die before suspension.
                let succeeded = {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::MaintainKeys { now, pto } = command else {
                        return Err(Error::UnexpectedCommand);
                    };
                    match provider.maintain_keys(now, pto) {
                        Ok(()) => {
                            exchange.put_reply(provider, descriptor, Outcome::KeysMaintained)?;
                            true
                        }
                        Err(e) => {
                            exchange.put_reply(provider, descriptor, Outcome::Failed(e))?;
                            false
                        }
                    }
                };
                if succeeded {
                    endpoint.send::<p::KeysMaintained>(&wire).await?;
                } else {
                    endpoint.send::<p::MaintenanceRejected>(&wire).await?;
                }
            }
            p::LOAN_INTEGRITY => {
                let wire = branch.recv::<p::LoanIntegrity>().await?;
                let loan;
                let granted = {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::LoanIntegrity = command else {
                        return Err(Error::UnexpectedCommand);
                    };
                    loan = descriptor;
                    if let Some(budget) = provider.integrity_budget() {
                        let budget = budget.take_for_role();
                        exchange.put_reply(
                            provider,
                            descriptor,
                            Outcome::IntegrityGranted(IntegrityGrant { descriptor, budget }),
                        )?;
                        true
                    } else {
                        exchange.put_reply(provider, descriptor, Outcome::LoanUnavailable)?;
                        false
                    }
                };
                if granted {
                    endpoint.send::<p::IntegrityGranted>(&wire).await?;
                    same(endpoint.recv::<p::ResultTaken>().await?, wire)?;
                    // This directly projected receive prevents ALL crypto while the unique
                    // budget is away; cancellation leaves the Provider's exhausted tombstone.
                    let returned_wire = endpoint.recv::<p::IntegrityReturned>().await?;
                    completed = returned_wire;
                    {
                        let Request {
                            descriptor,
                            command,
                        } = exchange.take_request(returned_wire)?;
                        if descriptor.generation != generation
                            || descriptor.sequence
                                != loan
                                    .sequence
                                    .checked_add(1)
                                    .ok_or(Error::SequenceExhausted)?
                        {
                            return Err(Error::Correlation);
                        }
                        let Command::ReturnIntegrity(IntegrityReturn(grant)) = command else {
                            return Err(Error::UnexpectedCommand);
                        };
                        if grant.descriptor != loan {
                            return Err(Error::Correlation);
                        }
                        *provider
                            .integrity_budget()
                            .ok_or(Error::IntegrityUnavailable)? = grant.budget;
                        exchange.put_reply(provider, descriptor, Outcome::IntegrityRestored)?;
                    }
                    endpoint
                        .send::<p::IntegrityRestored>(&returned_wire)
                        .await?;
                } else {
                    completed = wire;
                    endpoint.send::<p::LoanUnavailable>(&wire).await?;
                }
            }
            p::OPEN_EARLY => {
                let wire = branch.recv::<p::OpenEarly>().await?;
                completed = wire;
                // All large packet/transcript locals die before suspension.
                let succeeded = {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::OpenEarly(packet) = command else {
                        return Err(Error::UnexpectedCommand);
                    };
                    let pn = packet.packet_number();
                    let len = packet.body().len();
                    let mut body = Zeroizing::new([0; N]);
                    body[..len].copy_from_slice(packet.body());
                    let header = packet.header();
                    match provider.open_early(pn, header, &mut body[..len]) {
                        Ok(len) => {
                            if len > N {
                                return Err(Error::PacketBounds);
                            }
                            if provider.early_generation() != Some(generation) {
                                return Err(Error::Correlation);
                            }
                            let packet = Packet::new(pn, header, &body[..len])
                                .map_err(|_| Error::PacketBounds)?;
                            exchange.put_reply(
                                provider,
                                descriptor,
                                Outcome::EarlyOpened(OpenedEarlyPacket {
                                    packet,
                                    receipt: EarlyOpenReceipt {
                                        descriptor,
                                        packet_number: pn,
                                    },
                                }),
                            )?;
                            true
                        }
                        Err(e) => {
                            drop(packet);
                            exchange.put_reply(provider, descriptor, Outcome::Failed(e))?;
                            false
                        }
                    }
                };
                if succeeded {
                    endpoint.send::<p::EarlyOpened>(&wire).await?;
                } else {
                    endpoint.send::<p::EarlyOpenRejected>(&wire).await?;
                }
            }
            p::SEAL_EARLY => {
                let wire = branch.recv::<p::SealEarly>().await?;
                completed = wire;
                // All large packet/transcript locals die before suspension.
                let succeeded = {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::SealEarly(packet) = command else {
                        return Err(Error::UnexpectedCommand);
                    };
                    let pn = packet.packet_number();
                    let plaintext_len = packet.body().len();
                    let mut body = Zeroizing::new([0; N]);
                    body[..plaintext_len].copy_from_slice(packet.body());
                    let header = packet.header();
                    let capacity = N - header.len();
                    match provider.seal_early(pn, header, &mut body[..capacity], plaintext_len) {
                        Ok(len) => {
                            if len > N {
                                return Err(Error::PacketBounds);
                            }
                            let packet = Packet::new(pn, header, &body[..len])
                                .map_err(|_| Error::PacketBounds)?;
                            exchange.put_reply(provider, descriptor, Outcome::Sealed(packet))?;
                            true
                        }
                        Err(e) => {
                            drop(packet);
                            exchange.put_reply(provider, descriptor, Outcome::Failed(e))?;
                            false
                        }
                    }
                };
                if succeeded {
                    endpoint.send::<p::EarlySealed>(&wire).await?;
                } else {
                    endpoint.send::<p::EarlySealRejected>(&wire).await?;
                }
            }
            p::EARLY_HEADER_MASK => {
                let wire = branch.recv::<p::EarlyHeaderMask>().await?;
                completed = wire;
                // All large packet/transcript locals die before suspension.
                let succeeded = {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::EarlyHeaderMask { local, sample } = command else {
                        return Err(Error::UnexpectedCommand);
                    };
                    match provider.early_header_mask(local, &sample) {
                        Ok(mask) => {
                            exchange.put_reply(provider, descriptor, Outcome::HeaderMask(mask))?;
                            true
                        }
                        Err(e) => {
                            exchange.put_reply(provider, descriptor, Outcome::Failed(e))?;
                            false
                        }
                    }
                };
                if succeeded {
                    endpoint.send::<p::HeaderMaskReady>(&wire).await?;
                } else {
                    endpoint.send::<p::HeaderMaskRejected>(&wire).await?;
                }
            }
            p::TAKE_EARLY_REPLAY_CLAIM => {
                let wire = branch.recv::<p::TakeEarlyReplayClaim>().await?;
                completed = wire;
                let claimed = {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::TakeEarlyReplayClaim = command else {
                        return Err(Error::UnexpectedCommand);
                    };
                    if let Some(claim) = provider.take_early_replay_claim() {
                        exchange.put_reply(
                            provider,
                            descriptor,
                            Outcome::EarlyReplayClaim(claim),
                        )?;
                        true
                    } else {
                        exchange.put_reply(provider, descriptor, Outcome::NoEarlyReplayClaim)?;
                        false
                    }
                };
                if claimed {
                    endpoint.send::<p::EarlyReplayClaimReady>(&wire).await?;
                } else {
                    endpoint.send::<p::NoEarlyReplayClaim>(&wire).await?;
                }
            }
            p::DISCARD_EARLY => {
                let wire = branch.recv::<p::DiscardEarly>().await?;
                completed = wire;
                {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::DiscardEarly = command else {
                        return Err(Error::UnexpectedCommand);
                    };
                    provider.discard_early_keys();
                    exchange.put_reply(provider, descriptor, Outcome::EarlyDiscarded)?;
                }
                endpoint.send::<p::EarlyDiscarded>(&wire).await?;
            }
            p::OPEN_HANDSHAKE => {
                let wire = branch.recv::<p::OpenHandshake>().await?;
                completed = wire;
                // All large packet/transcript locals die before suspension.
                let succeeded = {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::OpenHandshake(packet) = command else {
                        return Err(Error::UnexpectedCommand);
                    };
                    let pn = packet.packet_number();
                    let len = packet.body().len();
                    let mut body = Zeroizing::new([0; N]);
                    body[..len].copy_from_slice(packet.body());
                    let header = packet.header();
                    match provider.open(Level::Handshake, pn, header, &mut body[..len]) {
                        Ok(len) => {
                            if len > N {
                                return Err(Error::PacketBounds);
                            }
                            let packet = Packet::new(pn, header, &body[..len])
                                .map_err(|_| Error::PacketBounds)?;
                            exchange.put_reply(
                                provider,
                                descriptor,
                                Outcome::Opened {
                                    packet,
                                    generation: 0,
                                    key_updated: false,
                                    receipt: OpenReceipt {
                                        descriptor,
                                        level: Level::Handshake,
                                        packet_number: pn,
                                        key_generation: 0,
                                    },
                                },
                            )?;
                            true
                        }
                        Err(e) => {
                            drop(packet);
                            exchange.put_reply(provider, descriptor, Outcome::Failed(e))?;
                            false
                        }
                    }
                };
                if succeeded {
                    endpoint.send::<p::HandshakeOpened>(&wire).await?;
                } else {
                    endpoint.send::<p::HandshakeOpenRejected>(&wire).await?;
                }
            }
            p::SEAL_HANDSHAKE => {
                let wire = branch.recv::<p::SealHandshake>().await?;
                completed = wire;
                // All large packet/transcript locals die before suspension.
                let succeeded = {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::SealHandshake(packet) = command else {
                        return Err(Error::UnexpectedCommand);
                    };
                    let pn = packet.packet_number();
                    let plaintext_len = packet.body().len();
                    let mut body = Zeroizing::new([0; N]);
                    body[..plaintext_len].copy_from_slice(packet.body());
                    let header = packet.header();
                    let capacity = N - header.len();
                    match provider.seal(
                        Level::Handshake,
                        pn,
                        header,
                        &mut body[..capacity],
                        plaintext_len,
                    ) {
                        Ok(len) => {
                            if len > N {
                                return Err(Error::PacketBounds);
                            }
                            let packet = Packet::new(pn, header, &body[..len])
                                .map_err(|_| Error::PacketBounds)?;
                            exchange.put_reply(provider, descriptor, Outcome::Sealed(packet))?;
                            true
                        }
                        Err(e) => {
                            drop(packet);
                            exchange.put_reply(provider, descriptor, Outcome::Failed(e))?;
                            false
                        }
                    }
                };
                if succeeded {
                    endpoint.send::<p::HandshakeSealed>(&wire).await?;
                } else {
                    endpoint.send::<p::HandshakeSealRejected>(&wire).await?;
                }
            }
            p::HANDSHAKE_HEADER_MASK => {
                let wire = branch.recv::<p::HandshakeHeaderMask>().await?;
                completed = wire;
                // All large packet/transcript locals die before suspension.
                let succeeded = {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::HeaderMask {
                        level: Level::Handshake,
                        local,
                        sample,
                    } = command
                    else {
                        return Err(Error::UnexpectedCommand);
                    };
                    match provider.header_mask(Level::Handshake, local, &sample) {
                        Ok(mask) => {
                            exchange.put_reply(provider, descriptor, Outcome::HeaderMask(mask))?;
                            true
                        }
                        Err(e) => {
                            exchange.put_reply(provider, descriptor, Outcome::Failed(e))?;
                            false
                        }
                    }
                };
                if succeeded {
                    endpoint.send::<p::HeaderMaskReady>(&wire).await?;
                } else {
                    endpoint.send::<p::HeaderMaskRejected>(&wire).await?;
                }
            }
            p::OPEN_ONE_RTT => {
                let wire = branch.recv::<p::OpenOneRtt>().await?;
                completed = wire;
                // All large packet/transcript locals die before suspension.
                let succeeded = {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::OpenOneRtt {
                        packet,
                        phase,
                        now,
                        pto,
                    } = command
                    else {
                        return Err(Error::UnexpectedCommand);
                    };
                    let pn = packet.packet_number();
                    let len = packet.body().len();
                    let mut body = Zeroizing::new([0; N]);
                    body[..len].copy_from_slice(packet.body());
                    let header = packet.header();
                    match provider.open_one_rtt(pn, phase, header, &mut body[..len], now, pto) {
                        Ok(opened) => {
                            if opened.len > N {
                                return Err(Error::PacketBounds);
                            }
                            let packet = Packet::new(pn, header, &body[..opened.len])
                                .map_err(|_| Error::PacketBounds)?;
                            exchange.put_reply(
                                provider,
                                descriptor,
                                Outcome::Opened {
                                    packet,
                                    generation: opened.generation,
                                    key_updated: opened.key_updated,
                                    receipt: OpenReceipt {
                                        descriptor,
                                        level: Level::OneRtt,
                                        packet_number: pn,
                                        key_generation: opened.generation,
                                    },
                                },
                            )?;
                            true
                        }
                        Err(e) => {
                            drop(packet);
                            exchange.put_reply(provider, descriptor, Outcome::Failed(e))?;
                            false
                        }
                    }
                };
                if succeeded {
                    endpoint.send::<p::OneRttOpened>(&wire).await?;
                } else {
                    endpoint.send::<p::OneRttOpenRejected>(&wire).await?;
                }
            }
            p::SEAL_ONE_RTT => {
                let wire = branch.recv::<p::SealOneRtt>().await?;
                completed = wire;
                // All large packet/transcript locals die before suspension.
                let succeeded = {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::SealOneRtt(packet) = command else {
                        return Err(Error::UnexpectedCommand);
                    };
                    let pn = packet.packet_number();
                    let plaintext_len = packet.body().len();
                    let mut body = Zeroizing::new([0; N]);
                    body[..plaintext_len].copy_from_slice(packet.body());
                    let header = packet.header();
                    let capacity = N - header.len();
                    match provider.seal(
                        Level::OneRtt,
                        pn,
                        header,
                        &mut body[..capacity],
                        plaintext_len,
                    ) {
                        Ok(len) => {
                            if len > N {
                                return Err(Error::PacketBounds);
                            }
                            let packet = Packet::new(pn, header, &body[..len])
                                .map_err(|_| Error::PacketBounds)?;
                            exchange.put_reply(provider, descriptor, Outcome::Sealed(packet))?;
                            true
                        }
                        Err(e) => {
                            drop(packet);
                            exchange.put_reply(provider, descriptor, Outcome::Failed(e))?;
                            false
                        }
                    }
                };
                if succeeded {
                    endpoint.send::<p::OneRttSealed>(&wire).await?;
                } else {
                    endpoint.send::<p::OneRttSealRejected>(&wire).await?;
                }
            }
            p::ONE_RTT_HEADER_MASK => {
                let wire = branch.recv::<p::OneRttHeaderMask>().await?;
                completed = wire;
                // All large packet/transcript locals die before suspension.
                let succeeded = {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::HeaderMask {
                        level: Level::OneRtt,
                        local,
                        sample,
                    } = command
                    else {
                        return Err(Error::UnexpectedCommand);
                    };
                    match provider.header_mask(Level::OneRtt, local, &sample) {
                        Ok(mask) => {
                            exchange.put_reply(provider, descriptor, Outcome::HeaderMask(mask))?;
                            true
                        }
                        Err(e) => {
                            exchange.put_reply(provider, descriptor, Outcome::Failed(e))?;
                            false
                        }
                    }
                };
                if succeeded {
                    endpoint.send::<p::HeaderMaskReady>(&wire).await?;
                } else {
                    endpoint.send::<p::HeaderMaskRejected>(&wire).await?;
                }
            }
            p::VALIDATED_ACK => {
                let wire = branch.recv::<p::ValidatedAck>().await?;
                completed = wire;
                // All large packet/transcript locals die before suspension.
                let succeeded = {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::ValidatedAck {
                        sent_pn,
                        received_generation,
                        now,
                        pto,
                    } = command
                    else {
                        return Err(Error::UnexpectedCommand);
                    };
                    match provider.acknowledge_one_rtt(sent_pn, received_generation, now, pto) {
                        Ok(()) => {
                            exchange.put_reply(provider, descriptor, Outcome::AckApplied)?;
                            true
                        }
                        Err(e) => {
                            exchange.put_reply(provider, descriptor, Outcome::Failed(e))?;
                            false
                        }
                    }
                };
                if succeeded {
                    endpoint.send::<p::AckApplied>(&wire).await?;
                } else {
                    endpoint.send::<p::AckRejected>(&wire).await?;
                }
            }
            p::CONFIRM_HANDSHAKE => {
                let wire = branch.recv::<p::ConfirmHandshake>().await?;
                completed = wire;
                // All large packet/transcript locals die before suspension.
                let succeeded = {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::ConfirmHandshake = command else {
                        return Err(Error::UnexpectedCommand);
                    };
                    match provider.confirm_handshake() {
                        Ok(()) => {
                            exchange.put_reply(
                                provider,
                                descriptor,
                                Outcome::HandshakeConfirmed,
                            )?;
                            true
                        }
                        Err(e) => {
                            exchange.put_reply(provider, descriptor, Outcome::Failed(e))?;
                            false
                        }
                    }
                };
                if succeeded {
                    advance = Some(wire);
                    endpoint.send::<p::HandshakeConfirmed>(&wire).await?;
                } else {
                    endpoint.send::<p::ConfirmationRejected>(&wire).await?;
                }
            }
            p::RETIRE_REQUESTED => {
                let wire = branch.recv::<p::RetireRequested>().await?;
                {
                    let Request {
                        descriptor,
                        command,
                    } = exchange.take_request(wire)?;
                    if descriptor.generation != generation {
                        return Err(Error::Correlation);
                    }
                    let Command::Retire = command else {
                        return Err(Error::UnexpectedCommand);
                    };
                    provider.discard_keys(Level::Handshake);
                    provider.discard_keys(Level::OneRtt);
                    provider.discard_early_keys();
                    exchange.put_reply(provider, descriptor, Outcome::Retired)?;
                }
                endpoint.send::<p::RetirementPrepared>(&wire).await?;
                same(endpoint.recv::<p::ResultTaken>().await?, wire)?;
                return Ok(OwnerExit::Retiring(wire));
            }
            label => return Err(Error::UnexpectedLabel(label)),
        }
        same(endpoint.recv::<p::ResultTaken>().await?, completed)?;
        if let Some(wire) = advance {
            return Ok(OwnerExit::Advanced(wire));
        }
        runtime::yield_now().await;
    }
}
