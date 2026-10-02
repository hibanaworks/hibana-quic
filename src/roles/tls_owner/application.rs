//! Literal application local continuations. The projected arm set owns phase admission.
use super::*;
use crate::roles::protocol_tls_phases::application as p;

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
            command @ Command::InitiateUpdate { .. } => {
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                endpoint.send::<p::InitiateUpdate>(&wire).await?;
                let branch = endpoint.offer().await?;
                let observed = match branch.label() {
                    p::KEY_UPDATED => branch.recv::<p::KeyUpdated>().await?,
                    p::UPDATE_REJECTED => branch.recv::<p::UpdateRejected>().await?,
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
            p::INITIATE_UPDATE => {
                let wire = branch.recv::<p::InitiateUpdate>().await?;
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
                    let Command::InitiateUpdate { now, pto } = command else {
                        return Err(Error::UnexpectedCommand);
                    };
                    match provider.initiate_key_update(now, pto) {
                        Ok(()) => {
                            exchange.put_reply(provider, descriptor, Outcome::KeyUpdated)?;
                            true
                        }
                        Err(e) => {
                            exchange.put_reply(provider, descriptor, Outcome::Failed(e))?;
                            false
                        }
                    }
                };
                if succeeded {
                    endpoint.send::<p::KeyUpdated>(&wire).await?;
                } else {
                    endpoint.send::<p::UpdateRejected>(&wire).await?;
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
        runtime::yield_now().await;
    }
}
