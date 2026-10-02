//! A publication owns its reservations until the real adapter and every domain
//! settle. No protected bytes or copied reporting ID can authorize a callback.
use super::stream_actor::STREAM_FRAME_BYTES;
use super::*;
use crate::roles::{datagram, path_owner, recovery_owner, stream_owner};

/// Cancellation consumes the connection's live service capabilities. A caller
/// cannot retain an unpublished reservation after dropping the send future.
struct Publication<'a, 'r, 's, 'tc, 'ts, K: InitialKeyProtection> {
    engine: &'a mut HandshakeEndpoint<'r, 's, 'tc, 'ts, K>,
    completed: bool,
}
impl<K: InitialKeyProtection> Drop for Publication<'_, '_, '_, '_, '_, K> {
    fn drop(&mut self) {
        if !self.completed {
            self.engine.retire();
        }
    }
}

impl<'r, 's, 'tc, 'ts, K: InitialKeyProtection> HandshakeEndpoint<'r, 's, 'tc, 'ts, K> {
    pub async fn transmit_with<A: path_owner::UdpAdapter>(
        &mut self,
        adapter: &mut A,
    ) -> Result<Option<Transmit>, Error> {
        let mut operation = Publication {
            engine: self,
            completed: false,
        };
        let result = operation.engine.transmit_owned(adapter, None).await;
        operation.completed = result.is_ok();
        result
    }

    pub async fn transmit_application_with<A: path_owner::UdpAdapter>(
        &mut self,
        prepared: stream_owner::PreparedFrame<STREAM_FRAME_BYTES>,
        adapter: &mut A,
    ) -> Result<Option<Transmit>, Error> {
        let mut operation = Publication {
            engine: self,
            completed: false,
        };
        let result = operation
            .engine
            .transmit_owned(adapter, Some(prepared))
            .await;
        operation.completed = result.is_ok();
        result
    }

    async fn transmit_owned<A: path_owner::UdpAdapter>(
        &mut self,
        adapter: &mut A,
        application: Option<stream_owner::PreparedFrame<STREAM_FRAME_BYTES>>,
    ) -> Result<Option<Transmit>, Error> {
        if self.retired {
            return Err(Error::Retired);
        }
        if self.poll_idle_timeout(self.now)? {
            return Err(Error::Retired);
        }
        self.io_started = true;
        self.path_prepare().await?;
        self.stream_install_early_send().await?;
        if self.lifecycle.state() == ConnectionState::Draining {
            if let Some(frame) = application {
                self.stream_cancel_prepared(frame.id()).await?;
            }
            return Ok(None);
        }
        if self.lifecycle.state() == ConnectionState::Closing {
            if let Some(frame) = application {
                self.stream_cancel_prepared(frame.id()).await?;
            }
            return self.transmit_close_owned(adapter).await;
        }
        if let Some(frame) = application.as_ref() {
            if frame.bytes().is_empty() || frame.bytes().len() > MAX_APPLICATION_FRAME_BYTES {
                return Err(Error::Capacity);
            }
            if (!frame.is_early() && !self.handshake_complete())
                || (frame.is_early() && self.side != Side::Client)
            {
                return Err(Error::Busy);
            }
        }
        let result = self
            .publish_packet(adapter, application, None, None)
            .await?;
        if result.is_some() {
            return Ok(result);
        }
        if let Some(quote) = self.path_snapshot().control_quote {
            return self.publish_packet(adapter, None, None, Some(quote)).await;
        }
        Ok(None)
    }

    async fn transmit_close_owned<A: path_owner::UdpAdapter>(
        &mut self,
        adapter: &mut A,
    ) -> Result<Option<Transmit>, Error> {
        if self.close_round.is_none() {
            let mut levels = 0u8;
            if self.tls_has_keys(Level::OneRtt) && !self.tls_snapshot().handshaking {
                levels |= 4;
            }
            if !self.handshake_confirmed {
                if self.tls_has_keys(Level::Handshake) {
                    levels |= 2;
                }
                if !self.discarded[0] && (self.side == Side::Server || levels == 0) {
                    levels |= 1;
                }
            }
            if levels == 0 {
                self.retire();
                return Ok(None);
            }
            let Some(token) = self.lifecycle.poll_transmit(self.now)? else {
                return Ok(None);
            };
            self.close_round = Some((token, levels, false));
        }
        let (token, levels, previously_accepted) = self.close_round.ok_or(Error::InvalidConfig)?;
        let level = if levels & 4 != 0 {
            Level::OneRtt
        } else if levels & 2 != 0 {
            Level::Handshake
        } else {
            Level::Initial
        };
        let mut bytes = [0u8; 160];
        let frame = self
            .lifecycle
            .reason()
            .ok_or(Error::InvalidConfig)?
            .frame(level);
        let len = packet::encode_frame(&frame, &mut bytes)?;
        let result = self
            .publish_packet(adapter, None, Some((level, &bytes[..len])), None)
            .await?;
        match result {
            Some(report) if report.accepted_at.is_some() => {
                let remaining = levels & !(1 << index(level));
                if remaining != 0 {
                    self.close_round = Some((token, remaining, true));
                } else {
                    self.close_round = None;
                    self.lifecycle
                        .adapter_result(token, true, report.accepted_at.unwrap())?;
                }
            }
            _ => {
                self.close_round = None;
                self.lifecycle
                    .adapter_result(token, previously_accepted, self.now)?;
            }
        }
        Ok(result)
    }

    async fn publish_packet<A: path_owner::UdpAdapter>(
        &mut self,
        adapter: &mut A,
        application: Option<stream_owner::PreparedFrame<STREAM_FRAME_BYTES>>,
        closing: Option<(Level, &[u8])>,
        control: Option<path_owner::ControlQuote>,
    ) -> Result<Option<Transmit>, Error> {
        use recovery_owner::{Command as R, FlightCommand as F, Outcome as O};
        let early = application.as_ref().is_some_and(|frame| frame.is_early());
        if application.is_none() && closing.is_none() && control.is_none() {
            if self.probe.is_none() {
                self.probe = self.recovery_snapshot().next_lost_flight;
            }
            if self.pending_tls.is_none() && self.probe.is_none() {
                self.take_tls_flight().await?;
            }
            if let Some(output) = self.pending_tls
                && self.queued_flight.is_none()
            {
                let bytes = recovery_owner::FlightBytes::new(
                    self.pending_crypto
                        .get(..output.len)
                        .ok_or(Error::Capacity)?,
                )
                .map_err(Error::RecoveryRejected)?;
                match self
                    .recovery_flight(F::Store {
                        level: output.level,
                        offset: self.offsets[index(output.level)],
                        bytes,
                    })
                    .await
                {
                    Ok(O::FlightStored(id)) => self.queued_flight = Some(id),
                    Err(Error::RecoveryRejected(recovery_owner::Rejection::Flight(
                        flights::Error::Full,
                    ))) => {}
                    Err(error) => return Err(error),
                    _ => return Err(Error::InvalidConfig),
                }
            }
            if self.handshake_done_pending && self.handshake_done_flight.is_none() {
                match self.recovery_flight(F::StoreHandshakeDone).await {
                    Ok(O::FlightStored(id)) => self.handshake_done_flight = Some(id),
                    Err(Error::RecoveryRejected(recovery_owner::Rejection::Flight(
                        flights::Error::Full,
                    ))) => {}
                    Err(error) => return Err(error),
                    _ => return Err(Error::InvalidConfig),
                }
            }
        }
        let selected = if closing.is_none() && application.is_none() && control.is_none() {
            self.probe
                .or(self.queued_flight)
                .or(if self.handshake_done_pending {
                    self.handshake_done_flight
                } else {
                    None
                })
        } else {
            None
        };
        let flight = if let Some(id) = selected {
            match self.recovery_flight(F::Read(id)).await? {
                O::FlightData {
                    level,
                    offset,
                    bytes,
                    handshake_done,
                    ..
                } => Some((level, offset, bytes, handshake_done)),
                _ => return Err(Error::InvalidConfig),
            }
        } else {
            None
        };
        let level = if let Some((level, _)) = closing {
            level
        } else if application.is_some() || control.is_some() {
            Level::OneRtt
        } else if let Some((level, _, _, _)) = &flight {
            *level
        } else if let Some(level) = self.ping_probe {
            level
        } else {
            let Some(i) = self.received.iter().enumerate().find_map(|(i, seen)| {
                let level = [Level::Initial, Level::Handshake, Level::OneRtt][i];
                (seen.ack_pending && self.tls_has_keys(level)).then_some(i)
            }) else {
                return Ok(None);
            };
            [Level::Initial, Level::Handshake, Level::OneRtt][i]
        };
        if !early && level == Level::OneRtt && self.tls_snapshot().handshaking {
            if let Some(frame) = application {
                self.stream_cancel_prepared(frame.id()).await?;
            }
            return Ok(None);
        }
        let was_probe = selected.is_some() && selected == self.probe;
        let ping = closing.is_none()
            && application.is_none()
            && control.is_none()
            && selected.is_none()
            && self.ping_probe == Some(level);
        let mut plaintext = zeroize::Zeroizing::new([0u8; 1200]);
        let mut len = 0usize;
        let mut ack_largest = None;
        let mut ack_bits = 0;
        if !early && closing.is_none() {
            let seen = &self.received[index(level)];
            if seen.ack_pending {
                let mut ranges = [packet::AckRange {
                    smallest: 0,
                    largest: 0,
                }; 32];
                let count = seen.ranges(&mut ranges);
                if count > 0 {
                    len += packet::encode_frame(
                        &Frame::Ack {
                            delay: 0,
                            ranges: AckRanges::new(&ranges[..count])?,
                            ecn: self.ecn_rx.ack_counts(space(level)),
                        },
                        &mut plaintext[len..],
                    )?;
                    ack_largest = seen.largest;
                    ack_bits = seen.bits;
                }
            }
        }
        let ack_len = len;
        let mut crypto_len = 0usize;
        let mut handshake_done = false;
        if let Some((_, offset, bytes, done)) = &flight {
            handshake_done = *done;
            let frame = if *done {
                Frame::HandshakeDone
            } else {
                Frame::Crypto {
                    offset: *offset,
                    data: bytes.as_bytes(),
                }
            };
            len += packet::encode_frame(&frame, &mut plaintext[len..])?;
            if !*done && selected == self.queued_flight {
                crypto_len = bytes.as_bytes().len();
            }
        }
        if ping {
            len += packet::encode_frame(&Frame::Ping, &mut plaintext[len..])?;
        }
        if let Some(frame) = application.as_ref() {
            let end = len
                .checked_add(frame.bytes().len())
                .ok_or(Error::Capacity)?;
            plaintext
                .get_mut(len..end)
                .ok_or(Error::Capacity)?
                .copy_from_slice(frame.bytes());
            len = end;
        }
        if let Some((_, bytes)) = closing {
            plaintext[..bytes.len()].copy_from_slice(bytes);
            len = bytes.len();
        }
        let control_offset = len;
        if let Some(quote) = control {
            len = len
                .checked_add(quote.frame_bytes)
                .filter(|n| *n <= plaintext.len())
                .ok_or(Error::Capacity)?;
        }
        let path_snapshot = self.path_snapshot();
        let path_id = control.map_or(path_snapshot.active, |quote| quote.path);
        let slot = path_snapshot
            .paths
            .iter()
            .position(|entry| entry.is_some_and(|(id, _)| id == path_id))
            .ok_or(Error::InvalidConfig)?;
        let destination = path_snapshot.destinations[slot].ok_or(Error::InvalidConfig)?;
        let path_state = path_snapshot.paths[slot].ok_or(Error::InvalidConfig)?.1;
        let pn =
            self.recovery_snapshot().next_packet_number[index(level)].ok_or(Error::Capacity)?;
        let packet_number = accounting::PacketNumber {
            space: space(level),
            value: pn,
        };
        let mut wire = zeroize::Zeroizing::new([0u8; tls_actor::TLS_PACKET_BYTES]);
        let mut header_len = encode_header(
            level,
            early,
            pn,
            destination.as_bytes(),
            self.local.bytes(),
            self.client_retry.token(),
            self.side,
            self.tls_snapshot().key_phase,
            len,
            &mut wire[..],
        )?;
        let minimum = if level == Level::Initial {
            1200
        } else {
            control.map_or(0, |q| q.minimum_datagram_bytes as usize)
        };
        if minimum > 0 {
            if level == Level::Initial {
                header_len = encode_header(
                    level,
                    early,
                    pn,
                    destination.as_bytes(),
                    self.local.bytes(),
                    self.client_retry.token(),
                    self.side,
                    false,
                    minimum - header_len - 16,
                    &mut wire[..],
                )?;
                header_len = encode_header(
                    level,
                    early,
                    pn,
                    destination.as_bytes(),
                    self.local.bytes(),
                    self.client_retry.token(),
                    self.side,
                    false,
                    minimum - header_len - 16,
                    &mut wire[..],
                )?;
            }
            let padded = minimum
                .checked_sub(header_len + 16)
                .ok_or(Error::Capacity)?;
            if len > padded && ack_len > 0 && len - ack_len <= padded && control.is_none() {
                plaintext.copy_within(ack_len..len, 0);
                len -= ack_len;
                ack_largest = None;
                ack_bits = 0;
            }
            if len > padded {
                return Err(Error::Capacity);
            }
            plaintext[len..padded].fill(0);
            len = padded;
        }
        let total = header_len
            .checked_add(len + 16)
            .filter(|n| *n <= wire.len())
            .ok_or(Error::Capacity)?;
        if path_state.available_bytes < total as u64 {
            if let Some(frame) = application {
                self.stream_cancel_prepared(frame.id()).await?;
            }
            return Ok(None);
        }
        let command = if control.is_some() {
            path_owner::Command::ReserveControl {
                path: path_id,
                bytes: total as u64,
                packet: packet_number,
                now: self.now,
            }
        } else {
            path_owner::Command::Reserve {
                path: path_id,
                bytes: total as u64,
                packet: packet_number,
                now: self.now,
            }
        };
        let pending = match self.path_request(command).await? {
            path_owner::Outcome::Reserved(pending) => pending,
            _ => return Err(Error::InvalidConfig),
        };
        if pending.destination() != destination {
            return Err(Error::InvalidConfig);
        }
        if let Some(quote) = control {
            let selected = pending.control().ok_or(Error::InvalidConfig)?;
            let n = encode_control(selected, &mut plaintext[control_offset..])?;
            if n != quote.frame_bytes {
                return Err(Error::InvalidConfig);
            }
        }
        let mut eliciting = false;
        let mut padded = false;
        let encryption = if early {
            EncryptionLevel::ZeroRtt
        } else {
            wire_level(level)
        };
        for frame in FrameIter::new(&plaintext[..len], encryption, ParseLimits::default())? {
            let frame = frame?;
            eliciting |= frame.ack_eliciting();
            padded |= matches!(frame, Frame::Padding { .. });
        }
        let probe = application.as_ref().is_some_and(|frame| frame.is_probe())
            || ping
            || (was_probe
                && self.recovery_snapshot().pto_probe_space == Some(space(level))
                && self.recovery_snapshot().pto_probe_credits > 0);
        let plan = recovery_owner::SendPlan {
            kind: if early {
                PacketKind::ZeroRtt
            } else {
                kind(level)
            },
            bytes: total as u64,
            in_flight: eliciting || padded,
            ack_eliciting: eliciting,
            pto_probe: probe,
            flight: selected,
        };
        let ticket = match self.recovery_reserve(plan).await {
            Ok(ticket) => ticket,
            Err(Error::RecoveryRejected(
                recovery_owner::Rejection::CongestionLimited
                | recovery_owner::Rejection::Capacity
                | recovery_owner::Rejection::ProbeUnavailable
                | recovery_owner::Rejection::Accounting(accounting::AccountingError::Full),
            )) => {
                self.path_request(path_owner::Command::AdapterComplete(pending.reject()))
                    .await?;
                if let Some(frame) = application {
                    self.stream_cancel_prepared(frame.id()).await?;
                }
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        if ticket.packet() != packet_number {
            return Err(Error::InvalidConfig);
        }
        let transmission = if let Some(frame) = application.as_ref() {
            Some(self.stream_reserve(frame.id(), pn).await?)
        } else {
            None
        };
        let actual_header_len = encode_header(
            level,
            early,
            pn,
            pending.destination().as_bytes(),
            pending.source_cid().as_bytes(),
            self.client_retry.token(),
            self.side,
            self.tls_snapshot().key_phase,
            len,
            &mut wire[..],
        )?;
        if actual_header_len != header_len {
            return Err(Error::InvalidConfig);
        }
        wire[header_len..header_len + len].copy_from_slice(&plaintext[..len]);
        let (header, body) = wire[..total].split_at_mut(header_len);
        let sealed = if early {
            self.tls
                .as_mut()
                .ok_or(Error::Retired)?
                .seal_early(crate::roles::packet_protection::Packet::new(
                    pn,
                    header,
                    &plaintext[..len],
                )?)
                .await??
        } else if level == Level::Initial {
            self.initial.seal(pn, header, body, len).await?
        } else {
            self.tls_seal(level, pn, header, body, len).await?
        };
        let sample: [u8; 16] = sealed.bytes()[header_len..header_len + 16]
            .try_into()
            .map_err(|_| Error::Capacity)?;
        let mask = if early {
            self.tls
                .as_mut()
                .ok_or(Error::Retired)?
                .early_header_mask(true, sample)
                .await??
        } else if level == Level::Initial {
            self.initial.transmit_mask(sample).await?
        } else {
            self.tls_mask(level, true, sample).await?
        };
        let ecn = match self
            .recovery_request(R::EcnMarking {
                path: path_id,
                now: self.now,
            })
            .await?
        {
            O::EcnMarking(ecn) => ecn,
            _ => return Err(Error::InvalidConfig),
        };
        let protected = datagram::ProtectedDatagram::from_sealed(
            &pending,
            ticket,
            transmission.zip(application.as_ref()),
            ecn,
            sealed,
            &plaintext[..len],
            header_len - 4,
            mask,
        )
        .map_err(Error::Datagram)?;
        let address = pending.address();
        let completed = self
            .path
            .as_mut()
            .ok_or(Error::Retired)?
            .submit(pending, adapter, protected)
            .await
            .map_err(Error::UdpSubmission)?;
        let accepted_at = completed.recovery.accepted_at();
        if let Some(now) = accepted_at {
            // Record the real socket acceptance before settling the domain
            // owners: a later settlement error cannot undo a transmitted packet.
            self.trace_event_at(
                now,
                crate::trace::Event::Packet {
                    direction: crate::trace::Direction::Sent,
                    header: crate::trace::PacketHeader {
                        packet_type: if early {
                            crate::trace::PacketType::ZeroRtt
                        } else {
                            match level {
                                Level::Initial => crate::trace::PacketType::Initial,
                                Level::Handshake => crate::trace::PacketType::Handshake,
                                Level::OneRtt => crate::trace::PacketType::OneRtt,
                            }
                        },
                        packet_number: Some(pn),
                        key_phase: (!early && level == Level::OneRtt)
                            .then_some(self.tls_snapshot().send_generation),
                    },
                    datagram_id: None,
                },
            );
        }
        self.recovery_complete(completed.recovery).await?;
        if let Some(stream) = completed.stream {
            self.stream_complete(stream).await?;
        }
        self.path_request(path_owner::Command::AdapterComplete(completed.path.into()))
            .await?;
        let report = Transmit {
            early,
            connection_generation: self.generation(),
            id: self.next_id,
            len: total,
            level,
            packet_number,
            ecn,
            address: Some(address),
            accepted_at,
        };
        self.next_id = self.next_id.checked_add(1).ok_or(Error::Capacity)?;
        if let Some(now) = accepted_at {
            self.now = self.now.max(now);
            self.idle
                .on_accepted_send(eliciting, now, self.idle_pto()?)?;
            if level == Level::Initial
                && !early
                && let Some(client) = &mut self.version_negotiation
            {
                client.on_initial_accepted();
            }
            if ping {
                self.ping_probe = None;
            }
            if was_probe {
                self.probe = None;
            }
            if handshake_done {
                self.handshake_done_pending = false;
            }
            if crypto_len > 0 {
                self.offsets[index(level)] = self.offsets[index(level)]
                    .checked_add(crypto_len as u64)
                    .filter(|n| *n <= packet::MAX_VARINT)
                    .ok_or(Error::Capacity)?;
                self.pending_tls = None;
                self.queued_flight = None;
            }
            let seen = &mut self.received[index(level)];
            if ack_largest == seen.largest && ack_bits == seen.bits {
                seen.ack_pending = false;
            }
            if self.side == Side::Client && level == Level::Handshake {
                self.discard_requested[0] = true;
            }
        }
        self.recovery_reclaim(space(level)).await?;
        self.apply_client_retry().await?;
        self.apply_key_discards().await?;
        self.refresh_timer().await?;
        Ok(Some(report))
    }
}

#[allow(clippy::too_many_arguments)]
fn encode_header(
    level: Level,
    early: bool,
    pn: u64,
    destination: &[u8],
    source: &[u8],
    token: &[u8],
    side: Side,
    phase: bool,
    plaintext_len: usize,
    out: &mut [u8],
) -> Result<usize, Error> {
    if level == Level::OneRtt && !early {
        Ok(packet::encode_short_header(
            &ShortHeader {
                destination_id: destination,
                packet_number: pn,
                packet_number_len: 4,
                spin: false,
                key_phase: phase,
            },
            out,
        )?)
    } else {
        let kind = if early {
            LongType::ZeroRtt
        } else if level == Level::Initial {
            LongType::Initial
        } else {
            LongType::Handshake
        };
        Ok(packet::encode_long_header(
            &LongHeader {
                kind,
                destination_id: destination,
                source_id: source,
                token: if level == Level::Initial && side == Side::Client {
                    token
                } else {
                    &[]
                },
                packet_number: pn,
                packet_number_len: 4,
            },
            plaintext_len + 16,
            out,
        )?)
    }
}
fn encode_control(control: path_owner::Control, out: &mut [u8]) -> Result<usize, Error> {
    Ok(match control {
        path_owner::Control::Challenge(data) => {
            packet::encode_frame(&Frame::PathChallenge { data: &data }, out)?
        }
        path_owner::Control::Response(data) => {
            packet::encode_frame(&Frame::PathResponse { data: &data }, out)?
        }
        path_owner::Control::NewConnectionId {
            sequence,
            retire_prior_to,
            cid,
            reset_token,
        } => packet::encode_frame(
            &Frame::NewConnectionId {
                sequence,
                retire_prior_to,
                id: cid.as_bytes(),
                reset_token: reset_token.as_bytes(),
            },
            out,
        )?,
        path_owner::Control::RetireConnectionId { sequence } => {
            packet::encode_frame(&Frame::RetireConnectionId { sequence }, out)?
        }
    })
}
