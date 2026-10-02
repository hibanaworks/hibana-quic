//! Actual early packet protection and quarantine integration. Early traffic
//! shares ApplicationData packet numbers but never the ordinary receive ticket.
use super::*;
use crate::early_data::{EarlyStatus, Quarantine, QuarantineSlot, ServerPolicy};
pub const EARLY_REQUEST_BYTES: usize = 1024;
pub(super) struct State<'s> {
    slots: Option<&'s mut [QuarantineSlot<EARLY_REQUEST_BYTES>]>,
    policy: ServerPolicy,
    quarantine: Option<Quarantine<'s, EARLY_REQUEST_BYTES>>,
    finished: bool,
    client_reconciled: bool,
}
impl<'s> State<'s> {
    pub(super) const fn new() -> Self {
        Self {
            slots: None,
            policy: ServerPolicy::Disabled,
            quarantine: None,
            finished: false,
            client_reconciled: false,
        }
    }
}
impl<'r, 's, T: Provider> HandshakeEndpoint<'r, 's, T> {
    pub(super) fn reconcile_early_client<A: ApplicationHandler>(
        &mut self,
        handler: &mut A,
    ) -> Result<(), Error> {
        if self.side != Side::Client
            || !self.parameters_verified
            || self.tls.is_handshaking()
            || self.early.client_reconciled
        {
            return Ok(());
        }
        let decision = match self.tls.early_status() {
            EarlyStatus::Accepted => crate::early_send::Decision::Accepted,
            EarlyStatus::Rejected => crate::early_send::Decision::Rejected,
            _ => return Ok(()),
        };
        if decision == crate::early_send::Decision::Rejected {
            self.reject_early_packets()?;
        }
        self.driver.handshake_finished()?;
        handler
            .early_decision(decision, self.peer_limits.ok_or(Error::InvalidConfig)?)
            .map_err(Error::Streams)?;
        self.early.client_reconciled = true;
        Ok(())
    }
    pub(super) fn retry_early_packets(&mut self) -> Result<(), Error> {
        // Retry invalidates old-path early transmissions, not their owned
        // application intent. This is a retransmission notification only;
        // reject_zero_rtt does not call NewReno loss or rewind packet numbers.
        self.sent.reject_zero_rtt()?;
        let mut retry = [None;64];
        for (index, record) in self.application_packets.iter_mut().enumerate() {
            if record.is_some_and(|p| p.early) { retry[index]=record.take().map(|p| p.number); }
        }
        for pn in retry.into_iter().flatten() {
            if !self.lost_application.iter().flatten().any(|old| *old==pn) { self.report_application_loss(pn)?; }
        }
        self.sent.reclaim_completed_prefix(PacketNumberSpace::ApplicationData)?;
        Ok(())
    }
    pub(super) fn clear_early(&mut self) {
        self.tls.discard_early_keys();
        self.early.quarantine.take();
    }
    /// Reconcile authenticated TLS early rejection without declaring loss,
    /// discarding one-RTT records, or rewinding the shared application allocator.
    pub fn reject_early_packets(&mut self) -> Result<u64, Error> {
        if self.side != Side::Client || self.tls.early_status() != EarlyStatus::Rejected {
            return Err(Error::InvalidConfig);
        }
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        let removed = self.sent.reject_zero_rtt()?;
        for record in &mut self.application_packets {
            if record.is_some_and(|r| r.early) {
                *record = None;
            }
        }
        self.tls.discard_early_keys();
        if self.driver.is_early_key_installed() {
            self.driver.retire_early_key()?;
        }
        self.sent
            .reclaim_completed_prefix(PacketNumberSpace::ApplicationData)?;
        self.refresh_timer()?;
        Ok(removed)
    }
    /// Send an explicitly replay-safe encoded early STREAM request. The caller
    /// retains intent and maps the accepted PN into its EarlyIntentJournal.
    /// Initial CRYPTO must already have been submitted; output still owns the
    /// ordinary path/PN/adapter reservation and the distinct early-key authority.
    pub fn transmit_early_application(
        &mut self,
        encoded: &[u8],
        out: &mut [u8],
    ) -> Result<Option<Transmit>, Error> {
        if self.retired {
            return Err(Error::Retired);
        }
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        if self.side != Side::Client
            || self.lifecycle.state() != ConnectionState::Active
            || self.offsets[0] == 0
            || !matches!(self.tls.early_status(), EarlyStatus::Offered | EarlyStatus::AcceptedPendingFinished)
            || !self.tls.has_early_keys()
            || self.tls.has_keys(Level::OneRtt)
        {
            return Err(Error::InvalidConfig);
        }
        if out.len() < 1200 || encoded.is_empty() || encoded.len() > MAX_APPLICATION_FRAME_BYTES {
            return Err(Error::Capacity);
        }
        let mut eliciting = false;
        for frame in FrameIter::new(encoded, EncryptionLevel::ZeroRtt, ParseLimits::default())? {
            let frame = frame?;
            eliciting |= frame.ack_eliciting();
            if !matches!(
                frame,
                Frame::Stream { .. } | Frame::Padding { .. } | Frame::Ping
            ) {
                return Err(Error::UnexpectedFrame);
            }
        }
        if !eliciting {
            return Err(Error::UnexpectedFrame);
        }
        let result = self.transmit_early_inner(encoded, out);
        if result.is_err() {
            self.retire();
        }
        result
    }
    fn transmit_early_inner(
        &mut self,
        encoded: &[u8],
        out: &mut [u8],
    ) -> Result<Option<Transmit>, Error> {
        self.sync_early_authority()?;
        let Some(slot) = self.application_packets.iter().position(Option::is_none) else {
            return Ok(None);
        };
        let pn = self
            .sent
            .next_packet_number(PacketNumberSpace::ApplicationData)
            .ok_or(Error::Capacity)?;
        let hlen = packet::encode_long_header(
            &LongHeader {
                kind: LongType::ZeroRtt,
                destination_id: self.remote.bytes(),
                source_id: self.local.bytes(),
                token: &[],
                packet_number: pn,
                packet_number_len: 4,
            },
            encoded.len() + 16,
            out,
        )?;
        let total = hlen + encoded.len() + 16;
        if total > out.len() {
            return Err(Error::Capacity);
        }
        if !self.cc.can_send(
            self.sent.bytes_in_flight(),
            self.sent.reserved_in_flight(),
            total as u64,
            true,
            self.application_probe_permit,
        ) {
            return Ok(None);
        }
        let path = match self.path.reserve(total as u64) {
            Ok(p) => p,
            Err(accounting::AccountingError::AmplificationLimited) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let reservation =
            match self
                .sent
                .reserve_classified(PacketKind::ZeroRtt, total as u64, true, true)
            {
                Ok(r) => r,
                Err(accounting::AccountingError::Full) => {
                    self.path.cancel(path)?;
                    return Ok(None);
                }
                Err(e) => {
                    self.path.cancel(path)?;
                    return Err(e.into());
                }
            };
        let ticket = self.driver.reserve_transmit()?;
        let key = self.driver.begin_early_key_use()?;
        out[hlen..hlen + encoded.len()].copy_from_slice(encoded);
        let operation = (|| -> Result<(), Error> {
            let (header, body) = out[..total].split_at_mut(hlen);
            self.tls.seal_early(pn, header, body, encoded.len())?;
            let sample: &[u8; 16] = out[hlen..hlen + 16]
                .try_into()
                .map_err(|_| Error::Capacity)?;
            let mask = self.tls.early_header_mask(true, sample)?;
            out[0] ^= mask[0] & 0x0f;
            for i in 0..4 {
                out[hlen - 4 + i] ^= mask[i + 1];
            }
            Ok(())
        })();
        self.driver.finish_early_key_use(key)?;
        operation?;
        let output = Transmit {
            authority: ticket,
            early: true,
            connection_generation: self.generation(),
            id: self.next_id,
            len: total,
            level: Level::OneRtt,
            packet_number: reservation.packet(),
            ecn: if self.ecn_enabled {
                self.ecn_tx.marking(self.path_identity(), self.now)?
            } else {
                Codepoint::NotEct
            },
        };
        self.next_id = self.next_id.checked_add(1).ok_or(Error::Capacity)?;
        self.pending = Some(Pending {
            close: None,
            output,
            sent: reservation,
            path,
            ticket,
            crypto_len: 0,
            reference: None,
            was_probe: false,
            handshake_done: false,
            application_slot: Some(slot),
            ping: false,
            ack_largest: None,
            ack_bits: 0,
        });
        Ok(Some(output))
    }

    /// Configure actual caller storage before admitting an early-data offer.
    /// The TLS provider's policy must be no broader than this backing storage.
    pub fn configure_early_receive(
        &mut self,
        policy: ServerPolicy,
        slots: &'s mut [QuarantineSlot<EARLY_REQUEST_BYTES>],
    ) -> Result<(), Error> {
        if self.side != Side::Server
            || self.early.slots.is_some()
            || self.early.quarantine.is_some()
            || self.received[0].largest.is_some()
            || self.pending.is_some()
        {
            return Err(Error::InvalidConfig);
        }
        self.early.policy = policy;
        self.early.slots = Some(slots);
        Ok(())
    }
    pub(super) fn sync_early_authority(&mut self) -> Result<(), Error> {
        if self.tls.has_early_keys() {
            if self.tls.early_generation() != Some(self.generation()) {
                return Err(Error::InvalidConfig);
            }
            if !self.driver.is_early_key_installed() {
                self.driver.install_early_key()?;
            }
        } else if self.driver.is_early_key_installed() {
            self.driver.retire_early_key()?;
        }
        if self.side == Side::Server
            && self.early.quarantine.is_none()
            && matches!(
                self.tls.early_status(),
                EarlyStatus::AcceptedPendingFinished | EarlyStatus::Accepted
            )
        {
            let claim = self
                .tls
                .take_early_replay_claim()
                .ok_or(Error::InvalidConfig)?;
            if claim.generation() != self.generation() {
                return Err(Error::InvalidConfig);
            }
            let limits = self
                .tls
                .remembered_early_limits()
                .ok_or(Error::InvalidConfig)?;
            let slots = self.early.slots.take().ok_or(Error::InvalidConfig)?;
            self.early.quarantine = Some(
                Quarantine::new(self.early.policy, limits, claim, slots).map_err(Error::Early)?,
            );
        }
        Ok(())
    }
    /// Drain bounded quarantined ranges only after genuine verified Finished
    /// and authenticated transport parameters, holding both checked authorities.
    pub(super) fn release_early<A: ApplicationHandler>(
        &mut self,
        handler: &mut A,
    ) -> Result<(), Error> {
        if self.side != Side::Server
            || self.tls.is_handshaking()
            || !self.parameters_verified
            || self.early.quarantine.is_none()
        {
            return Ok(());
        }
        if !self.early.finished {
            self.driver.handshake_finished()?;
            let generation = self.generation();
            self.early
                .quarantine
                .as_mut()
                .ok_or(Error::InvalidConfig)?
                .finish_after_verified_handshake(generation)
                .map_err(Error::Early)?;
            self.early.finished = true;
        }
        // At most one complete receive-buffer capacity can be released in a
        // turn. The outer caller supplies bounded slots; no unbounded input loop.
        let mut work = 0usize;
        loop {
            let q = self.early.quarantine.as_mut().ok_or(Error::InvalidConfig)?;
            let Some(view) = q.next_release().map_err(Error::Early)? else {
                break;
            };
            if work >= 128 {
                return Err(Error::Capacity);
            }
            work += 1;
            let ticket = view.ticket;
            let authority = self.driver.begin_early_release(view.stream_id, ticket)?;
            handler
                .frame(Frame::Stream {
                    id: view.stream_id,
                    offset: view.offset,
                    fin: view.fin,
                    data: view.bytes,
                })
                .map_err(Error::Streams)?;
            self.driver.finish_early_release(authority)?;
            q.complete_release(ticket).map_err(Error::Early)?;
        }
        Ok(())
    }
    pub(super) fn receive_early<A: ApplicationHandler>(
        &mut self,
        packet: packet::Packet<'_>,
        scratch: &mut [u8],
        received_ecn: Option<Codepoint>,
        handler: &mut A,
    ) -> Result<bool, Error> {
        let Header::Long {
            kind: LongType::ZeroRtt,
            packet_number_offset: pn_offset,
            source_id,
            destination_id,
            ..
        } = packet.header
        else {
            return Ok(false);
        };
        if self.side != Side::Server
            || self.lifecycle.state() != ConnectionState::Active
            || !self.tls.has_early_keys()
            || !matches!(
                self.tls.early_status(),
                EarlyStatus::AcceptedPendingFinished | EarlyStatus::Accepted
            )
            || self.early.quarantine.is_none()
            || packet.bytes.len() > scratch.len()
            || (destination_id != self.local.bytes()
                && destination_id != self.initial_destination.bytes())
            || (self.remote_known && source_id != self.remote.bytes())
        {
            return Ok(false);
        }
        self.sync_early_authority()?;
        let bytes = &mut scratch[..packet.bytes.len()];
        bytes.copy_from_slice(packet.bytes);
        let Some(sample) = bytes.get(pn_offset + 4..pn_offset + 20) else {
            return Ok(false);
        };
        let sample: [u8; 16] = sample.try_into().map_err(|_| Error::Capacity)?;
        let authority = self.driver.begin_early_key_use()?;
        let operation = (|| -> Result<Option<(u64, usize, usize)>, Error> {
            let mask = self.tls.early_header_mask(false, &sample)?;
            bytes[0] ^= mask[0] & 0x0f;
            let n = usize::from((bytes[0] & 3) + 1);
            if pn_offset + n > bytes.len() {
                return Ok(None);
            }
            for i in 0..n {
                bytes[pn_offset + i] ^= mask[i + 1];
            }
            let (truncated, _) =
                packet::decode_truncated_packet_number(bytes[0], &bytes[pn_offset..])?;
            let pn =
                match packet::restore_packet_number(truncated, n as u8, self.received[2].largest) {
                    Ok(p) => p,
                    Err(_) => return Ok(None),
                };
            let first = bytes[0];
            let (header, body) = bytes.split_at_mut(pn_offset + n);
            let len = match self.tls.open_early(pn, header, body) {
                Ok(n) => n,
                Err(tls::Error::Authentication | tls::Error::KeysUnavailable) => return Ok(None),
                Err(e) => return Err(e.into()),
            };
            packet::validate_reserved_bits(first)?;
            if len == 0 {
                return Err(Error::ProtocolViolation);
            }
            Ok(Some((pn, pn_offset + n, len)))
        })();
        self.driver.finish_early_key_use(authority)?;
        let Some((pn, header_len, len)) = operation? else {
            return Ok(false);
        };
        let payload = &bytes[header_len..header_len + len];
        let limits = ParseLimits {
            max_bytes: 65535,
            max_frames: 128,
            max_ack_ranges: 32,
        };
        let mut eliciting = false;
        for frame in FrameIter::new(payload, EncryptionLevel::ZeroRtt, limits)? {
            let frame = frame?;
            eliciting |= frame.ack_eliciting();
            // This initial bounded early application profile admits only
            // complete replay-safe STREAM requests plus PING/PADDING.
            if !matches!(
                frame,
                Frame::Stream { .. } | Frame::Ping | Frame::Padding { .. }
            ) {
                return Ok(false);
            }
        }
        if !self.received[2].insert(pn) {
            if eliciting {
                self.received[2].ack_pending = true;
            }
            return Ok(false);
        }
        let receive = self.driver.begin_early_receive()?;
        for frame in FrameIter::new(payload, EncryptionLevel::ZeroRtt, limits)? {
            if let Frame::Stream {
                id,
                offset,
                fin,
                data,
            } = frame?
            {
                let buffer = self.driver.begin_early_buffer(receive, id)?;
                let generation = self.generation();
                self.early
                    .quarantine
                    .as_mut()
                    .ok_or(Error::InvalidConfig)?
                    .buffer_authenticated_stream(generation, id, offset, data, fin)
                    .map_err(Error::Early)?;
                self.driver.finish_early_buffer(buffer)?;
            }
        }
        self.driver.finish_early_receive(receive)?;
        self.ecn_rx
            .processed(PacketNumberSpace::ApplicationData, received_ecn)?;
        if eliciting {
            self.received[2].ack_pending = true;
        }
        self.release_early(handler)?;
        Ok(true)
    }
}
