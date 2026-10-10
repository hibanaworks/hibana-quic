//! Sealed packets, affine reservations and synchronous settlement.

use crate::crypto::directional::ApplicationKeyScope;
use crate::crypto::directional::ApplicationWriteKeys;
use crate::quic::Config;
use crate::quic::ConnectionId;
use crate::quic::application::Error;
use crate::quic::application::imp::stream;
use crate::quic::imp::application_wire;
use crate::quic::imp::application_wire::SealedApplicationDatagram;
use crate::quic::imp::kernel::accounting::AccountingError;
use crate::quic::imp::kernel::flights::FlightId;
use crate::quic::imp::kernel::packet;
use crate::quic::imp::kernel::packet::Frame;
use crate::quic::imp::recovery;
use crate::quic::wire;
use core::cell::{Cell, RefCell};
use hibana_tls::quic::Level;
use hibana_tls::secret::Secret;

// Both variants own bounded packets; this no_alloc path cannot box either.
#[allow(clippy::large_enum_variant)]
pub(in crate::quic::application) enum Sealed<'book, const N: usize> {
    Application(SealedApplicationDatagram<'book, N>),
    Long(wire::Datagram<'book, N>),
}
impl<'book, const N: usize> Sealed<'book, N> {
    pub(in crate::quic::application) fn reservation(&self) -> &recovery::Reservation<'book> {
        match self {
            Self::Application(packet) => packet.reservation(),
            Self::Long(packet) => &packet.reservation,
        }
    }
    pub(in crate::quic::application) fn bytes(&self) -> &[u8] {
        match self {
            Self::Application(packet) => packet.bytes(),
            Self::Long(packet) => packet.sealed.bytes(),
        }
    }
    pub(in crate::quic::application) fn into_parts(
        self,
    ) -> (
        recovery::Reservation<'book>,
        Option<recovery::AckSnapshot<'book>>,
    ) {
        match self {
            Self::Application(packet) => (packet.into_reservation(), None),
            Self::Long(wire::Datagram {
                sealed: _,
                reservation,
                acknowledgment,
            }) => (reservation, acknowledgment),
        }
    }
}

#[must_use = "publish or cancel both reservations together"]
pub(in crate::quic::application) struct Pending<'book, 'streams, const N: usize> {
    pub(in crate::quic::application) scope: &'book ApplicationKeyScope,
    pub(in crate::quic::application) sealed: Sealed<'book, N>,
    pub(in crate::quic::application) stream: Option<stream::Transmission<'streams>>,
    pub(in crate::quic::application) acknowledgment: Option<recovery::AckSnapshot<'book>>,
    pub(in crate::quic::application) close_deadline: Option<u64>,
    pub(in crate::quic::application) response: Option<crate::quic::path::imp::responses::Response>,
    pub(in crate::quic::application) cid: Option<crate::quic::imp::kernel::connection_id::LocalCid>,
    pub(in crate::quic::application) path: Option<crate::io::Address>,
    pub(in crate::quic::application) probe: Option<[u8; 8]>,
    pub(in crate::quic::application) peer_cid:
        Option<crate::quic::imp::kernel::connection_id::PeerCid>,
    pub(in crate::quic::application) retirement: Option<u64>,
}

/// The slot transfers the actual packet on the declared Datagram edge. It
/// owns the unique publication facets, so even cancellation before the adapter
/// takes the slot releases both reservations. Borrows are synchronous only.
pub(in crate::quic::application) struct Exchange<
    'book,
    'streams,
    'storage,
    'scope,
    const N: usize,
    const RX: usize,
    const CHUNK: usize,
> {
    pub(in crate::quic::application) responses: crate::quic::path::imp::responses::Responses,
    pub(in crate::quic::application) peers:
        RefCell<Option<crate::quic::path::imp::peer_ids::Peers<'storage, 'scope>>>,
    pub(in crate::quic::application) paths: crate::quic::path::imp::observations::Paths<'storage>,
    pub(in crate::quic::application) ids:
        RefCell<Option<crate::quic::path::imp::ids::Ids<'storage, 'scope>>>,
    pub(in crate::quic::application) pending: RefCell<Option<Pending<'book, 'streams, N>>>,
    pub(in crate::quic::application) owners:
        RefCell<Owners<'book, 'streams, 'storage, 'scope, N, RX, CHUNK>>,
    pub(in crate::quic::application) delivery:
        crate::quic::imp::tls::Inbox<stream::Delivered<'streams>>,
    pub(in crate::quic::application) drain_deadline: Cell<Option<u64>>,
}
pub(in crate::quic::application) struct Owners<
    'book,
    'streams,
    'storage,
    'scope,
    const N: usize,
    const RX: usize,
    const CHUNK: usize,
> {
    pub(in crate::quic::application) book: recovery::Publication<'book, 'scope, N>,
    pub(in crate::quic::application) streams:
        stream::Publication<'streams, 'storage, 'scope, RX, CHUNK>,
}
impl<'book, 'streams, 'storage, 'scope, const N: usize, const RX: usize, const CHUNK: usize>
    Exchange<'book, 'streams, 'storage, 'scope, N, RX, CHUNK>
{
    pub(in crate::quic::application) const fn new(
        book: recovery::Publication<'book, 'scope, N>,
        streams: stream::Publication<'streams, 'storage, 'scope, RX, CHUNK>,
        ids: Option<crate::quic::path::imp::ids::Ids<'storage, 'scope>>,
        paths: crate::quic::path::imp::observations::Paths<'storage>,
        peers: Option<crate::quic::path::imp::peer_ids::Peers<'storage, 'scope>>,
    ) -> Self {
        Self {
            peers: RefCell::new(peers),
            paths,
            responses: crate::quic::path::imp::responses::Responses::new(),
            ids: RefCell::new(ids),
            pending: RefCell::new(None),
            owners: RefCell::new(Owners { book, streams }),
            delivery: crate::quic::imp::tls::Inbox::new(),
            drain_deadline: Cell::new(None),
        }
    }
    pub(in crate::quic::application) fn retire_all(&self) {
        self.owners.borrow_mut().book.retire_all();
    }
    pub(in crate::quic::application) fn put(
        &self,
        mut packet: Pending<'book, 'streams, N>,
    ) -> Result<(), (Error, Pending<'book, 'streams, N>)> {
        let Ok(mut slot) = self.pending.try_borrow_mut() else {
            return Err((Error::Binding, packet));
        };
        if slot.is_some() {
            return Err((Error::Binding, packet));
        }
        if packet.path.is_none() {
            packet.path = self.paths.current().path;
        }
        if packet.peer_cid.is_none()
            && matches!(packet.sealed, Sealed::Application(_))
            && let (Some(peers), Some(path)) = (self.peers.borrow().as_ref(), packet.path)
        {
            let selected = match peers.choose(path, self.paths.preferred_cid(Some(path))) {
                Ok(cid) => cid,
                Err(_) => return Err((Error::Binding, packet)),
            };
            let cid = selected.cid.as_bytes();
            if packet.sealed.bytes().get(1..1 + cid.len()) != Some(cid) {
                return Err((Error::Binding, packet));
            }
            packet.peer_cid = Some(selected);
        }
        *slot = Some(packet);
        Ok(())
    }
    pub(in crate::quic::application) fn take(&self) -> Result<Pending<'book, 'streams, N>, Error> {
        self.pending
            .try_borrow_mut()
            .map_err(|_| Error::Binding)?
            .take()
            .ok_or(Error::Binding)
    }
    pub(in crate::quic::application) fn settle(
        &self,
        packet: Pending<'book, 'streams, N>,
        accepted_at: Option<u64>,
        ecn: crate::io::Codepoint,
    ) -> Result<(), Error> {
        if accepted_at.is_some()
            && let Some(cid) = packet.peer_cid
        {
            let mut peers = self.peers.borrow_mut();
            let peers = peers.as_mut().ok_or(Error::Binding)?;
            peers
                .accepted(cid, packet.path.ok_or(Error::Binding)?)
                .map_err(|_| Error::Binding)?;
            if let Some(sequence) = packet.retirement {
                peers
                    .retirement_accepted(sequence, packet.sealed.reservation().packet().value)
                    .map_err(|_| Error::Binding)?;
            }
        }
        if let Some(at) = accepted_at {
            self.paths
                .accepted(packet.path, packet.probe, packet.sealed.bytes().len(), at)?;
        }
        if accepted_at.is_some()
            && let Some(cid) = packet.cid
        {
            self.ids
                .try_borrow_mut()
                .map_err(|_| Error::Binding)?
                .as_mut()
                .ok_or(Error::Binding)?
                .accepted(cid, packet.sealed.reservation().packet().value)
                .map_err(|_| Error::Binding)?;
        }
        let mut owners = self.owners.try_borrow_mut().map_err(|_| Error::Binding)?;
        let Owners { book, streams } = &mut *owners;
        settle(packet, book, streams, &self.responses, accepted_at, ecn)
    }
    pub(in crate::quic::application) fn cancel_pending(&self) -> Result<(), Error> {
        let pending = self
            .pending
            .try_borrow_mut()
            .map_err(|_| Error::Binding)?
            .take();
        if let Some(pending) = pending {
            self.settle(pending, None, crate::io::Codepoint::NotEct)?;
        }
        Ok(())
    }
}
impl<const N: usize, const RX: usize, const CHUNK: usize> Drop
    for Exchange<'_, '_, '_, '_, N, RX, CHUNK>
{
    fn drop(&mut self) {
        if let Some(packet) = self.pending.get_mut().take() {
            let Owners { book, streams } = self.owners.get_mut();
            let _ = settle(
                packet,
                book,
                streams,
                &self.responses,
                None,
                crate::io::Codepoint::NotEct,
            );
        }
    }
}

/// The adapter owns this guard across Pending. Cancellation releases both
/// reservations synchronously; an accepted result is settled before any await.
pub(in crate::quic::application) struct InFlight<
    'a,
    'book,
    'streams,
    'storage,
    'scope,
    const N: usize,
    const RX: usize,
    const CHUNK: usize,
> {
    pub(in crate::quic::application) packet: Option<Pending<'book, 'streams, N>>,
    pub(in crate::quic::application) state:
        &'a Exchange<'book, 'streams, 'storage, 'scope, N, RX, CHUNK>,
}
impl<const N: usize, const RX: usize, const CHUNK: usize>
    InFlight<'_, '_, '_, '_, '_, N, RX, CHUNK>
{
    pub(in crate::quic::application) fn bytes(&self) -> &[u8] {
        self.packet
            .as_ref()
            .expect("live publication")
            .sealed
            .bytes()
    }
    pub(in crate::quic::application) fn path(&self) -> Option<crate::io::Address> {
        self.packet.as_ref().and_then(|p| p.path)
    }
    pub(in crate::quic::application) fn complete(
        &mut self,
        accepted_at: Option<u64>,
        ecn: crate::io::Codepoint,
    ) -> Result<(), Error> {
        self.state
            .settle(self.packet.take().ok_or(Error::Binding)?, accepted_at, ecn)
    }
}
impl<const N: usize, const RX: usize, const CHUNK: usize> Drop
    for InFlight<'_, '_, '_, '_, '_, N, RX, CHUNK>
{
    fn drop(&mut self) {
        if let Some(packet) = self.packet.take() {
            let _ = self
                .state
                .settle(packet, None, crate::io::Codepoint::NotEct);
        }
    }
}

pub(in crate::quic::application) fn settle<
    'book,
    const N: usize,
    const RX: usize,
    const CHUNK: usize,
>(
    packet: Pending<'book, '_, N>,
    book: &mut recovery::Publication<'book, '_, N>,
    streams: &mut stream::Publication<'_, '_, '_, RX, CHUNK>,
    responses: &crate::quic::path::imp::responses::Responses,
    accepted_at: Option<u64>,
    ecn: crate::io::Codepoint,
) -> Result<(), Error> {
    let Pending {
        scope: _,
        sealed,
        stream,
        acknowledgment,
        close_deadline: _,
        response,
        cid: _,
        path: _,
        probe: _,
        peer_cid: _,
        retirement: _,
    } = packet;
    let (reservation, long_ack) = sealed.into_parts();
    // Complete both numeric owners in this synchronous turn even if one owner
    // reports an invariant failure. No peer ACK can interleave between them.
    let recovery_result = book.settle(recovery::Completion::from_adapter(
        reservation,
        accepted_at,
        ecn,
    ));
    let stream_result = match stream {
        Some(stream) if accepted_at.is_some() => streams.commit(stream),
        Some(stream) => streams.cancel(stream),
        None => Ok(()),
    };
    recovery_result?;
    stream_result?;
    if accepted_at.is_some()
        && let Some(response) = response
    {
        responses.accepted(response).map_err(|_| Error::Binding)?;
    }
    if accepted_at.is_some()
        && let Some(ack) = acknowledgment.or(long_ack)
    {
        book.acknowledgment_sent(ack)?;
    }
    Ok(())
}

pub(in crate::quic::application) fn cancel_prepared<
    'book,
    'streams,
    'scope,
    const N: usize,
    const RX: usize,
    const CHUNK: usize,
>(
    packet: Pending<'book, 'streams, N>,
    book: &mut recovery::Tx<'book, 'scope, N>,
    streams: &mut stream::Tx<'streams, '_, 'scope, RX, CHUNK>,
) -> Result<(), Error> {
    let (reservation, _) = packet.sealed.into_parts();
    let recovery_result = book.cancel(reservation);
    let stream_result = packet
        .stream
        .map(|stream| streams.cancel_transmission(stream))
        .unwrap_or(Ok(()));
    recovery_result?;
    stream_result?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(in crate::quic::application) fn prepare<
    'book,
    'streams,
    'scope,
    const N: usize,
    const RX: usize,
    const CHUNK: usize,
>(
    keys: &crate::quic::application::imp::keys::KeyOwner<'scope>,
    book: &mut recovery::Tx<'book, 'scope, N>,
    streams: &mut stream::Tx<'streams, '_, 'scope, RX, CHUNK>,
    config: Config<'_>,
    peer: &ConnectionId,
    now: u64,
    responses: &crate::quic::path::imp::responses::Responses,
    ids: &RefCell<Option<crate::quic::path::imp::ids::Ids<'_, '_>>>,
    peers: &RefCell<Option<crate::quic::path::imp::peer_ids::Peers<'_, '_>>>,
    grant: crate::quic::path::imp::observations::Grant,
) -> Result<Option<Pending<'book, 'streams, N>>, Error> {
    let selected = match (peers.borrow().as_ref(), grant.path) {
        (Some(peers), Some(path)) => Some(
            peers
                .choose(path, grant.preferred_cid)
                .map_err(|_| Error::Binding)?,
        ),
        _ => None,
    };
    let selected_id = selected
        .map(|cid| ConnectionId::new(cid.cid.as_bytes()))
        .transpose()?;
    let peer = selected_id.as_ref().unwrap_or(peer);
    let retirement = match (peers.borrow_mut().as_mut(), selected) {
        (Some(peers), Some(cid)) => peers
            .prepare_retirement(cid.cid)
            .map_err(|_| Error::Binding)?,
        _ => None,
    };
    if grant.response_size != 0 {
        let response = responses
            .pending()
            .map_err(|_| Error::Binding)?
            .filter(|r| r.path == grant.path)
            .ok_or(Error::Binding)?;
        let overhead = short_overhead(peer)?;
        let len = grant
            .response_size
            .checked_sub(overhead)
            .filter(|len| *len >= 9 && *len <= N)
            .ok_or(Error::Capacity)?;
        let mut plaintext = Secret::new([0u8; N]);
        let used = packet::encode_frame(
            &Frame::PathResponse {
                data: &response.data,
            },
            &mut plaintext[..],
        )?;
        packet::encode_frame(
            &Frame::Padding { length: len - used },
            &mut plaintext[used..],
        )?;
        let reservation = match book.reserve_application(
            &plaintext[..len],
            keys.generation()?,
            grant.response_size as u64,
            false,
            now,
        ) {
            Ok(r) => r,
            Err(e) if limited(&e) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let scope = reservation.scope();
        return match keys.seal(reservation, peer.bytes(), &plaintext[..len]) {
            Ok(sealed) => Ok(Some(Pending {
                scope,
                sealed: Sealed::Application(sealed),
                stream: None,
                acknowledgment: None,
                close_deadline: None,
                response: Some(response),
                cid: None,
                path: grant.path,
                probe: None,
                peer_cid: selected,
                retirement: None,
            })),
            Err((e, r)) => {
                book.cancel(r)?;
                Err(e.into())
            }
        };
    }
    if let Some(data) = grant.challenge {
        let overhead = short_overhead(peer)?;
        if N < 1200 || overhead + 9 > 1200 {
            return Err(Error::Capacity);
        }
        let mut plaintext = Secret::new([0u8; N]);
        let mut used = 0;
        let offered_cid = ids
            .borrow_mut()
            .as_mut()
            .map(crate::quic::path::imp::ids::Ids::prepare)
            .transpose()
            .map_err(|_| Error::Binding)?
            .flatten();
        let mut cid = None;
        if let Some(advertisement) = offered_cid {
            let len = packet::encode_frame(
                &Frame::NewConnectionId {
                    sequence: advertisement.sequence,
                    retire_prior_to: advertisement.retire_prior_to,
                    id: advertisement.cid.as_bytes(),
                    reset_token: advertisement
                        .token
                        .as_ref()
                        .ok_or(Error::Binding)?
                        .as_bytes(),
                },
                &mut plaintext[..],
            )?;
            if overhead + len + 9 <= grant.probe_size {
                used = len;
                cid = Some(advertisement);
            }
        }
        // Supply a fresh return CID before the peer has to answer this probe.
        used += packet::encode_frame(
            &Frame::PathChallenge { data: &data },
            &mut plaintext[used..],
        )?;
        let response = responses
            .pending()
            .map_err(|_| Error::Binding)?
            .filter(|r| r.path == grant.path);
        if let Some(r) = response {
            used += packet::encode_frame(
                &Frame::PathResponse { data: &r.data },
                &mut plaintext[used..],
            )?;
        }
        if grant.probe_size < overhead + used || grant.probe_size > N {
            return Err(Error::Capacity);
        }
        let len = grant.probe_size - overhead;
        packet::encode_frame(
            &Frame::Padding { length: len - used },
            &mut plaintext[used..],
        )?;
        let reservation = match book.reserve_application(
            &plaintext[..len],
            keys.generation()?,
            grant.probe_size as u64,
            false,
            now,
        ) {
            Ok(r) => r,
            Err(e) if limited(&e) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let scope = reservation.scope();
        return match keys.seal(reservation, peer.bytes(), &plaintext[..len]) {
            Ok(sealed) => Ok(Some(Pending {
                scope,
                sealed: Sealed::Application(sealed),
                stream: None,
                acknowledgment: None,
                close_deadline: None,
                response,
                cid,
                path: grant.path,
                probe: Some(data),
                peer_cid: selected,
                retirement: None,
            })),
            Err((e, r)) => {
                book.cancel(r)?;
                Err(e.into())
            }
        };
    }
    let available = keys.available_levels()?;
    // Initial/Handshake receive and recovery survive until their actual scoped
    // retirement, including ACKs and CRYPTO retransmission after TLS Finished.
    if let Some(ack) = book.pending_ack()
        && ack.level() != Level::OneRtt
        && available[level_index(ack.level())]
    {
        let frame = Frame::Ack {
            delay: ack.encoded_delay(now)?,
            ranges: packet::AckRanges::new(ack.ranges())?,
            ecn: ack.ecn(),
        };
        let plain = wire::PlainPacket::<N>::new(config, peer, ack.level(), frame)?;
        let reservation = match book.reserve(
            ack.level(),
            plain.len() as u64,
            None,
            false,
            plain.padded(),
            false,
            now,
        ) {
            Ok(reservation) => Some(reservation),
            Err(error) if limited(&error) => None,
            Err(error) => return Err(error.into()),
        };
        if let Some(reservation) = reservation {
            let scope = reservation.scope();
            let sealed = match keys.seal_long(ack.level(), plain, reservation, Some(ack)) {
                Ok(sealed) => sealed,
                Err((error, reservation)) => {
                    book.cancel(reservation)?;
                    return Err(error.into());
                }
            };
            return Ok(Some(Pending {
                scope,
                sealed: Sealed::Long(sealed),
                stream: None,
                acknowledgment: None,
                close_deadline: None,
                response: None,
                cid: None,
                path: None,
                probe: None,
                peer_cid: None,
                retirement: None,
            }));
        }
    }
    // Initial publication comes from the retained flight and its actual packet
    // references. The Accepted continuation commits that reference; rejection
    // cancels it. There is no copied initial-send phase in the pending slot.
    if let Some(flight) = book.unsent_control() {
        let mut plaintext = Secret::new([0; N]);
        let data = book.flight_data(flight)?;
        let len = data.bytes().len();
        plaintext[..len].copy_from_slice(data.bytes());
        if let Some(pending) =
            application_control_packet(keys, book, peer, &mut plaintext, len, flight, false, now)?
        {
            return Ok(Some(pending));
        }
    }
    // A retained HANDSHAKE_DONE/ticket must not spend both application PTO
    // credits while an unacknowledged STREAM (especially FIN) is stranded.
    // The second existing credit is available only after actual publication;
    // cancellation restores it. No extra probe allowance or ACK is invented.
    if let Some((flight, probe)) = book.next_retransmit()
        && !(probe
            && book.pending_probe() == Some(Level::OneRtt)
            && book.snapshot().probe_credits == 1
            && streams.prepare::<N>(true)?.is_some())
    {
        if book.is_handshake_done(flight)? {
            let mut plaintext = Secret::new([0; N]);
            let data = book.flight_data(flight)?;
            let len = data.bytes().len();
            plaintext[..len].copy_from_slice(data.bytes());
            if let Some(pending) = application_control_packet(
                keys,
                book,
                peer,
                &mut plaintext,
                len,
                flight,
                probe,
                now,
            )? {
                return Ok(Some(pending));
            }
        } else {
            let flight_data = book.flight_data(flight)?;
            let level = flight_data.level();
            if available[level_index(level)] {
                let frame = Frame::Crypto {
                    offset: flight_data.offset(),
                    data: flight_data.bytes(),
                };
                if level == Level::OneRtt {
                    let mut plaintext = Secret::new([0; N]);
                    let len = packet::encode_frame(&frame, &mut plaintext[..])?;
                    if let Some(pending) = application_control_packet(
                        keys,
                        book,
                        peer,
                        &mut plaintext,
                        len,
                        flight,
                        probe,
                        now,
                    )? {
                        return Ok(Some(pending));
                    }
                } else if let Some(pending) = long_packet(
                    keys,
                    book,
                    config,
                    peer,
                    level,
                    frame,
                    Some(flight),
                    probe,
                    now,
                )? {
                    return Ok(Some(pending));
                }
            }
        }
    }
    if let Some(level) = book.pending_probe()
        && level != Level::OneRtt
        && available[level_index(level)]
        && let Some(pending) = long_packet(
            keys,
            book,
            config,
            peer,
            level,
            Frame::Ping,
            None,
            true,
            now,
        )?
    {
        return Ok(Some(pending));
    }
    let probe = book.pending_probe() == Some(Level::OneRtt);
    let acknowledgment = book
        .pending_ack()
        .filter(|ack| ack.level() == Level::OneRtt);
    let mut plaintext = Secret::new([0; N]);
    let mut len = 0;
    if let Some(ack) = acknowledgment.as_ref() {
        len = packet::encode_frame(
            &Frame::Ack {
                delay: ack.encoded_delay(now)?,
                ranges: packet::AckRanges::new(ack.ranges())?,
                ecn: ack.ecn(),
            },
            &mut plaintext[..],
        )?;
    }
    let cid = ids
        .try_borrow_mut()
        .map_err(|_| Error::Binding)?
        .as_mut()
        .map(|i| i.prepare())
        .transpose()
        .map_err(|_| Error::Binding)?
        .flatten();
    if let Some(c) = &cid {
        len += packet::encode_frame(
            &Frame::NewConnectionId {
                sequence: c.sequence,
                retire_prior_to: c.retire_prior_to,
                id: c.cid.as_bytes(),
                reset_token: c.token.as_ref().ok_or(Error::Binding)?.as_bytes(),
            },
            &mut plaintext[len..],
        )?;
    }
    let response = responses
        .pending()
        .map_err(|_| Error::Binding)?
        .filter(|r| r.path.is_none() || r.path == grant.path);
    if let Some(r) = response {
        len += packet::encode_frame(
            &Frame::PathResponse { data: &r.data },
            &mut plaintext[len..],
        )?;
    }
    if let Some(sequence) = retirement {
        len += packet::encode_frame(
            &Frame::RetireConnectionId { sequence },
            &mut plaintext[len..],
        )?;
    }
    let prepared = streams.prepare::<N>(probe)?;
    let overhead = short_overhead(peer)?;
    let had_prepared = prepared.is_some();
    let prepared = prepared.filter(|prepared| {
        len.checked_add(prepared.bytes().len())
            .and_then(|n| n.checked_add(overhead))
            .is_some_and(|n| n <= N.min(book.path_datagram_limit()))
    });
    if had_prepared && prepared.is_none() && len == 0 && !probe {
        return Err(Error::Capacity);
    }
    if let Some(prepared) = prepared.as_ref() {
        plaintext[len..len + prepared.bytes().len()].copy_from_slice(prepared.bytes());
        len += prepared.bytes().len();
    } else if probe {
        len += packet::encode_frame(&Frame::Ping, &mut plaintext[len..])?;
    }
    if len == 0 {
        return Ok(None);
    }
    if response.is_some() && len + overhead < 1200 {
        let padded = 1200usize.checked_sub(overhead).ok_or(Error::Capacity)?;
        if padded > N {
            return Err(Error::Capacity);
        }
        packet::encode_frame(
            &Frame::Padding {
                length: padded - len,
            },
            &mut plaintext[len..],
        )?;
        len = padded;
    }
    pad_probe(
        &mut plaintext,
        &mut len,
        peer,
        probe,
        book.pending_probe_minimum(),
    )?;
    // Reserve exact recovery bytes before associating a real stream chunk.
    let generation = keys.generation()?;
    let reservation = match book.reserve_application(
        &plaintext[..len],
        generation,
        (len + overhead) as u64,
        probe,
        now,
    ) {
        Ok(reservation) => reservation,
        Err(error) if limited(&error) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let transmission = if let Some(prepared) = prepared.as_ref() {
        match streams.reserve_transmission(prepared, reservation.packet().value) {
            Ok(transmission) => Some(transmission),
            Err(error) => {
                book.cancel(reservation)?;
                return Err(error.into());
            }
        }
    } else {
        None
    };
    let scope = reservation.scope();
    match keys.seal(reservation, peer.bytes(), &plaintext[..len]) {
        Ok(sealed) => Ok(Some(Pending {
            scope,
            sealed: Sealed::Application(sealed),
            stream: transmission,
            acknowledgment,
            close_deadline: None,
            response,
            cid,
            path: grant.path,
            probe: grant.challenge,
            peer_cid: selected,
            retirement,
        })),
        Err((error, reservation)) => {
            let recovery_result = book.cancel(reservation);
            let stream_result = match transmission {
                Some(transmission) => streams.cancel_transmission(transmission),
                None => Ok(()),
            };
            recovery_result?;
            stream_result?;
            Err(error.into())
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(in crate::quic::application) fn long_packet<'book, 'scope, const N: usize>(
    keys: &crate::quic::application::imp::keys::KeyOwner<'scope>,
    book: &mut recovery::Tx<'book, 'scope, N>,
    config: Config<'_>,
    peer: &ConnectionId,
    level: Level,
    frame: Frame<'_>,
    flight: Option<FlightId>,
    probe: bool,
    now: u64,
) -> Result<Option<Pending<'book, 'static, N>>, Error> {
    let ack_eliciting = frame.ack_eliciting();
    let (plain, acknowledgment) = wire::PlainPacket::<N>::with_received_ack(
        config,
        peer,
        level,
        frame,
        book.ack_for_packet(level),
        now,
    )?;
    let reservation = match book.reserve(
        level,
        plain.len() as u64,
        flight,
        ack_eliciting,
        plain.padded(),
        probe,
        now,
    ) {
        Ok(reservation) => reservation,
        Err(error) if limited(&error) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let scope = reservation.scope();
    match keys.seal_long(level, plain, reservation, acknowledgment) {
        Ok(sealed) => Ok(Some(Pending {
            scope,
            sealed: Sealed::Long(sealed),
            stream: None,
            acknowledgment: None,
            close_deadline: None,
            response: None,
            cid: None,
            path: None,
            probe: None,
            peer_cid: None,
            retirement: None,
        })),
        Err((error, reservation)) => {
            book.cancel(reservation)?;
            Err(error.into())
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(in crate::quic::application) fn application_control_packet<
    'book,
    'streams,
    'scope,
    const N: usize,
>(
    keys: &crate::quic::application::imp::keys::KeyOwner<'scope>,
    book: &mut recovery::Tx<'book, 'scope, N>,
    peer: &ConnectionId,
    plaintext: &mut [u8; N],
    mut len: usize,
    flight: FlightId,
    probe: bool,
    now: u64,
) -> Result<Option<Pending<'book, 'streams, N>>, Error> {
    // Repeat actual receive evidence with an independently authorized control
    // flight. A lost standalone ACK must not be starved by retained PTO work.
    let acknowledgment = book.ack_for_packet(Level::OneRtt);
    if len > N {
        return Err(Error::Capacity);
    }
    let overhead = short_overhead(peer)?;
    let acknowledgment = match acknowledgment {
        Some(ack) => {
            let frame = Frame::Ack {
                delay: ack.encoded_delay(now)?,
                ranges: packet::AckRanges::new(ack.ranges())?,
                ecn: ack.ecn(),
            };
            let needed = packet::frame_encoded_len(&frame)?;
            if len
                .checked_add(needed)
                .and_then(|n| n.checked_add(overhead))
                .is_some_and(|n| n <= N.min(book.path_datagram_limit()))
            {
                len += packet::encode_frame(&frame, &mut plaintext[len..])?;
                Some(ack)
            } else {
                None
            }
        }
        None => None,
    };
    pad_probe(
        plaintext,
        &mut len,
        peer,
        probe,
        book.pending_probe_minimum(),
    )?;
    let plaintext = &plaintext[..len];
    let generation = keys.generation()?;
    let bytes = plaintext
        .len()
        .checked_add(overhead)
        .ok_or(Error::Capacity)? as u64;
    let reservation = if book.is_handshake_done(flight)? {
        book.reserve_application_control(plaintext, generation, bytes, flight, probe, now)
    } else {
        book.reserve_application_crypto(plaintext, generation, bytes, flight, probe, now)
    };
    let reservation = match reservation {
        Ok(reservation) => reservation,
        Err(error) if limited(&error) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let scope = reservation.scope();
    match keys.seal(reservation, peer.bytes(), plaintext) {
        Ok(sealed) => Ok(Some(Pending {
            scope,
            sealed: Sealed::Application(sealed),
            stream: None,
            acknowledgment,
            close_deadline: None,
            response: None,
            cid: None,
            path: None,
            probe: None,
            peer_cid: None,
            retirement: None,
        })),
        Err((error, reservation)) => {
            book.cancel(reservation)?;
            Err(error.into())
        }
    }
}

pub(in crate::quic::application) fn short_overhead(peer: &ConnectionId) -> Result<usize, Error> {
    peer.bytes()
        .len()
        .checked_add(1 + 4 + 16)
        .ok_or(Error::Capacity)
}
pub(in crate::quic::application) fn pad_probe<const N: usize>(
    plaintext: &mut [u8; N],
    len: &mut usize,
    peer: &ConnectionId,
    probe: bool,
    minimum: Option<u16>,
) -> Result<(), Error> {
    if probe {
        let minimum = usize::from(minimum.ok_or(Error::Binding)?);
        let required = minimum.saturating_sub(short_overhead(peer)?).max(*len);
        if required
            .checked_add(short_overhead(peer)?)
            .is_none_or(|bytes| bytes > N)
        {
            return Err(Error::Capacity);
        }
        plaintext[*len..required].fill(0);
        *len = required;
    }
    Ok(())
}
pub(in crate::quic::application) fn level_index(level: Level) -> usize {
    match level {
        Level::Initial => 0,
        Level::Handshake => 1,
        Level::OneRtt => 2,
    }
}
pub(in crate::quic::application) fn limited(error: &recovery::Error) -> bool {
    matches!(
        error,
        recovery::Error::CongestionLimited
            | recovery::Error::Accounting(
                AccountingError::Full | AccountingError::AmplificationLimited
            )
    )
}

pub(in crate::quic::application) fn close_packet<'book, 'streams, const N: usize>(
    keys: &mut ApplicationWriteKeys<'_>,
    book: &mut recovery::Tx<'book, '_, N>,
    peer: &ConnectionId,
    application: bool,
    code: u64,
    deadline: u64,
    now: u64,
) -> Result<Option<Pending<'book, 'streams, N>>, Error> {
    let mut plaintext = Secret::new([0; N]);
    let len = packet::encode_frame(
        &Frame::ConnectionClose {
            error_code: code,
            frame_type: if application { None } else { Some(0) },
            reason: &[],
        },
        &mut plaintext[..],
    )?;
    let bytes = len
        .checked_add(short_overhead(peer)?)
        .ok_or(Error::Capacity)?;
    if bytes > N {
        return Err(Error::Capacity);
    }
    let reservation =
        match book.reserve_close(&plaintext[..len], keys.generation(), bytes as u64, now) {
            Ok(reservation) => reservation,
            Err(error) if limited(&error) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
    let scope = reservation.scope();
    match application_wire::seal(keys, reservation, peer.bytes(), &plaintext[..len]) {
        Ok(sealed) => Ok(Some(Pending {
            scope,
            sealed: Sealed::Application(sealed),
            stream: None,
            acknowledgment: None,
            close_deadline: Some(deadline),
            response: None,
            cid: None,
            path: None,
            probe: None,
            peer_cid: None,
            retirement: None,
        })),
        Err((error, reservation)) => {
            book.cancel(reservation)?;
            Err(error.into())
        }
    }
}
