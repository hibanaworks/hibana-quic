//! Ordinary packet publication and the finite, affine close continuation.
//!
//! A pending packet owns both numerical reservations and immutable sealed
//! bytes. Key borrows finish before any endpoint or adapter is awaited.
use super::{CloseKind, Control, Error, keys, protocol as p, startup, timer};
use crate::{
    accounting::AccountingError,
    connection::{self, Clock, Config, ConnectionId, DatagramTx, Outcome,
        application_stream, application_wire::{self, SealedApplicationDatagram},
        recovery, wire},
    crypto::directional::{ApplicationKeyScope, ApplicationWriteKeys},
    flights::FlightId,
    packet::{self, Frame},
    roles::publication_gate,
    tls::Level,
};
use core::{cell::{Cell, RefCell}, future::{Future, poll_fn}, pin::pin, task::Poll};
use hibana::{Endpoint, runtime::resolver::DecisionArm};
use zeroize::Zeroizing;

enum Sealed<'book, const N: usize> {
    Application(SealedApplicationDatagram<'book, N>),
    Long(wire::Datagram<'book, N>),
}
impl<'book, const N: usize> Sealed<'book, N> {
    fn bytes(&self) -> &[u8] {
        match self { Self::Application(packet) => packet.bytes(), Self::Long(packet) => packet.sealed.bytes() }
    }
    fn into_parts(self) -> (recovery::Reservation<'book>, Option<recovery::AckSnapshot<'book>>) {
        match self {
            Self::Application(packet) => (packet.into_reservation(), None),
            Self::Long(wire::Datagram { sealed: _, reservation, acknowledgment }) => (reservation, acknowledgment),
        }
    }
}

#[must_use = "publish or cancel both reservations together"]
struct Pending<'book, 'streams, const N: usize> {
    scope: &'book ApplicationKeyScope,
    sealed: Sealed<'book, N>,
    stream: Option<application_stream::Transmission<'streams>>,
    acknowledgment: Option<recovery::AckSnapshot<'book>>,
    close_deadline: Option<u64>,
    initial_handshake_done: bool,
}

/// The slot transfers the actual packet on the declared Datagram edge. It
/// owns the unique publication facets, so even cancellation before the adapter
/// takes the slot releases both reservations. Borrows are synchronous only.
pub(crate) struct State<'book, 'streams, 'storage, 'scope, const N: usize, const RX: usize, const CHUNK: usize> {
    pending: RefCell<Option<Pending<'book, 'streams, N>>>,
    owners: RefCell<Owners<'book, 'streams, 'storage, 'scope, N, RX, CHUNK>>,
    closing: Cell<bool>,
    drain_deadline: Cell<Option<u64>>,
    completed: Cell<bool>,
}
struct Owners<'book, 'streams, 'storage, 'scope, const N: usize, const RX: usize, const CHUNK: usize> {
    book: recovery::Publication<'book, 'scope, N>,
    streams: application_stream::Publication<'streams, 'storage, 'scope, RX, CHUNK>,
}
impl<'book, 'streams, 'storage, 'scope, const N: usize, const RX: usize, const CHUNK: usize>
    State<'book, 'streams, 'storage, 'scope, N, RX, CHUNK>
{
    pub(crate) const fn new(
        book: recovery::Publication<'book, 'scope, N>,
        streams: application_stream::Publication<'streams, 'storage, 'scope, RX, CHUNK>,
    ) -> Self {
        Self { pending: RefCell::new(None), owners: RefCell::new(Owners { book, streams }),
            closing: Cell::new(false), drain_deadline: Cell::new(None), completed: Cell::new(false) }
    }
    pub(crate) fn close_completed(&self) -> bool { self.completed.get() }
    pub(crate) fn snapshot(&self) -> recovery::Snapshot { self.owners.borrow().book.snapshot() }
    pub(crate) fn retire_all(&self) { self.owners.borrow_mut().book.retire_all(); }
    fn put(&self, packet: Pending<'book, 'streams, N>) -> Result<(), (Error, Pending<'book, 'streams, N>)> {
        let Ok(mut slot) = self.pending.try_borrow_mut() else { return Err((Error::Binding, packet)); };
        if slot.is_some() { return Err((Error::Binding, packet)); }
        *slot = Some(packet);
        Ok(())
    }
    fn take(&self) -> Result<Pending<'book, 'streams, N>, Error> {
        self.pending.try_borrow_mut().map_err(|_| Error::Binding)?.take().ok_or(Error::Binding)
    }
    fn settle(&self, packet: Pending<'book, 'streams, N>, accepted_at: Option<u64>) -> Result<(), Error> {
        let mut owners = self.owners.try_borrow_mut().map_err(|_| Error::Binding)?;
        let Owners { book, streams } = &mut *owners;
        settle(packet, book, streams, accepted_at)
    }
    pub(crate) fn cancel_pending(&self) -> Result<(), Error> {
        let pending = self.pending.try_borrow_mut().map_err(|_| Error::Binding)?.take();
        if let Some(pending) = pending { self.settle(pending, None)?; }
        Ok(())
    }
}
impl<const N: usize, const RX: usize, const CHUNK: usize> Drop for State<'_, '_, '_, '_, N, RX, CHUNK> {
    fn drop(&mut self) {
        if let Some(packet) = self.pending.get_mut().take() {
            let Owners { book, streams } = self.owners.get_mut();
            let _ = settle(packet, book, streams, None);
        }
    }
}

/// The adapter owns this guard across Pending. Cancellation releases both
/// reservations synchronously; an accepted result is settled before any await.
struct InFlight<'a, 'book, 'streams, 'storage, 'scope, const N: usize, const RX: usize, const CHUNK: usize> {
    packet: Option<Pending<'book, 'streams, N>>,
    state: &'a State<'book, 'streams, 'storage, 'scope, N, RX, CHUNK>,
}
impl<const N: usize, const RX: usize, const CHUNK: usize> InFlight<'_, '_, '_, '_, '_, N, RX, CHUNK> {
    fn bytes(&self) -> &[u8] { self.packet.as_ref().expect("live publication").sealed.bytes() }
    fn complete(&mut self, accepted_at: Option<u64>) -> Result<(), Error> {
        self.state.settle(self.packet.take().ok_or(Error::Binding)?, accepted_at)
    }
}
impl<const N: usize, const RX: usize, const CHUNK: usize> Drop for InFlight<'_, '_, '_, '_, '_, N, RX, CHUNK> {
    fn drop(&mut self) {
        if let Some(packet) = self.packet.take() { let _ = self.state.settle(packet, None); }
    }
}

fn settle<'book, const N: usize, const RX: usize, const CHUNK: usize>(
    packet: Pending<'book, '_, N>,
    book: &mut recovery::Publication<'book, '_, N>,
    streams: &mut application_stream::Publication<'_, '_, '_, RX, CHUNK>,
    accepted_at: Option<u64>,
) -> Result<(), Error> {
    let Pending { scope: _, sealed, stream, acknowledgment, close_deadline: _, initial_handshake_done: _ } = packet;
    let (reservation, long_ack) = sealed.into_parts();
    // Complete both numeric owners in this synchronous turn even if one owner
    // reports an invariant failure. No peer ACK can interleave between them.
    let recovery_result = book.settle(recovery::Completion::from_adapter(reservation, accepted_at));
    let stream_result = match stream {
        Some(stream) if accepted_at.is_some() => streams.commit(stream),
        Some(stream) => streams.cancel(stream),
        None => Ok(()),
    };
    recovery_result?;
    stream_result?;
    if accepted_at.is_some() {
        if let Some(ack) = acknowledgment.or(long_ack) { book.acknowledgment_sent(ack)?; }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run<'book, 'streams, 'scope, const N: usize, const RX: usize, const CHUNK: usize>(
    endpoint: &mut Endpoint<'_, { p::TRANSMIT }>,
    control: &Control<'_, 'scope>,
    state: &State<'book, 'streams, '_, 'scope, N, RX, CHUNK>,
    keys: &keys::KeyOwner<'scope>,
    book: &mut recovery::Tx<'book, 'scope, N>,
    streams: &mut application_stream::Tx<'streams, '_, 'scope, RX, CHUNK>,
    mut handshake_done: Option<FlightId>,
    config: Config<'_>,
    peer: &ConnectionId,
    clock: &impl Clock,
) -> Result<(), Error> {
    let mut sequence = 0u64;
    let mut history_floor = book.application_history_floor();
    while !control.stopping() {
        let revision = control.revision();
        while let Some(packet) = book.take_lost_application() { streams.lost(packet.value)?; }
        let floor = book.application_history_floor();
        while history_floor < floor {
            streams.forget_lost(history_floor)?;
            history_floor += 1;
        }
        let pending = prepare(keys, book, streams, handshake_done, config, peer, clock.now())?;
        let Some(pending) = pending else {
            control.wait(4, revision).await;
            continue;
        };
        let sent_handshake_done = pending.initial_handshake_done;
        if let Err((error, pending)) = state.put(pending) {
            cancel_prepared(pending, book, streams)?;
            return Err(error);
        }
        endpoint.send::<p::Datagram>(&sequence).await?;
        let offered = endpoint.offer().await?;
        match offered.label() {
            27 => {
                check(offered.recv::<p::Accepted>().await?, sequence)?;
                if sent_handshake_done { handshake_done = None; }
            },
            28 => {
                check(offered.recv::<p::Rejected>().await?, sequence)?;
                if !control.stopping() { control.fail()?; }
            }
            label => return Err(Error::UnexpectedLabel(label)),
        }
        endpoint.send::<p::Settled>(&sequence).await?;
        sequence = sequence.checked_add(1).ok_or(Error::Binding)?;
        crate::runtime::yield_now().await;
    }
    endpoint.send::<p::StopPublication>(&sequence).await?;
    check(endpoint.recv::<p::PublicationStopped>().await?, sequence)
}

fn cancel_prepared<const N: usize, const RX: usize, const CHUNK: usize>(
    packet: Pending<'_, '_, N>,
    book: &mut recovery::Tx<'_, '_, N>,
    streams: &mut application_stream::Tx<'_, '_, '_, RX, CHUNK>,
) -> Result<(), Error> {
    let (reservation, _) = packet.sealed.into_parts();
    let recovery_result = book.cancel(reservation);
    let stream_result = packet.stream.map(|stream| streams.cancel_transmission(stream)).unwrap_or(Ok(()));
    recovery_result?;
    stream_result?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn prepare<'book, 'streams, 'scope, const N: usize, const RX: usize, const CHUNK: usize>(
    keys: &keys::KeyOwner<'scope>,
    book: &mut recovery::Tx<'book, 'scope, N>,
    streams: &mut application_stream::Tx<'streams, '_, 'scope, RX, CHUNK>,
    handshake_done: Option<FlightId>,
    config: Config<'_>,
    peer: &ConnectionId,
    now: u64,
) -> Result<Option<Pending<'book, 'streams, N>>, Error> {
    let available = keys.available_levels()?;
    // Initial/Handshake receive and recovery survive until their actual scoped
    // retirement, including ACKs and CRYPTO retransmission after TLS Finished.
    if let Some(ack) = book.pending_ack() {
        if ack.level() != Level::OneRtt && available[level_index(ack.level())] {
            let frame = Frame::Ack { delay: 0, ranges: packet::AckRanges::new(ack.ranges())?, ecn: None };
            let plain = wire::PlainPacket::<N>::new(config, peer, ack.level(), frame)?;
            let reservation = match book.reserve(ack.level(), plain.len() as u64, None, false, plain.padded(), false, now) {
                Ok(reservation) => Some(reservation),
                Err(error) if limited(&error) => None,
                Err(error) => return Err(error.into()),
            };
            if let Some(reservation) = reservation {
                let scope = reservation.scope();
                let sealed = match keys.seal_long(ack.level(), plain, reservation, Some(ack)) {
                    Ok(sealed) => sealed,
                    Err((error, reservation)) => { book.cancel(reservation)?; return Err(error.into()); }
                };
                return Ok(Some(Pending { scope, sealed: Sealed::Long(sealed), stream: None, acknowledgment: None, close_deadline: None, initial_handshake_done: false }));
            }
        }
    }
    // A newly appended control flight has never been sent and is neither
    // lost nor PTO eligible yet. Keep its actual FlightId until acceptance.
    if let Some(flight) = handshake_done {
        let mut plaintext = Zeroizing::new([0; N]);
        let len = packet::encode_frame(&Frame::HandshakeDone, &mut plaintext[..])?;
        if let Some(mut pending) = application_control_packet(keys, book, peer, &plaintext[..len], flight, false, now)? {
            pending.initial_handshake_done = true;
            return Ok(Some(pending));
        }
    }
    if let Some((flight, probe)) = book.next_retransmit() {
        if book.is_handshake_done(flight)? {
            let mut plaintext = Zeroizing::new([0; N]);
            let mut len = packet::encode_frame(&Frame::HandshakeDone, &mut plaintext[..])?;
            pad_probe(&mut plaintext, &mut len, peer, probe, book.pending_probe_minimum())?;
            if let Some(pending) = application_control_packet(keys, book, peer, &plaintext[..len], flight, probe, now)? {
                return Ok(Some(pending));
            }
        } else {
            let flight_data = book.flight_data(flight)?;
            let level = flight_data.level();
            if available[level_index(level)] {
                let frame = Frame::Crypto { offset: flight_data.offset(), data: flight_data.bytes() };
                if let Some(pending) = long_packet(keys, book, config, peer, level, frame, Some(flight), probe, now)? {
                    return Ok(Some(pending));
                }
            }
        }
    }
    if let Some(level) = book.pending_probe() {
        if level != Level::OneRtt && available[level_index(level)] {
            if let Some(pending) = long_packet(keys, book, config, peer, level, Frame::Ping, None, true, now)? {
                return Ok(Some(pending));
            }
        }
    }
    let probe = book.pending_probe() == Some(Level::OneRtt);
    let acknowledgment = book.pending_ack().filter(|ack| ack.level() == Level::OneRtt);
    let mut plaintext = Zeroizing::new([0; N]);
    let mut len = 0;
    if let Some(ack) = acknowledgment.as_ref() {
        len = packet::encode_frame(&Frame::Ack { delay: 0, ranges: packet::AckRanges::new(ack.ranges())?, ecn: None }, &mut plaintext[..])?;
    }
    let prepared = streams.prepare::<N>(probe)?;
    let overhead = short_overhead(peer)?;
    let had_prepared = prepared.is_some();
    let prepared = prepared.filter(|prepared| len.checked_add(prepared.bytes().len()).and_then(|n| n.checked_add(overhead)).is_some_and(|n| n <= N));
    if had_prepared && prepared.is_none() && len == 0 && !probe { return Err(Error::Capacity); }
    if let Some(prepared) = prepared.as_ref() {
        plaintext[len..len + prepared.bytes().len()].copy_from_slice(prepared.bytes());
        len += prepared.bytes().len();
    } else if probe {
        len += packet::encode_frame(&Frame::Ping, &mut plaintext[len..])?;
    }
    if len == 0 { return Ok(None); }
    pad_probe(&mut plaintext, &mut len, peer, probe, book.pending_probe_minimum())?;
    // Reserve exact recovery bytes before associating a real stream chunk.
    let generation = keys.generation()?;
    let reservation = match book.reserve_application(&plaintext[..len], generation, (len + overhead) as u64, probe, now) {
        Ok(reservation) => reservation,
        Err(error) if limited(&error) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let transmission = if let Some(prepared) = prepared.as_ref() {
        match streams.reserve_transmission(prepared, reservation.packet().value) {
            Ok(transmission) => Some(transmission),
            Err(error) => { book.cancel(reservation)?; return Err(error.into()); }
        }
    } else { None };
    let scope = reservation.scope();
    match keys.seal(reservation, peer.bytes(), &plaintext[..len]) {
        Ok(sealed) => Ok(Some(Pending { scope, sealed: Sealed::Application(sealed), stream: transmission, acknowledgment, close_deadline: None, initial_handshake_done: false })),
        Err((error, reservation)) => {
            let recovery_result = book.cancel(reservation);
            let stream_result = match transmission {
                Some(transmission) => streams.cancel_transmission(transmission),
                None => Ok(()),
            };
            recovery_result?; stream_result?; Err(error.into())
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn long_packet<'book, 'scope, const N: usize>(
    keys: &keys::KeyOwner<'scope>, book: &mut recovery::Tx<'book, 'scope, N>,
    config: Config<'_>, peer: &ConnectionId, level: Level, frame: Frame<'_>,
    flight: Option<FlightId>, probe: bool, now: u64,
) -> Result<Option<Pending<'book, 'static, N>>, Error> {
    let ack_eliciting = frame.ack_eliciting();
    let plain = wire::PlainPacket::<N>::new(config, peer, level, frame)?;
    let reservation = match book.reserve(level, plain.len() as u64, flight, ack_eliciting, plain.padded(), probe, now) {
        Ok(reservation) => reservation,
        Err(error) if limited(&error) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let scope = reservation.scope();
    match keys.seal_long(level, plain, reservation, None) {
        Ok(sealed) => Ok(Some(Pending { scope, sealed: Sealed::Long(sealed), stream: None, acknowledgment: None, close_deadline: None, initial_handshake_done: false })),
        Err((error, reservation)) => { book.cancel(reservation)?; Err(error.into()) }
    }
}

#[allow(clippy::too_many_arguments)]
fn application_control_packet<'book, 'streams, 'scope, const N: usize>(
    keys: &keys::KeyOwner<'scope>, book: &mut recovery::Tx<'book, 'scope, N>, peer: &ConnectionId,
    plaintext: &[u8], flight: FlightId, probe: bool, now: u64,
) -> Result<Option<Pending<'book, 'streams, N>>, Error> {
    let generation = keys.generation()?;
    let bytes = plaintext.len().checked_add(short_overhead(peer)?).ok_or(Error::Capacity)? as u64;
    let reservation = book.reserve_application_control(plaintext, generation, bytes, flight, probe, now);
    let reservation = match reservation {
        Ok(reservation) => reservation,
        Err(error) if limited(&error) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let scope = reservation.scope();
    match keys.seal(reservation, peer.bytes(), plaintext) {
        Ok(sealed) => Ok(Some(Pending { scope, sealed: Sealed::Application(sealed), stream: None, acknowledgment: None, close_deadline: None, initial_handshake_done: false })),
        Err((error, reservation)) => { book.cancel(reservation)?; Err(error.into()) }
    }
}

fn short_overhead(peer: &ConnectionId) -> Result<usize, Error> {
    peer.bytes().len().checked_add(1 + 4 + 16).ok_or(Error::Capacity)
}
fn pad_probe<const N: usize>(plaintext: &mut [u8; N], len: &mut usize, peer: &ConnectionId, probe: bool, minimum: Option<u16>) -> Result<(), Error> {
    if probe {
        let minimum = usize::from(minimum.ok_or(Error::Binding)?);
        let required = minimum.saturating_sub(short_overhead(peer)?).max(*len);
        if required.checked_add(short_overhead(peer)?).is_none_or(|bytes| bytes > N) { return Err(Error::Capacity); }
        plaintext[*len..required].fill(0);
        *len = required;
    }
    Ok(())
}
fn level_index(level: Level) -> usize { match level { Level::Initial => 0, Level::Handshake => 1, Level::OneRtt => 2 } }
fn limited(error: &recovery::Error) -> bool {
    matches!(error, recovery::Error::CongestionLimited | recovery::Error::Accounting(AccountingError::Full | AccountingError::AmplificationLimited))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn publish<'book, 'streams, 'scope, const N: usize, const RX: usize, const CHUNK: usize>(
    endpoint: &mut Endpoint<'_, { p::ADAPTER }>, control: &Control<'_, 'scope>,
    state: &State<'book, 'streams, '_, 'scope, N, RX, CHUNK>, issuer: &mut publication_gate::Issuer<'_, 'scope>,
    outcome: &Outcome,
    socket: &mut impl DatagramTx,
) -> Result<(), Error> {
    let mut sequence = 0u64;
    loop {
        let offered = endpoint.offer().await?;
        match offered.label() {
            26 => {
                check(offered.recv::<p::Datagram>().await?, sequence)?;
                let packet = state.take()?;
                if packet.close_deadline.is_some() {
                    state.settle(packet, None)?;
                    return Err(Error::Binding);
                }
                let accepted_at = {
                    let scope = packet.scope;
                    let mut pending = InFlight { packet: Some(packet), state };
                    if !core::ptr::eq(scope, issuer.scope()) {
                        pending.complete(None)?;
                        return Err(Error::Binding);
                    }
                    let result = match issuer.begin() {
                        Ok(permit) => permit.submit(socket.send(pending.bytes())).await,
                        Err(error) => Err(error),
                    };
                    let accepted_at = match result { Ok(Ok(at)) => Some(at), _ => None };
                    pending.complete(accepted_at)?;
                    accepted_at
                };
                control.changed()?;
                outcome.set(accepted_at.is_some())?;
                match outcome.resolver::<{ p::SUBMISSION_RESULT }>().decide().map_err(connection::Error::from)? {
                    DecisionArm::Left => endpoint.send::<p::Accepted>(&sequence).await?,
                    DecisionArm::Right => endpoint.send::<p::Rejected>(&sequence).await?,
                }
                check(endpoint.recv::<p::Settled>().await?, sequence)?;
                outcome.clear();
                sequence = sequence.checked_add(1).ok_or(Error::Binding)?;
            }
            30 => {
                check(offered.recv::<p::StopPublication>().await?, sequence)?;
                if state.pending.borrow().is_some() { return Err(Error::Binding); }
                endpoint.send::<p::PublicationStopped>(&sequence).await?;
                return Ok(());
            }
            label => return Err(Error::UnexpectedLabel(label)),
        }
        crate::runtime::yield_now().await;
    }
}

/// Entered only by the post-parallel global continuation. The affine ordinary
/// retirement proof frees bounded history without resetting any burned PN;
/// actual key-role retirement releases the sole write key for close sealing.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn close<'book, 'streams, 'owner, 'scope, const N: usize, const RX: usize, const CHUNK: usize>(
    endpoint: &mut Endpoint<'_, { p::TRANSMIT }>,
    control: &Control<'_, 'scope>,
    state: &State<'book, 'streams, '_, 'scope, N, RX, CHUNK>,
    owner: &'owner keys::KeyOwner<'scope>,
    closing: startup::Closing<'owner, 'scope>,
    book: &mut recovery::Tx<'book, 'scope, N>,
    peer: &ConnectionId,
    clock: &impl Clock,
) -> Result<(), Error> {
    let startup::Closing { ordinary: retired, keys: quiesced, permission } = closing;
    if !core::ptr::eq(owner.scope(), retired.scope())
        || !core::ptr::eq(owner.scope(), permission.scope()) || !control.stopping()
        || state.closing.get() || state.pending.borrow().is_some()
    { return Err(Error::Binding); }
    let kind = permission.kind();
    let pto = book.pto_duration_us()?.max(1);
    let started_at = clock.now();
    let deadline = started_at.checked_add(pto.checked_mul(3).ok_or(Error::Capacity)?).ok_or(Error::Capacity)?;
    book.discard_for_close(retired)?;
    let mut keys = owner.take_closing(quiesced)?;
    state.closing.set(true);
    state.drain_deadline.set(Some(deadline));
    let mut sequence = 0u64;
    let mut close_accepted = matches!(kind, CloseKind::Peer { .. });
    match kind {
        CloseKind::Peer { .. } => {
            // Peer-initiated draining publishes no packets.
            endpoint.send::<p::Drain>(&sequence).await?;
            check(endpoint.recv::<p::Drained>().await?, sequence)?;
        }
        CloseKind::Local { application, code } => {
            for attempt in 0u64..3 {
                let at = started_at.checked_add(pto.checked_mul(attempt).ok_or(Error::Capacity)?).ok_or(Error::Capacity)?;
                clock.wait_until(at).await;
                if clock.now() >= deadline { break; }
                let Some(packet) = close_packet(&mut keys, book, peer, application, code, deadline, clock.now())? else { break; };
                if let Err((error, packet)) = state.put(packet) {
                    book.cancel(packet.sealed.into_parts().0)?;
                    return Err(error);
                }
                endpoint.send::<p::CloseDatagram>(&sequence).await?;
                let offered = endpoint.offer().await?;
                match offered.label() {
                    33 => {
                        check(offered.recv::<p::CloseAccepted>().await?, sequence)?;
                        close_accepted = true;
                    }
                    34 => check(offered.recv::<p::CloseRejected>().await?, sequence)?,
                    label => return Err(Error::UnexpectedLabel(label)),
                }
                endpoint.send::<p::CloseSettled>(&sequence).await?;
                sequence = sequence.checked_add(1).ok_or(Error::Binding)?;
            }
            endpoint.send::<p::CloseFlightDone>(&sequence).await?;
            check(endpoint.recv::<p::CloseFlightSettled>().await?, sequence)?;
        }
    }
    keys.discard();
    endpoint.send::<p::Retire>(&sequence).await?;
    check(endpoint.recv::<p::Retired>().await?, sequence)?;
    if !close_accepted { return Err(Error::Incomplete); }
    state.completed.set(true);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn close_packet<'book, 'streams, const N: usize>(
    keys: &mut ApplicationWriteKeys<'_>, book: &mut recovery::Tx<'book, '_, N>,
    peer: &ConnectionId, application: bool, code: u64, deadline: u64, now: u64,
) -> Result<Option<Pending<'book, 'streams, N>>, Error> {
    let mut plaintext = Zeroizing::new([0; N]);
    let len = packet::encode_frame(&Frame::ConnectionClose {
        error_code: code, frame_type: if application { None } else { Some(0) }, reason: &[],
    }, &mut plaintext[..])?;
    let bytes = len.checked_add(short_overhead(peer)?).ok_or(Error::Capacity)?;
    if bytes > N { return Err(Error::Capacity); }
    let reservation = match book.reserve_close(&plaintext[..len], keys.generation(), bytes as u64, now) {
        Ok(reservation) => reservation,
        Err(error) if limited(&error) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let scope = reservation.scope();
    match application_wire::seal(keys, reservation, peer.bytes(), &plaintext[..len]) {
        Ok(sealed) => Ok(Some(Pending { scope, sealed: Sealed::Application(sealed), stream: None,
            acknowledgment: None, close_deadline: Some(deadline), initial_handshake_done: false })),
        Err((error, reservation)) => { book.cancel(reservation)?; Err(error.into()) }
    }
}

/// This continuation is projected after every ordinary role has retired. A
/// closing packet has no ordinary permit: its private construction required
/// both affine retirement objects, and its UDP attempt is deadline bounded.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn publish_close<'book, 'streams, 'scope, const N: usize, const RX: usize, const CHUNK: usize>(
    endpoint: &mut Endpoint<'_, { p::ADAPTER }>,
    state: &State<'book, 'streams, '_, 'scope, N, RX, CHUNK>, outcome: &Outcome,
    socket: &mut impl DatagramTx, clock: &impl Clock,
) -> Result<(), Error> {
    let mut sequence = 0u64;
    loop {
        let offered = endpoint.offer().await?;
        match offered.label() {
            32 => {
                check(offered.recv::<p::CloseDatagram>().await?, sequence)?;
                let packet = state.take()?;
                let Some(deadline) = packet.close_deadline else {
                    state.settle(packet, None)?;
                    return Err(Error::Binding);
                };
                if !state.closing.get() || packet.stream.is_some() || packet.acknowledgment.is_some() {
                    state.settle(packet, None)?;
                    return Err(Error::Binding);
                }
                let accepted_at = {
                    let mut pending = InFlight { packet: Some(packet), state };
                    let accepted_at = {
                        let mut send = pin!(socket.send(pending.bytes()));
                        let mut timeout = pin!(clock.wait_until(deadline));
                        poll_fn(|cx| {
                            // An observed actual completion wins over deadline
                            // readiness from the same poll turn.
                            match send.as_mut().poll(cx) {
                                Poll::Ready(Ok(at)) => return Poll::Ready(Some(at)),
                                Poll::Ready(Err(_)) => return Poll::Ready(None),
                                Poll::Pending => {}
                            }
                            timeout.as_mut().poll(cx).map(|()| None)
                        }).await
                    };
                    pending.complete(accepted_at)?;
                    accepted_at
                };
                outcome.set(accepted_at.is_some())?;
                match outcome.resolver::<{ p::SUBMISSION_RESULT }>().decide().map_err(connection::Error::from)? {
                    DecisionArm::Left => endpoint.send::<p::CloseAccepted>(&sequence).await?,
                    DecisionArm::Right => endpoint.send::<p::CloseRejected>(&sequence).await?,
                }
                check(endpoint.recv::<p::CloseSettled>().await?, sequence)?;
                outcome.clear();
                sequence = sequence.checked_add(1).ok_or(Error::Binding)?;
            }
            36 => {
                check(offered.recv::<p::CloseFlightDone>().await?, sequence)?;
                let deadline = state.drain_deadline.get().ok_or(Error::Binding)?;
                clock.wait_until(deadline).await;
                endpoint.send::<p::CloseFlightSettled>(&sequence).await?;
                break;
            }
            38 => {
                check(offered.recv::<p::Drain>().await?, sequence)?;
                if !state.closing.get() { return Err(Error::Binding); }
                let deadline = state.drain_deadline.get().ok_or(Error::Binding)?;
                clock.wait_until(deadline).await;
                endpoint.send::<p::Drained>(&sequence).await?;
                break;
            }
            label => return Err(Error::UnexpectedLabel(label)),
        }
    }
    check(endpoint.recv::<p::Retire>().await?, sequence)?;
    if state.pending.borrow().is_some() { return Err(Error::Binding); }
    state.retire_all();
    endpoint.send::<p::Retired>(&sequence).await?;
    Ok(())
}

fn check(actual: u64, expected: u64) -> Result<(), Error> {
    if actual == expected { Ok(()) } else { Err(Error::Binding) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        connection::{IoError, Side},
        crypto::{CipherSuite, IntegrityBudget, KeyKind, PacketKey},
        roles::packet_authority::{Arena, ScopedArena},
        streams::{Limits, PacketReference, Role, SendChunk, StreamSlot},
    };
    use core::task::{Context, Waker};

    const PACKET: usize = 256;
    const CHUNK: usize = 32;

    fn key(secret: u8) -> PacketKey {
        PacketKey::from_secret(CipherSuite::Aes128GcmSha256, KeyKind::OneRtt,
            &[secret; 32]).unwrap()
    }

    // Use the actual one-shot installation, packet arena binding and stream
    // queue. No authentication, accepted-ACK or key-update receipt is forged.
    macro_rules! fixture {
        ($book:ident, $write:ident, $streams:ident, $scope:ident) => {
            let mut key_scope = ApplicationKeyScope::new(146);
            let mut installation = key_scope.claim().unwrap();
            let mut arena_storage = Arena::<8, 32>::new(146);
            let arena = ScopedArena::new(&mut arena_storage,
                installation.take_packet_authority().unwrap()).unwrap();
            let (_read, mut $write) = installation.install(key(1), key(2)).unwrap();
            let $scope = $write.scope();
            let mut $book = recovery::Recovery::<PACKET>::new(
                arena.claim_recovery().unwrap(), Side::Client, 333_000, 1200).unwrap();
            let mut slots = [StreamSlot::<CHUNK>::EMPTY];
            let mut chunks = [SendChunk::<CHUNK>::EMPTY];
            // Exactly one reference makes any leaked Reserved entry observable.
            let mut references = [PacketReference::EMPTY];
            let peer = Limits { max_data: 1024, max_streams_bidi: 1,
                stream_data_bidi_local: 1024, stream_data_bidi_remote: 1024,
                ..Limits::ZERO };
            let local = Limits { max_data: 1024, stream_data_bidi_local: 1024,
                stream_data_bidi_remote: 1024, ..Limits::ZERO };
            let mut $streams = application_stream::StreamNumbers::new(
                $scope, Role::Client, peer, local, &mut slots, &mut chunks,
                &mut references).unwrap();
        };
    }

    fn stream_packet<'book, 'streams>(
        book: &mut recovery::Tx<'book, '_, PACKET>,
        streams: &mut application_stream::Tx<'streams, '_, '_, CHUNK, CHUNK>,
        keys: &mut ApplicationWriteKeys<'_>,
    ) -> Pending<'book, 'streams, PACKET> {
        let prepared = streams.prepare::<PACKET>(false).unwrap().expect("queued STREAM");
        let reservation = book.reserve_application(prepared.bytes(), keys.generation(),
            (prepared.bytes().len() + 21) as u64, false, 0).unwrap();
        let scope = reservation.scope();
        let stream = streams.reserve_transmission(&prepared, reservation.packet().value).unwrap();
        let sealed = match application_wire::seal(keys, reservation, &[], prepared.bytes()) {
            Ok(sealed) => sealed,
            Err(_) => panic!("actual reserved STREAM must seal"),
        };
        Pending { scope, sealed: Sealed::Application(sealed), stream: Some(stream),
            acknowledgment: None, close_deadline: None, initial_handshake_done: false }
    }

    fn assert_cancelled(snapshot: recovery::Snapshot, next_packet: u64) {
        assert_eq!(snapshot.pending_publications, [0; 3]);
        assert_eq!(snapshot.reserved_bytes, 0);
        assert_eq!(snapshot.reserved_in_flight, 0);
        assert_eq!(snapshot.accepted_bytes, 0);
        assert_eq!(snapshot.bytes_in_flight, 0);
        assert_eq!(snapshot.next_packet_number[2], Some(next_packet));
    }

    #[test]
    fn dropping_staged_state_cancels_recovery_and_the_only_stream_reference() {
        fixture!(book, write, numbers, scope);
        let _ = scope;
        let application_stream::Facets { mut app, mut tx, publication, .. } = numbers.split();
        let stream = app.open_local().unwrap();
        app.enqueue(stream, b"GET /\r\n", true).unwrap();
        let (mut book_tx, _, _, book_publication, mut retirement) = book.split().unwrap();
        let guard = actor_test_allocator::NoAlloc::start();
        let state = State::new(book_publication, publication);
        let packet = stream_packet(&mut book_tx, &mut tx, &mut write);
        assert!(state.put(packet).is_ok());
        assert_eq!(book_tx.snapshot().pending_publications, [0, 0, 1]);
        assert!(tx.prepare::<PACKET>(false).unwrap().is_none());
        assert_eq!(write.last_sealed_packet_number(), Some(0));

        // No publisher has taken the slot. Dropping the whole continuation
        // must nevertheless cancel the actual Recovery and SendQueue entries.
        drop(state);
        assert_cancelled(book_tx.snapshot(), 1);
        assert!(!app.send_complete(stream).unwrap());
        assert_eq!(app.queued_chunks().unwrap(), 1);
        let retry = stream_packet(&mut book_tx, &mut tx, &mut write);
        assert_eq!(retry.stream.as_ref().unwrap().packet_number(), 1);
        cancel_prepared(retry, &mut book_tx, &mut tx).unwrap();
        assert_cancelled(book_tx.snapshot(), 2);
        retirement.disarm();
        guard.finish();
    }

    struct Dropped<'a>(&'a Cell<bool>);
    impl Drop for Dropped<'_> { fn drop(&mut self) { self.0.set(true); } }
    struct PendingSocket<'a> { polls: &'a Cell<usize>, dropped: &'a Cell<bool> }
    impl DatagramTx for PendingSocket<'_> {
        fn send(&mut self, bytes: &[u8]) -> impl Future<Output = Result<u64, IoError>> {
            async move {
                let _dropped = Dropped(self.dropped);
                poll_fn(|_| {
                    assert!(!bytes.is_empty());
                    self.polls.set(self.polls.get() + 1);
                    Poll::<Result<u64, IoError>>::Pending
                }).await
            }
        }
    }

    #[test]
    fn dropping_actual_pending_udp_future_cancels_both_owned_reservations() {
        fixture!(book, write, numbers, scope);
        let _ = scope;
        let application_stream::Facets { mut app, mut tx, publication, .. } = numbers.split();
        let stream = app.open_local().unwrap();
        app.enqueue(stream, b"GET /pending\r\n", true).unwrap();
        let (mut book_tx, _, _, book_publication, mut retirement) = book.split().unwrap();
        let guard = actor_test_allocator::NoAlloc::start();
        let state = State::new(book_publication, publication);
        let packet = stream_packet(&mut book_tx, &mut tx, &mut write);
        assert!(state.put(packet).is_ok());
        let polls = Cell::new(0);
        let dropped = Cell::new(false);
        let mut socket = PendingSocket { polls: &polls, dropped: &dropped };
        {
            let mut send = pin!(async {
                let mut pending = InFlight { packet: Some(state.take().unwrap()), state: &state };
                let accepted_at = socket.send(pending.bytes()).await.unwrap();
                pending.complete(Some(accepted_at)).unwrap();
            });
            let mut context = Context::from_waker(Waker::noop());
            assert!(send.as_mut().poll(&mut context).is_pending());
            assert_eq!(polls.get(), 1);
            assert!(!dropped.get());
            assert!(state.pending.borrow().is_none());
            assert_eq!(book_tx.snapshot().pending_publications, [0, 0, 1]);
            assert!(tx.prepare::<PACKET>(false).unwrap().is_none());
            // Leaving this scope drops the actual socket future and InFlight.
        }
        assert!(dropped.get());
        assert_eq!(polls.get(), 1);
        assert_cancelled(book_tx.snapshot(), 1);
        assert!(!app.send_complete(stream).unwrap());
        let retry = stream_packet(&mut book_tx, &mut tx, &mut write);
        assert_eq!(retry.stream.as_ref().unwrap().packet_number(), 1);
        state.settle(retry, None).unwrap();
        assert_cancelled(book_tx.snapshot(), 2);
        drop(state);
        retirement.disarm();
        guard.finish();
    }

    struct AcceptedSocket { at: u64 }
    impl DatagramTx for AcceptedSocket {
        fn send(&mut self, bytes: &[u8]) -> impl Future<Output = Result<u64, IoError>> {
            assert!(!bytes.is_empty());
            core::future::ready(Ok(self.at))
        }
    }

    #[test]
    fn full_ordinary_ledger_close_preserves_accepted_and_cancelled_packet_number_burns() {
        fixture!(book, write, numbers, scope);
        let application_stream::Facets { publication, .. } = numbers.split();
        let (mut book_tx, _, _, book_publication, mut retirement) = book.split().unwrap();
        let guard = actor_test_allocator::NoAlloc::start();
        let state = State::new(book_publication, publication);
        // Burn numbers before filling the 64-record ordinary ledger.
        for expected in 0..3 {
            let reservation = book_tx.reserve_application(&[1], write.generation(), 22, false, 0).unwrap();
            assert_eq!(reservation.packet().value, expected);
            book_tx.cancel(reservation).unwrap();
        }
        let mut socket = AcceptedSocket { at: 10 };
        for offset in 0..recovery::LEDGER_CAPACITY as u64 {
            socket.at = 10 + offset;
            let reservation = book_tx.reserve_application(&[1], write.generation(), 22, false, socket.at).unwrap();
            assert_eq!(reservation.packet().value, 3 + offset);
            let sealed = match application_wire::seal(&mut write, reservation, &[], &[1]) {
                Ok(sealed) => sealed,
                Err(_) => panic!("real reserved PING must seal"),
            };
            let packet = Pending { scope, sealed: Sealed::Application(sealed), stream: None,
                acknowledgment: None, close_deadline: None, initial_handshake_done: false };
            let mut pending = InFlight { packet: Some(packet), state: &state };
            let accepted_at = {
                let mut send = pin!(socket.send(pending.bytes()));
                let mut context = Context::from_waker(Waker::noop());
                match send.as_mut().poll(&mut context) {
                    Poll::Ready(Ok(at)) => at,
                    _ => panic!("fixture adapter must accept immediately"),
                }
            };
            pending.complete(Some(accepted_at)).unwrap();
        }
        let full = book_tx.snapshot();
        assert_eq!(full.retained_packets, recovery::LEDGER_CAPACITY);
        assert_eq!(full.pending_publications, [0; 3]);
        assert_eq!(full.bytes_in_flight, 22 * recovery::LEDGER_CAPACITY as u64);
        assert_eq!(full.next_packet_number[2], Some(67));
        assert!(matches!(book_tx.reserve_application(&[1], write.generation(), 22, false, 80),
            Err(recovery::Error::Accounting(AccountingError::Full))));

        // Only this module's test can construct the private global-join token.
        // Production obtains it after all projected ordinary roles retire.
        book_tx.discard_for_close(super::super::OrdinaryRetired { scope }).unwrap();
        assert_eq!(book_tx.snapshot().retained_packets, 0);
        assert_eq!(book_tx.snapshot().next_packet_number[2], Some(67));
        let mut stream_plaintext = [0; 32];
        let stream_len = packet::encode_frame(&Frame::Stream { id: 0, offset: 0,
            fin: false, data: b"x" }, &mut stream_plaintext).unwrap();
        assert!(matches!(book_tx.reserve_application(&stream_plaintext[..stream_len],
            write.generation(), (21 + stream_len) as u64, false, 80),
            Err(recovery::Error::Accounting(AccountingError::Retired))));
        let peer = ConnectionId::new(&[]).unwrap();
        let close = close_packet(&mut write, &mut book_tx, &peer, true, 0, 1000, 80)
            .unwrap().expect("full ordinary ledger must permit close after retirement");
        assert_eq!(write.last_sealed_packet_number(), Some(67));
        assert_eq!(book_tx.snapshot().next_packet_number[2], Some(68));

        // Authenticate the actual protected close bytes with installed peer keys.
        let mut peer_scope = ApplicationKeyScope::new(147);
        let (mut peer_read, _peer_write) = peer_scope.install(key(2), key(1)).unwrap();
        let opened = application_wire::open::<PACKET>(&mut peer_read,
            &mut IntegrityBudget::new(), close.sealed.bytes(), &[], Some(66), 80, 1000).unwrap();
        assert_eq!(opened.packet_number(), 67);
        let frame = packet::FrameIter::new(opened.plaintext(), packet::EncryptionLevel::OneRtt,
            packet::ParseLimits::default()).unwrap().next().unwrap().unwrap();
        assert!(matches!(frame, Frame::ConnectionClose { error_code: 0, frame_type: None, reason } if reason.is_empty()));
        state.settle(close, None).unwrap();
        assert_eq!(book_tx.snapshot().pending_publications, [0; 3]);
        assert_eq!(book_tx.snapshot().next_packet_number[2], Some(68));
        let second = close_packet(&mut write, &mut book_tx, &peer, true, 0, 1000, 81)
            .unwrap().expect("cancelled close burns its number");
        assert_eq!(write.last_sealed_packet_number(), Some(68));
        state.settle(second, Some(81)).unwrap();
        assert_eq!(book_tx.snapshot().next_packet_number[2], Some(69));
        drop(state);
        retirement.disarm();
        guard.finish();
    }
}
