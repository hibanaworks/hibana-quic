//! Ordinary packet publication and the finite, affine close continuation.
//!
//! A pending packet owns both numerical reservations and immutable sealed
//! bytes. Key borrows finish before any endpoint or adapter is awaited.
use crate::quic::ecn::global as ep;
use crate::quic::ecn::local as ecn;
use crate::quic::path::global as pp;
use hibana::g::Message;

use super::{CloseKind, Control, Error, global as p, keys, ownership};
use crate::crypto::directional::ApplicationKeyScope;
use crate::crypto::directional::ApplicationWriteKeys;
use crate::quic;
use crate::quic::Clock;
use crate::quic::Config;
use crate::quic::ConnectionId;
use crate::quic::DatagramRx;
use crate::quic::DatagramTx;
use crate::quic::Outcome;
use crate::quic::application::imp::stream;
use crate::quic::imp::application_wire;
use crate::quic::imp::application_wire::SealedApplicationDatagram;
use crate::quic::imp::kernel::accounting::AccountingError;
use crate::quic::imp::kernel::flights::FlightId;
use crate::quic::imp::kernel::packet;
use crate::quic::imp::kernel::packet::Frame;
use crate::quic::imp::publication_gate;
use crate::quic::imp::recovery;
use crate::quic::wire;
use core::cell::{Cell, RefCell};
#[cfg(test)]
use core::{
    future::{Future, poll_fn},
    pin::pin,
    task::Poll,
};
use hibana::{Endpoint, runtime::resolver::DecisionArm};
use hibana_tls::endpoint::Level;
use hibana_tls::secret::Secret;

// Both variants own bounded packets; this no_alloc path cannot box either.
#[allow(clippy::large_enum_variant)]
enum Sealed<'book, const N: usize> {
    Application(SealedApplicationDatagram<'book, N>),
    Long(wire::Datagram<'book, N>),
}
impl<'book, const N: usize> Sealed<'book, N> {
    fn reservation(&self) -> &recovery::Reservation<'book> {
        match self {
            Self::Application(packet) => packet.reservation(),
            Self::Long(packet) => &packet.reservation,
        }
    }
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Application(packet) => packet.bytes(),
            Self::Long(packet) => packet.sealed.bytes(),
        }
    }
    fn into_parts(
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
struct Pending<'book, 'streams, const N: usize> {
    scope: &'book ApplicationKeyScope,
    sealed: Sealed<'book, N>,
    stream: Option<stream::Transmission<'streams>>,
    acknowledgment: Option<recovery::AckSnapshot<'book>>,
    close_deadline: Option<u64>,
    response: Option<crate::quic::path::imp::responses::Response>,
    cid: Option<crate::quic::imp::kernel::connection_id::LocalCid>,
    path: Option<crate::quic::path::Address>,
    probe: Option<[u8; 8]>,
    peer_cid: Option<crate::quic::imp::kernel::connection_id::PeerCid>,
    retirement: Option<u64>,
}

/// The slot transfers the actual packet on the declared Datagram edge. It
/// owns the unique publication facets, so even cancellation before the adapter
/// takes the slot releases both reservations. Borrows are synchronous only.
pub(crate) struct State<
    'book,
    'streams,
    'storage,
    'scope,
    const N: usize,
    const RX: usize,
    const CHUNK: usize,
> {
    pub(crate) responses: crate::quic::path::imp::responses::Responses,
    pub(crate) peers: RefCell<Option<crate::quic::path::imp::peer_ids::Peers<'storage, 'scope>>>,
    pub(crate) paths: crate::quic::path::local::Paths<'storage>,
    pub(crate) ids: RefCell<Option<crate::quic::path::imp::ids::Ids<'storage, 'scope>>>,
    pending: RefCell<Option<Pending<'book, 'streams, N>>>,
    owners: RefCell<Owners<'book, 'streams, 'storage, 'scope, N, RX, CHUNK>>,
    delivery: crate::quic::imp::tls::Inbox<stream::Delivered<'streams>>,
    drain_deadline: Cell<Option<u64>>,
}
struct Owners<
    'book,
    'streams,
    'storage,
    'scope,
    const N: usize,
    const RX: usize,
    const CHUNK: usize,
> {
    book: recovery::Publication<'book, 'scope, N>,
    streams: stream::Publication<'streams, 'storage, 'scope, RX, CHUNK>,
}
impl<'book, 'streams, 'storage, 'scope, const N: usize, const RX: usize, const CHUNK: usize>
    State<'book, 'streams, 'storage, 'scope, N, RX, CHUNK>
{
    pub(crate) const fn new(
        book: recovery::Publication<'book, 'scope, N>,
        streams: stream::Publication<'streams, 'storage, 'scope, RX, CHUNK>,
        ids: Option<crate::quic::path::imp::ids::Ids<'storage, 'scope>>,
        paths: crate::quic::path::local::Paths<'storage>,
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
    pub(crate) fn retire_all(&self) {
        self.owners.borrow_mut().book.retire_all();
    }
    fn put(
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
    fn take(&self) -> Result<Pending<'book, 'streams, N>, Error> {
        self.pending
            .try_borrow_mut()
            .map_err(|_| Error::Binding)?
            .take()
            .ok_or(Error::Binding)
    }
    fn settle(
        &self,
        packet: Pending<'book, 'streams, N>,
        accepted_at: Option<u64>,
        ecn: crate::quic::ecn::imp::Codepoint,
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
    pub(crate) fn cancel_pending(&self) -> Result<(), Error> {
        let pending = self
            .pending
            .try_borrow_mut()
            .map_err(|_| Error::Binding)?
            .take();
        if let Some(pending) = pending {
            self.settle(pending, None, crate::quic::ecn::imp::Codepoint::NotEct)?;
        }
        Ok(())
    }
}
impl<const N: usize, const RX: usize, const CHUNK: usize> Drop
    for State<'_, '_, '_, '_, N, RX, CHUNK>
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
                crate::quic::ecn::imp::Codepoint::NotEct,
            );
        }
    }
}

/// The adapter owns this guard across Pending. Cancellation releases both
/// reservations synchronously; an accepted result is settled before any await.
struct InFlight<
    'a,
    'book,
    'streams,
    'storage,
    'scope,
    const N: usize,
    const RX: usize,
    const CHUNK: usize,
> {
    packet: Option<Pending<'book, 'streams, N>>,
    state: &'a State<'book, 'streams, 'storage, 'scope, N, RX, CHUNK>,
}
impl<const N: usize, const RX: usize, const CHUNK: usize>
    InFlight<'_, '_, '_, '_, '_, N, RX, CHUNK>
{
    fn bytes(&self) -> &[u8] {
        self.packet
            .as_ref()
            .expect("live publication")
            .sealed
            .bytes()
    }
    fn path(&self) -> Option<crate::quic::path::Address> {
        self.packet.as_ref().and_then(|p| p.path)
    }
    fn complete(
        &mut self,
        accepted_at: Option<u64>,
        ecn: crate::quic::ecn::imp::Codepoint,
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
                .settle(packet, None, crate::quic::ecn::imp::Codepoint::NotEct);
        }
    }
}

fn settle<'book, const N: usize, const RX: usize, const CHUNK: usize>(
    packet: Pending<'book, '_, N>,
    book: &mut recovery::Publication<'book, '_, N>,
    streams: &mut stream::Publication<'_, '_, '_, RX, CHUNK>,
    responses: &crate::quic::path::imp::responses::Responses,
    accepted_at: Option<u64>,
    ecn: crate::quic::ecn::imp::Codepoint,
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

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run<
    'book,
    'streams,
    'scope,
    const N: usize,
    const RX: usize,
    const CHUNK: usize,
>(
    endpoint: &mut Endpoint<'_, { p::TRANSMIT }>,
    control: &Control<'_, 'scope>,
    state: &State<'book, 'streams, '_, 'scope, N, RX, CHUNK>,
    keys: &keys::KeyOwner<'scope>,
    book: &mut recovery::Tx<'book, 'scope, N>,
    streams: &mut stream::Tx<'streams, '_, 'scope, RX, CHUNK>,
    reset: &super::reset::Exchange<'streams>,
    reclaim: &super::reclaim::Exchange<'streams>,
    acknowledgments: &super::acknowledgments::Exchange<'scope>,
    config: Config<'_>,
    peer: &ConnectionId,
    clock: &impl Clock,
) -> Result<(), Error> {
    let mut history_floor = book.application_history_floor();
    let publication_result = async {
        while !control.stopping() || !acknowledgments.pending.is_empty() {
            let revision = control.revision();
            if !acknowledgments.pending.is_empty() {
                endpoint.send::<p::ApplyAcknowledgments>(&()).await?;
                endpoint.recv::<p::AcknowledgmentsApplied>().await?;
                loop {
                    let offered = endpoint.offer().await?;
                    match offered.label() {
                        181 => {
                            let id = offered.recv::<p::StreamDelivered>().await?;
                            let receipt = state.delivery.take().map_err(|_| Error::Binding)?;
                            check(receipt.id(), id)?;
                            let released = streams.record_delivery(receipt)?;
                            reclaim.delivery.put(released).map_err(|_| Error::Binding)?;
                            endpoint.send::<p::DeliveryReclaim>(&id).await?;
                            check(endpoint.recv::<p::DeliveryStored>().await?, id)?;
                            endpoint.send::<p::StreamDeliverySeen>(&id).await?;
                        }
                        183 => {
                            offered.recv::<p::DeliveriesDone>().await?;
                            break;
                        }
                        label => return Err(Error::UnexpectedLabel(label)),
                    }
                }
                endpoint.send::<p::AcknowledgmentsSettled>(&()).await?;
            }
            if control.stopping() {
                break;
            }
            if let Some(id) =
                reclaim.stage(|origin| streams.reclaimable(origin).map_err(Error::from))?
            {
                endpoint.send::<p::ReclaimStream>(&id).await?;
                check(endpoint.recv::<p::StreamReclaimed>().await?, id)?;
                endpoint.send::<p::ReclaimSettled>(&id).await?;
            }
            // This branch is outside the complete Datagram/Accepted-or-Rejected/
            // Settled fragment. The global forbids resetting an unresolved send.
            if let Some(id) = reset.stage()? {
                endpoint.send::<p::ApplyStop>(&id).await?;
                let reply = endpoint.offer().await?;
                let applied = match reply.label() {
                    175 => {
                        check(reply.recv::<p::StopApplied>().await?, id)?;
                        true
                    }
                    176 => {
                        check(reply.recv::<p::StopFailed>().await?, id)?;
                        false
                    }
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                endpoint.send::<p::StopSettled>(&id).await?;
                if !applied {
                    return Err(Error::Application);
                }
                // Bound stop work to one observation per publication iteration;
                // repeated peer requests must not starve ACK/retransmission output.
                crate::runtime::yield_now().await;
            }
            while let Some(grant) = book.take_lost_application() {
                let packet = grant.packet().value;
                acknowledgments
                    .loss
                    .put(grant)
                    .map_err(|_| Error::Binding)?;
                endpoint.send::<p::ApplyLoss>(&packet).await?;
                check(endpoint.recv::<p::LossApplied>().await?, packet)?;
                endpoint.send::<p::LossSettled>(&packet).await?;
            }
            let floor = book.application_history_floor();
            while history_floor < floor {
                streams.forget_lost(history_floor)?;
                history_floor += 1;
            }
            state
                .paths
                .request
                .put(Some(crate::quic::path::local::Requested {
                    pto: book.pto_duration_us()?,
                    confirmed: book.snapshot().handshake_confirmed,
                    response_path: state
                        .responses
                        .pending()
                        .map_err(|_| Error::Binding)?
                        .and_then(|r| r.path)
                        .filter(|path| {
                            // A retired CID cannot answer a delayed challenge
                            // on the old path. Retain that response until an
                            // actual NEW_CONNECTION_ID supplies a usable CID;
                            // ordinary publication on the active path continues.
                            state.peers.borrow().as_ref().is_none_or(|peers| {
                                peers
                                    .choose(*path, state.paths.preferred_cid(Some(*path)))
                                    .is_ok()
                            })
                        }),
                }))
                .map_err(|_| Error::Binding)?;
            endpoint.send::<pp::Request>(&()).await?;
            loop {
                let offered = endpoint.offer().await?;
                match offered.label() {
                    label if label == pp::Reply::LOGICAL_LABEL => {
                        offered.recv::<pp::Reply>().await?;
                        break;
                    }
                    label if label == pp::ProbeReply::LOGICAL_LABEL => {
                        offered.recv::<pp::ProbeReply>().await?;
                        break;
                    }
                    label if label == pp::Current::LOGICAL_LABEL => {
                        offered.recv::<pp::Current>().await?;
                        break;
                    }
                    label if label == pp::Probe::LOGICAL_LABEL => {
                        offered.recv::<pp::Probe>().await?;
                        break;
                    }
                    label if label == pp::Hold::LOGICAL_LABEL => {
                        offered.recv::<pp::Hold>().await?;
                        break;
                    }
                    label if label == pp::ProbePause::LOGICAL_LABEL => {
                        offered.recv::<pp::ProbePause>().await?;
                        endpoint.send::<pp::ProbePaused>(&()).await?;
                        continue;
                    }
                    label if label == pp::Expand::LOGICAL_LABEL => {
                        offered.recv::<pp::Expand>().await?;
                    }
                    label if label == pp::Begin::LOGICAL_LABEL => {
                        offered.recv::<pp::Begin>().await?;
                    }
                    label if label == pp::Resolved::LOGICAL_LABEL => {
                        offered.recv::<pp::Resolved>().await?;
                        let (old, new) =
                            state.paths.migration.take().map_err(|_| Error::Binding)?;
                        if let Some(peers) = state.peers.borrow_mut().as_mut() {
                            peers
                                .retire_previous(old, new, state.paths.preferred_cid(Some(new)))
                                .map_err(|_| Error::Binding)?;
                        }
                        book.validated_path(old, new, clock.now())?;
                    }
                    label if label == pp::Abandoned::LOGICAL_LABEL => {
                        offered.recv::<pp::Abandoned>().await?;
                    }
                    label => return Err(Error::UnexpectedLabel(label)),
                }
                endpoint.send::<pp::Settled>(&()).await?;
                state
                    .paths
                    .request
                    .put(Some(crate::quic::path::local::Requested {
                        pto: book.pto_duration_us()?,
                        confirmed: book.snapshot().handshake_confirmed,
                        response_path: state
                            .responses
                            .pending()
                            .map_err(|_| Error::Binding)?
                            .and_then(|r| r.path)
                            .filter(|path| {
                                // A retired CID cannot answer a delayed challenge
                                // on the old path. Retain that response until an
                                // actual NEW_CONNECTION_ID supplies a usable CID;
                                // ordinary publication on the active path continues.
                                state.peers.borrow().as_ref().is_none_or(|peers| {
                                    peers
                                        .choose(*path, state.paths.preferred_cid(Some(*path)))
                                        .is_ok()
                                })
                            }),
                    }))
                    .map_err(|_| Error::Binding)?;
                endpoint.send::<pp::Request>(&()).await?;
            }
            let grant = state.paths.grant.take().map_err(|_| Error::Binding)?;
            let pending = match prepare(
                keys,
                book,
                streams,
                config,
                peer,
                clock.now(),
                &state.responses,
                &state.ids,
                &state.peers,
                grant,
            ) {
                Ok(pending) => pending,
                Err(error) => {
                    // This grant has no published datagram. Close its actual
                    // path round before the terminal Request/End continuation.
                    endpoint.send::<pp::Settled>(&()).await?;
                    return Err(error);
                }
            };
            let Some(pending) = pending else {
                endpoint.send::<pp::Settled>(&()).await?;
                if let Some(deadline) = state.paths.deadline(clock.now()) {
                    let _ = crate::runtime::select(
                        control.wait(4, revision),
                        clock.wait_until(deadline),
                    )
                    .await;
                } else {
                    control.wait(4, revision).await;
                }
                continue;
            };
            if let Err((error, pending)) = state.put(pending) {
                cancel_prepared(pending, book, streams)?;
                return Err(error);
            }
            endpoint.send::<p::Datagram>(&()).await?;
            let offered = endpoint.offer().await?;
            match offered.label() {
                27 => {
                    offered.recv::<p::Accepted>().await?;
                }
                28 => {
                    offered.recv::<p::Rejected>().await?;
                    if !control.stopping() {
                        endpoint.send::<p::Settled>(&()).await?;
                        endpoint.send::<pp::Settled>(&()).await?;
                        control.revoke()?;
                        return Err(Error::Connection(quic::Error::Io(quic::IoError::Rejected)));
                    }
                }
                label => return Err(Error::UnexpectedLabel(label)),
            }
            endpoint.send::<p::Settled>(&()).await?;
            endpoint.send::<pp::Settled>(&()).await?;

            crate::runtime::yield_now().await;
        }
        Ok::<(), Error>(())
    }
    .await;
    state.paths.request.put(None).map_err(|_| Error::Binding)?;
    endpoint.send::<pp::Request>(&()).await?;
    loop {
        let offered = endpoint.offer().await?;
        match offered.label() {
            label if label == pp::Pause::LOGICAL_LABEL => {
                offered.recv::<pp::Pause>().await?;
                endpoint.send::<pp::Paused>(&()).await?;
                endpoint.recv::<pp::End>().await?;
                break;
            }
            label if label == pp::ProbePause::LOGICAL_LABEL => {
                offered.recv::<pp::ProbePause>().await?;
                endpoint.send::<pp::ProbePaused>(&()).await?;
                continue;
            }
            label if label == pp::End::LOGICAL_LABEL => {
                offered.recv::<pp::End>().await?;
                break;
            }
            label if label == pp::Resolved::LOGICAL_LABEL => {
                offered.recv::<pp::Resolved>().await?;
                let (old, new) = state.paths.migration.take().map_err(|_| Error::Binding)?;
                book.validated_path(old, new, clock.now())?;
            }
            label if label == pp::Abandoned::LOGICAL_LABEL => {
                offered.recv::<pp::Abandoned>().await?;
            }
            label => return Err(Error::UnexpectedLabel(label)),
        }
        endpoint.send::<pp::Settled>(&()).await?;
        state.paths.request.put(None).map_err(|_| Error::Binding)?;
        endpoint.send::<pp::Request>(&()).await?;
    }
    endpoint.send::<pp::Joined>(&()).await?;
    endpoint.send::<p::StopPublication>(&()).await?;
    endpoint.recv::<p::PublicationStopped>().await?;
    endpoint.send::<p::DeliveryReclaimsDone>(&()).await?;
    endpoint.recv::<p::DeliveryReclaimsClosed>().await?;
    publication_result
}

fn cancel_prepared<'book, 'streams, 'scope, const N: usize, const RX: usize, const CHUNK: usize>(
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
fn prepare<'book, 'streams, 'scope, const N: usize, const RX: usize, const CHUNK: usize>(
    keys: &keys::KeyOwner<'scope>,
    book: &mut recovery::Tx<'book, 'scope, N>,
    streams: &mut stream::Tx<'streams, '_, 'scope, RX, CHUNK>,
    config: Config<'_>,
    peer: &ConnectionId,
    now: u64,
    responses: &crate::quic::path::imp::responses::Responses,
    ids: &RefCell<Option<crate::quic::path::imp::ids::Ids<'_, '_>>>,
    peers: &RefCell<Option<crate::quic::path::imp::peer_ids::Peers<'_, '_>>>,
    grant: crate::quic::path::local::Grant,
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
fn long_packet<'book, 'scope, const N: usize>(
    keys: &keys::KeyOwner<'scope>,
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
    let plain = wire::PlainPacket::<N>::new(config, peer, level, frame)?;
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
    match keys.seal_long(level, plain, reservation, None) {
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
fn application_control_packet<'book, 'streams, 'scope, const N: usize>(
    keys: &keys::KeyOwner<'scope>,
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

fn short_overhead(peer: &ConnectionId) -> Result<usize, Error> {
    peer.bytes()
        .len()
        .checked_add(1 + 4 + 16)
        .ok_or(Error::Capacity)
}
fn pad_probe<const N: usize>(
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
fn level_index(level: Level) -> usize {
    match level {
        Level::Initial => 0,
        Level::Handshake => 1,
        Level::OneRtt => 2,
    }
}
fn limited(error: &recovery::Error) -> bool {
    matches!(
        error,
        recovery::Error::CongestionLimited
            | recovery::Error::Accounting(
                AccountingError::Full | AccountingError::AmplificationLimited
            )
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn publish<
    'book,
    'streams,
    'scope,
    const N: usize,
    const RX: usize,
    const CHUNK: usize,
>(
    endpoint: &mut Endpoint<'_, { p::ADAPTER }>,
    control: &Control<'_, 'scope>,
    state: &State<'book, 'streams, '_, 'scope, N, RX, CHUNK>,
    ecn_exchange: &ecn::Exchange,
    issuer: &mut publication_gate::Issuer<'_, 'scope>,
    reset_outcome: &Outcome,
    reset: &super::reset::Exchange<'_>,
    reclaim: &super::reclaim::Exchange<'streams>,
    acknowledgments: &super::acknowledgments::Exchange<'scope>,
    reset_owner: &mut stream::FrameEffects<'streams, '_, '_, RX, CHUNK>,
    socket: &mut impl DatagramTx,
) -> Result<(), Error> {
    loop {
        let offered = endpoint.offer().await?;
        match offered.label() {
            26 => {
                offered.recv::<p::Datagram>().await?;
                let packet = state.take()?;
                if packet.close_deadline.is_some() {
                    state.settle(packet, None, crate::quic::ecn::imp::Codepoint::NotEct)?;
                    return Err(Error::Binding);
                }
                let accepted_at = {
                    let scope = packet.scope;
                    let mut pending = InFlight {
                        packet: Some(packet),
                        state,
                    };
                    if !core::ptr::eq(scope, issuer.scope()) {
                        pending.complete(None, crate::quic::ecn::imp::Codepoint::NotEct)?;
                        return Err(Error::Binding);
                    }
                    let reservation = pending
                        .packet
                        .as_ref()
                        .ok_or(Error::Binding)?
                        .sealed
                        .reservation();
                    ecn_exchange
                        .requested
                        .put(Some(ecn::Requested {
                            packet: reservation.packet(),
                            ack_eliciting: reservation.ack_eliciting(),
                        }))
                        .map_err(|_| Error::Binding)?;
                    endpoint.send::<ep::Request>(&()).await?;
                    let mark = loop {
                        let granted = endpoint.offer().await.map_err(|error| {
                            Error::Connection(quic::Error::EndpointAt {
                                role: p::ADAPTER,
                                expected_label: 100,
                                error,
                            })
                        })?;
                        let mark = match granted.label() {
                            100 => granted.recv::<ep::ProbePermit>().await?,
                            103 => granted.recv::<ep::Validated>().await?,
                            106 => granted.recv::<ep::CapablePermit>().await?,
                            107 => {
                                granted.recv::<ep::ProbeFailed>().await?;
                                0
                            }
                            110 => {
                                granted.recv::<ep::ProbeFailedPermit>().await?;
                                0
                            }
                            112 => {
                                granted.recv::<ep::ValidationFailed>().await?;
                                0
                            }
                            115 => {
                                granted.recv::<ep::FailedPermit>().await?;
                                0
                            }
                            120 => {
                                granted.recv::<ep::ProbePause>().await?;
                                endpoint.send::<ep::ProbePaused>(&()).await?;
                                continue;
                            }
                            122 => {
                                granted.recv::<ep::CapablePause>().await?;
                                endpoint.send::<ep::CapablePaused>(&()).await?;
                                continue;
                            }
                            label => return Err(Error::UnexpectedLabel(label)),
                        };
                        break match mark {
                            0 => crate::quic::ecn::imp::Codepoint::NotEct,
                            2 => crate::quic::ecn::imp::Codepoint::Ect0,
                            _ => return Err(Error::Binding),
                        };
                    };
                    let result = match issuer.begin() {
                        Ok(permit) => {
                            permit
                                .submit(socket.send_on_path(pending.bytes(), mark, pending.path()))
                                .await
                        }
                        Err(error) => Err(error),
                    };
                    let accepted_at = match result {
                        Ok(Ok(at)) => Some(at),
                        _ => None,
                    };
                    pending.complete(accepted_at, mark)?;
                    endpoint.send::<ep::Settled>(&()).await?;
                    accepted_at
                };
                control.changed()?;
                if accepted_at.is_some() {
                    endpoint.send::<p::Accepted>(&()).await?;
                } else {
                    endpoint.send::<p::Rejected>(&()).await?;
                }
                endpoint.recv::<p::Settled>().await?;
            }
            202 => {
                let id = offered.recv::<p::ReclaimStream>().await?;
                let joined = reclaim.applying.take().map_err(|_| Error::Binding)?;
                check(joined.id(), id)?;
                reset_owner.reclaim(joined)?;
                endpoint.send::<p::StreamReclaimed>(&id).await?;
                check(endpoint.recv::<p::ReclaimSettled>().await?, id)?;
                control.changed()?;
            }
            184 => {
                let packet = offered.recv::<p::ApplyLoss>().await?;
                let grant = acknowledgments.loss.take().map_err(|_| Error::Binding)?;
                check(grant.packet().value, packet)?;
                if let Some(peers) = state.peers.borrow_mut().as_mut() {
                    peers.loss(&grant).map_err(|_| Error::Binding)?;
                }
                if let Some(ids) = state.ids.borrow_mut().as_mut() {
                    ids.loss(&grant).map_err(|_| Error::Binding)?;
                }
                reset_owner.apply_loss(grant)?;
                endpoint.send::<p::LossApplied>(&packet).await?;
                check(endpoint.recv::<p::LossSettled>().await?, packet)?;
                control.changed()?;
            }
            178 => {
                offered.recv::<p::ApplyAcknowledgments>().await?;
                let grant = acknowledgments.pending.take().map_err(|_| Error::Binding)?;
                if let Some(peers) = state.peers.borrow_mut().as_mut() {
                    peers.acknowledge(&grant).map_err(|_| Error::Binding)?;
                }
                if let Some(ids) = state.ids.borrow_mut().as_mut() {
                    ids.acknowledge(&grant).map_err(|_| Error::Binding)?;
                }
                reset_owner.acknowledge(grant)?;
                endpoint.send::<p::AcknowledgmentsApplied>(&()).await?;
                while let Some(receipt) = reset_owner.take_delivery()? {
                    let stream = receipt.id();
                    state.delivery.put(receipt).map_err(|_| Error::Binding)?;
                    endpoint.send::<p::StreamDelivered>(&stream).await?;
                    check(endpoint.recv::<p::StreamDeliverySeen>().await?, stream)?;
                }
                endpoint.send::<p::DeliveriesDone>(&()).await?;
                endpoint.recv::<p::AcknowledgmentsSettled>().await?;
                acknowledgments.settled(control)?;
            }
            174 => {
                let id = offered.recv::<p::ApplyStop>().await?;
                let intent = reset.applying.take().map_err(|_| Error::Binding)?;
                if intent.id() != id {
                    return Err(Error::Binding);
                }
                let result = reset_owner.apply(intent);
                reset_outcome.set(result.is_ok())?;
                match reset_outcome
                    .resolver::<{ p::STOP_RESULT }>()
                    .decide()
                    .map_err(quic::Error::from)?
                {
                    DecisionArm::Left => endpoint.send::<p::StopApplied>(&id).await?,
                    DecisionArm::Right => endpoint.send::<p::StopFailed>(&id).await?,
                }
                check(endpoint.recv::<p::StopSettled>().await?, id)?;
                reset_outcome.clear();
                control.changed()?;
                result?;
            }
            30 => {
                offered.recv::<p::StopPublication>().await?;
                if state.pending.borrow().is_some() {
                    return Err(Error::Binding);
                }
                ecn_exchange
                    .requested
                    .put(None)
                    .map_err(|_| Error::Binding)?;
                endpoint.send::<ep::Request>(&()).await?;
                loop {
                    let ending = endpoint.offer().await?;
                    match ending.label() {
                        120 => {
                            ending.recv::<ep::ProbePause>().await?;
                            endpoint.send::<ep::ProbePaused>(&()).await?;
                        }
                        122 => {
                            ending.recv::<ep::CapablePause>().await?;
                            endpoint.send::<ep::CapablePaused>(&()).await?;
                        }
                        124 => {
                            ending.recv::<ep::ProbeFailedPause>().await?;
                            endpoint.send::<ep::ProbeFailedPaused>(&()).await?;
                            endpoint.recv::<ep::ProbeFailedEnd>().await?;
                            break;
                        }
                        126 => {
                            ending.recv::<ep::FailedPause>().await?;
                            endpoint.send::<ep::FailedPaused>(&()).await?;
                            endpoint.recv::<ep::FailedEnd>().await?;
                            break;
                        }
                        117 => {
                            ending.recv::<ep::ProbeEnd>().await?;
                            break;
                        }
                        118 => {
                            ending.recv::<ep::CapableEnd>().await?;
                            break;
                        }
                        label => return Err(Error::UnexpectedLabel(label)),
                    }
                }
                endpoint.send::<ep::Joined>(&()).await?;
                reset.cancel_pending()?;
                endpoint.send::<p::PublicationStopped>(&()).await?;
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
pub(crate) async fn close<
    'book,
    'streams,
    'owner,
    'scope,
    const N: usize,
    const RX: usize,
    const CHUNK: usize,
>(
    endpoint: &mut Endpoint<'_, { p::TRANSMIT }>,
    control: &Control<'_, 'scope>,
    state: &State<'book, 'streams, '_, 'scope, N, RX, CHUNK>,
    owner: &'owner keys::KeyOwner<'scope>,
    closing: ownership::Closing<'scope>,
    book: &mut recovery::Tx<'book, 'scope, N>,
    peer: &ConnectionId,
    receive: &mut impl DatagramRx,
    clock: &impl Clock,
) -> Result<(), Error> {
    let ownership::Closing {
        ordinary: retired,
        permission,
    } = closing;
    if !core::ptr::eq(owner.scope(), retired.scope())
        || !core::ptr::eq(owner.scope(), permission.scope())
        || !control.stopping()
        || state.pending.borrow().is_some()
    {
        return Err(Error::Binding);
    }
    let path = state.paths.current().path;
    let selected = match (state.peers.borrow().as_ref(), path) {
        (Some(peers), Some(path)) => Some(
            peers
                .choose(path, state.paths.preferred_cid(Some(path)))
                .map_err(|_| Error::Binding)?,
        ),
        _ => None,
    };
    let selected_id = selected
        .map(|cid| ConnectionId::new(cid.cid.as_bytes()))
        .transpose()?;
    let peer = selected_id.as_ref().unwrap_or(peer);
    let kind = permission.kind();
    let pto = book.pto_duration_us()?.max(1);
    let started_at = clock.now();
    let deadline = started_at
        .checked_add(pto.checked_mul(3).ok_or(Error::Capacity)?)
        .ok_or(Error::Capacity)?;
    let mut keys = owner.take_closing(&retired)?;
    book.discard_for_close(retired)?;
    state
        .drain_deadline
        .set(Some(if matches!(kind, CloseKind::IdleExpired) {
            started_at
        } else {
            deadline
        }));
    let mut close_accepted = matches!(
        kind,
        CloseKind::Peer { .. } | CloseKind::PeerApplication { .. }
    );
    match kind {
        CloseKind::Peer { .. } | CloseKind::PeerApplication { .. } | CloseKind::IdleExpired => {
            // Peer-initiated draining publishes no packets.
            endpoint.send::<p::Drain>(&()).await?;
            endpoint.recv::<p::Drained>().await?;
        }
        CloseKind::Local { application, code } => {
            let mut retry_at = started_at;
            let mut received = [0; N];
            let mut received_since_reply = 0u64;
            let mut packets_per_reply = 1u64;
            loop {
                if clock.now() >= deadline {
                    break;
                }
                // Ordinary RX has actually retired, transferring its native
                // receive borrow here. Observe late datagrams during closing
                // rather than abandoning them behind three blind timer sends.
                let input = match crate::runtime::select(
                    clock.wait_until(retry_at.min(deadline)),
                    receive.receive(&mut received),
                )
                .await
                {
                    core::ops::ControlFlow::Break(()) => None,
                    core::ops::ControlFlow::Continue(result) => Some(result),
                };
                let reply_budget = match input {
                    Some(Ok(received)) if received.len <= N => {
                        // RFC9000 10.2.1 suggests progressively requiring more
                        // input packets, bounding close-response ping-pong.
                        received_since_reply =
                            received_since_reply.checked_add(1).ok_or(Error::Capacity)?;
                        if received_since_reply < packets_per_reply {
                            crate::runtime::yield_now().await;
                            continue;
                        }
                        received_since_reply = 0;
                        packets_per_reply = packets_per_reply.saturating_mul(2);
                        Some(received.len.checked_mul(3).ok_or(Error::Capacity)?)
                    }
                    Some(Ok(_)) => return Err(Error::Capacity),
                    Some(Err(_)) => {
                        // A late native receive error cannot invent another
                        // datagram. Keep the original finite closing deadline.
                        clock.wait_until(retry_at.min(deadline)).await;
                        None
                    }
                    None => None,
                };
                if clock.now() >= deadline {
                    break;
                }
                let Some(packet) = close_packet(
                    &mut keys,
                    book,
                    peer,
                    application,
                    code,
                    deadline,
                    clock.now(),
                )?
                else {
                    break;
                };
                // No read key remains in closing. A triggered response may
                // use at most three times the actual attributed input bytes.
                if reply_budget.is_some_and(|budget| packet.sealed.bytes().len() > budget) {
                    book.cancel(packet.sealed.into_parts().0)?;
                    crate::runtime::yield_now().await;
                    continue;
                }
                if let Err((error, packet)) = state.put(packet) {
                    book.cancel(packet.sealed.into_parts().0)?;
                    return Err(error);
                }
                endpoint.send::<p::CloseDatagram>(&()).await?;
                let offered = endpoint.offer().await?;
                match offered.label() {
                    33 => {
                        offered.recv::<p::CloseAccepted>().await?;
                        close_accepted = true;
                    }
                    34 => offered.recv::<p::CloseRejected>().await?,
                    label => return Err(Error::UnexpectedLabel(label)),
                }
                endpoint.send::<p::CloseSettled>(&()).await?;

                retry_at = clock.now().checked_add(pto).ok_or(Error::Capacity)?;
                crate::runtime::yield_now().await;
            }
            endpoint.send::<p::CloseFlightDone>(&()).await?;
            endpoint.recv::<p::CloseFlightSettled>().await?;
        }
    }
    keys.discard();
    endpoint.send::<p::Retire>(&()).await?;
    endpoint.recv::<p::Retired>().await?;
    if matches!(kind, CloseKind::IdleExpired) {
        return Ok(());
    }
    if !close_accepted {
        return Err(Error::Incomplete);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn close_packet<'book, 'streams, const N: usize>(
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

/// This continuation is projected after every ordinary role has retired. A
/// closing packet has no ordinary permit: its private construction required
/// both affine retirement objects, and its UDP attempt is deadline bounded.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn publish_close<
    'book,
    'streams,
    'scope,
    const N: usize,
    const RX: usize,
    const CHUNK: usize,
>(
    endpoint: &mut Endpoint<'_, { p::ADAPTER }>,
    state: &State<'book, 'streams, '_, 'scope, N, RX, CHUNK>,
    outcome: &Outcome,
    socket: &mut impl DatagramTx,
    clock: &impl Clock,
) -> Result<(), Error> {
    loop {
        let offered = endpoint.offer().await?;
        match offered.label() {
            32 => {
                offered.recv::<p::CloseDatagram>().await?;
                let packet = state.take()?;
                let Some(deadline) = packet.close_deadline else {
                    state.settle(packet, None, crate::quic::ecn::imp::Codepoint::NotEct)?;
                    return Err(Error::Binding);
                };
                if packet.stream.is_some() || packet.acknowledgment.is_some() {
                    state.settle(packet, None, crate::quic::ecn::imp::Codepoint::NotEct)?;
                    return Err(Error::Binding);
                }
                let accepted_at = {
                    let mut pending = InFlight {
                        packet: Some(packet),
                        state,
                    };
                    let accepted_at = match crate::runtime::select(
                        socket.send_on_path(
                            pending.bytes(),
                            crate::quic::ecn::imp::Codepoint::NotEct,
                            pending.path(),
                        ),
                        clock.wait_until(deadline),
                    )
                    .await
                    {
                        core::ops::ControlFlow::Break(Ok(at)) => Some(at),
                        core::ops::ControlFlow::Break(Err(_))
                        | core::ops::ControlFlow::Continue(()) => None,
                    };
                    pending.complete(accepted_at, crate::quic::ecn::imp::Codepoint::NotEct)?;
                    accepted_at
                };
                outcome.set(accepted_at.is_some())?;
                match outcome
                    .resolver::<{ p::SUBMISSION_RESULT }>()
                    .decide()
                    .map_err(quic::Error::from)?
                {
                    DecisionArm::Left => endpoint.send::<p::CloseAccepted>(&()).await?,
                    DecisionArm::Right => endpoint.send::<p::CloseRejected>(&()).await?,
                }
                endpoint.recv::<p::CloseSettled>().await?;
                outcome.clear();
            }
            36 => {
                offered.recv::<p::CloseFlightDone>().await?;
                let deadline = state.drain_deadline.get().ok_or(Error::Binding)?;
                clock.wait_until(deadline).await;
                endpoint.send::<p::CloseFlightSettled>(&()).await?;
                break;
            }
            38 => {
                offered.recv::<p::Drain>().await?;
                let deadline = state.drain_deadline.get().ok_or(Error::Binding)?;
                clock.wait_until(deadline).await;
                endpoint.send::<p::Drained>(&()).await?;
                break;
            }
            label => return Err(Error::UnexpectedLabel(label)),
        }
    }
    endpoint.recv::<p::Retire>().await?;
    if state.pending.borrow().is_some() {
        return Err(Error::Binding);
    }
    state.retire_all();
    endpoint.send::<p::Retired>(&()).await?;
    Ok(())
}

fn check(actual: u64, expected: u64) -> Result<(), Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(Error::Binding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::CipherSuite;
    use crate::crypto::IntegrityBudget;
    use crate::crypto::KeyKind;
    use crate::crypto::PacketKey;
    use crate::quic::IoError;
    use crate::quic::Side;
    use crate::quic::imp::kernel::streams::Limits;
    use crate::quic::imp::kernel::streams::PacketReference;
    use crate::quic::imp::kernel::streams::Role;
    use crate::quic::imp::kernel::streams::SendChunk;
    use crate::quic::imp::kernel::streams::StreamSlot;
    use core::task::{Context, Waker};

    const PACKET: usize = 256;
    const CHUNK: usize = 32;

    fn key(secret: u8) -> PacketKey {
        PacketKey::from_secret(CipherSuite::Aes128GcmSha256, KeyKind::OneRtt, &[secret; 32])
            .unwrap()
    }

    // Use the actual one-shot installation, packet arena binding and stream
    // queue. No authentication, accepted-ACK or key-update receipt is forged.
    macro_rules! fixture {
        ($book:ident, $write:ident, $streams:ident, $scope:ident) => {
            let mut key_scope = ApplicationKeyScope::new(146);
            let mut installation = key_scope.claim().unwrap();
            let recovery = installation.take_recovery().unwrap();
            let (_read, mut $write) = crate::crypto::directional::ApplicationReadKeys::install(
                installation,
                key(1),
                key(2),
            )
            .unwrap();
            let $scope = $write.scope();
            let mut $book =
                recovery::Recovery::<PACKET>::new(recovery, Side::Client, 333_000, 1200, 3)
                    .unwrap();
            let mut slots = [StreamSlot::<CHUNK>::EMPTY];
            let mut chunks = [SendChunk::<CHUNK>::EMPTY];
            // Exactly one reference makes any leaked Reserved entry observable.
            let mut references = [PacketReference::EMPTY];
            let peer = Limits {
                max_data: 1024,
                max_streams_bidi: 1,
                stream_data_bidi_local: 1024,
                stream_data_bidi_remote: 1024,
                ..Limits::ZERO
            };
            // Receive credit is backed by this one CHUNK-sized slot. Peer
            // send credit is independent and may legitimately be larger.
            let local = Limits {
                max_data: CHUNK as u64,
                stream_data_bidi_local: CHUNK as u64,
                stream_data_bidi_remote: CHUNK as u64,
                ..Limits::ZERO
            };
            let mut $streams = stream::StreamNumbers::new(
                $scope,
                Role::Client,
                peer,
                local,
                &mut slots,
                &mut chunks,
                &mut references,
            )
            .unwrap();
        };
    }

    fn stream_packet<'book, 'streams>(
        book: &mut recovery::Tx<'book, '_, PACKET>,
        streams: &mut stream::Tx<'streams, '_, '_, CHUNK, CHUNK>,
        keys: &mut ApplicationWriteKeys<'_>,
    ) -> Pending<'book, 'streams, PACKET> {
        let prepared = streams
            .prepare::<PACKET>(false)
            .unwrap()
            .expect("queued STREAM");
        let reservation = book
            .reserve_application(
                prepared.bytes(),
                keys.generation(),
                (prepared.bytes().len() + 21) as u64,
                false,
                0,
            )
            .unwrap();
        let scope = reservation.scope();
        let stream = streams
            .reserve_transmission(&prepared, reservation.packet().value)
            .unwrap();
        let sealed = match application_wire::seal(keys, reservation, &[], prepared.bytes()) {
            Ok(sealed) => sealed,
            Err(_) => panic!("actual reserved STREAM must seal"),
        };
        Pending {
            scope,
            sealed: Sealed::Application(sealed),
            stream: Some(stream),
            acknowledgment: None,
            close_deadline: None,
            response: None,
            cid: None,
            path: None,
            probe: None,
            peer_cid: None,
            retirement: None,
        }
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
        let stream::Facets {
            mut app,
            mut tx,
            publication,
            ..
        } = numbers.split();
        let stream = app.open_local().unwrap();
        let mut production = app.take_production(stream).unwrap();
        assert_eq!(
            app.enqueue_prefix(&mut production, b"GET /\r\n", true)
                .unwrap(),
            (b"GET /\r\n").len()
        );
        let (mut book_tx, _, _, book_publication, mut retirement) = book.split().unwrap();
        let guard = actor_test_allocator::NoAlloc::start();
        let state = State::new(
            book_publication,
            publication,
            None,
            crate::quic::path::local::Paths::new(None, quic::Side::Client, None, None),
            None,
        );
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
    impl Drop for Dropped<'_> {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }
    struct PendingSocket<'a> {
        polls: &'a Cell<usize>,
        dropped: &'a Cell<bool>,
    }
    impl DatagramTx for PendingSocket<'_> {
        async fn send(
            &mut self,
            bytes: &[u8],
            _ecn: crate::quic::ecn::imp::Codepoint,
        ) -> Result<u64, IoError> {
            let _dropped = Dropped(self.dropped);
            poll_fn(|_| {
                assert!(!bytes.is_empty());
                self.polls.set(self.polls.get() + 1);
                Poll::<Result<u64, IoError>>::Pending
            })
            .await
        }
    }

    #[test]
    fn dropping_actual_pending_udp_future_cancels_both_owned_reservations() {
        fixture!(book, write, numbers, scope);
        let _ = scope;
        let stream::Facets {
            mut app,
            mut tx,
            publication,
            ..
        } = numbers.split();
        let stream = app.open_local().unwrap();
        let mut production = app.take_production(stream).unwrap();
        assert_eq!(
            app.enqueue_prefix(&mut production, b"GET /pending\r\n", true)
                .unwrap(),
            (b"GET /pending\r\n").len()
        );
        let (mut book_tx, _, _, book_publication, mut retirement) = book.split().unwrap();
        let guard = actor_test_allocator::NoAlloc::start();
        let state = State::new(
            book_publication,
            publication,
            None,
            crate::quic::path::local::Paths::new(None, quic::Side::Client, None, None),
            None,
        );
        let packet = stream_packet(&mut book_tx, &mut tx, &mut write);
        assert!(state.put(packet).is_ok());
        let polls = Cell::new(0);
        let dropped = Cell::new(false);
        let mut socket = PendingSocket {
            polls: &polls,
            dropped: &dropped,
        };
        {
            let mut send = pin!(async {
                let mut pending = InFlight {
                    packet: Some(state.take().unwrap()),
                    state: &state,
                };
                let accepted_at = socket
                    .send(pending.bytes(), crate::quic::ecn::imp::Codepoint::NotEct)
                    .await
                    .unwrap();
                pending
                    .complete(Some(accepted_at), crate::quic::ecn::imp::Codepoint::NotEct)
                    .unwrap();
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
        state
            .settle(retry, None, crate::quic::ecn::imp::Codepoint::NotEct)
            .unwrap();
        assert_cancelled(book_tx.snapshot(), 2);
        drop(state);
        retirement.disarm();
        guard.finish();
    }

    struct AcceptedSocket {
        at: u64,
    }
    impl DatagramTx for AcceptedSocket {
        fn send(
            &mut self,
            bytes: &[u8],
            _ecn: crate::quic::ecn::imp::Codepoint,
        ) -> impl Future<Output = Result<u64, IoError>> {
            assert!(!bytes.is_empty());
            core::future::ready(Ok(self.at))
        }
    }

    #[test]
    fn full_ordinary_ledger_close_preserves_accepted_and_cancelled_packet_number_burns() {
        fixture!(book, write, numbers, scope);
        let stream::Facets { publication, .. } = numbers.split();
        let (mut book_tx, _, _, book_publication, mut retirement) = book.split().unwrap();
        let guard = actor_test_allocator::NoAlloc::start();
        let state = State::new(
            book_publication,
            publication,
            None,
            crate::quic::path::local::Paths::new(None, quic::Side::Client, None, None),
            None,
        );
        // Burn numbers before filling the ordinary admission quota. PTO headroom
        // remains reserved, while close still requires actual ordinary retirement.
        for expected in 0..3 {
            let reservation = book_tx
                .reserve_application(&[1], write.generation(), 22, false, 0)
                .unwrap();
            assert_eq!(reservation.packet().value, expected);
            book_tx.cancel(reservation).unwrap();
        }
        let mut socket = AcceptedSocket { at: 10 };
        for offset in 0..recovery::ORDINARY_RECORD_CAPACITY as u64 {
            socket.at = 10 + offset;
            let reservation = book_tx
                .reserve_application(&[1], write.generation(), 22, false, socket.at)
                .unwrap();
            assert_eq!(reservation.packet().value, 3 + offset);
            let sealed = match application_wire::seal(&mut write, reservation, &[], &[1]) {
                Ok(sealed) => sealed,
                Err(_) => panic!("real reserved PING must seal"),
            };
            let packet = Pending {
                scope,
                sealed: Sealed::Application(sealed),
                stream: None,
                acknowledgment: None,
                close_deadline: None,
                response: None,
                cid: None,
                path: None,
                probe: None,
                peer_cid: None,
                retirement: None,
            };
            let mut pending = InFlight {
                packet: Some(packet),
                state: &state,
            };
            let accepted_at = {
                let mut send = pin!(socket.send_on_path(
                    pending.bytes(),
                    crate::quic::ecn::imp::Codepoint::NotEct,
                    pending.path()
                ));
                let mut context = Context::from_waker(Waker::noop());
                match send.as_mut().poll(&mut context) {
                    Poll::Ready(Ok(at)) => at,
                    _ => panic!("fixture adapter must accept immediately"),
                }
            };
            pending
                .complete(Some(accepted_at), crate::quic::ecn::imp::Codepoint::NotEct)
                .unwrap();
        }
        let next = recovery::ORDINARY_RECORD_CAPACITY as u64 + 3;
        let full = book_tx.snapshot();
        assert_eq!(full.retained_packets, recovery::ORDINARY_RECORD_CAPACITY);
        assert_eq!(full.pending_publications, [0; 3]);
        assert_eq!(
            full.bytes_in_flight,
            22 * recovery::ORDINARY_RECORD_CAPACITY as u64
        );
        assert_eq!(full.next_packet_number[2], Some(next));
        assert!(matches!(
            book_tx.reserve_application(&[1], write.generation(), 22, false, 80),
            Err(recovery::Error::Accounting(AccountingError::Full))
        ));

        // Only this module's test can construct the private global-join token.
        // Production obtains it after all projected ordinary roles retire.
        book_tx
            .discard_for_close(super::super::OrdinaryRetired { scope })
            .unwrap();
        assert_eq!(book_tx.snapshot().retained_packets, 0);
        assert_eq!(book_tx.snapshot().next_packet_number[2], Some(next));
        let mut stream_plaintext = [0; 32];
        let stream_len = packet::encode_frame(
            &Frame::Stream {
                id: 0,
                offset: 0,
                fin: false,
                data: b"x",
            },
            &mut stream_plaintext,
        )
        .unwrap();
        assert!(matches!(
            book_tx.reserve_application(
                &stream_plaintext[..stream_len],
                write.generation(),
                (21 + stream_len) as u64,
                false,
                80
            ),
            Err(recovery::Error::Accounting(AccountingError::Retired))
        ));
        let peer = ConnectionId::new(&[]).unwrap();
        let close = close_packet(&mut write, &mut book_tx, &peer, true, 0, 1000, 80)
            .unwrap()
            .expect("full ordinary ledger must permit close after retirement");
        assert_eq!(write.last_sealed_packet_number(), Some(next));
        assert_eq!(book_tx.snapshot().next_packet_number[2], Some(next + 1));

        // Authenticate the actual protected close bytes with installed peer keys.
        let mut peer_scope = ApplicationKeyScope::new(147);
        let (mut peer_read, _peer_write) =
            crate::crypto::directional::ApplicationReadKeys::install(
                peer_scope.claim().unwrap(),
                key(2),
                key(1),
            )
            .unwrap();
        let opened = application_wire::open::<PACKET>(
            &mut peer_read,
            &mut IntegrityBudget::new(),
            close.sealed.bytes(),
            &[],
            Some(next - 1),
            80,
            1000,
        )
        .unwrap();
        assert_eq!(opened.packet_number(), next);
        let frame = packet::FrameIter::new(
            opened.plaintext(),
            packet::EncryptionLevel::OneRtt,
            packet::ParseLimits::default(),
        )
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
        assert!(
            matches!(frame, Frame::ConnectionClose { error_code: 0, frame_type: None, reason } if reason.is_empty())
        );
        state
            .settle(close, None, crate::quic::ecn::imp::Codepoint::NotEct)
            .unwrap();
        assert_eq!(book_tx.snapshot().pending_publications, [0; 3]);
        assert_eq!(book_tx.snapshot().next_packet_number[2], Some(next + 1));
        let second = close_packet(&mut write, &mut book_tx, &peer, true, 0, 1000, 81)
            .unwrap()
            .expect("cancelled close burns its number");
        assert_eq!(write.last_sealed_packet_number(), Some(next + 1));
        state
            .settle(second, Some(81), crate::quic::ecn::imp::Codepoint::NotEct)
            .unwrap();
        assert_eq!(book_tx.snapshot().next_packet_number[2], Some(next + 2));
        drop(state);
        retirement.disarm();
        guard.finish();
    }
}
