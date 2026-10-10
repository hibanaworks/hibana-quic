//! Ordinary packet publication and the finite, affine close continuation.
//!
//! A pending packet owns both numerical reservations and immutable sealed
//! bytes. Key borrows finish before any endpoint or adapter is awaited.
use crate::quic::ecn::global as ep;
use crate::quic::path::global as pp;
use hibana::g::Message;

use super::{CloseKind, Control, Error, global as p, ownership};
use crate::quic;
use crate::quic::Clock;
use crate::quic::Config;
use crate::quic::ConnectionId;
use crate::quic::DatagramRx;
use crate::quic::DatagramTx;
use crate::quic::Outcome;
use crate::quic::application::imp::stream;
use crate::quic::imp::publication_gate;
use crate::quic::imp::recovery;
#[cfg(test)]
use core::{
    future::{Future, poll_fn},
    pin::pin,
    task::Poll,
};
use hibana::{Endpoint, runtime::resolver::DecisionArm};

use crate::quic::application::imp::publication::*;
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
    state: &Exchange<'book, 'streams, '_, 'scope, N, RX, CHUNK>,
    keys: &crate::quic::application::imp::keys::KeyOwner<'scope>,
    book: &mut recovery::Tx<'book, 'scope, N>,
    streams: &mut stream::Tx<'streams, '_, 'scope, RX, CHUNK>,
    reset: &super::reset::Exchange<'streams>,
    reclaim: &crate::quic::application::imp::reclaim::Exchange<'streams>,
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
                .put(Some(crate::quic::path::imp::observations::Requested {
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
                    .put(Some(crate::quic::path::imp::observations::Requested {
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
    state: &Exchange<'book, 'streams, '_, 'scope, N, RX, CHUNK>,
    ecn_exchange: &crate::quic::ecn::imp::exchange::Exchange,
    issuer: &mut publication_gate::Issuer<'_, 'scope>,
    reset_outcome: &Outcome,
    reset: &super::reset::Exchange<'_>,
    reclaim: &crate::quic::application::imp::reclaim::Exchange<'streams>,
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
                    state.settle(packet, None, crate::io::Codepoint::NotEct)?;
                    return Err(Error::Binding);
                }
                let accepted_at = {
                    let scope = packet.scope;
                    let mut pending = InFlight {
                        packet: Some(packet),
                        state,
                    };
                    if !core::ptr::eq(scope, issuer.scope()) {
                        pending.complete(None, crate::io::Codepoint::NotEct)?;
                        return Err(Error::Binding);
                    }
                    let reservation = pending
                        .packet
                        .as_ref()
                        .ok_or(Error::Binding)?
                        .sealed
                        .reservation();
                    // Pure ACK packets are always Not-ECT under this policy.
                    // Their owned publication needs no ECN marking decision; the
                    // ECN endpoint remains ready for the next ack-eliciting packet.
                    if !reservation.ack_eliciting() {
                        let mark = crate::io::Codepoint::NotEct;
                        let result = match issuer.begin() {
                            Ok(permit) => {
                                permit
                                    .submit(socket.send_on_path(
                                        pending.bytes(),
                                        mark,
                                        pending.path(),
                                    ))
                                    .await
                            }
                            Err(error) => Err(error),
                        };
                        let accepted_at = match result {
                            Ok(Ok(at)) => Some(at),
                            _ => None,
                        };
                        pending.complete(accepted_at, mark)?;
                        accepted_at
                    } else {
                        ecn_exchange
                            .requested
                            .put(Some(crate::quic::ecn::imp::exchange::Requested {
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
                                0 => crate::io::Codepoint::NotEct,
                                2 => crate::io::Codepoint::Ect0,
                                _ => return Err(Error::Binding),
                            };
                        };
                        let result = match issuer.begin() {
                            Ok(permit) => {
                                permit
                                    .submit(socket.send_on_path(
                                        pending.bytes(),
                                        mark,
                                        pending.path(),
                                    ))
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
                    }
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
    state: &Exchange<'book, 'streams, '_, 'scope, N, RX, CHUNK>,
    owner: &'owner crate::quic::application::imp::keys::KeyOwner<'scope>,
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
    state: &Exchange<'book, 'streams, '_, 'scope, N, RX, CHUNK>,
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
                    state.settle(packet, None, crate::io::Codepoint::NotEct)?;
                    return Err(Error::Binding);
                };
                if packet.stream.is_some() || packet.acknowledgment.is_some() {
                    state.settle(packet, None, crate::io::Codepoint::NotEct)?;
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
                            crate::io::Codepoint::NotEct,
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
                    pending.complete(accepted_at, crate::io::Codepoint::NotEct)?;
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
#[path = "transmit_tests.rs"]
mod tests;
