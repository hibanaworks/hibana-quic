//! Finished-gated optional early receive bridge in the connected global.
use super::{EarlyServer, Error, Roles};
use crate::{
    bounded_tls::key_source::{EarlyKeyMaterial, FinishedAuthenticated},
    connection::{Clock, Config, Side, application_stream, early_wire, recovery, tls::Transcript},
    crypto::IntegrityBudget,
    early_data::{EarlyStatus, owner, protocol as p},
    packet::{EncryptionLevel, Frame, FrameIter, ParseLimits},
};
use core::pin::pin;
use hibana::g::Message;
#[derive(Default)]
pub(super) struct Received {
    pub packets: usize,
    pub stream_bytes: u64,
    pub finished_streams: usize,
}
fn check(value: u64, expected: u64) -> Result<(), Error> {
    if value == expected {
        Ok(())
    } else {
        Err(Error::Binding)
    }
}
#[allow(clippy::too_many_arguments)]
pub(super) async fn receive<'scope, const N: usize, const RX: usize, const CHUNK: usize>(
    roles: &mut Roles<'_>,
    source: &mut Transcript<'scope, '_, '_>,
    config: Config<'_>,
    early: Option<EarlyServer<'_, RX>>,
    finished: FinishedAuthenticated<'scope>,
    integrity: &mut IntegrityBudget,
    book: &mut recovery::Rx<'_, 'scope, N>,
    streams: &mut application_stream::Rx<'_, '_, 'scope, RX, CHUNK>,
    clock: &impl Clock,
) -> Result<Received, Error> {
    let generation = finished.scope().connection_generation();
    if config.side != Side::Server || finished.early_status() != EarlyStatus::Accepted {
        source.discard_pending_early_key();
        async {
            let mut input = pin!(async {
                roles.handshake.rx.send::<p::Skip>(&generation).await?;
                check(roles.handshake.rx.recv::<p::SkipDone>().await?, generation)
            });
            let mut owner = pin!(async {
                check(
                    roles
                        .handshake
                        .tls_rx
                        .offer()
                        .await?
                        .recv::<p::Skip>()
                        .await?,
                    generation,
                )?;
                roles
                    .handshake
                    .tls_rx
                    .send::<p::SkipOwner>(&generation)
                    .await?;
                Ok(())
            });
            let mut tls = pin!(async {
                check(
                    roles
                        .handshake
                        .tx
                        .offer()
                        .await?
                        .recv::<p::SkipOwner>()
                        .await?,
                    generation,
                )?;
                roles.handshake.tx.send::<p::SkipTls>(&generation).await?;
                Ok(())
            });
            let mut application = pin!(async {
                check(
                    roles
                        .handshake
                        .tls_tx
                        .offer()
                        .await?
                        .recv::<p::SkipTls>()
                        .await?,
                    generation,
                )?;
                roles
                    .handshake
                    .tls_tx
                    .send::<p::SkipDone>(&generation)
                    .await?;
                Ok(())
            });
            crate::runtime::TaskSet::new([
                input.as_mut(),
                owner.as_mut(),
                tls.as_mut(),
                application.as_mut(),
            ])
            .await
        }
        .await?;
        return Ok(Received::default());
    }
    let early = early.ok_or(Error::Binding)?;
    if early.packets.len() > crate::connection::application_stream::MAX_LIVE_STREAMS {
        return Err(Error::Capacity);
    }
    let admission = source
        .take_early_admission()
        .map_err(crate::connection::Error::from)?;
    let claim = admission.generation();
    let EarlyKeyMaterial::Receive(mut key) = source
        .take_early_key()
        .map_err(crate::connection::Error::from)?
    else {
        return Err(Error::Binding);
    };
    let exchange = owner::Exchange::<N>::new();
    let mut stream_bytes = 0u64;
    let mut finished_streams = 0usize;
    let mut stored: [Option<owner::StoredPacket<'scope>>;
        crate::connection::application_stream::MAX_LIVE_STREAMS] = core::array::from_fn(|_| None);
    {
        let mut input = pin!(async {
            let mut largest = None;
            for index in 0..early.packets.len() {
                let packet = early.packets.packet(index).ok_or(Error::Binding)?;
                let mut opened = match early_wire::open::<N>(
                    &key,
                    integrity,
                    packet,
                    config.original_destination_id,
                    largest,
                ) {
                    Ok(value) => value,
                    Err(crate::connection::Error::Crypto(
                        crate::crypto::Error::AuthenticationFailed,
                    ))
                    | Err(crate::connection::Error::Packet(_))
                    | Err(crate::connection::Error::Binding) => continue,
                    Err(error) => return Err(error.into()),
                };
                let receipt = opened.take_receipt().ok_or(Error::Binding)?;
                let pn = receipt.packet_number();
                largest = Some(largest.map_or(pn, |old: u64| old.max(pn)));
                let input = owner::AuthenticatedInput::from_authentication(
                    receipt,
                    claim,
                    opened.plaintext(),
                )?;
                exchange.store_input(input)?;
                roles.handshake.rx.send::<p::Packet>(&pn).await?;
                let result = roles.handshake.rx.offer().await?;
                match result.label() {
                    label if label == p::PacketStored::LOGICAL_LABEL => {
                        check(result.recv::<p::PacketStored>().await?, pn)?;
                        stored[index] = Some(exchange.take_stored()?);
                    }
                    label if label == p::PacketDropped::LOGICAL_LABEL => {
                        check(result.recv::<p::PacketDropped>().await?, pn)?
                    }
                    label => return Err(Error::UnexpectedLabel(label)),
                }
            }
            roles.handshake.rx.send::<p::InputEnd>(&claim).await?;
            check(roles.handshake.rx.recv::<p::InputEnded>().await?, claim)?;
            roles.handshake.rx.send::<p::InputRetired>(&claim).await?;
            Ok(())
        });
        let mut owner_task = pin!(async {
            owner::run(
                &mut roles.handshake.tls_rx,
                admission,
                early.policy,
                early.slots,
                &exchange,
            )
            .await
            .map_err(Error::from)
        });
        let mut tls = pin!(async {
            check(
                roles
                    .handshake
                    .tx
                    .offer()
                    .await?
                    .recv::<p::InputRetired>()
                    .await?,
                claim,
            )?;
            exchange.store_finished(finished)?;
            roles.handshake.tx.send::<p::Verified>(&claim).await?;
            check(roles.handshake.tx.recv::<p::VerifiedTaken>().await?, claim)?;
            check(roles.handshake.tx.recv::<p::Retired>().await?, claim)
        });
        let mut application = pin!(async {
            loop {
                let offer = roles.handshake.tls_tx.offer().await?;
                match offer.label() {
                    label if label == p::Range::LOGICAL_LABEL => {
                        let id = offer.recv::<p::Range>().await?;
                        let range = exchange.take_range()?;
                        check(range.id, id)?;
                        streams.apply(&Frame::Stream {
                            id: range.id,
                            offset: range.offset,
                            fin: range.fin,
                            data: range.bytes(),
                        })?;
                        stream_bytes = stream_bytes
                            .checked_add(range.bytes().len() as u64)
                            .ok_or(Error::Capacity)?;
                        if range.fin {
                            finished_streams =
                                finished_streams.checked_add(1).ok_or(Error::Capacity)?;
                        }
                        roles.handshake.tls_tx.send::<p::RangeApplied>(&id).await?;
                    }
                    label if label == p::Controls::LOGICAL_LABEL => {
                        check(offer.recv::<p::Controls>().await?, claim)?;
                        let controls = exchange.take_controls()?;
                        for frame in FrameIter::new(
                            controls.bytes(),
                            EncryptionLevel::ZeroRtt,
                            ParseLimits::default(),
                        )? {
                            streams.apply(&frame?)?;
                        }
                        roles
                            .handshake
                            .tls_tx
                            .send::<p::ControlsApplied>(&claim)
                            .await?;
                    }
                    label if label == p::Released::LOGICAL_LABEL => {
                        check(offer.recv::<p::Released>().await?, claim)?;
                        roles
                            .handshake
                            .tls_tx
                            .send::<p::ReleaseSeen>(&claim)
                            .await?;
                        break;
                    }
                    label => return Err(Error::UnexpectedLabel(label)),
                }
            }
            Ok(())
        });
        crate::runtime::TaskSet::new([
            input.as_mut(),
            owner_task.as_mut(),
            tls.as_mut(),
            application.as_mut(),
        ])
        .await?;
    }
    let finished = exchange.take_finished()?;
    let mut accepted = 0;
    for packet in stored.into_iter().flatten() {
        let outcome = book.apply_stored_early(packet, &finished, clock.now())?;
        if !outcome.duplicate {
            accepted += 1;
        }
    }
    key.discard();
    Ok(Received {
        packets: accepted,
        stream_bytes,
        finished_streams,
    })
}
