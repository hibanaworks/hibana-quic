//! Finished-gated optional early receive bridge in the connected global.
use super::{EarlyServer, Endpoints, Error};
use crate::crypto::IntegrityBudget;
use crate::quic::Clock;
use crate::quic::Config;
use crate::quic::Side;
use crate::quic::application::imp::stream;
use crate::quic::early_data::global as p;
use crate::quic::early_data::imp::EarlyStatus;
use crate::quic::early_data::localside;
use crate::quic::imp::early_wire;
use crate::quic::imp::kernel::packet::EncryptionLevel;
use crate::quic::imp::kernel::packet::Frame;
use crate::quic::imp::kernel::packet::FrameIter;
use crate::quic::imp::kernel::packet::ParseLimits;
use crate::quic::imp::recovery;
use crate::quic::imp::tls::Transcript;
use hibana::g::Message;
use hibana_tls::handshake::keys::EarlyKeyMaterial;
use hibana_tls::handshake::keys::FinishedAuthenticated;
pub(super) struct Received<'scope> {
    pub finished: FinishedAuthenticated<'scope>,
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
    endpoints: &mut Endpoints<'_>,
    source: &mut Transcript<'scope, '_, '_>,
    config: Config<'_>,
    early: Option<EarlyServer<'_, RX>>,
    finished: FinishedAuthenticated<'scope>,
    integrity: &mut IntegrityBudget,
    book: &mut recovery::Rx<'_, 'scope, N>,
    streams: &mut stream::Rx<'_, '_, 'scope, RX, CHUNK>,
    clock: &impl Clock,
) -> Result<Received<'scope>, Error> {
    let generation = finished.scope().connection_generation();
    if config.side != Side::Server || finished.early_status() != EarlyStatus::Accepted {
        source.discard_pending_early_key();
        async {
            let input = async {
                endpoints.handshake.rx.send::<p::Skip>(&generation).await?;
                check(
                    endpoints.handshake.rx.recv::<p::SkipDone>().await?,
                    generation,
                )
            };
            let owner = async {
                check(
                    endpoints
                        .handshake
                        .tls_rx
                        .offer()
                        .await?
                        .recv::<p::Skip>()
                        .await?,
                    generation,
                )?;
                endpoints
                    .handshake
                    .tls_rx
                    .send::<p::SkipOwner>(&generation)
                    .await?;
                Ok(())
            };
            let tls = async {
                check(
                    endpoints
                        .handshake
                        .tx
                        .offer()
                        .await?
                        .recv::<p::SkipOwner>()
                        .await?,
                    generation,
                )?;
                endpoints
                    .handshake
                    .tx
                    .send::<p::SkipTls>(&generation)
                    .await?;
                Ok(())
            };
            let application = async {
                check(
                    endpoints
                        .handshake
                        .tls_tx
                        .offer()
                        .await?
                        .recv::<p::SkipTls>()
                        .await?,
                    generation,
                )?;
                endpoints
                    .handshake
                    .tls_tx
                    .send::<p::SkipDone>(&generation)
                    .await?;
                Ok(())
            };
            crate::runtime::join::values4(input, owner, tls, application)
                .await
                .map(|_| ())
        }
        .await?;
        return Ok(Received {
            finished,
            packets: 0,
            stream_bytes: 0,
            finished_streams: 0,
        });
    }
    let early = early.ok_or(Error::Binding)?;
    if early.packets.len() > crate::quic::application::imp::stream::MAX_LIVE_STREAMS {
        return Err(Error::Capacity);
    }
    let admission = source
        .take_early_admission()
        .map_err(crate::quic::Error::from)?;
    let claim = admission.generation();
    let EarlyKeyMaterial::Receive(mut key) =
        source.take_early_key().map_err(crate::quic::Error::from)?
    else {
        return Err(Error::Binding);
    };
    let exchange = crate::quic::early_data::Exchange::<N>::new();
    let mut stream_bytes = 0u64;
    let mut finished_streams = 0usize;
    let mut stored: [Option<crate::quic::early_data::StoredPacket<'scope>>;
        crate::quic::application::imp::stream::MAX_LIVE_STREAMS] = core::array::from_fn(|_| None);
    {
        let input = async {
            let mut largest = None;
            if early.packets.len() > stored.len() {
                return Err(Error::Binding);
            }
            for (index, retained) in stored.iter_mut().take(early.packets.len()).enumerate() {
                let packet = early.packets.packet(index).ok_or(Error::Binding)?;
                let mut opened = match early_wire::open::<N>(
                    &key,
                    integrity,
                    packet,
                    config.original_destination_id,
                    largest,
                ) {
                    Ok(value) => value,
                    Err(crate::quic::Error::Crypto(crate::crypto::Error::AuthenticationFailed))
                    | Err(crate::quic::Error::Packet(_))
                    | Err(crate::quic::Error::Binding) => continue,
                    Err(error) => return Err(error.into()),
                };
                let receipt = opened.take_receipt().ok_or(Error::Binding)?;
                let pn = receipt.packet_number();
                largest = Some(largest.map_or(pn, |old: u64| old.max(pn)));
                let input = crate::quic::early_data::AuthenticatedInput::from_authentication(
                    receipt,
                    claim,
                    opened.plaintext(),
                    early.packets.ecn(index),
                )?;
                exchange.store_input(input)?;
                endpoints.handshake.rx.send::<p::Packet>(&pn).await?;
                let result = endpoints.handshake.rx.offer().await?;
                match result.label() {
                    label if label == p::PacketStored::LOGICAL_LABEL => {
                        check(result.recv::<p::PacketStored>().await?, pn)?;
                        *retained = Some(exchange.take_stored()?);
                    }
                    label if label == p::PacketDropped::LOGICAL_LABEL => {
                        check(result.recv::<p::PacketDropped>().await?, pn)?
                    }
                    label => return Err(Error::UnexpectedLabel(label)),
                }
            }
            endpoints.handshake.rx.send::<p::InputEnd>(&claim).await?;
            check(endpoints.handshake.rx.recv::<p::InputEnded>().await?, claim)?;
            endpoints
                .handshake
                .rx
                .send::<p::InputRetired>(&claim)
                .await?;
            Ok(())
        };
        let owner_task = async {
            localside::run(
                &mut endpoints.handshake.tls_rx,
                admission,
                early.policy,
                early.slots,
                &exchange,
            )
            .await
            .map_err(Error::from)
        };
        let tls = async {
            check(
                endpoints
                    .handshake
                    .tx
                    .offer()
                    .await?
                    .recv::<p::InputRetired>()
                    .await?,
                claim,
            )?;
            exchange.store_finished(finished)?;
            endpoints.handshake.tx.send::<p::Verified>(&claim).await?;
            check(
                endpoints.handshake.tx.recv::<p::VerifiedTaken>().await?,
                claim,
            )?;
            check(endpoints.handshake.tx.recv::<p::Retired>().await?, claim)
        };
        let application = async {
            loop {
                let offer = endpoints.handshake.tls_tx.offer().await?;
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
                        endpoints
                            .handshake
                            .tls_tx
                            .send::<p::RangeApplied>(&id)
                            .await?;
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
                        endpoints
                            .handshake
                            .tls_tx
                            .send::<p::ControlsApplied>(&claim)
                            .await?;
                    }
                    label if label == p::Released::LOGICAL_LABEL => {
                        check(offer.recv::<p::Released>().await?, claim)?;
                        endpoints
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
        };
        crate::runtime::join::values4(input, owner_task, tls, application).await?;
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
        finished,
        packets: accepted,
        stream_bytes,
        finished_streams,
    })
}
