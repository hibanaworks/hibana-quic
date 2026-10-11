//! Execute the INGRESS role of the application global.
use core::cell::RefCell;

use hibana::Endpoint;

use super::{BodyReader, Control, Error, global as p};
use crate::quic::application::imp::stream;
use crate::quic::application::imp::stream::App;
use crate::quic::application::imp::stream::Production;
use crate::quic::imp::kernel::streams;

use crate::quic::application::imp::io::*;
fn check(actual: u64, expected: u64) -> Result<(), Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(Error::Binding)
    }
}

fn backpressure(error: &stream::Error) -> bool {
    matches!(
        error,
        stream::Error::Streams(
            streams::Error::Capacity | streams::Error::FlowControl | streams::Error::StreamLimit
        )
    )
}

pub(crate) async fn ingress<'book, const RX: usize, const CHUNK: usize, B: BodyReader>(
    endpoint: &mut Endpoint<'_, { p::INGRESS }>,
    control: &Control<'_, '_>,
    state: &Exchange<'book, CHUNK, B>,
    app: &RefCell<App<'book, '_, '_, RX, CHUNK>>,
    reclaim: &crate::quic::application::imp::reclaim::Exchange<'book>,
) -> Result<(), Error> {
    loop {
        let offered = endpoint.offer().await?;
        match offered.label() {
            168 => {
                let stream_id = offered.recv::<p::SourceOpen>().await?;
                let mut production = state.opened.take().map_err(|_| Error::Binding)?;
                check(production.id(), stream_id)?;
                loop {
                    let offered = endpoint.offer().await?;
                    match offered.label() {
                        0 => {
                            offered.recv::<p::SourceData>().await?;
                            let input = state.data.take().map_err(|_| Error::Binding)?;
                            let result = match input {
                                Input::Chunk(chunk) => {
                                    admit(control, app, &mut production, &chunk, false).await
                                }
                                // The local owns the actual reader until EOF or interruption.
                                // No second EOF flag or body-progress dispatcher is needed.
                                Input::Body(mut body) => {
                                    async {
                                        let mut work = 0usize;
                                        while !control.stopping() {
                                            let mut chunk = Chunk {
                                                bytes: [0; CHUNK],
                                                len: 0,
                                            };
                                            let len = match control
                                                .until_stop(1, body.read(&mut chunk.bytes))
                                                .await
                                            {
                                                Some(result) => {
                                                    result.map_err(|_| Error::Application)?
                                                }
                                                None => return Ok(Admission::Interrupted),
                                            };
                                            if len > CHUNK {
                                                return Err(Error::Capacity);
                                            }
                                            if len == 0 {
                                                return Ok(Admission::Accepted);
                                            }
                                            chunk.len = len;
                                            let accepted =
                                                admit(control, app, &mut production, &chunk, false)
                                                    .await?;
                                            if accepted != Admission::Accepted {
                                                return Ok(accepted);
                                            }
                                            work += 1;
                                            if work == 16 {
                                                work = 0;
                                                crate::runtime::yield_now().await;
                                            }
                                        }
                                        Ok(Admission::Interrupted)
                                    }
                                    .await
                                }
                            };
                            let accepted = match result {
                                Ok(accepted) => accepted,
                                Err(_) => Admission::Failed,
                            };
                            match accepted {
                                Admission::Accepted => {
                                    endpoint.send::<p::SourceAccepted>(&()).await?
                                }
                                Admission::Stopped => {
                                    endpoint.send::<p::SourceStopped>(&()).await?
                                }
                                Admission::Interrupted => {
                                    endpoint.send::<p::SourceRejected>(&()).await?
                                }
                                Admission::Failed => {
                                    endpoint.send::<p::SourceDataFailed>(&()).await?
                                }
                            }
                            endpoint.recv::<p::SourceTaken>().await?;
                        }
                        173 => {
                            check(offered.recv::<p::SourceDataFinished>().await?, stream_id)?;
                            break;
                        }
                        label => return Err(Error::UnexpectedLabel(label)),
                    }
                }
                let offered = endpoint.offer().await?;
                let outcome = match offered.label() {
                    169 => {
                        check(offered.recv::<p::SourceFin>().await?, stream_id)?;
                        let terminal = Chunk {
                            bytes: [0; CHUNK],
                            len: 0,
                        };
                        match admit(control, app, &mut production, &terminal, true).await {
                            Ok(outcome) => outcome,
                            Err(_) => Admission::Failed,
                        }
                    }
                    170 => {
                        check(offered.recv::<p::SourceAbandon>().await?, stream_id)?;
                        Admission::Accepted
                    }
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                let receipt = app
                    .try_borrow_mut()
                    .map_err(|_| Error::Binding)?
                    .release_production(production)?;
                reclaim.source.put(receipt).map_err(|_| Error::Binding)?;
                endpoint.send::<p::ProductionReclaim>(&stream_id).await?;
                check(endpoint.recv::<p::ProductionStored>().await?, stream_id)?;
                match outcome {
                    Admission::Accepted => endpoint.send::<p::SourceEnded>(&stream_id).await?,
                    Admission::Stopped => endpoint.send::<p::SourceEndStopped>(&stream_id).await?,
                    Admission::Interrupted => {
                        endpoint.send::<p::SourceEndRejected>(&stream_id).await?
                    }
                    Admission::Failed => endpoint.send::<p::SourceEndFailed>(&stream_id).await?,
                }
            }
            4 => {
                offered.recv::<p::SourceDone>().await?;
                if !state.data.is_empty() {
                    return Err(Error::Binding);
                }
                endpoint.send::<p::ProductionReclaimsDone>(&()).await?;
                endpoint.recv::<p::ProductionReclaimsClosed>().await?;
                endpoint.send::<p::SourceRetired>(&()).await?;
                return Ok(());
            }
            label => return Err(Error::UnexpectedLabel(label)),
        }
    }
}

pub(super) async fn admit<const RX: usize, const CHUNK: usize>(
    control: &Control<'_, '_>,
    app: &RefCell<App<'_, '_, '_, RX, CHUNK>>,
    production: &mut Production<'_>,
    chunk: &Chunk<CHUNK>,
    fin: bool,
) -> Result<Admission, Error> {
    if (chunk.len == 0 && !fin) || chunk.len > CHUNK {
        return Err(Error::Binding);
    }
    let mut offset = 0;
    loop {
        if control.stopping() {
            return Ok(Admission::Interrupted);
        }
        let revision = control.revision();
        let result = app
            .try_borrow_mut()
            .map_err(|_| Error::Binding)?
            .enqueue_prefix(production, &chunk.bytes[offset..chunk.len], fin);
        match result {
            Ok(count) => {
                offset = offset.checked_add(count).ok_or(Error::Capacity)?;
                control.changed()?;
                if offset == chunk.len {
                    return Ok(Admission::Accepted);
                }
                if count == 0 {
                    return Err(Error::Binding);
                }
            }
            Err(stream::Error::Streams(streams::Error::SendClosed)) => {
                return Ok(Admission::Stopped);
            }
            Err(error) if backpressure(&error) => control.wait(1, revision).await,
            Err(error) => return Err(error.into()),
        }
    }
}
