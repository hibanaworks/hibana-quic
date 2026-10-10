//! Execute the SOURCE role of the application global.
use core::cell::RefCell;

use hibana::Endpoint;

use super::{BodyReader, ClientRequests, Control, Error, MAX_REQUESTS, ServerHandler, global as p};
use crate::quic::application::imp::stream;
use crate::quic::application::imp::stream::App;
use crate::quic::imp::kernel::streams;
use crate::runtime::mailbox::Receiver;

use crate::quic::application::imp::io::*;
fn check(actual: u64, expected: u64) -> Result<(), Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(Error::Binding)
    }
}

pub(crate) async fn client_source<'book, const RX: usize, const CHUNK: usize, B>(
    endpoint: &mut Endpoint<'_, { p::SOURCE }>,
    control: &Control<'_, '_>,
    state: &Exchange<'book, CHUNK, B>,
    app: &RefCell<App<'book, '_, '_, RX, CHUNK>>,
    requests: &mut impl ClientRequests,
) -> Result<(), Error> {
    let result = async {
        if CHUNK == 0 {
            return Err(Error::Capacity);
        }
        let mut request = [0; REQUEST_BYTES];
        while !control.stopping() {
            let next = match control
                .until_stop(0, next_request(state, requests, &mut request))
                .await
            {
                Some(result) => result?,
                None => break,
            };
            let Some(len) = next else {
                break;
            };
            let stream = loop {
                if control.stopping() {
                    return Ok(());
                }
                let revision = control.revision();
                let result = app
                    .try_borrow_mut()
                    .map_err(|_| Error::Binding)?
                    .open_local();
                match result {
                    Ok(stream) => break stream,
                    // Peer credit and the actual three-owner reclamation can
                    // unblock the bounded slot; neither is fabricated here.
                    Err(stream::Error::Streams(
                        streams::Error::StreamLimit | streams::Error::Capacity,
                    )) => {
                        control.wait(0, revision).await;
                    }
                    Err(error) => return Err(error.into()),
                }
            };
            requests
                .started(stream.id())
                .map_err(|_| Error::Application)?;
            state.submitted()?;
            control.changed()?;
            let production = app
                .try_borrow_mut()
                .map_err(|_| Error::Binding)?
                .take_production(stream)?;
            {
                let id = production.id();
                state.opened.put(production).map_err(|_| Error::Binding)?;
                endpoint.send::<p::SourceOpen>(&id).await?;
            }
            let result = async {
                let mut offset = 0;
                while offset < len && !control.stopping() {
                    let count = (len - offset).min(CHUNK);
                    let mut chunk = Chunk {
                        bytes: [0; CHUNK],
                        len: count,
                    };
                    chunk.bytes[..count].copy_from_slice(&request[offset..offset + count]);
                    let admitted = async {
                        let endpoint = &mut *endpoint;

                        let input = Input::Chunk(chunk);

                        state.data.put(input).map_err(|_| Error::Binding)?;
                        endpoint.send::<p::SourceData>(&()).await?;
                        let reply = endpoint.offer().await?;
                        let accepted = match reply.label() {
                            1 => {
                                reply.recv::<p::SourceAccepted>().await?;
                                Admission::Accepted
                            }
                            2 => {
                                reply.recv::<p::SourceRejected>().await?;
                                Admission::Interrupted
                            }
                            187 => {
                                reply.recv::<p::SourceStopped>().await?;
                                Admission::Stopped
                            }
                            215 => {
                                reply.recv::<p::SourceDataFailed>().await?;
                                Admission::Failed
                            }
                            label => return Err(Error::UnexpectedLabel(label)),
                        };
                        endpoint.send::<p::SourceTaken>(&()).await?;

                        Ok(accepted)
                    }
                    .await?;
                    if admitted != Admission::Accepted {
                        return Ok(admitted);
                    }
                    offset += count;
                    crate::runtime::yield_now().await;
                }
                if offset != len {
                    return Ok(Admission::Interrupted);
                }
                loop {
                    let mut chunk = Chunk {
                        bytes: [0; CHUNK],
                        len: 0,
                    };
                    let count = match control
                        .until_stop(0, requests.body(stream.id(), &mut chunk.bytes))
                        .await
                    {
                        Some(result) => result.map_err(|_| Error::Application)?,
                        None => return Ok(Admission::Interrupted),
                    };
                    if count == 0 {
                        break;
                    }
                    if count > CHUNK {
                        return Err(Error::Capacity);
                    }
                    chunk.len = count;
                    state
                        .data
                        .put(Input::Chunk(chunk))
                        .map_err(|_| Error::Binding)?;
                    endpoint.send::<p::SourceData>(&()).await?;
                    let reply = endpoint.offer().await?;
                    let admitted = match reply.label() {
                        1 => {
                            reply.recv::<p::SourceAccepted>().await?;
                            Admission::Accepted
                        }
                        2 => {
                            reply.recv::<p::SourceRejected>().await?;
                            Admission::Interrupted
                        }
                        187 => {
                            reply.recv::<p::SourceStopped>().await?;
                            Admission::Stopped
                        }
                        215 => {
                            reply.recv::<p::SourceDataFailed>().await?;
                            Admission::Failed
                        }
                        label => return Err(Error::UnexpectedLabel(label)),
                    };
                    endpoint.send::<p::SourceTaken>(&()).await?;
                    if admitted != Admission::Accepted {
                        return Ok(admitted);
                    }
                    crate::runtime::yield_now().await;
                }
                Ok::<_, Error>(Admission::Accepted)
            }
            .await;
            let finished = async {
                let endpoint = &mut *endpoint;
                let stream_id = stream.id();
                let outcome = result.as_ref().copied().unwrap_or(Admission::Interrupted);

                endpoint.send::<p::SourceDataFinished>(&stream_id).await?;
                if outcome == Admission::Accepted {
                    endpoint.send::<p::SourceFin>(&stream_id).await?;
                } else {
                    // Connection shutdown abandons production; this is not a fabricated
                    // RESET_STREAM acknowledgment or a claim that FIN reached the peer.
                    endpoint.send::<p::SourceAbandon>(&stream_id).await?;
                }
                let reply = endpoint.offer().await?;
                match reply.label() {
                    171 => {
                        check(reply.recv::<p::SourceEnded>().await?, stream_id)?;
                        Ok(outcome)
                    }
                    172 => {
                        check(reply.recv::<p::SourceEndRejected>().await?, stream_id)?;
                        Ok(Admission::Interrupted)
                    }
                    188 => {
                        check(reply.recv::<p::SourceEndStopped>().await?, stream_id)?;
                        Ok(Admission::Stopped)
                    }
                    216 => {
                        check(reply.recv::<p::SourceEndFailed>().await?, stream_id)?;
                        Ok(Admission::Failed)
                    }
                    label => Err(Error::UnexpectedLabel(label)),
                }
            }
            .await?;
            result?;
            match finished {
                Admission::Interrupted => return Ok(()),
                Admission::Failed => return Err(Error::Application),
                Admission::Stopped => continue,
                Admission::Accepted => {}
            }
        }
        Ok(())
    }
    .await;
    let result = if result.is_ok() && state.submitted_count() == 0 {
        Err(Error::Application)
    } else {
        result
    };
    {
        endpoint.send::<p::SourceDone>(&()).await?;
        endpoint.recv::<p::SourceRetired>().await?;
        if result.is_err() {
            endpoint.send::<p::SourceFailed>(&()).await?;
        } else {
            endpoint.send::<p::SourceJoined>(&()).await?;
        }
        control.changed()?;
    }
    result
}

/// `next` must still be called at the limit so exactly MAX_REQUESTS requests
/// can end normally. An excess pending request is rejected before opening
/// an impossible stream or consuming the caller's pending request via started.
pub(super) async fn next_request<const CHUNK: usize, B>(
    state: &Exchange<'_, CHUNK, B>,
    requests: &mut impl ClientRequests,
    output: &mut [u8],
) -> Result<Option<usize>, Error> {
    let next = requests
        .next(output)
        .await
        .map_err(|_| Error::Application)?;
    let Some(len) = next else {
        return Ok(None);
    };
    if len == 0 || len > output.len() || state.submitted_count() >= MAX_REQUESTS {
        return Err(Error::Capacity);
    }
    Ok(Some(len))
}

pub(crate) async fn server_source<
    'book,
    const CHUNK: usize,
    B: BodyReader,
    H: ServerHandler<Body = B>,
>(
    endpoint: &mut Endpoint<'_, { p::SOURCE }>,
    control: &Control<'_, '_>,
    state: &Exchange<'book, CHUNK, B>,
    requests: &mut Receiver<'_, '_, OwnedRequest<'book>, REQUEST_CAPACITY>,
    handler: &mut H,
) -> Result<(), Error> {
    let result = async {
        if CHUNK == 0 {
            return Err(Error::Capacity);
        }
        let limit = handler.request_limit().map(core::num::NonZeroUsize::get);
        if limit.is_some_and(|count| count > MAX_REQUESTS) {
            return Err(Error::Capacity);
        }
        while !control.stopping() {
            if limit == Some(state.submitted_count()) {
                break;
            }
            let request = match control.until_stop(0, requests.recv()).await {
                Some(Ok(request)) => request,
                Some(Err(_)) | None => break,
            };
            if state.submitted_count() >= MAX_REQUESTS {
                return Err(Error::Capacity);
            }
            let body = match control
                .until_stop(
                    0,
                    handler.open(request.production.id(), &request.bytes[..request.len]),
                )
                .await
            {
                Some(result) => result.map_err(|_| Error::Application)?,
                None => break,
            };
            state.submitted()?;
            control.changed()?;
            let stream_id = request.production.id();
            {
                let production = request.production;

                let id = production.id();
                state.opened.put(production).map_err(|_| Error::Binding)?;
                endpoint.send::<p::SourceOpen>(&id).await?;
            }
            // The actual reader moves once through the Hibana data edge. Ingress
            // alone owns the reader until EOF, failure or cancellation; each packet
            // still uses its ordinary bounded send chunk and publication contract.
            let result = async {
                let endpoint = &mut *endpoint;

                let input = Input::Body(body);

                state.data.put(input).map_err(|_| Error::Binding)?;
                endpoint.send::<p::SourceData>(&()).await?;
                let reply = endpoint.offer().await?;
                let accepted = match reply.label() {
                    1 => {
                        reply.recv::<p::SourceAccepted>().await?;
                        Admission::Accepted
                    }
                    2 => {
                        reply.recv::<p::SourceRejected>().await?;
                        Admission::Interrupted
                    }
                    187 => {
                        reply.recv::<p::SourceStopped>().await?;
                        Admission::Stopped
                    }
                    215 => {
                        reply.recv::<p::SourceDataFailed>().await?;
                        Admission::Failed
                    }
                    label => return Err(Error::UnexpectedLabel(label)),
                };
                endpoint.send::<p::SourceTaken>(&()).await?;

                Ok(accepted)
            }
            .await;
            let finished = async {
                let endpoint = &mut *endpoint;

                let outcome = result.as_ref().copied().unwrap_or(Admission::Interrupted);

                endpoint.send::<p::SourceDataFinished>(&stream_id).await?;
                if outcome == Admission::Accepted {
                    endpoint.send::<p::SourceFin>(&stream_id).await?;
                } else {
                    // Connection shutdown abandons production; this is not a fabricated
                    // RESET_STREAM acknowledgment or a claim that FIN reached the peer.
                    endpoint.send::<p::SourceAbandon>(&stream_id).await?;
                }
                let reply = endpoint.offer().await?;
                match reply.label() {
                    171 => {
                        check(reply.recv::<p::SourceEnded>().await?, stream_id)?;
                        Ok(outcome)
                    }
                    172 => {
                        check(reply.recv::<p::SourceEndRejected>().await?, stream_id)?;
                        Ok(Admission::Interrupted)
                    }
                    188 => {
                        check(reply.recv::<p::SourceEndStopped>().await?, stream_id)?;
                        Ok(Admission::Stopped)
                    }
                    216 => {
                        check(reply.recv::<p::SourceEndFailed>().await?, stream_id)?;
                        Ok(Admission::Failed)
                    }
                    label => Err(Error::UnexpectedLabel(label)),
                }
            }
            .await?;
            result?;
            match finished {
                Admission::Interrupted => return Ok(()),
                Admission::Failed => return Err(Error::Application),
                Admission::Stopped => continue,
                Admission::Accepted => {}
            }
            state.bodies_finished.set(
                state
                    .bodies_finished
                    .get()
                    .checked_add(1)
                    .ok_or(Error::Capacity)?,
            );
            control.changed()?;
        }
        Ok(())
    }
    .await;
    requests.close();
    {
        endpoint.send::<p::SourceDone>(&()).await?;
        endpoint.recv::<p::SourceRetired>().await?;
        if result.is_err() {
            endpoint.send::<p::SourceFailed>(&()).await?;
        } else {
            endpoint.send::<p::SourceJoined>(&()).await?;
        }
        control.changed()?;
    }
    result
}
