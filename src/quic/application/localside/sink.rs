//! Execute the SINK role of the application global.
use core::cell::RefCell;

use hibana::Endpoint;

use super::{Control, Error, StreamSink, global as p};
use crate::quic::application::imp::stream;
use crate::quic::application::imp::stream::App;
use crate::quic::application::imp::stream::MAX_LIVE_STREAMS;
use crate::quic::imp::kernel::streams::StreamHandle;
use crate::runtime::mailbox::Sender;

use crate::quic::application::imp::io::*;
fn check(actual: u64, expected: u64) -> Result<(), Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(Error::Binding)
    }
}

pub(super) fn ready_handle<const RX: usize, const CHUNK: usize>(
    app: &RefCell<App<'_, '_, '_, RX, CHUNK>>,
    stream_id: u64,
) -> Result<StreamHandle, Error> {
    app.try_borrow()
        .map_err(|_| Error::Binding)?
        .find_readable_stream(|stream| stream.id() == stream_id)?
        .ok_or(Error::Binding)
}

// Result of one actual delivery attempt, not a retained protocol phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Delivery {
    More,
    Fin,
    Interrupted,
}

pub(crate) async fn client_sink<'book, const RX: usize, const CHUNK: usize, B>(
    endpoint: &mut Endpoint<'_, { p::SINK }>,
    control: &Control<'_, '_>,
    state: &Exchange<'book, CHUNK, B>,
    app: &RefCell<App<'book, '_, '_, RX, CHUNK>>,
    sink: &mut impl StreamSink,
    reclaim: &crate::quic::application::imp::reclaim::Exchange<'book>,
    auxiliary: Option<&crate::http3::imp::control::Ingress>,
) -> Result<(), Error> {
    let mut bytes = [0; RX];
    loop {
        let offered = endpoint.offer().await?;
        match offered.label() {
            6 => {
                let stream_id = offered.recv::<p::ReceivedData>().await?;
                let delivery = if control.stopping() {
                    Ok(Delivery::Interrupted)
                } else if state.is_complete(stream_id) {
                    Ok(Delivery::Fin)
                } else if stream_id & 2 != 0 {
                    async {
                        use crate::http3::global as h3;
                        let auxiliary = auxiliary.ok_or(Error::Application)?;
                        let stream = ready_handle(app, stream_id)?;
                        let read = app
                            .try_borrow_mut()
                            .map_err(|_| Error::Binding)?
                            .read(stream, &mut bytes)?;
                        control.changed()?;
                        if read.reset.is_some() {
                            return Err(Error::Application);
                        }
                        auxiliary.append(stream, &bytes[..read.len], read.fin)?;
                        while let Some(frame) = auxiliary.next_frame(stream)? {
                            auxiliary
                                .frame
                                .put(Some(frame))
                                .map_err(|_| Error::Binding)?;
                            endpoint.send::<h3::Input>(&()).await?;
                            let offered = endpoint.offer().await?;
                            match offered.label() {
                                245 => {
                                    offered.recv::<h3::SettingsStored>().await?;
                                }
                                246 => {
                                    offered.recv::<h3::Stored>().await?;
                                }
                                label => return Err(Error::UnexpectedLabel(label)),
                            }
                        }
                        if read.fin {
                            state.complete(stream)?;
                            control.changed()?;
                            Ok(Delivery::Fin)
                        } else {
                            Ok(Delivery::More)
                        }
                    }
                    .await
                } else {
                    deliver(control, state, app, sink, stream_id, &mut bytes).await
                };
                if !matches!(delivery, Ok(Delivery::More)) {
                    let receipt = if state.is_complete(stream_id) {
                        app.try_borrow_mut()
                            .map_err(|_| Error::Binding)?
                            .release_input(stream_id)?
                    } else {
                        None
                    };
                    if let Some(receipt) = receipt {
                        reclaim.input.put(receipt).map_err(|_| Error::Binding)?;
                        endpoint.send::<p::InputReclaim>(&stream_id).await?;
                    } else {
                        endpoint.send::<p::NoInputReclaim>(&stream_id).await?;
                    }
                    check(endpoint.recv::<p::InputStored>().await?, stream_id)?;
                    match delivery {
                        Ok(Delivery::Fin) => endpoint.send::<p::ReceivedFin>(&stream_id).await?,
                        Ok(Delivery::Interrupted) => {
                            endpoint.send::<p::ReceivedInterrupted>(&stream_id).await?
                        }
                        Ok(Delivery::More) => return Err(Error::Binding),
                        Err(_) => endpoint.send::<p::ReceivedFailed>(&stream_id).await?,
                    }
                } else {
                    endpoint.send::<p::ReceivedMore>(&stream_id).await?;
                }
            }
            9 => {
                offered.recv::<p::ReceiveRetire>().await?;
                if let Some(auxiliary) = auxiliary {
                    use crate::http3::global as h3;
                    auxiliary.frame.put(None).map_err(|_| Error::Binding)?;
                    endpoint.send::<h3::Input>(&()).await?;
                    let offered = endpoint.offer().await?;
                    match offered.label() {
                        247 => {
                            offered.recv::<h3::EarlyClosed>().await?;
                        }
                        248 => {
                            offered.recv::<h3::Closed>().await?;
                        }
                        label => return Err(Error::UnexpectedLabel(label)),
                    }
                }
                endpoint.send::<p::InputReclaimsDone>(&()).await?;
                endpoint.recv::<p::InputReclaimsClosed>().await?;
                endpoint.send::<p::ReceiveRetired>(&()).await?;
                return Ok(());
            }
            label => return Err(Error::UnexpectedLabel(label)),
        }
    }
}

pub(super) async fn deliver<const RX: usize, const CHUNK: usize, B>(
    control: &Control<'_, '_>,
    state: &Exchange<'_, CHUNK, B>,
    app: &RefCell<App<'_, '_, '_, RX, CHUNK>>,
    sink: &mut impl StreamSink,
    stream_id: u64,
    bytes: &mut [u8],
) -> Result<Delivery, Error> {
    let stream = ready_handle(app, stream_id)?;
    // The SINK role retains this scratch storage across deliveries. Only the
    // prefix returned by read is exposed, including after a shorter read.
    let read = app
        .try_borrow_mut()
        .map_err(|_| Error::Binding)?
        .read(stream, bytes)?;
    control.changed()?;
    if read.reset.is_some() {
        return Err(Error::Application);
    }
    if read.len != 0 {
        match control
            .until_stop(2, sink.write(stream_id, &bytes[..read.len]))
            .await
        {
            Some(result) => result.map_err(|_| Error::Application)?,
            None => return Ok(Delivery::Interrupted),
        }
    }
    if read.fin {
        match control.until_stop(2, sink.finish(stream_id)).await {
            Some(result) => result.map_err(|_| Error::Application)?,
            None => return Ok(Delivery::Interrupted),
        }
        state.complete(stream)?;
        control.changed()?;
    }
    Ok(if read.fin {
        Delivery::Fin
    } else {
        Delivery::More
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn server_sink<'book, const RX: usize, const CHUNK: usize, B>(
    endpoint: &mut Endpoint<'_, { p::SINK }>,
    control: &Control<'_, '_>,
    state: &Exchange<'book, CHUNK, B>,
    app: &RefCell<App<'book, '_, '_, RX, CHUNK>>,
    requests: &mut Sender<'_, '_, OwnedRequest<'book>, REQUEST_CAPACITY>,
    mut streaming: Option<&mut impl StreamSink>,
    reclaim: &crate::quic::application::imp::reclaim::Exchange<'book>,
    auxiliary: Option<&crate::http3::imp::control::Ingress>,
) -> Result<(), Error> {
    let mut bytes = [0; RX];
    let mut pending: [Option<PendingRequest>; MAX_LIVE_STREAMS] =
        [const { None }; MAX_LIVE_STREAMS];
    loop {
        let offered = endpoint.offer().await?;
        match offered.label() {
            6 => {
                let stream_id = offered.recv::<p::ReceivedData>().await?;
                let delivery = if control.stopping() {
                    Ok(Delivery::Interrupted)
                } else if state.is_complete(stream_id) {
                    Ok(Delivery::Fin)
                } else if stream_id & 2 != 0 {
                    async {
                        use crate::http3::global as h3;
                        let auxiliary = auxiliary.ok_or(Error::Application)?;
                        let stream = ready_handle(app, stream_id)?;
                        let read = app
                            .try_borrow_mut()
                            .map_err(|_| Error::Binding)?
                            .read(stream, &mut bytes)?;
                        control.changed()?;
                        if read.reset.is_some() {
                            return Err(Error::Application);
                        }
                        auxiliary.append(stream, &bytes[..read.len], read.fin)?;
                        while let Some(frame) = auxiliary.next_frame(stream)? {
                            auxiliary
                                .frame
                                .put(Some(frame))
                                .map_err(|_| Error::Binding)?;
                            endpoint.send::<h3::Input>(&()).await?;
                            let offered = endpoint.offer().await?;
                            match offered.label() {
                                245 => {
                                    offered.recv::<h3::SettingsStored>().await?;
                                }
                                246 => {
                                    offered.recv::<h3::Stored>().await?;
                                }
                                label => return Err(Error::UnexpectedLabel(label)),
                            }
                        }
                        if read.fin {
                            state.complete(stream)?;
                            control.changed()?;
                            Ok(Delivery::Fin)
                        } else {
                            Ok(Delivery::More)
                        }
                    }
                    .await
                } else {
                    if let Some(sink) = streaming.as_deref_mut() {
                        async {
                            let stream = ready_handle(app, stream_id)?;
                            let production = app
                                .try_borrow_mut()
                                .map_err(|_| Error::Binding)?
                                .take_unissued_production(stream)?;
                            if let Some(production) = production {
                                let request = OwnedRequest {
                                    production,
                                    bytes: [0; REQUEST_BYTES],
                                    len: 0,
                                };
                                match control.until_stop(2, requests.send(request)).await {
                                    Some(result) => result.map_err(|_| Error::Application)?,
                                    None => return Ok(Delivery::Interrupted),
                                }
                            }
                            deliver(control, state, app, sink, stream_id, &mut bytes).await
                        }
                        .await
                    } else {
                        receive_request(control, state, app, requests, &mut pending, stream_id)
                            .await
                    }
                };
                if !matches!(delivery, Ok(Delivery::More)) {
                    let receipt = if state.is_complete(stream_id) {
                        app.try_borrow_mut()
                            .map_err(|_| Error::Binding)?
                            .release_input(stream_id)?
                    } else {
                        None
                    };
                    if let Some(receipt) = receipt {
                        reclaim.input.put(receipt).map_err(|_| Error::Binding)?;
                        endpoint.send::<p::InputReclaim>(&stream_id).await?;
                    } else {
                        endpoint.send::<p::NoInputReclaim>(&stream_id).await?;
                    }
                    check(endpoint.recv::<p::InputStored>().await?, stream_id)?;
                    match delivery {
                        Ok(Delivery::Fin) => endpoint.send::<p::ReceivedFin>(&stream_id).await?,
                        Ok(Delivery::Interrupted) => {
                            endpoint.send::<p::ReceivedInterrupted>(&stream_id).await?
                        }
                        Ok(Delivery::More) => return Err(Error::Binding),
                        Err(_) => endpoint.send::<p::ReceivedFailed>(&stream_id).await?,
                    }
                } else {
                    endpoint.send::<p::ReceivedMore>(&stream_id).await?;
                }
            }
            9 => {
                offered.recv::<p::ReceiveRetire>().await?;
                if let Some(auxiliary) = auxiliary {
                    use crate::http3::global as h3;
                    auxiliary.frame.put(None).map_err(|_| Error::Binding)?;
                    endpoint.send::<h3::Input>(&()).await?;
                    let offered = endpoint.offer().await?;
                    match offered.label() {
                        247 => {
                            offered.recv::<h3::EarlyClosed>().await?;
                        }
                        248 => {
                            offered.recv::<h3::Closed>().await?;
                        }
                        label => return Err(Error::UnexpectedLabel(label)),
                    }
                }
                requests.close();
                endpoint.send::<p::InputReclaimsDone>(&()).await?;
                endpoint.recv::<p::InputReclaimsClosed>().await?;
                endpoint.send::<p::ReceiveRetired>(&()).await?;
                return Ok(());
            }
            label => return Err(Error::UnexpectedLabel(label)),
        }
    }
}

pub(super) async fn receive_request<'book, const RX: usize, const CHUNK: usize, B>(
    control: &Control<'_, '_>,
    state: &Exchange<'book, CHUNK, B>,
    app: &RefCell<App<'book, '_, '_, RX, CHUNK>>,
    requests: &mut Sender<'_, '_, OwnedRequest<'book>, REQUEST_CAPACITY>,
    pending: &mut [Option<PendingRequest>; MAX_LIVE_STREAMS],
    stream_id: u64,
) -> Result<Delivery, Error> {
    let stream = ready_handle(app, stream_id)?;
    let slot = pending.get_mut(stream.slot()).ok_or(Error::Capacity)?;
    let request = slot.get_or_insert_with(|| PendingRequest {
        stream,
        bytes: [0; REQUEST_BYTES],
        len: 0,
    });
    if request.stream != stream {
        return Err(Error::Binding);
    }
    // Copy once from the receive ring into the retained request. This owner
    // crosses an await, so a borrowed view of reusable receive storage cannot.
    let read = app
        .try_borrow_mut()
        .map_err(|_| Error::Binding)?
        .consume(stream, |view| {
            if view.reset.is_some() {
                return Ok(0);
            }
            let len = view.first.len() + view.second.len();
            let end = request
                .len
                .checked_add(len)
                .filter(|end| *end <= REQUEST_BYTES)
                .ok_or(stream::Error::Capacity)?;
            let middle = request.len + view.first.len();
            request.bytes[request.len..middle].copy_from_slice(view.first);
            request.bytes[middle..end].copy_from_slice(view.second);
            request.len = end;
            Ok(len)
        })?;
    control.changed()?;
    if read.reset.is_some() {
        return Err(Error::Application);
    }
    if read.fin {
        let pending = slot.take().ok_or(Error::Binding)?;
        let production = app
            .try_borrow_mut()
            .map_err(|_| Error::Binding)?
            .take_production(pending.stream)?;
        let request = OwnedRequest {
            production,
            bytes: pending.bytes,
            len: pending.len,
        };
        match control.until_stop(2, requests.send(request)).await {
            Some(result) => result.map_err(|_| Error::Application)?,
            None => return Ok(Delivery::Interrupted),
        }
        state.complete(stream)?;
        control.changed()?;
    }
    Ok(if read.fin {
        Delivery::Fin
    } else {
        Delivery::More
    })
}
