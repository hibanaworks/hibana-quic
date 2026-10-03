//! Role-local bounded HTTP/0.9 source, ingress and sink continuations.
//! Application/file futures never hold a numeric stream borrow. Owned chunks
//! cross the projected source lane; complete bounded GETs cross the request
//! mailbox while the independent source streams a previous response body.

use core::cell::{Cell, RefCell};

use hibana::Endpoint;

use super::{BodyReader, ClientRequests, Control, Error, MAX_REQUEST_BYTES, MAX_REQUESTS, ServerHandler, StreamSink, protocol as p};
use crate::{
    connection::{application_stream::{self, App, MAX_LIVE_STREAMS}, tls::Inbox},
    mailbox::{Receiver, Sender},
    streams::{self, StreamHandle},
};

pub(crate) const REQUEST_BYTES: usize = MAX_REQUEST_BYTES;
pub(crate) const REQUEST_CAPACITY: usize = MAX_REQUESTS;

pub(crate) struct Chunk<const CHUNK: usize> {
    pub stream: StreamHandle,
    pub bytes: [u8; CHUNK],
    pub len: usize,
    pub fin: bool,
}

pub(crate) struct OwnedRequest {
    pub stream: StreamHandle,
    pub bytes: [u8; REQUEST_BYTES],
    pub len: usize,
}

/// Application job observations only. Packet/key/connection phase is owned by
/// the transport continuations, never by these completion counters.
pub(crate) struct State<const CHUNK: usize> {
    chunks: Inbox<Chunk<CHUNK>>,
    submitted: Cell<usize>,
    done: Cell<bool>,
    completed: RefCell<[Option<u64>; MAX_LIVE_STREAMS]>,
}
impl<const CHUNK: usize> State<CHUNK> {
    pub(crate) const fn new() -> Self {
        Self { chunks: Inbox::new(), submitted: Cell::new(0), done: Cell::new(false),
            completed: RefCell::new([None; MAX_LIVE_STREAMS]) }
    }
    pub(crate) fn submitted_count(&self) -> usize { self.submitted.get() }
    pub(crate) fn completed_count(&self) -> usize {
        self.completed.borrow().iter().flatten().count()
    }
    pub(crate) fn source_done(&self) -> bool { self.done.get() }
    pub(crate) fn is_complete(&self, stream_id: u64) -> bool {
        self.completed.borrow().iter().flatten().any(|id| *id == stream_id)
    }
    fn submitted(&self) -> Result<(), Error> {
        let count = self.submitted.get().checked_add(1).ok_or(Error::Capacity)?;
        if count > MAX_REQUESTS { return Err(Error::Capacity); }
        self.submitted.set(count);
        Ok(())
    }
    fn complete(&self, stream_id: u64) -> Result<(), Error> {
        let mut completed = self.completed.try_borrow_mut().map_err(|_| Error::Binding)?;
        if completed.iter().flatten().any(|id| *id == stream_id) { return Ok(()); }
        *completed.iter_mut().find(|id| id.is_none()).ok_or(Error::Capacity)? = Some(stream_id);
        Ok(())
    }
}

fn check(actual: u64, expected: u64) -> Result<(), Error> {
    if actual == expected { Ok(()) } else { Err(Error::Binding) }
}

fn backpressure(error: &application_stream::Error) -> bool {
    matches!(error, application_stream::Error::Streams(
        streams::Error::Capacity | streams::Error::FlowControl | streams::Error::StreamLimit))
}

/// Transfer a real owned chunk before announcing it on the source wire. The
/// ingress response and SourceTaken settle the lane even during shutdown.
async fn submit<const CHUNK: usize>(
    endpoint: &mut Endpoint<'_, { p::SOURCE }>,
    state: &State<CHUNK>,
    sequence: &mut u64,
    chunk: Chunk<CHUNK>,
) -> Result<bool, Error> {
    state.chunks.put(chunk).map_err(|_| Error::Binding)?;
    endpoint.send::<p::SourceData>(sequence).await?;
    let reply = endpoint.offer().await?;
    let accepted = match reply.label() {
        1 => { check(reply.recv::<p::SourceAccepted>().await?, *sequence)?; true }
        2 => { check(reply.recv::<p::SourceRejected>().await?, *sequence)?; false }
        label => return Err(Error::UnexpectedLabel(label)),
    };
    endpoint.send::<p::SourceTaken>(sequence).await?;
    *sequence = sequence.checked_add(1).ok_or(Error::Binding)?;
    Ok(accepted)
}

async fn source_finished<const CHUNK: usize>(
    endpoint: &mut Endpoint<'_, { p::SOURCE }>,
    control: &Control<'_, '_>,
    state: &State<CHUNK>,
    sequence: u64,
) -> Result<(), Error> {
    endpoint.send::<p::SourceDone>(&sequence).await?;
    check(endpoint.recv::<p::SourceRetired>().await?, sequence)?;
    state.done.set(true);
    control.changed()?;
    Ok(())
}

pub(crate) async fn client_source<const RX: usize, const CHUNK: usize>(
    endpoint: &mut Endpoint<'_, { p::SOURCE }>,
    control: &Control<'_, '_>,
    state: &State<CHUNK>,
    app: &RefCell<App<'_, '_, '_, RX, CHUNK>>,
    requests: &mut impl ClientRequests,
) -> Result<(), Error> {
    let mut sequence = 0;
    let result = client_requests(endpoint, control, state, app, requests, &mut sequence).await;
    if result.is_err() { control.fail()?; }
    source_finished(endpoint, control, state, sequence).await?;
    result
}

async fn client_requests<const RX: usize, const CHUNK: usize>(
    endpoint: &mut Endpoint<'_, { p::SOURCE }>,
    control: &Control<'_, '_>,
    state: &State<CHUNK>,
    app: &RefCell<App<'_, '_, '_, RX, CHUNK>>,
    requests: &mut impl ClientRequests,
    sequence: &mut u64,
) -> Result<(), Error> {
    if CHUNK == 0 { return Err(Error::Capacity); }
    let mut request = [0; REQUEST_BYTES];
    while !control.stopping() {
        let next = match control.until_stop(0, next_request(state, requests, &mut request)).await {
            Some(result) => result?,
            None => break,
        };
        let Some(len) = next else { break; };
        let stream = loop {
            if control.stopping() { return Ok(()); }
            let revision = control.revision();
            let result = app.try_borrow_mut().map_err(|_| Error::Binding)?.open_local();
            match result {
                Ok(stream) => break stream,
                // Peer MAX_STREAMS can unblock opening; the fixed local
                // table's Capacity cannot. Its slots are never recycled.
                Err(application_stream::Error::Streams(streams::Error::StreamLimit)) => {
                    control.wait(0, revision).await;
                }
                Err(error) => return Err(error.into()),
            }
        };
        requests.started(stream.id()).map_err(|_| Error::Application)?;
        state.submitted()?;
        control.changed()?;
        let mut offset = 0;
        while offset < len && !control.stopping() {
            let count = (len - offset).min(CHUNK);
            let mut chunk = Chunk { stream, bytes: [0; CHUNK], len: count, fin: offset + count == len };
            chunk.bytes[..count].copy_from_slice(&request[offset..offset + count]);
            if !submit(endpoint, state, sequence, chunk).await? { return Ok(()); }
            offset += count;
            crate::runtime::yield_now().await;
        }
    }
    Ok(())
}

/// `next` must still be called at the limit so exactly MAX_REQUESTS requests
/// can end normally. A seventeenth pending request is rejected before opening
/// an impossible stream or consuming the caller's pending request via started.
async fn next_request<const CHUNK: usize>(
    state: &State<CHUNK>,
    requests: &mut impl ClientRequests,
    output: &mut [u8],
) -> Result<Option<usize>, Error> {
    let next = requests.next(output).await.map_err(|_| Error::Application)?;
    let Some(len) = next else { return Ok(None); };
    if len == 0 || len > output.len() || state.submitted_count() >= MAX_REQUESTS {
        return Err(Error::Capacity);
    }
    Ok(Some(len))
}

pub(crate) async fn server_source<const CHUNK: usize>(
    endpoint: &mut Endpoint<'_, { p::SOURCE }>,
    control: &Control<'_, '_>,
    state: &State<CHUNK>,
    requests: &mut Receiver<'_, '_, OwnedRequest, REQUEST_CAPACITY>,
    handler: &mut impl ServerHandler,
) -> Result<(), Error> {
    let mut sequence = 0;
    let result = server_responses(endpoint, control, state, requests, handler, &mut sequence).await;
    if result.is_err() { control.fail()?; }
    requests.close();
    source_finished(endpoint, control, state, sequence).await?;
    result
}

async fn server_responses<const CHUNK: usize>(
    endpoint: &mut Endpoint<'_, { p::SOURCE }>,
    control: &Control<'_, '_>,
    state: &State<CHUNK>,
    requests: &mut Receiver<'_, '_, OwnedRequest, REQUEST_CAPACITY>,
    handler: &mut impl ServerHandler,
    sequence: &mut u64,
) -> Result<(), Error> {
    if CHUNK == 0 { return Err(Error::Capacity); }
    while !control.stopping() {
        let request = match control.until_stop(0, requests.recv()).await {
            Some(Ok(request)) => request,
            Some(Err(_)) | None => break,
        };
        if state.submitted_count() >= MAX_REQUESTS { return Err(Error::Capacity); }
        let mut body = match control.until_stop(0,
            handler.open(request.stream.id(), &request.bytes[..request.len])).await {
            Some(result) => result.map_err(|_| Error::Application)?,
            None => break,
        };
        state.submitted()?;
        control.changed()?;
        while !control.stopping() {
            let mut chunk = Chunk { stream: request.stream, bytes: [0; CHUNK], len: 0, fin: false };
            let len = match control.until_stop(0, body.read(&mut chunk.bytes)).await {
                Some(result) => result.map_err(|_| Error::Application)?,
                None => return Ok(()),
            };
            if len > CHUNK { return Err(Error::Capacity); }
            chunk.len = len;
            chunk.fin = len == 0;
            if !submit(endpoint, state, sequence, chunk).await? { return Ok(()); }
            if len == 0 { break; }
            crate::runtime::yield_now().await;
        }
    }
    Ok(())
}

pub(crate) async fn ingress<const RX: usize, const CHUNK: usize>(
    endpoint: &mut Endpoint<'_, { p::INGRESS }>,
    control: &Control<'_, '_>,
    state: &State<CHUNK>,
    app: &RefCell<App<'_, '_, '_, RX, CHUNK>>,
) -> Result<(), Error> {
    let mut sequence = 0;
    loop {
        let offered = endpoint.offer().await?;
        match offered.label() {
            0 => {
                check(offered.recv::<p::SourceData>().await?, sequence)?;
                let chunk = state.chunks.take().map_err(|_| Error::Binding)?;
                let accepted = match admit(control, app, &chunk).await {
                    Ok(accepted) => accepted,
                    Err(_) => { control.fail()?; false }
                };
                if accepted { endpoint.send::<p::SourceAccepted>(&sequence).await?; }
                else { endpoint.send::<p::SourceRejected>(&sequence).await?; }
                check(endpoint.recv::<p::SourceTaken>().await?, sequence)?;
                sequence = sequence.checked_add(1).ok_or(Error::Binding)?;
            }
            4 => {
                check(offered.recv::<p::SourceDone>().await?, sequence)?;
                if !state.chunks.is_empty() { control.fail()?; }
                endpoint.send::<p::SourceRetired>(&sequence).await?;
                return Ok(());
            }
            label => return Err(Error::UnexpectedLabel(label)),
        }
    }
}

async fn admit<const RX: usize, const CHUNK: usize>(
    control: &Control<'_, '_>,
    app: &RefCell<App<'_, '_, '_, RX, CHUNK>>,
    chunk: &Chunk<CHUNK>,
) -> Result<bool, Error> {
    if chunk.len > CHUNK || (chunk.len == 0 && !chunk.fin) { return Err(Error::Binding); }
    let mut offset = 0;
    loop {
        if control.stopping() { return Ok(false); }
        let revision = control.revision();
        let result = app.try_borrow_mut().map_err(|_| Error::Binding)?
            .enqueue_prefix(chunk.stream, &chunk.bytes[offset..chunk.len], chunk.fin);
        match result {
            Ok(count) => {
                offset = offset.checked_add(count).ok_or(Error::Capacity)?;
                control.changed()?;
                if offset == chunk.len { return Ok(true); }
                if count == 0 { return Err(Error::Binding); }
            }
            Err(error) if backpressure(&error) => control.wait(1, revision).await,
            Err(error) => return Err(error.into()),
        }
    }
}

fn ready_handle<const RX: usize, const CHUNK: usize>(
    app: &RefCell<App<'_, '_, '_, RX, CHUNK>>,
    stream_id: u64,
) -> Result<StreamHandle, Error> {
    let ready = app.try_borrow().map_err(|_| Error::Binding)?.ready_streams()?;
    ready.into_iter().flatten().find(|stream| stream.id() == stream_id).ok_or(Error::Binding)
}

pub(crate) async fn client_sink<const RX: usize, const CHUNK: usize>(
    endpoint: &mut Endpoint<'_, { p::SINK }>,
    control: &Control<'_, '_>,
    state: &State<CHUNK>,
    app: &RefCell<App<'_, '_, '_, RX, CHUNK>>,
    sink: &mut impl StreamSink,
) -> Result<(), Error> {
    loop {
        let offered = endpoint.offer().await?;
        match offered.label() {
            6 => {
                let stream_id = offered.recv::<p::ReceivedData>().await?;
                let done = if control.stopping() || state.is_complete(stream_id) { true } else {
                    match deliver(control, state, app, sink, stream_id).await {
                        Ok(done) => done,
                        Err(_) => { control.fail()?; true }
                    }
                };
                if done { endpoint.send::<p::ReceivedFin>(&stream_id).await?; }
                else { endpoint.send::<p::ReceivedMore>(&stream_id).await?; }
            }
            9 => {
                let sequence = offered.recv::<p::ReceiveRetire>().await?;
                endpoint.send::<p::ReceiveRetired>(&sequence).await?;
                return Ok(());
            }
            label => return Err(Error::UnexpectedLabel(label)),
        }
    }
}

async fn deliver<const RX: usize, const CHUNK: usize>(
    control: &Control<'_, '_>,
    state: &State<CHUNK>,
    app: &RefCell<App<'_, '_, '_, RX, CHUNK>>,
    sink: &mut impl StreamSink,
    stream_id: u64,
) -> Result<bool, Error> {
    let stream = ready_handle(app, stream_id)?;
    let mut bytes = [0; CHUNK];
    let read = app.try_borrow_mut().map_err(|_| Error::Binding)?.read(stream, &mut bytes)?;
    control.changed()?;
    if read.reset.is_some() { return Err(Error::Application); }
    if read.len != 0 {
        match control.until_stop(2, sink.write(stream_id, &bytes[..read.len])).await {
            Some(result) => result.map_err(|_| Error::Application)?,
            None => return Ok(true),
        }
    }
    if read.fin {
        match control.until_stop(2, sink.finish(stream_id)).await {
            Some(result) => result.map_err(|_| Error::Application)?,
            None => return Ok(true),
        }
        state.complete(stream_id)?;
        control.changed()?;
    }
    Ok(read.fin)
}

pub(crate) async fn server_sink<const RX: usize, const CHUNK: usize>(
    endpoint: &mut Endpoint<'_, { p::SINK }>,
    control: &Control<'_, '_>,
    state: &State<CHUNK>,
    app: &RefCell<App<'_, '_, '_, RX, CHUNK>>,
    requests: &mut Sender<'_, '_, OwnedRequest, REQUEST_CAPACITY>,
) -> Result<(), Error> {
    let mut pending: [Option<OwnedRequest>; MAX_LIVE_STREAMS] = [const { None }; MAX_LIVE_STREAMS];
    loop {
        let offered = endpoint.offer().await?;
        match offered.label() {
            6 => {
                let stream_id = offered.recv::<p::ReceivedData>().await?;
                let done = if control.stopping() || state.is_complete(stream_id) { true } else {
                    match receive_request(control, state, app, requests, &mut pending, stream_id).await {
                        Ok(done) => done,
                        Err(_) => { control.fail()?; true }
                    }
                };
                if done { endpoint.send::<p::ReceivedFin>(&stream_id).await?; }
                else { endpoint.send::<p::ReceivedMore>(&stream_id).await?; }
            }
            9 => {
                let sequence = offered.recv::<p::ReceiveRetire>().await?;
                requests.close();
                endpoint.send::<p::ReceiveRetired>(&sequence).await?;
                return Ok(());
            }
            label => return Err(Error::UnexpectedLabel(label)),
        }
    }
}

async fn receive_request<const RX: usize, const CHUNK: usize>(
    control: &Control<'_, '_>,
    state: &State<CHUNK>,
    app: &RefCell<App<'_, '_, '_, RX, CHUNK>>,
    requests: &mut Sender<'_, '_, OwnedRequest, REQUEST_CAPACITY>,
    pending: &mut [Option<OwnedRequest>; MAX_LIVE_STREAMS],
    stream_id: u64,
) -> Result<bool, Error> {
    let stream = ready_handle(app, stream_id)?;
    let mut bytes = [0; CHUNK];
    let read = app.try_borrow_mut().map_err(|_| Error::Binding)?.read(stream, &mut bytes)?;
    control.changed()?;
    if read.reset.is_some() { return Err(Error::Application); }
    let slot = pending.get_mut(stream.slot()).ok_or(Error::Capacity)?;
    let request = slot.get_or_insert_with(|| OwnedRequest { stream, bytes: [0; REQUEST_BYTES], len: 0 });
    if request.stream != stream { return Err(Error::Binding); }
    let end = request.len.checked_add(read.len).filter(|len| *len <= REQUEST_BYTES).ok_or(Error::Capacity)?;
    request.bytes[request.len..end].copy_from_slice(&bytes[..read.len]);
    request.len = end;
    if read.fin {
        let request = slot.take().ok_or(Error::Binding)?;
        match control.until_stop(2, requests.send(request)).await {
            Some(result) => result.map_err(|_| Error::Application)?,
            None => return Ok(true),
        }
        state.complete(stream_id)?;
        control.changed()?;
    }
    Ok(read.fin)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::{future::Future, pin::pin, task::{Context, Poll, Waker}};

    struct Requests {
        remaining: usize,
        pending: bool,
        started: usize,
    }

    impl ClientRequests for Requests {
        async fn next(&mut self, output: &mut [u8]) -> Result<Option<usize>, ()> {
            assert!(!self.pending, "next must not overwrite an unstarted request");
            if self.remaining == 0 { return Ok(None); }
            output[0] = b'/';
            self.pending = true;
            Ok(Some(1))
        }

        fn started(&mut self, _stream_id: u64) -> Result<(), ()> {
            assert!(self.pending, "started must correspond to exactly one next");
            self.pending = false;
            self.remaining -= 1;
            self.started += 1;
            Ok(())
        }
    }

    fn ready<T>(future: impl Future<Output = T>) -> T {
        match pin!(future).as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(result) => result,
            Poll::Pending => panic!("bounded request admission unexpectedly parked"),
        }
    }

    #[test]
    fn exactly_sixteen_requests_reach_eof_without_capacity_failure() {
        let state = State::<8>::new();
        let mut requests = Requests { remaining: MAX_REQUESTS, pending: false, started: 0 };
        let mut bytes = [0; REQUEST_BYTES];
        for index in 0..MAX_REQUESTS {
            assert_eq!(ready(next_request(&state, &mut requests, &mut bytes)).unwrap(), Some(1));
            assert!(requests.pending);
            requests.started(index as u64 * 4).unwrap();
            state.submitted().unwrap();
        }
        assert_eq!(ready(next_request(&state, &mut requests, &mut bytes)).unwrap(), None);
        assert_eq!(state.submitted_count(), MAX_REQUESTS);
        assert_eq!(requests.started, MAX_REQUESTS);
        assert!(!requests.pending);
    }

    #[test]
    fn seventeenth_request_is_rejected_while_still_pending() {
        let state = State::<8>::new();
        let mut requests = Requests { remaining: MAX_REQUESTS + 1, pending: false, started: 0 };
        let mut bytes = [0; REQUEST_BYTES];
        for index in 0..MAX_REQUESTS {
            ready(next_request(&state, &mut requests, &mut bytes)).unwrap();
            requests.started(index as u64 * 4).unwrap();
            state.submitted().unwrap();
        }
        assert!(matches!(ready(next_request(&state, &mut requests, &mut bytes)), Err(Error::Capacity)));
        assert!(requests.pending);
        assert_eq!(requests.remaining, 1);
        assert_eq!(requests.started, MAX_REQUESTS);
        assert_eq!(state.submitted_count(), MAX_REQUESTS);
    }
}
