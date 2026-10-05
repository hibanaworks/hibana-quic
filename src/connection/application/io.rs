//! Role-local bounded HTTP/0.9 source, ingress and sink continuations.
//! Application/file futures never hold a numeric stream borrow. Owned chunks
//! cross the projected source lane; complete bounded GETs cross the request
//! mailbox while the independent source streams a previous response body.

use core::cell::{Cell, RefCell};

use hibana::Endpoint;

use super::{
    BodyReader, ClientRequests, Control, Error, MAX_REQUEST_BYTES, MAX_REQUESTS, ServerHandler,
    StreamSink, protocol as p,
};
use crate::{
    connection::{
        application_stream::{self, App, MAX_LIVE_STREAMS, Production},
        tls::Inbox,
    },
    mailbox::{Receiver, Sender},
    streams::{self, StreamHandle},
};

pub(crate) const REQUEST_BYTES: usize = MAX_REQUEST_BYTES;
// One retained complete request per admitted stream slot. A response body may
// be blocked on transport ACKs, so RX must be able to hand off every admitted
// request without waiting for that body's source to drain this queue.
pub(crate) const REQUEST_CAPACITY: usize = MAX_LIVE_STREAMS;

pub(crate) struct Chunk<const CHUNK: usize> {
    pub bytes: [u8; CHUNK],
    pub len: usize,
}

struct PendingRequest {
    pub stream: StreamHandle,
    pub bytes: [u8; REQUEST_BYTES],
    pub len: usize,
}

pub(crate) struct OwnedRequest<'book> {
    production: Production<'book>,
    bytes: [u8; REQUEST_BYTES],
    len: usize,
}

// The data edge carries either bounded request bytes or the actual response
// reader. This is owned input data, not an independently advanced phase.
enum Input<B, const CHUNK: usize> {
    Chunk(Chunk<CHUNK>),
    Body(B),
}

/// Application observations; protocol progression stays in the local awaits.
pub(crate) struct State<'book, const CHUNK: usize, B> {
    data: Inbox<Input<B, CHUNK>>,
    opened: Inbox<Production<'book>>,
    submitted: Cell<usize>,
    bodies_finished: Cell<usize>,
    done: Cell<bool>,
    completed: RefCell<[Option<StreamHandle>; MAX_LIVE_STREAMS]>,
    completed_total: Cell<usize>,
}
impl<const CHUNK: usize, B> State<'_, CHUNK, B> {
    pub(crate) const fn new() -> Self {
        Self {
            data: Inbox::new(),
            opened: Inbox::new(),
            submitted: Cell::new(0),
            bodies_finished: Cell::new(0),
            done: Cell::new(false),
            completed: RefCell::new([None; MAX_LIVE_STREAMS]),
            completed_total: Cell::new(0),
        }
    }
    pub(crate) fn submitted_count(&self) -> usize {
        self.submitted.get()
    }
    pub(crate) fn bodies_finished(&self) -> usize {
        self.bodies_finished.get()
    }
    pub(crate) fn completed_count(&self) -> usize {
        self.completed_total.get()
    }
    pub(crate) fn source_done(&self) -> bool {
        self.done.get()
    }
    pub(crate) fn is_complete(&self, stream_id: u64) -> bool {
        self.completed
            .borrow()
            .iter()
            .flatten()
            .any(|stream| stream.id() == stream_id)
    }
    pub(super) fn submitted(&self) -> Result<(), Error> {
        let count = self.submitted.get().checked_add(1).ok_or(Error::Capacity)?;
        if count > MAX_REQUESTS {
            return Err(Error::Capacity);
        }
        self.submitted.set(count);
        Ok(())
    }
    fn complete(&self, stream: StreamHandle) -> Result<(), Error> {
        // A new handle in this slot can only originate after the existing
        // three-receipt Hibana reclaim released the old storage. Keep only
        // the live slot's completion identity, plus a cumulative observation.
        let mut completed = self
            .completed
            .try_borrow_mut()
            .map_err(|_| Error::Binding)?;
        let slot = completed.get_mut(stream.slot()).ok_or(Error::Capacity)?;
        if *slot == Some(stream) {
            return Ok(());
        }
        let total = self
            .completed_total
            .get()
            .checked_add(1)
            .ok_or(Error::Capacity)?;
        *slot = Some(stream);
        self.completed_total.set(total);
        Ok(())
    }
}

fn check(actual: u64, expected: u64) -> Result<(), Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(Error::Binding)
    }
}

fn backpressure(error: &application_stream::Error) -> bool {
    matches!(
        error,
        application_stream::Error::Streams(
            streams::Error::Capacity | streams::Error::FlowControl | streams::Error::StreamLimit
        )
    )
}

// Results of one actual ingress exchange, not connection/stream phases.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Admission {
    Accepted,
    Stopped,
    Interrupted,
}

/// Transfer actual owned input before announcing it on the source wire. The
/// ingress response and SourceTaken settle the lane even during shutdown.
async fn submit<const CHUNK: usize, B>(
    endpoint: &mut Endpoint<'_, { p::SOURCE }>,
    state: &State<'_, CHUNK, B>,
    sequence: &mut u64,
    input: Input<B, CHUNK>,
) -> Result<Admission, Error> {
    state.data.put(input).map_err(|_| Error::Binding)?;
    endpoint.send::<p::SourceData>(sequence).await?;
    let reply = endpoint.offer().await?;
    let accepted = match reply.label() {
        1 => {
            check(reply.recv::<p::SourceAccepted>().await?, *sequence)?;
            Admission::Accepted
        }
        2 => {
            check(reply.recv::<p::SourceRejected>().await?, *sequence)?;
            Admission::Interrupted
        }
        187 => {
            check(reply.recv::<p::SourceStopped>().await?, *sequence)?;
            Admission::Stopped
        }
        label => return Err(Error::UnexpectedLabel(label)),
    };
    endpoint.send::<p::SourceTaken>(sequence).await?;
    *sequence = sequence.checked_add(1).ok_or(Error::Binding)?;
    Ok(accepted)
}

// A stream is bound once at the start of its finite production fragment.
async fn begin_stream<'book, const CHUNK: usize, B>(
    endpoint: &mut Endpoint<'_, { p::SOURCE }>,
    state: &State<'book, CHUNK, B>,
    production: Production<'book>,
) -> Result<(), Error> {
    let id = production.id();
    state.opened.put(production).map_err(|_| Error::Binding)?;
    endpoint.send::<p::SourceOpen>(&id).await?;
    Ok(())
}

async fn end_stream(
    endpoint: &mut Endpoint<'_, { p::SOURCE }>,
    stream_id: u64,
    outcome: Admission,
) -> Result<Admission, Error> {
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
        label => Err(Error::UnexpectedLabel(label)),
    }
}

async fn source_finished<const CHUNK: usize, B>(
    endpoint: &mut Endpoint<'_, { p::SOURCE }>,
    control: &Control<'_, '_>,
    state: &State<'_, CHUNK, B>,
    sequence: u64,
) -> Result<(), Error> {
    endpoint.send::<p::SourceDone>(&sequence).await?;
    check(endpoint.recv::<p::SourceRetired>().await?, sequence)?;
    state.done.set(true);
    control.changed()?;
    Ok(())
}

pub(crate) async fn client_source<'book, const RX: usize, const CHUNK: usize, B>(
    endpoint: &mut Endpoint<'_, { p::SOURCE }>,
    control: &Control<'_, '_>,
    state: &State<'book, CHUNK, B>,
    app: &RefCell<App<'book, '_, '_, RX, CHUNK>>,
    requests: &mut impl ClientRequests,
) -> Result<(), Error> {
    let mut sequence = 0;
    let result = client_requests(endpoint, control, state, app, requests, &mut sequence).await;
    if result.is_err() {
        control.fail()?;
    }
    source_finished(endpoint, control, state, sequence).await?;
    result
}

async fn client_requests<'book, const RX: usize, const CHUNK: usize, B>(
    endpoint: &mut Endpoint<'_, { p::SOURCE }>,
    control: &Control<'_, '_>,
    state: &State<'book, CHUNK, B>,
    app: &RefCell<App<'book, '_, '_, RX, CHUNK>>,
    requests: &mut impl ClientRequests,
    sequence: &mut u64,
) -> Result<(), Error> {
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
                // Peer MAX_STREAMS can unblock opening; the fixed local
                // table's Capacity cannot. Its slots are never recycled.
                Err(application_stream::Error::Streams(
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
        begin_stream(endpoint, state, production).await?;
        let result = async {
            let mut offset = 0;
            while offset < len && !control.stopping() {
                let count = (len - offset).min(CHUNK);
                let mut chunk = Chunk {
                    bytes: [0; CHUNK],
                    len: count,
                };
                chunk.bytes[..count].copy_from_slice(&request[offset..offset + count]);
                let admitted = submit(endpoint, state, sequence, Input::Chunk(chunk)).await?;
                if admitted != Admission::Accepted {
                    return Ok(admitted);
                }
                offset += count;
                crate::runtime::yield_now().await;
            }
            Ok::<_, Error>(if offset == len {
                Admission::Accepted
            } else {
                Admission::Interrupted
            })
        }
        .await;
        let finished = end_stream(
            endpoint,
            stream.id(),
            result.as_ref().copied().unwrap_or(Admission::Interrupted),
        )
        .await?;
        result?;
        match finished {
            Admission::Interrupted => return Ok(()),
            Admission::Stopped => continue,
            Admission::Accepted => {}
        }
    }
    Ok(())
}

/// `next` must still be called at the limit so exactly MAX_REQUESTS requests
/// can end normally. An excess pending request is rejected before opening
/// an impossible stream or consuming the caller's pending request via started.
async fn next_request<const CHUNK: usize, B>(
    state: &State<'_, CHUNK, B>,
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
    state: &State<'book, CHUNK, B>,
    requests: &mut Receiver<'_, '_, OwnedRequest<'book>, REQUEST_CAPACITY>,
    handler: &mut H,
) -> Result<(), Error> {
    let mut sequence = 0;
    let result = server_responses(endpoint, control, state, requests, handler, &mut sequence).await;
    if result.is_err() {
        control.fail()?;
    }
    requests.close();
    source_finished(endpoint, control, state, sequence).await?;
    result
}

async fn server_responses<'book, const CHUNK: usize, B: BodyReader, H: ServerHandler<Body = B>>(
    endpoint: &mut Endpoint<'_, { p::SOURCE }>,
    control: &Control<'_, '_>,
    state: &State<'book, CHUNK, B>,
    requests: &mut Receiver<'_, '_, OwnedRequest<'book>, REQUEST_CAPACITY>,
    handler: &mut H,
    sequence: &mut u64,
) -> Result<(), Error> {
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
        begin_stream(endpoint, state, request.production).await?;
        // The actual reader moves once through the Hibana data edge. Ingress
        // alone owns the reader until EOF, failure or cancellation; each packet
        // still uses its ordinary bounded send chunk and publication contract.
        let result = submit(endpoint, state, sequence, Input::Body(body)).await;
        let finished = end_stream(
            endpoint,
            stream_id,
            result.as_ref().copied().unwrap_or(Admission::Interrupted),
        )
        .await?;
        result?;
        match finished {
            Admission::Interrupted => return Ok(()),
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

pub(crate) async fn ingress<'book, const RX: usize, const CHUNK: usize, B: BodyReader>(
    endpoint: &mut Endpoint<'_, { p::INGRESS }>,
    control: &Control<'_, '_>,
    state: &State<'book, CHUNK, B>,
    app: &RefCell<App<'book, '_, '_, RX, CHUNK>>,
    reclaim: &super::reclaim::Exchange<'book>,
) -> Result<(), Error> {
    let mut sequence = 0;
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
                            check(offered.recv::<p::SourceData>().await?, sequence)?;
                            let input = state.data.take().map_err(|_| Error::Binding)?;
                            let result = match input {
                                Input::Chunk(chunk) => {
                                    admit(control, app, &mut production, &chunk, false).await
                                }
                                Input::Body(body) => {
                                    read_body(control, app, &mut production, body).await
                                }
                            };
                            let accepted = match result {
                                Ok(accepted) => accepted,
                                Err(_) => {
                                    control.fail()?;
                                    Admission::Interrupted
                                }
                            };
                            match accepted {
                                Admission::Accepted => {
                                    endpoint.send::<p::SourceAccepted>(&sequence).await?
                                }
                                Admission::Stopped => {
                                    endpoint.send::<p::SourceStopped>(&sequence).await?
                                }
                                Admission::Interrupted => {
                                    endpoint.send::<p::SourceRejected>(&sequence).await?
                                }
                            }
                            check(endpoint.recv::<p::SourceTaken>().await?, sequence)?;
                            sequence = sequence.checked_add(1).ok_or(Error::Binding)?;
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
                            Err(_) => {
                                control.fail()?;
                                Admission::Interrupted
                            }
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
                }
            }
            4 => {
                check(offered.recv::<p::SourceDone>().await?, sequence)?;
                if !state.data.is_empty() {
                    control.fail()?;
                }
                endpoint.send::<p::ProductionReclaimsDone>(&0).await?;
                check(endpoint.recv::<p::ProductionReclaimsClosed>().await?, 0)?;
                endpoint.send::<p::SourceRetired>(&sequence).await?;
                return Ok(());
            }
            label => return Err(Error::UnexpectedLabel(label)),
        }
    }
}

// A body is a data resource, not a control phase. Only a real zero-length
// read means EOF. No FIN or successful completion is manufactured on stop.
async fn read_body<B: BodyReader, const RX: usize, const CHUNK: usize>(
    control: &Control<'_, '_>,
    app: &RefCell<App<'_, '_, '_, RX, CHUNK>>,
    production: &mut Production<'_>,
    mut body: B,
) -> Result<Admission, Error> {
    let mut work = 0usize;
    while !control.stopping() {
        let mut chunk = Chunk {
            bytes: [0; CHUNK],
            len: 0,
        };
        let len = match control.until_stop(1, body.read(&mut chunk.bytes)).await {
            Some(result) => result.map_err(|_| Error::Application)?,
            None => return Ok(Admission::Interrupted),
        };
        if len > CHUNK {
            return Err(Error::Capacity);
        }
        if len == 0 {
            return Ok(Admission::Accepted);
        }
        chunk.len = len;
        let accepted = admit(control, app, production, &chunk, false).await?;
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

async fn admit<const RX: usize, const CHUNK: usize>(
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
            Err(application_stream::Error::Streams(streams::Error::SendClosed)) => {
                return Ok(Admission::Stopped);
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
    let ready = app
        .try_borrow()
        .map_err(|_| Error::Binding)?
        .ready_streams()?;
    ready
        .into_iter()
        .flatten()
        .find(|stream| stream.id() == stream_id)
        .ok_or(Error::Binding)
}

pub(crate) async fn client_sink<'book, const RX: usize, const CHUNK: usize, B>(
    endpoint: &mut Endpoint<'_, { p::SINK }>,
    control: &Control<'_, '_>,
    state: &State<'book, CHUNK, B>,
    app: &RefCell<App<'book, '_, '_, RX, CHUNK>>,
    sink: &mut impl StreamSink,
    reclaim: &super::reclaim::Exchange<'book>,
) -> Result<(), Error> {
    loop {
        let offered = endpoint.offer().await?;
        match offered.label() {
            6 => {
                let stream_id = offered.recv::<p::ReceivedData>().await?;
                let done = if control.stopping() || state.is_complete(stream_id) {
                    true
                } else {
                    match deliver(control, state, app, sink, stream_id).await {
                        Ok(done) => done,
                        Err(_) => {
                            control.fail()?;
                            true
                        }
                    }
                };
                if done {
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
                    endpoint.send::<p::ReceivedFin>(&stream_id).await?;
                } else {
                    endpoint.send::<p::ReceivedMore>(&stream_id).await?;
                }
            }
            9 => {
                let sequence = offered.recv::<p::ReceiveRetire>().await?;
                endpoint.send::<p::InputReclaimsDone>(&0).await?;
                check(endpoint.recv::<p::InputReclaimsClosed>().await?, 0)?;
                endpoint.send::<p::ReceiveRetired>(&sequence).await?;
                return Ok(());
            }
            label => return Err(Error::UnexpectedLabel(label)),
        }
    }
}

async fn deliver<const RX: usize, const CHUNK: usize, B>(
    control: &Control<'_, '_>,
    state: &State<'_, CHUNK, B>,
    app: &RefCell<App<'_, '_, '_, RX, CHUNK>>,
    sink: &mut impl StreamSink,
    stream_id: u64,
) -> Result<bool, Error> {
    let stream = ready_handle(app, stream_id)?;
    // Receive delivery uses its actual receive window, not the unrelated
    // outbound chunk size. One datagram must not require several sink rounds.
    let mut bytes = [0; RX];
    let read = app
        .try_borrow_mut()
        .map_err(|_| Error::Binding)?
        .read(stream, &mut bytes)?;
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
            None => return Ok(true),
        }
    }
    if read.fin {
        match control.until_stop(2, sink.finish(stream_id)).await {
            Some(result) => result.map_err(|_| Error::Application)?,
            None => return Ok(true),
        }
        state.complete(stream)?;
        control.changed()?;
    }
    Ok(read.fin)
}

pub(crate) async fn server_sink<'book, const RX: usize, const CHUNK: usize, B>(
    endpoint: &mut Endpoint<'_, { p::SINK }>,
    control: &Control<'_, '_>,
    state: &State<'book, CHUNK, B>,
    app: &RefCell<App<'book, '_, '_, RX, CHUNK>>,
    requests: &mut Sender<'_, '_, OwnedRequest<'book>, REQUEST_CAPACITY>,
    reclaim: &super::reclaim::Exchange<'book>,
) -> Result<(), Error> {
    let mut pending: [Option<PendingRequest>; MAX_LIVE_STREAMS] =
        [const { None }; MAX_LIVE_STREAMS];
    loop {
        let offered = endpoint.offer().await?;
        match offered.label() {
            6 => {
                let stream_id = offered.recv::<p::ReceivedData>().await?;
                let done = if control.stopping() || state.is_complete(stream_id) {
                    true
                } else {
                    match receive_request(control, state, app, requests, &mut pending, stream_id)
                        .await
                    {
                        Ok(done) => done,
                        Err(_) => {
                            control.fail()?;
                            true
                        }
                    }
                };
                if done {
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
                    endpoint.send::<p::ReceivedFin>(&stream_id).await?;
                } else {
                    endpoint.send::<p::ReceivedMore>(&stream_id).await?;
                }
            }
            9 => {
                let sequence = offered.recv::<p::ReceiveRetire>().await?;
                requests.close();
                endpoint.send::<p::InputReclaimsDone>(&0).await?;
                check(endpoint.recv::<p::InputReclaimsClosed>().await?, 0)?;
                endpoint.send::<p::ReceiveRetired>(&sequence).await?;
                return Ok(());
            }
            label => return Err(Error::UnexpectedLabel(label)),
        }
    }
}

async fn receive_request<'book, const RX: usize, const CHUNK: usize, B>(
    control: &Control<'_, '_>,
    state: &State<'book, CHUNK, B>,
    app: &RefCell<App<'book, '_, '_, RX, CHUNK>>,
    requests: &mut Sender<'_, '_, OwnedRequest<'book>, REQUEST_CAPACITY>,
    pending: &mut [Option<PendingRequest>; MAX_LIVE_STREAMS],
    stream_id: u64,
) -> Result<bool, Error> {
    let stream = ready_handle(app, stream_id)?;
    // Receive delivery uses its actual receive window, not the unrelated
    // outbound chunk size. One datagram must not require several sink rounds.
    let mut bytes = [0; RX];
    let read = app
        .try_borrow_mut()
        .map_err(|_| Error::Binding)?
        .read(stream, &mut bytes)?;
    control.changed()?;
    if read.reset.is_some() {
        return Err(Error::Application);
    }
    let slot = pending.get_mut(stream.slot()).ok_or(Error::Capacity)?;
    let request = slot.get_or_insert_with(|| PendingRequest {
        stream,
        bytes: [0; REQUEST_BYTES],
        len: 0,
    });
    if request.stream != stream {
        return Err(Error::Binding);
    }
    let end = request
        .len
        .checked_add(read.len)
        .filter(|len| *len <= REQUEST_BYTES)
        .ok_or(Error::Capacity)?;
    request.bytes[request.len..end].copy_from_slice(&bytes[..read.len]);
    request.len = end;
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
            None => return Ok(true),
        }
        state.complete(stream)?;
        control.changed()?;
    }
    Ok(read.fin)
}

#[cfg(test)]
struct EmptyBody;
#[cfg(test)]
impl BodyReader for EmptyBody {
    async fn read(&mut self, _: &mut [u8]) -> Result<usize, ()> {
        panic!("chunk-only fixture must not read a body")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };

    #[test]
    fn all_admitted_requests_enqueue_while_response_source_is_paused() {
        let mut slots = [None; REQUEST_CAPACITY];
        let mailbox = crate::mailbox::Mailbox::new(&mut slots).unwrap();
        let (mut sender, mut receiver) = mailbox.split().unwrap();
        // No consumer poll occurs until all admitted stream requests arrive.
        // An eight-entry queue parks here before RX can receive transport ACKs.
        for stream in 0..MAX_LIVE_STREAMS {
            ready(sender.send(stream)).unwrap();
        }
        for stream in 0..MAX_LIVE_STREAMS {
            assert_eq!(ready(receiver.recv()).unwrap(), stream);
        }
    }

    struct Requests {
        remaining: usize,
        pending: bool,
        started: usize,
    }

    impl ClientRequests for Requests {
        async fn next(&mut self, output: &mut [u8]) -> Result<Option<usize>, ()> {
            assert!(
                !self.pending,
                "next must not overwrite an unstarted request"
            );
            if self.remaining == 0 {
                return Ok(None);
            }
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
        match pin!(future)
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(result) => result,
            Poll::Pending => panic!("bounded request admission unexpectedly parked"),
        }
    }

    #[test]
    fn exactly_sixteen_requests_reach_eof_without_capacity_failure() {
        let state = State::<8, EmptyBody>::new();
        let mut requests = Requests {
            remaining: MAX_REQUESTS,
            pending: false,
            started: 0,
        };
        let mut bytes = [0; REQUEST_BYTES];
        for index in 0..MAX_REQUESTS {
            assert_eq!(
                ready(next_request(&state, &mut requests, &mut bytes)).unwrap(),
                Some(1)
            );
            assert!(requests.pending);
            requests.started(index as u64 * 4).unwrap();
            state.submitted().unwrap();
        }
        assert_eq!(
            ready(next_request(&state, &mut requests, &mut bytes)).unwrap(),
            None
        );
        assert_eq!(state.submitted_count(), MAX_REQUESTS);
        assert_eq!(requests.started, MAX_REQUESTS);
        assert!(!requests.pending);
    }

    #[test]
    fn seventeenth_request_is_rejected_while_still_pending() {
        let state = State::<8, EmptyBody>::new();
        let mut requests = Requests {
            remaining: MAX_REQUESTS + 1,
            pending: false,
            started: 0,
        };
        let mut bytes = [0; REQUEST_BYTES];
        for index in 0..MAX_REQUESTS {
            ready(next_request(&state, &mut requests, &mut bytes)).unwrap();
            requests.started(index as u64 * 4).unwrap();
            state.submitted().unwrap();
        }
        assert!(matches!(
            ready(next_request(&state, &mut requests, &mut bytes)),
            Err(Error::Capacity)
        ));
        assert!(requests.pending);
        assert_eq!(requests.remaining, 1);
        assert_eq!(requests.started, MAX_REQUESTS);
        assert_eq!(state.submitted_count(), MAX_REQUESTS);
    }
}

#[cfg(test)]
mod stop_tests {
    use super::*;
    use crate::{
        carrier::CarrierStorage,
        connection::{
            application_stream::{Facets, StreamNumbers},
            publication_gate::PublicationGate,
        },
        crypto::directional::ApplicationKeyScope,
        streams::{Limits, PacketReference, Role, SendChunk, StreamSlot},
    };
    use core::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };
    use hibana::runtime::{
        SessionKitStorage,
        ids::SessionId,
        program::{RoleProgram, project},
    };

    struct CountingBody<'a> {
        drops: &'a Cell<usize>,
        reads: &'a Cell<usize>,
        byte: Option<u8>,
        fail: bool,
    }
    impl BodyReader for CountingBody<'_> {
        async fn read(&mut self, output: &mut [u8]) -> Result<usize, ()> {
            let mut yielded = false;
            core::future::poll_fn(|cx| {
                if !yielded {
                    yielded = true;
                    cx.waker().wake_by_ref();
                    Poll::Pending
                } else {
                    Poll::Ready(())
                }
            })
            .await;
            self.reads.set(self.reads.get() + 1);
            if self.fail {
                return Err(());
            }
            match self.byte.take() {
                Some(byte) => {
                    output[0] = byte;
                    Ok(1)
                }
                None => Ok(0),
            }
        }
    }
    impl Drop for CountingBody<'_> {
        fn drop(&mut self) {
            self.drops.set(self.drops.get() + 1);
        }
    }

    fn stopped_ingress(fin: bool, body: bool, fail_second: bool) {
        let mut scope = ApplicationKeyScope::new(912);
        let mut installation = scope.claim().unwrap();
        let mut gate = PublicationGate::new(installation.take_publication_gate().unwrap());
        let (_issuer, stop) = gate.split().unwrap();
        let control = Control::new(stop);
        let limits = Limits {
            max_data: 16,
            max_streams_bidi: 2,
            max_streams_uni: 0,
            stream_data_bidi_local: 8,
            stream_data_bidi_remote: 8,
            stream_data_uni: 0,
        };
        let mut slots = [StreamSlot::<8>::EMPTY; 2];
        let mut chunks = [SendChunk::<8>::EMPTY; 4];
        let mut refs = [PacketReference::EMPTY; 4];
        let mut numbers = StreamNumbers::new(
            installation.scope(),
            Role::Client,
            limits,
            Limits {
                max_streams_bidi: 0,
                ..limits
            },
            &mut slots,
            &mut chunks,
            &mut refs,
        )
        .unwrap();
        let Facets {
            mut app,
            mut rx,
            reset: mut effects,
            ..
        } = numbers.split();
        let first = app.open_local().unwrap();
        let first_production = app.take_production(first).unwrap();
        effects
            .apply(rx.stop_intent(first.id(), 7).unwrap())
            .unwrap();
        let second = app.open_local().unwrap();
        let second_production = app.take_production(second).unwrap();
        let app = RefCell::new(app);
        let drops = Cell::new(0);
        let reads = Cell::new(0);
        let state = State::<8, CountingBody<'_>>::new();
        let global = p::source_choreography();
        let source: RoleProgram<{ p::SOURCE }> = project(&global);
        let ingress_role: RoleProgram<{ p::INGRESS }> = project(&global);
        let collector_role: RoleProgram<{ p::SOURCE_COLLECTOR }> = project(&global);
        let reclaim = super::super::reclaim::Exchange::new();
        let carrier = CarrierStorage::<1, 16, 8>::new();
        let mut slab = [0; 65536];
        let mut storage = SessionKitStorage::uninit();
        let id = SessionId::new(912);
        let rv = storage
            .init()
            .rendezvous(&mut slab, carrier.bind(id).unwrap())
            .unwrap();
        let mut source = rv.enter(id, &source).unwrap();
        let mut input = rv.enter(id, &ingress_role).unwrap();
        let mut collector = rv.enter(id, &collector_role).unwrap();
        let allocations = actor_test_allocator::NoAlloc::start();
        let mut all = pin!(crate::runtime::join2(
            async {
                let mut sequence = 0;
                begin_stream(&mut source, &state, first_production).await?;
                let outcome = if fin {
                    Admission::Accepted
                } else {
                    let result = submit(
                        &mut source,
                        &state,
                        &mut sequence,
                        if body {
                            Input::Body(CountingBody {
                                drops: &drops,
                                reads: &reads,
                                byte: Some(1),
                                fail: false,
                            })
                        } else {
                            Input::Chunk(Chunk {
                                bytes: [1; 8],
                                len: 1,
                            })
                        },
                    )
                    .await?;
                    assert!(result == Admission::Stopped);
                    result
                };
                assert!(end_stream(&mut source, first.id(), outcome).await? == Admission::Stopped);
                assert!(!control.failed());
                assert!(!control.stopping());
                begin_stream(&mut source, &state, second_production).await?;
                let second_outcome = submit(
                    &mut source,
                    &state,
                    &mut sequence,
                    if body {
                        Input::Body(CountingBody {
                            drops: &drops,
                            reads: &reads,
                            byte: Some(2),
                            fail: fail_second,
                        })
                    } else {
                        Input::Chunk(Chunk {
                            bytes: [2; 8],
                            len: 1,
                        })
                    },
                )
                .await?;
                let expected = if fail_second {
                    Admission::Interrupted
                } else {
                    Admission::Accepted
                };
                assert!(second_outcome == expected);
                assert!(end_stream(&mut source, second.id(), second_outcome).await? == expected);
                assert_eq!(control.failed(), fail_second);
                source_finished(&mut source, &control, &state, sequence).await?;
                Ok::<_, Error>(())
            },
            crate::runtime::join2(
                ingress(&mut input, &control, &state, &app, &reclaim),
                super::super::reclaim::source(&mut collector, &reclaim, &control)
            )
        ));
        for _ in 0..1000 {
            if let Poll::Ready(result) = all.as_mut().poll(&mut Context::from_waker(Waker::noop()))
            {
                result.unwrap();
                allocations.finish();
                if body {
                    // The stopped body is read once, never reaches EOF, and
                    // is dropped once. The next body is read through real EOF.
                    assert_eq!(reads.get(), if fail_second { 2 } else { 3 });
                    assert_eq!(drops.get(), 2);
                }
                return;
            }
        }
        panic!("real ingress stalled after peer stop");
    }
    #[test]
    fn actual_ingress_preserves_connection_after_stopped_data_and_fin() {
        stopped_ingress(false, false, false);
        stopped_ingress(true, false, false);
    }
    #[test]
    fn actual_owned_body_moves_once_and_stop_does_not_fabricate_eof() {
        stopped_ingress(false, true, false);
    }
    #[test]
    fn actual_body_read_failure_is_rejected_without_a_successful_eof() {
        stopped_ingress(false, true, true);
    }
}
