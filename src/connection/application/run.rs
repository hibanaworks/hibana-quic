//! The library owns one projected connection from Initial input through
//! authenticated application admission, ordinary role retirement and close.
//! No host callback chooses connection phases or owns a replacement FSM.
use super::{
    BodyReader, ClientRequests, Control, Error, OrdinaryRetired, Outcomes, Report, Roles,
    ServerHandler, Setup, StreamSink, io, keys, receive, startup, termination, timer, transmit,
};
use crate::{
    connection::{
        self, Clock, ConnectionId, DatagramRx, DatagramTx, Side, Storage,
        application_stream::{self, StreamNumbers},
        recovery::Recovery,
        tls::Transcript,
    },
    mailbox::Mailbox,
    connection::publication_gate::{Issuer, Stop},
    streams,
};
use core::{cell::RefCell, pin::pin};

/// Run the single connected global with client request and response handlers.
#[allow(clippy::too_many_arguments)]
pub async fn client<'scope, const N: usize, const P: usize, const RX: usize, const CHUNK: usize>(
    roles: &mut Roles<'_>,
    source: &mut Transcript<'scope, '_, '_>,
    setup: Setup<'_, RX, CHUNK>,
    receive: &mut impl DatagramRx,
    send: &mut impl DatagramTx,
    clock: &impl Clock,
    issuer: &mut Issuer<'_, 'scope>,
    stop: Stop<'_, 'scope>,
    book: &mut Recovery<'scope, N>,
    outcomes: &Outcomes,
    requests: &mut impl ClientRequests,
    sink: &mut impl StreamSink,
) -> Result<Report, Error> {
    if setup.config.side != Side::Client {
        return Err(Error::Binding);
    }
    connected::<N, P, RX, CHUNK, _, Unused, _>(
        roles,
        source,
        setup,
        receive,
        send,
        clock,
        issuer,
        stop,
        book,
        outcomes,
        Source::Client(requests),
        Sink::Client(sink),
    )
    .await
}

/// Each actual authenticated request is passed to the handler only after FIN.
/// Response bodies are read incrementally into the caller's fixed send chunks.
#[allow(clippy::too_many_arguments)]
pub async fn server<'scope, const N: usize, const P: usize, const RX: usize, const CHUNK: usize>(
    roles: &mut Roles<'_>,
    source: &mut Transcript<'scope, '_, '_>,
    setup: Setup<'_, RX, CHUNK>,
    receive: &mut impl DatagramRx,
    send: &mut impl DatagramTx,
    clock: &impl Clock,
    issuer: &mut Issuer<'_, 'scope>,
    stop: Stop<'_, 'scope>,
    book: &mut Recovery<'scope, N>,
    outcomes: &Outcomes,
    handler: &mut impl ServerHandler,
) -> Result<Report, Error> {
    if setup.config.side != Side::Server {
        return Err(Error::Binding);
    }
    connected::<N, P, RX, CHUNK, Unused, _, Unused>(
        roles,
        source,
        setup,
        receive,
        send,
        clock,
        issuer,
        stop,
        book,
        outcomes,
        Source::Server(handler),
        Sink::Server,
    )
    .await
}

// These variants select the fixed local application role, never a packet or
// connection-phase branch. The public callers above are the only constructors.
enum Source<'a, C, H> {
    Client(&'a mut C),
    Server(&'a mut H),
}
enum Sink<'a, S> {
    Client(&'a mut S),
    Server,
}
struct Unused;
impl BodyReader for Unused {
    async fn read(&mut self, _: &mut [u8]) -> Result<usize, ()> {
        Err(())
    }
}
impl ClientRequests for Unused {
    async fn next(&mut self, _: &mut [u8]) -> Result<Option<usize>, ()> {
        Err(())
    }
    fn started(&mut self, _: u64) -> Result<(), ()> {
        Err(())
    }
}
impl ServerHandler for Unused {
    type Body = Self;
    async fn open(&mut self, _: u64, _: &[u8]) -> Result<Self::Body, ()> {
        Err(())
    }
}
impl StreamSink for Unused {
    async fn write(&mut self, _: u64, _: &[u8]) -> Result<(), ()> {
        Err(())
    }
    async fn finish(&mut self, _: u64) -> Result<(), ()> {
        Err(())
    }
}

#[allow(clippy::too_many_arguments)]
async fn connected<
    'scope,
    const N: usize,
    const P: usize,
    const RX: usize,
    const CHUNK: usize,
    C: ClientRequests,
    H: ServerHandler,
    S: StreamSink,
>(
    roles: &mut Roles<'_>,
    source: &mut Transcript<'scope, '_, '_>,
    setup: Setup<'_, RX, CHUNK>,
    receive_io: &mut impl DatagramRx,
    send_io: &mut impl DatagramTx,
    clock: &impl Clock,
    issuer: &mut Issuer<'_, 'scope>,
    stop: Stop<'_, 'scope>,
    book: &mut Recovery<'scope, N>,
    outcomes: &Outcomes,
    source_io: Source<'_, C, H>,
    sink_io: Sink<'_, S>,
) -> Result<Report, Error> {
    let Setup {
        config,
        local_limits,
        handshake_crypto,
        application: buffers,
    } = setup;
    if CHUNK == 0
        || CHUNK.checked_add(192).is_none_or(|required| required > N)
        || RX == 0
        || buffers.streams.is_empty()
        || buffers.chunks.is_empty()
        || buffers.references.is_empty()
        || buffers.streams.len() > super::MAX_REQUESTS
    {
        return Err(Error::Capacity);
    }
    let scope = source.scope();
    let (read, write) = {
        // Storage is bounded and owned by this finite prefix; dropping it ends
        // every reservation borrow before application facets are issued.
        let storage = Storage::<N, P>::new(config.peer_connection_id)?;
        connection::handshake(
            &mut roles.handshake,
            source,
            config,
            handshake_crypto,
            receive_io,
            send_io,
            clock,
            issuer,
            &storage,
            book,
            &outcomes.tls,
            &outcomes.handshake_adapter,
        )
        .await?
    };
    let (received, write, transcript) =
        startup::transfer(roles, source, config, read, write).await?;
    let owner = keys::KeyOwner::new(scope, write)?;
    let exchange = keys::Exchange::new(&owner);
    let (peer, writer, rx_control) =
        startup::admit(roles, received.peer, &owner, &exchange).await?;
    if peer.max_udp_payload() < (CHUNK + 192) as u64 {
        return Err(Error::Capacity);
    }
    let peer_id = ConnectionId::new(received.material.peer_connection_id())?;
    let confirmation = book.bind_validated_peer(&peer)?;
    let mut stream_numbers = StreamNumbers::new(
        scope,
        if config.side == Side::Client {
            streams::Role::Client
        } else {
            streams::Role::Server
        },
        peer.limits(),
        local_limits,
        buffers.streams,
        buffers.chunks,
        buffers.references,
    )?;
    let application_stream::Facets {
        app,
        mut rx,
        mut tx,
        publication,
    } = stream_numbers.split();
    let app = RefCell::new(app);
    let (mut book_tx, mut book_rx, mut book_clock, book_publication, mut retirement) =
        book.split()?;
    let completion_book = book_tx.completion_observer();
    let handshake_done = if config.side == Side::Server {
        Some(book_tx.store_handshake_done(peer.finished())?)
    } else {
        None
    };
    let control = Control::new(stop);
    let state = io::State::<CHUNK>::new();
    let publication_state = transmit::State::new(book_publication, publication);
    let terminal = termination::Exchange::new(&control, scope);
    let mut request_slots = [const { None }; io::REQUEST_CAPACITY];
    let requests = Mailbox::<io::OwnedRequest, { io::REQUEST_CAPACITY }>::new(&mut request_slots)
        .map_err(|_| Error::Capacity)?;
    let (mut request_sender, mut request_receiver) =
        requests.split().map_err(|_| Error::Binding)?;
    let mut quiesced = None;
    let mut permission = None;
    let first_io_error = RefCell::new(None);

    let result = {
        let mut source = pin!(async {
            let result = match source_io {
                Source::Client(requests) => {
                    io::client_source(&mut roles.source, &control, &state, &app, requests).await
                }
                Source::Server(handler) => {
                    io::server_source(
                        &mut roles.source,
                        &control,
                        &state,
                        &mut request_receiver,
                        handler,
                    )
                    .await
                }
            };
            if let Err(error) = result {
                // File IO has already settled SourceDone/SourceRetired. Let
                // ApplicationFailed carry its authority before final return.
                if matches!(error, Error::Application | Error::Capacity) {
                    *first_io_error.borrow_mut() = Some(error);
                    control.fail()?;
                } else {
                    return Err(error);
                }
            } else if config.side == Side::Client && state.submitted_count() == 0 {
                *first_io_error.borrow_mut() = Some(Error::Application);
                control.fail()?;
            }
            Ok::<(), Error>(())
        });
        let mut ingress = pin!(io::ingress(&mut roles.ingress, &control, &state, &app));
        let mut sink = pin!(async {
            match sink_io {
                Sink::Client(sink) => {
                    io::client_sink(&mut roles.sink, &control, &state, &app, sink).await
                }
                Sink::Server => {
                    io::server_sink(&mut roles.sink, &control, &state, &app, &mut request_sender)
                        .await
                }
            }
        });
        let mut receiving = pin!(async {
            quiesced = Some(
                receive::run::<N, RX, CHUNK>(
                    &mut roles.receive,
                    &mut roles.rx_keys,
                    &mut roles.peer_event,
                    received.material,
                    config,
                    transcript,
                    buffers.crypto,
                    &mut book_rx,
                    &mut rx,
                    &app,
                    &state,
                    rx_control,
                    &control,
                    clock,
                    receive_io,
                    &terminal,
                    confirmation,
                )
                .await?,
            );
            Ok::<(), Error>(())
        });
        let mut key_control = pin!(async {
            keys::run(&mut roles.tx_keys, &owner, &exchange)
                .await
                .map_err(Error::from)
        });
        let mut clock_role = pin!(timer::run(
            &mut roles.clock,
            &control,
            &owner,
            &mut book_clock,
            clock
        ));
        let mut timer_receive = pin!(timer::receive(&mut roles.tx_clock, &control));
        let mut transmitting = pin!(transmit::run(
            &mut roles.transmit,
            &control,
            &publication_state,
            writer,
            &mut book_tx,
            &mut tx,
            handshake_done,
            config,
            &peer_id,
            clock
        ));
        let mut publishing = pin!(transmit::publish(
            &mut roles.adapter,
            &control,
            &publication_state,
            issuer,
            &outcomes.application_adapter,
            send_io
        ));
        let mut completion = pin!(termination::completion(
            &mut roles.files_event,
            &terminal,
            &state,
            &app,
            &completion_book,
            config.side
        ));
        let mut terminal_receive = pin!(async {
            permission = Some(
                termination::receive(&mut roles.peer_close, &mut roles.files_close, &terminal)
                    .await?,
            );
            Ok::<(), Error>(())
        });
        crate::runtime::TaskSet::new([
            source.as_mut(),
            ingress.as_mut(),
            sink.as_mut(),
            receiving.as_mut(),
            key_control.as_mut(),
            clock_role.as_mut(),
            timer_receive.as_mut(),
            transmitting.as_mut(),
            publishing.as_mut(),
            completion.as_mut(),
            terminal_receive.as_mut(),
        ])
        .await
    };
    if let Err(error) = result {
        control.revoke()?;
        publication_state.cancel_pending()?;
        retirement.retire_all();
        return Err(error);
    }

    let before_close = book_tx.snapshot();
    let completed_streams = if config.side == Side::Client {
        state.completed_count()
    } else {
        state.bodies_finished()
    };
    let all_streams_acked = app.borrow().queued_chunks()? == 0
        && completed_streams == state.submitted_count()
        && (config.side == Side::Client || state.completed_count() == completed_streams);
    // This constructor is reached only after every ordinary future completed,
    // including adapter cancellation, timer acknowledgement and key retirement.
    let closing = startup::retire(
        roles,
        OrdinaryRetired { scope },
        quiesced.ok_or(Error::Binding)?,
        permission.ok_or(Error::Binding)?,
    )
    .await?;
    let close_kind = closing.permission.kind();
    let result = crate::runtime::join2(
        transmit::close(
            &mut roles.transmit,
            &control,
            &publication_state,
            &owner,
            closing,
            &mut book_tx,
            &peer_id,
            clock,
        ),
        transmit::publish_close(
            &mut roles.adapter,
            &publication_state,
            &outcomes.application_adapter,
            send_io,
            clock,
        ),
    )
    .await;
    publication_state.cancel_pending()?;
    retirement.retire_all();
    result?;
    if let Some(error) = first_io_error.into_inner() {
        return Err(error);
    }
    if control.failed() {
        return Err(Error::Application);
    }
    if !matches!(
        close_kind,
        super::CloseKind::Local {
            application: true,
            code: 0
        } | super::CloseKind::Peer { code: 0 }
    ) {
        return Err(Error::Application);
    }
    if config.side == Side::Client
        && (!before_close.handshake_confirmed
            || !all_streams_acked
            || completed_streams == 0
            || !publication_state.close_completed())
    {
        return Err(Error::Incomplete);
    }
    Ok(Report {
        confirmed: before_close.handshake_confirmed,
        submitted_streams: state.submitted_count(),
        completed_streams,
        all_streams_acked,
        close_completed: publication_state.close_completed(),
        received_bytes: before_close.received_bytes,
        sent_bytes: before_close.accepted_bytes,
    })
}
