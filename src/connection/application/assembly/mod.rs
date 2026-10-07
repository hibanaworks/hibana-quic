//! The library owns one projected connection from Initial input through
//! authenticated application admission, ordinary role retirement and close.
//! No host callback chooses connection phases or owns a replacement FSM.
mod early;
mod early_client;
pub(super) mod ownership;

use super::{
    BodyReader, ClientRequests, Control, Error, OrdinaryRetired, Outcomes, Report, Roles,
    ServerHandler, Setup, StreamSink, io, keys, receive, reset, termination, timer, transmit,
};
use crate::{
    connection::publication_gate::{Issuer, Stop},
    connection::{
        self, Clock, ConnectionId, DatagramRx, DatagramTx, Side, Storage,
        application_stream::{self, StreamNumbers},
        recovery::Recovery,
        tls::Transcript,
    },
    mailbox::Mailbox,
    streams,
};
use core::cell::RefCell;

/// Run the single connected global with client request and response handlers.
#[allow(clippy::too_many_arguments)]
pub fn client<'scope, const N: usize, const P: usize, const RX: usize, const CHUNK: usize>(
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
) -> impl core::future::Future<Output = Result<Report, Error>> {
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
        None,
    )
}

/// Explicit replay-safe early client. Slot storage is caller-owned and used
/// only for this connection. TLS must already be configured for early data.
#[allow(clippy::too_many_arguments)]
pub async fn client_early<
    'scope,
    const N: usize,
    const P: usize,
    const RX: usize,
    const CHUNK: usize,
>(
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
    slots: &mut [connection::early_client::RequestSlot],
) -> Result<Report, Error> {
    let limits = source.remembered_early_limits().ok_or(Error::Binding)?;
    let mut retained = connection::early_client::Requests::new(
        source.scope(),
        slots,
        limits,
        setup
            .application
            .streams
            .len()
            .min(setup.application.chunks.len())
            .min(setup.application.references.len()),
        CHUNK,
    )?;
    retained.prepare(requests).await?;
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
        Some(&mut retained),
    )
    .await
}

/// Each actual authenticated request is passed to the handler only after FIN.
/// Response bodies are read incrementally into the caller's fixed send chunks.
#[allow(clippy::too_many_arguments)]
pub fn server<'scope, const N: usize, const P: usize, const RX: usize, const CHUNK: usize>(
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
) -> impl core::future::Future<Output = Result<Report, Error>> {
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
        None,
    )
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
    mut client_early: Option<&mut connection::early_client::Requests<'_, 'scope>>,
) -> Result<Report, Error> {
    if !matches!(
        (&source_io, setup.config.side),
        (Source::Client(_), Side::Client) | (Source::Server(_), Side::Server)
    ) {
        return Err(Error::Binding);
    }
    let Setup {
        local_ids,
        peer_ids,
        server_token,
        local_idle_timeout_ms,
        key_update_target,
        config,
        local_limits,
        handshake_crypto,
        application: buffers,
        mut early,
    } = setup;
    if server_token
        .is_some_and(|token| config.side != Side::Server || token.is_empty() || token.len() > 256)
        || CHUNK == 0
        || CHUNK.checked_add(192).is_none_or(|required| required > N)
        || RX == 0
        || buffers.streams.is_empty()
        || buffers.chunks.is_empty()
        || buffers.references.is_empty()
        || buffers.streams.len() > application_stream::MAX_LIVE_STREAMS
    {
        return Err(Error::Capacity);
    }
    let scope = source.scope();
    let (read, write, pending_application) = {
        // Storage is bounded and owned by this finite prefix; dropping it ends
        // every reservation borrow before application facets are issued.
        let storage = if let Some(early) = early.as_mut() {
            Storage::<N, P>::with_early_packets(config.peer_connection_id, &mut early.packets)?
        } else {
            Storage::<N, P>::new(config.peer_connection_id)?
        };

        let (read, write) = connection::handshake_with_early(
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
            &outcomes.handshake_adapter,
            client_early.as_deref_mut(),
        )
        .await?;
        let pending = storage.pending_application.borrow_mut().take();
        (read, write, pending)
    };
    let (mut received, write, transcript) =
        ownership::transfer(roles, source, config, read, write).await?;
    let owner = keys::KeyOwner::new(scope, write)?;
    let exchange = keys::Exchange::new(&owner);
    let (peer, writer, rx_control) =
        ownership::admit(roles, received.peer, &owner, &exchange).await?;
    if peer.max_udp_payload() < (CHUNK + 192) as u64 {
        return Err(Error::Capacity);
    }
    let peer_cid_limit = peer.active_connection_id_limit();
    let peer_id = ConnectionId::new(received.material.peer_connection_id())?;
    let accepted_early = if let Some(requests) = client_early.as_deref() {
        match requests.decision(peer.finished())? {
            crate::early_data::EarlyStatus::Accepted => {
                requests.validate_accepted_limits(peer.parameters())?;
                requests.accepted_count()
            }
            crate::early_data::EarlyStatus::Rejected => 0,
            _ => return Err(Error::Binding),
        }
    } else {
        0
    };
    let peer_parameters = crate::parameters::Parameters::parse(
        peer.parameters(),
        if config.side == Side::Client {
            crate::parameters::Peer::Server
        } else {
            crate::parameters::Peer::Client
        },
        &mut [0; 64],
    )
    .map_err(|_| Error::Binding)?;
    let preferred = peer_parameters
        .get(13)
        .map(crate::path::preferred::Preferred::parse)
        .transpose()
        .map_err(|_| Error::Binding)?;
    let initial_token = peer_parameters
        .get(2)
        .map(|bytes| bytes.try_into().map(crate::connection_id::ResetToken::new))
        .transpose()
        .map_err(|_| Error::Binding)?;
    if peer_id.bytes().is_empty() && initial_token.is_some() {
        return Err(Error::Binding);
    }
    // Zero-length peer CIDs use the authenticated physical address tuple. They
    // cannot be inserted into the nonzero CID/token ledger or invented later.
    let peers = peer_ids
        .filter(|_| !peer_id.bytes().is_empty())
        .map(|storage| {
            crate::path::peer_ids::Peers::new(
                storage,
                scope,
                peer_id.bytes(),
                config.initial_path,
                preferred,
                initial_token,
            )
        })
        .transpose()
        .map_err(|_| Error::Binding)?;
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
        mut publication,
        reset: mut reset_owner,
    } = stream_numbers.split();
    let app = RefCell::new(app);
    let (mut book_tx, mut book_rx, mut book_clock, book_publication, mut retirement) =
        book.split()?;
    let completion_book = book_tx.completion_observer();
    if config.side == Side::Server {
        book_tx.store_handshake_done_token(peer.finished(), server_token)?;
    }
    let early_received = early::receive::<N, RX, CHUNK>(
        roles,
        transcript,
        config,
        early,
        peer.into_finished(),
        &mut received.material.integrity,
        &mut book_rx,
        &mut rx,
        clock,
    )
    .await?;
    let control = Control::new(stop);
    let state = io::State::<CHUNK, H::Body>::new();
    let terminal = termination::Exchange::new(&control, scope);
    let reset_exchange = reset::Exchange::new();
    let reclaim_exchange = super::reclaim::Exchange::new();
    early_client::admit::<N, RX, CHUNK, H::Body>(
        roles,
        client_early.as_deref(),
        accepted_early,
        &app,
        &mut tx,
        &mut publication,
        &state,
        &reclaim_exchange,
    )
    .await?;
    let paths = crate::path::validation::Paths::new(
        config.initial_path,
        config.side,
        local_ids.as_ref().map(|storage| storage.seed),
        preferred,
    );
    let ids = local_ids
        .map(|storage| {
            crate::path::ids::Ids::new(
                storage,
                scope,
                config.local_connection_id,
                peer_cid_limit,
                config.local_preferred,
            )
        })
        .transpose()
        .map_err(|_| Error::Binding)?;
    let publication_state = transmit::State::new(book_publication, publication, ids, paths, peers);
    let ecn_exchange = transmit::ecn::Exchange::new();

    let acknowledgments = super::acknowledgments::Exchange::new();
    let mut request_slots = [const { None }; io::REQUEST_CAPACITY];
    let requests = Mailbox::<io::OwnedRequest, { io::REQUEST_CAPACITY }>::new(&mut request_slots)
        .map_err(|_| Error::Capacity)?;
    let (mut request_sender, mut request_receiver) =
        requests.split().map_err(|_| Error::Binding)?;
    let mut permission = None;
    let first_io_error = RefCell::new(None);

    let result = {
        let source = async {
            let result = match source_io {
                Source::Client(requests) => {
                    if let Some(retained) = client_early.as_deref() {
                        let mut replay = retained.replay(accepted_early);
                        io::client_source(&mut roles.source, &control, &state, &app, &mut replay)
                            .await
                    } else {
                        io::client_source(&mut roles.source, &control, &state, &app, requests).await
                    }
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
                } else {
                    return Err(error);
                }
            }
            Ok::<(), Error>(())
        };
        let ingress = io::ingress(
            &mut roles.ingress,
            &control,
            &state,
            &app,
            &reclaim_exchange,
        );
        let sink = async {
            match sink_io {
                Sink::Client(sink) => {
                    io::client_sink(
                        &mut roles.sink,
                        &control,
                        &state,
                        &app,
                        sink,
                        &reclaim_exchange,
                    )
                    .await
                }
                Sink::Server => {
                    io::server_sink(
                        &mut roles.sink,
                        &control,
                        &state,
                        &app,
                        &mut request_sender,
                        &reclaim_exchange,
                    )
                    .await
                }
            }
        };
        let receiving = async {
            receive::run::<N, RX, CHUNK, _>(
                &mut roles.receive,
                &mut roles.rx_keys,
                &mut roles.peer_event,
                received.material,
                config,
                transcript,
                buffers.crypto,
                &mut book_rx,
                &mut rx,
                &reset_exchange,
                &acknowledgments,
                &app,
                &state,
                rx_control,
                &control,
                clock,
                receive_io,
                &terminal,
                confirmation,
                key_update_target,
                &publication_state.responses,
                &publication_state.ids,
                &publication_state.peers,
                &publication_state.paths,
                pending_application,
            )
            .await
        };
        let key_control = async {
            keys::run(&mut roles.tx_keys, &owner, &exchange)
                .await
                .map_err(Error::from)
        };
        let clock_role = timer::run(&mut roles.clock, &control, &owner, &mut book_clock, clock);
        let timer_receive = timer::receive(&mut roles.tx_clock, &control);
        let transmitting = transmit::run(
            &mut roles.transmit,
            &control,
            &publication_state,
            writer,
            &mut book_tx,
            &mut tx,
            &reset_exchange,
            &reclaim_exchange,
            &acknowledgments,
            config,
            &peer_id,
            clock,
        );
        let publishing = transmit::publish(
            &mut roles.adapter,
            &control,
            &publication_state,
            &ecn_exchange,
            issuer,
            &outcomes.application_reset,
            &reset_exchange,
            &reclaim_exchange,
            &acknowledgments,
            &mut reset_owner,
            send_io,
        );
        let marking =
            transmit::ecn::owner(&mut roles.ecn_owner, &ecn_exchange, &completion_book, clock);
        let path_validation = crate::path::validation::owner(
            &mut roles.handshake.initial_event,
            &publication_state.paths,
            clock,
        );
        let completion = termination::completion(
            &mut roles.files_event,
            &mut roles.source_join,
            &terminal,
            &state,
            &app,
            &completion_book,
            config.side,
            (local_idle_timeout_ms, clock),
        );
        let terminal_receive = async {
            permission = Some(
                termination::receive(&mut roles.peer_close, &mut roles.files_close, &terminal)
                    .await?,
            );
            Ok::<(), Error>(())
        };
        let source_collector =
            super::reclaim::source(&mut roles.source_collector, &reclaim_exchange, &control);
        let input_collector =
            super::reclaim::input(&mut roles.input_collector, &reclaim_exchange, &control);
        let delivery_collector =
            super::reclaim::delivery(&mut roles.delivery_collector, &reclaim_exchange, &control);
        futures_util::try_join!(
            source,
            ingress,
            sink,
            receiving,
            key_control,
            clock_role,
            timer_receive,
            transmitting,
            publishing,
            marking,
            path_validation,
            completion,
            terminal_receive,
            source_collector,
            input_collector,
            delivery_collector,
        )
        .map(|_| ())
    };
    if let Err(error) = result {
        control.revoke()?;
        publication_state.cancel_pending()?;
        retirement.retire_all();
        return Err(error);
    }

    let before_close = book_tx.snapshot();
    let ecn_before_close = completion_book.ecn_observation()?;
    let key_generation = owner.generation()?;
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
    let closing = ownership::retire(
        roles,
        OrdinaryRetired { scope },
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
            receive_io,
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
    if let Some(error) = control.take_protocol_error() {
        return Err(error);
    }
    if !matches!(
        close_kind,
        super::CloseKind::Local {
            application: true,
            code: 0
        } | super::CloseKind::Peer { code: 0 }
            | super::CloseKind::IdleExpired
    ) {
        return Err(Error::Application);
    }
    // An authenticated peer close ends retransmission (RFC 9000 section10.2.2).
    // Complete response delivery is still mandatory. A missing request ACK
    // stays false in the report; peer close must never fabricate that receipt.
    // The explicit ResponsesComplete edge also permits a local application
    // close after every response FIN. It does not assert request transport ACKs.
    if config.side == Side::Client
        && !matches!(close_kind, super::CloseKind::IdleExpired)
        && (!before_close.handshake_confirmed
            || completed_streams == 0
            || completed_streams != state.submitted_count())
    {
        return Err(Error::Incomplete);
    }
    let (validated_paths, preferred_address_used) = publication_state.paths.observation();
    Ok(Report {
        validated_paths,
        preferred_address_used,
        termination: if matches!(close_kind, super::CloseKind::IdleExpired) {
            super::Termination::IdleExpired
        } else {
            super::Termination::Closed
        },
        key_generation,
        early_accepted_packets: early_received.packets + accepted_early,
        early_stream_bytes: early_received.stream_bytes
            + if let Some(requests) = client_early.as_deref() {
                (0..accepted_early).try_fold(0_u64, |sum, index| {
                    requests.bytes(index).map(|bytes| sum + bytes.len() as u64)
                })?
            } else {
                0
            },
        early_finished_streams: early_received.finished_streams + accepted_early,
        confirmed: before_close.handshake_confirmed,
        submitted_streams: state.submitted_count(),
        completed_streams,
        all_streams_acked,
        close_completed: !matches!(close_kind, super::CloseKind::IdleExpired),
        received_bytes: before_close.received_bytes,
        sent_bytes: before_close.accepted_bytes,
        ecn_accepted_packets: ecn_before_close.accepted,
        ecn_validated_packets: ecn_before_close.validated,
        ecn_received_packets: ecn_before_close.received,
        ecn_acknowledgments_sent: ecn_before_close.acknowledgments_sent,
        ecn_feedback_error: ecn_before_close.first_failure.map(|failure| failure.reason),
    })
}
