//! Host allocation and endpoint attachment for one direct Hibana global.
use super::direct_wire::{HostClock, Receive, Transmit};
use super::{application_storage, host_files};
use hibana::runtime::{SessionKitStorage, ids::SessionId};
use hibana_quic::{
    carrier::CarrierStorage,
    connection::publication_gate::{Issuer, Stop},
    connection::{
        self, Config, Outcome, Roles, Side, Storage, application, protocol, recovery::Recovery,
        tls::Transcript,
    },
    handshake::CryptoBuffer,
};
pub const DATAGRAM: usize = 1536;
pub const PARAMETERS: usize = 2048;
#[allow(clippy::too_many_arguments)]
pub async fn handshake<'scope>(
    source: &mut Transcript<'scope, '_, '_>,
    config: Config<'_>,
    receive: &mut Receive<'_, '_>,
    transmit: &mut Transmit<'_, '_>,
    clock: &HostClock<'_>,
    issuer: &mut Issuer<'_, 'scope>,
    book: &mut Recovery<'scope, DATAGRAM>,
    generation: u64,
) -> Result<
    (
        connection::ReceiveContinuation<'scope, PARAMETERS>,
        connection::TransmitContinuation<'scope>,
    ),
    String,
> {
    let mut initial = vec![0; 8192];
    let mut handshake = vec![0; 16384];
    let mut initial_bitmap = vec![0; 1024];
    let mut handshake_bitmap = vec![0; 2048];
    let reassembly = [
        CryptoBuffer::new(&mut initial, &mut initial_bitmap)
            .map_err(|e| format!("Initial storage: {e:?}"))?,
        CryptoBuffer::new(&mut handshake, &mut handshake_bitmap)
            .map_err(|e| format!("Handshake storage: {e:?}"))?,
    ];
    let programs = protocol::programs();
    let tls_result = Outcome::new();
    let adapter_result = Outcome::new();
    let queues = Box::new(CarrierStorage::<1, 16, 64>::new());
    let mut slab = vec![0; 64 * 1024];
    let mut kit_storage = Box::new(SessionKitStorage::uninit());
    let kit = kit_storage.init();
    // One session per kit. Full generation is retained by cryptographic scope.
    let session = SessionId::new(generation as u32);
    let rendezvous = kit
        .rendezvous(
            &mut slab,
            queues
                .bind(session)
                .map_err(|e| format!("carrier: {e:?}"))?,
        )
        .map_err(|e| format!("rendezvous: {e:?}"))?;
    rendezvous
        .set_resolver(
            &programs.udp,
            adapter_result.resolver::<{ protocol::ADAPTER_RESULT }>(),
        )
        .map_err(|e| format!("adapter resolver: {e:?}"))?;
    macro_rules! enter {
        ($name:ident) => {
            rendezvous
                .enter(session, &programs.$name)
                .map_err(|e| format!("{} role: {e:?}", stringify!($name)))?
        };
    }
    let mut roles = Roles {
        rx: enter!(rx),
        tls_rx: enter!(tls_rx),
        tx: enter!(tx),
        tx_wire: enter!(tx_wire),
        tls_tx: enter!(tls_tx),
        udp: enter!(udp),
        timer: enter!(timer),
        timer_tx: enter!(timer_tx),
        initial_event: enter!(initial_event),
        initial_owner: enter!(initial_owner),
    };
    let storage = Box::new(
        Storage::<DATAGRAM, PARAMETERS>::new(config.peer_connection_id)
            .map_err(|e| format!("wire storage: {e:?}"))?,
    );
    let result = Box::pin(connection::handshake(
        &mut roles,
        source,
        config,
        reassembly,
        receive,
        transmit,
        clock,
        issuer,
        &storage,
        book,
        &tls_result,
        &adapter_result,
    ))
    .await
    .map_err(|e| format!("direct connection: {e:?}"));
    drop(storage);
    if result.is_ok() && queues.queued() != 0 {
        return Err("wire roles left queued carrier frames".into());
    }
    result
}

/// This selects only local file handlers. The library owns the authenticated
/// prefix, affine handoff, stream work, retirement, closing and draining.
pub enum Files {
    Client(host_files::Client),
    Server(host_files::FileServer),
}

impl Files {
    pub fn local_limits(&self) -> hibana_quic::streams::Limits {
        match self {
            Self::Client(client) => {
                if application_storage::client_uses_large_window(client.count) {
                    application_storage::local_limits::<{ application_storage::CLIENT_RECEIVE_BYTES }>(
                        Side::Client,
                        client.count,
                    )
                } else {
                    application_storage::local_limits::<{ application_storage::RECEIVE_BYTES }>(
                        Side::Client,
                        client.count,
                    )
                }
            }
            Self::Server(_) => application_storage::local_limits::<
                { application_storage::RECEIVE_BYTES },
            >(Side::Server, application_storage::STREAMS),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn files<'scope>(
    source: &mut Transcript<'scope, '_, '_>,
    config: Config<'_>,
    receive: &mut Receive<'_, '_>,
    transmit: &mut Transmit<'_, '_>,
    clock: &HostClock<'_>,
    issuer: &mut Issuer<'_, 'scope>,
    stop: Stop<'_, 'scope>,
    book: &mut Recovery<'scope, DATAGRAM>,
    generation: u64,
    files: &mut Files,
    mut early: Option<application_storage::EarlyStorage>,
) -> Result<application::Report, String> {
    let programs = application::protocol::programs();
    // Resolver states precede the kit so all endpoint borrows expire first.
    let outcomes = application::Outcomes::new();
    let queues = Box::new(CarrierStorage::<1, 32, 128>::new());
    let mut slab = vec![0; 256 * 1024];
    let mut kit_storage = Box::new(SessionKitStorage::uninit());
    let kit = kit_storage.init();
    let session = SessionId::new(generation as u32);
    let rendezvous = kit
        .rendezvous(
            &mut slab,
            queues
                .bind(session)
                .map_err(|e| format!("carrier: {e:?}"))?,
        )
        .map_err(|e| format!("rendezvous: {e:?}"))?;

    rendezvous
        .set_resolver(
            &programs.handshake.udp,
            outcomes
                .handshake_adapter
                .resolver::<{ protocol::ADAPTER_RESULT }>(),
        )
        .map_err(|e| format!("handshake adapter resolver: {e:?}"))?;
    rendezvous
        .set_resolver(
            &programs.adapter,
            outcomes
                .application_adapter
                .resolver::<{ application::protocol::SUBMISSION_RESULT }>(),
        )
        .map_err(|e| format!("application adapter resolver: {e:?}"))?;
    rendezvous
        .set_resolver(
            &programs.adapter,
            outcomes
                .application_reset
                .resolver::<{ application::protocol::STOP_RESULT }>(),
        )
        .map_err(|e| format!("application reset resolver: {e:?}"))?;
    macro_rules! enter {
        ($program:expr) => {
            rendezvous
                .enter(session, &$program)
                .map_err(|e| format!("{} role: {e:?}", stringify!($program)))?
        };
    }
    let mut roles = application::Roles {
        handshake: Roles {
            rx: enter!(programs.handshake.rx),
            tls_rx: enter!(programs.handshake.tls_rx),
            tx: enter!(programs.handshake.tx),
            tx_wire: enter!(programs.handshake.tx_wire),
            tls_tx: enter!(programs.handshake.tls_tx),
            udp: enter!(programs.handshake.udp),
            timer: enter!(programs.handshake.timer),
            timer_tx: enter!(programs.handshake.timer_tx),
            initial_event: enter!(programs.handshake.initial_event),
            initial_owner: enter!(programs.handshake.initial_owner),
        },
        source: enter!(programs.source),
        ingress: enter!(programs.ingress),
        receive: enter!(programs.receive),
        sink: enter!(programs.sink),
        rx_keys: enter!(programs.rx_keys),
        tx_keys: enter!(programs.tx_keys),
        clock: enter!(programs.clock),
        tx_clock: enter!(programs.tx_clock),
        transmit: enter!(programs.transmit),
        adapter: enter!(programs.adapter),
        peer_event: enter!(programs.peer_event),
        peer_close: enter!(programs.peer_close),
        files_event: enter!(programs.files_event),
        files_close: enter!(programs.files_close),
        close_join: enter!(programs.close_join),
        source_collector: enter!(programs.source_collector),
        input_collector: enter!(programs.input_collector),
        delivery_collector: enter!(programs.delivery_collector),
    };
    let result = match files {
        Files::Client(client) => {
            macro_rules! run_client {
                ($rx:expr) => {{
                    let mut storage = application_storage::Storage::<$rx>::new(client.count)?;
                    let setup = storage.setup(config)?;
                    if source.early_status() == hibana_quic::early_data::EarlyStatus::Offered {
                        let mut early_slots = (0..client.count)
                            .map(|_| hibana_quic::connection::early_client::RequestSlot::EMPTY)
                            .collect::<Vec<_>>();
                        Box::pin(application::client_early::<
                            DATAGRAM,
                            PARAMETERS,
                            $rx,
                            { application_storage::CHUNK_BYTES },
                        >(
                            &mut roles,
                            source,
                            setup,
                            receive,
                            transmit,
                            clock,
                            issuer,
                            stop,
                            book,
                            &outcomes,
                            &mut client.requests,
                            &mut client.downloads,
                            &mut early_slots,
                        ))
                        .await
                    } else {
                        Box::pin(application::client::<
                            DATAGRAM,
                            PARAMETERS,
                            $rx,
                            { application_storage::CHUNK_BYTES },
                        >(
                            &mut roles,
                            source,
                            setup,
                            receive,
                            transmit,
                            clock,
                            issuer,
                            stop,
                            book,
                            &outcomes,
                            &mut client.requests,
                            &mut client.downloads,
                        ))
                        .await
                    }
                }};
            }
            if application_storage::client_uses_large_window(client.count) {
                run_client!({ application_storage::CLIENT_RECEIVE_BYTES })
            } else {
                run_client!({ application_storage::RECEIVE_BYTES })
            }
        }
        Files::Server(server) => {
            let mut storage =
                application_storage::Storage::<{ application_storage::RECEIVE_BYTES }>::new(
                    application_storage::STREAMS,
                )?;
            let mut setup = storage.setup(config)?;
            setup.early = early
                .as_mut()
                .map(application_storage::EarlyStorage::borrow);
            Box::pin(application::server::<
                DATAGRAM,
                PARAMETERS,
                { application_storage::RECEIVE_BYTES },
                { application_storage::CHUNK_BYTES },
            >(
                &mut roles, source, setup, receive, transmit, clock, issuer, stop, book, &outcomes,
                server,
            ))
            .await
        }
    }
    .map_err(|e| format!("direct application: {e:?}"));
    if result.is_err() && std::env::var("HIBANA_QUIC_DIAGNOSTICS").as_deref() == Ok("1") {
        for event in rendezvous.tap() {
            eprintln!("direct Hibana runtime: {event:?}");
        }
    }
    if result.is_ok() && queues.queued() != 0 {
        return Err("connected roles left queued carrier frames".into());
    }
    result
}
