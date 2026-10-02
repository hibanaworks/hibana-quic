//! Full host-profile resource bootstrap for the actual owned connection roles.
//!
//! The encompassing session owns every projected endpoint until all actors have
//! joined. Each mutable kernel and its fixed backing store belong exclusively
//! to its role. The application receives affine clients and a shared packet
//! authority arena; it cannot borrow the owners' mutable stores.
use hibana::{
    g,
    runtime::{SessionKitStorage, ids::SessionId, program::project},
};
use hibana_quic::{
    carrier::CarrierStorage,
    connection_id::{LocalCidSlot, PeerCidSlot},
    crypto::InitialKeys,
    early_data::{QuarantineSlot, ServerPolicy},
    early_send::RequestSlot,
    handshake_endpoint::{
        EARLY_COMMAND_BYTES, EARLY_CONTROL_BYTES, EARLY_REQUEST_BYTES, EarlyExchange, EarlyStarter,
        EarlyStorage, INITIAL_PACKET_BYTES, InitialKeyClient, InitialProtection, NetworkConfig,
        PacketAuthority, RecoveryClient, RecoveryExchange, RecoveryOwner, STREAM_FRAME_BYTES, Side,
        StreamClient, TLS_PACKET_BYTES, TLS_PARAMETER_BYTES, TlsClient,
    },
    mailbox::Mailbox,
    migration,
    path::PathSlot,
    recovery,
    roles::{
        early_owner, packet_protection, path_owner, protocol::key_choreography,
        protocol_early::early_choreography, protocol_path::path_choreography,
        protocol_recovery::recovery_choreography, protocol_stream::stream_choreography,
        protocol_tls::tls_choreography, recovery_owner, stream_owner, tls_owner,
    },
    runtime::{Task, TaskSet},
    streams::{self, Limits, PacketReference, SendChunk, StreamSlot},
};
use rand_core::OsRng;
use std::pin::pin;

pub const LIVE_STREAMS: usize = 4;
pub const STREAM_RECEIVE_BYTES: usize = 16 * 1024;
pub const STREAM_CHUNK_BYTES: usize = 1024;

/// Startup observations, never substitute authentication/validation authority.
/// `bootstrap_destination` is the original destination CID even after a server
/// Retry. The engine later transfers the actual ValidatedToken to Path.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub network: NetworkConfig,
    pub local_cid: path_owner::Destination,
    pub bootstrap_destination: path_owner::Destination,
    pub local_limits: Limits,
    pub early_send: bool,
    pub early_receive: Option<ServerPolicy>,
}

/// A joined application result plus the optional Early service's actual ending.
/// UnactivatedCancelled is local teardown before Install, not projected Retired.
pub struct Completed<R> {
    pub application: R,
    pub early: Option<early_owner::ServiceCompletion>,
}

/// The application must gracefully retire its connected clients before returning
/// success. An application/actor error cancels the aggregate and drops the real
/// owner state; it is never rewritten as successful protocol completion.
#[allow(clippy::too_many_arguments)]
pub async fn with_connection<T: hibana_quic::tls::Provider, R>(
    keys: InitialKeys,
    side: Side,
    generation: u64,
    provider: T,
    config: Config,
    application: impl for<'channel, 'storage> AsyncFnOnce(
        InitialProtection<'channel, 'storage>,
        TlsClient<'channel, 'storage>,
        RecoveryClient<'channel, 'storage>,
        &'channel PacketAuthority,
        path_owner::Client<'channel, 'storage, 1, 1>,
        StreamClient<'channel, 'storage>,
        Option<EarlyStarter<'channel, 'storage>>,
    ) -> Result<R, String>,
) -> Result<Completed<R>, String> {
    if (config.early_send && side != Side::Client)
        || (config.early_receive.is_some() && side != Side::Server)
    {
        return Err("early role configuration does not match endpoint side".into());
    }
    let (receive_key, transmit_key) = match side {
        Side::Client => (keys.server, keys.client),
        Side::Server => (keys.client, keys.server),
    };
    let initial_rtt_us = recovery::INITIAL_RTT_US;
    let initial_pto_us = recovery::RttEstimator::new(initial_rtt_us)
        .and_then(|rtt| rtt.pto_duration_us(0, 0))
        .map_err(|e| format!("initial PTO: {e:?}"))?;
    let mut paths = [const { PathSlot::<1, 3>::empty() }; path_owner::PATHS];
    let mut local_cids = [LocalCidSlot::EMPTY; path_owner::LOCAL_CIDS];
    let mut peer_cids = [PeerCidSlot::<2>::EMPTY; path_owner::PEER_CIDS];
    let path_state = path_owner::State::new(
        path_owner::Config {
            generation,
            role: match side {
                Side::Client => migration::Role::Client,
                Side::Server => migration::Role::Server,
            },
            initial: config.network.initial,
            local_cid: config.local_cid,
            bootstrap_destination: config.bootstrap_destination,
            local_active_limit: config.network.active_connection_id_limit,
            local_reset_token: config.network.initial_reset_token,
            preferred_server: config.network.preferred_server.map(|preferred| {
                path_owner::PreferredLocal {
                    address: preferred.address,
                    cid: preferred.connection_id,
                    reset_token: preferred.reset_token,
                }
            }),
            now: 0,
            pto: initial_pto_us,
        },
        path_owner::Resources {
            paths: &mut paths,
            local_cids: &mut local_cids,
            peer_cids: &mut peer_cids,
        },
        OsRng,
    )
    .map_err(|e| format!("Path state: {e:?}"))?;
    let recovery_state = RecoveryOwner::new(recovery_owner::Config {
        generation,
        initial_rtt_us,
        max_datagram_size: 1200,
        active_path: Some(path_state.initial_path()),
        ecn: None,
        max_ack_delay_us: 25_000,
    })
    .map_err(|e| format!("Recovery state: {e:?}"))?;
    let authority = PacketAuthority::new(generation);
    let mut stream_slots = [const { StreamSlot::<STREAM_RECEIVE_BYTES>::EMPTY }; LIVE_STREAMS];
    let mut chunks = [const { SendChunk::<STREAM_CHUNK_BYTES>::EMPTY }; 16];
    let mut references = [PacketReference::EMPTY; 128];
    let mut requests = [const { RequestSlot::<STREAM_CHUNK_BYTES>::EMPTY }; LIVE_STREAMS];
    let stream_state = stream_owner::State::<STREAM_RECEIVE_BYTES, STREAM_CHUNK_BYTES>::new(
        generation,
        match side {
            Side::Client => streams::Role::Client,
            Side::Server => streams::Role::Server,
        },
        config.local_limits,
        &mut stream_slots,
        &mut chunks,
        &mut references,
        generation,
        config.early_send.then_some(&mut requests[..]),
    )
    .map_err(|e| format!("Stream state: {e:?}"))?;
    let mut quarantine = [const { QuarantineSlot::<EARLY_REQUEST_BYTES>::EMPTY }; LIVE_STREAMS];
    let mut controls = [const { early_owner::ControlSlot::<EARLY_CONTROL_BYTES>::EMPTY }; 16];
    let early_storage = config
        .early_receive
        .map(|policy| EarlyStorage::new(generation, policy, &mut quarantine, &mut controls))
        .transpose()
        .map_err(|e| format!("Early resources: {e:?}"))?;
    let early_enabled = early_storage.is_some();

    // All traffic consists of actual 16-byte descriptors. Queue capacity one
    // intentionally preserves backpressure across all simultaneously live roles.
    let carrier = CarrierStorage::<1, 16, 128>::new();
    let mut slab = [0; 256 * 1024];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init();
    let sid = SessionId::new(2);
    let rv = kit
        .rendezvous(
            &mut slab,
            carrier
                .bind(sid)
                .map_err(|e| format!("connection carrier: {e:?}"))?,
        )
        .map_err(|e| format!("connection rendezvous: {e:?}"))?;
    let base = g::par(
        g::par(
            g::par(key_choreography::<16, 17>(), key_choreography::<18, 19>()),
            tls_choreography::<24, 25>(),
        ),
        g::par(
            recovery_choreography::<26, 27>(),
            g::par(
                stream_choreography::<28, 29>(),
                path_choreography::<30, 31>(),
            ),
        ),
    );
    // Configuration chooses the real projection source. Disabled Early is not
    // attached or represented by a decorative, unexecuted graph.
    macro_rules! ordinary_programs {
        ($global:expr, $early_client:expr, $early_owner:expr) => {
            (
                project::<16, _>($global),
                project::<17, _>($global),
                project::<18, _>($global),
                project::<19, _>($global),
                project::<24, _>($global),
                project::<25, _>($global),
                project::<26, _>($global),
                project::<27, _>($global),
                project::<28, _>($global),
                project::<29, _>($global),
                project::<30, _>($global),
                project::<31, _>($global),
                $early_client,
                $early_owner,
            )
        };
    }
    let (p16, p17, p18, p19, p24, p25, p26, p27, p28, p29, p30, p31, p32, p33) = if early_enabled {
        let global = g::par(base, early_choreography::<32, 33>());
        ordinary_programs!(
            &global,
            Some(project::<32, _>(&global)),
            Some(project::<33, _>(&global))
        )
    } else {
        ordinary_programs!(&base, None, None)
    };
    macro_rules! enter {
        ($program:expr, $name:literal) => {
            rv.enter(sid, $program)
                .map_err(|e| format!(concat!($name, " attach: {:?}"), e))?
        };
    }
    let mut e16 = enter!(&p16, "Initial RX client");
    let mut e17 = enter!(&p17, "Initial RX owner");
    let mut e18 = enter!(&p18, "Initial TX client");
    let mut e19 = enter!(&p19, "Initial TX owner");
    let mut e24 = enter!(&p24, "TLS client");
    let mut e25 = enter!(&p25, "TLS owner");
    let mut e26 = enter!(&p26, "Recovery client");
    let mut e27 = enter!(&p27, "Recovery owner");
    let mut e28 = enter!(&p28, "Stream client");
    let mut e29 = enter!(&p29, "Stream owner");
    let mut e30 = enter!(&p30, "Path client");
    let mut e31 = enter!(&p31, "Path owner");
    let mut e32 = p32
        .as_ref()
        .map(|p| rv.enter(sid, p))
        .transpose()
        .map_err(|e| format!("Early client attach: {e:?}"))?;
    let mut e33 = p33
        .as_ref()
        .map(|p| rv.enter(sid, p))
        .transpose()
        .map_err(|e| format!("Early owner attach: {e:?}"))?;

    // Every mailbox and exchange is caller-owned bounded storage. No role
    // receives a mutable alias to a sibling's state or its backing resources.
    macro_rules! mailbox_storage {
        ($name:ident, $ty:ty) => {
            let mut $name: [Option<$ty>; 1] = [None];
        };
    }
    macro_rules! mailbox_bind {
        ($name:ident) => {
            let $name = Mailbox::new(&mut $name)
                .map_err(|e| format!(concat!(stringify!($name), ": {:?}"), e))?;
        };
    }
    macro_rules! mailbox_split {
        ($name:ident, $send:ident, $recv:ident) => {
            let ($send, $recv) = $name
                .split()
                .map_err(|e| format!(concat!(stringify!($name), " split: {:?}"), e))?;
        };
    }
    // Shared capability lifetimes require all backing arrays to outlive every
    // mailbox, and every mailbox to outlive every endpoint's Drop.
    mailbox_storage!(
        rx_commands,
        packet_protection::Command<INITIAL_PACKET_BYTES>
    );
    mailbox_storage!(rx_replies, packet_protection::Reply<INITIAL_PACKET_BYTES>);
    mailbox_storage!(
        tx_commands,
        packet_protection::Command<INITIAL_PACKET_BYTES>
    );
    mailbox_storage!(tx_replies, packet_protection::Reply<INITIAL_PACKET_BYTES>);
    mailbox_storage!(tls_commands, tls_owner::Command<TLS_PACKET_BYTES>);
    mailbox_storage!(tls_replies, tls_owner::Reply<TLS_PACKET_BYTES, TLS_PARAMETER_BYTES>);
    mailbox_storage!(recovery_commands, recovery_owner::Command<900>);
    mailbox_storage!(recovery_replies, recovery_owner::Reply<64, 900>);
    mailbox_storage!(path_commands, path_owner::Command);
    mailbox_storage!(path_replies, path_owner::Reply);
    mailbox_storage!(stream_commands, stream_owner::Command<STREAM_FRAME_BYTES>);
    mailbox_storage!(stream_replies, stream_owner::Reply<STREAM_FRAME_BYTES>);
    mailbox_storage!(early_commands, early_owner::Command<EARLY_COMMAND_BYTES>);
    mailbox_storage!(early_replies, early_owner::Reply<EARLY_COMMAND_BYTES>);
    mailbox_bind!(rx_commands);
    mailbox_bind!(rx_replies);
    mailbox_bind!(tx_commands);
    mailbox_bind!(tx_replies);
    mailbox_bind!(tls_commands);
    mailbox_bind!(tls_replies);
    mailbox_bind!(recovery_commands);
    mailbox_bind!(recovery_replies);
    mailbox_bind!(path_commands);
    mailbox_bind!(path_replies);
    mailbox_bind!(stream_commands);
    mailbox_bind!(stream_replies);
    mailbox_bind!(early_commands);
    mailbox_bind!(early_replies);
    mailbox_split!(rx_commands, rx_send, rx_recv);
    mailbox_split!(rx_replies, rx_reply_send, rx_reply_recv);
    mailbox_split!(tx_commands, tx_send, tx_recv);
    mailbox_split!(tx_replies, tx_reply_send, tx_reply_recv);
    mailbox_split!(tls_commands, tls_send, tls_recv);
    mailbox_split!(tls_replies, tls_reply_send, tls_reply_recv);
    mailbox_split!(recovery_commands, recovery_send, recovery_recv);
    mailbox_split!(recovery_replies, recovery_reply_send, recovery_reply_recv);
    mailbox_split!(path_commands, path_send, path_recv);
    mailbox_split!(path_replies, path_reply_send, path_reply_recv);
    mailbox_split!(stream_commands, stream_send, stream_recv);
    mailbox_split!(stream_replies, stream_reply_send, stream_reply_recv);
    mailbox_split!(early_commands, early_send, early_recv);
    mailbox_split!(early_replies, early_reply_send, early_reply_recv);
    let mut rx_exchange = packet_protection::Exchange::new();
    let mut tx_exchange = packet_protection::Exchange::new();
    let mut tls_exchange = tls_owner::Exchange::new();
    let mut recovery_exchange = RecoveryExchange::new();
    let mut path_exchange = path_owner::Exchange::new();
    let mut stream_exchange = stream_owner::Exchange::new();
    let mut early_exchange = EarlyExchange::new();
    let mut result = None;
    let mut early_completion = None;
    {
        let mut work = pin!(async {
            let tls = TlsClient::connect(tls_send, tls_reply_recv, generation)
                .await
                .map_err(|e| format!("TLS connect: {e:?}"))?;
            let receive = InitialKeyClient::connect(rx_send, rx_reply_recv, generation)
                .await
                .map_err(|e| format!("Initial RX connect: {e:?}"))?;
            let transmit = InitialKeyClient::connect(tx_send, tx_reply_recv, generation)
                .await
                .map_err(|e| format!("Initial TX connect: {e:?}"))?;
            let initial = InitialProtection::new(receive, transmit)
                .map_err(|e| format!("Initial capabilities: {e:?}"))?;
            let recovery = RecoveryClient::connect(generation, recovery_send, recovery_reply_recv)
                .await
                .map_err(|e| format!("Recovery connect: {e:?}"))?;
            let path = path_owner::Client::connect(path_send, path_reply_recv, generation)
                .await
                .map_err(|e| format!("Path connect: {e:?}"))?;
            let stream = StreamClient::connect(stream_send, stream_reply_recv, generation)
                .await
                .map_err(|e| format!("Stream connect: {e:?}"))?;
            let early =
                early_enabled.then(|| EarlyStarter::new(early_send, early_reply_recv, generation));
            result =
                Some(application(initial, tls, recovery, &authority, path, stream, early).await?);
            Ok::<(), String>(())
        });
        let mut receive_actor = pin!(async {
            packet_protection::run_borrowed(
                &mut e16,
                &mut e17,
                generation,
                receive_key,
                rx_recv,
                rx_reply_send,
                &mut rx_exchange,
            )
            .await
            .map_err(|e| format!("Initial RX owner: {e:?}"))
        });
        let mut transmit_actor = pin!(async {
            packet_protection::run_borrowed(
                &mut e18,
                &mut e19,
                generation,
                transmit_key,
                tx_recv,
                tx_reply_send,
                &mut tx_exchange,
            )
            .await
            .map_err(|e| format!("Initial TX owner: {e:?}"))
        });
        let mut tls_actor = pin!(async {
            tls_owner::run_borrowed(
                &mut e24,
                &mut e25,
                generation,
                provider,
                tls_recv,
                tls_reply_send,
                &mut tls_exchange,
            )
            .await
            .map_err(|e| format!("TLS owner: {e:?}"))
        });
        let mut recovery_actor = pin!(async {
            recovery_owner::run_borrowed(
                &mut e26,
                &mut e27,
                recovery_state,
                &authority,
                recovery_recv,
                recovery_reply_send,
                &mut recovery_exchange,
            )
            .await
            .map_err(|e| format!("Recovery owner: {e:?}"))
        });
        let mut stream_actor = pin!(async {
            stream_owner::run_borrowed(
                &mut e28,
                &mut e29,
                stream_state,
                stream_recv,
                stream_reply_send,
                &mut stream_exchange,
                &authority,
            )
            .await
            .map_err(|e| format!("Stream owner: {e:?}"))
        });
        let mut path_actor = pin!(async {
            path_owner::run_borrowed(
                &mut e30,
                &mut e31,
                path_state,
                &authority,
                path_recv,
                path_reply_send,
                &mut path_exchange,
            )
            .await
            .map_err(|e| format!("Path owner: {e:?}"))
        });
        let mut early_actor = pin!(async {
            if let Some(resources) = early_storage {
                let client = e32.as_mut().ok_or("missing configured Early client")?;
                let owner = e33.as_mut().ok_or("missing configured Early owner")?;
                let completion = early_owner::run_unclaimed_borrowed(
                    client,
                    owner,
                    resources,
                    early_recv,
                    early_reply_send,
                    &mut early_exchange,
                )
                .await
                .map_err(|e| format!("Early owner: {e:?}"))?;
                // Both outcomes close real resources. Only Retired means the
                // activated projected retirement exchange actually completed.
                early_completion = Some(completion);
            }
            Ok::<(), String>(())
        });
        let tasks: [Task<'_, String>; 8] = [
            tls_actor.as_mut(),
            receive_actor.as_mut(),
            transmit_actor.as_mut(),
            recovery_actor.as_mut(),
            stream_actor.as_mut(),
            path_actor.as_mut(),
            early_actor.as_mut(),
            work.as_mut(),
        ];
        TaskSet::new(tasks).await?;
    }
    Ok(Completed {
        application: result.ok_or_else(|| "missing completed application report".to_string())?,
        early: early_completion,
    })
}
