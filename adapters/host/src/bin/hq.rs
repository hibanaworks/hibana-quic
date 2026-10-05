//! Primary direct Hibana host attachment. File mode enters the library's one
//! connected global from Initial through authenticated file IO and clean close.
#![forbid(unsafe_code)]
#![allow(long_running_const_eval)]
#[path = "support/application_storage.rs"]
mod application_storage;
#[path = "support/cli.rs"]
mod cli;
#[path = "support/direct_bootstrap.rs"]
mod direct_bootstrap;
#[path = "support/direct_wire.rs"]
mod direct_wire;
#[path = "support/files.rs"]
mod files;
#[path = "support/host_files.rs"]
mod host_files;
#[path = "support/parallel_server.rs"]
mod parallel_server;
#[path = "../pem.rs"]
mod pem;
use cli::{Options, USAGE, options};
use direct_wire::{
    HostClock, HostReactor, HostSocket, Receive, Statistics, Transmit, before_deadline,
};
use hibana_quic::{
    bounded_tls::{
        BoundedTls, ClientConfig, ClientEarlyData, ClientResumption, ServerConfig,
        ServerResumption, SigningKey, Storage as TlsStorage,
    },
    connection::publication_gate::PublicationGate,
    connection::{Config, Side, application, recovery::Recovery, tls::Transcript},
    crypto::directional::ApplicationKeyScope,
    packet::{Header, LongType, PacketIter, encode_varint},
    path::Address,
    tls_certificate::{Limits, UnixTime, trust_anchor_from_der},
    tls_ticket::{self as ticket, TicketClock},
};
use p256::pkcs8::DecodePrivateKey;
use rand_core::{OsRng, RngCore};
use rustls_pki_types::PrivateKeyDer;
use std::{
    net::{SocketAddr, UdpSocket},
    process::ExitCode,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
type Result<T> = std::result::Result<T, String>;
fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| format!("OS randomness: {e}"))?;
    Ok(bytes)
}
fn parameters(
    local: &[u8],
    original: Option<&[u8]>,
    application_limits: Option<hibana_quic::streams::Limits>,
) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut encoded = [0; 8];
    for (kind, value) in [(15, Some(local)), (0, original)] {
        if let Some(value) = value {
            let len = encode_varint(kind, &mut encoded).map_err(|e| format!("parameter: {e:?}"))?;
            bytes.extend_from_slice(&encoded[..len]);
            let len = encode_varint(value.len() as u64, &mut encoded)
                .map_err(|e| format!("parameter: {e:?}"))?;
            bytes.extend_from_slice(&encoded[..len]);
            bytes.extend_from_slice(value);
        }
    }
    if let Some(limits) = application_limits {
        // Advertise exactly the windows backed by application_storage.
        for (kind, value) in [
            (1, 30_000),
            (3, direct_bootstrap::DATAGRAM as u64),
            (4, limits.max_data),
            (5, limits.stream_data_bidi_local),
            (6, limits.stream_data_bidi_remote),
            (7, limits.stream_data_uni),
            (8, limits.max_streams_bidi),
            (9, limits.max_streams_uni),
        ] {
            let mut value_bytes = [0; 8];
            let value_len = encode_varint(value, &mut value_bytes)
                .map_err(|e| format!("parameter value: {e:?}"))?;
            let len =
                encode_varint(kind, &mut encoded).map_err(|e| format!("parameter kind: {e:?}"))?;
            bytes.extend_from_slice(&encoded[..len]);
            let len = encode_varint(value_len as u64, &mut encoded)
                .map_err(|e| format!("parameter length: {e:?}"))?;
            bytes.extend_from_slice(&encoded[..len]);
            bytes.extend_from_slice(&value_bytes[..value_len]);
        }
    }
    Ok(bytes)
}
struct TlsBuffers {
    rx: Vec<u8>,
    tx: Vec<u8>,
    certificates: Vec<u8>,
    parameters: Vec<u8>,
}
impl TlsBuffers {
    fn new() -> Self {
        Self {
            rx: vec![0; 16384],
            tx: vec![0; 16384],
            certificates: vec![0; 16384],
            parameters: vec![0; direct_bootstrap::PARAMETERS],
        }
    }
    fn storage(&mut self) -> TlsStorage<'_> {
        TlsStorage {
            rx_message: &mut self.rx,
            tx_flight: &mut self.tx,
            peer_certificates: &mut self.certificates,
            peer_parameters: &mut self.parameters,
        }
    }
}
fn signing_key(key: &PrivateKeyDer<'_>) -> Result<SigningKey> {
    match key {
        PrivateKeyDer::Pkcs8(key) => SigningKey::from_pkcs8_der(key.secret_pkcs8_der())
            .map_err(|_| "server signing key must be ECDSA P-256 PKCS8".into()),
        PrivateKeyDer::Sec1(key) => p256::SecretKey::from_sec1_der(key.secret_sec1_der())
            .map(SigningKey::from)
            .map_err(|_| "server signing key must be ECDSA P-256 SEC1".into()),
        _ => Err("unsupported server signing key; ECDSA P-256 required".into()),
    }
}
struct Report {
    connections: usize,
    idle_expired_connections: usize,
    resumed: bool,
    resumed_connections: usize,
    side: Side,
    peer: SocketAddr,
    sent: u64,
    received: u64,
    foreign: u64,
    accepted_at: u64,
    elapsed: u128,
    application: Option<application::Report>,
    body_bytes: u64,
}
impl Report {
    fn append(mut self, previous: Report) -> Result<Self> {
        self.connections = self
            .connections
            .checked_add(previous.connections)
            .ok_or("report counter overflow")?;
        self.idle_expired_connections = self
            .idle_expired_connections
            .checked_add(previous.idle_expired_connections)
            .ok_or("report counter overflow")?;
        self.resumed_connections = self
            .resumed_connections
            .checked_add(previous.resumed_connections)
            .ok_or("report counter overflow")?;
        self.sent = self
            .sent
            .checked_add(previous.sent)
            .ok_or("report counter overflow")?;
        self.received = self
            .received
            .checked_add(previous.received)
            .ok_or("report counter overflow")?;
        self.foreign = self
            .foreign
            .checked_add(previous.foreign)
            .ok_or("report counter overflow")?;
        self.body_bytes = self
            .body_bytes
            .checked_add(previous.body_bytes)
            .ok_or("report counter overflow")?;
        if let (Some(current), Some(old)) = (&mut self.application, previous.application) {
            current.early_accepted_packets = current
                .early_accepted_packets
                .checked_add(old.early_accepted_packets)
                .ok_or("report counter overflow")?;
            current.early_stream_bytes = current
                .early_stream_bytes
                .checked_add(old.early_stream_bytes)
                .ok_or("report counter overflow")?;
            current.early_finished_streams = current
                .early_finished_streams
                .checked_add(old.early_finished_streams)
                .ok_or("report counter overflow")?;
            if old.termination == application::Termination::IdleExpired {
                current.termination = old.termination;
            }
            current.confirmed &= old.confirmed;
            current.all_streams_acked &= old.all_streams_acked;
            current.close_completed &= old.close_completed;
            current.submitted_streams = current
                .submitted_streams
                .checked_add(old.submitted_streams)
                .ok_or("report counter overflow")?;
            current.completed_streams = current
                .completed_streams
                .checked_add(old.completed_streams)
                .ok_or("report counter overflow")?;
            current.received_bytes = current
                .received_bytes
                .checked_add(old.received_bytes)
                .ok_or("report counter overflow")?;
            current.sent_bytes = current
                .sent_bytes
                .checked_add(old.sent_bytes)
                .ok_or("report counter overflow")?;
        }
        Ok(self)
    }
    fn json<const S: usize, const T: usize>(&self, reactor: &HostReactor<S, T>) -> String {
        let stats = reactor.statistics();
        let transfer = if let Some(report) = self.application {
            format!(
                "\"scope\":\"{}\",\"key_generation\":{},\"early_accepted_packets\":{},\"early_stream_bytes\":{},\"early_finished_streams\":{},\"quic_handshake_confirmed\":{},\"http_transfer_complete\":{},\"resources_retired\":true,\"idle_expired_connections\":{},\"lifecycle_closed\":{},\"all_streams_acked\":{},\"files_submitted\":{},\"files_completed\":{},\"body_bytes\":{},\"udp_received_bytes_before_close\":{},\"udp_accepted_bytes_before_close\":{}",
                if self.idle_expired_connections == 0 {
                    "authenticated-file-transfer"
                } else {
                    "connection-retirement"
                },
                report.key_generation,
                report.early_accepted_packets,
                report.early_stream_bytes,
                report.early_finished_streams,
                report.confirmed,
                report.termination == application::Termination::Closed,
                self.idle_expired_connections,
                report.close_completed,
                report.all_streams_acked,
                report.submitted_streams,
                report.completed_streams,
                self.body_bytes,
                report.received_bytes,
                report.sent_bytes
            )
        } else {
            "\"scope\":\"authenticated-handshake-prefix\",\"owned_application_continuations\":true,\"quic_handshake_confirmed\":false,\"http_transfer_complete\":false,\"lifecycle_closed\":false".to_owned()
        };
        format!(
            "{{\"connections\":{},\"resumed\":{},\"resumed_connections\":{},\"backend\":\"direct-hibana-roles\",\"status\":\"{}\",{transfer},\"role\":\"{}\",\"peer\":\"{}\",\"tls_finished_authenticated\":true,\"datagrams_sent\":{},\"datagrams_received\":{},\"foreign_datagrams_ignored\":{},\"last_os_acceptance_us\":{},\"duration_ms\":{},\"reactor_polls\":{},\"reactor_waits\":{},\"reactor_socket_events\":{},\"reactor_timer_events\":{}}}",
            self.connections,
            self.resumed,
            self.resumed_connections,
            if self.idle_expired_connections == 0 {
                "success"
            } else {
                "idle-expired"
            },
            if self.side == Side::Client {
                "client"
            } else {
                "server"
            },
            self.peer,
            self.sent,
            self.received,
            self.foreign,
            self.accepted_at,
            self.elapsed,
            stats.polls,
            stats.waits,
            stats.socket_events,
            stats.timer_events
        )
    }
}
#[allow(clippy::too_many_arguments)]
async fn connected<const S: usize, const T: usize>(
    socket: &HostSocket<'_, S, T>,
    clock: &HostClock<'_, S, T>,
    address: Address,
    config: Config<'_>,
    tls: BoundedTls<'_, '_>,
    first: Option<&[u8]>,
    mut files: Option<direct_bootstrap::Files>,
    early: Option<application_storage::EarlyStorage>,
    key_update_target: u64,
    routed: Option<&mut hibana_quic_host::receive_routes::Receiver<{ direct_bootstrap::DATAGRAM }>>,
) -> Result<Report> {
    let generation = u64::from_be_bytes(random::<8>()?);
    let mut scope = ApplicationKeyScope::new(generation);
    let mut identity = scope.claim().map_err(|e| format!("scope: {e:?}"))?;
    let recovery = identity
        .take_recovery()
        .map_err(|e| format!("recovery authority: {e:?}"))?;
    let mut gate = PublicationGate::new(
        identity
            .take_publication_gate()
            .map_err(|e| format!("publication authority: {e:?}"))?,
    );
    let (mut issuer, stop) = gate
        .split()
        .map_err(|e| format!("publication facets: {e:?}"))?;
    let mut source = Transcript::new(
        tls.into_key_source(identity)
            .map_err(|e| format!("TLS source: {e:?}"))?,
    );
    let mut book = Recovery::<{ direct_bootstrap::DATAGRAM }>::new(
        recovery,
        config.side,
        333_000,
        direct_bootstrap::DATAGRAM as u64,
    )
    .map_err(|e| format!("recovery: {e:?}"))?;
    let statistics = Statistics::default();
    let mut receive = Receive {
        routed,
        socket,
        address,
        first,
        clock,
        statistics: &statistics,
    };
    let mut transmit = Transmit {
        socket,
        address,
        clock,
        statistics: &statistics,
    };
    let mut body_bytes = 0;
    let application = if let Some(files) = &mut files {
        let (observations, diagnostics, expected) = match files {
            direct_bootstrap::Files::Client(client) => (
                client.observations.clone(),
                client.diagnostics.clone(),
                Some(client.count),
            ),
            direct_bootstrap::Files::Server(server) => (
                server.observations.clone(),
                server.diagnostics.clone(),
                None,
            ),
        };
        // One combined projection and one library invocation own every phase.
        // A failed transfer cannot fall back to a successful prefix report.
        let report = Box::pin(direct_bootstrap::files(
            &mut source,
            config,
            &mut receive,
            &mut transmit,
            clock,
            &mut issuer,
            stop,
            &mut book,
            generation,
            files,
            early,
            key_update_target,
        ))
        .await
        .map_err(|error| match diagnostics.take() {
            Some(detail) => format!("{error}: {detail}"),
            None => error,
        })?;
        if report.key_generation < key_update_target {
            return Err("requested key generation was not actually installed".into());
        }
        if report.termination == application::Termination::Closed
            && (!report.confirmed
            // A real peer close retires the server's retained response even
            // when the peer did not include its final ACK. Keep that fact false
            // in the report; do not require or fabricate an acknowledgment.
            || (config.side == Side::Client && !report.all_streams_acked)
            || !report.close_completed
            || report.completed_streams == 0
            || report.completed_streams != report.submitted_streams
            || report.completed_streams != observations.files_finished.get()
            || report.submitted_streams != observations.files_started.get()
            || expected.is_some_and(|count| count != report.completed_streams))
        {
            return Err(format!("incomplete authenticated transfer: {report:?}"));
        }
        body_bytes = observations.body_bytes.get();
        Some(report)
    } else {
        let continuations = Box::pin(direct_bootstrap::handshake(
            &mut source,
            config,
            &mut receive,
            &mut transmit,
            clock,
            &mut issuer,
            &mut book,
            generation,
        ))
        .await?;
        // Explicit prefix diagnostics end here, with real affine continuations.
        drop(continuations);
        None
    };
    let snapshot = book.snapshot();
    if snapshot.active_flights != 0
        || snapshot.reserved_bytes != 0
        || snapshot.reserved_in_flight != 0
    {
        return Err("connection returned with live flight reservations".into());
    }
    if config.side == Side::Server && !snapshot.address_validated {
        return Err("server peer path was not validated".into());
    }
    Ok(Report {
        connections: 1,
        idle_expired_connections: usize::from(
            application
                .as_ref()
                .is_some_and(|report| report.termination == application::Termination::IdleExpired),
        ),
        resumed: source.resumed(),
        resumed_connections: usize::from(source.resumed()),
        side: config.side,
        peer: address.remote,
        sent: statistics.sent.get(),
        received: statistics.received.get(),
        foreign: statistics.foreign.get(),
        accepted_at: statistics
            .last_accepted
            .get()
            .ok_or("no real UDP acceptance")?,
        elapsed: clock.start.elapsed().as_millis(),
        application,
        body_bytes,
    })
}
async fn respond_unsupported_version<const S: usize, const T: usize>(
    socket: &HostSocket<'_, S, T>,
    header: &Header<'_>,
    source: SocketAddr,
    received_len: usize,
) -> Result<bool> {
    let Header::UnsupportedVersion {
        destination_id,
        source_id,
        ..
    } = header
    else {
        return Ok(false);
    };
    if destination_id.len() <= 20 && source_id.len() <= 20 {
        // Stateless version selection precedes connection/key ownership.
        // Unknown versions have a version-independent CID envelope; even
        // a small probe may elicit VN (RFC 9000 section 6). Reverse CIDs,
        // advertise only v1, and stay below the threefold response budget.
        let mut reply = [0; 51];
        reply[0] = 0x80 | (random::<1>()?[0] & 0x7f);
        let mut end = 5;
        reply[end] = source_id.len() as u8;
        end += 1;
        reply[end..end + source_id.len()].copy_from_slice(source_id);
        end += source_id.len();
        reply[end] = destination_id.len() as u8;
        end += 1;
        reply[end..end + destination_id.len()].copy_from_slice(destination_id);
        end += destination_id.len();
        reply[end..end + 4].copy_from_slice(&hibana_quic::packet::QUIC_V1.to_be_bytes());
        end += 4;
        if end <= received_len.saturating_mul(3) {
            socket
                .send_to(&reply[..end], source, hibana_quic::ecn::Codepoint::NotEct)
                .await
                .map_err(|error| format!("Version Negotiation: {error}"))?;
        }
    }
    Ok(true)
}
async fn admit_initial<const S: usize, const T: usize>(
    socket: &HostSocket<'_, S, T>,
    first: &mut [u8],
) -> Result<(Address, Vec<u8>, Vec<u8>, usize)> {
    loop {
        // Every rejection returns through this guaranteed Pending yield,
        // bounding admission to one datagram per root poll, including a flood
        // of truncated or malformed packets. The outer deadline stays live.
        hibana_quic::runtime::yield_now().await;
        let metadata = match socket.recv_from(first).await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::InvalidData => continue,
            Err(error) => return Err(format!("Initial admission: {error}")),
        };
        let packet = PacketIter::new(&first[..metadata.len], 8, 8)
            .ok()
            .and_then(|mut packets| packets.next())
            .and_then(std::result::Result::ok);
        if let Some(packet) = &packet
            && respond_unsupported_version(socket, &packet.header, metadata.source, metadata.len)
                .await?
        {
            continue;
        }
        if metadata.len < 1200 {
            continue;
        }
        if let Some(packet) = packet
            && let Header::Long {
                kind: LongType::Initial,
                destination_id,
                source_id,
                token,
                ..
            } = packet.header
            && destination_id.len() >= 8
            && token.is_empty()
        {
            // These are untrusted routing bytes; the direct core must still
            // authenticate the preserved encrypted Initial packet itself.
            return Ok((
                Address {
                    local: metadata.local,
                    remote: metadata.source,
                },
                destination_id.to_vec(),
                source_id.to_vec(),
                metadata.len,
            ));
        }
    }
}
struct WallTicketClock;
impl TicketClock for WallTicketClock {
    fn now_ms(&self) -> std::result::Result<u64, ticket::Error> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ticket::Error::ClockRollback)?
            .as_millis()
            .try_into()
            .map_err(|_| ticket::Error::ClockOverflow)
    }
}

async fn run_async<const S: usize, const T: usize>(
    reactor: &HostReactor<S, T>,
    clock: &HostClock<'_, S, T>,
    options: Options,
) -> Result<Report> {
    match options {
        Options::Client {
            connect,
            server_name,
            cipher,
            resumption,
            connections,
            early,
            key_update_target,
            ca,
            files,
            ..
        } => {
            let mut groups = if resumption {
                let mut files = files.ok_or("resumption requires files")?;
                if files.requests.len() < 2 {
                    return Err("resumption needs at least two requests".into());
                }
                let rest = files.requests.split_off(1);
                vec![
                    Some(cli::ClientFiles {
                        requests: files.requests,
                        downloads: files.downloads.clone(),
                    }),
                    Some(cli::ClientFiles {
                        requests: rest,
                        downloads: files.downloads,
                    }),
                ]
            } else if connections > 1 {
                let files = files.ok_or("independent connections require files")?;
                let downloads = files.downloads;
                files
                    .requests
                    .into_iter()
                    .map(|request| {
                        Some(cli::ClientFiles {
                            requests: vec![request],
                            downloads: downloads.clone(),
                        })
                    })
                    .collect()
            } else {
                vec![files]
            }
            .into_iter()
            .peekable();
            let mut cache_slots: Vec<ticket::ClientSlot<4096>> =
                (0..4).map(|_| ticket::ClientSlot::empty()).collect();
            let mut cache = ticket::ClientCache::new(&mut cache_slots);
            let ticket_clock = WallTicketClock;
            let mut offer = None;
            let mut previous: Option<Report> = None;
            let roots = pem::certificates(&ca)?;
            let anchors = roots
                .iter()
                .map(trust_anchor_from_der)
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| format!("trust anchor: {e:?}"))?;
            while let Some(files) = groups.next() {
                let files = files
                    .map(|files| {
                        host_files::Client::new(&files.downloads, files.requests)
                            .map(direct_bootstrap::Files::Client)
                    })
                    .transpose()?;
                // Routing-only connect chooses a source IP without transmitting.
                let route = UdpSocket::bind(if connect.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                })
                .map_err(|e| format!("route socket: {e}"))?;
                route
                    .connect(connect)
                    .map_err(|e| format!("route selection: {e}"))?;
                let mut bind = route
                    .local_addr()
                    .map_err(|e| format!("route address: {e}"))?;
                bind.set_port(0);
                drop(route);
                let socket = reactor
                    .register_udp(UdpSocket::bind(bind).map_err(|e| format!("UDP bind: {e}"))?)
                    .map_err(|e| format!("UDP registration: {e}"))?;
                let address = Address {
                    local: socket
                        .local_addr()
                        .map_err(|e| format!("local address: {e}"))?,
                    remote: connect,
                };
                let local = random::<8>()?;
                let original = random::<8>()?;
                let parameters = parameters(
                    &local,
                    None,
                    files.as_ref().map(direct_bootstrap::Files::local_limits),
                )?;
                let mut buffers = TlsBuffers::new();
                let now = UnixTime::since_unix_epoch(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_err(|_| "system clock precedes Unix epoch")?,
                );
                let config = ClientConfig {
                    server_name: &server_name,
                    trust_anchors: &anchors,
                    now,
                    certificate_limits: Limits::default(),
                    transport_parameters: &parameters,
                };
                let tls = if let Some(offer) = offer.take() {
                    if early {
                        BoundedTls::client_resuming_early_with_policy(
                            config,
                            buffers.storage(),
                            &mut OsRng,
                            ClientResumption {
                                store: &mut cache,
                                clock: &ticket_clock,
                            },
                            offer,
                            ClientEarlyData::replay_safe_requests(1),
                            cipher,
                        )
                    } else {
                        BoundedTls::client_resuming_with_policy(
                            config,
                            buffers.storage(),
                            &mut OsRng,
                            ClientResumption {
                                store: &mut cache,
                                clock: &ticket_clock,
                            },
                            offer,
                            cipher,
                        )
                    }
                } else if resumption {
                    BoundedTls::client_with_tickets_and_policy(
                        config,
                        buffers.storage(),
                        &mut OsRng,
                        ClientResumption {
                            store: &mut cache,
                            clock: &ticket_clock,
                        },
                        cipher,
                    )
                } else {
                    BoundedTls::client_with_policy(config, buffers.storage(), &mut OsRng, cipher)
                }
                .map_err(|e| format!("client TLS: {e:?}"))?;
                let report = Box::pin(connected(
                    &socket,
                    clock,
                    address,
                    Config {
                        side: Side::Client,
                        local_connection_id: &local,
                        original_destination_id: &original,
                        peer_connection_id: &original,
                    },
                    tls,
                    None,
                    files,
                    None,
                    key_update_target,
                    None,
                ))
                .await?;
                if resumption && previous.is_some() && !report.resumed {
                    return Err("second connection did not actually resume TLS".into());
                }
                previous = Some(match previous.take() {
                    Some(old) => report.append(old)?,
                    None => report,
                });
                if resumption && groups.peek().is_some() {
                    let origin = ticket::Binding::new(&server_name, b"hq-interop", &[])
                        .map_err(|e| format!("ticket origin: {e:?}"))?;
                    let context = ticket::VerificationContext::new(&anchors, Limits::default())
                        .map_err(|e| format!("ticket trust: {e:?}"))?;
                    let suites: &[u16] = match cipher {
                        hibana_quic::bounded_tls::CipherPolicy::Aes128Only => &[0x1301],
                        hibana_quic::bounded_tls::CipherPolicy::ChaCha20Only => &[0x1303],
                        _ => &[0x1301, 0x1303],
                    };
                    for suite in suites {
                        offer = cache
                            .take_verified_for_origin(
                                ticket_clock
                                    .now_ms()
                                    .map_err(|e| format!("ticket time: {e:?}"))?,
                                &origin,
                                *suite,
                                context,
                            )
                            .map_err(|e| format!("ticket selection: {e:?}"))?;
                        if offer.is_some() {
                            break;
                        }
                    }
                    if offer.is_none() {
                        return Err("no authenticated resumption ticket was received".into());
                    }
                }
            }
            previous.ok_or_else(|| "no client connection executed".into())
        }
        Options::Server {
            listen,
            cert,
            cipher,
            resumption,
            connections,
            early,
            key,
            files,
            ..
        } => {
            if !resumption && connections > 1 {
                return parallel_server::run(
                    reactor,
                    clock,
                    listen,
                    (&cert, &key),
                    files.as_ref().ok_or("parallel server requires files")?,
                    cipher,
                    connections,
                )
                .await;
            }
            let certificates = pem::certificates(&cert)?;
            let key = signing_key(&pem::private_key(&key)?)?;
            let chain: Vec<&[u8]> = certificates.iter().map(|cert| cert.as_ref()).collect();
            let socket = reactor
                .register_udp(UdpSocket::bind(listen).map_err(|e| format!("UDP bind: {e}"))?)
                .map_err(|e| format!("UDP registration: {e}"))?;
            eprintln!(
                "direct Hibana server listening on {}",
                socket
                    .local_addr()
                    .map_err(|e| format!("listen address: {e}"))?
            );
            let mut replay = [const { ticket::ReplaySlot::empty() }; 8];
            let mut early_replay = hibana_quic::early_data::ReplayStorage::<64>::new();
            let mut tickets = if early {
                ticket::TicketKey::generate_with_early_replay(
                    &mut OsRng,
                    ticket::ReplayPolicy::ReusableOneRtt,
                    &mut replay,
                    &mut early_replay,
                )
            } else {
                ticket::TicketKey::generate(
                    &mut OsRng,
                    ticket::ReplayPolicy::SingleUseOneRtt,
                    &mut replay,
                )
            }
            .map_err(|e| format!("ticket key: {e:?}"))?;
            let ticket_clock = WallTicketClock;
            let mut entropy = OsRng;
            let mut previous: Option<Report> = None;
            for connection_index in 0..connections {
                if std::env::var_os("HIBANA_QUIC_DIAGNOSTICS").is_some() {
                    eprintln!(
                        "connection admission {} of {}",
                        connection_index + 1,
                        connections
                    );
                }
                let files = files
                    .as_ref()
                    .map(|files| {
                        host_files::FileServer::new(
                            &files.www,
                            files.max_requests.unwrap_or(host_files::MAX_REQUESTS),
                        )
                        .map(|mut server| {
                            if !resumption && connections > 1 {
                                server.completion_limit = core::num::NonZeroUsize::new(1);
                            }
                            direct_bootstrap::Files::Server(server)
                        })
                    })
                    .transpose()?;
                let mut first = vec![0; direct_bootstrap::DATAGRAM];
                let (address, original, peer, len) = admit_initial(&socket, &mut first).await?;
                let local = random::<8>()?;
                let parameters = parameters(
                    &local,
                    Some(&original),
                    files.as_ref().map(direct_bootstrap::Files::local_limits),
                )?;
                let mut buffers = TlsBuffers::new();
                let config = ServerConfig {
                    certificate_chain: &chain,
                    signing_key: &key,
                    transport_parameters: &parameters,
                };
                let early_storage = early.then(application_storage::EarlyStorage::new);
                let tls = if let Some(storage) = early_storage.as_ref() {
                    let early_config = hibana_quic::bounded_tls::ServerEarlyData::buffered(
                        u64::try_from(connection_index + 1)
                            .map_err(|_| "connection scope overflow")?,
                        application_storage::EarlyStorage::policy(),
                        &parameters,
                        &storage.slots,
                        hibana_quic::early_data::EarlyFreshness::new(10000)
                            .map_err(|e| format!("early freshness: {e:?}"))?,
                    )
                    .map_err(|e| format!("early capacity: {e:?}"))?;
                    BoundedTls::server_with_early_data_and_policy(
                        config,
                        buffers.storage(),
                        &mut OsRng,
                        ServerResumption {
                            store: &mut tickets,
                            entropy: &mut entropy,
                            clock: &ticket_clock,
                            policy: b"hibana-quic fixed-path hq v1",
                            lifetime_seconds: 3600,
                            max_age_skew_ms: 300000,
                        },
                        early_config,
                        cipher,
                    )
                } else if resumption {
                    BoundedTls::server_with_tickets_and_policy(
                        config,
                        buffers.storage(),
                        &mut OsRng,
                        ServerResumption {
                            store: &mut tickets,
                            entropy: &mut entropy,
                            clock: &ticket_clock,
                            policy: b"hibana-quic fixed-path hq v1",
                            lifetime_seconds: 3600,
                            max_age_skew_ms: 300000,
                        },
                        cipher,
                    )
                } else {
                    BoundedTls::server_with_policy(config, buffers.storage(), &mut OsRng, cipher)
                }
                .map_err(|e| format!("server TLS: {e:?}"))?;
                let report = Box::pin(connected(
                    &socket,
                    clock,
                    address,
                    Config {
                        side: Side::Server,
                        local_connection_id: &local,
                        original_destination_id: &original,
                        peer_connection_id: &peer,
                    },
                    tls,
                    Some(&first[..len]),
                    files,
                    early_storage,
                    0,
                    None,
                ))
                .await?;
                if resumption && previous.is_some() && !report.resumed {
                    return Err("second connection did not actually resume TLS".into());
                }
                previous = Some(match previous.take() {
                    Some(old) => report.append(old)?,
                    None => report,
                });
            }
            previous.ok_or_else(|| "no server connection executed".into())
        }
    }
}
fn run(options: Options) -> Result<String> {
    if matches!(&options, Options::Server { resumption: false, connections, .. } if *connections > 1)
    {
        run_sized::<65, 256>(options)
    } else {
        run_sized::<4, 8>(options)
    }
}
fn run_sized<const S: usize, const T: usize>(options: Options) -> Result<String> {
    let require_clean_client = matches!(&options, Options::Client { .. });
    let reactor = HostReactor::<S, T>::new().map_err(|e| format!("host reactor: {e}"))?;
    let clock = HostClock::new(&reactor, Instant::now());
    let deadline = clock
        .start
        .checked_add(options.timeout())
        .ok_or("deadline overflow")?;
    // Explicit host heap boundary; no enlarged stack or blocking core pump.
    let task = Box::pin(before_deadline(
        &clock,
        deadline,
        run_async(&reactor, &clock, options),
    ));
    let result = reactor
        .block_on(task)
        .map_err(|e| format!("host reactor: {e}"))?;
    if reactor.active_resources() != (0, 0) {
        return Err("root returned with live native socket or timer owners".into());
    }
    let report = result?;
    if require_clean_client && report.idle_expired_connections != 0 {
        return Err("connection idle-expired after resource retirement".into());
    }
    Ok(report.json(&reactor))
}
fn main() -> ExitCode {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args
        .first()
        .is_some_and(|arg| arg == "--help" || arg == "-h")
    {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    match options(&args).and_then(run) {
        Ok(report) => {
            println!("{report}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("hq: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    use std::{
        future::Future,
        task::{Context, Waker},
        time::Duration,
    };

    #[test]
    fn unknown_version_probe_gets_reversed_cids_and_v1_without_initial_admission() {
        let reactor = HostReactor::<4, 8>::new().unwrap();
        let socket = reactor
            .register_udp(UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        // The simulator's WAIT version is deliberately not a v1 Initial.
        let probe = b"\xc0WAIT\x04dest\x03src";
        peer.send_to(probe, socket.local_addr().unwrap()).unwrap();
        let mut first = vec![0; direct_bootstrap::DATAGRAM];
        {
            let mut admission = Box::pin(admit_initial(&socket, &mut first));
            let mut context = Context::from_waker(Waker::noop());
            assert!(admission.as_mut().poll(&mut context).is_pending());
            assert!(admission.as_mut().poll(&mut context).is_pending());
        }
        let mut reply = [0; 64];
        let (len, source) = peer.recv_from(&mut reply).unwrap();
        assert_eq!(source, socket.local_addr().unwrap());
        assert!(len <= 3 * probe.len());
        let packet = PacketIter::new(&reply[..len], 8, 8)
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        match packet.header {
            Header::VersionNegotiation {
                destination_id,
                source_id,
                versions,
            } => {
                assert_eq!(destination_id, b"src");
                assert_eq!(source_id, b"dest");
                assert_eq!(
                    versions.iter().collect::<Vec<_>>(),
                    [hibana_quic::packet::QUIC_V1]
                );
            }
            other => panic!("unexpected version selection reply: {other:?}"),
        }
    }

    #[test]
    fn rejected_initials_yield_before_consuming_the_next_datagram() {
        for rejected in [
            vec![0; 64],
            vec![0; 1200],
            vec![0; direct_bootstrap::DATAGRAM + 1],
        ] {
            let reactor = HostReactor::<4, 8>::new().unwrap();
            let socket = reactor
                .register_udp(UdpSocket::bind("127.0.0.1:0").unwrap())
                .unwrap();
            let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
            let address = socket.local_addr().unwrap();
            peer.send_to(&rejected, address).unwrap();
            peer.send_to(b"next datagram remains queued", address)
                .unwrap();
            let mut first = vec![0; direct_bootstrap::DATAGRAM];
            {
                let mut admission = Box::pin(admit_initial(&socket, &mut first));
                let mut context = Context::from_waker(Waker::noop());
                assert!(admission.as_mut().poll(&mut context).is_pending());
                assert!(admission.as_mut().poll(&mut context).is_pending());
            }
            let clock = HostClock::new(&reactor, Instant::now());
            let metadata = reactor
                .block_on(before_deadline(
                    &clock,
                    clock.start + Duration::from_secs(1),
                    async {
                        socket
                            .recv_from(&mut first)
                            .await
                            .map_err(|e| e.to_string())
                    },
                ))
                .unwrap()
                .unwrap();
            assert_eq!(&first[..metadata.len], b"next datagram remains queued");
        }
    }
}
