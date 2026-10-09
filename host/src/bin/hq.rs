//! Primary direct Hibana host attachment. File mode enters the library's one
//! connected global from Initial through authenticated file IO and clean close.
#![forbid(unsafe_code)]
#![allow(long_running_const_eval)]
use hibana_quic_host::storage as application_storage;
#[path = "support/cli.rs"]
mod cli;
#[path = "support/direct_bootstrap.rs"]
mod direct_bootstrap;
use hibana_quic_host::io as direct_wire;
#[path = "support/files.rs"]
mod files;
#[path = "support/host_files.rs"]
mod host_files;
use hibana_quic_host::http3 as http3_files;
#[path = "support/parallel_server.rs"]
mod parallel_server;
#[path = "../pem.rs"]
mod pem;
#[path = "support/retry_admission.rs"]
mod retry_admission;
use cli::{Options, USAGE, options};
use direct_wire::{
    HostClock, HostReactor, HostSocket, Receive, Statistics, Transmit, before_deadline,
};
use hibana_quic::entropy::Entropy;
use hibana_quic::{
    crypto::directional::ApplicationKeyScope,
    quic::kernel::packet::{Header, LongType, PacketIter, encode_varint},
    quic::path::Address,
    quic::publication_gate::PublicationGate,
    quic::{Config, Side, application, recovery::Recovery, tls::Transcript},
    tls::certificate::{Limits, UnixTime, trust_anchor_from_der},
    tls::handshake::{
        BoundedTls, ClientConfig, ClientEarlyData, ClientResumption, ServerConfig,
        ServerResumption, SigningKey, Storage as TlsStorage,
    },
    tls::ticket::{self as ticket, TicketClock},
};
use hibana_quic_host::entropy::KernelEntropy;
use pem::PrivateKeyDer;
use std::{
    net::{SocketAddr, UdpSocket},
    process::ExitCode,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
type Result<T> = std::result::Result<T, String>;
fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    KernelEntropy
        .try_fill_bytes(&mut bytes)
        .map_err(|e| format!("OS randomness: {e}"))?;
    Ok(bytes)
}
fn parameters(
    version: hibana_quic::quic::kernel::version::Version,
    local: &[u8],
    original: Option<&[u8]>,
    application_limits: Option<hibana_quic::quic::kernel::streams::Limits>,
    retry_source: Option<&[u8]>,
    idle_timeout_ms: u64,
) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    if version == hibana_quic::quic::kernel::version::Version::V2 {
        let chosen = if original.is_some() {
            version.wire()
        } else {
            1
        };
        bytes.extend_from_slice(&[0x11, 12]);
        bytes.extend_from_slice(&chosen.to_be_bytes());
        bytes.extend_from_slice(&version.wire().to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
    }
    let mut encoded = [0; 8];
    for (kind, value) in [(15, Some(local)), (0, original), (16, retry_source)] {
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
            (1, idle_timeout_ms),
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
fn signing_key(key: &PrivateKeyDer) -> Result<SigningKey> {
    match key {
        PrivateKeyDer::Pkcs8(key) => SigningKey::from_pkcs8_der(key.as_slice())
            .map_err(|_| "server signing key must be ECDSA P-256 PKCS8".into()),
        PrivateKeyDer::Sec1(key) => SigningKey::from_sec1_der(key.as_slice())
            .map_err(|_| "server signing key must be ECDSA P-256 SEC1".into()),
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
            current.ecn_accepted_packets = current
                .ecn_accepted_packets
                .checked_add(old.ecn_accepted_packets)
                .ok_or("report counter overflow")?;
            current.ecn_validated_packets = current
                .ecn_validated_packets
                .checked_add(old.ecn_validated_packets)
                .ok_or("report counter overflow")?;
            current.ecn_received_packets = current
                .ecn_received_packets
                .checked_add(old.ecn_received_packets)
                .ok_or("report counter overflow")?;
            current.ecn_acknowledgments_sent = current
                .ecn_acknowledgments_sent
                .checked_add(old.ecn_acknowledgments_sent)
                .ok_or("report counter overflow")?;
            current.validated_paths = current
                .validated_paths
                .checked_add(old.validated_paths)
                .ok_or("report counter overflow")?;
            current.preferred_address_used |= old.preferred_address_used;
            current.ecn_feedback_error = current.ecn_feedback_error.or(old.ecn_feedback_error);
        }
        Ok(self)
    }
    fn json<const S: usize, const T: usize>(&self, reactor: &HostReactor<S, T>) -> String {
        let stats = reactor.statistics();
        let transfer = if let Some(report) = self.application {
            format!(
                "\"scope\":\"{}\",\"key_generation\":{},\"early_accepted_packets\":{},\"early_stream_bytes\":{},\"early_finished_streams\":{},\"quic_handshake_confirmed\":{},\"http_transfer_complete\":{},\"resources_retired\":true,\"idle_expired_connections\":{},\"lifecycle_closed\":{},\"all_streams_acked\":{},\"files_submitted\":{},\"files_completed\":{},\"body_bytes\":{},\"udp_received_bytes_before_close\":{},\"udp_accepted_bytes_before_close\":{},\"validated_paths\":{},\"preferred_address_used\":{},\"ecn_accepted_packets\":{},\"ecn_validated_packets\":{},\"ecn_received_packets\":{},\"ecn_acknowledgments_sent\":{},\"ecn_feedback_error\":{}",
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
                report.sent_bytes,
                report.validated_paths,
                report.preferred_address_used,
                report.ecn_accepted_packets,
                report.ecn_validated_packets,
                report.ecn_received_packets,
                report.ecn_acknowledgments_sent,
                report
                    .ecn_feedback_error
                    .map_or_else(|| "null".to_owned(), |error| format!("\"{error:?}\"")),
            )
        } else {
            "\"scope\":\"authenticated-handshake-prefix\",\"owned_application_continuations\":true,\"quic_handshake_confirmed\":false,\"http_transfer_complete\":false,\"lifecycle_closed\":false".to_owned()
        };
        format!(
            "{{\"connections\":{},\"resumed\":{},\"resumed_connections\":{},\"backend\":\"direct-hibana-roles\",\"status\":\"{}\",{transfer},\"role\":\"{}\",\"peer\":\"{}\",\"tls_finished_authenticated\":true,\"datagrams_sent\":{},\"datagrams_received\":{},\"different_path_datagrams_observed\":{},\"last_os_acceptance_us\":{},\"duration_ms\":{},\"reactor_polls\":{},\"reactor_waits\":{},\"reactor_socket_events\":{},\"reactor_timer_events\":{}}}",
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
    alternate: Option<&HostSocket<'_, S, T>>,
    clock: &HostClock<'_, S, T>,
    address: Address,
    config: Config<'_>,
    tls: BoundedTls<'_, '_>,
    first: Option<(&[u8], Option<hibana_quic::quic::ecn::Codepoint>)>,
    mut files: Option<direct_bootstrap::Files>,
    early: Option<application_storage::EarlyStorage>,
    key_update_target: u64,
    routed: Option<&mut hibana_quic_host::receive_routes::Receiver<{ direct_bootstrap::DATAGRAM }>>,
    server_token: Option<&[u8]>,
    idle_timeout_ms: u64,
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
        3,
    )
    .map_err(|e| format!("recovery: {e:?}"))?;
    let statistics = Statistics::default();
    let mut receive = Receive {
        alternate: alternate.map(|socket| (socket, vec![0; direct_bootstrap::DATAGRAM])),
        routed,
        socket,
        address,
        first,
        clock,
        statistics: &statistics,
    };
    let mut transmit = Transmit {
        alternate,
        socket,
        address,
        clock,
        statistics: &statistics,
    };
    let mut body_bytes = 0;
    let (application, resumed) = if let Some(files) = &mut files {
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
            server_token,
            idle_timeout_ms,
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
            // The library validates actual peer close separately from local
            // completion. Missing transport ACKs remain false in the report;
            // authenticated complete files and actual retirement are required.
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
        (Some(report), report.resumed)
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
        let resumed = continuations.0.finished.receipt().resumed();
        drop(continuations);
        // The diagnostic explicitly declines both affine application
        // continuations after all prefix roles have joined. Accepted but
        // unacknowledged CRYPTO is still owned by recovery; retire that owner
        // rather than reporting these flights as leaked native reservations.
        let prefix = book.snapshot();
        if prefix.reserved_bytes != 0 || prefix.reserved_in_flight != 0 {
            return Err("prefix returned with unsettled native publication".into());
        }
        let (_, _, _, _, mut retirement) = book
            .split()
            .map_err(|error| format!("prefix retirement: {error:?}"))?;
        retirement.retire_all();
        (None, resumed)
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
        resumed,
        resumed_connections: usize::from(resumed),
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
        reply[end..end + 4]
            .copy_from_slice(&hibana_quic::quic::kernel::packet::QUIC_V1.to_be_bytes());
        end += 4;
        if end <= received_len.saturating_mul(3) {
            socket
                .send_to(
                    &reply[..end],
                    source,
                    hibana_quic::quic::ecn::Codepoint::NotEct,
                )
                .await
                .map_err(|error| format!("Version Negotiation: {error}"))?;
        }
    }
    Ok(true)
}
/// Stateless integrity check before committing routing identities or a worker.
/// Initial keys are public: this is not TLS peer authentication. The untouched
/// datagram still enters the ordinary Hibana receive/authentication contract.
fn initial_integrity(packet: &hibana_quic::quic::kernel::packet::Packet<'_>) -> Option<()> {
    let Header::Long {
        kind: LongType::Initial,
        destination_id,
        packet_number_offset,
        ..
    } = packet.header
    else {
        return None;
    };
    if packet.bytes.len() > direct_bootstrap::DATAGRAM {
        return None;
    }
    let key = hibana_quic::crypto::initial_keys(destination_id)
        .ok()?
        .client;
    let mut bytes = packet.bytes.to_vec();
    let pn_len = key
        .unprotect_header(&mut bytes, packet_number_offset)
        .ok()?;
    let (truncated, _) = hibana_quic::quic::kernel::packet::decode_truncated_packet_number(
        bytes[0],
        bytes.get(packet_number_offset..packet_number_offset.checked_add(pn_len)?)?,
    )
    .ok()?;
    let pn =
        hibana_quic::quic::kernel::packet::restore_packet_number(truncated, pn_len as u8, None)
            .ok()?;
    let first = bytes[0];
    let (aad, ciphertext) = bytes.split_at_mut(packet_number_offset + pn_len);
    key.open(
        pn,
        aad,
        ciphertext,
        &mut hibana_quic::crypto::IntegrityBudget::new(),
    )
    .ok()?;
    hibana_quic::quic::kernel::packet::validate_reserved_bits(first).ok()?;
    Some(())
}

async fn admit_initial<const S: usize, const T: usize>(
    socket: &HostSocket<'_, S, T>,
    first: &mut [u8],
) -> Result<(
    Address,
    Vec<u8>,
    Vec<u8>,
    usize,
    Option<hibana_quic::quic::ecn::Codepoint>,
)> {
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
            && initial_integrity(&packet).is_some()
        {
            // Routing bytes have passed packet integrity. The direct core still
            // authenticates the preserved Initial within its own scoped keys.
            return Ok((
                Address {
                    local: metadata.local,
                    remote: metadata.source,
                },
                destination_id.to_vec(),
                source_id.to_vec(),
                metadata.len,
                metadata.ecn,
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
    // Share the requested whole-operation budget between inactive recovery
    // and terminal cleanup; do not silently impose the former fixed 30 s.
    let idle_timeout_ms =
        u64::try_from(options.timeout().as_millis() / 2).map_err(|_| "idle timeout overflow")?;
    match options {
        Options::Client {
            protocol,
            version,
            connect,
            server_name,
            cipher,
            resumption,
            connections,
            early,
            key_update_target,
            ca,
            files,
            timeout,
        } => {
            // Independent connections own independent projected sessions. Join
            // their real retirement concurrently instead of serializing every
            // new Initial behind the preceding connection's closing PTOs.
            // Resumption keeps its actual ticket-dependent sequential path.
            if !resumption && connections > 1 {
                use hibana_quic::runtime::{Task, TaskSet};
                use std::{cell::RefCell, future::Future, pin::Pin};
                const MAX: usize = 64;
                let files = files.ok_or("independent connections require files")?;
                if connections > MAX || files.requests.len() != connections {
                    return Err("independent client connection capacity".into());
                }
                let results: RefCell<Vec<Option<Result<Report>>>> =
                    RefCell::new((0..connections).map(|_| None).collect());
                let mut requests = files.requests.into_iter();
                let mut workers: Vec<Pin<Box<dyn Future<Output = Result<()>> + '_>>> =
                    Vec::with_capacity(MAX);
                for index in 0..MAX {
                    let request = requests.next();
                    let results = &results;
                    let server_name = server_name.clone();
                    let ca = ca.clone();
                    let downloads = files.downloads.clone();
                    workers.push(Box::pin(async move {
                        let Some(request) = request else {
                            return Ok(());
                        };
                        let result = Box::pin(run_async(
                            reactor,
                            clock,
                            Options::Client {
                                protocol,
                                version,
                                connect,
                                server_name,
                                ca,
                                timeout,
                                cipher,
                                resumption: false,
                                connections: 1,
                                early,
                                key_update_target,
                                files: Some(cli::ClientFiles {
                                    requests: vec![request],
                                    downloads,
                                }),
                            },
                        ))
                        .await;
                        if std::env::var_os("HIBANA_QUIC_DIAGNOSTICS").is_some() {
                            match &result {
                                Ok(report) => eprintln!("connection-terminal index={} idle={} confirmed={} completed={} submitted={} acked={} closed={} elapsed_ms={}", index,
                                    report.idle_expired_connections,
                                    report.application.as_ref().is_some_and(|a| a.confirmed),
                                    report.application.as_ref().map_or(0, |a| a.completed_streams),
                                    report.application.as_ref().map_or(0, |a| a.submitted_streams),
                                    report.application.as_ref().is_some_and(|a| a.all_streams_acked),
                                    report.application.as_ref().is_some_and(|a| a.close_completed),report.elapsed),
                                Err(error) => eprintln!("connection-terminal index={index} failure={error}"),
                            }
                        }
                        results.borrow_mut()[index] = Some(result);
                        Ok(())
                    }));
                }
                let refs: Vec<Task<'_, String>> = workers
                    .iter_mut()
                    .map(|f| f.as_mut() as Task<'_, String>)
                    .collect();
                let refs: [Task<'_, String>; MAX] = refs
                    .try_into()
                    .map_err(|_| "independent client task count")?;
                TaskSet::new(refs).await?;
                drop(workers);
                let mut aggregate: Option<Report> = None;
                for result in results.into_inner() {
                    let report = result.ok_or("missing independent client result")??;
                    aggregate = Some(match aggregate {
                        Some(old) => report.append(old)?,
                        None => report,
                    });
                }
                let mut report = aggregate.ok_or("no independent client result")?;
                report.elapsed = clock.start.elapsed().as_millis();
                return Ok(report);
            }
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
                .map(|root| {
                    trust_anchor_from_der(&hibana_quic::tls::certificate::CertificateDer::from(
                        root.as_ref(),
                    ))
                })
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| format!("trust anchor: {e:?}"))?;
            while let Some(files) = groups.next() {
                let files = files
                    .map(|files| {
                        host_files::Client::new(protocol, &files.downloads, files.requests)
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
                    version,
                    &local,
                    None,
                    files.as_ref().map(direct_bootstrap::Files::local_limits),
                    None,
                    idle_timeout_ms,
                )?;
                let mut buffers = TlsBuffers::new();
                let now = UnixTime::since_unix_epoch(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_err(|_| "system clock precedes Unix epoch")?,
                );
                let config = ClientConfig {
                    protocol,
                    version,
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
                            &mut KernelEntropy,
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
                            &mut KernelEntropy,
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
                        &mut KernelEntropy,
                        ClientResumption {
                            store: &mut cache,
                            clock: &ticket_clock,
                        },
                        cipher,
                    )
                } else {
                    BoundedTls::client_with_policy(
                        config,
                        buffers.storage(),
                        &mut KernelEntropy,
                        cipher,
                    )
                }
                .map_err(|e| format!("client TLS: {e:?}"))?;
                let report = Box::pin(connected(
                    &socket,
                    None,
                    clock,
                    address,
                    Config {
                        local_preferred: None,
                        initial_path: Some(address),
                        version,
                        side: Side::Client,
                        local_connection_id: &local,
                        original_destination_id: &original,
                        retry_source_id: None,
                        initial_token: &[],
                        peer_connection_id: &original,
                    },
                    tls,
                    None,
                    files,
                    None,
                    key_update_target,
                    None,
                    None,
                    idle_timeout_ms,
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
                        hibana_quic::tls::handshake::CipherPolicy::Aes128Only => &[0x1301],
                        hibana_quic::tls::handshake::CipherPolicy::ChaCha20Only => &[0x1303],
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
            protocol,
            preferred_port,
            version,
            require_retry,
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
                    version,
                    connections,
                    idle_timeout_ms,
                )
                .await;
            }
            let certificates = pem::certificates(&cert)?;
            let key = signing_key(&pem::private_key(&key)?)?;
            let chain: Vec<&[u8]> = certificates.iter().map(|cert| cert.as_ref()).collect();
            let socket = reactor
                .register_udp(UdpSocket::bind(listen).map_err(|e| format!("UDP bind: {e}"))?)
                .map_err(|e| format!("UDP registration: {e}"))?;
            let alternate = preferred_port
                .map(|port| {
                    let mut target = listen;
                    target.set_port(port);
                    if target == listen {
                        return Err("preferred port must differ from listen port".to_owned());
                    }
                    reactor
                        .register_udp(
                            UdpSocket::bind(target)
                                .map_err(|e| format!("preferred UDP bind: {e}"))?,
                        )
                        .map_err(|e| format!("preferred UDP registration: {e}"))
                })
                .transpose()?;
            eprintln!(
                "direct Hibana server listening on {}",
                socket
                    .local_addr()
                    .map_err(|e| format!("listen address: {e}"))?
            );
            let mut replay = [const { ticket::ReplaySlot::empty() }; 8];
            let mut early_replay = hibana_quic::quic::early_data::ReplayStorage::<64>::new();
            let mut tickets = if early {
                ticket::TicketKey::generate_with_early_replay(
                    &mut KernelEntropy,
                    ticket::ReplayPolicy::ReusableOneRtt,
                    &mut replay,
                    &mut early_replay,
                )
            } else {
                ticket::TicketKey::generate(
                    &mut KernelEntropy,
                    ticket::ReplayPolicy::SingleUseOneRtt,
                    &mut replay,
                )
            }
            .map_err(|e| format!("ticket key: {e:?}"))?;
            let ticket_clock = WallTicketClock;
            let mut entropy = KernelEntropy;
            let mut retry_tokens = if require_retry {
                Some(
                    hibana_quic::quic::retry::RetryTokens::<64>::generate(
                        &mut entropy,
                        u32::from_be_bytes(random::<4>()?),
                        hibana_quic::quic::retry::DEFAULT_TOKEN_LIFETIME_US,
                    )
                    .map_err(|e| format!("Retry issuer: {e:?}"))?,
                )
            } else {
                None
            };
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
                            protocol,
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
                let retried = if let Some(tokens) = retry_tokens.as_mut() {
                    Some(retry_admission::receive(&socket, clock, tokens).await?)
                } else {
                    None
                };
                let mut first = vec![0; direct_bootstrap::DATAGRAM];
                let (address, original, peer, len, ecn) = if let Some(admitted) = retried.as_ref() {
                    first[..admitted.datagram.len()].copy_from_slice(&admitted.datagram);
                    (
                        admitted.address,
                        admitted.token.original_destination_id().to_vec(),
                        admitted.token.client_source_id().to_vec(),
                        admitted.datagram.len(),
                        admitted.ecn,
                    )
                } else {
                    admit_initial(&socket, &mut first).await?
                };
                let retry_source = retried
                    .as_ref()
                    .map(|admitted| admitted.token.retry_source_id());
                let local = random::<8>()?;
                let local_preferred = preferred_port
                    .map(|port| -> Result<_> {
                        let mut target = address.local;
                        target.set_port(port);
                        Ok(hibana_quic::quic::path::preferred::Preferred {
                            ipv4: match target {
                                SocketAddr::V4(a) => Some(a),
                                _ => None,
                            },
                            ipv6: match target {
                                SocketAddr::V6(a) => Some(a),
                                _ => None,
                            },
                            cid:
                                hibana_quic::quic::kernel::connection_id::Cid::new(&random::<8>()?)
                                    .map_err(|e| format!("preferred CID: {e:?}"))?,
                            token: hibana_quic::quic::kernel::connection_id::ResetToken::new(
                                random::<16>()?,
                            ),
                        })
                    })
                    .transpose()?;
                let mut parameters = parameters(
                    version,
                    &local,
                    Some(&original),
                    files.as_ref().map(direct_bootstrap::Files::local_limits),
                    retry_source,
                    idle_timeout_ms,
                )?;
                let mut buffers = TlsBuffers::new();
                if let Some(preferred) = local_preferred {
                    let mut encoded = [0; 61];
                    let len = preferred
                        .encode(&mut encoded)
                        .map_err(|e| format!("preferred parameter: {e:?}"))?;
                    parameters.extend_from_slice(&[13, len as u8]);
                    parameters.extend_from_slice(&encoded[..len]);
                }
                let config = ServerConfig {
                    protocol,
                    version,
                    certificate_chain: &chain,
                    signing_key: &key,
                    transport_parameters: &parameters,
                };
                let early_storage = early.then(application_storage::EarlyStorage::new);
                let tls = if let Some(storage) = early_storage.as_ref() {
                    let early_config = hibana_quic::tls::handshake::ServerEarlyData::buffered::<
                        { application_storage::RECEIVE_BYTES },
                    >(
                        u64::try_from(connection_index + 1)
                            .map_err(|_| "connection scope overflow")?,
                        application_storage::EarlyStorage::policy(),
                        &parameters,
                        storage.slots.len(),
                        hibana_quic::quic::early_data::EarlyFreshness::new(10000)
                            .map_err(|e| format!("early freshness: {e:?}"))?,
                    )
                    .map_err(|e| format!("early capacity: {e:?}"))?;
                    BoundedTls::server_with_early_data_and_policy(
                        config,
                        buffers.storage(),
                        &mut KernelEntropy,
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
                        &mut KernelEntropy,
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
                    BoundedTls::server_with_policy(
                        config,
                        buffers.storage(),
                        &mut KernelEntropy,
                        cipher,
                    )
                }
                .map_err(|e| format!("server TLS: {e:?}"))?;
                let report = Box::pin(connected(
                    &socket,
                    alternate.as_ref(),
                    clock,
                    address,
                    Config {
                        local_preferred,
                        initial_path: Some(address),
                        version,
                        side: Side::Server,
                        local_connection_id: &local,
                        original_destination_id: &original,
                        retry_source_id: retry_source,
                        initial_token: &[],
                        peer_connection_id: &peer,
                    },
                    tls,
                    Some((&first[..len], ecn)),
                    files,
                    early_storage,
                    0,
                    None,
                    None,
                    idle_timeout_ms,
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
    if matches!(&options, Options::Server { resumption: false, connections, .. } | Options::Client { resumption: false, connections, .. } if *connections > 1)
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
    fn requested_idle_budget_matches_wire_and_application_setup() {
        use hibana_quic::quic::kernel::parameters::{Parameters, Peer};
        for side in [Side::Client, Side::Server] {
            for idle_timeout_ms in [30_000, 180_000] {
                let config = Config {
                    local_preferred: None,
                    initial_path: None,
                    version: hibana_quic::quic::kernel::version::Version::V1,
                    side,
                    local_connection_id: b"local001",
                    original_destination_id: b"original",
                    retry_source_id: None,
                    initial_token: &[],
                    peer_connection_id: b"peer0001",
                };
                let mut storage =
                    application_storage::Storage::<1024>::new(1, Default::default()).unwrap();
                let setup = storage.setup(config, idle_timeout_ms).unwrap();
                let original = (side == Side::Server).then_some(&b"original"[..]);
                let bytes = parameters(
                    config.version,
                    config.local_connection_id,
                    original,
                    Some(setup.local_limits),
                    None,
                    idle_timeout_ms,
                )
                .unwrap();
                let peer = if side == Side::Client {
                    Peer::Client
                } else {
                    Peer::Server
                };
                let parsed = Parameters::parse(&bytes, peer, &mut [0; 32]).unwrap();
                assert_eq!(parsed.get_integer(1, 0).unwrap(), idle_timeout_ms);
                assert_eq!(setup.local_idle_timeout_ms, idle_timeout_ms);
            }
        }
    }

    #[test]
    fn damaged_initial_source_id_cannot_become_the_connection_identity() {
        let mut bytes = [0; direct_bootstrap::DATAGRAM];
        let header = hibana_quic::quic::kernel::packet::LongHeader {
            kind: LongType::Initial,
            destination_id: b"original",
            source_id: b"client01",
            token: &[],
            packet_number: 0,
            packet_number_len: 4,
        };
        let hlen = hibana_quic::quic::kernel::packet::encode_long_header(&header, 1176, &mut bytes)
            .unwrap();
        let mut key = hibana_quic::crypto::initial_keys(b"original")
            .unwrap()
            .client;
        let (aad, payload) = bytes[..hlen + 1176].split_at_mut(hlen);
        key.seal(0, aad, payload, 1160).unwrap();
        key.protect_header(&mut bytes[..hlen + 1176], hlen - 4)
            .unwrap();
        // The source CID is plaintext but authenticated associated data.
        bytes[15] ^= 1;
        let reactor = HostReactor::<4, 8>::new().unwrap();
        let socket = reactor
            .register_udp(UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.send_to(&bytes[..hlen + 1176], socket.local_addr().unwrap())
            .unwrap();
        let mut first = vec![0; direct_bootstrap::DATAGRAM];
        let mut admission = Box::pin(admit_initial(&socket, &mut first));
        let mut context = Context::from_waker(Waker::noop());
        assert!(admission.as_mut().poll(&mut context).is_pending());
        assert!(
            admission.as_mut().poll(&mut context).is_pending(),
            "an unauthenticated source CID was committed as the peer identity"
        );
        bytes[15] ^= 1;
        peer.send_to(&bytes[..hlen + 1176], socket.local_addr().unwrap())
            .unwrap();
        let std::task::Poll::Ready(Ok((_, original, source, len, ecn))) =
            admission.as_mut().poll(&mut context)
        else {
            panic!("the following intact Initial was not admitted");
        };
        assert_eq!(ecn, Some(hibana_quic::quic::ecn::Codepoint::NotEct));
        assert_eq!(original, b"original");
        assert_eq!(source, b"client01");
        assert_eq!(len, hlen + 1176);
    }

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
                    [hibana_quic::quic::kernel::packet::QUIC_V1]
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
