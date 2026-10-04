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
#[path = "../pem.rs"]
mod pem;
use cli::{Options, USAGE, options};
use direct_wire::{
    HostClock, HostReactor, HostSocket, Receive, Statistics, Transmit, before_deadline,
};
use hibana_quic::{
    bounded_tls::{BoundedTls, ClientConfig, ServerConfig, SigningKey, Storage as TlsStorage},
    connection::publication_gate::PublicationGate,
    connection::{Config, Side, application, recovery::Recovery, tls::Transcript},
    crypto::directional::ApplicationKeyScope,
    packet::{Header, LongType, PacketIter, encode_varint},
    path::Address,
    tls_certificate::{Limits, UnixTime, trust_anchor_from_der},
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
    application_side: Option<Side>,
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
    if let Some(side) = application_side {
        // Advertise exactly the windows backed by application_storage.
        let limits = application_storage::local_limits(side);
        for (kind, value) in [
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
    fn json(&self, reactor: &HostReactor) -> String {
        let stats = reactor.statistics();
        let transfer = if let Some(report) = self.application {
            format!(
                "\"scope\":\"authenticated-file-transfer\",\"quic_handshake_confirmed\":{},\"http_transfer_complete\":true,\"lifecycle_closed\":{},\"all_streams_acked\":{},\"files_submitted\":{},\"files_completed\":{},\"body_bytes\":{},\"udp_received_bytes_before_close\":{},\"udp_accepted_bytes_before_close\":{}",
                report.confirmed,
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
            "{{\"backend\":\"direct-hibana-roles\",\"status\":\"success\",{transfer},\"role\":\"{}\",\"peer\":\"{}\",\"tls_finished_authenticated\":true,\"datagrams_sent\":{},\"datagrams_received\":{},\"foreign_datagrams_ignored\":{},\"last_os_acceptance_us\":{},\"duration_ms\":{},\"reactor_polls\":{},\"reactor_waits\":{},\"reactor_socket_events\":{},\"reactor_timer_events\":{}}}",
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
async fn connected(
    socket: &HostSocket<'_>,
    clock: &HostClock<'_>,
    address: Address,
    config: Config<'_>,
    tls: BoundedTls<'_, '_>,
    first: Option<&[u8]>,
    mut files: Option<direct_bootstrap::Files>,
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
        ))
        .await
        .map_err(|error| match diagnostics.take() {
            Some(detail) => format!("{error}: {detail}"),
            None => error,
        })?;
        if !report.confirmed
            || !report.all_streams_acked
            || !report.close_completed
            || report.completed_streams == 0
            || report.completed_streams != report.submitted_streams
            || report.completed_streams != observations.files_finished.get()
            || report.submitted_streams != observations.files_started.get()
            || expected.is_some_and(|count| count != report.completed_streams)
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
async fn admit_initial(
    socket: &HostSocket<'_>,
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
            && let Header::UnsupportedVersion {
                destination_id,
                source_id,
                ..
            } = packet.header
            && destination_id.len() <= 20
            && source_id.len() <= 20
        {
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
            if end <= metadata.len.saturating_mul(3) {
                socket
                    .send_to(
                        &reply[..end],
                        metadata.source,
                        hibana_quic::ecn::Codepoint::NotEct,
                    )
                    .await
                    .map_err(|error| format!("Version Negotiation: {error}"))?;
            }
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
async fn run_async(
    reactor: &HostReactor,
    clock: &HostClock<'_>,
    options: Options,
) -> Result<Report> {
    match options {
        Options::Client {
            connect,
            server_name,
            cipher,
            ca,
            files,
            ..
        } => {
            let files = files
                .map(|files| {
                    host_files::Client::new(&files.downloads, files.requests)
                        .map(direct_bootstrap::Files::Client)
                })
                .transpose()?;
            let roots = pem::certificates(&ca)?;
            let anchors = roots
                .iter()
                .map(trust_anchor_from_der)
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| format!("trust anchor: {e:?}"))?;
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
            let parameters = parameters(&local, None, files.as_ref().map(|_| Side::Client))?;
            let mut buffers = TlsBuffers::new();
            let now = UnixTime::since_unix_epoch(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| "system clock precedes Unix epoch")?,
            );
            let tls = BoundedTls::client_with_policy(
                ClientConfig {
                    server_name: &server_name,
                    trust_anchors: &anchors,
                    now,
                    certificate_limits: Limits::default(),
                    transport_parameters: &parameters,
                },
                buffers.storage(),
                &mut OsRng,
                cipher,
            )
            .map_err(|e| format!("client TLS: {e:?}"))?;
            Box::pin(connected(
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
            ))
            .await
        }
        Options::Server {
            listen,
            cert,
            cipher,
            key,
            files,
            ..
        } => {
            let files = files
                .map(|files| {
                    host_files::FileServer::new(
                        &files.www,
                        files.max_requests.unwrap_or(host_files::MAX_REQUESTS),
                    )
                    .map(direct_bootstrap::Files::Server)
                })
                .transpose()?;
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
            let mut first = vec![0; direct_bootstrap::DATAGRAM];
            let (address, original, peer, len) = admit_initial(&socket, &mut first).await?;
            let local = random::<8>()?;
            let parameters = parameters(
                &local,
                Some(&original),
                files.as_ref().map(|_| Side::Server),
            )?;
            let mut buffers = TlsBuffers::new();
            let tls = BoundedTls::server_with_policy(
                ServerConfig {
                    certificate_chain: &chain,
                    signing_key: &key,
                    transport_parameters: &parameters,
                },
                buffers.storage(),
                &mut OsRng,
                cipher,
            )
            .map_err(|e| format!("server TLS: {e:?}"))?;
            Box::pin(connected(
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
            ))
            .await
        }
    }
}
fn run(options: Options) -> Result<String> {
    let reactor = HostReactor::new().map_err(|e| format!("host reactor: {e}"))?;
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
    let report = reactor
        .block_on(task)
        .map_err(|e| format!("host reactor: {e}"))??;
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
        let reactor = HostReactor::new().unwrap();
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
            let reactor = HostReactor::new().unwrap();
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
