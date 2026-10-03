//! Primary direct Hibana host attachment. Authenticated prefix diagnostics are
//! executable; the file traits/CLI await the combined core application run.
#![forbid(unsafe_code)]
#![allow(long_running_const_eval)]
#[path = "support/cli.rs"] mod cli;
#[path = "support/host_files.rs"] mod host_files;
#[path = "support/direct_bootstrap.rs"] mod direct_bootstrap;
#[path = "support/direct_wire.rs"] mod direct_wire;
#[path = "support/files.rs"] mod files;
#[path = "../pem.rs"] mod pem;
use cli::{Options, USAGE, options};
use direct_wire::{HostClock, HostReactor, HostSocket, Receive, Statistics, Transmit, before_deadline};
use hibana_quic::{
    bounded_tls::{BoundedTls, ClientConfig, ServerConfig, SigningKey, Storage as TlsStorage},
    connection::{Config, Side, recovery::Recovery, tls::Transcript},
    crypto::directional::ApplicationKeyScope,
    packet::{Header, LongType, PacketIter, encode_varint}, path::Address,
    roles::{packet_authority::{Arena, ScopedArena}, publication_gate::PublicationGate},
    tls_certificate::{Limits, UnixTime, trust_anchor_from_der},
};
use p256::pkcs8::DecodePrivateKey;
use rand_core::{OsRng, RngCore};
use rustls_pki_types::PrivateKeyDer;
use std::{net::{SocketAddr, UdpSocket}, process::ExitCode, time::{Instant, SystemTime, UNIX_EPOCH}};
type Result<T> = std::result::Result<T, String>;
fn random<const N: usize>() -> Result<[u8; N]> { let mut bytes = [0; N]; OsRng.try_fill_bytes(&mut bytes).map_err(|e| format!("OS randomness: {e}"))?; Ok(bytes) }
fn parameters(local: &[u8], original: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut bytes = Vec::new(); let mut encoded = [0; 8];
    for (kind, value) in [(15, Some(local)), (0, original)] {
        if let Some(value) = value {
            let len = encode_varint(kind, &mut encoded).map_err(|e| format!("parameter: {e:?}"))?; bytes.extend_from_slice(&encoded[..len]);
            let len = encode_varint(value.len() as u64, &mut encoded).map_err(|e| format!("parameter: {e:?}"))?; bytes.extend_from_slice(&encoded[..len]); bytes.extend_from_slice(value);
        }
    }
    Ok(bytes)
}
struct TlsBuffers { rx: Vec<u8>, tx: Vec<u8>, certificates: Vec<u8>, parameters: Vec<u8> }
impl TlsBuffers {
    fn new() -> Self { Self { rx: vec![0; 16384], tx: vec![0; 16384], certificates: vec![0; 16384], parameters: vec![0; direct_bootstrap::PARAMETERS] } }
    fn storage(&mut self) -> TlsStorage<'_> { TlsStorage { rx_message: &mut self.rx, tx_flight: &mut self.tx, peer_certificates: &mut self.certificates, peer_parameters: &mut self.parameters } }
}
fn signing_key(key: &PrivateKeyDer<'_>) -> Result<SigningKey> {
    match key {
        PrivateKeyDer::Pkcs8(key) => SigningKey::from_pkcs8_der(key.secret_pkcs8_der()).map_err(|_| "server signing key must be ECDSA P-256 PKCS8".into()),
        PrivateKeyDer::Sec1(key) => p256::SecretKey::from_sec1_der(key.secret_sec1_der()).map(SigningKey::from).map_err(|_| "server signing key must be ECDSA P-256 SEC1".into()),
        _ => Err("unsupported server signing key; ECDSA P-256 required".into()),
    }
}
struct Report { side: Side, peer: SocketAddr, sent: u64, received: u64, foreign: u64, accepted_at: u64, elapsed: u128 }
impl Report {
    fn json(&self, reactor: &HostReactor) -> String {
        let stats = reactor.statistics();
        format!("{{\"backend\":\"direct-hibana-roles\",\"status\":\"success\",\"scope\":\"authenticated-handshake-prefix\",\"role\":\"{}\",\"peer\":\"{}\",\"tls_finished_authenticated\":true,\"owned_application_continuations\":true,\"quic_handshake_confirmed\":false,\"http_transfer_complete\":false,\"datagrams_sent\":{},\"datagrams_received\":{},\"foreign_datagrams_ignored\":{},\"last_os_acceptance_us\":{},\"duration_ms\":{},\"reactor_polls\":{},\"reactor_waits\":{},\"reactor_socket_events\":{},\"reactor_timer_events\":{}}}", if self.side == Side::Client { "client" } else { "server" }, self.peer, self.sent, self.received, self.foreign, self.accepted_at, self.elapsed, stats.polls, stats.waits, stats.socket_events, stats.timer_events)
    }
}
#[allow(clippy::too_many_arguments)]
async fn connected(socket: &HostSocket<'_>, clock: &HostClock<'_>, address: Address, config: Config<'_>, tls: BoundedTls<'_, '_>, first: Option<&[u8]>) -> Result<Report> {
    let generation = u64::from_be_bytes(random::<8>()?); let mut scope = ApplicationKeyScope::new(generation);
    let mut identity = scope.claim().map_err(|e| format!("scope: {e:?}"))?;
    let mut arena_storage = Box::new(Arena::<8, 32>::new(generation));
    let arena = ScopedArena::new(&mut arena_storage, identity.take_packet_authority().map_err(|e| format!("packet authority: {e:?}"))?).map_err(|e| format!("packet arena: {e:?}"))?;
    let mut gate = PublicationGate::new(identity.take_publication_gate().map_err(|e| format!("publication authority: {e:?}"))?);
    let (mut issuer, _stop) = gate.split().map_err(|e| format!("publication facets: {e:?}"))?;
    let mut source = Transcript::new(tls.into_key_source(identity).map_err(|e| format!("TLS source: {e:?}"))?);
    let mut book = Recovery::<{direct_bootstrap::DATAGRAM}>::new(arena.claim_recovery().map_err(|e| format!("recovery authority: {e:?}"))?, config.side, 333_000, direct_bootstrap::DATAGRAM as u64).map_err(|e| format!("recovery: {e:?}"))?;
    let statistics = Statistics::default();
    let mut receive = Receive { socket, address, first, clock, statistics: &statistics };
    let mut transmit = Transmit { socket, address, clock, statistics: &statistics };
    let (received, transmitted) = Box::pin(direct_bootstrap::handshake(&mut source, config, &mut receive, &mut transmit, clock, &mut issuer, &mut book, generation)).await?;
    let snapshot = book.snapshot();
    if snapshot.active_flights != 0 || snapshot.reserved_bytes != 0 || snapshot.reserved_in_flight != 0 { return Err("handshake returned with live flight reservations".into()); }
    if config.side == Side::Server && !snapshot.address_validated { return Err("server peer path was not validated".into()); }
    // These actual affine continuations await the combined application's
    // declared handoff. Prefix diagnostics never claim HTTP/confirmation.
    drop((received, transmitted));
    Ok(Report { side: config.side, peer: address.remote, sent: statistics.sent.get(), received: statistics.received.get(), foreign: statistics.foreign.get(), accepted_at: statistics.last_accepted.get().ok_or("no real UDP acceptance")?, elapsed: clock.start.elapsed().as_millis() })
}
async fn run_async(reactor: &HostReactor, clock: &HostClock<'_>, options: Options) -> Result<Report> {
    match options {
        Options::Client { connect, server_name, ca, .. } => {
            let roots = pem::certificates(&ca)?;
            let anchors = roots.iter().map(trust_anchor_from_der).collect::<std::result::Result<Vec<_>, _>>().map_err(|e| format!("trust anchor: {e:?}"))?;
            // Routing-only connect chooses a source IP without transmitting.
            let route = UdpSocket::bind(if connect.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).map_err(|e| format!("route socket: {e}"))?;
            route.connect(connect).map_err(|e| format!("route selection: {e}"))?;
            let mut bind = route.local_addr().map_err(|e| format!("route address: {e}"))?; bind.set_port(0); drop(route);
            let socket = reactor.register_udp(UdpSocket::bind(bind).map_err(|e| format!("UDP bind: {e}"))?).map_err(|e| format!("UDP registration: {e}"))?;
            let address = Address { local: socket.local_addr().map_err(|e| format!("local address: {e}"))?, remote: connect };
            let local = random::<8>()?; let original = random::<8>()?; let parameters = parameters(&local, None)?; let mut buffers = TlsBuffers::new();
            let now = UnixTime::since_unix_epoch(SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| "system clock precedes Unix epoch")?);
            let tls = BoundedTls::client(ClientConfig { server_name: &server_name, trust_anchors: &anchors, now, certificate_limits: Limits::default(), transport_parameters: &parameters }, buffers.storage(), &mut OsRng).map_err(|e| format!("client TLS: {e:?}"))?;
            Box::pin(connected(&socket, clock, address, Config { side: Side::Client, local_connection_id: &local, original_destination_id: &original, peer_connection_id: &original }, tls, None)).await
        }
        Options::Server { listen, cert, key, .. } => {
            let certificates = pem::certificates(&cert)?; let key = signing_key(&pem::private_key(&key)?)?;
            let chain: Vec<&[u8]> = certificates.iter().map(|cert| cert.as_ref()).collect();
            let socket = reactor.register_udp(UdpSocket::bind(listen).map_err(|e| format!("UDP bind: {e}"))?).map_err(|e| format!("UDP registration: {e}"))?;
            eprintln!("direct Hibana server listening on {}", socket.local_addr().map_err(|e| format!("listen address: {e}"))?);
            let mut first = vec![0; direct_bootstrap::DATAGRAM];
            let (address, original, peer, len) = loop {
                // Every rejection returns through this guaranteed Pending
                // yield, bounding admission to one datagram per root poll.
                hibana_quic::runtime::yield_now().await;
                let metadata = match socket.recv_from(&mut first).await {
                    Ok(metadata) => metadata,
                    Err(error) if error.kind() == std::io::ErrorKind::InvalidData => continue,
                    Err(error) => return Err(format!("Initial admission: {error}")),
                };
                if metadata.len < 1200 { continue; }
                let packet = PacketIter::new(&first[..metadata.len], 8, 8).ok().and_then(|mut packets| packets.next()).and_then(std::result::Result::ok);
                if let Some(packet) = packet && let Header::Long { kind: LongType::Initial, destination_id, source_id, token, .. } = packet.header && destination_id.len() >= 8 && token.is_empty() {
                    // Untrusted routing input; unchanged encrypted bytes still
                    // undergo the direct core's actual Initial AEAD check.
                    break (Address { local: metadata.local, remote: metadata.source }, destination_id.to_vec(), source_id.to_vec(), metadata.len);
                }
            };
            let local = random::<8>()?; let parameters = parameters(&local, Some(&original))?; let mut buffers = TlsBuffers::new();
            let tls = BoundedTls::server(ServerConfig { certificate_chain: &chain, signing_key: &key, transport_parameters: &parameters }, buffers.storage(), &mut OsRng).map_err(|e| format!("server TLS: {e:?}"))?;
            Box::pin(connected(&socket, clock, address, Config { side: Side::Server, local_connection_id: &local, original_destination_id: &original, peer_connection_id: &peer }, tls, Some(&first[..len]))).await
        }
    }
}
fn run(options: Options) -> Result<String> {
    if options.application_requested() { return Err("direct application continuation attachment is not ready".into()); }
    let reactor = HostReactor::new().map_err(|e| format!("host reactor: {e}"))?; let clock = HostClock::new(&reactor, Instant::now());
    let deadline = clock.start.checked_add(options.timeout()).ok_or("deadline overflow")?;
    // Explicit host heap boundary; no enlarged stack or blocking core pump.
    let task = Box::pin(before_deadline(&clock, deadline, run_async(&reactor, &clock, options)));
    let report = reactor.block_on(task).map_err(|e| format!("host reactor: {e}"))??; Ok(report.json(&reactor))
}
fn main() -> ExitCode {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|arg| arg == "--help" || arg == "-h") { println!("{USAGE}"); return ExitCode::SUCCESS; }
    match options(&args).and_then(run) { Ok(report) => { println!("{report}"); ExitCode::SUCCESS }, Err(error) => { eprintln!("hq: {error}"); ExitCode::FAILURE } }
}
