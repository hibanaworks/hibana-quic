//! Host UDP adapter using only the bounded P256/ECDSA TLS profile.
//! Host file/PEM/network setup allocates; TLS/QUIC core uses caller-owned buffers.
//! No HTTP, transfer, migration, complete recovery, or runner testcase support is implied.
#![forbid(unsafe_code)]
// The composed Initial RX/TX + TLS choreography exceeds the default const-eval lint budget.
#![allow(long_running_const_eval)]

#[path = "support/handshake_io.rs"]
mod handshake_io;
#[path = "support/initial_roles.rs"]
mod initial_roles;
#[path = "../../../adapters/host/src/pem.rs"]
mod pem;
use handshake_io::{EXPIRED, HostReactor, HostSocket, before_deadline, deadline, receive_until};
use pem::{certificates, private_key};

use hibana::runtime::{SessionKitStorage, ids::SessionId};
use hibana_quic::bounded_tls::{
    BoundedTls, ClientConfig as BoundedClientConfig, ServerConfig as BoundedServerConfig,
    SigningKey, Storage,
};
use hibana_quic::tls_certificate::{CertificateDer, Limits, UnixTime, trust_anchor_from_der};
use hibana_quic::{
    carrier::{CarrierStorage, LocalCarrier},
    driver::{Driver, Roles},
    handshake::CryptoBuffer,
    handshake_endpoint::{
        Config, HandshakeEndpoint, InitialKeyProtection, InitialProtection, Side, TlsClient,
    },
    packet::{Header, LongType, PacketIter, encode_varint},
    protocol::*,
};
use p256::pkcs8::DecodePrivateKey;
use rand_core::{OsRng, RngCore};
use rustls_pki_types::PrivateKeyDer;
use std::{
    collections::BTreeMap,
    io,
    net::{SocketAddr, UdpSocket},
    path::PathBuf,
    pin::pin,
    process::ExitCode,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

type Result<T> = std::result::Result<T, String>;
const DEFAULT_TIMEOUT: u64 = 10;
const UDP_BYTES: usize = 65_535;
const MAX_OUTPUT_PER_TURN: usize = 64;
const USAGE: &str = "Experimental bounded-profile QUIC v1 handshake adapter; P256/ECDSA/SHA256 only\n\n  bounded-handshake client --connect IP:PORT --server-name HOST --ca ROOTS.pem [--timeout-seconds 10]\n  bounded-handshake server --listen IP:PORT --cert CHAIN.pem --key KEY.pem [--timeout-seconds 10]\n\nIPv6 addresses use [IP]:PORT. One connection only. Explicit certificate verification.\nSuccess means local authenticated TLS/transport-parameter completion and queued output\naccepted by UDP, not full QUIC interoperability, HTTP transfer, or peer confirmation.\nP256 HRR is supported; mandatory RSA, PSK/ticket cache/0RTT, HTTP and migration remain unsupported; timeouts exit unsuccessfully.";

#[derive(Debug)]
enum Options {
    Client {
        connect: SocketAddr,
        server_name: String,
        ca: PathBuf,
        timeout: Duration,
    },
    Server {
        listen: SocketAddr,
        cert: PathBuf,
        key: PathBuf,
        timeout: Duration,
    },
}
fn parse_options(args: &[String]) -> Result<Options> {
    let role = args.first().ok_or_else(|| USAGE.to_owned())?;
    let mut flags = BTreeMap::new();
    let mut remaining = args[1..].chunks_exact(2);
    for pair in &mut remaining {
        if !pair[0].starts_with("--") {
            return Err(format!("expected flag, got {}", pair[0]));
        }
        if flags.insert(pair[0].as_str(), pair[1].as_str()).is_some() {
            return Err(format!("duplicate option {}", pair[0]));
        }
    }
    if !remaining.remainder().is_empty() {
        return Err("every option requires a value".into());
    }
    let timeout = flags
        .remove("--timeout-seconds")
        .map(|v| v.parse::<u64>())
        .transpose()
        .map_err(|_| "invalid timeout seconds")?
        .unwrap_or(DEFAULT_TIMEOUT);
    if !(1..=300).contains(&timeout) {
        return Err("timeout must be 1..=300 seconds".into());
    }
    let timeout = Duration::from_secs(timeout);
    let mut required = |name| {
        flags
            .remove(name)
            .ok_or_else(|| format!("missing required option {name}"))
    };
    let options = match role.as_str() {
        "client" => Options::Client {
            connect: required("--connect")?
                .parse()
                .map_err(|_| "--connect must be IP:PORT")?,
            server_name: required("--server-name")?.to_owned(),
            ca: required("--ca")?.into(),
            timeout,
        },
        "server" => Options::Server {
            listen: required("--listen")?
                .parse()
                .map_err(|_| "--listen must be IP:PORT")?,
            cert: required("--cert")?.into(),
            key: required("--key")?.into(),
            timeout,
        },
        _ => return Err(format!("unknown role {role}\n{USAGE}")),
    };
    if let Some(flag) = flags.keys().next() {
        return Err(format!("unsupported option {flag}"));
    }
    Ok(options)
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| format!("OS cryptographic randomness unavailable: {e}"))?;
    Ok(bytes)
}
struct TlsBuffers {
    rx: [u8; 16384],
    tx: [u8; 16384],
    cert: [u8; 16384],
    parameters: [u8; 2048],
}
impl TlsBuffers {
    fn new() -> Self {
        Self {
            rx: [0; 16384],
            tx: [0; 16384],
            cert: [0; 16384],
            parameters: [0; 2048],
        }
    }
    fn storage(&mut self) -> Storage<'_> {
        Storage {
            rx_message: &mut self.rx,
            tx_flight: &mut self.tx,
            peer_certificates: &mut self.cert,
            peer_parameters: &mut self.parameters,
        }
    }
}
fn certificate_time() -> Result<UnixTime> {
    Ok(UnixTime::since_unix_epoch(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock is before Unix epoch")?,
    ))
}
fn signing_key(key: &PrivateKeyDer<'_>) -> Result<SigningKey> {
    match key {
        PrivateKeyDer::Pkcs8(key) => SigningKey::from_pkcs8_der(key.secret_pkcs8_der())
            .map_err(|_| "bounded profile requires an ECDSA P-256 PKCS8 key".into()),
        PrivateKeyDer::Sec1(key) => p256::SecretKey::from_sec1_der(key.secret_sec1_der())
            .map(SigningKey::from)
            .map_err(|_| "bounded profile requires an ECDSA P-256 SEC1 key".into()),
        _ => Err("unsupported private-key algorithm; bounded profile has no RSA fallback".into()),
    }
}
fn parameters(local: &[u8], original: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut encoded = [0; 8];
    for (kind, data) in [(15, Some(local)), (0, original)] {
        if let Some(data) = data {
            let n = encode_varint(kind, &mut encoded)
                .map_err(|e| format!("transport parameter: {e:?}"))?;
            out.extend_from_slice(&encoded[..n]);
            let n = encode_varint(data.len() as u64, &mut encoded)
                .map_err(|e| format!("transport parameter: {e:?}"))?;
            out.extend_from_slice(&encoded[..n]);
            out.extend_from_slice(data);
        }
    }
    Ok(out)
}
fn now(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX)
}
fn transient(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

#[derive(Debug)]
struct Report {
    side: Side,
    peer: SocketAddr,
    sent: u64,
    received: u64,
    authenticated: u64,
    discarded: u64,
    duration_ms: u128,
}
impl Report {
    fn json(&self) -> String {
        format!(
            "{{\"backend\":\"bounded-profile\",\"tls_profile\":\"P256-ECDSA-SHA256\",\"mandatory_tls_algorithms_complete\":false,\"scope\":\"handshake-only\",\"status\":\"success\",\"role\":\"{}\",\"peer\":\"{}\",\"handshake_complete\":true,\"output_drained\":true,\"alpn\":\"hq-interop\",\"datagrams_sent\":{},\"datagrams_received\":{},\"authenticated_packets\":{},\"discarded_packets\":{},\"duration_ms\":{}}}",
            if self.side == Side::Client {
                "client"
            } else {
                "server"
            },
            self.peer,
            self.sent,
            self.received,
            self.authenticated,
            self.discarded,
            self.duration_ms
        )
    }
}
fn run(options: Options) -> Result<Report> {
    match options {
        Options::Client {
            connect,
            server_name,
            ca,
            timeout: budget,
        } => {
            let start = Instant::now();
            let root_der = certificates(&ca)?;
            let anchors = root_der
                .iter()
                .map(trust_anchor_from_der)
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| format!("trust root: {e:?}"))?;
            let local = random::<8>()?;
            let original = random::<8>()?;
            let parameters = parameters(&local, None)?;
            let mut buffers = TlsBuffers::new();
            let tls = BoundedTls::client(
                BoundedClientConfig {
                    server_name: &server_name,
                    trust_anchors: &anchors,
                    now: certificate_time()?,
                    certificate_limits: Limits::default(),
                    transport_parameters: &parameters,
                },
                buffers.storage(),
                &mut OsRng,
            )
            .map_err(|e| format!("bounded client TLS configuration: {e:?}"))?;
            let bind = if connect.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let socket = UdpSocket::bind(bind).map_err(|e| format!("UDP bind: {e}"))?;
            exchange(
                socket,
                connect,
                Side::Client,
                local,
                original.to_vec(),
                tls,
                None,
                start,
                budget,
            )
        }
        Options::Server {
            listen,
            cert,
            key,
            timeout: budget,
        } => {
            let chain = certificates(&cert)?;
            let key = private_key(&key)?;
            let socket = UdpSocket::bind(listen).map_err(|e| format!("UDP listen: {e}"))?;
            serve(socket, chain, key, budget)
        }
    }
}
fn serve(
    socket: UdpSocket,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    budget: Duration,
) -> Result<Report> {
    let reactor = HostReactor::new().map_err(|e| format!("reactor setup: {e}"))?;
    let socket = reactor
        .register_udp(socket)
        .map_err(|e| format!("UDP registration: {e}"))?;
    let mut execution = pin!(serve_async(&reactor, &socket, chain, key, budget));
    reactor
        .block_on(execution.as_mut())
        .map_err(|e| format!("reactor: {e}"))?
}
async fn serve_async(
    reactor: &HostReactor,
    socket: &HostSocket<'_>,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    budget: Duration,
) -> Result<Report> {
    let start = Instant::now();
    let mut incoming = [0_u8; UDP_BYTES];
    // Read a syntactically valid v1 Initial to discover its real original DCID.
    // This is untrusted routing input; authentication happens in the core.
    let overall_deadline = deadline(start, budget)?;
    let (len, peer, original) = loop {
        hibana_quic::runtime::yield_now().await;
        match receive_until(reactor, socket, &mut incoming, overall_deadline).await {
            Ok(Some(received)) => {
                let (len, peer) = (received.len, received.source);
                if len < 1200 {
                    continue;
                }
                let first = PacketIter::new(&incoming[..len], 8, 8)
                    .ok()
                    .and_then(|mut iter| iter.next())
                    .and_then(std::result::Result::ok);
                if let Some(packet) = first
                    && let Header::Long {
                        kind: LongType::Initial,
                        destination_id,
                        ..
                    } = packet.header
                    && !destination_id.is_empty()
                {
                    break (len, peer, destination_id.to_vec());
                }
            }
            Ok(None) => return Err(EXPIRED.into()),
            Err(error) if transient(&error) => continue,
            Err(error) => return Err(format!("UDP initial receive: {error}")),
        }
    };
    let local = random::<8>()?;
    let parameters = parameters(&local, Some(&original))?;
    let signing_key = signing_key(&key)?;
    let chain: Vec<&[u8]> = chain.iter().map(|cert| cert.as_ref()).collect();
    let mut buffers = TlsBuffers::new();
    let tls = BoundedTls::server(
        BoundedServerConfig {
            certificate_chain: &chain,
            signing_key: &signing_key,
            transport_parameters: &parameters,
        },
        buffers.storage(),
        &mut OsRng,
    )
    .map_err(|e| format!("bounded server TLS configuration: {e:?}"))?;
    exchange_async(
        reactor,
        socket,
        peer,
        Side::Server,
        local,
        original,
        tls,
        Some(&incoming[..len]),
        start,
        budget,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
fn exchange(
    socket: UdpSocket,
    peer: SocketAddr,
    side: Side,
    local: [u8; 8],
    original: Vec<u8>,
    tls: BoundedTls<'_, '_>,
    first: Option<&[u8]>,
    start: Instant,
    budget: Duration,
) -> Result<Report> {
    let reactor = HostReactor::new().map_err(|e| format!("reactor setup: {e}"))?;
    let socket = reactor
        .register_udp(socket)
        .map_err(|e| format!("UDP registration: {e}"))?;
    let mut execution = pin!(exchange_async(
        &reactor, &socket, peer, side, local, original, tls, first, start, budget,
    ));
    reactor
        .block_on(execution.as_mut())
        .map_err(|e| format!("reactor: {e}"))?
}
#[allow(clippy::too_many_arguments)]
async fn exchange_async(
    reactor: &HostReactor,
    socket: &HostSocket<'_>,
    peer: SocketAddr,
    side: Side,
    local: [u8; 8],
    original: Vec<u8>,
    tls: BoundedTls<'_, '_>,
    first: Option<&[u8]>,
    start: Instant,
    budget: Duration,
) -> Result<Report> {
    let generation = u64::from_be_bytes(random::<8>()?);
    let keys =
        hibana_quic::crypto::initial_keys(&original).map_err(|e| format!("Initial keys: {e:?}"))?;
    initial_roles::with_connection(keys, side, generation, tls, async move |initial, tls| {
        exchange_connected(
            reactor, socket, peer, side, local, original, tls, first, start, budget, generation,
            initial,
        )
        .await
    })
    .await
}
#[allow(clippy::too_many_arguments)]
async fn exchange_connected(
    reactor: &HostReactor,
    socket: &HostSocket<'_>,
    peer: SocketAddr,
    side: Side,
    local: [u8; 8],
    original: Vec<u8>,
    tls: TlsClient<'_, '_>,
    first: Option<&[u8]>,
    start: Instant,
    budget: Duration,
    generation: u64,
    initial: InitialProtection<'_, '_>,
) -> Result<Report> {
    let sid = SessionId::new(1);
    let queues = CarrierStorage::<8, 16, { hibana_quic::protocol::SERVICE_PORTS }>::new();
    let mut slab = [0_u8; 32 * 1024];
    let mut kit_storage = SessionKitStorage::<
        LocalCarrier<'_, 8, 16, { hibana_quic::protocol::SERVICE_PORTS }>,
    >::uninit();
    let kit = kit_storage.init();
    let rv = kit
        .rendezvous(
            &mut slab,
            queues
                .bind(sid)
                .map_err(|e| format!("carrier binding: {e:?}"))?,
        )
        .map_err(|e| format!("Hibana rendezvous: {e:?}"))?;
    let p0 = service_program::<INGRESS>();
    let p1 = service_program::<PACKET>();
    let p2 = service_program::<APPLICATION>();
    let p3 = service_program::<RECOVERY>();
    let p4 = service_program::<ADAPTER>();
    let p5 = service_program::<TIMER>();
    let roles = Roles {
        ingress: rv
            .enter(sid, &p0)
            .map_err(|e| format!("attach ingress: {e:?}"))?,
        packet: rv
            .enter(sid, &p1)
            .map_err(|e| format!("attach packet: {e:?}"))?,
        application: rv
            .enter(sid, &p2)
            .map_err(|e| format!("attach application: {e:?}"))?,
        recovery: rv
            .enter(sid, &p3)
            .map_err(|e| format!("attach recovery: {e:?}"))?,
        adapter: rv
            .enter(sid, &p4)
            .map_err(|e| format!("attach adapter: {e:?}"))?,
        timer: rv
            .enter(sid, &p5)
            .map_err(|e| format!("attach timer: {e:?}"))?,
    };
    // The nine-certificate bounded profile needs a >9KiB Handshake flight.
    // Initial and application CRYPTO keep their independent smaller budgets.
    let mut d0 = [0; 8192];
    let mut d1 = [0; 16384];
    let mut d2 = [0; 8192];
    let mut m0 = [0; hibana_quic::handshake::bitmap_bytes(8192)];
    let mut m1 = [0; hibana_quic::handshake::bitmap_bytes(16384)];
    let mut m2 = [0; hibana_quic::handshake::bitmap_bytes(8192)];
    let crypto = [
        CryptoBuffer::new(&mut d0, &mut m0).map_err(|e| format!("CRYPTO storage: {e:?}"))?,
        CryptoBuffer::new(&mut d1, &mut m1).map_err(|e| format!("CRYPTO storage: {e:?}"))?,
        CryptoBuffer::new(&mut d2, &mut m2).map_err(|e| format!("CRYPTO storage: {e:?}"))?,
    ];
    let config = Config {
        side,
        local_id: &local,
        original_destination_id: &original,
        generation,
    };
    let mut endpoint =
        HandshakeEndpoint::new(config, tls, Driver::new(generation, roles), crypto, initial)
            .map_err(|e| format!("endpoint configuration: {e:?}"))?;
    let mut report = Report {
        side,
        peer,
        sent: 0,
        received: 0,
        authenticated: 0,
        discarded: 0,
        duration_ms: 0,
    };
    let mut incoming = [0; UDP_BYTES];
    let mut scratch = [0; UDP_BYTES];
    let mut outgoing = [0; 1500];
    if let Some(bytes) = first {
        let result = endpoint
            .receive(bytes, &mut scratch)
            .await
            .map_err(|e| endpoint_error("initial receive", &endpoint, e))?;
        report.received += 1;
        report.authenticated += result.authenticated as u64;
        report.discarded += result.discarded as u64;
    }
    let overall_deadline = deadline(start, budget)?;
    loop {
        hibana_quic::runtime::yield_now().await;
        if start.elapsed() >= budget {
            endpoint.retire();
            return Err("handshake deadline expired; no success reported".into());
        }
        endpoint
            .timer(now(start))
            .await
            .map_err(|e| endpoint_error("monotonic timer", &endpoint, e))?;
        let mut drained = false;
        for _ in 0..MAX_OUTPUT_PER_TURN {
            let Some(tx) = endpoint
                .transmit(&mut outgoing)
                .await
                .map_err(|e| endpoint_error("transmit", &endpoint, e))?
            else {
                drained = true;
                break;
            };
            match before_deadline(
                reactor,
                overall_deadline,
                socket.send_to(
                    &outgoing[..tx.len],
                    peer,
                    hibana_quic::ecn::Codepoint::NotEct,
                ),
            )
            .await
            {
                Ok(written) if written == tx.len => {
                    // UDP acceptance is reported only after a successful send.
                    endpoint
                        .adapter_result(tx, true, now(start))
                        .await
                        .map_err(|e| endpoint_error("adapter acceptance", &endpoint, e))?;
                    report.sent += 1;
                }
                outcome => {
                    endpoint
                        .adapter_result(tx, false, now(start))
                        .await
                        .map_err(|e| endpoint_error("adapter rejection", &endpoint, e))?;
                    endpoint.retire();
                    return Err(format!("UDP datagram was not accepted: {outcome:?}"));
                }
            }
        }
        if !drained {
            endpoint.retire();
            return Err("bounded transmit work budget exhausted".into());
        }
        // Critically, test completion only AFTER flushing the client's own
        // Finished bytes and every other queued TLS/ACK output to the adapter.
        if endpoint.handshake_complete() {
            report.duration_ms = start.elapsed().as_millis();
            endpoint
                .retire_owned()
                .await
                .map_err(|e| endpoint_error("actor retirement", &endpoint, e))?;
            return Ok(report);
        }
        if endpoint.is_retired() {
            return Err("peer closed before handshake completion".into());
        }
        let wake_at = endpoint
            .next_deadline()
            .and_then(|micros| start.checked_add(Duration::from_micros(micros)))
            .map_or(overall_deadline, |at| at.min(overall_deadline));
        match receive_until(reactor, socket, &mut incoming, wake_at).await {
            Ok(Some(received)) if received.source == peer => {
                let len = received.len;
                let result = endpoint
                    .receive(&incoming[..len], &mut scratch)
                    .await
                    .map_err(|e| endpoint_error("receive", &endpoint, e))?;
                report.received += 1;
                report.authenticated += result.authenticated as u64;
                report.discarded += result.discarded as u64;
            }
            Ok(Some(_)) => { /* Single connection: no implicit migration. */ }
            Ok(None) => {}
            Err(error) if transient(&error) => {}
            Err(error) => {
                endpoint.retire();
                return Err(format!("UDP receive: {error}"));
            }
        }
    }
}
fn endpoint_error<K: InitialKeyProtection>(
    stage: &str,
    endpoint: &HandshakeEndpoint<'_, '_, '_, '_, K>,
    error: hibana_quic::handshake_endpoint::Error,
) -> String {
    let diagnostic = &endpoint.tls_snapshot().diagnostic;
    if diagnostic.is_empty() {
        format!("{stage}: {error:?}")
    } else {
        format!(
            "{stage}: {error:?}; TLS: {}{}",
            diagnostic.as_str(),
            if diagnostic.truncated() || diagnostic.format_error() {
                " [incomplete]"
            } else {
                ""
            }
        )
    }
}
fn json_string(value: &str) -> String {
    let mut out = String::from("\"");
    for character in value.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < '\u{20}' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.as_slice() == ["--help"] || args.as_slice() == ["-h"] {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    match parse_options(&args).and_then(run) {
        Ok(report) => {
            println!("{}", report.json());
            ExitCode::SUCCESS
        }
        Err(error) => {
            println!(
                "{{\"backend\":\"bounded-profile\",\"tls_profile\":\"P256-ECDSA-SHA256\",\"mandatory_tls_algorithms_complete\":false,\"scope\":\"handshake-only\",\"status\":\"failure\",\"handshake_complete\":false,\"error\":{}}}",
                json_string(&error)
            );
            ExitCode::FAILURE
        }
    }
}
