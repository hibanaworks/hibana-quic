//! Linux development HTTP/0.9 adapter. Real bounded TLS + hibana-quic transport;
//! host arguments, files and PEM setup allocate, file bodies are streamed.
#![forbid(unsafe_code)]

#[path = "../../../adapters/host/src/pem.rs"]
mod pem;
use pem::{certificates, private_key};
#[cfg(not(target_os = "linux"))]
compile_error!("hq's symlink-safe descriptor-relative file adapter requires Linux");

use hibana::runtime::{SessionKitStorage, ids::SessionId};
use hibana_quic::{
    bounded_tls::{
        BoundedTls, CipherPolicy, ClientConfig as BoundedClientConfig, ClientResumption,
        ServerConfig as BoundedServerConfig, ServerResumption, SigningKey, Storage,
    },
    carrier::{CarrierStorage, LocalCarrier},
    crypto::CipherSuite,
    driver::{Driver, Roles},
    ecn::{self, Codepoint},
    handshake::CryptoBuffer,
    handshake_endpoint::{Config, Error as EngineError, HandshakeEndpoint, Side},
    lifecycle::{CloseReason, State as ConnectionState},
    packet::{Header, LongType, PacketIter, encode_varint},
    protocol::*,
    retry::{self, ClientAddress, RetryTokens, TokenContext, ValidatedToken},
    streams::{self, Limits, PacketReference, SendChunk, StreamHandle, StreamSlot},
    tls,
    tls_certificate::{Limits as CertificateLimits, UnixTime, trust_anchor_from_der},
    tls_schedule::Secret32,
    tls_ticket::{
        self as ticket, Binding, ClientCache, ClientSlot, ReplayPolicy, ReplaySlot, TicketClock,
        TicketKey, VerificationContext,
    },
    transport_endpoint::{Error as TransportError, TransportEndpoint},
    version_negotiation::{self, ListenerAction},
};
use hibana_quic_host::udp::UdpMetadataSocket;
use p256::pkcs8::DecodePrivateKey;
use rand_core::{OsRng, RngCore};
use rustls_pki_types::PrivateKeyDer;
use std::{
    cell::Cell,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    net::{SocketAddr, UdpSocket},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::{Path, PathBuf},
    process::ExitCode,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

type Result<T> = std::result::Result<T, String>;
const LIVE: usize = 4;
const RX: usize = 4096;
const CHUNK: usize = 1024;
const MAX_TARGET: usize = 1000;
const MAX_REQUESTS: usize = 4096;
const UDP_BYTES: usize = 65535;
const O_DIRECTORY: i32 = 0o200000;
const O_NOFOLLOW: i32 = 0o400000;
const O_NONBLOCK: i32 = 0o4000;
const USAGE: &str = "Experimental hq-interop HTTP/0.9 over real QUIC v1; bounded X25519/P256 with ECDSA TLS\n\n  hq client --connect IP:PORT --server-name HOST --ca ROOTS.pem --request /FILE [--request https://HOST:PORT/FILE ...] --downloads DIR [--timeout-seconds 120]\n  hq server --listen IP:PORT --cert CHAIN.pem --key KEY.pem --www DIR [--max-requests N] [--timeout-seconds 120]\n\nOne connection by default, at most four live streams, streamed file chunks. Explicit CA+hostname verification; no insecure mode. Server exits after --max-requests completed streams or two seconds of quiescence after a completed transfer. Existing downloads are never overwritten. Optional --cipher-suite default|aes128|chacha20 on either role sets an immutable TLS suite policy (default retains AES128+ChaCha20); singleton modes never negotiate the other suite. Optional --ecn on enables per-path ECT0 probing with actual kernel metadata (default off); received markings are always reported when available. Optional --key-update-after-bytes N on either role requests one update after positive N body bytes; update success additionally requires an authenticated peer phase change. Linux descriptor-relative file access rejects symlinks/traversal. Optional server --retry requires an address-bound opaque token before TLS allocation; --retry-lifetime-ms 1..=60000 sets its lifetime (default 10000). Bounded sequential dispatcher, no production listener capacity claim. Unsupported-version Initial-sized datagrams receive at most one stateless v1 Version Negotiation response, limited to 64 prepared responses per 1-second listener window; retained CIDs route first. Optional client --connections 2 transfers the first request, caches an authenticated ticket, closes/drains, then transfers every remaining request on a fresh connection; --require-resumption true (default for two) rejects full fallback. Optional --resumption-delay-ms 0..60000 delays the second connection. Server --max-connections 2 retains one ticket key across two peer-closed/drained connections; --max-requests is the total across both, with exactly one file on the first. Server ticket-policy controls are --ticket-lifetime-seconds 1..604800 (default60), --ticket-age-skew-ms 0..300000 (default10000), --ticket-policy-second STRING, and --rotate-ticket-key-after-first true|false; policy/key changes permit explicit full-authentication fallback tests. No HTTP/3, 0RTT, migration, qlog or keylog support is implied. Failures/timeouts exit nonzero.";

#[derive(Debug)]
enum Options {
    Client {
        connect: SocketAddr,
        name: String,
        ca: PathBuf,
        requests: Vec<Request>,
        downloads: PathBuf,
        timeout: Duration,
        key_update_after: Option<u64>,
        use_ecn: bool,
        cipher_policy: CipherPolicy,
        connections: usize,
        require_resumption: bool,
        resumption_delay: Duration,
    },
    Server {
        listen: SocketAddr,
        cert: PathBuf,
        key: PathBuf,
        www: PathBuf,
        max_requests: Option<usize>,
        require_retry: bool,
        retry_lifetime_us: u64,
        timeout: Duration,
        key_update_after: Option<u64>,
        use_ecn: bool,
        cipher_policy: CipherPolicy,
        max_connections: usize,
        ticket_lifetime: u32,
        ticket_age_skew_ms: u32,
        ticket_policy_second: Option<String>,
        rotate_ticket_key: bool,
    },
}
#[derive(Debug)]
struct Request {
    target: String,
    components: Vec<String>,
}
fn flag<'a>(flags: &mut Vec<(&'a str, &'a str)>, name: &str) -> Result<&'a str> {
    let index = flags
        .iter()
        .position(|(k, _)| *k == name)
        .ok_or_else(|| format!("missing {name}"))?;
    Ok(flags.remove(index).1)
}
fn parse_options(args: &[String]) -> Result<Options> {
    let role = args.first().ok_or_else(|| USAGE.to_owned())?;
    let retries = args[1..].iter().filter(|s| s.as_str() == "--retry").count();
    if retries > 1 {
        return Err("duplicate --retry".into());
    }
    let require_retry = retries == 1;
    if require_retry && role != "server" {
        return Err("--retry is server-only".into());
    }
    let valued: Vec<&str> = args[1..]
        .iter()
        .map(String::as_str)
        .filter(|s| *s != "--retry")
        .collect();
    if !valued.len().is_multiple_of(2) {
        return Err("every option except --retry requires a value".into());
    }
    let mut flags = Vec::new();
    let mut targets = Vec::new();
    for pair in valued.chunks_exact(2) {
        if pair[0] == "--request" {
            targets.push(pair[1]);
            continue;
        }
        if !pair[0].starts_with("--") || flags.iter().any(|(k, _)| *k == pair[0]) {
            return Err(format!("invalid/duplicate flag {}", pair[0]));
        }
        flags.push((pair[0], pair[1]));
    }
    let seconds = if flags.iter().any(|(k, _)| *k == "--timeout-seconds") {
        flag(&mut flags, "--timeout-seconds")?
            .parse::<u64>()
            .map_err(|_| "invalid timeout")?
    } else {
        120
    };
    if !(1..=3600).contains(&seconds) {
        return Err("timeout must be 1..=3600 seconds".into());
    }
    let timeout = Duration::from_secs(seconds);
    let key_update_after = if flags.iter().any(|(k, _)| *k == "--key-update-after-bytes") {
        Some(parse_key_update_after(flag(
            &mut flags,
            "--key-update-after-bytes",
        )?)?)
    } else {
        None
    };
    let use_ecn = if flags.iter().any(|(k, _)| *k == "--ecn") {
        match flag(&mut flags, "--ecn")? {
            "on" => true,
            "off" => false,
            _ => return Err("--ecn must be on or off".into()),
        }
    } else {
        false
    };
    let cipher_policy = if flags.iter().any(|(k, _)| *k == "--cipher-suite") {
        match flag(&mut flags, "--cipher-suite")? {
            "default" => CipherPolicy::Default,
            "aes128" => CipherPolicy::Aes128Only,
            "chacha20" => CipherPolicy::ChaCha20Only,
            _ => return Err("--cipher-suite must be default, aes128, or chacha20".into()),
        }
    } else {
        CipherPolicy::Default
    };
    let options = match role.as_str() {
        "client" => {
            let connect = flag(&mut flags, "--connect")?
                .parse::<SocketAddr>()
                .map_err(|_| "--connect requires IP:PORT")?;
            let name = flag(&mut flags, "--server-name")?.to_owned();
            let ca = flag(&mut flags, "--ca")?.into();
            let downloads = flag(&mut flags, "--downloads")?.into();
            if targets.is_empty() || targets.len() > MAX_REQUESTS {
                return Err(format!("provide 1..={MAX_REQUESTS} --request options"));
            }
            let mut requests: Vec<Request> = Vec::new();
            for target in targets {
                let target = url_target(target, &name, connect.port())?;
                let components = path_components(target)?;
                if requests.iter().any(|r| r.components == components) {
                    return Err("duplicate download destination".into());
                }
                requests.push(Request {
                    target: target.to_owned(),
                    components,
                });
            }
            let connections = connection_count(&mut flags, "--connections")?;
            if connections == 2 && requests.len() < 2 {
                return Err(
                    "--connections 2 requires at least two distinct --request values".into(),
                );
            }
            let require_resumption =
                bool_flag(&mut flags, "--require-resumption", connections == 2)?;
            let delay_ms = optional_u64(&mut flags, "--resumption-delay-ms", 0)?;
            if delay_ms > 60_000 || (connections == 1 && (require_resumption || delay_ms != 0)) {
                return Err(
                    "resumption options require --connections 2; delay must be <=60000ms".into(),
                );
            }
            Options::Client {
                connections,
                require_resumption,
                resumption_delay: Duration::from_millis(delay_ms),
                connect,
                name,
                ca,
                requests,
                downloads,
                timeout,
                key_update_after,
                use_ecn,
                cipher_policy,
            }
        }
        "server" => {
            if !targets.is_empty() {
                return Err("--request is client-only".into());
            }
            let listen = flag(&mut flags, "--listen")?
                .parse()
                .map_err(|_| "--listen requires IP:PORT")?;
            let cert = flag(&mut flags, "--cert")?.into();
            let key = flag(&mut flags, "--key")?.into();
            let www = flag(&mut flags, "--www")?.into();
            let max_requests = if flags.iter().any(|(k, _)| *k == "--max-requests") {
                let count = flag(&mut flags, "--max-requests")?
                    .parse::<usize>()
                    .map_err(|_| "invalid max requests")?;
                if count == 0 {
                    return Err("max requests must be positive".into());
                }
                Some(count)
            } else {
                None
            };
            let retry_lifetime_us = if flags.iter().any(|(k, _)| *k == "--retry-lifetime-ms") {
                if !require_retry {
                    return Err("--retry-lifetime-ms requires --retry".into());
                }
                let millis = flag(&mut flags, "--retry-lifetime-ms")?
                    .parse::<u64>()
                    .map_err(|_| "invalid Retry lifetime")?;
                if !(1..=60_000).contains(&millis) {
                    return Err("Retry lifetime must be 1..=60000 milliseconds".into());
                }
                millis * 1000
            } else {
                retry::DEFAULT_TOKEN_LIFETIME_US
            };
            let max_connections = connection_count(&mut flags, "--max-connections")?;
            if max_connections == 2 && max_requests.is_some_and(|n| n < 2) {
                return Err("two connections require --max-requests >=2 when specified".into());
            }
            let ticket_lifetime = optional_u64(&mut flags, "--ticket-lifetime-seconds", 60)?;
            if !(1..=u64::from(ticket::MAX_LIFETIME_SECONDS)).contains(&ticket_lifetime) {
                return Err("ticket lifetime must be positive and at most seven days".into());
            }
            let ticket_age_skew_ms = optional_u64(&mut flags, "--ticket-age-skew-ms", 10_000)?;
            if ticket_age_skew_ms > u64::from(ticket::MAX_AGE_SKEW_MS) {
                return Err("ticket age skew must be <=300000 milliseconds".into());
            }
            let ticket_policy_second = if flags.iter().any(|(k, _)| *k == "--ticket-policy-second")
            {
                let policy = flag(&mut flags, "--ticket-policy-second")?;
                if policy.is_empty() || policy.len() > 256 {
                    return Err("second ticket policy must be 1..=256 bytes".into());
                }
                Some(policy.to_owned())
            } else {
                None
            };
            let rotate_ticket_key =
                bool_flag(&mut flags, "--rotate-ticket-key-after-first", false)?;
            if max_connections == 1
                && (ticket_lifetime != 60 || ticket_policy_second.is_some() || rotate_ticket_key)
            {
                return Err("ticket policy options require --max-connections 2".into());
            }
            Options::Server {
                max_connections,
                ticket_lifetime: ticket_lifetime as u32,
                ticket_age_skew_ms: ticket_age_skew_ms as u32,
                ticket_policy_second,
                rotate_ticket_key,
                require_retry,
                retry_lifetime_us,
                listen,
                cert,
                key,
                www,
                max_requests,
                timeout,
                key_update_after,
                use_ecn,
                cipher_policy,
            }
        }
        _ => return Err(format!("unknown role {role}")),
    };
    if let Some((key, _)) = flags.first() {
        return Err(format!("unsupported option {key}"));
    }
    Ok(options)
}
/// An explicit host goal plus fully retired streams permits connection shutdown.
/// Future-credit control acknowledgements are not file-delivery obligations.
fn completed_server_goal(
    side: Side,
    goal: Option<usize>,
    completed: usize,
    live_jobs: usize,
    live_streams: usize,
) -> bool {
    side == Side::Server
        && goal.is_some_and(|n| n > 0 && completed >= n)
        && live_jobs == 0
        && live_streams == 0
}
fn cipher_policy_name(policy: CipherPolicy) -> &'static str {
    match policy {
        CipherPolicy::Default => "default",
        CipherPolicy::Aes128Only => "aes128",
        CipherPolicy::ChaCha20Only => "chacha20",
    }
}
fn request_groups(mut requests: Vec<Request>, connections: usize) -> Result<Vec<Vec<Request>>> {
    match connections {
        1 if !requests.is_empty() => Ok(vec![requests]),
        2 if requests.len() >= 2 => {
            let remaining = requests.split_off(1);
            Ok(vec![requests, remaining])
        }
        _ => Err("connection count and requests cannot satisfy first-file then remaining-files semantics".into()),
    }
}
fn optional_u64<'a>(flags: &mut Vec<(&'a str, &'a str)>, name: &str, default: u64) -> Result<u64> {
    if flags.iter().any(|(key, _)| *key == name) {
        flag(flags, name)?
            .parse()
            .map_err(|_| format!("invalid {name}"))
    } else {
        Ok(default)
    }
}
fn bool_flag<'a>(flags: &mut Vec<(&'a str, &'a str)>, name: &str, default: bool) -> Result<bool> {
    if flags.iter().any(|(key, _)| *key == name) {
        match flag(flags, name)? {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(format!("{name} must be true or false")),
        }
    } else {
        Ok(default)
    }
}
fn connection_count<'a>(flags: &mut Vec<(&'a str, &'a str)>, name: &str) -> Result<usize> {
    match optional_u64(flags, name, 1)? {
        1 => Ok(1),
        2 => Ok(2),
        _ => Err(format!("{name} must be 1 or 2")),
    }
}
fn parse_key_update_after(value: &str) -> Result<u64> {
    value
        .parse::<u64>()
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(|| "--key-update-after-bytes must be a positive u64".into())
}
fn update_temporarily_blocked(error: &TransportError) -> bool {
    matches!(
        error,
        TransportError::Busy
            | TransportError::Engine(
                EngineError::Busy | EngineError::Tls(tls::Error::KeyUpdateNotAllowed)
            )
    )
}
fn url_target<'a>(value: &'a str, name: &str, port: u16) -> Result<&'a str> {
    if value.starts_with('/') {
        return Ok(value);
    }
    let rest = value
        .strip_prefix("https://")
        .ok_or("requests must be /paths or https:// URLs")?;
    let (authority, path) = rest.split_once('/').ok_or("URL must contain a file path")?;
    if authority.contains('@') {
        return Err("URL user information is forbidden".into());
    }
    let expected = format!("{name}:{port}");
    if !(authority.eq_ignore_ascii_case(&expected)
        || port == 443 && authority.eq_ignore_ascii_case(name))
    {
        return Err("URL authority must match --server-name and --connect port".into());
    }
    let start = value.len() - path.len() - 1;
    Ok(&value[start..])
}
fn path_components(target: &str) -> Result<Vec<String>> {
    if target.len() > MAX_TARGET
        || !target.starts_with('/')
        || target.starts_with("//")
        || target
            .bytes()
            .any(|b| b <= 0x20 || b == 0x7f || matches!(b, b'\\' | b'?' | b'#'))
    {
        return Err("invalid or overlong HTTP/0.9 file target".into());
    }
    let mut decoded = Vec::with_capacity(target.len());
    let raw = target.as_bytes();
    let mut i = 1;
    while i < raw.len() {
        if raw[i] == b'%' {
            let hex = |b: u8| -> Option<u8> {
                match b {
                    b'0'..=b'9' => Some(b - b'0'),
                    b'a'..=b'f' => Some(b - b'a' + 10),
                    b'A'..=b'F' => Some(b - b'A' + 10),
                    _ => None,
                }
            };
            if i + 2 >= raw.len() {
                return Err("truncated percent escape".into());
            }
            let v = hex(raw[i + 1])
                .and_then(|a| hex(raw[i + 2]).map(|b| (a << 4) | b))
                .ok_or("invalid percent escape")?;
            if v < 0x20 || v == 0x7f || matches!(v, b'/' | b'\\') {
                return Err("encoded separator/control is forbidden".into());
            }
            decoded.push(v);
            i += 3;
        } else {
            decoded.push(raw[i]);
            i += 1
        }
    }
    let value = String::from_utf8(decoded).map_err(|_| "file target is not UTF-8")?;
    let mut components = Vec::new();
    for component in value.split('/') {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.starts_with(".hibana-")
        {
            return Err("empty, dot or reserved path component".into());
        }
        components.push(component.to_owned());
    }
    Ok(components)
}
fn parse_get(bytes: &[u8]) -> Result<Vec<String>> {
    let line = bytes
        .strip_suffix(b"\r\n")
        .or_else(|| bytes.strip_suffix(b"\n"))
        .ok_or("GET request requires line ending and stream FIN")?;
    let target = line
        .strip_prefix(b"GET ")
        .ok_or("only HTTP/0.9 GET is supported")?;
    path_components(std::str::from_utf8(target).map_err(|_| "GET target is not UTF-8")?)
}

/// The root directory is a held capability. Every component is opened relative
/// to its held parent FD with O_NOFOLLOW; an attacker-controlled symlink cannot
/// move lookup outside the root, including if a directory name changes mid-walk.
struct SafeRoot {
    directory: File,
}
fn fd_path(parent: &File, name: &str) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}/{}", parent.as_raw_fd(), name))
}
impl SafeRoot {
    fn open(path: &Path, create: bool) -> Result<Self> {
        if create {
            fs::create_dir_all(path).map_err(|e| format!("create download root: {e}"))?
        }
        let canonical = fs::canonicalize(path)
            .map_err(|e| format!("canonical root {}: {e}", path.display()))?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(O_DIRECTORY | O_NOFOLLOW)
            .open(canonical)
            .map_err(|e| format!("open root: {e}"))?;
        Ok(Self { directory })
    }
    fn parent(&self, components: &[String], create: bool) -> Result<(File, String)> {
        if components.iter().any(|c| {
            c.is_empty()
                || c == "."
                || c == ".."
                || c.contains(['/', '\\', '\0'])
                || c.starts_with(".hibana-")
        }) {
            return Err("invalid relative path component".into());
        }
        let (last, parents) = components.split_last().ok_or("missing file name")?;
        let mut dir = self
            .directory
            .try_clone()
            .map_err(|e| format!("clone root descriptor: {e}"))?;
        for component in parents {
            let path = fd_path(&dir, component);
            let open = || {
                OpenOptions::new()
                    .read(true)
                    .custom_flags(O_DIRECTORY | O_NOFOLLOW)
                    .open(&path)
            };
            let next = match open() {
                Ok(file) => file,
                Err(e) if create && e.kind() == io::ErrorKind::NotFound => {
                    match fs::create_dir(&path) {
                        Ok(()) => {}
                        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                        Err(e) => return Err(format!("create relative directory: {e}")),
                    }
                    open().map_err(|e| format!("open relative directory without symlinks: {e}"))?
                }
                Err(e) => return Err(format!("open relative directory without symlinks: {e}")),
            };
            dir = next;
        }
        Ok((dir, last.clone()))
    }
    fn read(&self, components: &[String]) -> Result<File> {
        let (parent, name) = self.parent(components, false)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW | O_NONBLOCK)
            .open(fd_path(&parent, &name))
            .map_err(|e| format!("open requested file: {e}"))?;
        if !file
            .metadata()
            .map_err(|e| format!("file metadata: {e}"))?
            .is_file()
        {
            return Err("requested object is not a regular file".into());
        }
        Ok(file)
    }
    fn create(&self, components: &[String]) -> Result<Download> {
        let (parent, name) = self.parent(components, true)?;
        if fs::symlink_metadata(fd_path(&parent, &name)).is_ok() {
            return Err("download destination already exists; refusing overwrite".into());
        }
        let temp = format!(".hibana-{:016x}.part", u64::from_be_bytes(random::<8>()?));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(O_NOFOLLOW)
            .open(fd_path(&parent, &temp))
            .map_err(|e| format!("create bounded download staging file: {e}"))?;
        Ok(Download {
            file,
            parent,
            name,
            temp: Some(temp),
        })
    }
}
struct Download {
    file: File,
    parent: File,
    name: String,
    temp: Option<String>,
}
impl Download {
    fn finish(&mut self) -> Result<()> {
        self.file
            .sync_all()
            .map_err(|e| format!("sync completed body: {e}"))?;
        let temp = self.temp.as_ref().ok_or("download already finalized")?;
        // Hard-link creation fails atomically if the final destination exists,
        // unlike rename's overwrite semantics. Both paths use the same held dir.
        fs::hard_link(
            fd_path(&self.parent, temp),
            fd_path(&self.parent, &self.name),
        )
        .map_err(|e| format!("publish completed file without overwrite: {e}"))?;
        fs::remove_file(fd_path(&self.parent, temp))
            .map_err(|e| format!("remove staging link: {e}"))?;
        self.temp = None;
        self.parent
            .sync_all()
            .map_err(|e| format!("sync download directory: {e}"))?;
        Ok(())
    }
}
impl Drop for Download {
    fn drop(&mut self) {
        if let Some(temp) = &self.temp {
            let _ = fs::remove_file(fd_path(&self.parent, temp));
        }
    }
}
fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| format!("OS cryptographic randomness unavailable: {e}"))?;
    Ok(bytes)
}
#[derive(Clone, Copy, Default)]
struct RetryStats {
    enabled: bool,
    received: u64,
    sent: u64,
    invalid_tokens: u64,
    admissions: u64,
}
impl RetryStats {
    fn json(self) -> String {
        format!(
            "{{\"enabled\":{},\"input_datagrams\":{},\"packets_sent\":{},\"invalid_tokens\":{},\"admissions\":{}}}",
            self.enabled, self.received, self.sent, self.invalid_tokens, self.admissions
        )
    }
}
#[derive(Debug)]
enum RetryAction {
    Discard,
    Send(usize),
    Admit(ValidatedToken),
}
struct RetryDispatcher {
    tokens: RetryTokens<64>,
    stats: RetryStats,
}
fn retry_address(peer: SocketAddr) -> ClientAddress {
    match peer {
        SocketAddr::V4(address) => ClientAddress::V4 {
            ip: address.ip().octets(),
            port: address.port(),
        },
        SocketAddr::V6(address) => ClientAddress::V6 {
            ip: address.ip().octets(),
            port: address.port(),
        },
    }
}
impl RetryDispatcher {
    fn new(lifetime: u64) -> Result<Self> {
        Ok(Self {
            tokens: RetryTokens::generate(&mut OsRng, 1, lifetime)
                .map_err(|e| format!("Retry key setup: {e:?}"))?,
            stats: RetryStats {
                enabled: true,
                ..RetryStats::default()
            },
        })
    }
    /// Inspect only the first packet, returning at most one Retry per datagram.
    /// Every Retry is shorter than its >=1200-byte triggering datagram, hence
    /// cumulative bytes sent stay below the unvalidated path's 3x budget without
    /// an unbounded pre-connection address table. Failed sendmsg is never retried
    /// without another received datagram. No TLS/endpoint exists at this stage.
    fn handle(
        &mut self,
        now: u64,
        peer: SocketAddr,
        input: &[u8],
        out: &mut [u8],
    ) -> Result<RetryAction> {
        if input.len() < 1200 {
            return Ok(RetryAction::Discard);
        }
        let first = PacketIter::new(input, 8, 8)
            .ok()
            .and_then(|mut p| p.next())
            .and_then(std::result::Result::ok);
        let Some(packet) = first else {
            return Ok(RetryAction::Discard);
        };
        let Header::Long {
            kind: LongType::Initial,
            destination_id,
            source_id,
            token,
            ..
        } = packet.header
        else {
            return Ok(RetryAction::Discard);
        };
        if !token.is_empty() {
            return match self.tokens.validate(
                now,
                retry_address(peer),
                destination_id,
                source_id,
                token,
            ) {
                Ok(admission) => {
                    self.stats.admissions = self.stats.admissions.saturating_add(1);
                    Ok(RetryAction::Admit(admission))
                }
                Err(_) => {
                    self.stats.invalid_tokens = self.stats.invalid_tokens.saturating_add(1);
                    Ok(RetryAction::Discard)
                }
            };
        }
        if destination_id.len() < 8 {
            return Ok(RetryAction::Discard);
        }
        let retry_id = random::<8>()?;
        let mut token = [0; retry::TOKEN_LEN];
        self.tokens
            .issue(
                now,
                TokenContext {
                    original_destination_id: destination_id,
                    retry_source_id: &retry_id,
                    client_source_id: source_id,
                    address: retry_address(peer),
                },
                &mut token,
            )
            .map_err(|e| format!("Retry token issue: {e:?}"))?;
        let len = retry::encode_retry(
            destination_id,
            source_id,
            &retry_id,
            &token,
            0,
            out,
            &mut [0; 256],
        )
        .map_err(|e| format!("Retry encode: {e:?}"))?;
        if len > input.len() {
            return Err("Retry response exceeds its received-datagram budget".into());
        }
        Ok(RetryAction::Send(len))
    }
}

const CACHE_TICKET_BYTES: usize = 4096;
struct HostTicketClock(Instant);
impl TicketClock for HostTicketClock {
    fn now_ms(&self) -> std::result::Result<u64, ticket::Error> {
        u64::try_from(self.0.elapsed().as_millis()).map_err(|_| ticket::Error::ClockOverflow)
    }
}
struct ObservedCache<'a, 'b> {
    cache: &'a mut ClientCache<'b, CACHE_TICKET_BYTES>,
    inserted: &'a Cell<usize>,
}
impl ticket::ClientTicketStore for ObservedCache<'_, '_> {
    fn insert_verified(
        &mut self,
        now_ms: u64,
        received: ticket::ReceivedTicket<'_>,
        psk: Secret32,
        context: VerificationContext,
    ) -> std::result::Result<(), ticket::Error> {
        self.cache.insert_verified(now_ms, received, psk, context)?;
        self.inserted.set(self.inserted.get().saturating_add(1));
        Ok(())
    }
}
#[derive(Clone, Copy, Debug)]
struct TicketAgeObservation {
    server_age_ms: u64,
    reported_age_ms: u64,
    delta_ms: u64,
}
impl TicketAgeObservation {
    fn json(self) -> String {
        format!(
            "{{\"server_age_ms\":{},\"reported_age_ms\":{},\"delta_ms\":{}}}",
            self.server_age_ms, self.reported_age_ms, self.delta_ms
        )
    }
}
type TicketAcceptance = std::result::Result<(), ticket::Error>;
struct ObservedIssuer<'a, 'b> {
    key: &'a mut TicketKey<'b>,
    acceptance: &'a Cell<Option<TicketAcceptance>>,
    issued: &'a Cell<Option<(u64, u32)>>,
    age: &'a Cell<Option<TicketAgeObservation>>,
    prepared_at: Option<u64>,
}
impl ObservedIssuer<'_, '_> {
    fn observe_age(&self, request: &ticket::Acceptance<'_>) {
        if let Some((issued, add)) = self.issued.get()
            && let Some(server_age_ms) = request.now_ms.checked_sub(issued)
        {
            let reported_age_ms = u64::from(request.obfuscated_age.wrapping_sub(add));
            self.age.set(Some(TicketAgeObservation {
                server_age_ms,
                reported_age_ms,
                delta_ms: server_age_ms.abs_diff(reported_age_ms),
            }));
        }
    }
}
impl ticket::ServerTicketStore for ObservedIssuer<'_, '_> {
    fn prepare(
        &mut self,
        rng: &mut dyn rand_core::CryptoRngCore,
        now: u64,
        lifetime: u32,
        suite: u16,
        binding: Binding,
    ) -> std::result::Result<ticket::IssueToken, ticket::Error> {
        let result = self.key.prepare(rng, now, lifetime, suite, binding);
        if result.is_ok() {
            self.prepared_at = Some(now);
        }
        result
    }
    fn seal(
        &mut self,
        token: ticket::IssueToken,
        psk: Secret32,
        out: &mut [u8],
    ) -> std::result::Result<ticket::IssuedTicket, ticket::Error> {
        let result = self.key.seal(token, psk, out);
        if let (Ok(ticket), Some(issued)) = (&result, self.prepared_at.take()) {
            self.issued.set(Some((issued, ticket.age_add)));
        }
        result
    }
    fn accept(
        &mut self,
        identity: &[u8],
        request: ticket::Acceptance<'_>,
    ) -> std::result::Result<ticket::AcceptedTicket, ticket::Error> {
        self.observe_age(&request);
        let result = self.key.accept(identity, request);
        self.acceptance
            .set(Some(result.as_ref().map(|_| ()).map_err(|e| *e)));
        result
    }
    fn check(
        &mut self,
        identity: &[u8],
        request: ticket::Acceptance<'_>,
    ) -> std::result::Result<ticket::AcceptedTicket, ticket::Error> {
        self.observe_age(&request);
        let result = self.key.check(identity, request);
        self.acceptance
            .set(Some(result.as_ref().map(|_| ()).map_err(|e| *e)));
        result
    }
}
fn next_generation(generation: u64) -> Result<u64> {
    generation
        .checked_add(1)
        .ok_or_else(|| "connection generation exhausted".into())
}
struct SessionOptions<'a> {
    generation: u64,
    cipher_policy: CipherPolicy,
    index: usize,
    persistent: bool,
    offered: bool,
    require_resumed: bool,
    wait_ticket: Option<&'a Cell<usize>>,
    require_ticket: bool,
    ticket_acceptance: Option<&'a Cell<Option<TicketAcceptance>>>,
    ticket_age: Option<&'a Cell<Option<TicketAgeObservation>>>,
}
struct RunReport {
    connections: Vec<Report>,
    require_resumption: bool,
}
impl RunReport {
    fn json(&self) -> String {
        if self.connections.len() == 1 {
            return self.connections[0].json();
        }
        format!(
            "{{\"status\":\"success\",\"scope\":\"two-connection-1rtt-resumption\",\"backend\":\"bounded-profile\",\"zero_rtt\":false,\"require_resumption\":{},\"resumed\":{},\"files_completed\":{},\"body_bytes\":{},\"connections\":[{}]}}",
            self.require_resumption,
            self.connections[1].resumed,
            self.connections.iter().map(|r| r.files).sum::<usize>(),
            self.connections.iter().map(|r| r.bytes).sum::<u64>(),
            self.connections
                .iter()
                .map(Report::json)
                .collect::<Vec<_>>()
                .join(",")
        )
    }
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

fn local_limits(side: Side) -> Limits {
    Limits {
        max_data: (LIVE * RX) as u64,
        max_streams_bidi: if side == Side::Server { LIVE as u64 } else { 0 },
        max_streams_uni: 0,
        stream_data_bidi_local: RX as u64,
        stream_data_bidi_remote: RX as u64,
        stream_data_uni: 0,
    }
}
fn parameters(
    local: &[u8],
    original: Option<&[u8]>,
    retry_id: Option<&[u8]>,
    limits: Limits,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut b = [0; 8];
    for (kind, data) in [(15, Some(local)), (0, original), (16, retry_id)] {
        if let Some(data) = data {
            let n = encode_varint(kind, &mut b).map_err(|e| format!("TP: {e:?}"))?;
            out.extend_from_slice(&b[..n]);
            let n = encode_varint(data.len() as u64, &mut b).map_err(|e| format!("TP: {e:?}"))?;
            out.extend_from_slice(&b[..n]);
            out.extend_from_slice(data);
        }
    }
    for (kind, value) in [
        (4, limits.max_data),
        (5, limits.stream_data_bidi_local),
        (6, limits.stream_data_bidi_remote),
        (7, limits.stream_data_uni),
        (8, limits.max_streams_bidi),
        (9, limits.max_streams_uni),
    ] {
        let mut v = [0; 8];
        let length = encode_varint(value, &mut v).map_err(|e| format!("TP: {e:?}"))?;
        let n = encode_varint(kind, &mut b).map_err(|e| format!("TP: {e:?}"))?;
        out.extend_from_slice(&b[..n]);
        let n = encode_varint(length as u64, &mut b).map_err(|e| format!("TP: {e:?}"))?;
        out.extend_from_slice(&b[..n]);
        out.extend_from_slice(&v[..length]);
    }
    Ok(out)
}
fn now(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX)
}
fn transient(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}
fn backpressure(error: &TransportError) -> bool {
    matches!(
        error,
        TransportError::Streams(
            streams::Error::Capacity | streams::Error::FlowControl | streams::Error::StreamLimit
        )
    )
}
struct Report {
    side: Side,
    files: usize,
    bytes: u64,
    sent: u64,
    received: u64,
    authenticated: u64,
    discarded: u64,
    duration_ms: u128,
    body_progress: u64,
    key_update_after: Option<u64>,
    key_update_at: Option<u64>,
    send_key_generation: u64,
    receive_key_generation: u64,
    ecn: Option<ecn::Snapshot>,
    negotiated_group: Option<u16>,
    negotiated_suite: Option<u16>,
    cipher_policy: CipherPolicy,
    retry: RetryStats,
    connection_index: usize,
    connection_generation: u64,
    resumption_offered: bool,
    resumed: bool,
    tickets_cached: usize,
    lifecycle_closed: bool,
    ticket_acceptance: Option<TicketAcceptance>,
    ticket_age: Option<TicketAgeObservation>,
}
impl Report {
    fn update_ready(&self) -> bool {
        self.key_update_after.is_none()
            || (self.key_update_at.is_some() && self.receive_key_generation > 0)
    }
    fn check_update_threshold(&self) -> Result<()> {
        if self
            .key_update_after
            .is_some_and(|n| n > self.body_progress)
        {
            return Err(
                "requested key update threshold was not reached; no key-update success reported"
                    .into(),
            );
        }
        Ok(())
    }
    fn json(&self) -> String {
        format!(
            "{{\"status\":\"success\",\"scope\":\"direct-http09-transfer\",\"backend\":\"bounded-profile\",\"certificate_verification_profile\":\"ECDSA-P256-SHA256+RSA-2048/3072/4096-SHA256\",\"bounded_server_signing_profile\":\"ECDSA-P256-SHA256\",\"negotiated_group\":{},\"mandatory_tls_algorithms_complete\":false,\"alpn\":\"hq-interop\",\"role\":\"{}\",\"files_completed\":{},\"body_bytes\":{},\"datagrams_sent\":{},\"datagrams_received\":{},\"authenticated_packets\":{},\"discarded_packets\":{},\"duration_ms\":{},\"key_update_after_bytes\":{},\"key_update_initiated_at_body_bytes\":{},\"send_key_generation\":{},\"authenticated_receive_key_generation\":{},\"ecn\":{},\"server_retry\":{},\"cipher_policy\":{},\"negotiated_suite\":{},\"connection_index\":{},\"connection_generation\":{},\"resumption_offered\":{},\"resumed\":{},\"handshake_mode\":{},\"tickets_cached\":{},\"lifecycle_closed\":{},\"ticket_acceptance\":{},\"ticket_age\":{},\"authentication\":{},\"certificate_chain_hostname_time_verified\":{},\"zero_rtt\":false}}",
            self.negotiated_group
                .map_or_else(|| "null".into(), |group| group.to_string()),
            if self.side == Side::Client {
                "client"
            } else {
                "server"
            },
            self.files,
            self.bytes,
            self.sent,
            self.received,
            self.authenticated,
            self.discarded,
            self.duration_ms,
            self.key_update_after
                .map_or_else(|| "null".into(), |n| n.to_string()),
            self.key_update_at
                .map_or_else(|| "null".into(), |n| n.to_string()),
            self.send_key_generation,
            self.receive_key_generation,
            self.ecn.map_or_else(|| "null".into(), ecn_json),
            self.retry.json(),
            json_string(cipher_policy_name(self.cipher_policy)),
            self.negotiated_suite
                .map_or_else(|| "null".into(), |n| n.to_string()),
            self.connection_index,
            self.connection_generation,
            self.resumption_offered,
            self.resumed,
            json_string(if self.resumed {
                "resumed"
            } else if self.connection_index > 1 {
                "fallback"
            } else {
                "full"
            }),
            self.tickets_cached,
            self.lifecycle_closed,
            self.ticket_acceptance.map_or_else(
                || "null".into(),
                |result| json_string(&format!("{result:?}"))
            ),
            self.ticket_age
                .map_or_else(|| "null".into(), TicketAgeObservation::json),
            json_string(if self.side == Side::Server {
                "peer-finished"
            } else if self.resumed {
                "cached-ticket-finished"
            } else {
                "verified-certificate"
            }),
            if self.side == Side::Client {
                if self.resumed { "false" } else { "true" }
            } else {
                "null"
            }
        )
    }
}
fn ecn_json(snapshot: ecn::Snapshot) -> String {
    let mut spaces = String::from("[");
    for (i, name) in ["initial", "handshake", "application"].iter().enumerate() {
        if i != 0 {
            spaces.push(',');
        }
        let received = snapshot.received[i].map_or_else(
            || "null".into(),
            |n| {
                format!(
                    "{{\"ect0\":{},\"ect1\":{},\"ce\":{}}}",
                    n.ect0, n.ect1, n.ce
                )
            },
        );
        spaces.push_str(&format!(
            "{{\"space\":\"{name}\",\"sent_ect0\":{},\"sent_ect1\":{},\"received\":{received}}}",
            snapshot.sent[i].ect0, snapshot.sent[i].ect1
        ));
    }
    spaces.push(']');
    format!(
        "{{\"enabled\":{},\"state\":\"{:?}\",\"failure\":{},\"spaces\":{spaces},\"validated_ce\":{},\"congestion_events\":{}}}",
        snapshot.enabled,
        snapshot.state,
        snapshot
            .failure
            .map_or_else(|| "null".into(), |f| json_string(&format!("{f:?}"))),
        snapshot.validated_ce,
        snapshot.congestion_events
    )
}
struct ClientJob {
    stream: StreamHandle,
    download: Download,
    request: [u8; CHUNK],
    request_len: usize,
    queued: bool,
    unconsumed: usize,
    fin: bool,
    published: bool,
    bytes: u64,
}
struct ServerJob {
    stream: StreamHandle,
    request: [u8; CHUNK],
    request_len: usize,
    unconsumed: usize,
    request_fin: bool,
    file: Option<File>,
    chunk: [u8; CHUNK],
    chunk_len: usize,
    loaded: bool,
    eof: bool,
    fin_queued: bool,
    bytes: u64,
}
struct App {
    side: Side,
    root: SafeRoot,
    requests: Vec<Request>,
    next_request: usize,
    max_requests: Option<usize>,
    clients: [Option<ClientJob>; LIVE],
    servers: [Option<ServerJob>; LIVE],
}
type Endpoint<'r, 's, 'c, 't> = TransportEndpoint<'r, 's, BoundedTls<'c, 't>, RX, CHUNK, 64, 128>;
impl App {
    fn active(&self) -> usize {
        if self.side == Side::Client {
            self.clients.iter().filter(|j| j.is_some()).count()
        } else {
            self.servers.iter().filter(|j| j.is_some()).count()
        }
    }
    fn done(&self, report: &Report) -> bool {
        self.active() == 0
            && if self.side == Side::Client {
                self.next_request == self.requests.len()
            } else {
                self.max_requests.is_some_and(|n| report.files >= n)
            }
    }
    fn advance(&mut self, ep: &mut Endpoint<'_, '_, '_, '_>, report: &mut Report) -> Result<bool> {
        if !ep.handshake_complete() {
            return Ok(false);
        }
        if self.side == Side::Client {
            self.client_advance(ep, report)
        } else {
            self.server_advance(ep, report)
        }
    }
    fn client_advance(
        &mut self,
        ep: &mut Endpoint<'_, '_, '_, '_>,
        report: &mut Report,
    ) -> Result<bool> {
        let mut progress = false;
        for index in 0..LIVE {
            if self.clients[index].is_none() && self.next_request < self.requests.len() {
                let h = match ep.open(true) {
                    Ok(h) => h,
                    Err(e) if backpressure(&e) => break,
                    Err(e) => return Err(format!("open request stream: {e:?}")),
                };
                let request = &self.requests[self.next_request];
                let download = self.root.create(&request.components)?;
                let mut line = [0; CHUNK];
                let len = 4 + request.target.len() + 2;
                line[..4].copy_from_slice(b"GET ");
                line[4..len - 2].copy_from_slice(request.target.as_bytes());
                line[len - 2..len].copy_from_slice(b"\r\n");
                self.clients[index] = Some(ClientJob {
                    stream: h,
                    download,
                    request: line,
                    request_len: len,
                    queued: false,
                    unconsumed: 0,
                    fin: false,
                    published: false,
                    bytes: 0,
                });
                self.next_request += 1;
                progress = true;
            }
            let Some(job) = self.clients[index].as_mut() else {
                continue;
            };
            if !job.queued {
                match ep.send(job.stream, &job.request[..job.request_len], true) {
                    Ok(()) => {
                        job.queued = true;
                        progress = true
                    }
                    Err(e) if backpressure(&e) => continue,
                    Err(e) => return Err(format!("queue GET: {e:?}")),
                }
            }
            if !job.published {
                if job.unconsumed == 0 {
                    let view = ep
                        .read(job.stream)
                        .map_err(|e| format!("read body: {e:?}"))?;
                    if let Some(code) = view.reset {
                        return Err(format!("peer reset request stream with code {code}"));
                    }
                    let count = view.first.len() + view.second.len();
                    job.download
                        .file
                        .write_all(view.first)
                        .and_then(|_| job.download.file.write_all(view.second))
                        .map_err(|e| format!("write body chunk: {e}"))?;
                    job.bytes += count as u64;
                    report.body_progress += count as u64;
                    job.unconsumed = count;
                    job.fin = view.fin;
                }
                if job.unconsumed > 0 || job.fin {
                    match ep.consume(job.stream, job.unconsumed) {
                        Ok(()) => {
                            progress |= job.unconsumed > 0;
                            job.unconsumed = 0;
                        }
                        Err(e) if backpressure(&e) => continue,
                        Err(e) => return Err(format!("consume body: {e:?}")),
                    }
                }
                if job.fin && job.unconsumed == 0 {
                    job.download.finish()?;
                    job.published = true;
                    progress = true;
                }
            }
            if job.published {
                match ep.retire_stream(job.stream) {
                    Ok(()) => {
                        report.files += 1;
                        report.bytes += job.bytes;
                        self.clients[index] = None;
                        progress = true
                    }
                    Err(TransportError::Streams(
                        streams::Error::NotTerminal | streams::Error::Capacity,
                    )) => {}
                    Err(e) => return Err(format!("retire completed client stream: {e:?}")),
                }
            }
        }
        Ok(progress)
    }
    fn server_advance(
        &mut self,
        ep: &mut Endpoint<'_, '_, '_, '_>,
        report: &mut Report,
    ) -> Result<bool> {
        let mut progress = false;
        let mut handles = [None; LIVE];
        for (slot, h) in handles.iter_mut().zip(ep.streams().live_handles()) {
            *slot = Some(h);
        }
        for h in handles.into_iter().flatten() {
            if self
                .servers
                .iter()
                .all(|j| j.as_ref().is_none_or(|j| j.stream != h))
            {
                let slot = self
                    .servers
                    .iter()
                    .position(Option::is_none)
                    .ok_or("HTTP live request capacity exhausted")?;
                self.servers[slot] = Some(ServerJob {
                    stream: h,
                    request: [0; CHUNK],
                    request_len: 0,
                    unconsumed: 0,
                    request_fin: false,
                    file: None,
                    chunk: [0; CHUNK],
                    chunk_len: 0,
                    loaded: false,
                    eof: false,
                    fin_queued: false,
                    bytes: 0,
                });
            }
        }
        for index in 0..LIVE {
            let Some(job) = self.servers[index].as_mut() else {
                continue;
            };
            if job.file.is_none() {
                if job.unconsumed == 0 {
                    let view = ep
                        .read(job.stream)
                        .map_err(|e| format!("read GET: {e:?}"))?;
                    if view.reset.is_some() {
                        return Err("client reset unfinished GET".into());
                    }
                    let count = view.first.len() + view.second.len();
                    if job.request_len + count > CHUNK {
                        return Err("GET exceeds bounded request buffer".into());
                    }
                    let mid = job.request_len + view.first.len();
                    job.request[job.request_len..mid].copy_from_slice(view.first);
                    job.request[mid..mid + view.second.len()].copy_from_slice(view.second);
                    job.request_len += count;
                    job.unconsumed = count;
                    job.request_fin = view.fin;
                }
                if job.unconsumed > 0 || job.request_fin {
                    match ep.consume(job.stream, job.unconsumed) {
                        Ok(()) => {
                            progress |= job.unconsumed > 0;
                            job.unconsumed = 0;
                        }
                        Err(e) if backpressure(&e) => continue,
                        Err(e) => return Err(format!("consume GET: {e:?}")),
                    }
                }
                if !job.request_fin {
                    continue;
                }
                let components = parse_get(&job.request[..job.request_len])?;
                job.file = Some(self.root.read(&components)?);
                progress = true;
            }
            if !job.fin_queued {
                if !job.loaded {
                    let file = job.file.as_mut().ok_or("missing file")?;
                    job.chunk_len = loop {
                        match file.read(&mut job.chunk) {
                            Ok(n) => break n,
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                            Err(e) => return Err(format!("read file chunk: {e}")),
                        }
                    };
                    job.eof = job.chunk_len == 0;
                    job.loaded = true;
                }
                match ep.send(job.stream, &job.chunk[..job.chunk_len], job.eof) {
                    Ok(()) => {
                        job.bytes += job.chunk_len as u64;
                        report.body_progress += job.chunk_len as u64;
                        job.loaded = false;
                        job.fin_queued = job.eof;
                        progress = true
                    }
                    Err(e) if backpressure(&e) => {}
                    Err(e) => return Err(format!("queue file chunk: {e:?}")),
                }
            }
            if job.fin_queued {
                match ep.retire_stream(job.stream) {
                    Ok(()) => {
                        report.files += 1;
                        report.bytes += job.bytes;
                        self.servers[index] = None;
                        progress = true
                    }
                    Err(TransportError::Streams(
                        streams::Error::NotTerminal | streams::Error::Capacity,
                    )) => {}
                    Err(e) => return Err(format!("retire completed server stream: {e:?}")),
                }
            }
        }
        Ok(progress)
    }
}

/// One host-listener quota and monotonic epoch across repeated admissions.
struct VersionNegotiationListener {
    policy: version_negotiation::Listener,
    started: Instant,
}
impl VersionNegotiationListener {
    fn new() -> Result<Self> {
        Ok(Self {
            policy: version_negotiation::Listener::new(
                UDP_BYTES.min(version_negotiation::MAX_DATAGRAM_BYTES),
                64,
                1_000_000,
            )
            .map_err(|e| format!("version negotiation policy: {e:?}"))?,
            started: Instant::now(),
        })
    }
}
fn header_destination(header: Header<'_>) -> &[u8] {
    match header {
        Header::Long { destination_id, .. }
        | Header::Short { destination_id, .. }
        | Header::Retry { destination_id, .. }
        | Header::VersionNegotiation { destination_id, .. }
        | Header::UnsupportedVersion { destination_id, .. } => destination_id,
    }
}
fn header_is_retired(header: Header<'_>, retired: &[Vec<u8>]) -> bool {
    retired
        .iter()
        .any(|id| id.as_slice() == header_destination(header))
}
struct InitialAdmission {
    len: usize,
    peer: SocketAddr,
    original: Vec<u8>,
    ecn: Option<Codepoint>,
    token: Option<ValidatedToken>,
    retry: RetryStats,
}
fn await_initial(
    socket: &mut UdpMetadataSocket,
    input: &mut [u8],
    start: Instant,
    timeout: Duration,
    retry_lifetime: Option<u64>,
    retired: &[Vec<u8>],
    version_listener: &mut VersionNegotiationListener,
) -> Result<InitialAdmission> {
    let mut dispatcher = retry_lifetime.map(RetryDispatcher::new).transpose()?;
    let mut output = [0; version_negotiation::MAX_RESPONSE_BYTES];
    loop {
        if start.elapsed() >= timeout {
            return Err("deadline waiting for a fresh v1 Initial".into());
        }
        let metadata = match socket.recv_from(input) {
            Ok(metadata) => metadata,
            Err(e) if transient(&e) => continue,
            Err(e) => return Err(format!("server initial receive: {e}")),
        };
        if metadata.len < 1200 {
            continue;
        }
        let packet = PacketIter::new(&input[..metadata.len], 8, 8)
            .ok()
            .and_then(|mut p| p.next())
            .and_then(std::result::Result::ok);
        let Some(packet) = packet else {
            continue;
        };
        // Retained CID aliases route before the stateless service. An unknown
        // version cannot turn an old connection into fresh listener admission.
        if header_is_retired(packet.header, retired) {
            continue;
        }
        if let ListenerAction::Send { len } = version_listener
            .policy
            .on_datagram(
                now(version_listener.started),
                &input[..metadata.len],
                &mut OsRng,
                &mut output,
            )
            .map_err(|e| format!("version negotiation: {e:?}"))?
        {
            match socket.send_to(&output[..len], metadata.source, Codepoint::NotEct) {
                Ok(written) if written == len => {}
                Ok(_) => return Err("partial version negotiation datagram acceptance".into()),
                Err(e) if transient(&e) => {} // Quota is burned; never retry without new input.
                Err(e) => return Err(format!("version negotiation send: {e}")),
            }
            continue;
        }
        let Header::Long {
            kind: LongType::Initial,
            destination_id,
            ..
        } = packet.header
        else {
            continue;
        };
        if destination_id.is_empty() {
            continue;
        }
        if let Some(dispatcher) = &mut dispatcher {
            dispatcher.stats.received = dispatcher.stats.received.saturating_add(1);
            match dispatcher.handle(
                now(start),
                metadata.source,
                &input[..metadata.len],
                &mut output,
            )? {
                RetryAction::Discard => continue,
                RetryAction::Send(n) => {
                    match socket.send_to(&output[..n], metadata.source, Codepoint::NotEct) {
                        Ok(written) if written == n => {
                            dispatcher.stats.sent = dispatcher.stats.sent.saturating_add(1)
                        }
                        Ok(_) => return Err("partial Retry datagram acceptance".into()),
                        Err(e) if transient(&e) => {}
                        Err(e) => return Err(format!("Retry send: {e}")),
                    }
                    continue;
                }
                RetryAction::Admit(token) => {
                    return Ok(InitialAdmission {
                        len: metadata.len,
                        peer: metadata.source,
                        original: token.original_destination_id().to_vec(),
                        ecn: metadata.ecn,
                        token: Some(token),
                        retry: dispatcher.stats,
                    });
                }
            }
        }
        return Ok(InitialAdmission {
            len: metadata.len,
            peer: metadata.source,
            original: destination_id.to_vec(),
            ecn: metadata.ecn,
            token: None,
            retry: RetryStats::default(),
        });
    }
}
fn run(options: Options) -> Result<RunReport> {
    match options {
        Options::Client {
            connect,
            name,
            ca,
            requests,
            downloads,
            timeout,
            key_update_after,
            use_ecn,
            cipher_policy,
            connections,
            require_resumption,
            resumption_delay,
        } => {
            let clock = HostTicketClock(Instant::now());
            let root_der = certificates(&ca)?;
            let anchors = root_der
                .iter()
                .map(trust_anchor_from_der)
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| format!("CA trust roots: {e:?}"))?;
            let context = VerificationContext::new(&anchors, CertificateLimits::default())
                .map_err(|e| format!("verification context: {e:?}"))?;
            let origin = Binding::new(&name, b"hq-interop", &[])
                .map_err(|e| format!("ticket origin: {e:?}"))?;
            let mut slots = [ClientSlot::<CACHE_TICKET_BYTES>::empty()];
            let mut cache = ClientCache::new(&mut slots);
            let mut generation = u64::from_be_bytes(random::<8>()?);
            if connections == 2 {
                next_generation(generation)?;
            }
            let groups = request_groups(requests, connections)?;
            let mut reports = Vec::new();
            let mut sockets = Vec::new(); // Keep old bound ports unavailable through the next connection.
            for (index, requests) in groups.into_iter().enumerate() {
                if index > 0 {
                    generation = next_generation(generation)?;
                    std::thread::sleep(resumption_delay);
                }
                let offer = if index > 0 {
                    let now = clock.now_ms().map_err(|e| format!("ticket clock: {e:?}"))?;
                    let suite = reports
                        .last()
                        .and_then(|report: &Report| report.negotiated_suite)
                        .ok_or("first connection has no authenticated cipher suite")?;
                    cache
                        .take_verified_for_origin(now, &origin, suite, context)
                        .map_err(|e| format!("ticket selection: {e:?}"))?
                } else {
                    None
                };
                let offered = offer.is_some();
                if index > 0 && require_resumption && !offered {
                    return Err(
                        "no unexpired, trust-matching cached ticket for required resumption".into(),
                    );
                }
                let inserted = Cell::new(0);
                let mut observed = ObservedCache {
                    cache: &mut cache,
                    inserted: &inserted,
                };
                let local = random::<8>()?;
                let original = random::<8>()?;
                let params = parameters(&local, None, None, local_limits(Side::Client))?;
                let mut buffers = TlsBuffers::new();
                let cfg = BoundedClientConfig {
                    server_name: &name,
                    trust_anchors: &anchors,
                    now: certificate_time()?,
                    certificate_limits: CertificateLimits::default(),
                    transport_parameters: &params,
                };
                let session = ClientResumption {
                    store: &mut observed,
                    clock: &clock,
                };
                let tls = if connections == 1 {
                    BoundedTls::client_with_policy(
                        cfg,
                        buffers.storage(),
                        &mut OsRng,
                        cipher_policy,
                    )
                } else if let Some(offer) = offer {
                    BoundedTls::client_resuming_with_policy(
                        cfg,
                        buffers.storage(),
                        &mut OsRng,
                        session,
                        offer,
                        cipher_policy,
                    )
                } else {
                    BoundedTls::client_with_tickets_and_policy(
                        cfg,
                        buffers.storage(),
                        &mut OsRng,
                        session,
                        cipher_policy,
                    )
                }
                .map_err(|e| format!("bounded TLS client: {e:?}"))?;
                let socket = UdpSocket::bind(if connect.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                })
                .map_err(|e| format!("client UDP bind: {e}"))?;
                sockets.push(
                    UdpMetadataSocket::new(socket)
                        .map_err(|e| format!("UDP metadata setup: {e}"))?,
                );
                let app = App {
                    side: Side::Client,
                    root: SafeRoot::open(&downloads, true)?,
                    requests,
                    next_request: 0,
                    max_requests: None,
                    clients: std::array::from_fn(|_| None),
                    servers: std::array::from_fn(|_| None),
                };
                reports.push(exchange(
                    sockets.last_mut().ok_or("missing client socket")?,
                    connect,
                    local,
                    original.to_vec(),
                    tls,
                    None,
                    RetryStats::default(),
                    None,
                    Instant::now(),
                    timeout,
                    key_update_after,
                    use_ecn,
                    app,
                    SessionOptions {
                        generation,
                        cipher_policy,
                        index: index + 1,
                        persistent: connections == 2,
                        offered,
                        require_resumed: index > 0 && require_resumption,
                        wait_ticket: (connections == 2).then_some(&inserted),
                        require_ticket: connections == 2 && index == 0,
                        ticket_acceptance: None,
                        ticket_age: None,
                    },
                )?);
            }
            Ok(RunReport {
                connections: reports,
                require_resumption,
            })
        }
        Options::Server {
            listen,
            cert,
            key,
            www,
            max_requests,
            require_retry,
            retry_lifetime_us,
            timeout,
            key_update_after,
            use_ecn,
            cipher_policy,
            max_connections,
            ticket_lifetime,
            ticket_age_skew_ms,
            ticket_policy_second,
            rotate_ticket_key,
        } => {
            let chain = certificates(&cert)?;
            let key = private_key(&key)?;
            let signing = signing_key(&key)?;
            let der: Vec<&[u8]> = chain.iter().map(|c| c.as_ref()).collect();
            let clock = HostTicketClock(Instant::now());
            let mut replay = [ReplaySlot::empty(), ReplaySlot::empty()];
            let mut ticket_key =
                TicketKey::generate(&mut OsRng, ReplayPolicy::SingleUseOneRtt, &mut replay)
                    .map_err(|e| format!("ticket key generation: {e:?}"))?;
            let mut generation = u64::from_be_bytes(random::<8>()?);
            if max_connections == 2 {
                next_generation(generation)?;
            }
            let socket = UdpSocket::bind(listen).map_err(|e| format!("server UDP bind: {e}"))?;
            let mut socket =
                UdpMetadataSocket::new(socket).map_err(|e| format!("UDP metadata setup: {e}"))?;
            eprintln!(
                "listening {}",
                socket
                    .local_addr()
                    .map_err(|e| format!("local address: {e}"))?
            );
            socket
                .set_read_timeout(Some(Duration::from_millis(25)))
                .map_err(|e| format!("UDP timeout: {e}"))?;
            let mut reports = Vec::new();
            let mut retired = Vec::new();
            let mut version_listener = VersionNegotiationListener::new()?;
            let issued = Cell::new(None);
            for index in 0..max_connections {
                if index > 0 {
                    generation = next_generation(generation)?;
                    if rotate_ticket_key {
                        drop(ticket_key);
                        ticket_key = TicketKey::generate(
                            &mut OsRng,
                            ReplayPolicy::SingleUseOneRtt,
                            &mut replay,
                        )
                        .map_err(|e| format!("ticket key rotation: {e:?}"))?;
                    }
                }
                let start = Instant::now();
                let mut input = [0; UDP_BYTES];
                let admission = await_initial(
                    &mut socket,
                    &mut input,
                    start,
                    timeout,
                    require_retry.then_some(retry_lifetime_us),
                    &retired,
                    &mut version_listener,
                )?;
                let local = random::<8>()?;
                let params = parameters(
                    &local,
                    Some(&admission.original),
                    admission
                        .token
                        .as_ref()
                        .map(ValidatedToken::retry_source_id),
                    local_limits(Side::Server),
                )?;
                retired.push(admission.original.clone());
                retired.push(local.to_vec());
                if let Some(token) = &admission.token {
                    retired.push(token.retry_source_id().to_vec());
                }
                let acceptance = Cell::new(None);
                let age = Cell::new(None);
                let mut issuer = ObservedIssuer {
                    key: &mut ticket_key,
                    acceptance: &acceptance,
                    issued: &issued,
                    age: &age,
                    prepared_at: None,
                };
                let mut buffers = TlsBuffers::new();
                let cfg = BoundedServerConfig {
                    certificate_chain: &der,
                    signing_key: &signing,
                    transport_parameters: &params,
                };
                let mut entropy = OsRng;
                let policy = if index > 0 {
                    ticket_policy_second.as_deref().unwrap_or("hq-interop-v1")
                } else {
                    "hq-interop-v1"
                };
                let tls = if max_connections == 1 {
                    BoundedTls::server_with_policy(
                        cfg,
                        buffers.storage(),
                        &mut OsRng,
                        cipher_policy,
                    )
                } else {
                    BoundedTls::server_with_tickets_and_policy(
                        cfg,
                        buffers.storage(),
                        &mut OsRng,
                        ServerResumption {
                            store: &mut issuer,
                            entropy: &mut entropy,
                            clock: &clock,
                            policy: policy.as_bytes(),
                            lifetime_seconds: ticket_lifetime,
                            max_age_skew_ms: ticket_age_skew_ms,
                        },
                        cipher_policy,
                    )
                }
                .map_err(|e| format!("bounded TLS server: {e:?}"))?;
                let connection_requests = if max_connections == 2 && index == 0 {
                    Some(1)
                } else if max_connections == 2 {
                    max_requests.map(|n| n - 1)
                } else {
                    max_requests
                };
                let app = App {
                    side: Side::Server,
                    root: SafeRoot::open(&www, false)?,
                    requests: Vec::new(),
                    next_request: 0,
                    max_requests: connection_requests,
                    clients: std::array::from_fn(|_| None),
                    servers: std::array::from_fn(|_| None),
                };
                reports.push(exchange(
                    &mut socket,
                    admission.peer,
                    local,
                    admission.original,
                    tls,
                    admission.token,
                    admission.retry,
                    Some((&input[..admission.len], admission.ecn)),
                    start,
                    timeout,
                    key_update_after,
                    use_ecn,
                    app,
                    SessionOptions {
                        generation,
                        cipher_policy,
                        index: index + 1,
                        persistent: max_connections == 2,
                        offered: false,
                        require_resumed: false,
                        wait_ticket: None,
                        require_ticket: false,
                        ticket_acceptance: Some(&acceptance),
                        ticket_age: Some(&age),
                    },
                )?);
            }
            Ok(RunReport {
                connections: reports,
                require_resumption: false,
            })
        }
    }
}
#[allow(clippy::too_many_arguments)]
fn exchange(
    socket: &mut UdpMetadataSocket,
    peer: SocketAddr,
    local: [u8; 8],
    original: Vec<u8>,
    tls: BoundedTls<'_, '_>,
    admission: Option<ValidatedToken>,
    retry_stats: RetryStats,
    first: Option<(&[u8], Option<Codepoint>)>,
    start: Instant,
    budget: Duration,
    key_update_after: Option<u64>,
    use_ecn: bool,
    mut app: App,
    session: SessionOptions<'_>,
) -> Result<Report> {
    let side = app.side;
    let generation = session.generation;
    let sid = SessionId::new(1);
    let queues = CarrierStorage::<8, 16, { hibana_quic::protocol::SERVICE_PORTS }>::new();
    let mut slab = [0; 32768];
    let mut storage = SessionKitStorage::<
        LocalCarrier<'_, 8, 16, { hibana_quic::protocol::SERVICE_PORTS }>,
    >::uninit();
    let rv = storage
        .init()
        .rendezvous(
            &mut slab,
            queues.bind(sid).map_err(|e| format!("carrier: {e:?}"))?,
        )
        .map_err(|e| format!("rendezvous: {e:?}"))?;
    let p0 = service_program::<INGRESS>();
    let p1 = service_program::<PACKET>();
    let p2 = service_program::<APPLICATION>();
    let p3 = service_program::<RECOVERY>();
    let p4 = service_program::<ADAPTER>();
    let p5 = service_program::<TIMER>();
    let roles = Roles {
        ingress: rv.enter(sid, &p0).map_err(|e| format!("ingress: {e:?}"))?,
        packet: rv.enter(sid, &p1).map_err(|e| format!("packet: {e:?}"))?,
        application: rv
            .enter(sid, &p2)
            .map_err(|e| format!("application: {e:?}"))?,
        recovery: rv.enter(sid, &p3).map_err(|e| format!("recovery: {e:?}"))?,
        adapter: rv.enter(sid, &p4).map_err(|e| format!("adapter: {e:?}"))?,
        timer: rv.enter(sid, &p5).map_err(|e| format!("timer: {e:?}"))?,
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
        CryptoBuffer::new(&mut d0, &mut m0).map_err(|e| format!("crypto buffer: {e:?}"))?,
        CryptoBuffer::new(&mut d1, &mut m1).map_err(|e| format!("crypto buffer: {e:?}"))?,
        CryptoBuffer::new(&mut d2, &mut m2).map_err(|e| format!("crypto buffer: {e:?}"))?,
    ];
    let config = Config {
        side,
        local_id: &local,
        original_destination_id: &original,
        generation,
    };
    let driver = Driver::new(generation, roles);
    let mut engine = match admission {
        Some(admission) => {
            HandshakeEndpoint::new_after_retry(config, tls, driver, crypto, admission)
        }
        None => HandshakeEndpoint::new(config, tls, driver, crypto),
    }
    .map_err(|e| format!("QUIC setup: {e:?}"))?;
    // parameters() omits TP 1: the advertised local idle timeout is exactly zero.
    // The host wall deadline is deliberately independent.
    engine
        .configure_idle_timeout(0)
        .map_err(|e| format!("idle timeout setup: {e:?}"))?;
    let mut stream_slots = [const { StreamSlot::<RX>::EMPTY }; LIVE];
    let mut chunks = [const { SendChunk::<CHUNK>::EMPTY }; 16];
    let mut references = [PacketReference::EMPTY; 128];
    let mut endpoint: Endpoint<'_, '_, '_, '_> = TransportEndpoint::new(
        engine,
        local_limits(side),
        &mut stream_slots,
        &mut chunks,
        &mut references,
        generation,
    )
    .map_err(|e| format!("stream setup: {e:?}"))?;
    if use_ecn {
        endpoint
            .enable_ecn()
            .map_err(|e| format!("ECN enable: {e:?}"))?;
    }
    let mut input = [0; UDP_BYTES];
    let mut scratch = [0; UDP_BYTES];
    let mut output = [0; 1500];
    let mut report = Report {
        side,
        files: 0,
        bytes: 0,
        sent: retry_stats.sent,
        received: retry_stats.received.saturating_sub(1),
        authenticated: 0,
        discarded: 0,
        duration_ms: 0,
        body_progress: 0,
        key_update_after,
        key_update_at: None,
        send_key_generation: 0,
        receive_key_generation: 0,
        ecn: None,
        negotiated_group: None,
        negotiated_suite: None,
        cipher_policy: session.cipher_policy,
        retry: retry_stats,
        connection_index: session.index,
        connection_generation: generation,
        resumption_offered: session.offered,
        resumed: false,
        tickets_cached: 0,
        lifecycle_closed: false,
        ticket_acceptance: None,
        ticket_age: None,
    };
    if let Some((first, codepoint)) = first {
        let metadata = ecn::Metadata {
            path: endpoint.path_identity(),
            codepoint,
        };
        let r = endpoint
            .receive_with_metadata(first, &mut scratch, metadata)
            .map_err(|e| {
                format!(
                    "first packet: {e:?}; bounded TLS: {:?}",
                    endpoint.tls().last_failure()
                )
            })?;
        report.received += 1;
        report.authenticated += r.authenticated as u64;
        report.discarded += r.discarded as u64;
    }
    let mut last_activity = start.elapsed();
    let mut completed_at = None;
    loop {
        if start.elapsed() >= budget {
            return Err(format!(
                "deadline expired on connection {}: {} complete files, {} live; ticket acceptance {:?}, age {:?}; no overall success reported",
                session.index,
                report.files,
                app.active(),
                report.ticket_acceptance,
                report.ticket_age
            ));
        }
        if endpoint.connection_state() == ConnectionState::Closed {
            if !(app.done(&report)
                || (side == Side::Server
                    && app.max_requests.is_none()
                    && report.files > 0
                    && app.active() == 0))
            {
                return Err("connection retired before all expected files completed".into());
            }
            report.check_update_threshold()?;
            if !report.update_ready() || (session.require_ticket && report.tickets_cached == 0) {
                return Err("connection closed before requested key update or authenticated ticket was established".into());
            }
            report.lifecycle_closed = true;
            report.duration_ms = start.elapsed().as_millis();
            return Ok(report);
        }
        endpoint
            .timer(now(start))
            .map_err(|e| format!("timer: {e:?}"))?;
        let state = endpoint.connection_state();
        report.tickets_cached = session.wait_ticket.map_or(0, Cell::get);
        report.ticket_acceptance = session.ticket_acceptance.and_then(Cell::get);
        report.ticket_age = session.ticket_age.and_then(Cell::get);
        if side == Side::Server {
            report.resumption_offered = report.ticket_acceptance.is_some();
        }
        if state == ConnectionState::Active && endpoint.handshake_complete() {
            report.resumed = endpoint.tls().is_resumed();
            report.negotiated_suite = endpoint.tls().negotiated_suite().map(|suite| match suite {
                CipherSuite::Aes128GcmSha256 => 0x1301,
                CipherSuite::ChaCha20Poly1305Sha256 => 0x1303,
            });
            if !report
                .negotiated_suite
                .is_some_and(|suite| session.cipher_policy.permits(suite))
            {
                return Err("negotiated cipher suite violates configured policy".into());
            }
            if session.require_resumed && !report.resumed {
                return Err(
                    "server declined required resumption; full fallback is not resumption success"
                        .into(),
                );
            }
        }
        let progress = if state == ConnectionState::Active {
            app.advance(&mut endpoint, &mut report)?
        } else {
            false
        };
        let files_complete = app.done(&report)
            || (side == Side::Server
                && app.max_requests.is_none()
                && report.files > 0
                && app.active() == 0);
        if state != ConnectionState::Active && !files_complete {
            return Err("peer closed before every expected file and stream completed".into());
        }
        if state == ConnectionState::Closed {
            report.check_update_threshold()?;
            if !report.update_ready() || (session.require_ticket && report.tickets_cached == 0) {
                return Err("connection closed before requested key update or authenticated ticket was established".into());
            }
            report.lifecycle_closed = true;
            report.duration_ms = start.elapsed().as_millis();
            return Ok(report);
        }
        if state == ConnectionState::Active
            && report.key_update_at.is_none()
            && report
                .key_update_after
                .is_some_and(|n| report.body_progress >= n)
        {
            match endpoint.initiate_key_update() {
                Ok(()) => report.key_update_at = Some(report.body_progress),
                Err(error) if update_temporarily_blocked(&error) => {}
                Err(error) => return Err(format!("requested key update: {error:?}")),
            }
        }
        if endpoint.connection_state() == ConnectionState::Active {
            report.send_key_generation = endpoint.key_generation();
            report.receive_key_generation = endpoint.receive_key_generation();
            report.negotiated_group = endpoint.negotiated_group();
        }
        report.ecn = Some(endpoint.ecn_snapshot());
        if progress {
            last_activity = start.elapsed();
        }
        let mut drained = false;
        for _ in 0..64 {
            let Some(tx) = endpoint
                .transmit(&mut output)
                .map_err(|e| format!("packet production: {e:?}"))?
            else {
                drained = true;
                break;
            };
            if !endpoint
                .transmit_permitted(tx, now(start))
                .map_err(|e| format!("transmit permission: {e:?}"))?
            {
                continue;
            }
            match socket.send_to(&output[..tx.len], peer, tx.ecn) {
                Ok(n) if n == tx.len => {
                    endpoint
                        .adapter_result(tx, true, now(start))
                        .map_err(|e| format!("adapter acceptance: {e:?}"))?;
                    report.sent += 1;
                }
                other => {
                    endpoint
                        .adapter_result(tx, false, now(start))
                        .map_err(|e| format!("adapter rejection: {e:?}"))?;
                    return Err(format!("UDP did not accept datagram: {other:?}"));
                }
            }
        }
        let quiet = drained && !endpoint.pending_application_work();
        let done = app.done(&report);
        if done && quiet {
            report.check_update_threshold()?;
        }
        if !session.persistent
            && state == ConnectionState::Active
            && completed_server_goal(
                side,
                app.max_requests,
                report.files,
                app.active(),
                endpoint.streams().live_count(),
            )
        {
            report.check_update_threshold()?;
            if drained && report.update_ready() {
                // FIN/data ownership is retired. Unacknowledged future-credit
                // controls cannot hold an explicitly finished server forever.
                // The real close lifecycle cancels those obligations and keeps
                // routing/timers alive until Closed; do not return success here.
                endpoint
                    .initiate_close(
                        CloseReason::application(0, "completed requested files")
                            .map_err(|e| format!("close reason: {e:?}"))?,
                    )
                    .map_err(|e| format!("close completed server: {e:?}"))?;
                continue;
            }
        }
        if session.persistent
            && state == ConnectionState::Active
            && files_complete
            && quiet
            && report.update_ready()
            && (!session.require_ticket || report.tickets_cached > 0)
            && side == Side::Client
        {
            endpoint
                .initiate_close(
                    CloseReason::application(0, "transfer complete")
                        .map_err(|e| format!("close reason: {e:?}"))?,
                )
                .map_err(|e| format!("initiate close: {e:?}"))?;
            continue;
        }
        if !session.persistent
            && state == ConnectionState::Active
            && side == Side::Client
            && done
            && quiet
            && report.update_ready()
        {
            let completed = *completed_at.get_or_insert(start.elapsed());
            if start.elapsed().saturating_sub(completed) >= Duration::from_millis(500) {
                report.duration_ms = start.elapsed().as_millis();
                return Ok(report);
            }
        } else {
            completed_at = None;
        }
        if !session.persistent
            && state == ConnectionState::Active
            && side == Side::Server
            && app.max_requests.is_none()
            && report.files > 0
            && app.active() == 0
            && quiet
            && report.update_ready()
            && start.elapsed().saturating_sub(last_activity) >= Duration::from_secs(2)
        {
            report.duration_ms = start.elapsed().as_millis();
            return Ok(report);
        }
        let deadline = endpoint
            .next_deadline()
            .map(|d| Duration::from_micros(d.saturating_sub(now(start))));
        let wait = deadline
            .unwrap_or(Duration::from_millis(5))
            .min(if progress || !drained {
                Duration::from_millis(1)
            } else {
                Duration::from_millis(5)
            })
            .max(Duration::from_micros(100));
        socket
            .set_read_timeout(Some(wait))
            .map_err(|e| format!("receive timeout: {e}"))?;
        match socket.recv_from(&mut input) {
            Ok(received) if received.source == peer => {
                let metadata = ecn::Metadata {
                    path: endpoint.path_identity(),
                    codepoint: received.ecn,
                };
                let r = endpoint
                    .receive_with_metadata(&input[..received.len], &mut scratch, metadata)
                    .map_err(|e| {
                        format!(
                            "packet receive: {e:?}; bounded TLS: {:?}",
                            endpoint.tls().last_failure()
                        )
                    })?;
                if endpoint.connection_state() == ConnectionState::Active {
                    report.send_key_generation = endpoint.key_generation();
                    report.receive_key_generation = endpoint.receive_key_generation();
                    report.negotiated_group = endpoint.negotiated_group();
                }
                report.ecn = Some(endpoint.ecn_snapshot());
                report.received += 1;
                report.authenticated += r.authenticated as u64;
                report.discarded += r.discarded as u64;
                last_activity = start.elapsed();
                // Closing/Draining is not completion. The loop's exact Closed
                // check owns successful lifecycle exit after all file gates.
            }
            Ok(_) => {}
            Err(e) if transient(&e) => {}
            Err(e) => return Err(format!("UDP receive: {e}")),
        }
    }
}
fn json_string(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
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
                "{{\"status\":\"failure\",\"scope\":\"direct-http09-transfer\",\"backend\":\"bounded-profile\",\"error\":{}}}",
                json_string(&error)
            );
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "hibana-hq-test-{:016x}",
                u64::from_be_bytes(random().unwrap())
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn components(target: &str) -> Vec<String> {
        path_components(target).unwrap()
    }
    #[test]
    fn completed_server_close_requires_explicit_goal_and_no_live_owners() {
        assert!(completed_server_goal(Side::Server, Some(1), 1, 0, 0));
        assert!(completed_server_goal(Side::Server, Some(2), 3, 0, 0));
        assert!(!completed_server_goal(Side::Client, Some(1), 1, 0, 0));
        assert!(!completed_server_goal(Side::Server, None, 1, 0, 0));
        assert!(!completed_server_goal(Side::Server, Some(0), 0, 0, 0));
        assert!(!completed_server_goal(Side::Server, Some(2), 1, 0, 0));
        assert!(!completed_server_goal(Side::Server, Some(1), 1, 1, 0));
        assert!(!completed_server_goal(Side::Server, Some(1), 1, 0, 1));
    }
    #[test]
    fn version_negotiation_routes_retired_aliases_before_listener_and_uses_valid_capacity() {
        assert!(VersionNegotiationListener::new().is_ok());
        let retired = [
            b"original".to_vec(),
            b"retrycid".to_vec(),
            b"localcid".to_vec(),
        ];
        for id in &retired {
            assert!(header_is_retired(
                Header::UnsupportedVersion {
                    version: 0xface_b00c,
                    destination_id: id,
                    source_id: b"fresh-source",
                },
                &retired
            ));
            assert!(header_is_retired(
                Header::Short {
                    destination_id: id,
                    packet_number_offset: 9,
                },
                &retired
            ));
        }
        assert!(!header_is_retired(
            Header::UnsupportedVersion {
                version: 0xface_b00c,
                destination_id: b"original-prefix",
                source_id: b"fresh-source",
            },
            &retired
        ));
        assert!(!header_is_retired(
            Header::UnsupportedVersion {
                version: 0xface_b00c,
                destination_id: b"",
                source_id: b"fresh-source",
            },
            &retired
        ));
    }
    #[test]
    fn cipher_policy_cli_is_strict_and_preserves_defaults_on_both_roles() {
        let base = [
            "client --connect [::1]:4433 --server-name localhost --ca ca.pem --downloads out --request /x",
            "server --listen [::1]:0 --cert leaf.pem --key key.pem --www www",
        ];
        for base in base {
            for (tail, expected) in [
                ("", CipherPolicy::Default),
                (" --cipher-suite default", CipherPolicy::Default),
                (" --cipher-suite aes128", CipherPolicy::Aes128Only),
                (" --cipher-suite chacha20", CipherPolicy::ChaCha20Only),
            ] {
                let args = format!("{base}{tail}")
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect::<Vec<_>>();
                match parse_options(&args).unwrap() {
                    Options::Client {
                        cipher_policy,
                        connect,
                        ..
                    } => {
                        assert_eq!(cipher_policy, expected);
                        assert!(connect.is_ipv6());
                    }
                    Options::Server {
                        cipher_policy,
                        listen,
                        ..
                    } => {
                        assert_eq!(cipher_policy, expected);
                        assert!(listen.is_ipv6());
                    }
                }
            }
            for tail in [
                " --cipher-suite AES",
                " --cipher-suite chacha20,aes128",
                " --cipher-suite",
                " --cipher-suite chacha20 --cipher-suite default",
            ] {
                let args = format!("{base}{tail}")
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect::<Vec<_>>();
                assert!(parse_options(&args).is_err());
            }
        }
    }
    #[test]
    fn resumption_cli_is_bounded_and_requires_two_distinct_requests() {
        let base = [
            "client",
            "--connect",
            "127.0.0.1:4433",
            "--server-name",
            "localhost",
            "--ca",
            "ca.pem",
            "--downloads",
            "downloads",
            "--request",
            "/first",
        ];
        let parse = |extra: &[&str]| {
            let args: Vec<String> = base.iter().chain(extra).map(|s| s.to_string()).collect();
            parse_options(&args)
        };
        assert!(matches!(
            parse(&[]).unwrap(),
            Options::Client {
                connections: 1,
                require_resumption: false,
                ..
            }
        ));
        assert!(parse(&["--connections", "2"]).is_err());
        for count in ["0", "3", "-1", "18446744073709551616"] {
            assert!(parse(&["--connections", count]).is_err());
        }
        assert!(matches!(
            parse(&["--request", "/second", "--connections", "2"]).unwrap(),
            Options::Client {
                connections: 2,
                require_resumption: true,
                ..
            }
        ));
        assert!(matches!(
            parse(&[
                "--request",
                "/second",
                "--connections",
                "2",
                "--require-resumption",
                "false"
            ])
            .unwrap(),
            Options::Client {
                require_resumption: false,
                ..
            }
        ));
        assert!(parse(&["--require-resumption", "true"]).is_err());
        assert!(
            parse(&[
                "--request",
                "/second",
                "--connections",
                "2",
                "--resumption-delay-ms",
                "60001"
            ])
            .is_err()
        );
    }
    #[test]
    fn resumption_server_policy_and_generation_bounds_are_explicit() {
        let base = [
            "server",
            "--listen",
            "127.0.0.1:4433",
            "--cert",
            "cert.pem",
            "--key",
            "key.pem",
            "--www",
            "www",
        ];
        let parse = |extra: &[&str]| {
            let args: Vec<String> = base.iter().chain(extra).map(|s| s.to_string()).collect();
            parse_options(&args)
        };
        assert!(matches!(
            parse(&["--max-connections", "2"]).unwrap(),
            Options::Server {
                max_connections: 2,
                ticket_lifetime: 60,
                ..
            }
        ));
        for extra in [
            vec!["--max-connections", "3"],
            vec!["--max-connections", "2", "--max-requests", "1"],
            vec!["--max-connections", "2", "--ticket-lifetime-seconds", "0"],
            vec![
                "--max-connections",
                "2",
                "--ticket-lifetime-seconds",
                "604801",
            ],
            vec!["--max-connections", "2", "--ticket-policy-second", ""],
            vec!["--rotate-ticket-key-after-first", "true"],
        ] {
            assert!(parse(&extra).is_err(), "{extra:?}");
        }
        assert_eq!(next_generation(17), Ok(18));
        assert_eq!(next_generation(u64::MAX - 1), Ok(u64::MAX));
        assert!(next_generation(u64::MAX).is_err());
    }
    #[test]
    fn first_connection_has_exactly_first_file_and_second_has_all_remaining() {
        let requests = || {
            (0..7)
                .map(|i| Request {
                    target: format!("/{i}"),
                    components: vec![i.to_string()],
                })
                .collect()
        };
        let split = request_groups(requests(), 2).unwrap();
        assert_eq!(split.iter().map(Vec::len).collect::<Vec<_>>(), [1, 6]);
        assert_eq!(
            split
                .into_iter()
                .flatten()
                .map(|r| r.target)
                .collect::<Vec<_>>(),
            (0..7).map(|i| format!("/{i}")).collect::<Vec<_>>()
        );
        assert_eq!(request_groups(requests(), 1).unwrap()[0].len(), 7);
        assert!(request_groups(Vec::new(), 1).is_err());
        assert!(
            request_groups(
                vec![Request {
                    target: "/x".into(),
                    components: vec!["x".into()]
                }],
                2
            )
            .is_err()
        );
    }
    #[test]
    fn key_update_threshold_and_retry_errors_are_explicit() {
        for value in ["0", "-1", "bad", "18446744073709551616"] {
            assert!(parse_key_update_after(value).is_err());
        }
        assert_eq!(parse_key_update_after("1048576"), Ok(1048576));
        assert!(update_temporarily_blocked(&TransportError::Engine(
            EngineError::Tls(tls::Error::KeyUpdateNotAllowed)
        )));
        assert!(update_temporarily_blocked(&TransportError::Busy));
        for error in [
            tls::Error::Unsupported,
            tls::Error::Authentication,
            tls::Error::KeyUpdateError,
            tls::Error::KeysUnavailable,
        ] {
            assert!(!update_temporarily_blocked(&TransportError::Engine(
                EngineError::Tls(error)
            )));
        }
    }
    #[test]
    fn local_key_rotation_alone_cannot_satisfy_update_mode() {
        let mut report = Report {
            side: Side::Client,
            files: 1,
            bytes: 2048,
            sent: 1,
            received: 1,
            authenticated: 1,
            discarded: 0,
            duration_ms: 0,
            body_progress: 2048,
            key_update_after: Some(1024),
            key_update_at: Some(1024),
            send_key_generation: 1,
            receive_key_generation: 0,
            ecn: None,
            negotiated_group: None,
            negotiated_suite: None,
            cipher_policy: CipherPolicy::Default,
            retry: RetryStats::default(),
            connection_index: 1,
            connection_generation: 1,
            resumption_offered: false,
            resumed: false,
            tickets_cached: 0,
            lifecycle_closed: false,
            ticket_acceptance: None,
            ticket_age: None,
        };
        assert!(!report.update_ready());
        report.receive_key_generation = 1;
        assert!(report.update_ready());
        report.key_update_at = None;
        assert!(!report.update_ready());
        report.key_update_after = Some(4096);
        assert!(report.check_update_threshold().is_err());
        report.key_update_after = None;
        assert!(report.update_ready());
        assert!(report.check_update_threshold().is_ok());
    }
    #[test]
    fn path_decoder_rejects_traversal_separators_and_injection() {
        for target in [
            "../x",
            "//host/x",
            "/../x",
            "/a/./x",
            "/a//x",
            "/a/",
            "/%2e%2e/x",
            "/a%2fb",
            "/a%5cb",
            "/a\\b",
            "/%00",
            "/%0a",
            "/%",
            "/%xy",
            "/x?query",
            "/x#fragment",
            "/a b",
            "/x\r\nGET /secret",
            "/.hibana-temporary",
        ] {
            assert!(path_components(target).is_err(), "accepted {target:?}");
        }
        assert_eq!(
            components("/directory/hello%20world.txt"),
            ["directory", "hello world.txt"]
        );
        assert_eq!(components("/%252e%252e"), ["%2e%2e"]); // Decode exactly once.
    }
    #[test]
    fn get_parser_requires_method_line_end_and_no_extra_headers() {
        assert_eq!(parse_get(b"GET /hello\r\n").unwrap(), ["hello"]);
        assert_eq!(parse_get(b"GET /hello\n").unwrap(), ["hello"]);
        for bad in [
            &b"POST /hello\r\n"[..],
            &b"GET /hello"[..],
            &b"GET /hello HTTP/1.1\r\n"[..],
            &b"GET /hello\r\nX: header\r\n"[..],
        ] {
            assert!(parse_get(bad).is_err());
        }
    }
    #[test]
    fn url_authority_is_bound_to_verified_name_and_port() {
        assert_eq!(
            url_target("https://localhost:4433/a", "localhost", 4433).unwrap(),
            "/a"
        );
        assert_eq!(
            url_target("https://LOCALHOST/a", "localhost", 443).unwrap(),
            "/a"
        );
        for url in [
            "http://localhost:4433/a",
            "https://elsewhere:4433/a",
            "https://user@localhost:4433/a",
            "https://localhost:4434/a",
            "https://localhost:4433",
        ] {
            assert!(url_target(url, "localhost", 4433).is_err());
        }
    }
    #[test]
    fn symlink_parent_cannot_escape_server_or_download_root() {
        let f = Fixture::new();
        let root = f.0.join("root");
        let outside = f.0.join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("secret"), b"private").unwrap();
        symlink(&outside, root.join("escape")).unwrap();
        let safe = SafeRoot::open(&root, false).unwrap();
        assert!(safe.read(&components("/escape/secret")).is_err());
        assert!(safe.create(&components("/escape/new")).is_err());
        assert!(!outside.join("new").exists());
    }
    #[test]
    fn final_symlink_is_never_followed_or_overwritten() {
        let f = Fixture::new();
        fs::write(f.0.join("target"), b"original").unwrap();
        symlink(f.0.join("target"), f.0.join("alias")).unwrap();
        let safe = SafeRoot::open(&f.0, false).unwrap();
        assert!(safe.read(&components("/alias")).is_err());
        assert!(safe.create(&components("/alias")).is_err());
        assert_eq!(fs::read(f.0.join("target")).unwrap(), b"original");
    }
    #[test]
    fn held_root_descriptor_survives_path_replacement_without_escape() {
        let f = Fixture::new();
        let root = f.0.join("root");
        let moved = f.0.join("moved");
        let outside = f.0.join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(root.join("file"), b"authorized").unwrap();
        fs::write(outside.join("file"), b"outside").unwrap();
        let safe = SafeRoot::open(&root, false).unwrap();
        fs::rename(&root, &moved).unwrap();
        symlink(&outside, &root).unwrap();
        let mut content = String::new();
        safe.read(&components("/file"))
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        assert_eq!(content, "authorized");
    }
    #[test]
    fn complete_download_publishes_only_at_fin_without_overwrite() {
        let f = Fixture::new();
        let safe = SafeRoot::open(&f.0, false).unwrap();
        let mut download = safe.create(&components("/nested/body")).unwrap();
        download.file.write_all(b"complete").unwrap();
        assert!(!f.0.join("nested/body").exists());
        download.finish().unwrap();
        assert_eq!(fs::read(f.0.join("nested/body")).unwrap(), b"complete");
        assert!(safe.create(&components("/nested/body")).is_err());
    }
    #[test]
    fn failed_download_removes_staging_and_racing_destination_is_preserved() {
        let f = Fixture::new();
        let safe = SafeRoot::open(&f.0, false).unwrap();
        {
            let mut download = safe.create(&components("/body")).unwrap();
            download.file.write_all(b"partial").unwrap();
        }
        assert_eq!(fs::read_dir(&f.0).unwrap().count(), 0);
        let mut download = safe.create(&components("/body")).unwrap();
        download.file.write_all(b"ours").unwrap();
        fs::write(f.0.join("body"), b"existing").unwrap();
        assert!(download.finish().is_err());
        drop(download);
        assert_eq!(fs::read(f.0.join("body")).unwrap(), b"existing");
        assert_eq!(fs::read_dir(&f.0).unwrap().count(), 1);
    }
    #[test]
    fn cli_rejects_missing_roots_unknown_modes_and_duplicate_downloads() {
        let args = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        assert!(parse_options(&args("client --connect 127.0.0.1:4433")).is_err());
        assert!(parse_options(&args("client --connect 127.0.0.1:4433 --server-name localhost --ca root.pem --request /a --request /%61 --downloads output")).is_err());
        assert!(parse_options(&args("server --listen 127.0.0.1:4433 --cert leaf.pem --key key.pem --www www --insecure yes")).is_err());
        assert!(parse_options(&args("client --connect 127.0.0.1:4433 --server-name localhost --ca root.pem --request /a --downloads output")).is_ok());
    }
    #[test]
    fn named_pipe_cannot_block_the_server_before_regular_file_check() {
        let f = Fixture::new();
        let status = std::process::Command::new("mkfifo")
            .arg(f.0.join("pipe"))
            .status()
            .unwrap();
        assert!(status.success());
        let root = SafeRoot::open(&f.0, false).unwrap();
        assert!(root.read(&components("/pipe")).is_err());
    }
    fn retry_initial(destination: &[u8], source: &[u8], token: &[u8]) -> [u8; 1200] {
        let mut out = [0; 1200];
        let h = hibana_quic::packet::LongHeader {
            kind: LongType::Initial,
            destination_id: destination,
            source_id: source,
            token,
            packet_number: 0,
            packet_number_len: 4,
        };
        let n = hibana_quic::packet::encode_long_header(&h, 1000, &mut out).unwrap();
        hibana_quic::packet::encode_long_header(&h, 1200 - n, &mut out).unwrap();
        out
    }
    fn retry_challenge(
        dispatcher: &mut RetryDispatcher,
        now: u64,
        peer: SocketAddr,
    ) -> (Vec<u8>, Vec<u8>) {
        let input = retry_initial(b"original", b"client01", &[]);
        let mut out = [0; 256];
        let RetryAction::Send(n) = dispatcher.handle(now, peer, &input, &mut out).unwrap() else {
            panic!("Retry required")
        };
        assert!(n <= input.len());
        hibana_quic::crypto::verify_retry(b"original", &out[..n], &mut [0; 300]).unwrap();
        let packet = PacketIter::new(&out[..n], 8, 1)
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        let Header::Retry {
            destination_id,
            source_id,
            token,
            ..
        } = packet.header
        else {
            panic!("Retry required")
        };
        assert_eq!(destination_id, b"client01");
        assert_ne!(source_id, b"original");
        (source_id.to_vec(), token.to_vec())
    }
    #[test]
    fn retry_dispatcher_roundtrip_retransmits_before_admission_and_rejects_fresh_replay() {
        let mut d = RetryDispatcher::new(1000).unwrap();
        let peer = "127.0.0.1:12345".parse().unwrap();
        let (id, token) = retry_challenge(&mut d, 0, peer);
        retry_challenge(&mut d, 1, peer); // lost Retry/no-token Initial retransmission
        let packet = retry_initial(&id, b"client01", &token);
        let RetryAction::Admit(claims) = d.handle(2, peer, &packet, &mut [0; 256]).unwrap() else {
            panic!("admission")
        };
        assert_eq!(claims.original_destination_id(), b"original");
        assert_eq!(claims.retry_source_id(), &id);
        assert_eq!(d.stats.admissions, 1);
        assert!(matches!(
            d.handle(3, peer, &packet, &mut [0; 256]).unwrap(),
            RetryAction::Discard
        ));
        assert_eq!(d.stats.admissions, 1);
        assert_eq!(d.stats.invalid_tokens, 1);
    }
    #[test]
    fn retry_dispatcher_rejects_corruption_expiry_address_and_cid_changes_without_retry() {
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let mut d = RetryDispatcher::new(1000).unwrap();
        let (id, token) = retry_challenge(&mut d, 0, peer);
        let mut bad = token.clone();
        bad[30] ^= 1;
        for (address, destination, source, tok) in [
            (peer, id.as_slice(), &b"client01"[..], bad.as_slice()),
            (
                "127.0.0.1:54321".parse().unwrap(),
                id.as_slice(),
                &b"client01"[..],
                token.as_slice(),
            ),
            (
                "127.0.0.2:12345".parse().unwrap(),
                id.as_slice(),
                &b"client01"[..],
                token.as_slice(),
            ),
            (peer, &b"different"[..], &b"client01"[..], token.as_slice()),
            (peer, id.as_slice(), &b"changed!"[..], token.as_slice()),
        ] {
            let packet = retry_initial(destination, source, tok);
            assert!(matches!(
                d.handle(1, address, &packet, &mut [0; 256]).unwrap(),
                RetryAction::Discard
            ));
        }
        assert_eq!(d.stats.admissions, 0);
        assert_eq!(d.stats.invalid_tokens, 5);
        let valid = retry_initial(&id, b"client01", &token);
        assert!(matches!(
            d.handle(1000, peer, &valid, &mut [0; 256]).unwrap(),
            RetryAction::Discard
        ));
        assert_eq!(d.stats.admissions, 0);
    }
    #[test]
    fn retry_dispatcher_small_and_malformed_datagrams_never_issue_tokens() {
        let peer = "[::1]:12345".parse().unwrap();
        let mut d = RetryDispatcher::new(1000).unwrap();
        for input in [
            &[0; 1199][..],
            &[0; 1200][..],
            &retry_initial(b"short", b"client01", &[])[..],
        ] {
            assert!(matches!(
                d.handle(0, peer, input, &mut [0; 256]).unwrap(),
                RetryAction::Discard
            ));
        }
        assert_eq!(d.tokens.issued_tokens(), 0);
        let (id, token) = retry_challenge(&mut d, 0, peer);
        let valid = retry_initial(&id, b"client01", &token);
        assert!(matches!(
            d.handle(1, peer, &valid, &mut [0; 256]).unwrap(),
            RetryAction::Admit(_)
        ));
    }
    #[test]
    fn server_retry_parameters_bind_original_initial_and_retry_ids() {
        let bytes = parameters(
            b"server01",
            Some(b"original"),
            Some(b"retry001"),
            local_limits(Side::Server),
        )
        .unwrap();
        let p = hibana_quic::parameters::Parameters::parse(
            &bytes,
            hibana_quic::parameters::Peer::Server,
            &mut [0; 32],
        )
        .unwrap();
        p.verify_connection_ids(b"server01", Some(b"original"), Some(b"retry001"))
            .unwrap();
        assert!(
            p.verify_connection_ids(b"server01", Some(b"original"), None)
                .is_err()
        );
    }
    #[test]
    fn retry_cli_is_unary_server_only_with_explicit_lifetime() {
        let args = |s: &str| s.split_whitespace().map(str::to_owned).collect::<Vec<_>>();
        let base = "server --listen 127.0.0.1:0 --cert leaf.pem --key key.pem --www www";
        assert!(matches!(
            parse_options(&args(&format!("{base} --retry --retry-lifetime-ms 1"))).unwrap(),
            Options::Server {
                require_retry: true,
                retry_lifetime_us: 1000,
                ..
            }
        ));
        assert!(matches!(
            parse_options(&args(base)).unwrap(),
            Options::Server {
                require_retry: false,
                ..
            }
        ));
        for tail in [
            "--retry --retry",
            "--retry on",
            "--retry-lifetime-ms 1",
            "--retry --retry-lifetime-ms 0",
            "--retry --retry-lifetime-ms 60001",
        ] {
            assert!(parse_options(&args(&format!("{base} {tail}"))).is_err());
        }
        assert!(parse_options(&args("client --retry")).is_err());
    }
}
