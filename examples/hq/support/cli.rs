use super::host_files::{MAX_REQUESTS, Request};
use hibana_tls::handshake::CipherPolicy;
use std::{collections::BTreeMap, net::SocketAddr, path::PathBuf, time::Duration};
pub const USAGE: &str = "Direct Hibana QUIC v1/v2 / hq-interop or h3\n\n  hq client --connect IP:PORT --server-name HOST --ca ROOTS.pem [--request /FILE ... --downloads DIR] [--timeout-seconds 120] [--idle-timeout-seconds 60] [--http hq|3] [--cipher auto|aes128|chacha20] [--session single|resume|multi] [--early reject|replay-safe]\n  hq server --listen IP:PORT --cert CHAIN.pem --key KEY.pem [--www DIR --max-requests N] [--timeout-seconds 120] [--idle-timeout-seconds 60] [--http hq|3] [--cipher auto|aes128|chacha20] [--session single|resume|multi]\n\nOne connection, two ticket-resuming connections with --session resume, or one full connection per request with --session multi (server: --connections 1..64); at most 4096 file requests, explicit CA/hostname verification and real OS randomness.\nFile requests use bounded chunks and decoded-path-safe, atomic downloads.\nOmitting file options selects authenticated TLS-prefix diagnostics only; those\nreports never claim HTTP transfer, HANDSHAKE_DONE confirmation or completed close.";
#[derive(Debug)]
pub struct ClientFiles {
    pub requests: Vec<Request>,
    pub downloads: PathBuf,
}
#[derive(Debug)]
pub struct ServerFiles {
    pub www: PathBuf,
    pub max_requests: Option<usize>,
}
#[derive(Debug)]
pub enum Options {
    Client {
        protocol: hibana_quic::http3::Protocol,
        version: hibana_quic::quic::imp::kernel::version::Version,
        connect: SocketAddr,
        server_name: String,
        ca: PathBuf,
        timeout: Duration,
        idle_timeout: Duration,
        cipher: CipherPolicy,
        resumption: bool,
        connections: usize,
        early: bool,
        key_update_target: u64,
        files: Option<ClientFiles>,
    },
    Server {
        preferred_port: Option<u16>,
        protocol: hibana_quic::http3::Protocol,
        version: hibana_quic::quic::imp::kernel::version::Version,
        listen: SocketAddr,
        cert: PathBuf,
        key: PathBuf,
        timeout: Duration,
        idle_timeout: Duration,
        cipher: CipherPolicy,
        resumption: bool,
        connections: usize,
        early: bool,
        require_retry: bool,
        files: Option<ServerFiles>,
    },
}
impl Options {
    pub fn timeout(&self) -> Duration {
        match self {
            Self::Client { timeout, .. } | Self::Server { timeout, .. } => *timeout,
        }
    }
    pub fn idle_timeout(&self) -> Duration {
        match self {
            Self::Client { idle_timeout, .. } | Self::Server { idle_timeout, .. } => *idle_timeout,
        }
    }
    #[cfg(test)]
    pub fn application_requested(&self) -> bool {
        match self {
            Self::Client { files, .. } => files.is_some(),
            Self::Server { files, .. } => files.is_some(),
        }
    }
}
type Result<T> = std::result::Result<T, String>;
fn required<'a>(flags: &mut BTreeMap<&'a str, &'a str>, flag: &str) -> Result<&'a str> {
    flags.remove(flag).ok_or_else(|| format!("missing {flag}"))
}
pub fn options(args: &[String]) -> Result<Options> {
    let role = args.first().ok_or_else(|| USAGE.to_owned())?;
    let mut flags = BTreeMap::new();
    let mut targets = Vec::new();
    let mut pairs = args[1..].chunks_exact(2);
    for pair in &mut pairs {
        if pair[0] == "--request" {
            if targets.len() >= MAX_REQUESTS {
                return Err("at most 4096 requests are supported".into());
            }
            targets.push(pair[1].as_str());
        } else if !pair[0].starts_with("--")
            || flags.insert(pair[0].as_str(), pair[1].as_str()).is_some()
        {
            return Err(format!("invalid or repeated option {}", pair[0]));
        }
    }
    if !pairs.remainder().is_empty() {
        return Err("every option requires a value".into());
    }
    let application =
        !targets.is_empty() || flags.contains_key("--www") || flags.contains_key("--downloads");
    let seconds = flags
        .remove("--timeout-seconds")
        .unwrap_or(if application { "120" } else { "10" })
        .parse::<u64>()
        .map_err(|_| "invalid timeout")?;
    if !(1..=300).contains(&seconds) {
        return Err("timeout must be 1..=300 seconds".into());
    }
    let timeout = Duration::from_secs(seconds);
    let idle_timeout = match flags.remove("--idle-timeout-seconds") {
        Some(value) => {
            let idle = value.parse::<u64>().map_err(|_| "invalid idle timeout")?;
            if idle > 300 {
                return Err("idle timeout must be 0..=300 seconds".into());
            }
            Duration::from_secs(idle)
        }
        None => timeout / 2,
    };
    let cipher = match flags.remove("--cipher").unwrap_or("auto") {
        "auto" => CipherPolicy::Default,
        "aes128" => CipherPolicy::Aes128Only,
        "chacha20" => CipherPolicy::ChaCha20Only,
        _ => return Err("--cipher must be auto, aes128 or chacha20".into()),
    };
    let protocol = match flags.remove("--http").unwrap_or("hq") {
        "hq" => hibana_quic::http3::Protocol::Http09,
        "3" if application => hibana_quic::http3::Protocol::Http3,
        _ => return Err("--http must be hq or 3; HTTP/3 requires file mode".into()),
    };
    let version = match flags.remove("--version").unwrap_or("1") {
        "1" => hibana_quic::quic::imp::kernel::version::Version::V1,
        "2" => hibana_quic::quic::imp::kernel::version::Version::V2,
        _ => return Err("--version must be 1 or 2".into()),
    };
    let session = flags.remove("--session").unwrap_or("single");
    let resumption = match session {
        "single" => false,
        "resume" if application => true,
        "multi" if application => false,
        "resume" | "multi" => return Err("multiple connections require file mode".into()),
        _ => return Err("--session must be single, resume or multi".into()),
    };
    let result = match role.as_str() {
        "client" => {
            let connect: SocketAddr = required(&mut flags, "--connect")?
                .parse()
                .map_err(|_| "--connect must be IP:PORT")?;
            let server_name = required(&mut flags, "--server-name")?.to_owned();
            let ca = required(&mut flags, "--ca")?.into();
            let downloads = flags.remove("--downloads");
            let files = if targets.is_empty() && downloads.is_none() {
                None
            } else {
                let downloads = downloads.ok_or("--request requires --downloads")?;
                if targets.is_empty() {
                    return Err("--downloads requires at least one --request".into());
                }
                let mut requests = Vec::<Request>::with_capacity(targets.len());
                for target in targets {
                    let request = Request::from_url(target, &server_name, connect.port())?;
                    if requests
                        .iter()
                        .any(|previous| request.same_destination(previous))
                    {
                        return Err("duplicate decoded download destination".into());
                    }
                    requests.push(request);
                }
                Some(ClientFiles {
                    requests,
                    downloads: downloads.into(),
                })
            };
            if resumption && files.as_ref().is_none_or(|files| files.requests.len() < 2) {
                return Err("resumption requires at least two requests".into());
            }
            let early = match flags.remove("--early").unwrap_or("reject") {
                "reject" => false,
                "replay-safe" if resumption => true,
                _ => {
                    return Err(
                        "client --early replay-safe requires file mode and --session resume".into(),
                    );
                }
            };
            if early
                && files
                    .as_ref()
                    .is_some_and(|files| files.requests.len() > 64)
            {
                return Err("early replay storage supports at most 64 requests".into());
            }
            let key_update_target = match flags.remove("--key-update").unwrap_or("none") {
                "none" => 0,
                "once" if files.is_some() && session == "single" => 1,
                _ => return Err("--key-update once requires one file-transfer connection".into()),
            };
            let connections = if session == "multi" {
                files
                    .as_ref()
                    .ok_or("multi requires file requests")?
                    .requests
                    .len()
            } else if resumption {
                2
            } else {
                1
            };
            if connections > 64 {
                return Err("connections must be 1..=64".into());
            }
            Options::Client {
                protocol,
                version,
                connect,
                server_name,
                ca,
                timeout,
                idle_timeout,
                cipher,
                resumption,
                early,
                key_update_target,
                connections,
                files,
            }
        }
        "server" => {
            if !targets.is_empty() {
                return Err("--request is client-only".into());
            }
            let listen = required(&mut flags, "--listen")?
                .parse()
                .map_err(|_| "--listen must be IP:PORT")?;
            let preferred_port = flags
                .remove("--preferred-port")
                .map(|v| v.parse::<u16>().map_err(|_| "invalid preferred port"))
                .transpose()?;
            if preferred_port.is_some_and(|p| p == 0) {
                return Err("preferred port must be nonzero".into());
            }
            let cert = required(&mut flags, "--cert")?.into();
            let key = required(&mut flags, "--key")?.into();
            let www = flags.remove("--www");
            let max_requests = flags
                .remove("--max-requests")
                .map(|value| value.parse::<usize>().map_err(|_| "invalid max requests"))
                .transpose()?;
            if max_requests.is_some_and(|n| n == 0 || n > MAX_REQUESTS) {
                return Err("max requests must be 1..=4096".into());
            }
            let files = match www {
                Some(www) => Some(ServerFiles {
                    www: www.into(),
                    max_requests,
                }),
                None if max_requests.is_none() => None,
                None => return Err("--max-requests requires --www".into()),
            };
            let early = match flags.remove("--early").unwrap_or("reject") {
                "reject" => false,
                "buffered" if resumption => true,
                _ => {
                    return Err(
                        "--early buffered requires server file mode and --session resume".into(),
                    );
                }
            };
            let connections = if session == "multi" {
                let count = required(&mut flags, "--connections")?
                    .parse::<usize>()
                    .map_err(|_| "invalid connection count")?;
                if count == 0 || count > 64 {
                    return Err("connections must be 1..=64".into());
                }
                count
            } else if resumption {
                2
            } else {
                1
            };
            let require_retry = match flags.remove("--retry").unwrap_or("off") {
                "off" => false,
                "required" if connections == 1 && !early => true,
                _ => return Err("--retry required supports one non-early connection".into()),
            };
            if preferred_port.is_some() && (connections != 1 || files.is_none() || early) {
                return Err("preferred address requires one non-early file connection".into());
            }
            Options::Server {
                protocol,
                preferred_port,
                version,
                require_retry,
                early,
                listen,
                cert,
                key,
                timeout,
                idle_timeout,
                cipher,
                resumption,
                connections,
                files,
            }
        }
        _ => return Err(USAGE.into()),
    };
    if version == hibana_quic::quic::imp::kernel::version::Version::V2
        && matches!(
            &result,
            Options::Client { early: true, .. }
                | Options::Client {
                    resumption: true,
                    ..
                }
                | Options::Server { early: true, .. }
                | Options::Server {
                    resumption: true,
                    ..
                }
                | Options::Server {
                    require_retry: true,
                    ..
                }
        )
    {
        return Err("v2 requires a fresh non-Retry connection".into());
    }
    if protocol == hibana_quic::http3::Protocol::Http3
        && matches!(
            &result,
            Options::Client {
                resumption: true,
                ..
            } | Options::Client { early: true, .. }
                | Options::Server {
                    resumption: true,
                    ..
                }
                | Options::Server { early: true, .. }
                | Options::Client {
                    connections: 2..,
                    ..
                }
                | Options::Server {
                    connections: 2..,
                    ..
                }
        )
    {
        return Err("HTTP/3 currently requires one fresh non-early file connection".into());
    }
    if let Some(flag) = flags.keys().next() {
        return Err(format!("unsupported option {flag}"));
    }
    Ok(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_owned).collect()
    }
    #[test]
    fn operation_budget_and_negotiated_idle_are_independent() {
        for base in [
            "client --connect 127.0.0.1:443 --server-name localhost --ca ca.pem",
            "server --listen 127.0.0.1:443 --cert cert.pem --key key.pem",
        ] {
            for budget in [180, 300] {
                let options = options(&args(&format!(
                    "{base} --timeout-seconds {budget} --idle-timeout-seconds 90"
                )))
                .unwrap();
                assert_eq!(options.timeout(), Duration::from_secs(budget));
                assert_eq!(options.idle_timeout(), Duration::from_secs(90));
            }
            let disabled = options(&args(&format!("{base} --idle-timeout-seconds 0"))).unwrap();
            assert_eq!(disabled.idle_timeout(), Duration::ZERO);
            for invalid in ["-1", "301", "18446744073709551616", "later"] {
                assert!(
                    options(&args(&format!("{base} --idle-timeout-seconds {invalid}"))).is_err()
                );
            }
        }
    }

    #[test]
    fn cipher_policy_is_explicit_and_unknown_values_are_rejected() {
        for (name, expected) in [
            ("auto", CipherPolicy::Default),
            ("aes128", CipherPolicy::Aes128Only),
            ("chacha20", CipherPolicy::ChaCha20Only),
        ] {
            let Options::Client {cipher,..}=options(&args(&format!("client --connect 127.0.0.1:443 --server-name localhost --ca root.pem --cipher {name}"))).unwrap() else {panic!("wrong role")};
            assert_eq!(cipher, expected);
            let Options::Server { cipher, .. } = options(&args(&format!(
                "server --listen 127.0.0.1:443 --cert cert.pem --key key.pem --cipher {name}"
            )))
            .unwrap() else {
                panic!("wrong role")
            };
            assert_eq!(cipher, expected);
        }
        assert!(options(&args("client --connect 127.0.0.1:443 --server-name localhost --ca root.pem --cipher unknown")).is_err());
    }
    #[test]
    fn multiple_requests_share_one_verified_origin_and_unique_destinations() {
        let result = options(&args("client --connect 127.0.0.1:4433 --server-name localhost --ca ca.pem --request https://localhost:4433/one --request /two --request /three --downloads output")).unwrap();
        let Options::Client {
            files: Some(files), ..
        } = result
        else {
            panic!("missing file options")
        };
        assert_eq!(files.requests.len(), 3);
        for bad in [
            "https://elsewhere:4433/one",
            "https://localhost:4434/one",
            "/../one",
            "/.hibana-private",
        ] {
            assert!(options(&args(&format!("client --connect 127.0.0.1:4433 --server-name localhost --ca ca.pem --request {bad} --downloads output"))).is_err());
        }
        assert!(options(&args("client --connect 127.0.0.1:4433 --server-name localhost --ca ca.pem --request /a --request /%61 --downloads output")).is_err());
    }
    #[test]
    fn file_modes_require_their_roots_and_reject_unrecognized_or_insecure_flags() {
        assert!(
            options(&args(
                "client --connect 127.0.0.1:4433 --server-name localhost --ca ca.pem --request /one"
            ))
            .is_err()
        );
        assert!(options(&args("client --connect 127.0.0.1:4433 --server-name localhost --ca ca.pem --downloads output")).is_err());
        assert!(
            options(&args(
                "server --listen 127.0.0.1:4433 --cert cert.pem --key key.pem --max-requests 3"
            ))
            .is_err()
        );
        assert!(options(&args("server --listen 127.0.0.1:4433 --cert cert.pem --key key.pem --www root --insecure yes")).is_err());
        assert!(options(&args("server --listen 127.0.0.1:4433 --cert cert.pem --key key.pem --www root --max-requests 3")).unwrap().application_requested());
        assert!(
            !options(&args(
                "server --listen 127.0.0.1:4433 --cert cert.pem --key key.pem"
            ))
            .unwrap()
            .application_requested()
        );
    }
    #[test]
    fn independent_connections_are_bounded_by_explicit_work() {
        let base = "client --connect 127.0.0.1:443 --server-name localhost --ca ca.pem --request /a --request /b --downloads output";
        let Options::Client {
            connections,
            resumption,
            ..
        } = options(&args(&format!("{base} --session multi"))).unwrap()
        else {
            panic!("client expected")
        };
        assert_eq!(connections, 2);
        assert!(!resumption);
        assert!(options(&args(&format!("{base} --session multi --key-update once"))).is_err());
        let server =
            "server --listen 127.0.0.1:443 --cert cert.pem --key key.pem --www www --session multi";
        for count in [1, 50, 64] {
            let Options::Server {
                connections,
                resumption,
                ..
            } = options(&args(&format!("{server} --connections {count}"))).unwrap()
            else {
                panic!("server expected")
            };
            assert_eq!(connections, count);
            assert!(!resumption);
        }
        for count in [0, 65] {
            assert!(options(&args(&format!("{server} --connections {count}"))).is_err());
        }
        assert!(options(&args(server)).is_err());
    }

    #[test]
    fn key_update_policy_is_explicit_and_bounded() {
        let base = "client --connect 127.0.0.1:443 --server-name localhost --ca ca.pem --request /a --downloads output";
        let Options::Client {
            key_update_target, ..
        } = options(&args(&format!("{base} --key-update once"))).unwrap()
        else {
            panic!("client expected")
        };
        assert_eq!(key_update_target, 1);
        let Options::Client {
            key_update_target, ..
        } = options(&args(base)).unwrap()
        else {
            panic!("client expected")
        };
        assert_eq!(key_update_target, 0);
        assert!(options(&args(&format!("{base} --key-update arbitrary"))).is_err());
    }

    #[test]
    fn client_early_requires_explicit_replay_safe_two_connection_mode() {
        let base = "client --connect 127.0.0.1:443 --server-name localhost --ca ca.pem --request /a --request /b --downloads output";
        let Options::Client { early, .. } = options(&args(&format!(
            "{base} --session resume --early replay-safe"
        )))
        .unwrap() else {
            panic!("client expected")
        };
        assert!(early);
        let Options::Client { early, .. } =
            options(&args(&format!("{base} --session resume"))).unwrap()
        else {
            panic!("client expected")
        };
        assert!(!early);
        assert!(options(&args(&format!("{base} --early replay-safe"))).is_err());
        assert!(options(&args(&format!("{base} --session resume --early buffered"))).is_err());
    }

    #[test]
    fn multiplexing_admits_many_requests_without_expanding_early_or_connection_limits() {
        let mut values = args(
            "client --connect 127.0.0.1:443 --server-name localhost --ca ca.pem --downloads output",
        );
        for index in 0..1999 {
            values.extend(["--request".into(), format!("/file-{index}")]);
        }
        let Options::Client {
            files: Some(files),
            connections,
            ..
        } = options(&values).unwrap()
        else {
            panic!("files")
        };
        assert_eq!(files.requests.len(), 1999);
        assert_eq!(connections, 1);
        let mut early = values.clone();
        early.extend(args("--session resume --early replay-safe"));
        assert!(options(&early).is_err());
        values.extend(args("--session multi"));
        assert!(options(&values).is_err());
    }

    #[test]
    fn official_early_workload_fits_the_explicit_backed_request_bound() {
        let mut values = args(
            "client --connect 127.0.0.1:443 --server-name localhost --ca ca.pem --downloads output",
        );
        for i in 0..40 {
            values.push("--request".into());
            values.push(format!("/{}{:03}", "x".repeat(247), i));
        }
        let Options::Client {
            files: Some(files), ..
        } = options(&values).unwrap()
        else {
            panic!("files");
        };
        assert_eq!(files.requests.len(), 40);
        for i in 40..=MAX_REQUESTS {
            values.push("--request".into());
            values.push(format!("/file{i}"));
        }
        assert!(options(&values).is_err());
    }
}
