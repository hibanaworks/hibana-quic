use super::host_files::{MAX_REQUESTS, Request};
use hibana_quic::bounded_tls::CipherPolicy;
use std::{collections::BTreeMap, net::SocketAddr, path::PathBuf, time::Duration};
pub const USAGE: &str = "Direct Hibana QUIC v1 / hq-interop\n\n  hq client --connect IP:PORT --server-name HOST --ca ROOTS.pem [--request /FILE ... --downloads DIR] [--timeout-seconds 120] [--cipher auto|aes128|chacha20]\n  hq server --listen IP:PORT --cert CHAIN.pem --key KEY.pem [--www DIR --max-requests N] [--timeout-seconds 120] [--cipher auto|aes128|chacha20]\n\nOne admitted connection, at most 16 file requests, explicit CA/hostname verification and real OS randomness.\nFile requests use bounded chunks and decoded-path-safe, atomic downloads.\nOmitting file options selects authenticated TLS-prefix diagnostics only; those\nreports never claim HTTP transfer, HANDSHAKE_DONE confirmation or completed close.";
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
        connect: SocketAddr,
        server_name: String,
        ca: PathBuf,
        timeout: Duration,
        cipher: CipherPolicy,
        files: Option<ClientFiles>,
    },
    Server {
        listen: SocketAddr,
        cert: PathBuf,
        key: PathBuf,
        timeout: Duration,
        cipher: CipherPolicy,
        files: Option<ServerFiles>,
    },
}
impl Options {
    pub fn timeout(&self) -> Duration {
        match self {
            Self::Client { timeout, .. } | Self::Server { timeout, .. } => *timeout,
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
                return Err("at most 16 requests are supported".into());
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
    let cipher = match flags.remove("--cipher").unwrap_or("auto") {
        "auto" => CipherPolicy::Default,
        "aes128" => CipherPolicy::Aes128Only,
        "chacha20" => CipherPolicy::ChaCha20Only,
        _ => return Err("--cipher must be auto, aes128 or chacha20".into()),
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
            Options::Client {
                connect,
                server_name,
                ca,
                timeout,
                cipher,
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
            let cert = required(&mut flags, "--cert")?.into();
            let key = required(&mut flags, "--key")?.into();
            let www = flags.remove("--www");
            let max_requests = flags
                .remove("--max-requests")
                .map(|value| value.parse::<usize>().map_err(|_| "invalid max requests"))
                .transpose()?;
            if max_requests.is_some_and(|n| n == 0 || n > MAX_REQUESTS) {
                return Err("max requests must be 1..=16".into());
            }
            let files = match www {
                Some(www) => Some(ServerFiles {
                    www: www.into(),
                    max_requests,
                }),
                None if max_requests.is_none() => None,
                None => return Err("--max-requests requires --www".into()),
            };
            Options::Server {
                listen,
                cert,
                key,
                timeout,
                cipher,
                files,
            }
        }
        _ => return Err(USAGE.into()),
    };
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
}
