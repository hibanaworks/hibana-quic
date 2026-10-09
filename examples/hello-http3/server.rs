mod global;
#[path = "local/server.rs"]
mod local;
use hibana::runtime::program::project;
use hibana_quic_host::session;
use std::time::Duration;
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        return Err("usage: server LISTEN CERT.pem KEY.pem".into());
    }
    let config = session::Server {
        listen: args[0].parse().map_err(|e| format!("{e}"))?,
        certificate: args[1].clone().into(),
        key: args[2].clone().into(),
        protocol: session::Protocol::Http3,
        timeout: Duration::from_secs(30),
    };
    session::server(
        config,
        global::CLIENT,
        &project::<{ global::SERVER }, _>(&global::choreography()),
        local::run,
    )
}
