mod global;
#[path = "local/client.rs"]
mod local;
use hibana::runtime::program::project;
use hibana_quic_pal::launch;
use hibana_quic::session::Protocol;
use std::time::Duration;
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        return Err("usage: client REMOTE CA.pem (DNS:localhost)".into());
    }
    let config = launch::Client {
        remote: args[0].parse().map_err(|e| format!("{e}"))?,
        server_name: "localhost".into(),
        ca: args[1].clone().into(),
        protocol: Protocol::Http3,
        timeout: Duration::from_secs(30),
    };
    launch::client(
        config,
        global::SERVER,
        &project::<{ global::CLIENT }, _>(&global::choreography()),
        local::run,
    )?;
    println!("42 squared = 1764\n7 squared = 49");
    Ok(())
}
