#[path = "../unix/file.rs"]
mod native_files;
use hibana_quic::session::{self, Protocol};
use hibana_quic_pal::unix::{
    Instant, UdpSocket,
    clock::{Clock, before_deadline},
    entropy::KernelEntropy,
    reactor::Reactor,
};
use native_files::FileStorage;
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
        return Err("usage: client REMOTE CA.pem OUTPUT (DNS:localhost)".into());
    }
    let reactor = {
        static WAKE: hibana_quic_pal::unix::reactor::WakeStorage =
            hibana_quic_pal::unix::reactor::WakeStorage::new();
        Reactor::<4, 8>::new(&WAKE)
    }
    .map_err(|e| e.to_string())?;
    let clock = Clock::new(&reactor, Instant::now());
    let protocol = Protocol::Hq;
    let remote = args[0].parse().map_err(|e| format!("{e}"))?;
    let socket = reactor
        .register_udp(UdpSocket::bind_for_peer(remote).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let mut certificate_bytes = [0; 16384];
    let mut certificates: [&[u8]; 16] = [&[]; 16];
    let certificate_count = hibana_tls::certificate::pem::decode_certificates(
        &std::fs::read(&args[1]).map_err(|e| e.to_string())?,
        &mut certificate_bytes,
        &mut certificates,
    )?;
    let certificates = &certificates[..certificate_count];
    let anchors = certificates
        .iter()
        .map(|der| {
            hibana_tls::certificate::trust_anchor_from_der(
                &hibana_tls::certificate::CertificateDer::from(*der),
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{e:?}"))?;
    let config = session::Client {
        address: hibana_quic::io::Address {
            local: socket.local_addr().map_err(|e| e.to_string())?,
            remote,
        },
        now: hibana_tls::certificate::UnixTime::since_unix_epoch(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| e.to_string())?,
        ),
        server_name: "localhost",
        trust_anchors: &anchors,
        protocol,
        idle_timeout_ms: 15_000,
    };
    let output = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&args[2])
        .map_err(|e| e.to_string())?;
    let store = FileStorage(&output);
    let mut response = hibana_quic::hq::Response::new(&store).map_err(|e| format!("{e:?}"))?;
    let mut requests = hibana_quic::hq::Requests::new(&["/hello"]);
    let mut memory = const { session::ConnectionMemory::<1>::new() };
    let mut entropy = KernelEntropy;
    let connection = core::pin::pin!(config.transfer(
        &mut memory,
        session::Environment {
            socket: &socket,
            clock: &clock,
            entropy: &mut entropy
        },
        &mut requests,
        &mut response,
    ));
    let report = reactor
        .block_on(before_deadline(
            &clock,
            Instant::now() + Duration::from_secs(30),
            connection,
        ))
        .map_err(|e| e.to_string())?
        .map_err(|e| format!("{e:?}"))?;
    if report.termination != hibana_quic::quic::application::Termination::Closed
        || !report.close_completed
    {
        return Err("connection did not complete its close".into());
    }
    println!("received response");
    Ok(())
}
