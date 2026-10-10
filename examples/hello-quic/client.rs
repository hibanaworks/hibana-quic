mod global;
use global::{Number, Square};
use hibana::runtime::program::project;
use hibana_quic::session::{self, Protocol};
use hibana_quic_pal::unix::{
    Instant, UdpSocket,
    clock::{Clock, before_deadline},
    entropy::KernelEntropy,
    reactor::Reactor,
};
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
    let reactor = {
        static WAKE: hibana_quic_pal::unix::reactor::WakeStorage =
            hibana_quic_pal::unix::reactor::WakeStorage::new();
        Reactor::<4, 8>::new(&WAKE)
    }
    .map_err(|e| e.to_string())?;
    let clock = Clock::new(&reactor, Instant::now());
    let protocol = Protocol::Quic;
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
    let program = project::<{ global::CLIENT }>(&global::choreography());
    let mut memory = const { session::Memory::<8>::new() };
    let mut entropy = KernelEntropy;
    let connection = core::pin::pin!(config.run(
        &mut memory,
        session::Environment {
            socket: &socket,
            clock: &clock,
            entropy: &mut entropy
        },
        global::SERVER,
        &program,
        async |client| -> Result<(), ApplicationError> {
            for number in [42_u64, 7] {
                client
                    .send::<Number>(&number)
                    .await
                    .map_err(ApplicationError::Protocol)?;
                let square = client
                    .recv::<Square>()
                    .await
                    .map_err(ApplicationError::Protocol)?;
                if square != number * number {
                    return Err(ApplicationError::IncorrectSquare);
                }
            }
            Ok(())
        },
    ));
    reactor
        .block_on(before_deadline(
            &clock,
            Instant::now() + Duration::from_secs(30),
            connection,
        ))
        .map_err(|e| e.to_string())?
        .map_err(|e| format!("{e:?}"))?;
    println!("42 squared = 1764\n7 squared = 49");
    Ok(())
}

#[derive(Debug)]
pub enum ApplicationError {
    Protocol(hibana::EndpointError),
    IncorrectSquare,
}
