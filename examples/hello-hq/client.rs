// Project the complete TLS/QUIC/application graph in this binary.
use hibana_quic::session::{self, Protocol};
use hibana_quic_pal::unix::files::File;
use hibana_quic_pal::unix::{UdpSocket, reactor::Reactor};
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
    let protocol = Protocol::Http09;
    let remote = args[0].parse().map_err(|e| format!("{e}"))?;
    let socket = UdpSocket::bind_for_peer(remote).map_err(|e| e.to_string())?;
    let mut certificate_bytes = [0; 16384];
    let mut certificates: [&[u8]; 16] = [&[]; 16];
    let certificate_file = File::open(&args[1]).map_err(|e| e.to_string())?;
    let mut certificate_pem = [0; 32768];
    let certificate_len = usize::try_from(certificate_file.len().map_err(|e| e.to_string())?)
        .map_err(|_| "certificate PEM exceeds storage")?;
    let certificate_pem = certificate_pem
        .get_mut(..certificate_len)
        .ok_or("certificate PEM exceeds storage")?;
    certificate_file
        .read_exact_at(certificate_pem, 0)
        .map_err(|e| e.to_string())?;
    let certificate_count = hibana_tls::certificate::pem::decode_certificates(
        certificate_pem,
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
    let config = session::ClientConfig {
        address: hibana_quic::io::Address {
            local: socket.local_addr().map_err(|e| e.to_string())?,
            remote,
        },
        now: hibana_tls::certificate::UnixTime::since_unix_epoch(
            hibana_quic_pal::unix::clock::unix_time().map_err(|e| e.to_string())?,
        ),
        server_name: "localhost",
        trust_anchors: &anchors,
        protocol,
        idle_timeout_ms: 15_000,
    };
    let output = File::create_new(&args[2]).map_err(|e| e.to_string())?;
    let mut response = hibana_quic::hq::Response::new(&output).map_err(|e| format!("{e:?}"))?;
    let mut requests = hibana_quic::hq::Requests::new(&["/hello"]);
    let mut memory = const { session::ConnectionMemory::<1>::new() };
    let report = reactor
        .run_udp(
            socket,
            Duration::from_secs(30),
            async |socket, clock, entropy| {
                config
                    .transfer(
                        &mut memory,
                        session::Environment {
                            socket,
                            clock,
                            entropy,
                        },
                        &mut requests,
                        &mut response,
                    )
                    .await
            },
        )
        .map_err(|e| format!("{e:?}"))?;
    if report.termination != hibana_quic::quic::application::Termination::Closed
        || !report.close_completed
    {
        return Err("connection did not complete its close".into());
    }
    println!("received response");
    Ok(())
}
