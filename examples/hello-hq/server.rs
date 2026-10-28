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
    if args.len() != 4 {
        return Err("usage: server LISTEN CERT.pem KEY.pem CONTENT".into());
    }
    let reactor = {
        static WAKE: hibana_quic_pal::unix::reactor::WakeStorage =
            hibana_quic_pal::unix::reactor::WakeStorage::new();
        Reactor::<4, 8>::new(&WAKE)
    }
    .map_err(|e| e.to_string())?;
    let protocol = Protocol::Http09;
    let socket =
        UdpSocket::bind(args[0].parse().map_err(|e| format!("{e}"))?).map_err(|e| e.to_string())?;
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
    let chain = certificates;
    let mut key_bytes = [0; 4096];
    let mut key_pem = hibana_tls::secret::Secret::new([0; 16384]);
    let file = File::open(&args[2]).map_err(|e| e.to_string())?;
    let key_len = usize::try_from(file.len().map_err(|e| e.to_string())?)
        .map_err(|_| "key PEM exceeds storage")?;
    let key_input = key_pem
        .get_mut(..key_len)
        .ok_or("key PEM exceeds storage")?;
    file.read_exact_at(key_input, 0)
        .map_err(|e| e.to_string())?;
    let key = match hibana_tls::certificate::pem::decode_private_key(
        &key_pem[..key_len],
        &mut key_bytes,
    )? {
        hibana_tls::certificate::pem::PrivateKeyDer::Pkcs8(bytes) => {
            hibana_tls::handshake::SigningKey::from_pkcs8_der(&bytes)
        }
        hibana_tls::certificate::pem::PrivateKeyDer::Sec1(bytes) => {
            hibana_tls::handshake::SigningKey::from_sec1_der(&bytes)
        }
    }
    .map_err(|e| format!("{e:?}"))?;
    let config = session::ServerConfig {
        protocol,
        certificate_chain: chain,
        signing_key: &key,
        idle_timeout_ms: 15_000,
    };
    eprintln!(
        "listening on {}",
        socket.local_addr().map_err(|e| e.to_string())?
    );
    let content = File::open(&args[3]).map_err(|e| e.to_string())?;
    let mut service = hibana_quic::hq::Service::new(|path: &str| {
        if path == "/hello" {
            Ok(&content)
        } else {
            Err(())
        }
    });
    let mut memory = const { session::ConnectionMemory::<1>::new() };
    let report = reactor
        .run_udp(
            socket,
            Duration::from_secs(30),
            async |socket, clock, entropy| {
                config
                    .serve(
                        &mut memory,
                        session::Environment {
                            socket,
                            clock,
                            entropy,
                        },
                        &mut service,
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
    println!("served response");
    Ok(())
}
