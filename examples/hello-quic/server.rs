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
    if args.len() != 3 {
        return Err("usage: server LISTEN CERT.pem KEY.pem".into());
    }
    let reactor = {
        static WAKE: hibana_quic_pal::unix::reactor::WakeStorage =
            hibana_quic_pal::unix::reactor::WakeStorage::new();
        Reactor::<4, 8>::new(&WAKE)
    }
    .map_err(|e| e.to_string())?;
    let clock = Clock::new(&reactor, Instant::now());
    let protocol = Protocol::Quic;
    let socket = reactor
        .register_udp(
            UdpSocket::bind(args[0].parse().map_err(|e| format!("{e}"))?)
                .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
    let mut certificate_bytes = [0; 16384];
    let mut certificates: [&[u8]; 16] = [&[]; 16];
    let certificate_count = hibana_tls::certificate::pem::decode_certificates(
        &std::fs::read(&args[1]).map_err(|e| e.to_string())?,
        &mut certificate_bytes,
        &mut certificates,
    )?;
    let certificates = &certificates[..certificate_count];
    let chain = certificates;
    let mut key_bytes = [0; 4096];
    let mut key_pem = hibana_tls::secret::Secret::new([0; 16384]);
    use std::io::Read;
    let mut file = std::fs::File::open(&args[2]).map_err(|e| e.to_string())?;
    let mut key_len = 0;
    loop {
        if key_len == key_pem.len() {
            if file.read(&mut [0; 1]).map_err(|e| e.to_string())? != 0 {
                return Err("key PEM exceeds storage".into());
            }
            break;
        }
        let count = file
            .read(&mut key_pem[key_len..])
            .map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        key_len += count;
    }
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
    let config = session::Server {
        protocol,
        certificate_chain: chain,
        signing_key: &key,
        idle_timeout_ms: 15_000,
        stream_capacity: 8,
    };
    eprintln!(
        "listening on {}",
        socket.local_addr().map_err(|e| e.to_string())?
    );
    let program = project::<{ global::SERVER }>(&global::choreography());
    let mut streams = [const { hibana_quic::quic::streams::StreamSlot::EMPTY }; 8];
    let mut connection_slab = [0; 256 * 1024];
    let mut application_slab = [0; 65536];
    let mut entropy = KernelEntropy;
    let connection = core::pin::pin!(session::localside::owned::server(
        &mut streams,
        &mut connection_slab,
        &mut application_slab,
        &socket,
        &clock,
        &mut entropy,
        config,
        global::CLIENT,
        &program,
        async |server| -> Result<(), ApplicationError> {
            for _ in 0..2 {
                let number = server
                    .recv::<Number>()
                    .await
                    .map_err(ApplicationError::Protocol)?;
                let square = number
                    .checked_mul(number)
                    .ok_or(ApplicationError::Overflow)?;
                server
                    .send::<Square>(&square)
                    .await
                    .map_err(ApplicationError::Protocol)?;
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
    println!("served two requests");
    Ok(())
}

#[derive(Debug)]
pub enum ApplicationError {
    Protocol(hibana::EndpointError),
    Overflow,
}
