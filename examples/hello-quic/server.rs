mod global;
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
    let reactor = Reactor::<4, 8>::new().map_err(|e| e.to_string())?;
    let clock = Clock::new(&reactor, Instant::now());
    let protocol = Protocol::Quic;
    let socket = reactor
        .register_udp(
            UdpSocket::bind(args[0].parse().map_err(|e| format!("{e}"))?)
                .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
    let certificates = hibana_tls::certificate::pem::decode_certificates(
        &std::fs::read(&args[1]).map_err(|e| e.to_string())?,
    )?;
    let chain: Vec<_> = certificates.iter().map(Vec::as_slice).collect();
    let key = match hibana_tls::certificate::pem::decode_private_key(
        &hibana_tls::secret::Secret::new(std::fs::read(&args[2]).map_err(|e| e.to_string())?),
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
        certificate_chain: &chain,
        signing_key: &key,
        idle_timeout_ms: 15_000,
        stream_capacity: 8,
    };
    eprintln!(
        "listening on {}",
        socket.local_addr().map_err(|e| e.to_string())?
    );
    let program = project(&global::choreography());
    reactor
        .block_on(Box::pin(before_deadline(
            &clock,
            Instant::now() + Duration::from_secs(30),
            session::localside::owned::server(
                &socket,
                &clock,
                &mut KernelEntropy,
                config,
                global::CLIENT,
                &program,
                localside::run,
            ),
        )))
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    println!("served two requests");
    Ok(())
}

// This role's application code is next to its connection setup.
pub mod localside {
    //! The server application localside. Its Endpoint follows the shared global.
    //! QUIC/TLS and environment I/O are owned by the lower connection layers.
    use crate::global::*;
    use hibana::Endpoint;
    #[derive(Debug)]
    pub enum Error {
        Protocol(hibana::EndpointError),
        Overflow,
    }
    pub async fn run(server: &mut Endpoint<'_, SERVER>) -> Result<(), Error> {
        for _ in 0..2 {
            let number = server.recv::<Number>().await.map_err(Error::Protocol)?;
            let square = number.checked_mul(number).ok_or(Error::Overflow)?;
            server
                .send::<Square>(&square)
                .await
                .map_err(Error::Protocol)?;
        }
        Ok(())
    }
}
