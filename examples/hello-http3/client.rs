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
    if args.len() != 2 {
        return Err("usage: client REMOTE CA.pem (DNS:localhost)".into());
    }
    let reactor = Reactor::<4, 8>::new().map_err(|e| e.to_string())?;
    let clock = Clock::new(&reactor, Instant::now());
    let protocol = Protocol::Http3;
    let remote = args[0].parse().map_err(|e| format!("{e}"))?;
    let socket = reactor
        .register_udp(UdpSocket::bind_for_peer(remote).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let certificates = hibana_tls::certificate::pem::decode_certificates(
        &std::fs::read(&args[1]).map_err(|e| e.to_string())?,
    )?;
    let anchors = certificates
        .iter()
        .map(|der| {
            hibana_tls::certificate::trust_anchor_from_der(
                &hibana_tls::certificate::CertificateDer::from(der.as_slice()),
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
        stream_capacity: 8,
    };
    let program = project(&global::choreography());
    reactor
        .block_on(Box::pin(before_deadline(
            &clock,
            Instant::now() + Duration::from_secs(30),
            session::localside::owned::client(
                &socket,
                &clock,
                &mut KernelEntropy,
                config,
                global::SERVER,
                &program,
                localside::run,
            ),
        )))
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    println!("42 squared = 1764\n7 squared = 49");
    Ok(())
}

// This role's application code is next to its connection setup.
pub mod localside {
    //! The client application localside. Its Endpoint follows the shared global.
    //! QUIC/TLS and environment I/O are owned by the lower connection layers.
    use crate::global::*;
    use hibana::Endpoint;
    #[derive(Debug)]
    pub enum Error {
        Protocol(hibana::EndpointError),
        IncorrectSquare,
    }
    pub async fn run(client: &mut Endpoint<'_, CLIENT>) -> Result<(), Error> {
        for number in [42_u64, 7] {
            client
                .send::<Number>(&number)
                .await
                .map_err(Error::Protocol)?;
            let square = client.recv::<Square>().await.map_err(Error::Protocol)?;
            if square != number * number {
                return Err(Error::IncorrectSquare);
            }
        }
        Ok(())
    }
}
