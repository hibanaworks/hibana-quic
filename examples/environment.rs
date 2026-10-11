//! Native launch configuration, shared by every application example.
//! This is the one place to change credentials, socket, clock, entropy and
//! storage capacities. Protocol execution remains in hibana-quic.
use hibana_quic::session::{self, Protocol};
use hibana_quic_pal::unix::{
    UdpSocket,
    clock::Clock,
    entropy::KernelEntropy,
    files::File,
    reactor::{AsyncUdp, Reactor},
};
use std::time::Duration;
type Client<'a, 'cfg, 'io> =
    session::Client<'a, 'cfg, AsyncUdp<'io, 4, 8>, Clock<'io>, KernelEntropy, 8, 262144, 65536>;
type Server<'a, 'cfg, 'io> =
    session::Server<'a, 'cfg, AsyncUdp<'io, 4, 8>, Clock<'io>, KernelEntropy, 8, 262144, 65536>;

#[allow(dead_code)]
pub fn client<E: core::fmt::Debug>(
    protocol: Protocol,
    application: impl for<'a, 'cfg, 'io> AsyncFnOnce(Client<'a, 'cfg, 'io>) -> Result<(), E>,
) -> Result<(), String> {
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

    let mut memory = const { session::Memory::<8>::new() };
    reactor
        .run_udp(
            socket,
            Duration::from_secs(30),
            async |socket, clock, entropy| {
                let endpoint = config.bind(
                    &mut memory,
                    session::Environment {
                        socket,
                        clock,
                        entropy,
                    },
                    1,
                );
                application(endpoint).await
            },
        )
        .map_err(|error| format!("{error:?}"))
}

#[allow(dead_code)]
pub fn server<E: core::fmt::Debug>(
    protocol: Protocol,
    application: impl for<'a, 'cfg, 'io> AsyncFnOnce(Server<'a, 'cfg, 'io>) -> Result<(), E>,
) -> Result<(), String> {
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

    let mut memory = const { session::Memory::<8>::new() };
    reactor
        .run_udp(
            socket,
            Duration::from_secs(30),
            async |socket, clock, entropy| {
                let endpoint = config.bind(
                    &mut memory,
                    session::Environment {
                        socket,
                        clock,
                        entropy,
                    },
                    0,
                );
                application(endpoint).await
            },
        )
        .map_err(|error| format!("{error:?}"))
}
