use super::{Client, Result, Server};
use crate::{
    io::{HostClock, HostReactor},
    pem,
};
use hibana::{Endpoint, runtime::program::RoleProgram};
use hibana_quic::session::local::network as connection;
pub async fn client<const ROLE: u8, const S: usize, const T: usize, E: core::fmt::Debug>(
    reactor: &HostReactor<S, T>,
    clock: &HostClock<'_, S, T>,
    options: Client,
    peer: u8,
    program: &RoleProgram<ROLE>,
    application: impl for<'a, 'r> AsyncFnOnce(&'a mut Endpoint<'r, ROLE>) -> core::result::Result<(), E>,
) -> Result<()> {
    let route = std::net::UdpSocket::bind(if options.remote.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .map_err(|e| e.to_string())?;
    route.connect(options.remote).map_err(|e| e.to_string())?;
    let mut bind = route.local_addr().map_err(|e| e.to_string())?;
    bind.set_port(0);
    drop(route);
    let socket = reactor
        .register_udp(std::net::UdpSocket::bind(bind).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let address = hibana_quic::quic::path::Address {
        local: socket.local_addr().map_err(|e| e.to_string())?,
        remote: options.remote,
    };
    let now = hibana_tls::certificate::UnixTime::since_unix_epoch(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?,
    );
    let certificates = pem::certificates(&options.ca)?;
    let anchors = certificates
        .iter()
        .map(|der| {
            hibana_tls::certificate::trust_anchor_from_der(
                &hibana_tls::certificate::CertificateDer::from(der.as_slice()),
            )
        })
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| format!("trust anchor: {e:?}"))?;
    hibana_quic::session::local::owned::client(
        &socket,
        clock,
        &mut crate::entropy::KernelEntropy,
        connection::Client {
            address,
            now,
            server_name: &options.server_name,
            trust_anchors: &anchors,
            protocol: options.protocol.negotiated(),
            idle_timeout_ms: u64::try_from(options.timeout.as_millis() / 2)
                .map_err(|_| "timeout overflow")?,
            stream_capacity: 8,
        },
        options.protocol,
        peer,
        program,
        application,
    )
    .await
}
pub async fn server<const ROLE: u8, const S: usize, const T: usize, E: core::fmt::Debug>(
    reactor: &HostReactor<S, T>,
    clock: &HostClock<'_, S, T>,
    options: Server,
    peer: u8,
    program: &RoleProgram<ROLE>,
    application: impl for<'a, 'r> AsyncFnOnce(&'a mut Endpoint<'r, ROLE>) -> core::result::Result<(), E>,
) -> Result<()> {
    let certificates = pem::certificates(&options.certificate)?;
    let chain: Vec<&[u8]> = certificates.iter().map(Vec::as_slice).collect();
    let key = match pem::private_key(&options.key)? {
        pem::PrivateKeyDer::Pkcs8(bytes) => {
            hibana_tls::handshake::SigningKey::from_pkcs8_der(&bytes)
        }
        pem::PrivateKeyDer::Sec1(bytes) => hibana_tls::handshake::SigningKey::from_sec1_der(&bytes),
    }
    .map_err(|e| format!("signing key: {e:?}"))?;
    let socket = reactor
        .register_udp(std::net::UdpSocket::bind(options.listen).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    eprintln!(
        "listening on {}",
        socket.local_addr().map_err(|e| e.to_string())?
    );
    hibana_quic::session::local::owned::server(
        &socket,
        clock,
        &mut crate::entropy::KernelEntropy,
        connection::Server {
            certificate_chain: &chain,
            signing_key: &key,
            protocol: options.protocol.negotiated(),
            idle_timeout_ms: u64::try_from(options.timeout.as_millis() / 2)
                .map_err(|_| "timeout overflow")?,
            stream_capacity: 8,
        },
        options.protocol,
        peer,
        program,
        application,
    )
    .await
}
