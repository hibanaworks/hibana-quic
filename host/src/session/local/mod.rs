use super::{Client, Result, Server};
use crate::{
    connection,
    io::{HostClock, HostReactor},
    pem,
};
use hibana::{
    Endpoint,
    runtime::{ids::SessionId, program::RoleProgram},
};
use hibana_quic::session::{self, local::stream};
pub async fn client<const ROLE: u8, const S: usize, const T: usize, E: core::fmt::Debug>(
    reactor: &HostReactor<S, T>,
    clock: &HostClock<'_, S, T>,
    options: Client,
    peer: u8,
    program: &RoleProgram<ROLE>,
    application: impl for<'a, 'r> AsyncFnOnce(&'a mut Endpoint<'r, ROLE>) -> core::result::Result<(), E>,
) -> Result<()> {
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
    let mut storage = session::Storage::new();
    let mut slab = vec![0; 65536];
    let protocol = options.protocol.negotiated();
    let idle_timeout_ms =
        u64::try_from(options.timeout.as_millis() / 2).map_err(|_| "timeout overflow")?;
    let network = async |bridge: &session::local::StreamPeer<'_>| {
        let mut requests = stream::Requests::new(bridge, options.protocol, &options.server_name)
            .map_err(|_| "request prefix".to_string())?;
        let mut responses = stream::Input::new(bridge, options.protocol, false);
        let report = connection::local::connect(
            reactor,
            clock,
            connection::Client {
                remote: options.remote,
                server_name: &options.server_name,
                trust_anchors: &anchors,
                protocol,
                idle_timeout_ms,
                stream_capacity: 8,
            },
            &mut requests,
            &mut responses,
        )
        .await?;
        if report.termination != hibana_quic::quic::application::Termination::Closed
            || !report.close_completed
        {
            return Err("session did not close normally".into());
        }
        Ok(())
    };
    session::local::run(
        &mut storage,
        &mut slab,
        SessionId::new(1),
        peer,
        program,
        async |endpoint: &mut Endpoint<'_, ROLE>| {
            application(endpoint)
                .await
                .map_err(|e| format!("application: {e:?}"))
        },
        network,
    )
    .await
    .map_err(|e| format!("{e:?}"))
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
    let mut storage = session::Storage::new();
    let mut slab = vec![0; 65536];
    let protocol = options.protocol.negotiated();
    let idle_timeout_ms =
        u64::try_from(options.timeout.as_millis() / 2).map_err(|_| "timeout overflow")?;
    let network = async |bridge: &session::local::StreamPeer<'_>| {
        let mut service = stream::Service {
            peer: bridge,
            protocol: options.protocol,
        };
        let mut input = stream::Input::new(bridge, options.protocol, true);
        let report = connection::local::accept(
            &socket,
            clock,
            connection::Server {
                protocol,
                certificate_chain: &chain,
                signing_key: &key,
                idle_timeout_ms,
                stream_capacity: 8,
            },
            &mut service,
            &mut input,
        )
        .await?;
        if report.termination != hibana_quic::quic::application::Termination::Closed
            || !report.close_completed
        {
            return Err("session did not close normally".into());
        }
        Ok(())
    };
    session::local::run(
        &mut storage,
        &mut slab,
        SessionId::new(1),
        peer,
        program,
        async |endpoint: &mut Endpoint<'_, ROLE>| {
            application(endpoint)
                .await
                .map_err(|e| format!("application: {e:?}"))
        },
        network,
    )
    .await
    .map_err(|e| format!("{e:?}"))
}
