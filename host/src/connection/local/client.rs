use super::super::imp::{parameters::parameters, tls::TlsBuffers};
use crate::{
    application, connection,
    entropy::KernelEntropy,
    io::{HostClock, HostReactor, Receive, Statistics, Transmit},
    storage,
};
use hibana_quic::{
    crypto::directional::ApplicationKeyScope,
    entropy::Entropy,
    quic::{
        Config, Side,
        imp::{
            kernel::version::Version, publication_gate::PublicationGate, recovery::Recovery,
            tls::Transcript,
        },
        path::Address,
    },
};
use hibana_tls::handshake::BoundedTls;
use std::net::UdpSocket;
type Result<T> = std::result::Result<T, String>;
/// Connect one authenticated QUIC connection and run caller-owned stream effects.
/// The caller joins its application locals with this future on the Host reactor.
pub async fn connect<const S: usize, const T: usize>(
    reactor: &HostReactor<S, T>,
    clock: &HostClock<'_, S, T>,
    options: connection::Client<'_>,
    requests: &mut impl application::ClientRequests,
    sink: &mut impl application::StreamSink,
) -> Result<hibana_quic::quic::application::Report> {
    let route = UdpSocket::bind(if options.remote.is_ipv4() {
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
        .register_udp(UdpSocket::bind(bind).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let address = Address {
        local: socket.local_addr().map_err(|e| e.to_string())?,
        remote: options.remote,
    };
    let mut local = [0; 8];
    let mut original = [0; 8];
    let mut generation = [0; 8];
    for bytes in [&mut local, &mut original, &mut generation] {
        KernelEntropy
            .try_fill_bytes(bytes)
            .map_err(|e| e.to_string())?;
    }
    let limits = storage::local_limits::<{ storage::RECEIVE_BYTES }>(
        Side::Client,
        options.stream_capacity,
        options.protocol,
    );
    let parameters = parameters(
        Version::V1,
        &local,
        None,
        Some(limits),
        None,
        options.idle_timeout_ms,
    )?;
    let mut buffers = TlsBuffers::new();
    let tls = BoundedTls::client(
        hibana_tls::handshake::ClientConfig {
            protocol: options.protocol,
            version: Version::V1,
            server_name: options.server_name,
            trust_anchors: options.trust_anchors,
            now: hibana_tls::certificate::UnixTime::since_unix_epoch(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|e| e.to_string())?,
            ),
            certificate_limits: hibana_tls::certificate::Limits::default(),
            transport_parameters: &parameters,
        },
        buffers.storage(),
        &mut KernelEntropy,
    )
    .map_err(|e| format!("client TLS: {e:?}"))?;
    let config = Config {
        local_preferred: None,
        initial_path: Some(address),
        version: Version::V1,
        side: Side::Client,
        local_connection_id: &local,
        original_destination_id: &original,
        retry_source_id: None,
        initial_token: &[],
        peer_connection_id: &original,
    };
    let generation = u64::from_be_bytes(generation);
    let mut scope = ApplicationKeyScope::new(generation);
    let mut identity = scope.claim().map_err(|e| format!("scope: {e:?}"))?;
    let recovery = identity
        .take_recovery()
        .map_err(|e| format!("recovery: {e:?}"))?;
    let mut gate = PublicationGate::new(
        identity
            .take_publication_gate()
            .map_err(|e| format!("publication: {e:?}"))?,
    );
    let (mut issuer, stop) = gate.split().map_err(|e| format!("publication: {e:?}"))?;
    let mut source = Transcript::new(
        tls.into_key_source(identity)
            .map_err(|e| format!("TLS source: {e:?}"))?,
    );
    let mut book = Recovery::<{ connection::DATAGRAM }>::new(
        recovery,
        config.side,
        333_000,
        connection::DATAGRAM as u64,
        3,
    )
    .map_err(|e| format!("recovery: {e:?}"))?;
    let statistics = Statistics::default();
    let mut receive = Receive {
        alternate: None,
        routed: None,
        socket: &socket,
        address,
        first: None,
        clock,
        statistics: &statistics,
    };
    let mut transmit = Transmit {
        alternate: None,
        socket: &socket,
        address,
        clock,
        statistics: &statistics,
    };
    application::client::<{ storage::RECEIVE_BYTES }, S, T>(
        &mut source,
        config,
        &mut receive,
        &mut transmit,
        clock,
        &mut issuer,
        stop,
        &mut book,
        application::ClientProfile {
            generation,
            protocol: options.protocol,
            stream_capacity: options.stream_capacity,
            early_request_capacity: 0,
            key_update_target: 0,
            idle_timeout_ms: options.idle_timeout_ms,
        },
        requests,
        sink,
    )
    .await
}
