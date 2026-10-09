use super::{self as connection, imp::tls::TlsBuffers};
use crate::io::{Clock, DatagramSocket};
use crate::quic::application::{
    ClientRequests, StreamSink, imp::owned as storage, local::owned as application,
};
use crate::{
    crypto::directional::ApplicationKeyScope,
    entropy::Entropy,
    quic::{
        Config, Side,
        imp::{
            kernel::version::Version, publication_gate::PublicationGate, recovery::Recovery,
            tls::Transcript,
        },
    },
};
use alloc::{
    format,
    string::{String, ToString},
};
use hibana_tls::handshake::BoundedTls;
type Result<T> = core::result::Result<T, String>;
/// Connect one authenticated QUIC connection and run caller-owned stream effects.
/// The caller joins its application locals with this future on the Host reactor.
pub async fn connect(
    socket: &impl DatagramSocket,
    clock: &impl Clock,
    entropy: &mut impl Entropy,
    options: connection::Client<'_>,
    requests: &mut impl ClientRequests,
    sink: &mut impl StreamSink,
) -> Result<crate::quic::application::Report> {
    let address = options.address;
    let mut local = [0; 8];
    let mut original = [0; 8];
    let mut generation = [0; 8];
    for bytes in [&mut local, &mut original, &mut generation] {
        entropy.try_fill_bytes(bytes).map_err(|e| e.to_string())?;
    }
    let limits = storage::local_limits::<{ storage::RECEIVE_BYTES }>(
        Side::Client,
        options.stream_capacity,
        options.protocol,
    );
    let mut parameter_storage = [0; 2048];
    let parameter_len = crate::quic::imp::parameters::advertisement::Advertisement {
        version: Version::V1,
        local: &local,
        original: None,
        application_limits: Some(limits),
        retry_source: None,
        idle_timeout_ms: options.idle_timeout_ms,
        max_datagram_size: crate::quic::application::imp::owned::DATAGRAM as u64,
    }
    .encode(&mut parameter_storage)
    .map_err(|e| format!("parameters: {e:?}"))?;
    let parameters = &parameter_storage[..parameter_len];
    let mut buffers = TlsBuffers::new();
    let tls = BoundedTls::client(
        hibana_tls::handshake::ClientConfig {
            protocol: options.protocol,
            version: Version::V1,
            server_name: options.server_name,
            trust_anchors: options.trust_anchors,
            now: options.now,
            certificate_limits: hibana_tls::certificate::Limits::default(),
            transport_parameters: parameters,
        },
        buffers.storage(),
        entropy,
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
    let mut receive = super::imp::socket::Receive {
        socket,
        address,
        first: None,
    };
    let mut transmit = super::imp::socket::Transmit {
        socket,
        address,
        clock,
    };
    application::client::<{ storage::RECEIVE_BYTES }>(
        entropy,
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
