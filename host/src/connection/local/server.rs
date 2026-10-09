use super::super::imp::{parameters::parameters, tls::TlsBuffers};
use crate::{
    application, connection,
    entropy::KernelEntropy,
    io::{HostClock, HostSocket, Receive, Statistics, Transmit},
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
type Result<T> = std::result::Result<T, String>;
/// Accept one integrity-checked QUIC v1 Initial on a caller-owned listener.
/// Unknown versions and malformed input are ignored; the caller supplies a deadline.
pub async fn accept<const S: usize, const T: usize>(
    socket: &HostSocket<'_, S, T>,
    clock: &HostClock<'_, S, T>,
    options: connection::Server<'_>,
    handler: &mut impl application::ServerHandler,
    input: &mut impl application::StreamSink,
) -> Result<hibana_quic::quic::application::Report> {
    use hibana_quic::quic::imp::kernel::packet::{Header, LongType, PacketIter};
    let mut first = vec![0; connection::DATAGRAM];
    let (metadata, original, peer) = loop {
        hibana_quic::runtime::yield_now().await;
        let metadata = match socket.recv_from(&mut first).await {
            Ok(value) => value,
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => continue,
            Err(e) => return Err(e.to_string()),
        };
        if metadata.len < 1200 {
            continue;
        }
        let packet = PacketIter::new(&first[..metadata.len], 8, 8)
            .ok()
            .and_then(|mut packets| packets.next())
            .and_then(std::result::Result::ok);
        if let Some(packet) = packet
            && let Header::Long {
                kind: LongType::Initial,
                version,
                destination_id,
                source_id,
                token,
                ..
            } = packet.header
            && version == Version::V1
            && destination_id.len() >= 8
            && token.is_empty()
            && crate::retry::imp::initial_integrity(&packet).is_some()
        {
            break (metadata, destination_id.to_vec(), source_id.to_vec());
        }
    };
    let address = Address {
        local: metadata.local,
        remote: metadata.source,
    };
    let mut local = [0; 8];
    let mut generation = [0; 8];
    for bytes in [&mut local, &mut generation] {
        KernelEntropy
            .try_fill_bytes(bytes)
            .map_err(|e| e.to_string())?;
    }
    let limits = storage::local_limits::<{ storage::RECEIVE_BYTES }>(
        Side::Server,
        options.stream_capacity,
        options.protocol,
    );
    let parameters = parameters(
        Version::V1,
        &local,
        Some(&original),
        Some(limits),
        None,
        options.idle_timeout_ms,
    )?;
    let mut buffers = TlsBuffers::new();
    let tls = BoundedTls::server(
        hibana_tls::handshake::ServerConfig {
            protocol: options.protocol,
            version: Version::V1,
            certificate_chain: options.certificate_chain,
            signing_key: options.signing_key,
            transport_parameters: &parameters,
        },
        buffers.storage(),
        &mut KernelEntropy,
    )
    .map_err(|e| format!("server TLS: {e:?}"))?;
    let config = Config {
        local_preferred: None,
        initial_path: Some(address),
        version: Version::V1,
        side: Side::Server,
        local_connection_id: &local,
        original_destination_id: &original,
        retry_source_id: None,
        initial_token: &[],
        peer_connection_id: &peer,
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
        socket,
        address,
        first: Some((&first[..metadata.len], metadata.ecn)),
        clock,
        statistics: &statistics,
    };
    let mut transmit = Transmit {
        alternate: None,
        socket,
        address,
        clock,
        statistics: &statistics,
    };
    application::server::<S, T>(
        &mut source,
        config,
        &mut receive,
        &mut transmit,
        clock,
        &mut issuer,
        stop,
        &mut book,
        application::ServerProfile {
            generation,
            protocol: options.protocol,
            stream_capacity: options.stream_capacity,
            server_token: None,
            idle_timeout_ms: options.idle_timeout_ms,
        },
        handler,
        Some(input),
        None,
    )
    .await
}
