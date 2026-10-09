use super::{self as connection, imp::tls::TlsBuffers};
use crate::io::{Clock, DatagramSocket};
use crate::quic::application::{
    ServerHandler, StreamSink, imp::owned as storage, local::owned as application,
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
    vec,
};
use hibana_tls::handshake::BoundedTls;
type Result<T> = core::result::Result<T, String>;
/// Accept one integrity-checked QUIC v1 Initial on a caller-owned listener.
/// Unknown versions and malformed input are ignored; the caller supplies a deadline.
pub async fn accept(
    socket: &impl DatagramSocket,
    clock: &impl Clock,
    entropy: &mut impl Entropy,
    options: connection::Server<'_>,
    handler: &mut impl ServerHandler,
    input: &mut impl StreamSink,
) -> Result<crate::quic::application::Report> {
    use crate::quic::imp::kernel::packet::{Header, LongType, PacketIter};
    let mut first = vec![0; connection::DATAGRAM];
    let (metadata, original, peer) = loop {
        crate::runtime::yield_now().await;
        let metadata = socket
            .receive_from(&mut first)
            .await
            .map_err(|e| format!("receive: {e:?}"))?;
        if metadata.len > first.len() {
            return Err("receive length exceeds storage".into());
        }
        if metadata.len < 1200 {
            continue;
        }
        let packet = PacketIter::new(&first[..metadata.len], 8, 8)
            .ok()
            .and_then(|mut packets| packets.next())
            .and_then(core::result::Result::ok);
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
            && crate::quic::retry::imp::admission::initial_integrity(
                &packet,
                &mut [0; connection::DATAGRAM],
            )
            .is_some()
        {
            break (metadata, destination_id.to_vec(), source_id.to_vec());
        }
    };
    let address = metadata.path.ok_or("Initial has no path")?;
    let mut local = [0; 8];
    let mut generation = [0; 8];
    for bytes in [&mut local, &mut generation] {
        entropy.try_fill_bytes(bytes).map_err(|e| e.to_string())?;
    }
    let limits = storage::local_limits::<{ storage::RECEIVE_BYTES }>(
        Side::Server,
        options.stream_capacity,
        options.protocol,
    );
    let mut parameter_storage = [0; 2048];
    let parameter_len = crate::quic::imp::parameters::advertisement::Advertisement {
        version: Version::V1,
        local: &local,
        original: Some(&original),
        application_limits: Some(limits),
        retry_source: None,
        idle_timeout_ms: options.idle_timeout_ms,
        max_datagram_size: crate::quic::application::imp::owned::DATAGRAM as u64,
    }
    .encode(&mut parameter_storage)
    .map_err(|e| format!("parameters: {e:?}"))?;
    let parameters = &parameter_storage[..parameter_len];
    let mut buffers = TlsBuffers::new();
    let tls = BoundedTls::server(
        hibana_tls::handshake::ServerConfig {
            protocol: options.protocol,
            version: Version::V1,
            certificate_chain: options.certificate_chain,
            signing_key: options.signing_key,
            transport_parameters: parameters,
        },
        buffers.storage(),
        entropy,
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
    let mut receive = super::imp::socket::Receive {
        socket,
        address,
        first: Some((&first[..metadata.len], metadata.ecn)),
    };
    let mut transmit = super::imp::socket::Transmit {
        socket,
        address,
        clock,
    };
    application::server(
        entropy,
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
