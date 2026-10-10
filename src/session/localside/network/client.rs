use crate::io::{Clock, DatagramSocket};
use crate::quic::application::Error;
use crate::quic::application::{
    ClientRequests, StreamSink, imp::owned as storage, localside::owned as application,
};
use crate::session::{self as connection, imp::tls::TlsBuffers};
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
use hibana_tls::handshake::BoundedTls;
type Result<T> = core::result::Result<T, Error>;
/// Connect one authenticated QUIC connection and run caller-owned stream effects.
/// The caller joins its application locals with this future on the Host reactor.
#[allow(clippy::too_many_arguments)]
pub async fn connect(
    streams: &mut [crate::quic::streams::StreamSlot<{ storage::RECEIVE_BYTES }>],
    slab: &mut [u8],
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
        entropy.try_fill_bytes(bytes).map_err(|_| Error::Entropy)?;
    }
    let limits = storage::local_limits::<{ storage::RECEIVE_BYTES }>(
        Side::Client,
        options.stream_capacity,
        options.protocol.negotiated(),
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
    .map_err(Error::Packet)?;
    let parameters = &parameter_storage[..parameter_len];
    let mut buffers = TlsBuffers::new();
    let tls = BoundedTls::client(
        hibana_tls::handshake::ClientConfig {
            protocol: options.protocol.negotiated(),
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
    .map_err(|e| {
        Error::Connection(crate::quic::Error::Transcript(
            hibana_tls::handshake::Error::Crypto(e),
        ))
    })?;
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
    let mut identity = scope.claim().map_err(Error::Crypto)?;
    let recovery = identity.take_recovery().map_err(Error::Crypto)?;
    let mut gate = PublicationGate::new(identity.take_publication_gate().map_err(Error::Crypto)?);
    let (mut issuer, stop) = gate
        .split()
        .map_err(|e| Error::Connection(crate::quic::Error::Gate(e)))?;
    let mut source = Transcript::new(tls.into_key_source(identity).map_err(|e| {
        Error::Connection(crate::quic::Error::Transcript(
            hibana_tls::handshake::Error::Crypto(e),
        ))
    })?);
    let mut book = Recovery::<{ connection::DATAGRAM }>::new(
        recovery,
        config.side,
        333_000,
        connection::DATAGRAM as u64,
        3,
    )
    .map_err(Error::Recovery)?;
    let mut receive = crate::session::imp::socket::Receive {
        socket,
        address,
        first: None,
    };
    let mut transmit = crate::session::imp::socket::Transmit {
        socket,
        address,
        clock,
    };
    application::client::<{ storage::RECEIVE_BYTES }>(
        streams,
        &mut [],
        slab,
        entropy,
        &mut source,
        config,
        &mut receive,
        &mut transmit,
        clock,
        &mut issuer,
        stop,
        &mut book,
        crate::quic::application::ClientProfile {
            generation,
            protocol: options.protocol.negotiated(),
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
