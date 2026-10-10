use crate::io::{Clock, DatagramSocket};
use crate::quic::application::Error;
use crate::quic::application::{
    ServerHandler, imp::owned as storage, localside::owned as application,
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
/// Accept one integrity-checked QUIC v1 Initial on a caller-owned listener.
/// Unknown versions and malformed input are ignored; the caller supplies a deadline.
impl connection::Server<'_> {
    /// Serve complete, FIN-terminated requests with the application's owned bodies.
    /// The same connection and projected stream roles drive `run`; this entry
    /// omits its bidirectional application-message input capability.
    pub async fn serve<const S: usize, const B: usize>(
        self,
        memory: &mut connection::ConnectionMemory<S, B>,
        environment: connection::Environment<'_, impl DatagramSocket, impl Clock, impl Entropy>,
        handler: &mut impl ServerHandler,
    ) -> Result<crate::quic::application::Report> {
        core::pin::pin!(self.accept(memory, environment, handler, None)).await
    }

    pub(in crate::session) async fn accept<const S: usize, const B: usize>(
        self,
        memory: &mut connection::ConnectionMemory<S, B>,
        environment: connection::Environment<'_, impl DatagramSocket, impl Clock, impl Entropy>,
        handler: &mut impl ServerHandler,
        input: Option<&mut crate::session::imp::stream::Input<'_, '_>>,
    ) -> Result<crate::quic::application::Report> {
        let options = self;
        let connection::ConnectionMemory { streams, slab } = memory;
        let connection::Environment {
            socket,
            clock,
            entropy,
        } = environment;

        use crate::quic::imp::kernel::packet::{Header, LongType, PacketIter};
        let mut first = [0; connection::DATAGRAM];
        let mut original_bytes = [0; 20];
        let mut peer_bytes = [0; 20];
        let (metadata, original, peer) = loop {
            crate::runtime::yield_now().await;
            let metadata = socket
                .receive_from(&mut first)
                .await
                .map_err(|e| Error::Connection(crate::quic::Error::Io(e)))?;
            if metadata.len > first.len() {
                return Err(Error::Capacity);
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
                if destination_id.len() > 20 || source_id.len() > 20 {
                    continue;
                }
                original_bytes[..destination_id.len()].copy_from_slice(destination_id);
                peer_bytes[..source_id.len()].copy_from_slice(source_id);
                break (
                    metadata,
                    &original_bytes[..destination_id.len()],
                    &peer_bytes[..source_id.len()],
                );
            }
        };
        let address = metadata.path.ok_or(Error::Binding)?;
        let mut local = [0; 8];
        let mut generation = [0; 8];
        for bytes in [&mut local, &mut generation] {
            entropy.try_fill_bytes(bytes).map_err(|_| Error::Entropy)?;
        }
        let limits = storage::local_limits::<{ storage::RECEIVE_BYTES }>(
            Side::Server,
            S,
            options.protocol.negotiated(),
        );
        let mut parameter_storage = [0; 2048];
        let parameter_len = crate::quic::imp::parameters::advertisement::Advertisement {
            version: Version::V1,
            local: &local,
            original: Some(original),
            application_limits: Some(limits),
            retry_source: None,
            idle_timeout_ms: options.idle_timeout_ms,
            max_datagram_size: crate::quic::application::imp::owned::DATAGRAM as u64,
        }
        .encode(&mut parameter_storage)
        .map_err(Error::Packet)?;
        let parameters = &parameter_storage[..parameter_len];
        let mut buffers = TlsBuffers::new();
        let tls = BoundedTls::server(
            hibana_tls::handshake::ServerConfig {
                protocol: options.protocol.negotiated(),
                version: Version::V1,
                certificate_chain: options.certificate_chain,
                signing_key: options.signing_key,
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
            side: Side::Server,
            local_connection_id: &local,
            original_destination_id: original,
            retry_source_id: None,
            initial_token: &[],
            peer_connection_id: peer,
        };
        let generation = u64::from_be_bytes(generation);
        let mut scope = ApplicationKeyScope::new(generation);
        let mut identity = scope.claim().map_err(Error::Crypto)?;
        let recovery = identity.take_recovery().map_err(Error::Crypto)?;
        let mut gate =
            PublicationGate::new(identity.take_publication_gate().map_err(Error::Crypto)?);
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
            first: Some((&first[..metadata.len], metadata.ecn)),
        };
        let mut transmit = crate::session::imp::socket::Transmit {
            socket,
            address,
            clock,
        };
        core::pin::pin!(application::server(
            streams,
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
            crate::quic::application::ServerProfile {
                generation,
                protocol: options.protocol.negotiated(),
                stream_capacity: S,
                server_token: None,
                idle_timeout_ms: options.idle_timeout_ms,
            },
            handler,
            input,
            None,
        ))
        .await
    }
}
