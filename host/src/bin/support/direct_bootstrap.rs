//! Host allocation and endpoint attachment for one direct Hibana global.
use super::direct_wire::{HostClock, Receive, Transmit};
use super::{application_storage, host_files};
use hibana_quic::quic::Config;
use hibana_quic::quic::Side;
use hibana_quic::quic::application;
use hibana_quic::quic::imp::publication_gate::Issuer;
use hibana_quic::quic::imp::publication_gate::Stop;
use hibana_quic::quic::imp::recovery::Recovery;
use hibana_quic::quic::imp::tls::Transcript;
pub use hibana_quic_host::connection::handshake;
pub use hibana_quic_host::connection::{DATAGRAM, PARAMETERS};

/// This selects only local file handlers. The library owns the authenticated
/// prefix, affine handoff, stream work, retirement, closing and draining.
pub enum Files {
    Client(host_files::Client),
    Server(host_files::FileServer),
}

impl Files {
    pub fn local_limits(&self) -> hibana_quic::quic::imp::kernel::streams::Limits {
        match self {
            Self::Client(client) => {
                if application_storage::client_uses_large_window(client.count) {
                    application_storage::local_limits::<{ application_storage::CLIENT_RECEIVE_BYTES }>(
                        Side::Client,
                        application_storage::capacity(client.protocol, client.count),
                        client.protocol,
                    )
                } else {
                    application_storage::local_limits::<{ application_storage::RECEIVE_BYTES }>(
                        Side::Client,
                        application_storage::capacity(client.protocol, client.count),
                        client.protocol,
                    )
                }
            }
            Self::Server(server) => {
                application_storage::local_limits::<{ application_storage::RECEIVE_BYTES }>(
                    Side::Server,
                    application_storage::capacity(
                        server.protocol,
                        application_storage::server_capacity(server.completion_limit),
                    ),
                    server.protocol,
                )
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn files<'scope, const S: usize, const T: usize>(
    source: &mut Transcript<'scope, '_, '_>,
    config: Config<'_>,
    receive: &mut Receive<'_, '_, S, T>,
    transmit: &mut Transmit<'_, '_, S, T>,
    clock: &HostClock<'_, S, T>,
    issuer: &mut Issuer<'_, 'scope>,
    stop: Stop<'_, 'scope>,
    book: &mut Recovery<'scope, DATAGRAM>,
    generation: u64,
    files: &mut Files,
    early: Option<application_storage::EarlyStorage>,
    key_update_target: u64,
    server_token: Option<&[u8]>,
    idle_timeout_ms: u64,
) -> Result<application::Report, String> {
    match files {
        Files::Client(client) => {
            let profile = hibana_quic_host::application::ClientProfile {
                generation,
                protocol: client.protocol,
                stream_capacity: application_storage::capacity(client.protocol, client.count),
                early_request_capacity: client.count,
                key_update_target,
                idle_timeout_ms,
            };
            if application_storage::client_uses_large_window(client.count) {
                hibana_quic_host::application::client::<
                    { application_storage::CLIENT_RECEIVE_BYTES },
                    S,
                    T,
                >(
                    source,
                    config,
                    receive,
                    transmit,
                    clock,
                    issuer,
                    stop,
                    book,
                    profile,
                    &mut client.requests,
                    &mut client.downloads,
                )
                .await
            } else {
                hibana_quic_host::application::client::<{application_storage::RECEIVE_BYTES}, S, T>(
                    source, config, receive, transmit, clock, issuer, stop, book,
                    profile, &mut client.requests, &mut client.downloads,
                ).await
            }
        }
        Files::Server(server) => {
            let profile = hibana_quic_host::application::ServerProfile {
                generation,
                protocol: server.protocol,
                stream_capacity: application_storage::capacity(
                    server.protocol,
                    application_storage::server_capacity(server.completion_limit),
                ),
                server_token,
                idle_timeout_ms,
            };
            hibana_quic_host::application::server::<S, T>(
                source, config, receive, transmit, clock, issuer, stop, book, profile, server,
                early,
            )
            .await
        }
    }
}
