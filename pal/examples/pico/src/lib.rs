//! Board-facing no_std/no_alloc example using the native examples' exact application roles.
//! Supply initialized TLS/QUIC resources plus real UDP and monotonic-clock capabilities.
//! This library is an integration surface, not a boot image or a network-device driver.
#![no_std]
#[path = "../../../../examples/hello-quic/local/client.rs"]
mod client_local;
#[path = "../../../../examples/hello-quic/global.rs"]
pub mod global;
#[path = "../../../../examples/hello-quic/local/server.rs"]
mod server_local;
use hibana::runtime::{ids::SessionId, program::project};
use hibana_quic::{
    io::{Clock, DatagramRx, DatagramTx},
    quic::{
        application,
        imp::{
            publication_gate::{Issuer, Stop},
            recovery::Recovery,
            tls::Transcript,
        },
    },
    session,
};
#[derive(Debug)]
pub enum Error {
    Client(client_local::Error),
    Server(server_local::Error),
    Connection(application::Error),
    Framing,
    Incomplete,
}
/// Run the shared client localside over raw QUIC or HTTP/3, without an allocator.
#[allow(clippy::too_many_arguments)]
pub async fn client<'scope, const N: usize, const P: usize, const RX: usize, const CHUNK: usize>(
    source: &mut Transcript<'scope, '_, '_>,
    setup: application::Setup<'_, RX, CHUNK>,
    receive: &mut impl DatagramRx,
    transmit: &mut impl DatagramTx,
    clock: &impl Clock,
    issuer: &mut Issuer<'_, 'scope>,
    stop: Stop<'_, 'scope>,
    recovery: &mut Recovery<'scope, N>,
    application_slab: &mut [u8],
    connection_slab: &mut [u8],
    protocol: session::Protocol,
) -> Result<(), session::Error<Error>> {
    let program = project::<{ global::CLIENT }, _>(&global::choreography());
    let mut storage = session::Storage::new();
    session::local::run(
        &mut storage,
        application_slab,
        SessionId::new(1),
        global::SERVER,
        &program,
        async |endpoint| client_local::run(endpoint).await.map_err(Error::Client),
        async |bridge: &session::local::StreamPeer<'_>| {
            let mut requests = session::local::stream::Requests::new(bridge, protocol, "device")
                .map_err(|_| Error::Framing)?;
            let mut responses = session::local::stream::Input::new(bridge, protocol, false);
            let report = application::local::borrowed::client::<N, P, RX, CHUNK>(
                source,
                setup,
                receive,
                transmit,
                clock,
                issuer,
                stop,
                recovery,
                SessionId::new(2),
                connection_slab,
                &mut requests,
                &mut responses,
                &mut [],
            )
            .await
            .map_err(Error::Connection)?;
            if report.termination != application::Termination::Closed || !report.close_completed {
                return Err(Error::Incomplete);
            }
            Ok(())
        },
    )
    .await
}
/// Run the shared server localside over raw QUIC or HTTP/3, without an allocator.
#[allow(clippy::too_many_arguments)]
pub async fn server<'scope, const N: usize, const P: usize, const RX: usize, const CHUNK: usize>(
    source: &mut Transcript<'scope, '_, '_>,
    setup: application::Setup<'_, RX, CHUNK>,
    receive: &mut impl DatagramRx,
    transmit: &mut impl DatagramTx,
    clock: &impl Clock,
    issuer: &mut Issuer<'_, 'scope>,
    stop: Stop<'_, 'scope>,
    recovery: &mut Recovery<'scope, N>,
    application_slab: &mut [u8],
    connection_slab: &mut [u8],
    protocol: session::Protocol,
) -> Result<(), session::Error<Error>> {
    let program = project::<{ global::SERVER }, _>(&global::choreography());
    let mut storage = session::Storage::new();
    session::local::run(
        &mut storage,
        application_slab,
        SessionId::new(1),
        global::CLIENT,
        &program,
        async |endpoint| server_local::run(endpoint).await.map_err(Error::Server),
        async |bridge: &session::local::StreamPeer<'_>| {
            let mut service = session::local::stream::Service {
                peer: bridge,
                protocol,
            };
            let mut input = session::local::stream::Input::new(bridge, protocol, true);
            let report = application::local::borrowed::server::<N, P, RX, CHUNK>(
                source,
                setup,
                receive,
                transmit,
                clock,
                issuer,
                stop,
                recovery,
                SessionId::new(2),
                connection_slab,
                &mut service,
                Some(&mut input),
            )
            .await
            .map_err(Error::Connection)?;
            if report.termination != application::Termination::Closed || !report.close_completed {
                return Err(Error::Incomplete);
            }
            Ok(())
        },
    )
    .await
}
