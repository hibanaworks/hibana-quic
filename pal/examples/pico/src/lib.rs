//! Board-facing no_std/no_alloc example using the native examples' exact application roles.
//! Supply initialized TLS/QUIC resources plus real UDP and monotonic-clock capabilities.
//! This library is an integration surface, not a boot image or a network-device driver.
#![no_std]
mod client_local {
    //! The client application localside. Its Endpoint follows the shared global.
    //! QUIC/TLS and environment I/O are owned by the lower connection layers.
    use crate::global::*;
    use hibana::Endpoint;
    #[derive(Debug)]
    pub enum Error {
        Protocol(hibana::EndpointError),
        IncorrectSquare,
    }
    pub async fn run(client: &mut Endpoint<'_, CLIENT>) -> Result<(), Error> {
        for number in [42_u64, 7] {
            client
                .send::<Number>(&number)
                .await
                .map_err(Error::Protocol)?;
            let square = client.recv::<Square>().await.map_err(Error::Protocol)?;
            if square != number * number {
                return Err(Error::IncorrectSquare);
            }
        }
        Ok(())
    }
}

#[path = "../../../../examples/hello-quic/global.rs"]
pub mod global;
mod server_local {
    //! The server application localside. Its Endpoint follows the shared global.
    //! QUIC/TLS and environment I/O are owned by the lower connection layers.
    use crate::global::*;
    use hibana::Endpoint;
    #[derive(Debug)]
    pub enum Error {
        Protocol(hibana::EndpointError),
        Overflow,
    }
    pub async fn run(server: &mut Endpoint<'_, SERVER>) -> Result<(), Error> {
        for _ in 0..2 {
            let number = server.recv::<Number>().await.map_err(Error::Protocol)?;
            let square = number.checked_mul(number).ok_or(Error::Overflow)?;
            server
                .send::<Square>(&square)
                .await
                .map_err(Error::Protocol)?;
        }
        Ok(())
    }
}

use hibana::runtime::{ids::SessionId, program::project};
use hibana_quic::{
    io::{Clock, DatagramRx, DatagramTx},
    quic::{
        application,
        publication::{Issuer, Stop},
        recovery::Recovery,
        transcript::Transcript,
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
    let program = project(&global::choreography());
    let mut storage = session::Storage::new();
    session::localside::run(
        &mut storage,
        application_slab,
        SessionId::new(1),
        global::SERVER,
        &program,
        async |endpoint| client_local::run(endpoint).await.map_err(Error::Client),
        async |bridge: &session::StreamPeer<'_>| {
            let mut requests = session::stream::Requests::new(bridge, protocol, "device")
                .map_err(|_| Error::Framing)?;
            let mut responses =
                session::stream::Input::new(bridge, protocol, hibana_quic::quic::Side::Client);
            let report = application::localside::borrowed::client::<N, P, RX, CHUNK>(
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
    let program = project(&global::choreography());
    let mut storage = session::Storage::new();
    session::localside::run(
        &mut storage,
        application_slab,
        SessionId::new(1),
        global::CLIENT,
        &program,
        async |endpoint| server_local::run(endpoint).await.map_err(Error::Server),
        async |bridge: &session::StreamPeer<'_>| {
            let mut service = session::stream::Service {
                peer: bridge,
                protocol,
            };
            let mut input =
                session::stream::Input::new(bridge, protocol, hibana_quic::quic::Side::Server);
            let report = application::localside::borrowed::server::<N, P, RX, CHUNK>(
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
