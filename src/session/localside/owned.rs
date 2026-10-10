//! Bind application localsides to the canonical authenticated connection.
use super::network;
use crate::session::imp::stream;
use crate::{
    entropy::Entropy,
    io::{Clock, DatagramSocket},
    session,
};
use hibana::{
    Endpoint,
    runtime::{ids::SessionId, program::RoleProgram},
};
#[derive(Debug)]
pub enum RunError<E> {
    Application(E),
    Network(crate::quic::application::Error),
    Prefix,
    Incomplete,
}
type Result<T, E> = core::result::Result<T, session::Error<RunError<E>>>;
#[allow(clippy::too_many_arguments)]
pub async fn client<const ROLE: u8, E>(
    streams: &mut [crate::quic::streams::StreamSlot<
        { crate::quic::application::imp::owned::RECEIVE_BYTES },
    >],
    connection_slab: &mut [u8],
    application_slab: &mut [u8],
    socket: &impl DatagramSocket,
    clock: &impl Clock,
    entropy: &mut impl Entropy,
    options: crate::session::Client<'_>,
    peer: u8,
    program: &RoleProgram<ROLE>,
    application: impl for<'a, 'r> AsyncFnOnce(&'a mut Endpoint<'r, ROLE>) -> core::result::Result<(), E>,
) -> Result<(), E> {
    let protocol = options.protocol;
    let mut storage = session::Storage::new();
    let network = async |bridge: &session::StreamPeer<'_>| {
        let mut requests = stream::Requests::new(bridge, protocol, options.server_name)
            .map_err(|_| RunError::Prefix)?;
        let mut responses = stream::Input::new(bridge, protocol, crate::quic::Side::Client);
        let report = core::pin::pin!(network::connect(
            streams,
            connection_slab,
            socket,
            clock,
            entropy,
            options,
            &mut requests,
            &mut responses,
        ))
        .await
        .map_err(RunError::Network)?;
        if report.termination != crate::quic::application::Termination::Closed
            || !report.close_completed
        {
            return Err(RunError::Incomplete);
        }
        Ok(())
    };
    core::pin::pin!(session::localside::run(
        &mut storage,
        application_slab,
        SessionId::new(1),
        peer,
        program,
        async |endpoint: &mut Endpoint<'_, ROLE>| {
            application(endpoint).await.map_err(RunError::Application)
        },
        network,
    ))
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn server<const ROLE: u8, E>(
    streams: &mut [crate::quic::streams::StreamSlot<
        { crate::quic::application::imp::owned::RECEIVE_BYTES },
    >],
    connection_slab: &mut [u8],
    application_slab: &mut [u8],
    socket: &impl DatagramSocket,
    clock: &impl Clock,
    entropy: &mut impl Entropy,
    options: crate::session::Server<'_>,
    peer: u8,
    program: &RoleProgram<ROLE>,
    application: impl for<'a, 'r> AsyncFnOnce(&'a mut Endpoint<'r, ROLE>) -> core::result::Result<(), E>,
) -> Result<(), E> {
    let protocol = options.protocol;
    let mut storage = session::Storage::new();
    let network = async |bridge: &session::StreamPeer<'_>| {
        let mut service = stream::Service {
            peer: bridge,
            protocol,
        };
        let mut input = stream::Input::new(bridge, protocol, crate::quic::Side::Server);
        let report = core::pin::pin!(network::accept(
            streams,
            connection_slab,
            socket,
            clock,
            entropy,
            options,
            &mut service,
            &mut input,
        ))
        .await
        .map_err(RunError::Network)?;
        if report.termination != crate::quic::application::Termination::Closed
            || !report.close_completed
        {
            return Err(RunError::Incomplete);
        }
        Ok(())
    };
    core::pin::pin!(session::localside::run(
        &mut storage,
        application_slab,
        SessionId::new(1),
        peer,
        program,
        async |endpoint: &mut Endpoint<'_, ROLE>| {
            application(endpoint).await.map_err(RunError::Application)
        },
        network,
    ))
    .await
}
