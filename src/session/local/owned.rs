//! Bind application localsides to the canonical authenticated connection.
use super::{network, stream};
use crate::{
    entropy::Entropy,
    io::{Clock, DatagramSocket},
    session,
};
use alloc::{
    format,
    string::{String, ToString},
    vec,
};
use hibana::{
    Endpoint,
    runtime::{ids::SessionId, program::RoleProgram},
};
type Result<T> = core::result::Result<T, String>;
#[allow(clippy::too_many_arguments)]
pub async fn client<const ROLE: u8, E: core::fmt::Debug>(
    socket: &impl DatagramSocket,
    clock: &impl Clock,
    entropy: &mut impl Entropy,
    mut options: network::Client<'_>,
    protocol: session::Protocol,
    peer: u8,
    program: &RoleProgram<ROLE>,
    application: impl for<'a, 'r> AsyncFnOnce(&'a mut Endpoint<'r, ROLE>) -> core::result::Result<(), E>,
) -> Result<()> {
    options.protocol = protocol.negotiated();
    let mut storage = session::Storage::new();
    let mut slab = vec![0; 65536];
    let network = async |bridge: &session::local::StreamPeer<'_>| {
        let mut requests = stream::Requests::new(bridge, protocol, options.server_name)
            .map_err(|_| "request prefix".to_string())?;
        let mut responses = stream::Input::new(bridge, protocol, false);
        let report = network::connect(
            socket,
            clock,
            entropy,
            options,
            &mut requests,
            &mut responses,
        )
        .await?;
        if report.termination != crate::quic::application::Termination::Closed
            || !report.close_completed
        {
            return Err("session did not close normally".into());
        }
        Ok(())
    };
    session::local::run(
        &mut storage,
        &mut slab,
        SessionId::new(1),
        peer,
        program,
        async |endpoint: &mut Endpoint<'_, ROLE>| {
            application(endpoint)
                .await
                .map_err(|e| format!("application: {e:?}"))
        },
        network,
    )
    .await
    .map_err(|e| format!("{e:?}"))
}

#[allow(clippy::too_many_arguments)]
pub async fn server<const ROLE: u8, E: core::fmt::Debug>(
    socket: &impl DatagramSocket,
    clock: &impl Clock,
    entropy: &mut impl Entropy,
    mut options: network::Server<'_>,
    protocol: session::Protocol,
    peer: u8,
    program: &RoleProgram<ROLE>,
    application: impl for<'a, 'r> AsyncFnOnce(&'a mut Endpoint<'r, ROLE>) -> core::result::Result<(), E>,
) -> Result<()> {
    options.protocol = protocol.negotiated();
    let mut storage = session::Storage::new();
    let mut slab = vec![0; 65536];
    let network = async |bridge: &session::local::StreamPeer<'_>| {
        let mut service = stream::Service {
            peer: bridge,
            protocol,
        };
        let mut input = stream::Input::new(bridge, protocol, true);
        let report =
            network::accept(socket, clock, entropy, options, &mut service, &mut input).await?;
        if report.termination != crate::quic::application::Termination::Closed
            || !report.close_completed
        {
            return Err("session did not close normally".into());
        }
        Ok(())
    };
    session::local::run(
        &mut storage,
        &mut slab,
        SessionId::new(1),
        peer,
        program,
        async |endpoint: &mut Endpoint<'_, ROLE>| {
            application(endpoint)
                .await
                .map_err(|e| format!("application: {e:?}"))
        },
        network,
    )
    .await
    .map_err(|e| format!("{e:?}"))
}
