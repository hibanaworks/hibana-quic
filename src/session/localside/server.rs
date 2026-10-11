//! Bind application localsides to the canonical authenticated connection.
use super::RunError;
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
type Result<T, E> = core::result::Result<T, session::Error<RunError<E>>>;
impl<
    Socket: DatagramSocket,
    Timer: Clock,
    Random: Entropy,
    const S: usize,
    const C: usize,
    const A: usize,
> session::Server<'_, '_, Socket, Timer, Random, S, C, A>
{
    /// Serve a native HTTP/3 request with the caller's composed message graph.
    /// The application closure receives its inferred endpoint and borrowed
    /// request/response actions. Platform capabilities remain in the binding.
    pub async fn http3<const B: usize, const H: usize>(
        self,
        global: &impl hibana::runtime::program::Projectable,
        storage: &mut crate::http3::Storage<B, H>,
        application: impl for<'a, 'r, 'exchange, 'storage> AsyncFnOnce(
            &'a mut Endpoint<'r, { crate::http3::localside::server::APP }>,
            crate::http3::message::localside::request::Request<
                'exchange,
                'storage,
                { crate::http3::localside::server::APP },
            >,
            crate::http3::message::localside::producer::Response<
                'exchange,
                'storage,
                { crate::http3::localside::server::APP },
            >,
        )
            -> crate::http3::message::Result<
            (),
        >,
    ) -> core::result::Result<(), crate::http3::localside::server::Error> {
        let session::Server {
            config,
            memory,
            environment,
            ..
        } = self;
        core::pin::pin!(crate::http3::localside::server::run(
            config,
            &mut memory.connection,
            environment,
            &mut memory.application,
            global,
            storage,
            application,
        ))
        .await
    }

    /// Run this application's projected role with caller-owned memory and I/O.
    pub async fn run<const ROLE: u8, E>(
        self,
        program: RoleProgram<ROLE>,
        application: impl for<'a, 'r> AsyncFnOnce(
            &'a mut Endpoint<'r, ROLE>,
        ) -> core::result::Result<(), E>,
    ) -> Result<(), E> {
        let session::Server {
            config: options,
            memory,
            environment,
            peer,
        } = self;
        let protocol = options.protocol;
        if !matches!(protocol, session::Protocol::Raw(_)) {
            return Err(session::Error::Local(RunError::Prefix));
        }
        let session::Memory {
            connection,
            application: application_slab,
        } = memory;
        let mut storage = session::Storage::new();
        let network = async |bridge: &session::StreamPeer<'_>,
                             admission: super::Admission<'_, '_, '_, ROLE>| {
            let start = async move |authenticated| {
                if authenticated != protocol {
                    return Err(crate::quic::application::Error::Binding);
                }
                admission.open().await
            };
            let mut service = stream::Service {
                start: Some(start),
                peer: bridge,
            };
            let mut input = stream::Input::new(bridge);
            let report = core::pin::pin!(options.accept(
                connection,
                environment,
                &mut service,
                Some(&mut input),
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
            &program,
            async |endpoint: &mut Endpoint<'_, ROLE>| {
                application(endpoint).await.map_err(RunError::Application)
            },
            network,
        ))
        .await
    }
}
