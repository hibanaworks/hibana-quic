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
> session::Client<'_, '_, Socket, Timer, Random, S, C, A>
{
    /// Exchange one native HTTP/3 request and response with independently
    /// progressing upload/download roles in the caller's composed global.
    pub async fn http3<const B: usize, const H: usize>(
        self,
        global: &impl hibana::runtime::program::Projectable,
        storage: &mut crate::http3::Storage<B, H>,
        upload: impl for<'a, 'r, 'exchange, 'storage> AsyncFnOnce(
            &'a mut Endpoint<'r, { crate::http3::localside::client::UPLOAD }>,
            crate::http3::message::localside::outgoing::Request<
                'exchange,
                'storage,
                { crate::http3::localside::client::UPLOAD },
            >,
        )
            -> crate::http3::message::Result<()>,
        download: impl for<'a, 'r, 'exchange, 'storage> AsyncFnOnce(
            &'a mut Endpoint<'r, { crate::http3::localside::client::DOWNLOAD }>,
            crate::http3::localside::client::Response<
                'exchange,
                'storage,
                { crate::http3::localside::client::DOWNLOAD },
            >,
        )
            -> crate::http3::message::Result<()>,
    ) -> core::result::Result<(), crate::http3::localside::client::Error> {
        let session::Client {
            config,
            memory,
            environment,
            ..
        } = self;
        core::pin::pin!(crate::http3::localside::client::run(
            config,
            &mut memory.connection,
            environment,
            &mut memory.application,
            global,
            storage,
            upload,
            download,
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
        let session::Client {
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
            let mut requests = stream::Requests::new(bridge, start);
            let mut responses = stream::Input::new(bridge);
            let report = core::pin::pin!(options.transfer(
                connection,
                environment,
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
            &program,
            async |endpoint: &mut Endpoint<'_, ROLE>| {
                application(endpoint).await.map_err(RunError::Application)
            },
            network,
        ))
        .await
    }
}
