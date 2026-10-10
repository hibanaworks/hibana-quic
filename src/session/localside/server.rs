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
impl session::Server<'_> {
    /// Run this application's projected role with caller-owned memory and I/O.
    pub async fn run<const ROLE: u8, const S: usize, const C: usize, const A: usize, E>(
        self,
        memory: &mut session::Memory<S, C, A>,
        environment: session::Environment<'_, impl DatagramSocket, impl Clock, impl Entropy>,
        peer: u8,
        program: &RoleProgram<ROLE>,
        application: impl for<'a, 'r> AsyncFnOnce(
            &'a mut Endpoint<'r, ROLE>,
        ) -> core::result::Result<(), E>,
    ) -> Result<(), E> {
        let options = self;
        let protocol = options.protocol;
        #[cfg(feature = "hq")]
        if matches!(protocol, session::Protocol::Hq) {
            return Err(session::Error::Local(RunError::Prefix));
        }
        let session::Memory {
            connection,
            application: application_slab,
        } = memory;
        let mut storage = session::Storage::new();
        let network = async |bridge: &session::StreamPeer<'_>| {
            let mut service = stream::Service {
                peer: bridge,
                protocol,
            };
            let mut input = stream::Input::new(bridge, protocol, crate::quic::Side::Server);
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
            program,
            async |endpoint: &mut Endpoint<'_, ROLE>| {
                application(endpoint).await.map_err(RunError::Application)
            },
            network,
        ))
        .await
    }
}
