//! Attach the caller's projected application role and drive it with network I/O.
//! [`run`] creates the actual endpoint, gives its exclusive borrow to the caller's
//! application future, then joins that future with the network future. The caller
//! supplies the application global; this module does not invent another protocol.
//! Results come from the application and network futures. Successful application
//! return seals its output; affine endpoint cleanup remains owned by this scope.
use super::{Error, Storage, StreamPeer};
use hibana::{
    Endpoint,
    runtime::{ids::SessionId, program::RoleProgram},
};
/// Attach one role and join its actual localside with the supplied stream driver.
/// The driver owns physical I/O; callers choose their executor and memory.
pub async fn run<const ROLE: u8, E>(
    storage: &mut Storage,
    slab: &mut [u8],
    session: SessionId,
    peer: u8,
    program: &RoleProgram<ROLE>,
    application: impl for<'a, 'r> AsyncFnOnce(&'a mut Endpoint<'r, ROLE>) -> Result<(), E>,
    network: impl for<'a, 's, 'r, 'ch, 'st> AsyncFnOnce(
        &'a StreamPeer<'s>,
        Admission<'ch, 'st, 'r, ROLE>,
    ) -> Result<(), E>,
) -> Result<(), Error<E>> {
    let carrier = storage.carrier.bind(session).map_err(Error::Transport)?;
    let bridge = storage.carrier.peer(ROLE, peer).map_err(Error::Transport)?;
    core::pin::pin!(run_on(
        carrier,
        &bridge,
        slab,
        session,
        program,
        application,
        network,
    ))
    .await
}

pub(crate) async fn run_on<const ROLE: u8, E>(
    carrier: impl hibana::runtime::transport::Transport,
    bridge: &StreamPeer<'_>,
    slab: &mut [u8],
    session: SessionId,
    program: &RoleProgram<ROLE>,
    application: impl for<'a, 'r> AsyncFnOnce(&'a mut Endpoint<'r, ROLE>) -> Result<(), E>,
    network: impl for<'a, 's, 'r, 'ch, 'st> AsyncFnOnce(
        &'a StreamPeer<'s>,
        Admission<'ch, 'st, 'r, ROLE>,
    ) -> Result<(), E>,
) -> Result<(), Error<E>> {
    let mut kit = hibana::runtime::SessionKitStorage::uninit();
    let rendezvous = kit
        .init()
        .rendezvous(slab, carrier)
        .map_err(Error::Attach)?;
    let endpoint = rendezvous.enter(session, program).map_err(Error::Attach)?;
    let mut slots = [None];
    let mailbox = crate::runtime::mailbox::Mailbox::new(&mut slots).expect("one empty slot");
    let (sender, mut receiver) = mailbox.split().expect("unique halves");
    let local = async {
        let mut endpoint = receiver.recv().await.map_err(|_| Error::Admission)?;
        application(&mut endpoint).await.map_err(Error::Local)?;

        bridge.finish();
        Ok(endpoint)
    };
    let (endpoint, ()) = crate::runtime::join::values2(
        core::pin::pin!(local),
        core::pin::pin!(async {
            core::pin::pin!(network(bridge, Admission { endpoint, sender }))
                .await
                .map_err(Error::Network)
        }),
    )
    .await?;
    // Keep the actual endpoint alive until the network has drained its queued
    // bytes. Application return is distinct from network termination.
    drop(endpoint);
    Ok(())
}

/// Common connection startup using injected datagram, clock and entropy capabilities.
pub mod network;

/// Failures retain the distinction between application, network and incomplete close.
#[derive(Debug)]
pub enum RunError<E> {
    Application(E),
    Network(crate::quic::application::Error),
    Prefix,
    Incomplete,
}
mod client;
mod server;

/// Owns the actual endpoint until the connection's authenticated startup.
/// There is no readiness flag or duplicate application endpoint.
pub struct Admission<'ch, 'st, 'r, const ROLE: u8> {
    endpoint: Endpoint<'r, ROLE>,
    sender: crate::runtime::mailbox::Sender<'ch, 'st, Endpoint<'r, ROLE>, 1>,
}
impl<const ROLE: u8> Admission<'_, '_, '_, ROLE> {
    pub async fn open(mut self) -> Result<(), crate::quic::application::Error> {
        self.sender
            .send(self.endpoint)
            .await
            .map_err(|_| crate::quic::application::Error::Binding)
    }
}

#[cfg(test)]
mod tests;
