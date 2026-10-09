use super::{Error, Storage};
use crate::runtime::{carrier::Peer, join2};
use hibana::{
    Endpoint,
    runtime::{ids::SessionId, program::RoleProgram},
};
pub mod stream;
pub type StreamPeer<'a> = Peer<'a, 4, 256, 8>;
/// Attach one role and join its actual localside with the supplied stream driver.
/// The driver owns physical I/O; callers choose their executor and memory.
pub async fn run<const ROLE: u8, E>(
    storage: &mut Storage,
    slab: &mut [u8],
    session: SessionId,
    peer: u8,
    program: &RoleProgram<ROLE>,
    application: impl for<'a, 'r> AsyncFnOnce(&'a mut Endpoint<'r, ROLE>) -> Result<(), E>,
    network: impl for<'a, 's> AsyncFnOnce(&'a StreamPeer<'s>) -> Result<(), E>,
) -> Result<(), Error<E>> {
    let mut kit = hibana::runtime::SessionKitStorage::uninit();
    let rendezvous = kit
        .init()
        .rendezvous(
            slab,
            storage.carrier.bind(session).map_err(Error::Transport)?,
        )
        .map_err(Error::Attach)?;
    let mut endpoint = rendezvous.enter(session, program).map_err(Error::Attach)?;
    let bridge = storage.carrier.peer(ROLE, peer).map_err(Error::Transport)?;
    let local = async {
        application(&mut endpoint).await.map_err(Error::Local)?;
        bridge.finish();
        Ok(())
    };
    join2(local, async {
        network(&bridge).await.map_err(Error::Network)
    })
    .await
}

/// Common connection startup using injected datagram, clock and entropy capabilities.
#[cfg(feature = "alloc")]
pub mod network;

/// Allocator-backed application and connection resource owner.
#[cfg(feature = "alloc")]
pub mod owned;
