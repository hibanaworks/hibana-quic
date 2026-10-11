//! Borrow bounded caller-owned resources and run the actual projected handshake locals.
use crate::io::{Clock, DatagramRx, DatagramTx};
use crate::quic;
use crate::quic::Config;
use crate::quic::Outcome;
use crate::quic::Storage;
use crate::quic::application::Error;
use crate::quic::imp::crypto_buffer::CryptoBuffer;
use crate::quic::imp::publication_gate::Issuer;
use crate::quic::imp::recovery::Recovery;
use crate::quic::imp::tls::Transcript;
use crate::quic::localside::Endpoints;
use crate::quic::{
    application::imp::profile::{DATAGRAM, PARAMETERS},
    global,
};
use crate::runtime::carrier::CarrierStorage;
use hibana::runtime::{SessionKitStorage, ids::SessionId};
#[allow(clippy::too_many_arguments)]
pub async fn handshake<'scope>(
    slab: &mut [u8],
    source: &mut Transcript<'scope, '_, '_>,
    config: Config<'_>,
    receive: &mut impl DatagramRx,
    transmit: &mut impl DatagramTx,
    clock: &impl Clock,
    issuer: &mut Issuer<'_, 'scope>,
    book: &mut Recovery<'scope, DATAGRAM>,
    generation: u64,
) -> Result<
    (
        quic::ReceiveContinuation<'scope, PARAMETERS>,
        quic::TransmitContinuation<'scope>,
    ),
    Error,
> {
    let mut initial = [0; 8192];
    let mut handshake = [0; 16384];
    let mut initial_bitmap = [0; 1024];
    let mut handshake_bitmap = [0; 2048];
    let reassembly = [
        CryptoBuffer::new(&mut initial, &mut initial_bitmap)
            .map_err(|e| Error::Connection(quic::Error::Reassembly(e)))?,
        CryptoBuffer::new(&mut handshake, &mut handshake_bitmap)
            .map_err(|e| Error::Connection(quic::Error::Reassembly(e)))?,
    ];
    let projection = global::choreography();
    let adapter_result = Outcome::new();
    let queues = CarrierStorage::<1, 16, 64>::new();
    let mut kit_storage = SessionKitStorage::uninit();
    let kit = kit_storage.init();
    // One session per kit. Full generation is retained by cryptographic scope.
    let session = SessionId::new(generation as u32);
    let rendezvous = kit
        .rendezvous(slab, queues.bind(session).map_err(Error::Transport)?)
        .map_err(Error::Attach)?;
    let mut endpoints = Endpoints::attach(&rendezvous, session, &projection, &adapter_result)
        .map_err(Error::Attachment)?;
    let mut storage = Storage::<DATAGRAM, PARAMETERS>::new(config.peer_connection_id)
        .map_err(Error::Connection)?;
    let result = quic::handshake(
        &mut endpoints,
        source,
        config,
        reassembly,
        receive,
        transmit,
        clock,
        issuer,
        &mut storage,
        book,
        &adapter_result,
    )
    .await
    .map_err(Error::Connection);
    if result.is_ok() && queues.queued() != 0 {
        return Err(Error::Incomplete);
    }
    result
}
