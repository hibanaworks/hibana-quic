//! Allocate bounded Host resources and run the actual projected handshake locals.
use crate::io::{Clock, DatagramRx, DatagramTx};
use crate::quic;
use crate::quic::Config;
use crate::quic::Outcome;
use crate::quic::Roles;
use crate::quic::Storage;
use crate::quic::imp::crypto_buffer::CryptoBuffer;
use crate::quic::imp::publication_gate::Issuer;
use crate::quic::imp::recovery::Recovery;
use crate::quic::imp::tls::Transcript;
use crate::quic::{
    application::local::owned::{DATAGRAM, PARAMETERS},
    global,
};
use crate::runtime::carrier::CarrierStorage;
use alloc::{boxed::Box, format, string::String, vec};
use hibana::runtime::{SessionKitStorage, ids::SessionId};
#[allow(clippy::too_many_arguments)]
pub async fn handshake<'scope>(
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
    String,
> {
    let mut initial = vec![0; 8192];
    let mut handshake = vec![0; 16384];
    let mut initial_bitmap = vec![0; 1024];
    let mut handshake_bitmap = vec![0; 2048];
    let reassembly = [
        CryptoBuffer::new(&mut initial, &mut initial_bitmap)
            .map_err(|e| format!("Initial storage: {e:?}"))?,
        CryptoBuffer::new(&mut handshake, &mut handshake_bitmap)
            .map_err(|e| format!("Handshake storage: {e:?}"))?,
    ];
    let programs = global::programs();
    let adapter_result = Outcome::new();
    let queues = Box::new(CarrierStorage::<1, 16, 64>::new());
    let mut slab = vec![0; 64 * 1024];
    let mut kit_storage = Box::new(SessionKitStorage::uninit());
    let kit = kit_storage.init();
    // One session per kit. Full generation is retained by cryptographic scope.
    let session = SessionId::new(generation as u32);
    let rendezvous = kit
        .rendezvous(
            &mut slab,
            queues
                .bind(session)
                .map_err(|e| format!("carrier: {e:?}"))?,
        )
        .map_err(|e| format!("rendezvous: {e:?}"))?;
    let mut roles = Roles::attach(&rendezvous, session, &programs, &adapter_result)
        .map_err(|e| format!("handshake attachment: {e:?}"))?;
    let mut storage = Box::new(
        Storage::<DATAGRAM, PARAMETERS>::new(config.peer_connection_id)
            .map_err(|e| format!("wire storage: {e:?}"))?,
    );
    let result = Box::pin(quic::handshake(
        &mut roles,
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
    ))
    .await
    .map_err(|e| format!("direct connection: {e:?}"));
    if result.is_ok() && queues.queued() != 0 {
        return Err("wire roles left queued carrier frames".into());
    }
    result
}
