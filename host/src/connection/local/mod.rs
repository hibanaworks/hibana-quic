//! Allocate bounded Host resources and run the actual projected handshake locals.
use super::{DATAGRAM, PARAMETERS, global};
use crate::io::{HostClock, Receive, Transmit};
use hibana::runtime::{SessionKitStorage, ids::SessionId};
use hibana_quic::quic;
use hibana_quic::quic::Config;
use hibana_quic::quic::Outcome;
use hibana_quic::quic::Roles;
use hibana_quic::quic::Storage;
use hibana_quic::quic::imp::crypto_buffer::CryptoBuffer;
use hibana_quic::quic::imp::publication_gate::Issuer;
use hibana_quic::quic::imp::recovery::Recovery;
use hibana_quic::quic::imp::tls::Transcript;
use hibana_quic::runtime::carrier::CarrierStorage;
#[allow(clippy::too_many_arguments)]
pub async fn handshake<'scope, const S: usize, const T: usize>(
    source: &mut Transcript<'scope, '_, '_>,
    config: Config<'_>,
    receive: &mut Receive<'_, '_, S, T>,
    transmit: &mut Transmit<'_, '_, S, T>,
    clock: &HostClock<'_, S, T>,
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
