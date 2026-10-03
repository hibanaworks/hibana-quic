//! Host allocation boundary for the actual direct Hibana handshake roles.
use super::direct_wire::{HostClock, Receive, Transmit};
use hibana::runtime::{SessionKitStorage, ids::SessionId};
use hibana_quic::{carrier::CarrierStorage, connection::{self, Config, Outcome, Roles, Storage, protocol, recovery::Recovery, tls::Transcript}, handshake::CryptoBuffer, roles::publication_gate::Issuer};
pub const DATAGRAM: usize = 1536;
pub const PARAMETERS: usize = 2048;
#[allow(clippy::too_many_arguments)]
pub async fn handshake<'scope>(source: &mut Transcript<'scope, '_, '_>, config: Config<'_>, receive: &mut Receive<'_, '_>, transmit: &mut Transmit<'_, '_>, clock: &HostClock<'_>, issuer: &mut Issuer<'_, 'scope>, book: &mut Recovery<'scope, DATAGRAM>, generation: u64) -> Result<(connection::ReceiveContinuation<'scope, PARAMETERS>, connection::TransmitContinuation<'scope>), String> {
    let mut initial = vec![0; 8192]; let mut handshake = vec![0; 16384]; let mut initial_bitmap = vec![0; 1024]; let mut handshake_bitmap = vec![0; 2048];
    let reassembly = [CryptoBuffer::new(&mut initial, &mut initial_bitmap).map_err(|e| format!("Initial storage: {e:?}"))?, CryptoBuffer::new(&mut handshake, &mut handshake_bitmap).map_err(|e| format!("Handshake storage: {e:?}"))?];
    let programs = protocol::programs(); let tls_result = Outcome::new(); let adapter_result = Outcome::new();
    let queues = Box::new(CarrierStorage::<1, 16, 64>::new()); let mut slab = vec![0; 64 * 1024]; let mut kit_storage = Box::new(SessionKitStorage::uninit()); let kit = kit_storage.init();
    // One session per kit. Full generation is retained by cryptographic scope.
    let session = SessionId::new(generation as u32);
    let rendezvous = kit.rendezvous(&mut slab, queues.bind(session).map_err(|e| format!("carrier: {e:?}"))?).map_err(|e| format!("rendezvous: {e:?}"))?;
    rendezvous.set_resolver(&programs.tls_rx, tls_result.resolver::<{protocol::CRYPTO_RESULT}>()).map_err(|e| format!("TLS resolver: {e:?}"))?;
    rendezvous.set_resolver(&programs.udp, adapter_result.resolver::<{protocol::ADAPTER_RESULT}>()).map_err(|e| format!("adapter resolver: {e:?}"))?;
    macro_rules! enter { ($name:ident) => { rendezvous.enter(session, &programs.$name).map_err(|e| format!("{} role: {e:?}", stringify!($name)))? }; }
    let mut roles = Roles { rx: enter!(rx), tls_rx: enter!(tls_rx), tx: enter!(tx), tx_wire: enter!(tx_wire), tls_tx: enter!(tls_tx), udp: enter!(udp), timer: enter!(timer), timer_tx: enter!(timer_tx) };
    let storage = Box::new(Storage::<DATAGRAM, PARAMETERS>::new(config.peer_connection_id).map_err(|e| format!("wire storage: {e:?}"))?);
    let result = Box::pin(connection::handshake(&mut roles, source, config, reassembly, receive, transmit, clock, issuer, &storage, book, &tls_result, &adapter_result)).await.map_err(|e| format!("direct connection: {e:?}"));
    drop(storage);
    if result.is_ok() && queues.queued() != 0 { return Err("wire roles left queued carrier frames".into()); }
    result
}
