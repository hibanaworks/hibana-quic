//! Allocator-backed resources and direct projected client composition.
use super::ClientProfile;
use super::{DATAGRAM, PARAMETERS};
use crate::quic::Config;
use crate::quic::application;
use crate::quic::imp::publication_gate::Issuer;
use crate::quic::imp::publication_gate::Stop;
use crate::quic::imp::recovery::Recovery;
use crate::quic::imp::tls::Transcript;
use crate::{
    io::{Clock, DatagramRx, DatagramTx},
    quic::application::imp::owned as storage,
};
use alloc::{boxed::Box, format, string::String, vec, vec::Vec};
use hibana::runtime::ids::SessionId;
#[allow(clippy::too_many_arguments)]
pub async fn client<'scope, const RX: usize>(
    entropy: &mut impl crate::entropy::Entropy,
    source: &mut Transcript<'scope, '_, '_>,
    config: Config<'_>,
    receive: &mut impl DatagramRx,
    transmit: &mut impl DatagramTx,
    clock: &impl Clock,
    issuer: &mut Issuer<'_, 'scope>,
    stop: Stop<'_, 'scope>,
    book: &mut Recovery<'scope, DATAGRAM>,
    profile: ClientProfile,
    requests: &mut impl application::ClientRequests,
    sink: &mut impl application::StreamSink,
) -> Result<application::Report, String> {
    if profile.early_request_capacity > application::MAX_REQUESTS {
        return Err("early request capacity exceeds the application admission bound".into());
    }
    let mut slab = vec![0; 256 * 1024];
    let mut storage =
        storage::Storage::<RX>::new(profile.stream_capacity, profile.protocol, entropy)?;
    let mut setup = storage.setup(config, profile.idle_timeout_ms)?;
    setup.key_update_target = profile.key_update_target;
    let early_capacity = match source.early_status() {
        crate::quic::early_data::imp::EarlyStatus::Offered => profile.early_request_capacity,
        _ => 0,
    };
    let mut early_slots = (0..early_capacity)
        .map(|_| crate::quic::local::early_client::RequestSlot::EMPTY)
        .collect::<Vec<_>>();
    Box::pin(application::local::borrowed::client::<
        DATAGRAM,
        PARAMETERS,
        RX,
        { storage::CHUNK_BYTES },
    >(
        source,
        setup,
        receive,
        transmit,
        clock,
        issuer,
        stop,
        book,
        SessionId::new(profile.generation as u32),
        &mut slab,
        requests,
        sink,
        &mut early_slots,
    ))
    .await
    .map_err(|e| format!("application: {e:?}"))
}
