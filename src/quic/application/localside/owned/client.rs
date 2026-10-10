//! Caller-owned resources and direct projected client composition.
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
use hibana::runtime::ids::SessionId;
#[allow(clippy::too_many_arguments)]
pub async fn client<'scope, const RX: usize>(
    streams: &mut [crate::quic::imp::kernel::streams::StreamSlot<RX>],
    early_slots: &mut [crate::quic::imp::early_requests::RequestSlot],
    slab: &mut [u8],
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
) -> Result<application::Report, application::Error> {
    if profile.early_request_capacity > application::MAX_REQUESTS {
        return Err(application::Error::Capacity);
    }
    let mut storage = storage::Storage::<RX>::new(streams, profile.protocol, entropy)?;
    let early_capacity = match source.early_status() {
        crate::quic::early_data::imp::EarlyStatus::Offered => profile.early_request_capacity,
        _ => 0,
    };
    if profile.stream_capacity != storage.stream_capacity() || early_slots.len() < early_capacity {
        return Err(application::Error::Capacity);
    }
    let mut setup = storage.setup(config, profile.idle_timeout_ms)?;
    setup.key_update_target = profile.key_update_target;
    core::pin::pin!(application::localside::borrowed::client::<
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
        slab,
        requests,
        sink,
        &mut early_slots[..early_capacity],
    ))
    .await
}
