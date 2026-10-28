//! Caller-owned resources and direct projected server composition.
use super::ServerProfile;
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
pub async fn server<'scope>(
    storage: &mut storage::Storage,
    streams: &mut [crate::quic::imp::kernel::streams::StreamSlot<{ storage::RECEIVE_BYTES }>],
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
    profile: ServerProfile<'_>,
    handler: &mut impl application::ServerHandler,
    input: Option<&mut impl application::StreamSink>,
    early: Option<&mut storage::EarlyStorage<'_>>,
) -> Result<application::Report, application::Error> {
    if streams.is_empty()
        || streams.len() > storage::STREAMS
        || (profile.protocol == crate::http3::Protocol::Http3 && streams.len() <= 6)
        || streams.len() != profile.stream_capacity
    {
        return Err(application::Error::Capacity);
    }
    let mut setup = storage.setup(
        streams,
        config,
        profile.protocol,
        profile.idle_timeout_ms,
        entropy,
    )?;
    setup.server_token = profile.server_token;
    setup.early = early.map(storage::EarlyStorage::borrow);
    core::pin::pin!(application::localside::borrowed::server::<
        DATAGRAM,
        PARAMETERS,
        { storage::RECEIVE_BYTES },
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
        handler,
        input,
    ))
    .await
}
