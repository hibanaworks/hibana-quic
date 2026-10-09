//! Allocator-backed resources and direct projected server composition.
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
use alloc::{boxed::Box, format, string::String, vec};
use hibana::runtime::ids::SessionId;
#[allow(clippy::too_many_arguments)]
pub async fn server<'scope>(
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
    mut early: Option<storage::EarlyStorage>,
) -> Result<application::Report, String> {
    let mut slab = vec![0; 256 * 1024];
    let mut storage = storage::Storage::<{ storage::RECEIVE_BYTES }>::new(
        profile.stream_capacity,
        profile.protocol,
        entropy,
    )?;
    let mut setup = storage.setup(config, profile.idle_timeout_ms)?;
    setup.server_token = profile.server_token;
    setup.early = early.as_mut().map(storage::EarlyStorage::borrow);
    Box::pin(application::local::borrowed::server::<
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
        &mut slab,
        handler,
        input,
    ))
    .await
    .map_err(|e| format!("application: {e:?}"))
}
