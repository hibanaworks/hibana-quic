//! Attach the connected protocol to caller-owned storage and physical capabilities.
//! The returned future owns the projected endpoints until all endpoints retire.
use super::super::{self as application, *};
use super::Endpoints;
use crate::{
    io::{Clock, DatagramRx, DatagramTx},
    quic::imp::{
        publication_gate::{Issuer, Stop},
        recovery::Recovery,
        tls::Transcript,
    },
    runtime::carrier::CarrierStorage,
};
use hibana::runtime::{SessionKitStorage, ids::SessionId};
#[allow(clippy::too_many_arguments)]
pub async fn client<'scope, const N: usize, const P: usize, const RX: usize, const CHUNK: usize>(
    source: &mut Transcript<'scope, '_, '_>,
    setup: Setup<'_, RX, CHUNK>,
    receive: &mut impl DatagramRx,
    transmit: &mut impl DatagramTx,
    clock: &impl Clock,
    issuer: &mut Issuer<'_, 'scope>,
    stop: Stop<'_, 'scope>,
    book: &mut Recovery<'scope, N>,
    session: SessionId,
    slab: &mut [u8],
    requests: &mut impl ClientRequests,
    sink: &mut impl StreamSink,
    early_slots: &mut [crate::quic::imp::early_requests::RequestSlot],
) -> Result<Report, Error> {
    let projection = global::choreography();
    let outcomes = Outcomes::new();
    let queues = CarrierStorage::<1, 32, 128>::new();
    let mut kit = SessionKitStorage::uninit();
    let rendezvous = kit
        .init()
        .rendezvous(slab, queues.bind(session).map_err(Error::Transport)?)
        .map_err(Error::Attach)?;
    let mut endpoints = Endpoints::attach(&rendezvous, session, &projection, &outcomes)
        .map_err(Error::Attachment)?;
    let result = if source.early_status() == crate::quic::early_data::imp::EarlyStatus::Offered {
        application::client_early::<N, P, RX, CHUNK>(
            &mut endpoints,
            source,
            setup,
            receive,
            transmit,
            clock,
            issuer,
            stop,
            book,
            &outcomes,
            requests,
            sink,
            early_slots,
        )
        .await
    } else {
        application::client::<N, P, RX, CHUNK>(
            &mut endpoints,
            source,
            setup,
            receive,
            transmit,
            clock,
            issuer,
            stop,
            book,
            &outcomes,
            requests,
            sink,
        )
        .await
    };
    if result.is_ok() && queues.queued() != 0 {
        return Err(Error::Incomplete);
    }
    result
}
#[allow(clippy::too_many_arguments)]
pub async fn server<'scope, const N: usize, const P: usize, const RX: usize, const CHUNK: usize>(
    source: &mut Transcript<'scope, '_, '_>,
    setup: Setup<'_, RX, CHUNK>,
    receive: &mut impl DatagramRx,
    transmit: &mut impl DatagramTx,
    clock: &impl Clock,
    issuer: &mut Issuer<'_, 'scope>,
    stop: Stop<'_, 'scope>,
    book: &mut Recovery<'scope, N>,
    session: SessionId,
    slab: &mut [u8],
    handler: &mut impl ServerHandler,
    input: Option<&mut impl StreamSink>,
) -> Result<Report, Error> {
    let projection = global::choreography();
    let outcomes = Outcomes::new();
    let queues = CarrierStorage::<1, 32, 128>::new();
    let mut kit = SessionKitStorage::uninit();
    let rendezvous = kit
        .init()
        .rendezvous(slab, queues.bind(session).map_err(Error::Transport)?)
        .map_err(Error::Attach)?;
    let mut endpoints = Endpoints::attach(&rendezvous, session, &projection, &outcomes)
        .map_err(Error::Attachment)?;
    let result = match input {
        Some(input) => {
            application::server_stream::<N, P, RX, CHUNK>(
                &mut endpoints,
                source,
                setup,
                receive,
                transmit,
                clock,
                issuer,
                stop,
                book,
                &outcomes,
                handler,
                input,
            )
            .await
        }
        None => {
            application::server::<N, P, RX, CHUNK>(
                &mut endpoints,
                source,
                setup,
                receive,
                transmit,
                clock,
                issuer,
                stop,
                book,
                &outcomes,
                handler,
            )
            .await
        }
    };
    if result.is_ok() && queues.queued() != 0 {
        return Err(Error::Incomplete);
    }
    result
}
