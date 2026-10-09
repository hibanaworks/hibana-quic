//! Host allocation and direct projected client composition.
use super::super::ClientProfile;
use crate::connection::{DATAGRAM, PARAMETERS};
use crate::{
    io::{HostClock, Receive, Transmit},
    storage,
};
use hibana::runtime::{SessionKitStorage, ids::SessionId};
use hibana_quic::quic::Config;
use hibana_quic::quic::application;
use hibana_quic::quic::imp::publication_gate::Issuer;
use hibana_quic::quic::imp::publication_gate::Stop;
use hibana_quic::quic::imp::recovery::Recovery;
use hibana_quic::quic::imp::tls::Transcript;
use hibana_quic::runtime::carrier::CarrierStorage;
#[allow(clippy::too_many_arguments)]
pub async fn client<'scope, const RX: usize, const S: usize, const T: usize>(
    source: &mut Transcript<'scope, '_, '_>,
    config: Config<'_>,
    receive: &mut Receive<'_, '_, S, T>,
    transmit: &mut Transmit<'_, '_, S, T>,
    clock: &HostClock<'_, S, T>,
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
    let programs = application::global::programs();
    // Resolver states precede the kit so all endpoint borrows expire first.
    let outcomes = application::Outcomes::new();
    let queues = Box::new(CarrierStorage::<1, 32, 128>::new());
    let mut slab = vec![0; 256 * 1024];
    let mut kit_storage = Box::new(SessionKitStorage::uninit());
    let kit = kit_storage.init();
    let session = SessionId::new(profile.generation as u32);
    let rendezvous = kit
        .rendezvous(
            &mut slab,
            queues
                .bind(session)
                .map_err(|e| format!("carrier: {e:?}"))?,
        )
        .map_err(|e| format!("rendezvous: {e:?}"))?;

    let mut roles = application::Roles::attach(&rendezvous, session, &programs, &outcomes)
        .map_err(|e| format!("application attachment: {e:?}"))?;
    let statistics = receive.statistics;
    let observed_clock = crate::io::ObservedClock {
        physical: clock,
        session: profile.generation as u32,
    };
    let mut application = Box::pin(async {
        let mut storage = storage::Storage::<RX>::new(profile.stream_capacity, profile.protocol)?;
        let mut setup = storage.setup(config, profile.idle_timeout_ms)?;
        setup.key_update_target = profile.key_update_target;
        if source.early_status() == hibana_quic::quic::early_data::imp::EarlyStatus::Offered {
            let mut early_slots = (0..profile.early_request_capacity)
                .map(|_| hibana_quic::quic::local::early_client::RequestSlot::EMPTY)
                .collect::<Vec<_>>();
            Box::pin(application::client_early::<
                DATAGRAM,
                PARAMETERS,
                RX,
                { storage::CHUNK_BYTES },
            >(
                &mut roles,
                source,
                setup,
                receive,
                transmit,
                &observed_clock,
                issuer,
                stop,
                book,
                &outcomes,
                requests,
                sink,
                &mut early_slots,
            ))
            .await
        } else {
            Box::pin(application::client::<
                DATAGRAM,
                PARAMETERS,
                RX,
                { storage::CHUNK_BYTES },
            >(
                &mut roles,
                source,
                setup,
                receive,
                transmit,
                &observed_clock,
                issuer,
                stop,
                book,
                &outcomes,
                requests,
                sink,
            ))
            .await
        }
        .map_err(|e| format!("direct application: {e:?}"))
    });

    // Read-only diagnostic sampling at the host executor boundary. This never
    // wakes a task or changes an endpoint, deadline, or success condition.
    let diagnostics = std::env::var("HIBANA_QUIC_DIAGNOSTICS").as_deref() == Ok("1");
    let started = std::time::Instant::now();
    let mut sampled_at = None;
    let mut traced_through = None;
    let mut trace_records = 0u16;
    let result = std::future::poll_fn(|cx| {
        let result = std::future::Future::poll(application.as_mut(), cx);
        if diagnostics && (result.is_ready() || sampled_at.is_none_or(|at: std::time::Instant| at.elapsed() >= std::time::Duration::from_secs(1))) {
            sampled_at = Some(std::time::Instant::now());
            // A bounded sample of preceding committed operations distinguishes
            // Flight from Idle without adding protocol state or private bytes.
            for event in rendezvous.tap().filter(|event| matches!(event.id(),
                hibana::runtime::tap::ENDPOINT_SEND | hibana::runtime::tap::ENDPOINT_RECV | hibana::runtime::tap::ENDPOINT_SESSION)) {
                if traced_through.is_none_or(|ordinal| event.ts() > ordinal) {
                    traced_through = Some(event.ts());
                    if trace_records < 512 {
                        eprintln!("connection-trace session={} ordinal={} event={} metadata={}", event.arg0(), event.ts(), event.id(), event.arg1());
                        trace_records += 1;
                    } else if trace_records == 512 {
                        eprintln!("connection-trace-capacity session={}", event.arg0());
                        trace_records += 1;
                    }
                }
            }
            if let Some(event) = rendezvous.tap().filter(|event| matches!(event.id(),
                hibana::runtime::tap::ENDPOINT_SEND | hibana::runtime::tap::ENDPOINT_RECV | hibana::runtime::tap::ENDPOINT_SESSION)).last() {
                eprintln!("connection-frontier session={} ordinal={} event={} metadata={} finished={} elapsed_ms={} sent={} received={}",
                    event.arg0(), event.ts(), event.id(), event.arg1(), result.is_ready(), started.elapsed().as_millis(), statistics.sent.get(), statistics.received.get());
            }
        }
        result
    }).await;
    drop(application);
    if (result.is_err()
        || result
            .as_ref()
            .is_ok_and(|report| report.termination == application::Termination::IdleExpired))
        && std::env::var("HIBANA_QUIC_DIAGNOSTICS").as_deref() == Ok("1")
    {
        for event in rendezvous.tap() {
            eprintln!("direct Hibana runtime: {event:?}");
        }
    }
    if result.is_ok() && queues.queued() != 0 {
        return Err("connected roles left queued carrier frames".into());
    }
    result
}
