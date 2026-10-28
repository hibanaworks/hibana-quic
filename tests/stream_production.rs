//! Drive the source protocol, returned endpoint and reclamation with bounded transport.
use hibana::{
    EndpointError,
    runtime::{SessionKitStorage, ids::SessionId, program::project},
};
use hibana_quic::{quic::application::global as p, runtime::carrier::CarrierStorage};
use hibana_tls::quic::scope::ApplicationKeyScope;

#[global_allocator]
static ALLOCATOR: actor_test_allocator::Counting = actor_test_allocator::Counting;

async fn run(cases: &[(usize, bool, u8, u8)], illegal: u8) {
    let global = p::source_choreography();
    let source_program = project::<{ p::SOURCE }>(&global);
    let ingress_program = project::<{ p::INGRESS }>(&global);
    let production_program = project::<{ p::PRODUCTION }>(&global);
    let collector_program = project::<{ p::SOURCE_COLLECTOR }>(&global);
    let join_program = project::<{ p::SOURCE_JOIN }>(&global);
    // Five logical roles participate in the two parallel protocol fragments.
    let queues = CarrierStorage::<1, 16, { 5 * 2 }>::new();
    let scope = ApplicationKeyScope::new(907);
    let bindings = scope.endpoint_bindings();
    let id = SessionId::new(907);
    let carrier = queues.bind(id, &bindings).unwrap();
    let mut slab = [0; 65536];
    let mut storage = SessionKitStorage::uninit();
    let runtime = storage.init().rendezvous(&mut slab, &carrier).unwrap();
    let mut source = runtime.enter(id, &source_program).unwrap();
    let mut ingress = runtime.enter(id, &ingress_program).unwrap();
    let mut operations = runtime.enter(id, &production_program).unwrap();
    let mut collector = runtime.enter(id, &collector_program).unwrap();
    let mut joined = runtime.enter(id, &join_program).unwrap();
    let all = async {
        tokio::try_join!(
            async {
                for (index, &(chunks, abandon, reply, terminal)) in cases.iter().enumerate() {
                    let stream_id = (index as u64 + 1) * 4;
                    source.send::<p::SourceOpen>(&stream_id).await.unwrap();
                    let mut operations = source.recv::<p::StreamLoan<'_>>().await.unwrap();
                    for _ in 0..chunks {
                        operations.send::<p::SourceData>(&()).await.unwrap();
                        let offered = operations.offer().await.unwrap();
                        assert_eq!(offered.label(), reply);
                        match reply {
                            1 => offered.recv::<p::SourceAccepted>().await?,
                            187 => offered.recv::<p::SourceStopped>().await?,
                            _ => unreachable!(),
                        }
                        operations.send::<p::SourceTaken>(&()).await.unwrap();
                    }
                    operations.send::<p::SourceFlush>(&stream_id).await.unwrap();
                    assert_eq!(
                        operations.recv::<p::SourceFlushed>().await.unwrap(),
                        stream_id
                    );
                    if abandon {
                        source
                            .send::<p::SourceAbandon<'_>>(operations)
                            .await
                            .unwrap();
                    } else {
                        source.send::<p::SourceFin<'_>>(operations).await.unwrap();
                    }
                    let offered = source.offer().await.unwrap();
                    assert_eq!(offered.label(), terminal);
                    let actual = match terminal {
                        171 => offered.recv::<p::SourceEnded>().await?,
                        172 => offered.recv::<p::SourceEndRejected>().await?,
                        188 => offered.recv::<p::SourceEndStopped>().await?,
                        _ => unreachable!(),
                    };
                    assert_eq!(actual, stream_id);
                }
                source.send::<p::SourceDone>(&()).await.unwrap();
                source.recv::<p::SourceRetired>().await.unwrap();
                source.send::<p::SourceJoined>(&()).await.unwrap();
                Ok::<_, EndpointError>(())
            },
            async {
                for (index, &(chunks, abandon, reply, terminal)) in cases.iter().enumerate() {
                    let stream_id = (index as u64 + 1) * 4;
                    assert_eq!(
                        ingress.offer().await?.recv::<p::SourceOpen>().await?,
                        stream_id
                    );
                    ingress.send::<p::StreamLoan<'_>>(operations).await.unwrap();
                    for _ in 0..chunks {
                        let offered = ingress.offer().await.unwrap();
                        offered.recv::<p::SourceData>().await.unwrap();
                        match reply {
                            1 => ingress.send::<p::SourceAccepted>(&()).await?,
                            187 => ingress.send::<p::SourceStopped>(&()).await?,
                            _ => unreachable!(),
                        }
                        ingress.recv::<p::SourceTaken>().await.unwrap();
                    }
                    assert_eq!(
                        ingress.offer().await?.recv::<p::SourceFlush>().await?,
                        stream_id
                    );
                    ingress.send::<p::SourceFlushed>(&stream_id).await.unwrap();
                    let offered = ingress.offer().await.unwrap();
                    operations = if abandon {
                        offered.recv::<p::SourceAbandon<'_>>().await?
                    } else {
                        offered.recv::<p::SourceFin<'_>>().await?
                    };
                    ingress
                        .send::<p::ProductionReclaim>(&stream_id)
                        .await
                        .unwrap();
                    assert_eq!(ingress.recv::<p::ProductionStored>().await?, stream_id);
                    match terminal {
                        171 => ingress.send::<p::SourceEnded>(&stream_id).await?,
                        172 => ingress.send::<p::SourceEndRejected>(&stream_id).await?,
                        188 => ingress.send::<p::SourceEndStopped>(&stream_id).await?,
                        _ => unreachable!(),
                    }
                }
                ingress
                    .offer()
                    .await?
                    .recv::<p::SourceDone>()
                    .await
                    .unwrap();
                ingress
                    .send::<p::ProductionReclaimsDone>(&())
                    .await
                    .unwrap();
                ingress.recv::<p::ProductionReclaimsClosed>().await.unwrap();
                ingress.send::<p::SourceRetired>(&()).await.unwrap();
                Ok::<_, EndpointError>(operations)
            },
            async {
                for index in 0..cases.len() {
                    let stream_id = (index as u64 + 1) * 4;
                    assert_eq!(
                        collector
                            .offer()
                            .await?
                            .recv::<p::ProductionReclaim>()
                            .await?,
                        stream_id
                    );
                    collector
                        .send::<p::ProductionStored>(&stream_id)
                        .await
                        .unwrap();
                }
                collector
                    .offer()
                    .await?
                    .recv::<p::ProductionReclaimsDone>()
                    .await
                    .unwrap();
                collector
                    .send::<p::ProductionReclaimsClosed>(&())
                    .await
                    .unwrap();
                Ok::<_, EndpointError>(())
            },
            async {
                joined
                    .offer()
                    .await?
                    .recv::<p::SourceJoined>()
                    .await
                    .unwrap();
                Ok::<_, EndpointError>(())
            },
        )
    };
    // Initialize the host watchdog before measuring the endpoint operations.
    let mut deadline = core::pin::pin!(tokio::time::sleep(std::time::Duration::from_secs(2)));
    let until = deadline.deadline();
    deadline.as_mut().reset(until);
    let allocation = actor_test_allocator::NoAlloc::start();
    let (_, mut operations, _, _) = tokio::select! {
        biased;
        result = all => result.unwrap(),
        _ = deadline.as_mut() => panic!("stream production stalled"),
    };
    assert_eq!(queues.queued(), 0);
    // A fault probe must not race another local's pending terminal receive.
    let rejected = tokio::select! {
        biased;
        result = async {
            match illegal {
                0 => Ok(()),
                1 => operations.send::<p::SourceData>(&()).await,
                2 => ingress.send::<p::SourceFin<'_>>(operations).await,
                3 => ingress.send::<p::SourceAbandon<'_>>(operations).await,
                4 => source.recv::<p::StreamLoan<'_>>().await.map(|_| ()),
                5 => source.send::<p::SourceData>(&()).await,
                _ => unreachable!(),
            }
        } => result,
        _ = deadline.as_mut() => panic!("post-terminal operation stalled: {illegal}"),
    };
    if illegal != 0 {
        assert!(
            rejected.is_err(),
            "operation after returning endpoint: {illegal}"
        );
    }
    allocation.finish();
}

#[tokio::test(flavor = "current_thread")]
async fn empty_and_multi_chunk_streams_finish_or_abandon_without_allocating() {
    for chunks in [0, 1, 8] {
        for abandon in [false, true] {
            for terminal in [171, 172] {
                run(&[(chunks, abandon, 1, terminal)], 0).await;
            }
        }
    }
}
#[tokio::test(flavor = "current_thread")]
async fn terminal_rejects_data_reentry_duplicate_fin_and_duplicate_abandon() {
    for chunks in [0, 3] {
        for abandon in [false, true] {
            for illegal in 1..=5 {
                run(&[(chunks, abandon, 1, 171)], illegal).await;
            }
        }
    }
}
#[tokio::test(flavor = "current_thread")]
async fn peer_stop_during_data_or_fin_preserves_the_next_stream_continuation() {
    run(&[(1, true, 187, 171), (0, false, 1, 171)], 0).await;
    run(&[(1, false, 1, 188), (0, false, 1, 171)], 0).await;
}
