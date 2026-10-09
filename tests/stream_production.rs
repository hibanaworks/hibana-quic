//! Exercise the actual source fragment, with capacity-one transport and no
//! surrogate stream FSM. A finite terminal must retire the inner data roll.
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use hibana::{
    EndpointError,
    runtime::{
        SessionKitStorage,
        ids::SessionId,
        program::{RoleProgram, project},
    },
};
use hibana_quic::{
    quic::application::global as p, runtime::carrier::CarrierStorage, runtime::join2,
};

fn run(chunks: usize, abandon: bool, rejected: bool, illegal: u8) {
    let global = p::source_choreography();
    let source: RoleProgram<{ p::SOURCE }> = project(&global);
    let ingress: RoleProgram<{ p::INGRESS }> = project(&global);
    let carrier = CarrierStorage::<1, 16, 8>::new();
    let mut slab = [0; 65536];
    let mut storage = SessionKitStorage::uninit();
    let id = SessionId::new(907);
    let rv = storage
        .init()
        .rendezvous(&mut slab, carrier.bind(id).unwrap())
        .unwrap();
    let mut source = rv.enter(id, &source).unwrap();
    let mut ingress = rv.enter(id, &ingress).unwrap();
    let allocation = actor_test_allocator::NoAlloc::start();
    let mut all = pin!(join2(
        async {
            source.send::<p::SourceOpen>(&4).await?;
            for _ in 0..chunks {
                source.send::<p::SourceData>(&()).await?;
                source.offer().await?.recv::<p::SourceAccepted>().await?;
                source.send::<p::SourceTaken>(&()).await?;
            }
            source.send::<p::SourceDataFinished>(&4).await?;
            if abandon {
                source.send::<p::SourceAbandon>(&4).await?;
            } else {
                source.send::<p::SourceFin>(&4).await?;
            }
            let terminal = source.offer().await?;
            if rejected {
                assert_eq!(terminal.recv::<p::SourceEndRejected>().await?, 4);
            } else {
                assert_eq!(terminal.recv::<p::SourceEnded>().await?, 4);
            }
            match illegal {
                1 => assert!(
                    source.send::<p::SourceData>(&()).await.is_err(),
                    "data roll reopened after terminal"
                ),
                2 => assert!(
                    source.send::<p::SourceFin>(&4).await.is_err(),
                    "FIN repeated without a new stream"
                ),
                3 => assert!(
                    source.send::<p::SourceAbandon>(&4).await.is_err(),
                    "abandon repeated after terminal"
                ),
                _ => {
                    source.send::<p::SourceDone>(&()).await?;
                    source.recv::<p::SourceRetired>().await?;
                }
            }
            Ok::<_, EndpointError>(())
        },
        async {
            assert_eq!(ingress.offer().await?.recv::<p::SourceOpen>().await?, 4);
            for _ in 0..chunks {
                ingress.offer().await?.recv::<p::SourceData>().await?;
                ingress.send::<p::SourceAccepted>(&()).await?;
                ingress.recv::<p::SourceTaken>().await?;
            }
            assert_eq!(
                ingress
                    .offer()
                    .await?
                    .recv::<p::SourceDataFinished>()
                    .await?,
                4
            );
            let terminal = ingress.offer().await?;
            if abandon {
                assert_eq!(terminal.recv::<p::SourceAbandon>().await?, 4);
            } else {
                assert_eq!(terminal.recv::<p::SourceFin>().await?, 4);
            }
            if rejected {
                ingress.send::<p::SourceEndRejected>(&4).await?;
            } else {
                ingress.send::<p::SourceEnded>(&4).await?;
            }
            if illegal == 0 {
                ingress.offer().await?.recv::<p::SourceDone>().await?;
                ingress.send::<p::SourceRetired>(&()).await?;
            }
            Ok(())
        }
    ));
    for _ in 0..1000 {
        if let Poll::Ready(result) = all.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            result.unwrap();
            allocation.finish();
            return;
        }
    }
    panic!("stream production did not settle");
}

#[test]
fn empty_and_multi_chunk_streams_finish_or_abandon_without_allocating() {
    for chunks in [0, 1, 8] {
        for abandon in [false, true] {
            for rejected in [false, true] {
                run(chunks, abandon, rejected, 0);
            }
        }
    }
}
#[test]
fn terminal_rejects_data_reentry_duplicate_fin_and_duplicate_abandon() {
    for chunks in [0, 3] {
        for abandon in [false, true] {
            for illegal in 1..=3 {
                run(chunks, abandon, false, illegal);
            }
        }
    }
}

fn stopped_stream_then_next(stop_at_fin: bool) {
    let global = p::source_choreography();
    let source: RoleProgram<{ p::SOURCE }> = project(&global);
    let ingress: RoleProgram<{ p::INGRESS }> = project(&global);
    let carrier = CarrierStorage::<1, 16, 8>::new();
    let mut slab = [0; 65536];
    let mut storage = SessionKitStorage::uninit();
    let id = SessionId::new(910);
    let rv = storage
        .init()
        .rendezvous(&mut slab, carrier.bind(id).unwrap())
        .unwrap();
    let mut source = rv.enter(id, &source).unwrap();
    let mut ingress = rv.enter(id, &ingress).unwrap();
    let allocation = actor_test_allocator::NoAlloc::start();
    let mut all = pin!(join2(
        async {
            source.send::<p::SourceOpen>(&4).await?;
            source.send::<p::SourceData>(&()).await?;
            let reply = source.offer().await?;
            if stop_at_fin {
                reply.recv::<p::SourceAccepted>().await?;
            } else {
                reply.recv::<p::SourceStopped>().await?;
            }
            source.send::<p::SourceTaken>(&()).await?;
            source.send::<p::SourceDataFinished>(&4).await?;
            if stop_at_fin {
                source.send::<p::SourceFin>(&4).await?;
            } else {
                source.send::<p::SourceAbandon>(&4).await?;
            }
            let reply = source.offer().await?;
            if stop_at_fin {
                assert_eq!(reply.recv::<p::SourceEndStopped>().await?, 4);
            } else {
                assert_eq!(reply.recv::<p::SourceEnded>().await?, 4);
            }
            // The finite stopped production ends; the same projected connection
            // admits another stream without resetting or rebuilding its endpoints.
            source.send::<p::SourceOpen>(&8).await?;
            source.send::<p::SourceDataFinished>(&8).await?;
            source.send::<p::SourceFin>(&8).await?;
            assert_eq!(source.offer().await?.recv::<p::SourceEnded>().await?, 8);
            source.send::<p::SourceDone>(&()).await?;
            source.recv::<p::SourceRetired>().await?;
            Ok::<_, EndpointError>(())
        },
        async {
            assert_eq!(ingress.offer().await?.recv::<p::SourceOpen>().await?, 4);
            ingress.offer().await?.recv::<p::SourceData>().await?;
            if stop_at_fin {
                ingress.send::<p::SourceAccepted>(&()).await?;
            } else {
                ingress.send::<p::SourceStopped>(&()).await?;
            }
            ingress.recv::<p::SourceTaken>().await?;
            assert_eq!(
                ingress
                    .offer()
                    .await?
                    .recv::<p::SourceDataFinished>()
                    .await?,
                4
            );
            let end = ingress.offer().await?;
            if stop_at_fin {
                assert_eq!(end.recv::<p::SourceFin>().await?, 4);
                ingress.send::<p::SourceEndStopped>(&4).await?;
            } else {
                assert_eq!(end.recv::<p::SourceAbandon>().await?, 4);
                ingress.send::<p::SourceEnded>(&4).await?;
            }
            assert_eq!(ingress.offer().await?.recv::<p::SourceOpen>().await?, 8);
            assert_eq!(
                ingress
                    .offer()
                    .await?
                    .recv::<p::SourceDataFinished>()
                    .await?,
                8
            );
            assert_eq!(ingress.offer().await?.recv::<p::SourceFin>().await?, 8);
            ingress.send::<p::SourceEnded>(&8).await?;
            ingress.offer().await?.recv::<p::SourceDone>().await?;
            ingress.send::<p::SourceRetired>(&()).await?;
            Ok(())
        }
    ));
    for _ in 0..1000 {
        if let Poll::Ready(result) = all.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            result.unwrap();
            allocation.finish();
            return;
        }
    }
    panic!("stopped production blocked the next stream");
}
#[test]
fn peer_stop_during_data_or_fin_preserves_the_next_stream_continuation() {
    stopped_stream_then_next(false);
    stopped_stream_then_next(true);
}
