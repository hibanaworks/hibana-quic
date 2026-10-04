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
    carrier::CarrierStorage, connection::application::protocol as p, runtime::join2,
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
            for n in 0..chunks as u64 {
                source.send::<p::SourceData>(&n).await?;
                assert_eq!(source.offer().await?.recv::<p::SourceAccepted>().await?, n);
                source.send::<p::SourceTaken>(&n).await?;
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
                    source.send::<p::SourceData>(&99).await.is_err(),
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
                    source.send::<p::SourceDone>(&(chunks as u64)).await?;
                    assert_eq!(source.recv::<p::SourceRetired>().await?, chunks as u64);
                }
            }
            Ok::<_, EndpointError>(())
        },
        async {
            assert_eq!(ingress.offer().await?.recv::<p::SourceOpen>().await?, 4);
            for n in 0..chunks as u64 {
                assert_eq!(ingress.offer().await?.recv::<p::SourceData>().await?, n);
                ingress.send::<p::SourceAccepted>(&n).await?;
                assert_eq!(ingress.recv::<p::SourceTaken>().await?, n);
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
                assert_eq!(
                    ingress.offer().await?.recv::<p::SourceDone>().await?,
                    chunks as u64
                );
                ingress.send::<p::SourceRetired>(&(chunks as u64)).await?;
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
