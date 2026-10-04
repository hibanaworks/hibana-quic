//! The real publication choreography rejects applying a reset while a datagram
//! is unresolved. An adapter result alone does not replace the Settled edge.
use core::{
    cell::Cell,
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
        resolver::{DecisionArm, ResolverError, ResolverRef},
    },
};
use hibana_quic::{
    carrier::CarrierStorage, connection::application::protocol as p, runtime::join2,
};

fn run(illegal_at: u8, rejected: bool, reset_failed: bool) {
    let global = p::publication_choreography();
    let tx: RoleProgram<{ p::TRANSMIT }> = project(&global);
    let adapter: RoleProgram<{ p::ADAPTER }> = project(&global);
    let carrier = CarrierStorage::<1, 16, 8>::new();
    let mut slab = [0; 65536];
    let decision = Cell::new(Some(if rejected {
        DecisionArm::Right
    } else {
        DecisionArm::Left
    }));
    let reset_decision = Cell::new(if illegal_at == 4 {
        None
    } else {
        Some(if reset_failed {
            DecisionArm::Right
        } else {
            DecisionArm::Left
        })
    });
    let mut storage = SessionKitStorage::uninit();
    let id = SessionId::new(908);
    let rv = storage
        .init()
        .rendezvous(&mut slab, carrier.bind(id).unwrap())
        .unwrap();
    rv.set_resolver(
        &adapter,
        ResolverRef::<{ p::SUBMISSION_RESULT }>::decision_state(&decision, |state| {
            state.get().ok_or_else(ResolverError::reject)
        }),
    )
    .unwrap();
    rv.set_resolver(
        &adapter,
        ResolverRef::<{ p::STOP_RESULT }>::decision_state(&reset_decision, |state| {
            state.get().ok_or_else(ResolverError::reject)
        }),
    )
    .unwrap();
    let mut tx = rv.enter(id, &tx).unwrap();
    let mut adapter = rv.enter(id, &adapter).unwrap();
    let forbidden_rejected = Cell::new(false);
    let allocation = actor_test_allocator::NoAlloc::start();
    let mut all = pin!(join2(
        async {
            tx.send::<p::Datagram>(&0).await?;
            if illegal_at == 1 {
                assert!(
                    tx.send::<p::ApplyStop>(&4).await.is_err(),
                    "reset entered before adapter outcome"
                );
                forbidden_rejected.set(true);
                return Ok(());
            }
            if illegal_at == 5 {
                assert!(tx.send::<p::ApplyAcknowledgments>(&0).await.is_err());
                forbidden_rejected.set(true);
                return Ok(());
            }
            let outcome = tx.offer().await?;
            if rejected {
                assert_eq!(outcome.recv::<p::Rejected>().await?, 0);
            } else {
                assert_eq!(outcome.recv::<p::Accepted>().await?, 0);
            }
            if illegal_at == 2 {
                assert!(
                    tx.send::<p::ApplyStop>(&4).await.is_err(),
                    "reset entered before Settled"
                );
                forbidden_rejected.set(true);
                return Ok(());
            }
            if illegal_at == 6 {
                assert!(tx.send::<p::ApplyAcknowledgments>(&0).await.is_err());
                forbidden_rejected.set(true);
                return Ok(());
            }
            tx.send::<p::Settled>(&0).await?;
            tx.send::<p::ApplyStop>(&4).await?;
            let outcome = tx.offer().await?;
            if reset_failed {
                assert_eq!(outcome.recv::<p::StopFailed>().await?, 4);
            } else {
                assert_eq!(outcome.recv::<p::StopApplied>().await?, 4);
            }
            tx.send::<p::StopSettled>(&4).await?;
            tx.send::<p::ApplyAcknowledgments>(&1).await?;
            assert_eq!(tx.recv::<p::AcknowledgmentsApplied>().await?, 1);
            if illegal_at == 7 {
                assert!(tx.send::<p::Datagram>(&1).await.is_err());
                forbidden_rejected.set(true);
                return Ok(());
            }
            assert_eq!(tx.offer().await?.recv::<p::StreamDelivered>().await?, 4);
            if illegal_at == 8 {
                return Ok(());
            }
            tx.send::<p::StreamDeliverySeen>(&4).await?;
            assert_eq!(tx.offer().await?.recv::<p::DeliveriesDone>().await?, 1);
            tx.send::<p::AcknowledgmentsSettled>(&1).await?;
            tx.send::<p::StopPublication>(&1).await?;
            assert_eq!(tx.recv::<p::PublicationStopped>().await?, 1);
            Ok::<_, EndpointError>(())
        },
        async {
            assert_eq!(adapter.offer().await?.recv::<p::Datagram>().await?, 0);
            if illegal_at == 1 || illegal_at == 5 {
                return Ok(());
            }
            if rejected {
                adapter.send::<p::Rejected>(&0).await?;
            } else {
                adapter.send::<p::Accepted>(&0).await?;
            }
            if illegal_at == 2 || illegal_at == 6 {
                return Ok(());
            }
            assert_eq!(adapter.recv::<p::Settled>().await?, 0);
            assert_eq!(adapter.offer().await?.recv::<p::ApplyStop>().await?, 4);
            if illegal_at == 3 || illegal_at == 4 {
                let wrong = if reset_failed {
                    adapter.send::<p::StopApplied>(&4).await
                } else {
                    adapter.send::<p::StopFailed>(&4).await
                };
                assert!(
                    wrong.is_err(),
                    "the local sender bypassed the reset resolver verdict"
                );
                forbidden_rejected.set(true);
                return Ok(());
            }
            if reset_failed {
                adapter.send::<p::StopFailed>(&4).await?;
            } else {
                adapter.send::<p::StopApplied>(&4).await?;
            }
            assert_eq!(adapter.recv::<p::StopSettled>().await?, 4);
            assert_eq!(
                adapter
                    .offer()
                    .await?
                    .recv::<p::ApplyAcknowledgments>()
                    .await?,
                1
            );
            adapter.send::<p::AcknowledgmentsApplied>(&1).await?;
            if illegal_at == 7 {
                return Ok(());
            }
            adapter.send::<p::StreamDelivered>(&4).await?;
            if illegal_at == 8 {
                assert!(
                    adapter.send::<p::DeliveriesDone>(&1).await.is_err(),
                    "completion batch bypassed the receiver's actual receipt edge"
                );
                forbidden_rejected.set(true);
                return Ok(());
            }
            assert_eq!(adapter.recv::<p::StreamDeliverySeen>().await?, 4);
            adapter.send::<p::DeliveriesDone>(&1).await?;
            assert_eq!(adapter.recv::<p::AcknowledgmentsSettled>().await?, 1);
            assert_eq!(
                adapter.offer().await?.recv::<p::StopPublication>().await?,
                1
            );
            adapter.send::<p::PublicationStopped>(&1).await?;
            Ok(())
        }
    ));
    for _ in 0..1000 {
        if let Poll::Ready(result) = all.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            if illegal_at == 0 {
                result.unwrap();
            } else {
                // A rejected operation poisons the session; the peer may see
                // that fault before consuming the preceding datagram marker.
                assert!(forbidden_rejected.get());
            }
            allocation.finish();
            return;
        }
    }
    panic!("publication/reset fragment stalled");
}

#[test]
fn actual_global_forbids_reset_before_outcome_and_settlement() {
    for rejected in [false, true] {
        for at in [1, 2] {
            run(at, rejected, false);
        }
    }
}
#[test]
fn actual_global_allows_reset_only_after_complete_publication() {
    for rejected in [false, true] {
        for reset_failed in [false, true] {
            run(0, rejected, reset_failed);
        }
    }
}

#[test]
fn independent_reset_resolver_rejects_a_fabricated_opposite_outcome() {
    for rejected in [false, true] {
        for reset_failed in [false, true] {
            run(3, rejected, reset_failed);
        }
    }
}

#[test]
fn missing_reset_verdict_cannot_reuse_the_udp_publication_result() {
    for rejected in [false, true] {
        run(4, rejected, false);
    }
}

#[test]
fn acknowledgment_effects_cannot_cross_an_unsettled_publication() {
    for at in [5, 6, 7] {
        for rejected in [false, true] {
            run(at, rejected, false);
        }
    }
}

#[test]
fn delivery_batch_cannot_finish_before_the_consumer_receives_completion() {
    for rejected in [false, true] {
        run(8, rejected, false);
    }
}
