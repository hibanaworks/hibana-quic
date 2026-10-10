//! Capacity-one execution of the actual server Retry admission graph.
//! This tests projected order; native token and socket evidence is separate.
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
        resolver::{DecisionArm, ResolverError, ResolverRef},
    },
};
use hibana_quic::{quic::retry::global as p, runtime::carrier::CarrierStorage, runtime::join2};

fn run(outcomes: &[Option<bool>], wrong_reply: bool) {
    let verdict = Cell::new(None);
    let graph = p::choreography();
    let input_program = hibana::runtime::program::project::<{ p::INPUT }, _>(&graph);
    let owner_program = hibana::runtime::program::project::<{ p::OWNER }, _>(&graph);
    let output_program = hibana::runtime::program::project::<{ p::OUTPUT }, _>(&graph);
    let carrier = CarrierStorage::<1, 16, 8>::new();
    let mut slab = [0; 65536];
    let mut kit = SessionKitStorage::uninit();
    let sid = SessionId::new(1100);
    let session = kit
        .init()
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    session
        .set_resolver(
            &output_program,
            ResolverRef::<{ p::SEND_RESULT }>::decision_state(&verdict, |value| {
                value.get().ok_or_else(ResolverError::reject)
            }),
        )
        .unwrap();
    let mut input = session.enter(sid, &input_program).unwrap();
    let mut owner = session.enter(sid, &owner_program).unwrap();
    let mut output = session.enter(sid, &output_program).unwrap();
    let rejected = Cell::new(false);
    let settled = Cell::new(0usize);
    let observed = Cell::new(0usize);
    let allocation = actor_test_allocator::NoAlloc::start();
    let mut all = pin!(join2(
        async {
            input.send::<p::Observed>(&()).await?;
            loop {
                let offered = input.offer().await?;
                match offered.label() {
                    4 => {
                        offered.recv::<p::Settled>().await?;
                        settled.set(settled.get() + 1);
                    }
                    5 => {
                        offered.recv::<p::Ignored>().await?;
                    }
                    6 => {
                        offered.recv::<p::Admitted>().await?;
                        input.recv::<p::Joined>().await?;
                        return Ok::<(), EndpointError>(());
                    }
                    _ => panic!("unexpected input branch"),
                }
                input.send::<p::Observed>(&()).await?;
            }
        },
        join2(
            async {
                owner.recv::<p::Observed>().await?;
                observed.set(1);
                for outcome in outcomes {
                    if let Some(sent) = outcome {
                        owner.send::<p::Datagram>(&()).await?;
                        let reply = owner.offer().await?;
                        if *sent {
                            reply.recv::<p::Sent>().await?;
                        } else {
                            reply.recv::<p::Rejected>().await?;
                        }
                        owner.send::<p::Settled>(&()).await?;
                    } else {
                        owner.send::<p::NoSend>(&()).await?;
                        owner.recv::<p::NoSendSeen>().await?;
                        owner.send::<p::Ignored>(&()).await?;
                    }
                    owner.recv::<p::Observed>().await?;
                    observed.set(observed.get() + 1);
                }
                owner.send::<p::Admitted>(&()).await?;
                owner.send::<p::Stop>(&()).await?;
                owner.recv::<p::Stopped>().await?;
                owner.send::<p::Joined>(&()).await?;
                Ok(())
            },
            async {
                for outcome in outcomes {
                    let Some(sent) = outcome else {
                        output.offer().await?.recv::<p::NoSend>().await?;
                        output.send::<p::NoSendSeen>(&()).await?;
                        continue;
                    };
                    output.offer().await?.recv::<p::Datagram>().await?;
                    verdict.set(Some(if *sent {
                        DecisionArm::Left
                    } else {
                        DecisionArm::Right
                    }));
                    if wrong_reply {
                        let result = if *sent {
                            output.send::<p::Rejected>(&()).await
                        } else {
                            output.send::<p::Sent>(&()).await
                        };
                        assert!(
                            result.is_err(),
                            "send result bypassed the actual resolver verdict"
                        );
                        rejected.set(true);
                        return Ok(());
                    }
                    if *sent {
                        output.send::<p::Sent>(&()).await?;
                    } else {
                        output.send::<p::Rejected>(&()).await?;
                    }
                    verdict.set(None);
                }
                output.offer().await?.recv::<p::Stop>().await?;
                output.send::<p::Stopped>(&()).await?;
                Ok(())
            },
        ),
    ));
    for _ in 0..2000 {
        if let Poll::Ready(result) = all.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            if wrong_reply {
                assert!(rejected.get());
            } else {
                result.unwrap();
                assert_eq!(observed.get(), outcomes.len() + 1);
                assert_eq!(settled.get(), outcomes.iter().flatten().count());
                assert_eq!(carrier.queued(), 0);
            }
            allocation.finish();
            return;
        }
    }
    panic!("Retry admission did not settle");
}

#[test]
fn rejected_ignored_and_accepted_rounds_join_before_admission() {
    for rounds in [
        &[][..],
        &[None][..],
        &[Some(true)][..],
        &[Some(false), None, Some(true), None, Some(false)][..],
    ] {
        run(rounds, false);
    }
}

#[test]
fn adapter_cannot_fabricate_the_opposite_send_result() {
    run(&[Some(true)], true);
    run(&[Some(false)], true);
}
