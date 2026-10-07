//! Actual projected endpoint tests; these do not claim network qualification.
use super::global as p;
use crate::carrier::CarrierStorage;
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use hibana::runtime::{
    SessionKitStorage,
    ids::SessionId,
    program::{RoleProgram, project},
};

#[derive(Clone, Copy)]
enum Scenario {
    StopProbing,
    ProbeFails,
    Validated,
    ValidationFails,
    RejectReenable,
}

fn run(scenario: Scenario) {
    let global = p::choreography();
    let owner_program: RoleProgram<{ p::OWNER }> = project(&global);
    let publisher_program: RoleProgram<{ p::PUBLISHER }> = project(&global);
    let carrier = CarrierStorage::<1, 16, 16>::new();
    let mut slab = [0; 65536];
    let mut storage = SessionKitStorage::uninit();
    let sid = SessionId::new(1801);
    let rv = storage
        .init()
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    let mut owner = rv.enter(sid, &owner_program).unwrap();
    let mut publisher = rv.enter(sid, &publisher_program).unwrap();
    let allocation = actor_test_allocator::NoAlloc::start();
    let owning = async {
        owner.recv::<p::Request>().await?;
        for mark in [2, 0] {
            owner.send::<p::ProbePermit>(&mark).await?;
            owner.recv::<p::Settled>().await?;
            owner.recv::<p::Request>().await?;
        }
        owner.send::<p::ProbePause>(&()).await?;
        owner.recv::<p::ProbePaused>().await?;
        match scenario {
            Scenario::StopProbing => owner.send::<p::ProbeEnd>(&()).await?,
            Scenario::ProbeFails | Scenario::RejectReenable => {
                owner.send::<p::ProbeFailed>(&()).await?;
                owner.recv::<p::Settled>().await?;
                owner.recv::<p::Request>().await?;
                for _ in 0..2 {
                    owner.send::<p::ProbeFailedPermit>(&()).await?;
                    owner.recv::<p::Settled>().await?;
                    owner.recv::<p::Request>().await?;
                }
                owner.send::<p::ProbeFailedPause>(&()).await?;
                owner.recv::<p::ProbeFailedPaused>().await?;
                if matches!(scenario, Scenario::RejectReenable) {
                    assert!(owner.send::<p::Validated>(&2).await.is_err());
                    return Ok::<(), hibana::EndpointError>(());
                }
                owner.send::<p::ProbeFailedEnd>(&()).await?;
            }
            Scenario::Validated | Scenario::ValidationFails => {
                owner.send::<p::Validated>(&2).await?;
                owner.recv::<p::Settled>().await?;
                owner.recv::<p::Request>().await?;
                for _ in 0..2 {
                    owner.send::<p::CapablePermit>(&2).await?;
                    owner.recv::<p::Settled>().await?;
                    owner.recv::<p::Request>().await?;
                }
                owner.send::<p::CapablePause>(&()).await?;
                owner.recv::<p::CapablePaused>().await?;
                if matches!(scenario, Scenario::ValidationFails) {
                    owner.send::<p::ValidationFailed>(&()).await?;
                    owner.recv::<p::Settled>().await?;
                    owner.recv::<p::Request>().await?;
                    for _ in 0..2 {
                        owner.send::<p::FailedPermit>(&()).await?;
                        owner.recv::<p::Settled>().await?;
                        owner.recv::<p::Request>().await?;
                    }
                    owner.send::<p::FailedPause>(&()).await?;
                    owner.recv::<p::FailedPaused>().await?;
                    owner.send::<p::FailedEnd>(&()).await?;
                } else {
                    owner.send::<p::CapableEnd>(&()).await?;
                }
            }
        }
        owner.recv::<p::Joined>().await?;
        Ok(())
    };
    let publishing = async {
        publisher.send::<p::Request>(&()).await?;
        loop {
            let offered = publisher.offer().await?;
            match offered.label() {
                100 => {
                    let mark = offered.recv::<p::ProbePermit>().await?;
                    assert!(mark == 0 || mark == 2);
                    publisher.send::<p::Settled>(&()).await?;
                    publisher.send::<p::Request>(&()).await?;
                }
                103 => {
                    offered.recv::<p::Validated>().await?;
                    publisher.send::<p::Settled>(&()).await?;
                    publisher.send::<p::Request>(&()).await?;
                }
                106 => {
                    offered.recv::<p::CapablePermit>().await?;
                    publisher.send::<p::Settled>(&()).await?;
                    publisher.send::<p::Request>(&()).await?;
                }
                107 => {
                    offered.recv::<p::ProbeFailed>().await?;
                    publisher.send::<p::Settled>(&()).await?;
                    publisher.send::<p::Request>(&()).await?;
                }
                110 => {
                    offered.recv::<p::ProbeFailedPermit>().await?;
                    publisher.send::<p::Settled>(&()).await?;
                    publisher.send::<p::Request>(&()).await?;
                }
                112 => {
                    offered.recv::<p::ValidationFailed>().await?;
                    publisher.send::<p::Settled>(&()).await?;
                    publisher.send::<p::Request>(&()).await?;
                }
                115 => {
                    offered.recv::<p::FailedPermit>().await?;
                    publisher.send::<p::Settled>(&()).await?;
                    publisher.send::<p::Request>(&()).await?;
                }
                120 => {
                    offered.recv::<p::ProbePause>().await?;
                    publisher.send::<p::ProbePaused>(&()).await?;
                }
                122 => {
                    offered.recv::<p::CapablePause>().await?;
                    publisher.send::<p::CapablePaused>(&()).await?;
                }
                124 => {
                    offered.recv::<p::ProbeFailedPause>().await?;
                    publisher.send::<p::ProbeFailedPaused>(&()).await?;
                    if matches!(scenario, Scenario::RejectReenable) {
                        return Ok(());
                    }
                    publisher.recv::<p::ProbeFailedEnd>().await?;
                    break;
                }
                126 => {
                    offered.recv::<p::FailedPause>().await?;
                    publisher.send::<p::FailedPaused>(&()).await?;
                    publisher.recv::<p::FailedEnd>().await?;
                    break;
                }
                111 => {
                    offered.recv::<p::ProbeFailedEnd>().await?;
                    break;
                }
                116 => {
                    offered.recv::<p::FailedEnd>().await?;
                    break;
                }
                117 => {
                    offered.recv::<p::ProbeEnd>().await?;
                    break;
                }
                118 => {
                    offered.recv::<p::CapableEnd>().await?;
                    break;
                }
                label => panic!("unexpected ECN label {label}"),
            }
        }
        publisher.send::<p::Joined>(&()).await?;
        Ok(())
    };
    let mut task = pin!(async { futures_util::try_join!(owning, publishing) });
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..1024 {
        if let Poll::Ready(result) = task.as_mut().poll(&mut cx) {
            result.unwrap();
            drop(allocation);
            return;
        }
    }
    panic!("ECN projected lifetime did not join");
}
#[test]
fn probe_can_retire_without_claiming_validation() {
    run(Scenario::StopProbing);
}
#[test]
fn probe_failure_stays_disabled_and_joins() {
    run(Scenario::ProbeFails);
}
#[test]
fn actual_validation_continuation_can_retire() {
    run(Scenario::Validated);
}
#[test]
fn later_validation_failure_disables_and_joins() {
    run(Scenario::ValidationFails);
}
#[test]
fn failed_projection_rejects_reenable() {
    run(Scenario::RejectReenable);
}
