//! A scoped elastic-reentry fixture, not full Stream endpoint qualification.
//!
//! This preserves the real labels/directions and the completed bootstrap roll,
//! current early roll, and required cancellation attempt. The full production
//! occurrence-aware negatives are recorded in external-stream-diagnostic's
//! source-linked formal execution; a raw label cannot identify an occurrence.
#![allow(long_running_const_eval)]
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use hibana::{
    EndpointError, g,
    runtime::{
        SessionKitStorage,
        ids::SessionId,
        program::{Projectable, project},
    },
};
use hibana_quic::{carrier::CarrierStorage, roles::protocol_stream as p};

fn result() -> g::Program<p::OperationResult<0, 1>> {
    g::seq(
        g::route(
            g::send::<1, 0, p::Applied>(),
            g::send::<1, 0, p::Rejected>(),
        ),
        g::send::<0, 1, p::ResultTaken>(),
    )
}
fn graph() -> impl Projectable {
    let bootstrap = g::route(
        g::seq(g::send::<0, 1, p::Inspect>(), result()),
        g::send::<0, 1, p::EarlySendReady>(),
    )
    .roll();
    let reservations = g::route(
        g::seq(g::send::<0, 1, p::Reserve>(), result()),
        g::seq(g::send::<0, 1, p::CancelPrepared>(), result()),
    )
    .roll();
    let prepared = g::seq(
        g::send::<0, 1, p::PrepareEarly>(),
        g::seq(
            g::send::<1, 0, p::FramePrepared>(),
            g::seq(
                g::send::<0, 1, p::ResultTaken>(),
                g::seq(reservations, g::send::<1, 0, p::SelectionCancelled>()),
            ),
        ),
    );
    let early = g::route(g::seq(g::send::<0, 1, p::Inspect>(), result()), prepared).roll();
    g::seq(
        bootstrap,
        g::seq(
            g::send::<1, 0, p::EarlySendInstalled>(),
            g::seq(g::send::<0, 1, p::ResultTaken>(), early),
        ),
    )
}
fn step<T>(tag: &str, future: impl Future<Output = Result<T, EndpointError>>) -> T {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(Ok(value)) => value,
        Poll::Ready(Err(error)) => panic!("{tag}: {error:?}"),
        Poll::Pending => {
            panic!("{tag}: unexpectedly pending with the peer's frame already available")
        }
    }
}
fn scenario(cancel_without_attempt: bool) {
    let carrier = CarrierStorage::<1, 16, 4>::new();
    let mut slab = [0; 65536];
    let mut storage = SessionKitStorage::uninit();
    let sid = SessionId::new(994);
    let rendezvous = storage
        .init()
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    let global = graph();
    let cp = project::<0, _>(&global);
    let op = project::<1, _>(&global);
    let mut client = rendezvous.enter(sid, &cp).unwrap();
    let mut owner = rendezvous.enter(sid, &op).unwrap();
    let wire = [0; 16];
    step(
        "send EarlySendReady",
        client.send::<p::EarlySendReady>(&wire),
    );
    let branch = step("offer EarlySendReady", owner.offer());
    assert_eq!(branch.label(), p::EARLY_SEND_READY);
    step("receive EarlySendReady", branch.recv::<p::EarlySendReady>());
    step(
        "send EarlySendInstalled",
        owner.send::<p::EarlySendInstalled>(&wire),
    );
    step(
        "receive EarlySendInstalled",
        client.recv::<p::EarlySendInstalled>(),
    );
    step("send ResultTaken", client.send::<p::ResultTaken>(&wire));
    step("receive ResultTaken", owner.recv::<p::ResultTaken>());
    step("send PrepareEarly", client.send::<p::PrepareEarly>(&wire));
    step("receive PrepareEarly", owner.recv::<p::PrepareEarly>());
    step("send FramePrepared", owner.send::<p::FramePrepared>(&wire));
    step("receive FramePrepared", client.recv::<p::FramePrepared>());
    step(
        "send prepared ResultTaken",
        client.send::<p::ResultTaken>(&wire),
    );
    step(
        "receive prepared ResultTaken",
        owner.recv::<p::ResultTaken>(),
    );
    if cancel_without_attempt {
        let mut suffix = pin!(owner.send::<p::SelectionCancelled>(&wire));
        assert!(
            matches!(
                suffix
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Err(_))
            ),
            "completed older rolls cannot discharge a zero-attempt reservation suffix"
        );
        return;
    }
    // Inspect is legal through the completed bootstrap roll. It does not grant
    // authority to mutate a Stream owner or settle its current preparation.
    step(
        "send completed-bootstrap Inspect",
        client.send::<p::Inspect>(&wire),
    );
    let branch = step("offer completed-bootstrap Inspect", owner.offer());
    assert_eq!(branch.label(), p::INSPECT);
    step(
        "receive completed-bootstrap Inspect",
        branch.recv::<p::Inspect>(),
    );
    step("send Inspect result", owner.send::<p::Applied>(&wire));
    let branch = step("offer Inspect result", client.offer());
    assert_eq!(branch.label(), p::APPLIED);
    step("receive Inspect result", branch.recv::<p::Applied>());
    step("send Inspect receipt", client.send::<p::ResultTaken>(&wire));
    step("receive Inspect receipt", owner.recv::<p::ResultTaken>());
    step(
        "send required CancelPrepared",
        client.send::<p::CancelPrepared>(&wire),
    );
    let branch = step("offer required CancelPrepared", owner.offer());
    assert_eq!(branch.label(), p::CANCEL_PREPARED);
    step("receive CancelPrepared", branch.recv::<p::CancelPrepared>());
    step("send cancellation result", owner.send::<p::Applied>(&wire));
    let branch = step("offer cancellation result", client.offer());
    assert_eq!(branch.label(), p::APPLIED);
    step("receive cancellation result", branch.recv::<p::Applied>());
    step(
        "send cancellation receipt",
        client.send::<p::ResultTaken>(&wire),
    );
    step(
        "receive cancellation receipt",
        owner.recv::<p::ResultTaken>(),
    );
    step(
        "send SelectionCancelled",
        owner.send::<p::SelectionCancelled>(&wire),
    );
    step(
        "receive SelectionCancelled",
        client.recv::<p::SelectionCancelled>(),
    );
}
#[test]
fn scoped_completed_bootstrap_reentry_keeps_current_cancellation_obligation() {
    scenario(false);
}
#[test]
fn scoped_preparation_cannot_skip_every_reservation_attempt() {
    scenario(true);
}
