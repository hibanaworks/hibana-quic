//! The upstream containing-visit contract on QUIC's real capacity-one carrier.
//! This transport regression is separate from the full connection/UDP tests.
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll},
};
use hibana::{
    g::{self, Msg},
    runtime::{
        SessionKitStorage,
        ids::SessionId,
        program::{RoleProgram, project},
    },
};
use hibana_quic::carrier::CarrierStorage;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Wake, Waker},
};

type Connected = Msg<128, ()>;
type ConnectedAck = Msg<129, ()>;
type Sample = Msg<110, [u8; 7]>;
type Retained = Msg<111, [u8; 7]>;
type Failed = Msg<130, u16>;
type FailureRetained = Msg<131, u16>;
type Disconnected = Msg<134, u16>;
type DisconnectedAck = Msg<135, u16>;

type SampleVisit = g::Seq<g::Send<0, 1, Sample>, g::Send<1, 0, Retained>>;
type FailureVisit = g::Seq<g::Send<0, 1, Failed>, g::Send<1, 0, FailureRetained>>;
type ConnectedVisit = g::Seq<
    g::Send<0, 1, Connected>,
    g::Seq<g::Send<1, 0, ConnectedAck>, g::Roll<g::Route<SampleVisit, FailureVisit>>>,
>;
type DisconnectedVisit = g::Seq<g::Send<0, 1, Disconnected>, g::Send<1, 0, DisconnectedAck>>;
type Visits = g::Roll<g::Route<ConnectedVisit, DisconnectedVisit>>;

fn choreography() -> g::Program<Visits> {
    g::route(
        g::seq(
            g::send::<0, 1, Connected>(),
            g::seq(
                g::send::<1, 0, ConnectedAck>(),
                g::route(
                    g::seq(g::send::<0, 1, Sample>(), g::send::<1, 0, Retained>()),
                    g::seq(
                        g::send::<0, 1, Failed>(),
                        g::send::<1, 0, FailureRetained>(),
                    ),
                )
                .roll(),
            ),
        ),
        g::seq(
            g::send::<0, 1, Disconnected>(),
            g::send::<1, 0, DisconnectedAck>(),
        ),
    )
    .roll()
}

struct WakeFlag(AtomicBool);
impl Wake for WakeFlag {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
}

macro_rules! with_endpoints {
    ($global:expr, |$source:ident, $receiver:ident| $trace:expr) => {{
        let global = $global;
        let source_program: RoleProgram<0> = project(&global);
        let receiver_program: RoleProgram<1> = project(&global);
        let queues = Box::new(CarrierStorage::<1, 32, 128>::new());
        let mut slab = vec![0; 256 * 1024];
        let mut storage = Box::new(SessionKitStorage::uninit());
        let kit = storage.init();
        let session = SessionId::new(192);
        let rendezvous = kit
            .rendezvous(&mut slab, queues.bind(session).unwrap())
            .unwrap();
        let mut $source = rendezvous.enter(session, &source_program).unwrap();
        let mut $receiver = rendezvous.enter(session, &receiver_program).unwrap();
        let wake = Arc::new(WakeFlag(AtomicBool::new(true)));
        let waker: Waker = wake.clone().into();
        let mut cx = Context::from_waker(&waker);
        let mut future = pin!($trace);
        let mut done = false;
        for _ in 0..128 {
            wake.0.store(false, Ordering::SeqCst);
            match future.as_mut().poll(&mut cx) {
                Poll::Ready(()) => {
                    done = true;
                    break;
                }
                Poll::Pending => assert!(
                    wake.0.load(Ordering::SeqCst),
                    "the sequential trace must make progress or have a real wake"
                ),
            }
        }
        assert!(done, "nested visit exceeded its bounded poll schedule");
        assert_eq!(
            queues.queued(),
            0,
            "no duplicate or unconsumed carrier frame"
        );
    }};
}

#[test]
fn completed_samples_keep_the_connection_prefix_for_failure_ack() {
    for samples in [0, 1, 3] {
        with_endpoints!(choreography(), |source, receiver| async {
            source.send::<Connected>(&()).await.unwrap();
            receiver
                .offer()
                .await
                .unwrap()
                .recv::<Connected>()
                .await
                .unwrap();
            receiver.send::<ConnectedAck>(&()).await.unwrap();
            source.recv::<ConnectedAck>().await.unwrap();
            for index in 0..samples {
                let frame = [index; 7];
                source.send::<Sample>(&frame).await.unwrap();
                assert_eq!(
                    receiver
                        .offer()
                        .await
                        .unwrap()
                        .recv::<Sample>()
                        .await
                        .unwrap(),
                    frame
                );
                receiver.send::<Retained>(&frame).await.unwrap();
                assert_eq!(source.recv::<Retained>().await.unwrap(), frame);
            }
            source.send::<Failed>(&1).await.unwrap();
            assert_eq!(
                receiver
                    .offer()
                    .await
                    .unwrap()
                    .recv::<Failed>()
                    .await
                    .unwrap(),
                1
            );
            receiver.send::<FailureRetained>(&1).await.unwrap();
            assert_eq!(source.recv::<FailureRetained>().await.unwrap(), 1);
            // Only an actual new enclosing visit permits replacing its prefix.
            source.send::<Disconnected>(&2).await.unwrap();
            assert_eq!(
                receiver
                    .offer()
                    .await
                    .unwrap()
                    .recv::<Disconnected>()
                    .await
                    .unwrap(),
                2
            );
            receiver.send::<DisconnectedAck>(&2).await.unwrap();
            assert_eq!(source.recv::<DisconnectedAck>().await.unwrap(), 2);
            source.send::<Connected>(&()).await.unwrap();
            receiver
                .offer()
                .await
                .unwrap()
                .recv::<Connected>()
                .await
                .unwrap();
            receiver.send::<ConnectedAck>(&()).await.unwrap();
            source.recv::<ConnectedAck>().await.unwrap();
            source.send::<Failed>(&3).await.unwrap();
            assert_eq!(
                receiver
                    .offer()
                    .await
                    .unwrap()
                    .recv::<Failed>()
                    .await
                    .unwrap(),
                3
            );
            receiver.send::<FailureRetained>(&3).await.unwrap();
            assert_eq!(source.recv::<FailureRetained>().await.unwrap(), 3);
        });
    }
}

#[test]
fn an_unretained_sample_cannot_authorize_the_failure_arm() {
    with_endpoints!(choreography(), |source, receiver| async {
        source.send::<Connected>(&()).await.unwrap();
        receiver
            .offer()
            .await
            .unwrap()
            .recv::<Connected>()
            .await
            .unwrap();
        receiver.send::<ConnectedAck>(&()).await.unwrap();
        source.recv::<ConnectedAck>().await.unwrap();
        source.send::<Sample>(&[1; 7]).await.unwrap();
        receiver
            .offer()
            .await
            .unwrap()
            .recv::<Sample>()
            .await
            .unwrap();
        assert!(source.send::<Failed>(&1).await.is_err());
    });
}

#[test]
fn completed_failure_cannot_authorize_a_duplicate_retention_ack() {
    with_endpoints!(choreography(), |source, receiver| async {
        source.send::<Connected>(&()).await.unwrap();
        receiver
            .offer()
            .await
            .unwrap()
            .recv::<Connected>()
            .await
            .unwrap();
        receiver.send::<ConnectedAck>(&()).await.unwrap();
        source.recv::<ConnectedAck>().await.unwrap();
        source.send::<Failed>(&1).await.unwrap();
        receiver
            .offer()
            .await
            .unwrap()
            .recv::<Failed>()
            .await
            .unwrap();
        receiver.send::<FailureRetained>(&1).await.unwrap();
        source.recv::<FailureRetained>().await.unwrap();
        assert!(receiver.send::<FailureRetained>(&1).await.is_err());
    });
}

#[test]
fn parallel_right_lane_reentry_preserves_the_enclosing_prefix() {
    type Left = Msg<110, u16>;
    type LeftAck = Msg<111, u16>;
    type Right = Msg<112, u16>;
    type RightAck = Msg<113, u16>;
    let global = g::route(
        g::seq(
            g::send::<0, 1, Connected>(),
            g::seq(
                g::send::<1, 0, ConnectedAck>(),
                g::route(
                    g::par(
                        g::seq(g::send::<0, 1, Left>(), g::send::<1, 0, LeftAck>()),
                        g::seq(g::send::<0, 1, Right>(), g::send::<1, 0, RightAck>()),
                    ),
                    g::seq(
                        g::send::<0, 1, Failed>(),
                        g::send::<1, 0, FailureRetained>(),
                    ),
                )
                .roll(),
            ),
        ),
        g::seq(
            g::send::<0, 1, Disconnected>(),
            g::send::<1, 0, DisconnectedAck>(),
        ),
    )
    .roll();
    with_endpoints!(global, |source, receiver| async {
        source.send::<Connected>(&()).await.unwrap();
        receiver
            .offer()
            .await
            .unwrap()
            .recv::<Connected>()
            .await
            .unwrap();
        receiver.send::<ConnectedAck>(&()).await.unwrap();
        source.recv::<ConnectedAck>().await.unwrap();
        source.send::<Left>(&1).await.unwrap();
        assert_eq!(
            receiver
                .offer()
                .await
                .unwrap()
                .recv::<Left>()
                .await
                .unwrap(),
            1
        );
        receiver.send::<LeftAck>(&1).await.unwrap();
        assert_eq!(source.recv::<LeftAck>().await.unwrap(), 1);
        source.send::<Right>(&1).await.unwrap();
        assert_eq!(receiver.recv::<Right>().await.unwrap(), 1);
        receiver.send::<RightAck>(&1).await.unwrap();
        assert_eq!(source.recv::<RightAck>().await.unwrap(), 1);
        source.send::<Right>(&2).await.unwrap();
        assert_eq!(receiver.recv::<Right>().await.unwrap(), 2);
        receiver.send::<RightAck>(&2).await.unwrap();
        assert_eq!(source.recv::<RightAck>().await.unwrap(), 2);
        source.send::<Left>(&2).await.unwrap();
        assert_eq!(receiver.recv::<Left>().await.unwrap(), 2);
        receiver.send::<LeftAck>(&2).await.unwrap();
        assert_eq!(source.recv::<LeftAck>().await.unwrap(), 2);
        source.send::<Failed>(&3).await.unwrap();
        assert_eq!(
            receiver
                .offer()
                .await
                .unwrap()
                .recv::<Failed>()
                .await
                .unwrap(),
            3
        );
        receiver.send::<FailureRetained>(&3).await.unwrap();
        assert_eq!(source.recv::<FailureRetained>().await.unwrap(), 3);
    });
}
