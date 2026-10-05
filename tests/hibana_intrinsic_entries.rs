//! Upstream 4d0077b9 entry-selection histories on the QUIC bounded carrier.
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
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
fn run(f: impl Future<Output = ()>) {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..4096 {
        if let Poll::Ready(()) = f.as_mut().poll(&mut cx) {
            return;
        }
    }
    panic!("bounded local histories unexpectedly parked");
}
#[test]
fn completed_read_then_normal_return_uses_the_outer_entry_with_the_reused_contract() {
    let global = g::route(
        g::seq(
            g::send::<0, 1, Msg<90, ()>>(),
            g::route(
                g::seq(
                    g::send::<1, 0, Msg<91, ()>>(),
                    g::send::<0, 1, Msg<92, ()>>(),
                ),
                g::seq(
                    g::send::<1, 0, Msg<93, ()>>(),
                    g::seq(
                        g::send::<0, 1, Msg<94, ()>>(),
                        g::send::<1, 0, Msg<95, ()>>(),
                    ),
                ),
            ),
        ),
        g::seq(
            g::send::<0, 1, Msg<94, ()>>(),
            g::send::<1, 0, Msg<95, ()>>(),
        ),
    )
    .roll();
    let p0: RoleProgram<0> = project(&global);
    let p1: RoleProgram<1> = project(&global);
    for reads in [0, 1, 2, 64] {
        let carrier = CarrierStorage::<1, 16, 8>::new();
        let mut slab = [0; 65536];
        let mut storage = SessionKitStorage::uninit();
        let kit = storage
            .init()
            .rendezvous(&mut slab, carrier.bind(SessionId::new(40)).unwrap())
            .unwrap();
        let mut requester = kit.enter(SessionId::new(40), &p0).unwrap();
        let mut source = kit.enter(SessionId::new(40), &p1).unwrap();
        run(async {
            for _ in 0..reads {
                requester.send::<Msg<90, ()>>(&()).await.unwrap();
                source
                    .offer()
                    .await
                    .unwrap()
                    .recv::<Msg<90, ()>>()
                    .await
                    .unwrap();
                source.send::<Msg<91, ()>>(&()).await.unwrap();
                requester
                    .offer()
                    .await
                    .unwrap()
                    .recv::<Msg<91, ()>>()
                    .await
                    .unwrap();
                requester.send::<Msg<92, ()>>(&()).await.unwrap();
                source.recv::<Msg<92, ()>>().await.unwrap();
            }
            requester.send::<Msg<94, ()>>(&()).await.unwrap();
            source
                .offer()
                .await
                .unwrap()
                .recv::<Msg<94, ()>>()
                .await
                .unwrap();
            source.send::<Msg<95, ()>>(&()).await.unwrap();
            requester.recv::<Msg<95, ()>>().await.unwrap();
        });
    }
}

#[test]
fn an_unfinished_read_cannot_take_the_normal_return_entry() {
    let global = g::route(
        g::seq(
            g::send::<0, 1, Msg<90, ()>>(),
            g::route(
                g::seq(
                    g::send::<1, 0, Msg<91, ()>>(),
                    g::send::<0, 1, Msg<92, ()>>(),
                ),
                g::seq(
                    g::send::<1, 0, Msg<93, ()>>(),
                    g::seq(
                        g::send::<0, 1, Msg<94, ()>>(),
                        g::send::<1, 0, Msg<95, ()>>(),
                    ),
                ),
            ),
        ),
        g::seq(
            g::send::<0, 1, Msg<94, ()>>(),
            g::send::<1, 0, Msg<95, ()>>(),
        ),
    )
    .roll();
    let p0: RoleProgram<0> = project(&global);
    let p1: RoleProgram<1> = project(&global);
    let carrier = CarrierStorage::<1, 16, 8>::new();
    let mut slab = [0; 65536];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage
        .init()
        .rendezvous(&mut slab, carrier.bind(SessionId::new(40)).unwrap())
        .unwrap();
    let mut requester = kit.enter(SessionId::new(40), &p0).unwrap();
    let mut source = kit.enter(SessionId::new(40), &p1).unwrap();
    run(async {
        requester.send::<Msg<90, ()>>(&()).await.unwrap();
        source
            .offer()
            .await
            .unwrap()
            .recv::<Msg<90, ()>>()
            .await
            .unwrap();
        assert!(requester.send::<Msg<94, ()>>(&()).await.is_err());
    });
}

#[test]
fn intrinsic_choice_can_start_with_either_nested_arm_and_reenter() {
    let global = g::route(
        g::route(g::send::<0, 1, Msg<1, ()>>(), g::send::<0, 1, Msg<2, ()>>()),
        g::send::<0, 1, Msg<3, ()>>(),
    )
    .roll();
    let p0: RoleProgram<0> = project(&global);
    let p1: RoleProgram<1> = project(&global);
    let carrier = CarrierStorage::<1, 16, 8>::new();
    let mut slab = [0; 65536];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage
        .init()
        .rendezvous(&mut slab, carrier.bind(SessionId::new(40)).unwrap())
        .unwrap();
    let mut sender = kit.enter(SessionId::new(40), &p0).unwrap();
    let mut receiver = kit.enter(SessionId::new(40), &p1).unwrap();
    run(async {
        for label in [2, 1, 3, 2, 3, 1] {
            match label {
                1 => sender.send::<Msg<1, ()>>(&()).await.unwrap(),
                2 => sender.send::<Msg<2, ()>>(&()).await.unwrap(),
                3 => sender.send::<Msg<3, ()>>(&()).await.unwrap(),
                _ => unreachable!(),
            }
            let branch = receiver.offer().await.unwrap();
            assert_eq!(branch.label(), label);
            match label {
                1 => branch.recv::<Msg<1, ()>>().await.unwrap(),
                2 => branch.recv::<Msg<2, ()>>().await.unwrap(),
                3 => branch.recv::<Msg<3, ()>>().await.unwrap(),
                _ => unreachable!(),
            }
        }
    });
}
