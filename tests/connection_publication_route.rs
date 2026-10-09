//! A capacity-one reproduction of the real prefix's changing publication arms.
use core::{
    cell::Cell,
    future::Future,
    pin::pin,
    task::{Context, Poll},
};
use hibana::{
    g::{self, Message},
    runtime::{
        SessionKitStorage,
        ids::SessionId,
        program::{RoleProgram, project},
        resolver::{DecisionArm, ResolverError, ResolverRef},
    },
};
use hibana_quic::{
    quic::{application, global as p},
    runtime::carrier::CarrierStorage,
};
use std::{
    sync::Arc,
    task::{Wake, Waker},
};

struct WakeFlag(std::sync::atomic::AtomicBool);
impl Wake for WakeFlag {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

#[test]
fn initial_publication_changes_arms_after_a_parked_offer() {
    for combined in [false, true] {
        for publications in [&[0, 1, 2][..], &[0][..], &[1][..], &[2][..], &[][..]] {
            run_publications(publications, combined);
        }
    }
}

type Publication<P> = g::Seq<
    g::Send<{ p::TX_WIRE }, { p::UDP }, <P as p::Publication>::Datagram>,
    g::Seq<
        g::Resolve<
            g::Route<
                g::Send<{ p::UDP }, { p::TX_WIRE }, <P as p::Publication>::Accepted>,
                g::Send<{ p::UDP }, { p::TX_WIRE }, <P as p::Publication>::Rejected>,
            >,
            { p::ADAPTER_RESULT },
        >,
        g::Send<{ p::TX_WIRE }, { p::UDP }, <P as p::Publication>::Settled>,
    >,
>;
fn publication<P: p::Publication>() -> g::Program<Publication<P>> {
    g::seq(
        g::send::<{ p::TX_WIRE }, { p::UDP }, P::Datagram>(),
        g::seq(
            g::route(
                g::send::<{ p::UDP }, { p::TX_WIRE }, P::Accepted>(),
                g::send::<{ p::UDP }, { p::TX_WIRE }, P::Rejected>(),
            )
            .resolve::<{ p::ADAPTER_RESULT }>(),
            g::send::<{ p::TX_WIRE }, { p::UDP }, P::Settled>(),
        ),
    )
}
fn minimal_programs() -> (RoleProgram<{ p::TX_WIRE }>, RoleProgram<{ p::UDP }>) {
    type Stage = p::InitialTransmit;
    let global =
        g::route(
            publication::<<Stage as p::TransmitPhase>::Data>(),
            g::route(
                publication::<<Stage as p::TransmitPhase>::Ack>(),
                g::route(
                    publication::<<Stage as p::TransmitPhase>::Probe>(),
                    g::seq(
                        g::send::<
                            { p::TX_WIRE },
                            { p::UDP },
                            <Stage as p::TransmitPhase>::WireBoundary,
                        >(),
                        g::send::<
                            { p::UDP },
                            { p::TX_WIRE },
                            <Stage as p::TransmitPhase>::WireBoundarySeen,
                        >(),
                    ),
                ),
            ),
        )
        .roll();
    (project(&global), project(&global))
}

fn run_publications(publications: &[u8], combined: bool) {
    let (sender_program, receiver_program, starter_program) = if combined {
        let programs = application::global::programs();
        (
            programs.handshake.tx_wire,
            programs.handshake.udp,
            Some(programs.handshake.tls_tx),
        )
    } else {
        let (sender, receiver) = minimal_programs();
        (sender, receiver, None)
    };
    let result = Cell::new(None);
    let queues = Box::new(CarrierStorage::<1, 32, 128>::new());
    let mut slab = vec![0; 256 * 1024];
    let mut storage = Box::new(SessionKitStorage::uninit());
    let kit = storage.init();
    let session = SessionId::new(171);
    let rendezvous = kit
        .rendezvous(&mut slab, queues.bind(session).unwrap())
        .unwrap();
    rendezvous
        .set_resolver(
            &receiver_program,
            ResolverRef::<{ p::ADAPTER_RESULT }>::decision_state(&result, |state| {
                state.get().ok_or_else(ResolverError::reject)
            }),
        )
        .unwrap();
    let mut sender = rendezvous.enter(session, &sender_program).unwrap();
    let mut receiver = rendezvous.enter(session, &receiver_program).unwrap();
    let mut starter = starter_program
        .as_ref()
        .map(|program| rendezvous.enter(session, program).unwrap());
    let start = async {
        if let Some(endpoint) = starter.as_mut() {
            endpoint
                .send::<hibana_quic::quic::retry::global::client::Skip>(&())
                .await?;
            endpoint
                .recv::<hibana_quic::quic::retry::global::client::Skipped>()
                .await?;
            endpoint.send::<p::EarlySkip>(&()).await?;
        }
        Ok::<_, hibana::EndpointError>(())
    };
    type Data = <p::InitialTransmit as p::TransmitPhase>::Data;
    type Ack = <p::InitialTransmit as p::TransmitPhase>::Ack;
    type Probe = <p::InitialTransmit as p::TransmitPhase>::Probe;
    type Boundary = <p::InitialTransmit as p::TransmitPhase>::WireBoundary;
    type Seen = <p::InitialTransmit as p::TransmitPhase>::WireBoundarySeen;
    let parked = Cell::new(0);
    let send = async {
        if combined {
            sender.offer().await?.recv::<p::EarlySkip>().await?;
            sender.send::<p::EarlySkip>(&()).await?;
        }
        macro_rules! publish {
            ($pub:ty, $id:expr) => {{
                sender
                    .send::<<$pub as p::Publication>::Datagram>(&())
                    .await?;
                sender.recv::<<$pub as p::Publication>::Accepted>().await?;
                sender
                    .send::<<$pub as p::Publication>::Settled>(&())
                    .await?;
                // The receiver must actually park before the next route choice.
                while parked.get() <= $id {
                    hibana_quic::runtime::yield_now().await;
                }
            }};
        }
        for (id, kind) in publications.iter().enumerate() {
            let id = id as u64;
            match kind {
                0 => publish!(Data, id),
                1 => publish!(Ack, id),
                2 => publish!(Probe, id),
                _ => unreachable!(),
            }
        }
        sender.send::<Boundary>(&()).await?;
        sender.recv::<Seen>().await?;
        Ok::<_, hibana::EndpointError>(())
    };
    let receive = async {
        if combined {
            receiver
                .offer()
                .await?
                .recv::<hibana_quic::quic::retry::global::client::Skip>()
                .await?;
            receiver
                .send::<hibana_quic::quic::retry::global::client::Skipped>(&())
                .await?;
            receiver.offer().await?.recv::<p::EarlySkip>().await?;
        }
        macro_rules! accept {
            ($pub:ty, $id:expr) => {{
                {
                    let mut offer = pin!(receiver.offer());
                    let branch = core::future::poll_fn(|cx| match offer.as_mut().poll(cx) {
                        Poll::Pending => {
                            parked.set($id);
                            Poll::Pending
                        }
                        Poll::Ready(value) => Poll::Ready(value),
                    })
                    .await?;
                    assert_eq!(
                        branch.label(),
                        <$pub as p::Publication>::Datagram::LOGICAL_LABEL
                    );
                    branch.recv::<<$pub as p::Publication>::Datagram>().await?;
                }
                result.set(Some(DecisionArm::Left));
                receiver
                    .send::<<$pub as p::Publication>::Accepted>(&())
                    .await?;
                receiver.recv::<<$pub as p::Publication>::Settled>().await?;
                result.set(None);
            }};
        }
        for (id, kind) in publications.iter().enumerate() {
            let id = id as u64;
            match kind {
                0 => accept!(Data, id),
                1 => accept!(Ack, id),
                2 => accept!(Probe, id),
                _ => unreachable!(),
            }
        }
        let end = publications.len() as u64;
        {
            let mut offer = pin!(receiver.offer());
            let branch = core::future::poll_fn(|cx| match offer.as_mut().poll(cx) {
                Poll::Pending => {
                    parked.set(end);
                    Poll::Pending
                }
                Poll::Ready(value) => Poll::Ready(value),
            })
            .await?;
            assert_eq!(branch.label(), Boundary::LOGICAL_LABEL);
            branch.recv::<Boundary>().await?;
        }
        receiver.send::<Seen>(&()).await?;
        Ok::<_, hibana::EndpointError>(())
    };
    let wake = Arc::new(WakeFlag(std::sync::atomic::AtomicBool::new(true)));
    let waker: Waker = wake.clone().into();
    let mut cx = Context::from_waker(&waker);
    let mut joined = Box::pin(hibana_quic::runtime::join2(
        send,
        hibana_quic::runtime::join2(receive, start),
    ));
    for _ in 0..128 {
        wake.0.store(false, std::sync::atomic::Ordering::SeqCst);
        match joined.as_mut().poll(&mut cx) {
            Poll::Ready(value) => {
                if value.is_err() {
                    for event in rendezvous.tap() {
                        eprintln!("runtime: {event:?}");
                    }
                }
                value.unwrap_or_else(|error| panic!(
                    "Initial publication must retain ownership: combined={combined}, arms={publications:?}, {error:?}"));
                assert_eq!(queues.queued(), 0);
                return;
            }
            Poll::Pending => assert!(
                wake.0.load(std::sync::atomic::Ordering::SeqCst),
                "parked publication must have a real wake"
            ),
        }
    }
    panic!("publication route did not complete within the bounded poll schedule");
}
