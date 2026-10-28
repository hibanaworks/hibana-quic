//! A capacity-one reproduction of the real prefix's changing publication arms.
use core::{cell::Cell, future::Future, pin::pin, task::Poll};
use hibana::runtime::program::Projectable;
use hibana::{
    g::{self, Message},
    runtime::{
        SessionKitStorage,
        ids::SessionId,
        program::{RoleProgram, project},
        resolver::{DecisionArm, ResolverError, ResolverRef},
        transport::EndpointBinding,
    },
};
use hibana_quic::{
    quic::{application, global as p},
    runtime::carrier::CarrierStorage,
};
#[tokio::test(flavor = "current_thread")]
async fn initial_publication_changes_arms_after_a_parked_offer() {
    for combined in [false, true] {
        for publications in [&[0, 1, 2][..], &[0][..], &[1][..], &[2][..], &[][..]] {
            run_publications(publications, combined).await;
        }
    }
}

fn publication<P: p::Publication>() -> impl Projectable {
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

async fn run_publications(publications: &[u8], combined: bool) {
    let (sender_program, receiver_program, starter_program, owner_program, keys_program) =
        if combined {
            let projection = application::global::choreography();
            (
                project(&projection),
                project(&projection),
                Some(project::<{ p::TLS_TX }>(&projection)),
                Some(project::<{ p::TX }>(&projection)),
                Some(project::<{ p::WRITE_KEYS }>(&projection)),
            )
        } else {
            let (sender, receiver) = minimal_programs();
            (sender, receiver, None, None, None)
        };
    let result = Cell::new(None);
    let queues = Box::new(CarrierStorage::<1, 32, 128>::new());
    let mut slab = vec![0; 256 * 1024];
    let session = SessionId::new(171);
    // SAFETY: this fixture has one publication resource and one initial issuer.
    let binding = unsafe { EndpointBinding::new() };
    let issuers = [(p::WRITE_KEYS, &binding)];
    let queues_binding = queues
        .bind(session, if combined { &issuers } else { &[] })
        .unwrap();
    let mut storage = Box::new(SessionKitStorage::uninit());
    let kit = storage.init();
    let rendezvous = kit.rendezvous(&mut slab, &queues_binding).unwrap();
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
    let mut owner = owner_program
        .as_ref()
        .map(|program| rendezvous.enter(session, program).unwrap());
    let keys = keys_program
        .as_ref()
        .map(|program| rendezvous.enter(session, program).unwrap());
    let lend = async {
        match (owner.as_mut(), keys) {
            (Some(owner), Some(keys)) => owner.send::<p::PacketKeys<'_>>(keys).await?,
            (None, None) => {}
            _ => unreachable!("the combined fixture attaches both owner and resource"),
        }
        Ok::<_, hibana::EndpointError>(())
    };
    let start = async {
        if let Some(endpoint) = starter.as_mut() {
            endpoint
                .send::<hibana_quic::quic::retry::global::client::Skip>(&())
                .await?;
            endpoint
                .recv::<hibana_quic::quic::retry::global::client::Skipped>()
                .await?;
            endpoint.send::<p::EarlySkip>(&()).await?;
            endpoint.recv::<p::EarlyDone>().await?;
        }
        Ok::<_, hibana::EndpointError>(())
    };
    type Data = <p::InitialTransmit as p::TransmitPhase>::Data;
    type Ack = <p::InitialTransmit as p::TransmitPhase>::Ack;
    type Probe = <p::InitialTransmit as p::TransmitPhase>::Probe;
    type Boundary = <p::InitialTransmit as p::TransmitPhase>::WireBoundary;
    type Seen = <p::InitialTransmit as p::TransmitPhase>::WireBoundarySeen;
    let parked = Cell::new(0);
    macro_rules! publish {
        ($endpoint:ident, $pub:ty, $id:expr) => {{
            $endpoint
                .send::<<$pub as p::Publication>::Datagram>(&())
                .await?;
            $endpoint
                .recv::<<$pub as p::Publication>::Accepted>()
                .await?;
            $endpoint
                .send::<<$pub as p::Publication>::Settled>(&())
                .await?;
            while parked.get() <= $id {
                hibana_quic::runtime::yield_now().await;
            }
        }};
    }
    macro_rules! publications {
        ($endpoint:ident) => {{
            for (id, kind) in publications.iter().enumerate() {
                let id = id as u64;
                match kind {
                    0 => publish!($endpoint, Data, id),
                    1 => publish!($endpoint, Ack, id),
                    2 => publish!($endpoint, Probe, id),
                    _ => unreachable!(),
                }
            }
            $endpoint.send::<Boundary>(&()).await?;
            $endpoint.recv::<Seen>().await?;
        }};
    }
    let send = async {
        if combined {
            sender.offer().await?.recv::<p::EarlySkip>().await?;
            sender.send::<p::EarlySkip>(&()).await?;
            sender.recv::<p::EarlySettled>().await?;
            sender.send::<p::EarlyDone>(&()).await?;
            let mut keys = sender.recv::<p::PacketKeys<'_>>().await?;
            let [mut keys] = keys.par()?;
            let [_input, mut output] = keys.par()?;
            publications!(output);
            // This is a prefix check. The unexecuted TLS input is dropped only
            // after the publication boundary and its reply have completed.
        } else {
            publications!(sender);
        }
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
            receiver.send::<p::EarlySettled>(&()).await?;
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
    let joined = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        tokio::try_join!(send, receive, start, lend)
    })
    .await
    .expect("publication route stalled");
    if joined.is_err() {
        for event in rendezvous.tap() {
            eprintln!("runtime: {event:?}");
        }
    }
    joined.unwrap_or_else(|error| {
        panic!(
            "Initial publication must retain ownership: combined={combined}, arms={publications:?}, {error:?}"
        )
    });
    assert_eq!(queues.queued(), 0);
}
