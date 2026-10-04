//! Deadline progress is independent of a pending UDP publication.
use super::protocol as p;
use super::*;
use core::{future::Future, pin::pin};
use hibana::g::Message;

pub(super) async fn run<const N: usize, const P: usize>(
    endpoint: &mut Endpoint<'_, { p::TIMER }>,
    slots: &Storage<'_, '_, N, P>,
    book: &mut recovery::Clock<'_, '_, N>,
    clock: &impl Clock,
) -> Result<(), Error> {
    let mut sequence = 0u64;
    loop {
        if slots.schedule.stop_timer.get() {
            endpoint.send::<p::TimerRetired>(&sequence).await?;
            if endpoint.recv::<p::TimerAcknowledged>().await? != sequence {
                return Err(Error::Binding);
            }
            return Ok(());
        }
        let revision = slots.schedule.revision.get();
        let Some(deadline) = book.update(clock.now(), slots.schedule.keys.get())? else {
            slots.schedule.wait_changed(2, revision).await;
            continue;
        };
        let expired = {
            let mut wait = pin!(clock.wait_until(deadline.at()));
            let mut changed = pin!(slots.schedule.wait_changed(2, revision));
            poll_fn(|cx| {
                if changed.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(false);
                }
                wait.as_mut().poll(cx).map(|()| true)
            })
            .await
        };
        if !expired {
            continue;
        }
        match book.expire(deadline, clock.now()) {
            Ok(Some(_)) => {
                endpoint.send::<p::TimerExpired>(&sequence).await?;
                if endpoint.recv::<p::TimerTaken>().await? != sequence {
                    return Err(Error::Binding);
                }
                sequence = sequence.checked_add(1).ok_or(Error::Binding)?;
            }
            Ok(None) | Err(recovery::Error::StaleDeadline) => {}
            Err(error) => return Err(error.into()),
        }
        crate::runtime::yield_now().await;
    }
}

/// Keep the timer facet runnable while TX waits for UDP settlement. The
/// numeric expiry has already been committed when its projected edge arrives;
/// acknowledging that edge releases the timer before waking packet preparation.
pub(super) async fn receive(
    endpoint: &mut Endpoint<'_, { p::TIMER_TX }>,
    schedule: &Schedule,
) -> Result<(), Error> {
    loop {
        let branch = endpoint.offer().await?;
        match branch.label() {
            label if label == p::TimerExpired::LOGICAL_LABEL => {
                let sequence = branch.recv::<p::TimerExpired>().await?;
                endpoint.send::<p::TimerTaken>(&sequence).await?;
                schedule.changed()?;
            }
            label if label == p::TimerRetired::LOGICAL_LABEL => {
                let sequence = branch.recv::<p::TimerRetired>().await?;
                endpoint.send::<p::TimerAcknowledged>(&sequence).await?;
                return Ok(());
            }
            label => return Err(Error::UnexpectedLabel(label)),
        }
        crate::runtime::yield_now().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::carrier::CarrierStorage;
    use core::{
        future::pending,
        task::{Context, Waker},
    };
    use hibana::{
        g,
        runtime::{
            SessionKitStorage,
            ids::SessionId,
            program::{RoleProgram, project},
        },
    };

    struct PendingUdp;
    impl DatagramTx for PendingUdp {
        async fn send(&mut self, _bytes: &[u8]) -> Result<u64, IoError> {
            pending().await
        }
    }

    #[test]
    fn expiry_and_retirement_progress_while_udp_publication_is_pending() {
        let global = g::route(
            g::seq(
                g::send::<{ p::TIMER }, { p::TIMER_TX }, p::TimerExpired>(),
                g::send::<{ p::TIMER_TX }, { p::TIMER }, p::TimerTaken>(),
            ),
            g::seq(
                g::send::<{ p::TIMER }, { p::TIMER_TX }, p::TimerRetired>(),
                g::send::<{ p::TIMER_TX }, { p::TIMER }, p::TimerAcknowledged>(),
            ),
        )
        .roll();
        let producer_program: RoleProgram<{ p::TIMER }> = project(&global);
        let receiver_program: RoleProgram<{ p::TIMER_TX }> = project(&global);
        let carrier = CarrierStorage::<1, 16, 128>::new();
        let mut slab = [0; 262144];
        let mut kit = SessionKitStorage::uninit();
        let sid = SessionId::new(1);
        let rendezvous = kit
            .init()
            .rendezvous(&mut slab, carrier.bind(sid).unwrap())
            .unwrap();
        let mut producer_endpoint = rendezvous.enter(sid, &producer_program).unwrap();
        let mut receiver_endpoint = rendezvous.enter(sid, &receiver_program).unwrap();
        let schedule = Schedule::new();
        let mut udp = PendingUdp;
        let mut publication = pin!(udp.send(&[0]));
        let mut producer = pin!(async {
            for sequence in 0..3u64 {
                producer_endpoint
                    .send::<p::TimerExpired>(&sequence)
                    .await
                    .unwrap();
                assert_eq!(
                    producer_endpoint.recv::<p::TimerTaken>().await.unwrap(),
                    sequence
                );
            }
            producer_endpoint.send::<p::TimerRetired>(&3).await.unwrap();
            assert_eq!(
                producer_endpoint
                    .recv::<p::TimerAcknowledged>()
                    .await
                    .unwrap(),
                3
            );
        });
        let mut receiver = pin!(receive(&mut receiver_endpoint, &schedule));
        let mut cx = Context::from_waker(Waker::noop());
        let mut producer_done = false;
        let mut receiver_done = false;
        for _ in 0..128 {
            assert!(publication.as_mut().poll(&mut cx).is_pending());
            if !producer_done {
                producer_done = producer.as_mut().poll(&mut cx).is_ready();
            }
            if !receiver_done {
                if let Poll::Ready(result) = receiver.as_mut().poll(&mut cx) {
                    result.unwrap();
                    receiver_done = true;
                }
            }
            if producer_done && receiver_done {
                break;
            }
        }
        assert!(
            producer_done && receiver_done,
            "timer progress depends on stalled UDP"
        );
        assert_eq!(
            schedule.revision.get(),
            3,
            "each observed expiry must wake packet preparation"
        );
        assert!(publication.as_mut().poll(&mut cx).is_pending());
    }
}
