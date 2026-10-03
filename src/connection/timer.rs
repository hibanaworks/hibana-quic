// Recovered verbatim from root read-only tool output at 2026-10-03 05:51 UTC.
// Historical handshake prefix only. NOT revalidated after environment loss.
use super::protocol as p;
use super::*;
use core::{future::Future, pin::pin};

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
                slots.schedule.timer_ready.set(true);
                slots.schedule.changed()?;
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

pub(super) async fn take(
    endpoint: &mut Endpoint<'_, { p::TIMER_TX }>,
    schedule: &Schedule,
) -> Result<(), Error> {
    if schedule.timer_ready.replace(false) {
        let sequence = endpoint.recv::<p::TimerExpired>().await?;
        endpoint.send::<p::TimerTaken>(&sequence).await?;
    }
    Ok(())
}
pub(super) async fn retire(
    endpoint: &mut Endpoint<'_, { p::TIMER_TX }>,
    schedule: &Schedule,
) -> Result<(), Error> {
    schedule.stop_timer.set(true);
    schedule.changed()?;
    loop {
        let branch = endpoint.offer().await?;
        match branch.label() {
            141 => {
                let sequence = branch.recv::<p::TimerExpired>().await?;
                schedule.timer_ready.set(false);
                endpoint.send::<p::TimerTaken>(&sequence).await?;
            }
            143 => {
                let sequence = branch.recv::<p::TimerRetired>().await?;
                endpoint.send::<p::TimerAcknowledged>(&sequence).await?;
                return Ok(());
            }
            label => return Err(Error::UnexpectedLabel(label)),
        }
    }
}
