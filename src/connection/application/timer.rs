//! Deadline progress is independent of a pending UDP publication.
use super::{Control, Error, keys::KeyOwner, protocol as p};
use crate::connection::{Clock, recovery};
use core::{
    future::{Future, poll_fn},
    pin::pin,
    task::Poll,
};
use hibana::Endpoint;

pub(crate) async fn run<const N: usize>(
    endpoint: &mut Endpoint<'_, { p::CLOCK }>,
    control: &Control<'_, '_>,
    keys: &KeyOwner<'_>,
    book: &mut recovery::Clock<'_, '_, N>,
    clock: &impl Clock,
) -> Result<(), Error> {
    let mut sequence = 0u64;
    loop {
        if control.stopping() {
            endpoint.send::<p::ClockRetired>(&sequence).await?;
            return check(endpoint.recv::<p::ClockAcknowledged>().await?, sequence);
        }
        let revision = control.revision();
        let available = keys.available_levels()?;
        let Some(deadline) = book.update_application(clock.now(), available)? else {
            control.wait(5, revision).await;
            continue;
        };
        let expired = {
            let mut wait = pin!(clock.wait_until(deadline.at()));
            let mut changed = pin!(control.wait(5, revision));
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
                endpoint.send::<p::Expired>(&sequence).await?;
                check(endpoint.recv::<p::TimerTaken>().await?, sequence)?;
                sequence = sequence.checked_add(1).ok_or(Error::Binding)?;
            }
            Ok(None) | Err(recovery::Error::StaleDeadline) => {}
            Err(error) => return Err(error.into()),
        }
        crate::runtime::yield_now().await;
    }
}

/// This distinct logical facet remains runnable while TRANSMIT waits on UDP.
/// Only after observing the actual timeout edge does it wake packet preparation.
/// No shared endpoint borrow or queued timer frame can block adapter settlement.
pub(crate) async fn receive(
    endpoint: &mut Endpoint<'_, { p::TX_CLOCK }>,
    control: &Control<'_, '_>,
) -> Result<(), Error> {
    loop {
        let offered = endpoint.offer().await?;
        match offered.label() {
            22 => {
                let sequence = offered.recv::<p::Expired>().await?;
                endpoint.send::<p::TimerTaken>(&sequence).await?;
                control.changed()?;
            }
            24 => {
                let sequence = offered.recv::<p::ClockRetired>().await?;
                endpoint.send::<p::ClockAcknowledged>(&sequence).await?;
                return Ok(());
            }
            label => return Err(Error::UnexpectedLabel(label)),
        }
        crate::runtime::yield_now().await;
    }
}

fn check(actual: u64, expected: u64) -> Result<(), Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(Error::Binding)
    }
}
