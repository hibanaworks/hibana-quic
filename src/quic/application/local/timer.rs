//! Deadline progress is independent of a pending UDP publication.
use super::{Control, Error, global as p, keys::KeyOwner};
use crate::quic::Clock;
use crate::quic::imp::recovery;
use hibana::Endpoint;

pub(crate) async fn run<const N: usize>(
    endpoint: &mut Endpoint<'_, { p::CLOCK }>,
    control: &Control<'_, '_>,
    keys: &KeyOwner<'_>,
    book: &mut recovery::Clock<'_, '_, N>,
    clock: &impl Clock,
) -> Result<(), Error> {
    loop {
        if control.stopping() {
            endpoint.send::<p::ClockRetired>(&()).await?;
            endpoint.recv::<p::ClockAcknowledged>().await?;
            return Ok(());
        }
        let revision = control.revision();
        let available = keys.available_levels()?;
        let Some(deadline) = book.update_application(clock.now(), available)? else {
            control.wait(5, revision).await;
            continue;
        };
        if let core::ops::ControlFlow::Break(()) =
            crate::runtime::select(control.wait(5, revision), clock.wait_until(deadline.at())).await
        {
            continue;
        }
        match book.expire(deadline, clock.now()) {
            Ok(Some(_)) => {
                endpoint.send::<p::Expired>(&()).await?;
                endpoint.recv::<p::TimerTaken>().await?;
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
                offered.recv::<p::Expired>().await?;
                endpoint.send::<p::TimerTaken>(&()).await?;
                control.changed()?;
            }
            24 => {
                offered.recv::<p::ClockRetired>().await?;
                endpoint.send::<p::ClockAcknowledged>(&()).await?;
                return Ok(());
            }
            label => return Err(Error::UnexpectedLabel(label)),
        }
        crate::runtime::yield_now().await;
    }
}
