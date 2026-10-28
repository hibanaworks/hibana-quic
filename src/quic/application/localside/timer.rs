//! Deadline progress is independent of a pending UDP publication.
use super::{Control, Error, global as p};
use crate::quic::Clock;
use crate::quic::application::imp::keys::KeyOwner;
use crate::quic::imp::recovery;
use core::{ops::ControlFlow, pin::pin};
use hibana::Endpoint;

pub(crate) async fn run<const N: usize>(
    endpoint: &mut Endpoint<'_, { p::CLOCK }>,
    control: &Control<'_, '_>,
    keys: &KeyOwner<'_>,
    book: &mut recovery::Clock<'_, '_, N>,
    clock: &impl Clock,
) -> Result<(), Error> {
    {
        let [mut notice, mut timer] = endpoint.par()?;
        let mut stopped = pin!(notice.recv::<p::StopClock>());
        loop {
            let expired = crate::runtime::select(stopped.as_mut(), async {
                let revision = control.revision();
                let available = keys.available_levels()?;
                let Some(deadline) = book.update_application(clock.now(), available)? else {
                    control.wait(5, revision).await;
                    return Ok::<_, Error>(None);
                };
                if let ControlFlow::Break(()) = crate::runtime::select(
                    control.wait(5, revision),
                    clock.wait_until(deadline.at()),
                )
                .await
                {
                    return Ok(None);
                }
                match book.expire(deadline, clock.now()) {
                    Ok(value) => Ok(value),
                    Err(recovery::Error::StaleDeadline) => Ok(None),
                    Err(error) => Err(error.into()),
                }
            })
            .await;
            match expired {
                ControlFlow::Break(result) => {
                    result?;
                    break;
                }
                ControlFlow::Continue(result) => {
                    if result?.is_some() {
                        timer.send::<p::Expired>(&()).await?;
                        timer.recv::<p::TimerTaken>().await?;
                    }
                }
            }
            crate::runtime::yield_now().await;
        }
        timer.send::<p::ClockRetired>(&()).await?;
    }
    endpoint.recv::<p::ClockAcknowledged>().await?;
    Ok(())
}

/// Receive timer notifications independently of packet submission.
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
