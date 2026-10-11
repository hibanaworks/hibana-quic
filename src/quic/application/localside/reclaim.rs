//! Projected SOURCE_COLLECTOR, INPUT_COLLECTOR and DELIVERY_COLLECTOR roles.
use super::{Control, Error, global as p};
use crate::quic::application::imp::reclaim::Exchange;
use hibana::Endpoint;

fn check(actual: u64, expected: u64) -> Result<(), Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(Error::Binding)
    }
}

pub(super) async fn source(
    endpoint: &mut Endpoint<'_, { p::SOURCE_COLLECTOR }>,
    exchange: &Exchange<'_>,
    control: &Control<'_, '_>,
) -> Result<(), Error> {
    loop {
        let offered = endpoint.offer().await?;
        match offered.label() {
            189 => {
                let id = offered.recv::<p::ProductionReclaim>().await?;
                let receipt = exchange.source.take().map_err(|_| Error::Binding)?;
                check(receipt.origin().id(), id)?;
                exchange.source_received(receipt)?;
                endpoint.send::<p::ProductionStored>(&id).await?;
                control.changed()?;
            }
            191 => {
                offered.recv::<p::ProductionReclaimsDone>().await?;
                endpoint.send::<p::ProductionReclaimsClosed>(&()).await?;
                return Ok(());
            }
            label => return Err(Error::UnexpectedLabel(label)),
        }
    }
}
pub(super) async fn input(
    endpoint: &mut Endpoint<'_, { p::INPUT_COLLECTOR }>,
    exchange: &Exchange<'_>,
    control: &Control<'_, '_>,
) -> Result<(), Error> {
    loop {
        let offered = endpoint.offer().await?;
        match offered.label() {
            193 => {
                let id = offered.recv::<p::InputReclaim>().await?;
                let receipt = exchange.input.take().map_err(|_| Error::Binding)?;
                check(receipt.origin().id(), id)?;
                exchange.input_received(receipt)?;
                endpoint.send::<p::InputStored>(&id).await?;
                control.changed()?;
            }
            195 => {
                let id = offered.recv::<p::NoInputReclaim>().await?;
                endpoint.send::<p::InputStored>(&id).await?;
            }
            196 => {
                offered.recv::<p::InputReclaimsDone>().await?;
                endpoint.send::<p::InputReclaimsClosed>(&()).await?;
                return Ok(());
            }
            label => return Err(Error::UnexpectedLabel(label)),
        }
    }
}
pub(super) async fn delivery(
    endpoint: &mut Endpoint<'_, { p::DELIVERY_COLLECTOR }>,
    exchange: &Exchange<'_>,
    control: &Control<'_, '_>,
) -> Result<(), Error> {
    loop {
        let offered = endpoint.offer().await?;
        match offered.label() {
            198 => {
                let id = offered.recv::<p::DeliveryReclaim>().await?;
                let receipt = exchange.delivery.take().map_err(|_| Error::Binding)?;
                check(receipt.origin().id(), id)?;
                exchange.delivery_received(receipt)?;
                endpoint.send::<p::DeliveryStored>(&id).await?;
                control.changed()?;
            }
            200 => {
                offered.recv::<p::DeliveryReclaimsDone>().await?;
                endpoint.send::<p::DeliveryReclaimsClosed>(&()).await?;
                return Ok(());
            }
            label => return Err(Error::UnexpectedLabel(label)),
        }
    }
}
