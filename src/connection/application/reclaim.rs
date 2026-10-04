//! Three independent projected receipt lanes join actual owned stream resources.
//! Correlation uses the complete table/slot/generation identity, never a phase enum.
use super::{Control, Error, protocol as p};
use crate::connection::{
    application_stream::{
        DeliveryReleased, InputReleased, MAX_LIVE_STREAMS, Origin, ProductionReleased,
    },
    tls::Inbox,
};
use core::cell::{Cell, RefCell};
use hibana::Endpoint;

struct Slot<'book> {
    source: Option<ProductionReleased<'book>>,
    input: Option<InputReleased<'book>>,
    delivery: Option<DeliveryReleased<'book>>,
}
impl Slot<'_> {
    const EMPTY: Self = Self {
        source: None,
        input: None,
        delivery: None,
    };
    fn check(&self, origin: Origin<'_>) -> Result<(), Error> {
        if self
            .source
            .as_ref()
            .is_some_and(|v| !v.origin().same(origin))
            || self
                .input
                .as_ref()
                .is_some_and(|v| !v.origin().same(origin))
            || self
                .delivery
                .as_ref()
                .is_some_and(|v| !v.origin().same(origin))
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
}
pub(crate) struct Joined<'book> {
    source: ProductionReleased<'book>,
    input: InputReleased<'book>,
    delivery: DeliveryReleased<'book>,
}
impl<'book> Joined<'book> {
    pub(crate) fn new(
        source: ProductionReleased<'book>,
        input: InputReleased<'book>,
        delivery: DeliveryReleased<'book>,
    ) -> Result<Self, Error> {
        if !source.origin().same(input.origin()) || !source.origin().same(delivery.origin()) {
            return Err(Error::Binding);
        }
        Ok(Self {
            source,
            input,
            delivery,
        })
    }

    pub(super) fn id(&self) -> u64 {
        self.source.origin().id()
    }
    pub(crate) fn into_parts(
        self,
    ) -> (
        ProductionReleased<'book>,
        InputReleased<'book>,
        DeliveryReleased<'book>,
    ) {
        (self.source, self.input, self.delivery)
    }
}
pub(super) struct Exchange<'book> {
    pub(super) source: Inbox<ProductionReleased<'book>>,
    pub(super) input: Inbox<InputReleased<'book>>,
    pub(super) delivery: Inbox<DeliveryReleased<'book>>,
    pub(super) applying: Inbox<Joined<'book>>,
    slots: RefCell<[Slot<'book>; MAX_LIVE_STREAMS]>,
    cursor: Cell<usize>,
}
impl<'book> Exchange<'book> {
    pub(super) const fn new() -> Self {
        Self {
            source: Inbox::new(),
            input: Inbox::new(),
            delivery: Inbox::new(),
            applying: Inbox::new(),
            slots: RefCell::new([const { Slot::EMPTY }; MAX_LIVE_STREAMS]),
            cursor: Cell::new(0),
        }
    }
    fn source_received(&self, receipt: ProductionReleased<'book>) -> Result<(), Error> {
        let origin = receipt.origin();
        let mut slots = self.slots.try_borrow_mut().map_err(|_| Error::Binding)?;
        let slot = slots.get_mut(origin.slot()).ok_or(Error::Capacity)?;
        slot.check(origin)?;
        if slot.source.is_some() {
            return Err(Error::Binding);
        }
        slot.source = Some(receipt);
        Ok(())
    }
    fn input_received(&self, receipt: InputReleased<'book>) -> Result<(), Error> {
        let origin = receipt.origin();
        let mut slots = self.slots.try_borrow_mut().map_err(|_| Error::Binding)?;
        let slot = slots.get_mut(origin.slot()).ok_or(Error::Capacity)?;
        slot.check(origin)?;
        if slot.input.is_some() {
            return Err(Error::Binding);
        }
        slot.input = Some(receipt);
        Ok(())
    }
    fn delivery_received(&self, receipt: DeliveryReleased<'book>) -> Result<(), Error> {
        let origin = receipt.origin();
        let mut slots = self.slots.try_borrow_mut().map_err(|_| Error::Binding)?;
        let slot = slots.get_mut(origin.slot()).ok_or(Error::Capacity)?;
        slot.check(origin)?;
        if slot.delivery.is_some() {
            return Err(Error::Binding);
        }
        slot.delivery = Some(receipt);
        Ok(())
    }
    pub(super) fn stage(
        &self,
        mut storage_free: impl FnMut(Origin<'book>) -> Result<bool, Error>,
    ) -> Result<Option<u64>, Error> {
        if !self.applying.is_empty() {
            return Err(Error::Binding);
        }
        let mut slots = self.slots.try_borrow_mut().map_err(|_| Error::Binding)?;
        for offset in 0..MAX_LIVE_STREAMS {
            let index = (self.cursor.get() + offset) % MAX_LIVE_STREAMS;
            let slot = &mut slots[index];
            let Some(source) = slot.source.as_ref() else {
                continue;
            };
            if slot.input.is_none() || slot.delivery.is_none() || !storage_free(source.origin())? {
                continue;
            }
            let joined = Joined::new(
                slot.source.take().ok_or(Error::Binding)?,
                slot.input.take().ok_or(Error::Binding)?,
                slot.delivery.take().ok_or(Error::Binding)?,
            )?;
            let id = joined.id();
            self.applying.put(joined).map_err(|_| Error::Binding)?;
            self.cursor.set((index + 1) % MAX_LIVE_STREAMS);
            return Ok(Some(id));
        }
        Ok(None)
    }
}
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
                check(offered.recv::<p::ProductionReclaimsDone>().await?, 0)?;
                endpoint.send::<p::ProductionReclaimsClosed>(&0).await?;
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
                check(offered.recv::<p::InputReclaimsDone>().await?, 0)?;
                endpoint.send::<p::InputReclaimsClosed>(&0).await?;
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
                check(offered.recv::<p::DeliveryReclaimsDone>().await?, 0)?;
                endpoint.send::<p::DeliveryReclaimsClosed>(&0).await?;
                return Ok(());
            }
            label => return Err(Error::UnexpectedLabel(label)),
        }
    }
}
