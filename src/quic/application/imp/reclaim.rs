//! Correlation and affine joining of owned stream release receipts.
use crate::quic::application::Error;
use crate::quic::application::imp::stream::{
    DeliveryReleased, InputReleased, MAX_LIVE_STREAMS, Origin, ProductionReleased,
};
use crate::quic::imp::tls::Inbox;
use core::cell::{Cell, RefCell};
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
pub(in crate::quic) struct Joined<'book> {
    source: ProductionReleased<'book>,
    input: InputReleased<'book>,
    delivery: DeliveryReleased<'book>,
}
impl<'book> Joined<'book> {
    pub(in crate::quic) fn new(
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

    pub(in crate::quic::application) fn id(&self) -> u64 {
        self.source.origin().id()
    }
    pub(in crate::quic) fn into_parts(
        self,
    ) -> (
        ProductionReleased<'book>,
        InputReleased<'book>,
        DeliveryReleased<'book>,
    ) {
        (self.source, self.input, self.delivery)
    }
}
pub(in crate::quic::application) struct Exchange<'book> {
    pub(in crate::quic::application) source: Inbox<ProductionReleased<'book>>,
    pub(in crate::quic::application) input: Inbox<InputReleased<'book>>,
    pub(in crate::quic::application) delivery: Inbox<DeliveryReleased<'book>>,
    pub(in crate::quic::application) applying: Inbox<Joined<'book>>,
    slots: RefCell<[Slot<'book>; MAX_LIVE_STREAMS]>,
    cursor: Cell<usize>,
}
impl<'book> Exchange<'book> {
    pub(in crate::quic::application) const fn new() -> Self {
        Self {
            source: Inbox::new(),
            input: Inbox::new(),
            delivery: Inbox::new(),
            applying: Inbox::new(),
            slots: RefCell::new([const { Slot::EMPTY }; MAX_LIVE_STREAMS]),
            cursor: Cell::new(0),
        }
    }
    pub(in crate::quic::application) fn source_received(
        &self,
        receipt: ProductionReleased<'book>,
    ) -> Result<(), Error> {
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
    pub(in crate::quic::application) fn input_received(
        &self,
        receipt: InputReleased<'book>,
    ) -> Result<(), Error> {
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
    pub(in crate::quic::application) fn delivery_received(
        &self,
        receipt: DeliveryReleased<'book>,
    ) -> Result<(), Error> {
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
    pub(in crate::quic::application) fn stage(
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
