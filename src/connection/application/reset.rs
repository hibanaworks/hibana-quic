//! Authenticated stop observations wait in bounded owned slots. Only the
//! projected publication boundary can authorize their application: no receive
//! callback or publication-completion callback secretly advances reset state.
use super::Error;
use crate::connection::{
    application_stream::{MAX_LIVE_STREAMS, StopIntent},
    tls::Inbox,
};
use core::cell::RefCell;

pub(crate) struct Exchange<'book> {
    pending: RefCell<[Option<StopIntent<'book>>; MAX_LIVE_STREAMS]>,
    pub(super) applying: Inbox<StopIntent<'book>>,
}
impl<'book> Exchange<'book> {
    pub(crate) const fn new() -> Self {
        Self {
            pending: RefCell::new([const { None }; MAX_LIVE_STREAMS]),
            applying: Inbox::new(),
        }
    }
    pub(crate) fn observe(&self, intent: StopIntent<'book>) -> Result<(), Error> {
        let mut pending = self.pending.try_borrow_mut().map_err(|_| Error::Binding)?;
        let slot = pending.get_mut(intent.slot()).ok_or(Error::Capacity)?;
        if let Some(first) = slot {
            if !first.same_stream(&intent) {
                return Err(Error::Binding);
            }
            // Repeated peer STOP_SENDING retains the first error code.
        } else {
            *slot = Some(intent);
        }
        Ok(())
    }
    pub(crate) fn stage(&self) -> Result<Option<u64>, Error> {
        let intent = self
            .pending
            .try_borrow_mut()
            .map_err(|_| Error::Binding)?
            .iter_mut()
            .find_map(Option::take);
        let Some(intent) = intent else {
            return Ok(None);
        };
        let id = intent.id();
        self.applying.put(intent).map_err(|_| Error::Binding)?;
        Ok(Some(id))
    }
    pub(crate) fn cancel_pending(&self) -> Result<(), Error> {
        if !self.applying.is_empty() {
            return Err(Error::Binding);
        }
        for intent in self
            .pending
            .try_borrow_mut()
            .map_err(|_| Error::Binding)?
            .iter_mut()
        {
            *intent = None;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        connection::application_stream::{Facets, StreamNumbers},
        crypto::directional::ApplicationKeyScope,
        packet::{EncryptionLevel, Frame, FrameIter, ParseLimits},
        streams::{Limits, PacketReference, Role, SendChunk, StreamSlot},
    };

    fn exercise(cancel: bool) {
        let scope = ApplicationKeyScope::new(900);
        let limits = Limits {
            max_data: 8,
            max_streams_bidi: 1,
            max_streams_uni: 0,
            stream_data_bidi_local: 8,
            stream_data_bidi_remote: 8,
            stream_data_uni: 0,
        };
        let mut slots = [StreamSlot::<8>::EMPTY; 2];
        let mut chunks = [SendChunk::<8>::EMPTY];
        let mut refs = [PacketReference::EMPTY; 4];
        let mut numbers = StreamNumbers::new(
            &scope,
            Role::Client,
            limits,
            limits,
            &mut slots,
            &mut chunks,
            &mut refs,
        )
        .unwrap();
        let Facets {
            mut app,
            mut rx,
            tx,
            mut reset,
            ..
        } = numbers.split();
        let stream = app.open_local().unwrap();
        let exchange = Exchange::new();
        let allocations = actor_test_allocator::NoAlloc::start();
        exchange
            .observe(rx.stop_intent(stream.id(), 7).unwrap())
            .unwrap();
        exchange
            .observe(rx.stop_intent(stream.id(), 9).unwrap())
            .unwrap();
        assert!(
            tx.prepare::<64>(false).unwrap().is_none(),
            "observation is not reset authority"
        );
        if cancel {
            exchange.cancel_pending().unwrap();
            assert_eq!(exchange.stage().unwrap(), None);
            assert!(tx.prepare::<64>(false).unwrap().is_none());
        } else {
            assert_eq!(exchange.stage().unwrap(), Some(stream.id()));
            reset.apply(exchange.applying.take().unwrap()).unwrap();
            assert_eq!(
                exchange.stage().unwrap(),
                None,
                "duplicate observation was not coalesced"
            );
            let prepared = tx.prepare::<64>(false).unwrap().unwrap();
            let frame = FrameIter::new(
                prepared.bytes(),
                EncryptionLevel::OneRtt,
                ParseLimits::default(),
            )
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
            assert!(matches!(
                frame,
                Frame::ResetStream {
                    id: 0,
                    error_code: 7,
                    final_size: 0
                }
            ));
        }
        allocations.finish();
    }
    #[test]
    fn foreign_table_stop_is_rejected_even_with_identical_numeric_handles() {
        let scope = ApplicationKeyScope::new(901);
        let limits = Limits {
            max_data: 8,
            max_streams_bidi: 1,
            max_streams_uni: 0,
            stream_data_bidi_local: 8,
            stream_data_bidi_remote: 8,
            stream_data_uni: 0,
        };
        let mut sa = [StreamSlot::<8>::EMPTY; 2];
        let mut ca = [SendChunk::<8>::EMPTY];
        let mut ra = [PacketReference::EMPTY; 4];
        let mut sb = [StreamSlot::<8>::EMPTY; 2];
        let mut cb = [SendChunk::<8>::EMPTY];
        let mut rb = [PacketReference::EMPTY; 4];
        let mut a = StreamNumbers::new(
            &scope,
            Role::Client,
            limits,
            limits,
            &mut sa,
            &mut ca,
            &mut ra,
        )
        .unwrap();
        let mut b = StreamNumbers::new(
            &scope,
            Role::Client,
            limits,
            limits,
            &mut sb,
            &mut cb,
            &mut rb,
        )
        .unwrap();
        let mut a = a.split();
        let mut b = b.split();
        let ha = a.app.open_local().unwrap();
        let hb = b.app.open_local().unwrap();
        assert_eq!(ha, hb);
        let exchange = Exchange::new();
        let allocations = actor_test_allocator::NoAlloc::start();
        exchange
            .observe(a.rx.stop_intent(ha.id(), 7).unwrap())
            .unwrap();
        assert!(
            exchange
                .observe(b.rx.stop_intent(hb.id(), 9).unwrap())
                .is_err()
        );
        assert!(
            b.reset
                .apply(a.rx.stop_intent(ha.id(), 7).unwrap())
                .is_err()
        );
        assert!(b.tx.prepare::<64>(false).unwrap().is_none());
        assert_eq!(exchange.stage().unwrap(), Some(ha.id()));
        a.reset.apply(exchange.applying.take().unwrap()).unwrap();
        assert!(a.tx.prepare::<64>(false).unwrap().is_some());
        assert!(b.tx.prepare::<64>(false).unwrap().is_none());
        allocations.finish();
    }

    #[test]
    fn first_stop_observation_is_retained_without_applying_it() {
        exercise(false);
    }
    #[test]
    fn connection_retirement_discards_unapplied_observations_without_publishing() {
        exercise(true);
    }
}
