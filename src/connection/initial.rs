//! Finite Initial key-space ownership. Actual Handshake evidence revokes both
//! Initial directions and pending Initial-only publication before ledger discard.
use super::{protocol as p, recovery, tls::Inbox, wire, *};
use core::cell::Ref;
use hibana::g::Message;

pub(super) struct Keys<'scope> {
    scope: &'scope ApplicationKeyScope,
    read: RefCell<Option<ReceivePacketKey<'scope>>>,
    write: RefCell<Option<crypto::PacketKey>>,
    publication_waker: RefCell<Option<Waker>>,
}
impl<'scope> Keys<'scope> {
    pub fn new(
        scope: &'scope ApplicationKeyScope,
        read: crypto::PacketKey,
        write: crypto::PacketKey,
    ) -> Result<Self, Error> {
        if write.kind() != crypto::KeyKind::Initial {
            return Err(Error::Binding);
        }
        write.ensure_active()?;
        Ok(Self {
            scope,
            read: RefCell::new(Some(ReceivePacketKey::from_initial(scope, read)?)),
            write: RefCell::new(Some(write)),
            publication_waker: RefCell::new(None),
        })
    }
    pub fn available(&self) -> bool {
        self.write.borrow().is_some()
    }
    /// This guard is used only within the synchronous packet-open block.
    pub fn read(&self) -> Ref<'_, Option<ReceivePacketKey<'scope>>> {
        self.read.borrow()
    }
    pub fn seal<'book, const N: usize>(
        &self,
        plain: wire::PlainPacket<N>,
        reservation: recovery::Reservation<'book>,
        ack: Option<recovery::AckSnapshot<'book>>,
    ) -> Result<wire::Datagram<'book, N>, (Error, recovery::Reservation<'book>)> {
        if !core::ptr::eq(self.scope, reservation.scope()) {
            return Err((Error::Binding, reservation));
        }
        let mut key = self.write.borrow_mut();
        match key.as_mut() {
            Some(key) => plain.seal_initial(key, reservation, ack),
            None => Err((Error::UnsupportedLevel, reservation)),
        }
    }
    fn revoke(&self, evidence: &recovery::InitialRetirement<'scope>) -> Result<(), Error> {
        if !core::ptr::eq(self.scope, evidence.scope()) {
            return Err(Error::Binding);
        }
        let read = self.read.borrow_mut().take();
        let write = self.write.borrow_mut().take();
        drop(read);
        drop(write);
        let wake = self.publication_waker.borrow_mut().take();
        if let Some(wake) = wake {
            wake.wake();
        }
        Ok(())
    }
    /// None means the actual adapter future was dropped without acceptance.
    /// A Ready result from the same poll is authoritative even if its callback
    /// triggered revocation; Pending promises that no acceptance happened.
    pub async fn submit<F: Future>(&self, future: F) -> Option<F::Output> {
        let mut future = pin!(future);
        poll_fn(|cx| {
            if !self.available() {
                return Poll::Ready(None);
            }
            let next = cx.waker().clone();
            let old = self.publication_waker.borrow_mut().replace(next);
            drop(old);
            if !self.available() {
                return Poll::Ready(None);
            }
            match future.as_mut().poll(cx) {
                Poll::Ready(result) => Poll::Ready(Some(result)),
                Poll::Pending if !self.available() => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            }
        })
        .await
    }
}

pub(super) struct Exchange<'scope> {
    event: Inbox<recovery::InitialRetirement<'scope>>,
    retired: Inbox<recovery::InitialRetired<'scope>>,
}
impl<'scope> Exchange<'scope> {
    pub fn new() -> Self {
        Self {
            event: Inbox::new(),
            retired: Inbox::new(),
        }
    }
}
/// Called in the actual server RX/client publication future at its event site.
pub(super) async fn announce<'scope>(
    endpoint: &mut Endpoint<'_, { p::INITIAL_EVENT }>,
    exchange: &Exchange<'scope>,
    evidence: recovery::InitialRetirement<'scope>,
) -> Result<(), Error> {
    let scope = evidence.scope();
    let event = evidence.event();
    exchange.event.put(evidence)?;
    match event {
        recovery::InitialRetirementEvent::ClientHandshakeAccepted => {
            endpoint.send::<p::ClientInitialRetire>(&0).await?
        }
        recovery::InitialRetirementEvent::ServerHandshakeAuthenticated => {
            endpoint.send::<p::ServerInitialRetire>(&0).await?
        }
    }
    if endpoint.recv::<p::InitialRetired>().await? != 0 {
        return Err(Error::Binding);
    }
    let proof = exchange.retired.take()?;
    if !core::ptr::eq(proof.scope(), scope) || proof.event() != event {
        return Err(Error::Binding);
    }
    Ok(())
}
pub(super) async fn retire<'scope, const N: usize>(
    endpoint: &mut Endpoint<'_, { p::INITIAL_OWNER }>,
    keys: &Keys<'scope>,
    exchange: &Exchange<'scope>,
    schedule: &Schedule,
    owner: &mut recovery::InitialRetirementOwner<'_, 'scope, N>,
    side: Side,
) -> Result<(), Error> {
    let offered = endpoint.offer().await.map_err(|error| Error::EndpointAt {
        role: p::INITIAL_OWNER,
        expected_label: match side {
            Side::Client => p::ClientInitialRetire::LOGICAL_LABEL,
            Side::Server => p::ServerInitialRetire::LOGICAL_LABEL,
        },
        error,
    })?;
    let event = match offered.label() {
        label if label == p::ClientInitialRetire::LOGICAL_LABEL && side == Side::Client => {
            if offered.recv::<p::ClientInitialRetire>().await? != 0 {
                return Err(Error::Binding);
            }
            recovery::InitialRetirementEvent::ClientHandshakeAccepted
        }
        label if label == p::ServerInitialRetire::LOGICAL_LABEL && side == Side::Server => {
            if offered.recv::<p::ServerInitialRetire>().await? != 0 {
                return Err(Error::Binding);
            }
            recovery::InitialRetirementEvent::ServerHandshakeAuthenticated
        }
        label => return Err(Error::UnexpectedLabel(label)),
    };
    let mut evidence = exchange.event.take()?;
    if evidence.event() != event {
        return Err(Error::Binding);
    }
    keys.revoke(&evidence)?;
    let mut available = schedule.keys.get();
    available[0] = false;
    schedule.keys.set(available);
    schedule.changed()?;
    let proof = loop {
        let revision = schedule.revision.get();
        match owner.retire_initial(evidence) {
            Ok(proof) => break proof,
            Err((recovery::Error::PendingInitialPublication, returned)) => {
                evidence = returned;
                // The publisher first drops its actual pending IO future, then
                // cancels its reservation and wakes this distinct lane.
                schedule.wait_changed(3, revision).await;
            }
            Err((error, _)) => return Err(error.into()),
        }
    };
    schedule.changed()?;
    exchange.retired.put(proof)?;
    endpoint.send::<p::InitialRetired>(&0).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        accounting::PacketNumberSpace,
        roles::packet_authority::{Arena, ScopedArena},
    };
    use core::{pin::Pin, task::Context};

    macro_rules! setup {
        ($book:ident, $scope:ident, $installation:ident, $arena:ident, $keys:ident) => {
            let mut $scope = ApplicationKeyScope::new(200);
            let mut $installation = $scope.claim().unwrap();
            let mut storage = Arena::<8, 32>::new(200);
            let $arena =
                ScopedArena::new(&mut storage, $installation.take_packet_authority().unwrap())
                    .unwrap();
            let mut $book = recovery::Recovery::<1536>::new(
                $arena.claim_recovery().unwrap(),
                Side::Client,
                333_000,
                1200,
            )
            .unwrap();
            let packet_keys = crypto::initial_keys(b"initial-destination").unwrap();
            let $keys = Keys::new($book.scope(), packet_keys.server, packet_keys.client).unwrap();
        };
    }
    fn accepted_handshake<'scope, 'book>(
        tx: &mut recovery::Tx<'book, 'scope, 1536>,
        publication: &mut recovery::Publication<'book, 'scope, 1536>,
    ) -> recovery::InitialRetirement<'scope> {
        let reservation = tx
            .reserve(Level::Handshake, 32, None, true, false, false, 0)
            .unwrap();
        publication
            .settle(recovery::Completion::from_adapter(reservation, Some(0)))
            .unwrap();
        publication.take_initial_retirement().unwrap()
    }
    struct PendingAdapter<'a> {
        polls: &'a Cell<usize>,
        dropped: &'a Cell<bool>,
    }
    impl Future for PendingAdapter<'_> {
        type Output = Result<u64, IoError>;
        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
            self.polls.set(self.polls.get() + 1);
            Poll::Pending
        }
    }
    impl Drop for PendingAdapter<'_> {
        fn drop(&mut self) {
            self.dropped.set(true);
        }
    }

    #[test]
    fn pending_initial_io_is_dropped_before_numeric_space_retirement() {
        setup!(book, scope, installation, arena, keys);
        let (mut tx, _, _, mut publication, mut retirement) = book.split().unwrap();
        let mut owner = tx.initial_retirement_owner();
        let reservation = tx
            .reserve(Level::Initial, 1200, None, true, true, false, 0)
            .unwrap();
        let event = accepted_handshake(&mut tx, &mut publication);
        let polls = Cell::new(0);
        let dropped = Cell::new(false);
        let mut cx = Context::from_waker(Waker::noop());
        {
            let mut pending = pin!(keys.submit(PendingAdapter {
                polls: &polls,
                dropped: &dropped
            }));
            assert!(pending.as_mut().poll(&mut cx).is_pending());
            keys.revoke(&event).unwrap();
            assert!(keys.read().is_none());
            assert!(!keys.available());
            assert!(matches!(pending.as_mut().poll(&mut cx), Poll::Ready(None)));
        }
        assert!(dropped.get());
        assert_eq!(polls.get(), 1);
        let event = match owner.retire_initial(event) {
            Err((recovery::Error::PendingInitialPublication, token)) => token,
            _ => panic!("ledger discarded before reservation cancellation"),
        };
        publication.cancel(reservation).unwrap();
        let proof = owner.retire_initial(event).unwrap();
        assert_eq!(
            proof.event(),
            recovery::InitialRetirementEvent::ClientHandshakeAccepted
        );
        assert_eq!(tx.snapshot().pending_publications[0], 0);
        assert_eq!(tx.snapshot().history_floor[0], 1);
        assert_eq!(tx.snapshot().next_packet_number[0], Some(1));
        retirement.disarm();
    }

    #[test]
    fn same_poll_ready_acceptance_survives_initial_key_revocation() {
        setup!(book, scope, installation, arena, keys);
        let (mut tx, _, _, mut publication, mut retirement) = book.split().unwrap();
        let mut owner = tx.initial_retirement_owner();
        let reservation = tx
            .reserve(Level::Initial, 1200, None, true, true, false, 0)
            .unwrap();
        assert_eq!(reservation.packet().space, PacketNumberSpace::Initial);
        let event = accepted_handshake(&mut tx, &mut publication);
        let mut cx = Context::from_waker(Waker::noop());
        let accepted = {
            let adapter = poll_fn(|_| {
                keys.revoke(&event).unwrap();
                Poll::Ready(Ok::<_, IoError>(7))
            });
            let mut submission = pin!(keys.submit(adapter));
            match submission.as_mut().poll(&mut cx) {
                Poll::Ready(Some(Ok(at))) => at,
                _ => panic!("accepted datagram was treated as cancelled"),
            }
        };
        publication
            .settle(recovery::Completion::from_adapter(
                reservation,
                Some(accepted),
            ))
            .unwrap();
        owner.retire_initial(event).unwrap();
        assert_eq!(tx.snapshot().pending_publications[0], 0);
        assert_eq!(tx.snapshot().next_packet_number[0], Some(1));
        retirement.disarm();
    }

    #[test]
    fn initial_revoked_before_poll_never_calls_adapter() {
        setup!(book, scope, installation, arena, keys);
        let (mut tx, _, _, mut publication, mut retirement) = book.split().unwrap();
        let event = accepted_handshake(&mut tx, &mut publication);
        keys.revoke(&event).unwrap();
        let polls = Cell::new(0);
        let dropped = Cell::new(false);
        let mut cx = Context::from_waker(Waker::noop());
        {
            let mut submission = pin!(keys.submit(PendingAdapter {
                polls: &polls,
                dropped: &dropped
            }));
            assert!(matches!(
                submission.as_mut().poll(&mut cx),
                Poll::Ready(None)
            ));
        }
        assert_eq!(polls.get(), 0);
        assert!(dropped.get());
        tx.initial_retirement_owner().retire_initial(event).unwrap();
        retirement.disarm();
    }
    #[test]
    fn foreign_scope_retirement_cannot_revoke_initial_keys() {
        setup!(book, scope, installation, arena, keys);
        let (mut tx, _, _, mut publication, mut retirement) = book.split().unwrap();
        let event = accepted_handshake(&mut tx, &mut publication);
        let foreign_scope = ApplicationKeyScope::new(200);
        let pair = crypto::initial_keys(b"initial-destination").unwrap();
        let foreign = Keys::new(&foreign_scope, pair.server, pair.client).unwrap();
        assert!(matches!(foreign.revoke(&event), Err(Error::Binding)));
        assert!(foreign.available());
        assert!(foreign.read().is_some());
        keys.revoke(&event).unwrap();
        tx.initial_retirement_owner().retire_initial(event).unwrap();
        retirement.disarm();
    }

    #[test]
    fn finite_retirement_lane_waits_for_udp_cancellation_then_returns_actual_proof() {
        use crate::carrier::CarrierStorage;
        use hibana::{
            g,
            runtime::{
                SessionKitStorage,
                ids::SessionId,
                program::{RoleProgram, project},
            },
        };
        setup!(book, scope, installation, arena, keys);
        let (mut tx, _, _, mut publication, mut retirement) = book.split().unwrap();
        let mut owner = tx.initial_retirement_owner();
        let reservation = tx
            .reserve(Level::Initial, 1200, None, true, true, false, 0)
            .unwrap();
        let evidence = accepted_handshake(&mut tx, &mut publication);
        let global = g::seq(
            g::route(
                g::send::<{ p::INITIAL_EVENT }, { p::INITIAL_OWNER }, p::ClientInitialRetire>(),
                g::send::<{ p::INITIAL_EVENT }, { p::INITIAL_OWNER }, p::ServerInitialRetire>(),
            ),
            g::send::<{ p::INITIAL_OWNER }, { p::INITIAL_EVENT }, p::InitialRetired>(),
        );
        let event_program: RoleProgram<{ p::INITIAL_EVENT }> = project(&global);
        let owner_program: RoleProgram<{ p::INITIAL_OWNER }> = project(&global);
        let carrier = CarrierStorage::<1, 16, 128>::new();
        let mut slab = [0; 65536];
        let mut kit = SessionKitStorage::uninit();
        let sid = SessionId::new(200);
        let rendezvous = kit
            .init()
            .rendezvous(&mut slab, carrier.bind(sid).unwrap())
            .unwrap();
        let mut event_endpoint = rendezvous.enter(sid, &event_program).unwrap();
        let mut owner_endpoint = rendezvous.enter(sid, &owner_program).unwrap();
        let exchange = Exchange::new();
        let schedule = Schedule::new();
        let polls = Cell::new(0);
        let dropped = Cell::new(false);
        let mut cx = Context::from_waker(Waker::noop());
        {
            let mut submission = pin!(keys.submit(PendingAdapter {
                polls: &polls,
                dropped: &dropped
            }));
            assert!(submission.as_mut().poll(&mut cx).is_pending());
            let mut event = pin!(announce(&mut event_endpoint, &exchange, evidence));
            let mut retiring = pin!(retire(
                &mut owner_endpoint,
                &keys,
                &exchange,
                &schedule,
                &mut owner,
                Side::Client
            ));
            for _ in 0..128 {
                assert!(event.as_mut().poll(&mut cx).is_pending());
                assert!(retiring.as_mut().poll(&mut cx).is_pending());
                if !keys.available() {
                    break;
                }
            }
            assert!(!keys.available());
            assert_eq!(tx.snapshot().pending_publications[0], 1);
            assert!(
                exchange.retired.is_empty(),
                "proof must wait for actual adapter cancellation"
            );
            assert!(matches!(
                submission.as_mut().poll(&mut cx),
                Poll::Ready(None)
            ));
            assert!(dropped.get());
            publication.cancel(reservation).unwrap();
            schedule.changed().unwrap();
            let mut event_done = false;
            let mut owner_done = false;
            for _ in 0..128 {
                if !owner_done {
                    if let Poll::Ready(result) = retiring.as_mut().poll(&mut cx) {
                        result.unwrap();
                        owner_done = true;
                    }
                }
                if !event_done {
                    if let Poll::Ready(result) = event.as_mut().poll(&mut cx) {
                        result.unwrap();
                        event_done = true;
                    }
                }
                if owner_done && event_done {
                    break;
                }
            }
            assert!(owner_done && event_done);
            assert!(exchange.event.is_empty() && exchange.retired.is_empty());
        }
        assert_eq!(polls.get(), 1);
        assert_eq!(tx.snapshot().pending_publications[0], 0);
        assert_eq!(tx.snapshot().history_floor[0], 1);
        assert_eq!(carrier.queued(), 0);
        retirement.disarm();
    }
}
