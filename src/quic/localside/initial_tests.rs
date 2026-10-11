use super::*;
use crate::quic::imp::kernel::accounting::PacketNumberSpace;
use core::{pin::Pin, task::Context};

macro_rules! setup {
    ($book:ident, $scope:ident, $installation:ident, $arena:ident, $keys:ident) => {
        let mut $scope = ApplicationKeyScope::new(200);
        let mut $installation = $scope.claim().unwrap();
        let mut $book = recovery::Recovery::<1536>::new(
            $installation.take_recovery().unwrap(),
            Side::Client,
            333_000,
            1200,
            3,
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
        .settle(recovery::Completion::from_adapter(
            reservation,
            Some(0),
            crate::io::Codepoint::NotEct,
        ))
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
            crate::io::Codepoint::NotEct,
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
    use crate::runtime::carrier::CarrierStorage;
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
        let mut event = pin!(async {
            let endpoint = &mut event_endpoint;
            let exchange = &exchange;

            let scope = evidence.scope();
            let event = evidence.event();
            exchange.event.put(evidence)?;
            match event {
                recovery::InitialRetirementEvent::ClientHandshakeAccepted => {
                    endpoint.send::<p::ClientInitialRetire>(&()).await?
                }
                recovery::InitialRetirementEvent::ServerHandshakeAuthenticated => {
                    endpoint.send::<p::ServerInitialRetire>(&()).await?
                }
            }
            endpoint.recv::<p::InitialRetired>().await?;
            let proof = exchange.retired.take()?;
            if !core::ptr::eq(proof.scope(), scope) || proof.event() != event {
                return Err(Error::Binding);
            }
            Ok::<(), Error>(())
        });
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
            if !owner_done && let Poll::Ready(result) = retiring.as_mut().poll(&mut cx) {
                result.unwrap();
                owner_done = true;
            }
            if !event_done && let Poll::Ready(result) = event.as_mut().poll(&mut cx) {
                result.unwrap();
                event_done = true;
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
