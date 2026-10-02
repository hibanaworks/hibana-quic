use hibana::{
    g,
    runtime::{
        SessionKitStorage,
        ids::SessionId,
        program::{RoleProgram, project},
    },
};
use hibana_quic::{
    carrier::{CarrierStorage, LocalCarrier},
    protocol::*,
};
use std::{
    future::Future,
    pin::pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}
fn counted_waker() -> (Arc<WakeCount>, Waker) {
    let count = Arc::new(WakeCount(AtomicUsize::new(0)));
    (count.clone(), Waker::from(count))
}
fn ready<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("fixture expected one bounded ready poll"),
    }
}

#[test]
fn independent_guarded_tx_and_timer_progress_while_rx_is_parked() {
    let queues = CarrierStorage::<8, 16, { hibana_quic::protocol::SERVICE_PORTS }>::new();
    let carrier = queues.bind(SessionId::new(1)).unwrap();
    let mut slab = [0_u8; 32 * 1024];
    let mut storage = SessionKitStorage::<
        LocalCarrier<'_, 8, 16, { hibana_quic::protocol::SERVICE_PORTS }>,
    >::uninit();
    let kit = storage.init();
    let rv = kit.rendezvous(&mut slab, carrier).unwrap();
    let p0 = service_program::<INGRESS>();
    let p1 = service_program::<PACKET>();
    let p2 = service_program::<APPLICATION>();
    let p3 = service_program::<RECOVERY>();
    let p4 = service_program::<ADAPTER>();
    let p5 = service_program::<TIMER>();
    let mut ingress = rv.enter(SessionId::new(1), &p0).unwrap();
    let mut packet = rv.enter(SessionId::new(1), &p1).unwrap();
    let mut app = rv.enter(SessionId::new(1), &p2).unwrap();
    let mut recovery = rv.enter(SessionId::new(1), &p3).unwrap();
    let mut adapter = rv.enter(SessionId::new(1), &p4).unwrap();
    let mut timer = rv.enter(SessionId::new(1), &p5).unwrap();
    let (rx_wakes, rx_waker) = counted_waker();
    let mut rx = pin!(packet.recv::<RxDatagram>());
    let mut rx_cx = Context::from_waker(&rx_waker);
    assert!(rx.as_mut().poll(&mut rx_cx).is_pending());

    // Re-enter each individual service while Rx remains idle. Timer input is
    // deliberately handled in the middle of an outstanding Tx reservation.
    // Recovery is never cloned or mutably borrowed by two futures at once.
    for turn in 0..4_u32 {
        ready(app.send::<TxRequest>(&turn)).unwrap();
        assert_eq!(ready(recovery.recv::<TxRequest>()).unwrap(), turn);
        ready(recovery.send::<TxReserved>(&turn)).unwrap();
        assert_eq!(ready(adapter.recv::<TxReserved>()).unwrap(), turn);
        let now = 1000 + u64::from(turn);
        ready(timer.send::<TimerExpired>(&now)).unwrap();
        assert_eq!(ready(recovery.recv::<TimerExpired>()).unwrap(), now);
        ready(recovery.send::<TimerHandled>(&now)).unwrap();
        assert_eq!(ready(timer.recv::<TimerHandled>()).unwrap(), now);
        ready(adapter.send::<TxResult>(&turn)).unwrap();
        assert_eq!(ready(recovery.recv::<TxResult>()).unwrap(), turn);
        ready(recovery.send::<TxComplete>(&turn)).unwrap();
        assert_eq!(ready(app.recv::<TxComplete>()).unwrap(), turn);
        assert!(rx.as_mut().poll(&mut rx_cx).is_pending());
    }
    assert_eq!(
        rx_wakes.0.load(Ordering::Relaxed),
        0,
        "idle receive has no spurious carrier wakeup"
    );
    ready(ingress.send::<RxDatagram>(&77)).unwrap();
    assert!(rx_wakes.0.load(Ordering::Relaxed) > 0);
    assert!(matches!(rx.as_mut().poll(&mut rx_cx), Poll::Ready(Ok(77))));
}

#[test]
fn carrier_backpressure_wakes_current_sender_and_delivers_fifo_once() {
    let queues = CarrierStorage::<1, 8, 4>::new();
    let carrier = queues.bind(SessionId::new(2)).unwrap();
    let mut slab = [0_u8; 12 * 1024];
    let mut storage = SessionKitStorage::<LocalCarrier<'_, 1, 8, 4>>::uninit();
    let kit = storage.init();
    let rv = kit.rendezvous(&mut slab, carrier).unwrap();
    let program = g::send::<0, 1, g::Msg<60, u32>>().roll();
    let p0: RoleProgram<0> = project(&program);
    let p1: RoleProgram<1> = project(&program);
    let mut sender = rv.enter(SessionId::new(2), &p0).unwrap();
    let mut receiver = rv.enter(SessionId::new(2), &p1).unwrap();
    ready(sender.send::<g::Msg<60, u32>>(&100)).unwrap();
    let (old_count, old_waker) = counted_waker();
    let (new_count, new_waker) = counted_waker();
    {
        let value = 200;
        let mut pending = pin!(sender.send::<g::Msg<60, u32>>(&value));
        assert!(
            pending
                .as_mut()
                .poll(&mut Context::from_waker(&old_waker))
                .is_pending()
        );
        assert!(
            pending
                .as_mut()
                .poll(&mut Context::from_waker(&new_waker))
                .is_pending()
        );
        assert_eq!(
            queues.queued(),
            1,
            "Pending must not enqueue an extra frame"
        );
        assert_eq!(ready(receiver.recv::<g::Msg<60, u32>>()).unwrap(), 100);
        assert_eq!(old_count.0.load(Ordering::Relaxed), 0);
        assert!(new_count.0.load(Ordering::Relaxed) > 0);
        assert!(matches!(
            pending.as_mut().poll(&mut Context::from_waker(&new_waker)),
            Poll::Ready(Ok(()))
        ));
    }
    assert_eq!(ready(receiver.recv::<g::Msg<60, u32>>()).unwrap(), 200);
    assert_eq!(queues.queued(), 0);
    let mut next = pin!(receiver.recv::<g::Msg<60, u32>>());
    assert!(
        next.as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending(),
        "delivery is not repeated"
    );
}

#[test]
fn carrier_close_wakes_pending_receive_and_quarantines_queue() {
    let queues = CarrierStorage::<2, 8, 4>::new();
    let carrier = queues.bind(SessionId::new(3)).unwrap();
    let mut slab = [0_u8; 12 * 1024];
    let mut storage = SessionKitStorage::<LocalCarrier<'_, 2, 8, 4>>::uninit();
    let kit = storage.init();
    let rv = kit.rendezvous(&mut slab, carrier).unwrap();
    let program = g::send::<0, 1, g::Msg<61, u32>>().roll();
    let p0: RoleProgram<0> = project(&program);
    let p1: RoleProgram<1> = project(&program);
    let _sender = rv.enter(SessionId::new(3), &p0).unwrap();
    let mut receiver = rv.enter(SessionId::new(3), &p1).unwrap();
    let (count, waker) = counted_waker();
    let mut recv = pin!(receiver.recv::<g::Msg<61, u32>>());
    assert!(
        recv.as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    queues.close();
    assert!(count.0.load(Ordering::Relaxed) > 0);
    assert!(matches!(
        recv.as_mut().poll(&mut Context::from_waker(&waker)),
        Poll::Ready(Err(_))
    ));
    assert_eq!(queues.queued(), 0);
}

#[test]
fn forbidden_publish_without_reservation_fails_closed() {
    let queues = CarrierStorage::<8, 16, { hibana_quic::protocol::SERVICE_PORTS }>::new();
    let carrier = queues.bind(SessionId::new(4)).unwrap();
    let mut slab = [0_u8; 32 * 1024];
    let mut storage = SessionKitStorage::<
        LocalCarrier<'_, 8, 16, { hibana_quic::protocol::SERVICE_PORTS }>,
    >::uninit();
    let kit = storage.init();
    let rv = kit.rendezvous(&mut slab, carrier).unwrap();
    let p4 = contract_program::<4>();
    let mut publisher = rv.enter(SessionId::new(4), &p4).unwrap();
    assert!(ready(publisher.send::<PublishPacket>(&1)).is_err());
    assert_eq!(
        queues.queued(),
        0,
        "forbidden publication never reaches the carrier"
    );
    assert!(
        ready(publisher.recv::<ReservationGranted>()).is_err(),
        "error cannot be used as alternate progress"
    );
}

#[test]
fn forbidden_authentication_before_key_installation_fails_closed() {
    let queues = CarrierStorage::<8, 16, { hibana_quic::protocol::SERVICE_PORTS }>::new();
    let carrier = queues.bind(SessionId::new(5)).unwrap();
    let mut slab = [0_u8; 32 * 1024];
    let mut storage = SessionKitStorage::<
        LocalCarrier<'_, 8, 16, { hibana_quic::protocol::SERVICE_PORTS }>,
    >::uninit();
    let kit = storage.init();
    let rv = kit.rendezvous(&mut slab, carrier).unwrap();
    let p1 = contract_program::<1>();
    let mut packet = rv.enter(SessionId::new(5), &p1).unwrap();
    assert!(ready(packet.send::<AuthenticatedPacket>(&1)).is_err());
    assert_eq!(queues.queued(), 0);
}

#[test]
fn forbidden_delivery_and_credit_before_authentication_fail_closed() {
    // The two forbidden operations are tried in independent generations,
    // because the first EndpointError poisons the entire generation.
    for credit in [false, true] {
        let queues = CarrierStorage::<8, 16, { hibana_quic::protocol::SERVICE_PORTS }>::new();
        let carrier = queues.bind(SessionId::new(6)).unwrap();
        let mut slab = [0_u8; 32 * 1024];
        let mut storage = SessionKitStorage::<
            LocalCarrier<'_, 8, 16, { hibana_quic::protocol::SERVICE_PORTS }>,
        >::uninit();
        let kit = storage.init();
        let rv = kit.rendezvous(&mut slab, carrier).unwrap();
        let p2 = contract_program::<2>();
        let mut streams = rv.enter(SessionId::new(6), &p2).unwrap();
        let rejected = if credit {
            ready(streams.send::<ValidatedAck>(&1))
        } else {
            ready(streams.send::<StreamDelivery>(&1))
        };
        assert!(rejected.is_err());
        assert_eq!(queues.queued(), 0);
    }
}

fn walk_contract(release_before_adapter_result: bool) {
    let queues = CarrierStorage::<8, 16, { hibana_quic::protocol::SERVICE_PORTS }>::new();
    let sid = SessionId::new(7);
    let carrier = queues.bind(sid).unwrap();
    let mut slab = [0_u8; 32 * 1024];
    let mut storage = SessionKitStorage::<
        LocalCarrier<'_, 8, 16, { hibana_quic::protocol::SERVICE_PORTS }>,
    >::uninit();
    let kit = storage.init();
    let rv = kit.rendezvous(&mut slab, carrier).unwrap();
    let p0 = contract_program::<0>();
    let p1 = contract_program::<1>();
    let p2 = contract_program::<2>();
    let p3 = contract_program::<3>();
    let p4 = contract_program::<4>();
    let p5 = contract_program::<5>();
    let p6 = contract_program::<6>();
    let mut authority = rv.enter(sid, &p0).unwrap();
    let mut packet = rv.enter(sid, &p1).unwrap();
    let mut streams = rv.enter(sid, &p2).unwrap();
    let mut recovery = rv.enter(sid, &p3).unwrap();
    let mut publisher = rv.enter(sid, &p4).unwrap();
    let mut adapter = rv.enter(sid, &p5).unwrap();
    let mut application = rv.enter(sid, &p6).unwrap();
    ready(authority.send::<InstallKey>(&101)).unwrap();
    assert_eq!(ready(packet.recv::<InstallKey>()).unwrap(), 101);
    ready(packet.send::<AuthenticatedPacket>(&102)).unwrap();
    assert_eq!(ready(streams.recv::<AuthenticatedPacket>()).unwrap(), 102);
    ready(streams.send::<StreamDelivery>(&103)).unwrap();
    assert_eq!(ready(application.recv::<StreamDelivery>()).unwrap(), 103);
    ready(streams.send::<ValidatedAck>(&104)).unwrap();
    assert_eq!(ready(recovery.recv::<ValidatedAck>()).unwrap(), 104);
    ready(recovery.send::<ReservationGranted>(&105)).unwrap();
    assert_eq!(ready(publisher.recv::<ReservationGranted>()).unwrap(), 105);
    ready(publisher.send::<PublishPacket>(&106)).unwrap();
    assert_eq!(ready(adapter.recv::<PublishPacket>()).unwrap(), 106);
    if release_before_adapter_result {
        assert!(ready(recovery.send::<ReservationReleased>(&107)).is_err());
        assert_eq!(queues.queued(), 0);
        assert!(
            ready(adapter.send::<AdapterResult>(&108)).is_err(),
            "a forbidden operation poisons all roles in the generation"
        );
    } else {
        ready(adapter.send::<AdapterResult>(&107)).unwrap();
        assert_eq!(ready(recovery.recv::<AdapterResult>()).unwrap(), 107);
        ready(recovery.send::<ReservationReleased>(&108)).unwrap();
        assert_eq!(ready(authority.recv::<ReservationReleased>()).unwrap(), 108);
        assert_eq!(queues.queued(), 0);
    }
}

#[test]
fn legal_typed_contract_completes() {
    walk_contract(false);
}

#[test]
fn forbidden_reservation_reuse_before_adapter_result_fails_closed() {
    walk_contract(true);
}

#[test]
fn actual_key_services_reject_use_before_install_at_hibana_endpoint() {
    use hibana_quic::roles::{protocol as key, protocol_tls as tls};
    for level in 0..3 {
        let queues = CarrierStorage::<8, 16, 26>::new();
        let sid = SessionId::new(200 + level);
        let carrier = queues.bind(sid).unwrap();
        let mut slab = [0_u8; 64 * 1024];
        let mut storage = SessionKitStorage::<LocalCarrier<'_, 8, 16, 26>>::uninit();
        let kit = storage.init();
        let rv = kit.rendezvous(&mut slab, carrier).unwrap();
        let descriptor = [0u8; 16];
        let rejected = if level == 0 {
            let program = key::key_program::<{ key::KEY_CLIENT }>();
            let mut endpoint = rv.enter(sid, &program).unwrap();
            ready(endpoint.send::<key::Open>(&descriptor)).is_err()
        } else {
            let program = tls::tls_program::<{ tls::TLS_CLIENT }>();
            let mut endpoint = rv.enter(sid, &program).unwrap();
            if level == 1 {
                ready(endpoint.send::<tls::OpenHandshake>(&descriptor)).is_err()
            } else {
                ready(endpoint.send::<tls::OpenOneRtt>(&descriptor)).is_err()
            }
        };
        assert!(
            rejected,
            "the actual owner projection rejects use before install"
        );
        assert_eq!(
            queues.queued(),
            0,
            "forbidden key use never reaches the carrier"
        );
    }
}

#[test]
fn actual_service_rejects_early_release_before_verified_finished() {
    let queues = CarrierStorage::<8, 16, { SERVICE_PORTS }>::new();
    let sid = SessionId::new(300);
    let carrier = queues.bind(sid).unwrap();
    let mut slab = [0u8; SERVICE_SLAB_BYTES];
    let mut storage = SessionKitStorage::<LocalCarrier<'_, 8, 16, { SERVICE_PORTS }>>::uninit();
    let kit = storage.init();
    let rv = kit.rendezvous(&mut slab, carrier).unwrap();
    let program = service_program::<PACKET>();
    let mut packet = rv.enter(sid, &program).unwrap();
    assert!(ready(packet.send::<EarlyReleaseRequest>(&[0; 12])).is_err());
    assert_eq!(queues.queued(), 0, "mutated transition must never publish");
}

#[test]
fn actual_service_rejects_client_intent_import_before_finished() {
    let queues = CarrierStorage::<8, 16, { SERVICE_PORTS }>::new();
    let sid = SessionId::new(301);
    let carrier = queues.bind(sid).unwrap();
    let mut slab = [0; SERVICE_SLAB_BYTES];
    let mut storage = SessionKitStorage::<LocalCarrier<'_, 8, 16, { SERVICE_PORTS }>>::uninit();
    let kit = storage.init();
    let rv = kit.rendezvous(&mut slab, carrier).unwrap();
    let p = service_program::<PACKET>();
    let mut packet = rv.enter(sid, &p).unwrap();
    assert!(ready(packet.send::<EarlyIntentRequest>(&[0; 12])).is_err());
    assert_eq!(queues.queued(), 0);
}

#[test]
fn actual_service_rejects_deferred_control_release_before_finished() {
    let queues = CarrierStorage::<8, 16, { SERVICE_PORTS }>::new();
    let sid = SessionId::new(302);
    let carrier = queues.bind(sid).unwrap();
    let mut slab = [0; SERVICE_SLAB_BYTES];
    let mut storage = SessionKitStorage::<LocalCarrier<'_, 8, 16, { SERVICE_PORTS }>>::uninit();
    let kit = storage.init();
    let rv = kit.rendezvous(&mut slab, carrier).unwrap();
    let p = service_program::<PACKET>();
    let mut packet = rv.enter(sid, &p).unwrap();
    assert!(ready(packet.send::<EarlyControlReleaseRequest>(&[0; 12])).is_err());
    assert_eq!(queues.queued(), 0);
}
