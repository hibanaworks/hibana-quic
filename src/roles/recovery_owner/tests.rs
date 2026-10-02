use super::*;
use crate::{
    carrier::CarrierStorage,
    crypto,
    mailbox::Mailbox,
    packet,
    roles::{packet_authority::ReceiveEvidence, packet_protection as keys, protocol as kp},
};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use hibana::runtime::{SessionKitStorage, ids::SessionId};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::Wake,
};

const GENERATION: u64 = 71;
struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
fn counted_waker() -> (Arc<WakeCount>, Waker) {
    let count = Arc::new(WakeCount(AtomicUsize::new(0)));
    (count.clone(), Waker::from(count))
}
fn drive<F: Future>(future: F) -> F::Output {
    let (count, waker) = counted_waker();
    let mut future = pin!(future);
    let mut cx = Context::from_waker(&waker);
    for _ in 0..1024 {
        let before = count.0.load(Ordering::SeqCst);
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(value) => return value,
            Poll::Pending => assert!(
                count.0.load(Ordering::SeqCst) > before,
                "ready test work stalled without a wake"
            ),
        }
    }
    panic!("test work did not finish")
}
/// All authority in these tests originates in actual AEAD success in the real
/// projected key owner; no test constructor fabricates receipts or auth flags.
fn authenticated_receipt(acknowledged: &[u8]) -> (keys::OpenReceipt, keys::Packet<64>) {
    let mut payload = [0u8; 64];
    assert!(acknowledged.len() <= 12);
    for (index, number) in acknowledged.iter().enumerate() {
        assert!(*number < 64);
        payload[index * 5..index * 5 + 5].copy_from_slice(&[2, *number, 0, 0, 0]);
    }
    let payload = &payload[..acknowledged.len() * 5];
    authenticated_payload(payload)
}
fn authenticated_payload(payload: &[u8]) -> (keys::OpenReceipt, keys::Packet<64>) {
    let carrier = CarrierStorage::<1, 16, 16>::new();
    let mut slab = [0; 32768];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init();
    let sid = SessionId::new(711);
    let rv = kit
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    let cp = kp::key_program::<{ kp::KEY_CLIENT }>();
    let op = kp::key_program::<{ kp::KEY_CRYPTO }>();
    let mut client = rv.enter(sid, &cp).unwrap();
    let mut owner = rv.enter(sid, &op).unwrap();
    let mut requests = [None];
    let mut responses: [Option<keys::Reply<64>>; 1] = [None];
    let requests = Mailbox::new(&mut requests).unwrap();
    let responses = Mailbox::new(&mut responses).unwrap();
    let (mut tx, rx) = requests.split().unwrap();
    let (rtx, mut rrx) = responses.split().unwrap();
    let mut exchange = keys::Exchange::<64>::new();
    let mut opened = None;
    let workload = async {
        assert!(matches!(
            rrx.recv().await.unwrap().outcome,
            keys::Outcome::Installed
        ));
        tx.send(keys::Command::Seal(
            keys::Packet::new(9, b"header", payload).unwrap(),
        ))
        .await
        .unwrap_or_else(|_| panic!("closed"));
        let keys::Outcome::Sealed(packet) = rrx.recv().await.unwrap().outcome else {
            panic!("seal")
        };
        tx.send(keys::Command::Open {
            packet: keys::Packet::new(packet.packet_number(), packet.header(), packet.body())
                .unwrap(),
            budget: crypto::IntegrityBudget::new(),
        })
        .await
        .unwrap_or_else(|_| panic!("closed"));
        let keys::Outcome::Opened {
            receipt, packet, ..
        } = rrx.recv().await.unwrap().outcome
        else {
            panic!("open")
        };
        assert_eq!(packet.body(), payload);
        let frames = packet::FrameIter::new(
            packet.body(),
            packet::EncryptionLevel::Initial,
            packet::ParseLimits::default(),
        )
        .unwrap();
        for frame in frames {
            frame.unwrap();
        }
        opened = Some((receipt, packet));
        tx.send(keys::Command::Retire)
            .await
            .unwrap_or_else(|_| panic!("closed"));
        assert!(matches!(
            rrx.recv().await.unwrap().outcome,
            keys::Outcome::Retired
        ));
        Ok(())
    };
    let service = keys::run_borrowed(
        &mut client,
        &mut owner,
        GENERATION,
        crypto::initial_keys(b"owned-recovery").unwrap().client,
        rx,
        rtx,
        &mut exchange,
    );
    drive(runtime::join2(service, workload)).unwrap();
    opened.unwrap()
}
fn authenticated_scope<const P: usize, const E: usize>(
    arena: &Arena<P, E>,
    acknowledged: &[u8],
) -> packet_authority::PacketTicket {
    let (receipt, packet) = authenticated_receipt(acknowledged);
    arena
        .admit(ReceiveEvidence::Initial(receipt), packet.body())
        .unwrap()
}
fn sealed_datagram(
    packet_number: u64,
) -> (
    crate::roles::sealed_packet::SealedPacket<1200>,
    [u8; 5],
    [u8; 1157],
) {
    let mut plaintext = [0; 1157];
    plaintext[0] = 1; // PING followed by actual padding to one full Initial datagram.
    let mut header = [0; 64];
    let header_len = packet::encode_long_header(
        &packet::LongHeader {
            kind: packet::LongType::Initial,
            destination_id: b"clientid",
            source_id: b"serverid",
            token: &[],
            packet_number,
            packet_number_len: 1,
        },
        plaintext.len() + 16,
        &mut header,
    )
    .unwrap();
    assert_eq!(header_len + plaintext.len() + 16, 1200);
    let carrier = CarrierStorage::<1, 16, 16>::new();
    let mut slab = [0; 32768];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init();
    let sid = SessionId::new(714);
    let rv = kit
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    let cp = kp::key_program::<{ kp::KEY_CLIENT }>();
    let op = kp::key_program::<{ kp::KEY_CRYPTO }>();
    let mut client = rv.enter(sid, &cp).unwrap();
    let mut endpoint = rv.enter(sid, &op).unwrap();
    let mut requests: [Option<keys::Command<1200>>; 1] = [None];
    let mut responses: [Option<keys::Reply<1200>>; 1] = [None];
    let commands = Mailbox::new(&mut requests).unwrap();
    let replies = Mailbox::new(&mut responses).unwrap();
    let (mut tx, rx) = commands.split().unwrap();
    let (rtx, mut rrx) = replies.split().unwrap();
    let mut exchange = keys::Exchange::new();
    let mut result = None;
    let workload = async {
        assert!(matches!(
            rrx.recv().await.unwrap().outcome,
            keys::Outcome::Installed
        ));
        tx.send(keys::Command::Seal(
            keys::Packet::new(packet_number, &header[..header_len], &plaintext).unwrap(),
        ))
        .await
        .unwrap_or_else(|_| panic!("closed"));
        let keys::Outcome::Sealed(sealed) = rrx.recv().await.unwrap().outcome else {
            panic!("seal")
        };
        let mut sample = [0; 16];
        sample.copy_from_slice(&sealed.bytes()[header_len + 3..header_len + 19]);
        tx.send(keys::Command::HeaderMask(sample))
            .await
            .unwrap_or_else(|_| panic!("closed"));
        let keys::Outcome::HeaderMask(mask) = rrx.recv().await.unwrap().outcome else {
            panic!("header protection")
        };
        result = Some((sealed, mask));
        tx.send(keys::Command::Retire)
            .await
            .unwrap_or_else(|_| panic!("closed"));
        assert!(matches!(
            rrx.recv().await.unwrap().outcome,
            keys::Outcome::Retired
        ));
        Ok(())
    };
    drive(runtime::join2(
        keys::run_borrowed(
            &mut client,
            &mut endpoint,
            GENERATION,
            crypto::initial_keys(b"clientid").unwrap().client,
            rx,
            rtx,
            &mut exchange,
        ),
        workload,
    ))
    .unwrap();
    let (sealed, mask) = result.unwrap();
    (sealed, mask, plaintext)
}
fn owner() -> RecoveryOwner<8, 2, 64, 16> {
    RecoveryOwner::new(Config {
        generation: GENERATION,
        initial_rtt_us: recovery::INITIAL_RTT_US,
        max_datagram_size: 1200,
        active_path: None,
        ecn: None,
        max_ack_delay_us: 25_000,
    })
    .unwrap()
}
fn descriptor(sequence: u64) -> Descriptor {
    Descriptor {
        generation: GENERATION,
        sequence,
    }
}
fn plan(flight: Option<FlightId>) -> SendPlan {
    SendPlan {
        kind: PacketKind::Initial,
        bytes: 1200,
        in_flight: true,
        ack_eliciting: true,
        pto_probe: false,
        flight,
    }
}
fn context() -> AckContext {
    AckContext {
        ack_delay_exponent: 3,
        max_ack_delay_us: 25000,
        handshake_confirmed: false,
        peer_address_validated: true,
        received_path: None,
        local_decryption_delay_us: 0,
        app_or_flow_limited: false,
    }
}
fn grant<const P: usize, const E: usize>(
    arena: &Arena<P, E>,
    ticket: packet_authority::PacketTicket,
    ordinal: u32,
    pn: u64,
) -> AckGrant {
    let ranges = [packet::AckRange {
        smallest: pn,
        largest: pn,
    }];
    arena
        .grant_ack(
            ticket,
            ordinal,
            packet::AckRanges::new(&ranges).unwrap(),
            0,
            None,
        )
        .unwrap()
}
fn with_roles<T>(
    f: impl for<'a> FnOnce(
        Endpoint<'a, { p::RECOVERY_CLIENT }>,
        Endpoint<'a, { p::RECOVERY_OWNER }>,
    ) -> T,
) -> T {
    let carrier = CarrierStorage::<1, 16, 16>::new();
    let mut slab = [0; 32768];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init();
    let sid = SessionId::new(712);
    let rv = kit
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    let cp = p::recovery_program::<{ p::RECOVERY_CLIENT }>();
    let op = p::recovery_program::<{ p::RECOVERY_OWNER }>();
    f(rv.enter(sid, &cp).unwrap(), rv.enter(sid, &op).unwrap())
}

#[test]
fn affine_packet_scope_multiple_acks_finish_and_cancellation_revoke_copied_ids() {
    let arena = Arena::<1, 2>::new(GENERATION);
    let ticket = authenticated_scope(&arena, &[0, 1, 2]);
    let first = grant(&arena, ticket, 0, 0);
    let second = grant(&arena, ticket, 1, 1);
    assert_eq!(
        arena.finish(ticket),
        Err(packet_authority::Error::OutstandingEffects)
    );
    let (_, first) = arena.consume_ack(first).unwrap();
    let (_, second) = arena.consume_ack(second).unwrap();
    assert_eq!(first.ranges()[0].start, 0);
    assert_eq!(second.ranges()[0].start, 1);
    assert!(
        arena
            .grant_ack(
                ticket,
                1,
                packet::AckRanges::new(&[packet::AckRange {
                    smallest: 1,
                    largest: 1
                }])
                .unwrap(),
                0,
                None
            )
            .is_err()
    );
    let stale = grant(&arena, ticket, 2, 2);
    arena.cancel(ticket).unwrap();
    assert!(matches!(
        arena.consume_ack(stale),
        Err(packet_authority::Error::InvalidGrant)
    ));
    assert_eq!(
        arena.finish(ticket),
        Err(packet_authority::Error::InvalidPacket)
    );
    assert_eq!(arena.live_packets(), 0);
    assert_eq!(arena.live_effects(), 0);
}
#[test]
fn reservations_real_accept_reject_and_late_callbacks_do_not_double_count() {
    let mut owner = owner();
    let reserved = owner.reserve(descriptor(1), plan(None)).unwrap();
    assert_eq!(owner.snapshot().reserved_in_flight, 1200);
    assert_eq!(owner.snapshot().bytes_in_flight, 0);
    owner.rejected(reserved).unwrap();
    assert_eq!(
        owner.accepted(reserved, 10, Codepoint::NotEct, None),
        Err(Rejection::InvalidTicket)
    );
    assert_eq!(owner.snapshot().reserved_in_flight, 0);
    assert_eq!(owner.snapshot().bytes_in_flight, 0);
    let next = owner.reserve(descriptor(2), plan(None)).unwrap();
    assert_eq!(next.packet().value, 1);
    owner.accepted(next, 10, Codepoint::Ect0, None).unwrap();
    assert_eq!(
        owner.accepted(next, 10, Codepoint::NotEct, None),
        Err(Rejection::InvalidTicket)
    );
    assert_eq!(owner.rejected(next), Err(Rejection::InvalidTicket));
    assert_eq!(owner.snapshot().bytes_in_flight, 1200);
    assert_eq!(owner.snapshot().accepted_ecn[0].ect0, 1);
    assert_eq!(
        owner.space_change(PacketNumberSpace::ApplicationData, false),
        Err(Rejection::Recovery(
            recovery::RecoveryError::InvalidConfiguration
        ))
    );
    assert_eq!(owner.snapshot().bytes_in_flight, 1200);
}
#[test]
fn real_ack_loss_rtt_newreno_and_flight_storage_have_once_only_effects() {
    let arena = Arena::<1, 2>::new(GENERATION);
    let scope = authenticated_scope(&arena, &[3, 0, 0, 4]);
    let mut owner = owner();
    let flight = owner
        .flights
        .append(Level::Initial, 0, b"retained crypto")
        .unwrap();
    for n in 0..4 {
        let ticket = owner
            .reserve(descriptor(n + 1), plan((n == 0).then_some(flight)))
            .unwrap();
        owner
            .accepted(ticket, 10 + n * 10, Codepoint::NotEct, None)
            .unwrap();
    }
    let ack = owner
        .ack(&arena, grant(&arena, scope, 0, 3), 1000, context())
        .unwrap();
    assert_eq!(ack.summary.bytes_removed_from_flight, 1200);
    assert_eq!(owner.snapshot().min_rtt_us, Some(960));
    assert_eq!(owner.snapshot().congestion_window, 13200);
    assert_eq!(owner.snapshot().bytes_in_flight, 3600);
    let (stream, path) = ack.validated.split();
    assert_eq!(stream.ranges(), path.ranges());
    let lost = owner.detect_loss(1000).unwrap();
    assert_eq!(lost.newly.iter().flatten().count(), 1);
    assert_eq!(
        lost.stream.iter().flatten().next().unwrap().packet().value,
        0
    );
    assert_eq!(owner.snapshot().bytes_in_flight, 2400);
    assert_eq!(owner.snapshot().congestion_window, 6600);
    assert_eq!(owner.snapshot().active_flights, 1);
    assert_eq!(owner.snapshot().next_lost_flight, Some(flight));
    assert_eq!(
        owner
            .detect_loss(1000)
            .unwrap()
            .newly
            .iter()
            .flatten()
            .count(),
        0
    );
    let late = owner
        .ack(&arena, grant(&arena, scope, 1, 0), 1000, context())
        .unwrap();
    assert_eq!(late.summary.previously_lost, 1);
    assert_eq!(late.summary.bytes_removed_from_flight, 0);
    assert_eq!(owner.snapshot().bytes_in_flight, 2400);
    assert_eq!(owner.snapshot().congestion_window, 6600);
    assert_eq!(owner.snapshot().active_flights, 0);
    let duplicate = owner
        .ack(&arena, grant(&arena, scope, 2, 0), 1000, context())
        .unwrap();
    assert_eq!(duplicate.summary.newly_acknowledged, 0);
    let never_sent = owner.reserve(descriptor(5), plan(None)).unwrap();
    owner.rejected(never_sent).unwrap();
    assert!(matches!(
        owner.ack(&arena, grant(&arena, scope, 3, 4), 1000, context()),
        Err(Rejection::Accounting(
            accounting::AccountingError::UnsentPacket
        ))
    ));
    assert_eq!(owner.snapshot().bytes_in_flight, 2400);
    arena.finish(scope).unwrap();
}
#[test]
fn pending_flight_reference_blocks_recycling_and_retry_preserves_burned_numbers() {
    let arena = Arena::<1, 1>::new(GENERATION);
    let scope = authenticated_scope(&arena, &[0]);
    let mut owner = owner();
    let flight = owner.flights.append(Level::Initial, 0, b"flight").unwrap();
    let sent = owner.reserve(descriptor(1), plan(Some(flight))).unwrap();
    owner.accepted(sent, 1, Codepoint::NotEct, None).unwrap();
    let pending = owner.reserve(descriptor(2), plan(Some(flight))).unwrap();
    owner
        .ack(&arena, grant(&arena, scope, 0, 0), 100, context())
        .unwrap();
    assert_eq!(owner.snapshot().active_flights, 1);
    assert_eq!(
        owner.space_change(PacketNumberSpace::Initial, true),
        Err(Rejection::Accounting(
            accounting::AccountingError::OutstandingPackets
        ))
    );
    owner.rejected(pending).unwrap();
    assert_eq!(owner.snapshot().active_flights, 0);
    owner
        .space_change(PacketNumberSpace::Initial, true)
        .unwrap();
    assert_eq!(owner.snapshot().next_packet_number[0], Some(2));
    arena.finish(scope).unwrap();
}
#[test]
fn pto_is_a_probe_and_never_decrements_flight_or_declares_loss() {
    let mut owner = owner();
    let sent = owner.reserve(descriptor(1), plan(None)).unwrap();
    owner.accepted(sent, 1, Codepoint::NotEct, None).unwrap();
    owner
        .timer(TimerCommand::Update {
            now: 1,
            keys_available: [true, false, false],
            context: TimerContext {
                is_server: false,
                handshake_confirmed: false,
                handshake_ack_received: false,
                server_amplification_blocked: false,
            },
            max_ack_delay_us: 25000,
        })
        .unwrap();
    let at = owner.snapshot().timer.unwrap().at;
    assert!(matches!(
        owner.timer(TimerCommand::Expire { now: at }).unwrap(),
        Outcome::Timeout(TimeoutResult {
            action: Some(TimeoutAction::Probe { .. }),
            ..
        })
    ));
    assert_eq!(owner.snapshot().bytes_in_flight, 1200);
    assert_eq!(owner.snapshot().pto_count, 1);
    assert!(matches!(
        owner.timer(TimerCommand::Expire { now: at }).unwrap(),
        Outcome::Timeout(TimeoutResult { action: None, .. })
    ));
    assert_eq!(
        owner
            .detect_loss(at)
            .unwrap()
            .newly
            .iter()
            .flatten()
            .count(),
        0
    );
}
#[test]
fn q1_projected_owner_runs_real_reserve_accept_ack_and_retire() {
    let arena = Arena::<1, 1>::new(GENERATION);
    let scope = authenticated_scope(&arena, &[0]);
    with_roles(|mut client, mut endpoint| {
        let mut slots = [None];
        let mut replies = [None];
        let commands = Mailbox::new(&mut slots).unwrap();
        let response = Mailbox::new(&mut replies).unwrap();
        let (mut tx, rx) = commands.split().unwrap();
        let (rtx, mut rrx) = response.split().unwrap();
        let mut exchange = Exchange::new();
        let service = run_borrowed(
            &mut client,
            &mut endpoint,
            owner(),
            &arena,
            rx,
            rtx,
            &mut exchange,
        );
        let workload = async {
            assert!(matches!(
                rrx.recv().await.unwrap().outcome,
                Outcome::Installed
            ));
            tx.send(Command::Reserve(plan(None)))
                .await
                .unwrap_or_else(|_| panic!("closed"));
            let reply = rrx.recv().await.unwrap();
            assert_eq!(reply.snapshot.bytes_in_flight, 0);
            assert_eq!(reply.snapshot.reserved_in_flight, 1200);
            let Outcome::Reserved(ticket) = reply.outcome else {
                panic!("reserve")
            };
            let (sealed, mask, plaintext) = sealed_datagram(ticket.packet().value);
            let completion =
                crate::roles::path_owner::tests::submit_recovery(ticket, sealed, &plaintext, mask)
                    .await;
            let accepted_path = completion.path().unwrap();
            tx.send(Command::AdapterComplete(completion))
                .await
                .unwrap_or_else(|_| panic!("closed"));
            let reply = rrx.recv().await.unwrap();
            assert_eq!(reply.snapshot.bytes_in_flight, 1200);
            tx.send(Command::Ack {
                grant: grant(&arena, scope, 0, 0),
                now: 1010,
                context: context(),
            })
            .await
            .unwrap_or_else(|_| panic!("closed"));
            let reply = rrx.recv().await.unwrap();
            assert_eq!(reply.snapshot.bytes_in_flight, 0);
            assert_eq!(reply.snapshot.min_rtt_us, Some(1000));
            assert!(matches!(reply.outcome, Outcome::Acknowledged(_)));
            tx.send(Command::KeyPto {
                max_ack_delay_us: 25_000,
            })
            .await
            .unwrap_or_else(|_| panic!("closed"));
            assert!(matches!(
                rrx.recv().await.unwrap().outcome,
                Outcome::KeyPto(28_000)
            ));
            tx.send(Command::EcnMarking {
                path: accepted_path,
                now: 1010,
            })
            .await
            .unwrap_or_else(|_| panic!("closed"));
            assert!(matches!(
                rrx.recv().await.unwrap().outcome,
                Outcome::EcnMarking(Codepoint::NotEct)
            ));
            tx.send(Command::RejectZeroRtt(actual_retry_rejection(GENERATION)))
                .await
                .unwrap_or_else(|_| panic!("closed"));
            assert!(matches!(
                rrx.recv().await.unwrap().outcome,
                Outcome::ZeroRttRejected { bytes_removed: 0 }
            ));
            tx.send(Command::Reserve(SendPlan {
                in_flight: false,
                ..plan(None)
            }))
            .await
            .unwrap_or_else(|_| panic!("closed"));
            assert!(matches!(
                rrx.recv().await.unwrap().outcome,
                Outcome::Rejected(Rejection::Accounting(
                    accounting::AccountingError::InvalidClassification
                ))
            ));
            tx.send(Command::Retire)
                .await
                .unwrap_or_else(|_| panic!("closed"));
            assert!(matches!(
                rrx.recv().await.unwrap().outcome,
                Outcome::Retired
            ));
            Ok(())
        };
        drive(runtime::join2(service, workload)).unwrap();
        assert!(exchange.is_empty());
        assert!(tx.is_closed());
    });
    arena.finish(scope).unwrap();
}
#[test]
fn idle_pending_uses_real_waker_and_drop_cancels_endpoints_and_reply_slots() {
    with_roles(|mut client, mut endpoint| {
        let arena = Arena::<1, 1>::new(GENERATION);
        let mut slots = [None];
        let mut replies = [None];
        let commands = Mailbox::new(&mut slots).unwrap();
        let responses = Mailbox::new(&mut replies).unwrap();
        let (mut tx, rx) = commands.split().unwrap();
        let (rtx, mut rrx) = responses.split().unwrap();
        let mut exchange = Exchange::new();
        let (count, waker) = counted_waker();
        let mut cx = Context::from_waker(&waker);
        {
            let service = run_borrowed(
                &mut client,
                &mut endpoint,
                owner(),
                &arena,
                rx,
                rtx,
                &mut exchange,
            );
            let mut service = pin!(service);
            // Drive installation, drain its single reply, then park on commands.
            for _ in 0..24 {
                assert!(service.as_mut().poll(&mut cx).is_pending());
            }
            {
                let mut receive = pin!(rrx.recv());
                assert!(matches!(
                    receive.as_mut().poll(&mut cx),
                    Poll::Ready(Ok(Reply {
                        outcome: Outcome::Installed,
                        ..
                    }))
                ));
            }
            for _ in 0..8 {
                assert!(service.as_mut().poll(&mut cx).is_pending());
            }
            let before = count.0.load(Ordering::SeqCst);
            assert!(service.as_mut().poll(&mut cx).is_pending());
            assert_eq!(
                before,
                count.0.load(Ordering::SeqCst),
                "idle service self-woke"
            );
            let mut send = pin!(tx.send(Command::Reserve(plan(None))));
            assert!(matches!(send.as_mut().poll(&mut cx), Poll::Ready(Ok(()))));
            drop(send);
            assert!(
                count.0.load(Ordering::SeqCst) > before,
                "command failed to wake parked service"
            );
            for _ in 0..24 {
                assert!(service.as_mut().poll(&mut cx).is_pending());
            }
            let mut receive = pin!(rrx.recv());
            let Poll::Ready(Ok(reply)) = receive.as_mut().poll(&mut cx) else {
                panic!("reserve reply")
            };
            assert_eq!(reply.snapshot.reserved_in_flight, 1200);
            assert_eq!(reply.snapshot.bytes_in_flight, 0);
            // Drop with actual pending adapter reservation, never manufacture an
            // accepted send or cancel callback just because the role stops.
        }
        assert!(exchange.is_empty());
        assert!(tx.is_closed());
        assert!(drive(tx.send(Command::Inspect)).is_err());
    });
}

#[test]
fn abandoned_client_request_closes_channels_instead_of_reusing_a_stale_reply() {
    with_roles(|mut client, mut endpoint| {
        let arena = Arena::<1, 1>::new(GENERATION);
        let mut requests = [None];
        let mut replies = [None];
        let commands = Mailbox::new(&mut requests).unwrap();
        let responses = Mailbox::new(&mut replies).unwrap();
        let (tx, rx) = commands.split().unwrap();
        let (rtx, rrx) = responses.split().unwrap();
        let mut exchange = Exchange::new();
        let service = run_borrowed(
            &mut client,
            &mut endpoint,
            owner(),
            &arena,
            rx,
            rtx,
            &mut exchange,
        );
        let workload = async {
            let mut client = Client::connect(GENERATION, tx, rrx).await.unwrap();
            {
                let mut request = pin!(client.request(Command::Reserve(plan(None))));
                core::future::poll_fn(|cx| {
                    assert!(request.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                })
                .await;
                // Dropping the suspended actual request closes both halves.
            }
            assert!(client.commands.is_closed());
            assert!(client.replies.is_closed());
            assert!(matches!(
                client.request(Command::Inspect).await,
                Err(ClientError::CommandsClosed)
            ));
            Ok(())
        };
        assert!(matches!(
            drive(runtime::join2(service, workload)),
            Err(Error::RepliesClosed | Error::CommandsClosed)
        ));
        assert!(exchange.is_empty());
    });
}

#[test]
fn independent_recovery_pairs_compose_under_par_with_distinct_endpoints() {
    use hibana::{g, runtime::program::project};
    let global = g::par(
        p::recovery_choreography::<26, 27>(),
        p::recovery_choreography::<34, 35>(),
    );
    let _client_a = project::<26, _>(&global);
    let _owner_a = project::<27, _>(&global);
    let _client_b = project::<34, _>(&global);
    let _owner_b = project::<35, _>(&global);
}

#[test]
fn migration_keeps_pto_for_retained_old_path_data_without_charging_new_path() {
    let old = PathIdentity {
        connection_generation: GENERATION,
        slot: 0,
        path_generation: 0,
    };
    let new = PathIdentity {
        connection_generation: GENERATION,
        slot: 1,
        path_generation: 0,
    };
    let mut owner = owner();
    let sent = owner.reserve(descriptor(1), plan(None)).unwrap();
    owner
        .accepted(sent, 10, Codepoint::NotEct, Some(old))
        .unwrap();
    owner.reset_path(Some(new)).unwrap();
    assert_eq!(owner.snapshot().active_bytes_in_flight, 0);
    assert_eq!(owner.snapshot().bytes_in_flight, 1200);
    owner
        .timer(TimerCommand::Update {
            now: 10,
            keys_available: [true, false, false],
            context: TimerContext {
                is_server: true,
                handshake_confirmed: true,
                handshake_ack_received: true,
                server_amplification_blocked: false,
            },
            max_ack_delay_us: 25_000,
        })
        .unwrap();
    assert!(matches!(
        owner.snapshot().timer.unwrap().kind,
        recovery::TimerKind::Probe {
            space: PacketNumberSpace::Initial,
            ..
        }
    ));
}

#[test]
fn authenticated_plaintext_and_exact_ack_frame_cannot_be_substituted() {
    let arena = Arena::<1, 1>::new(GENERATION);
    let (receipt, packet) = authenticated_receipt(&[0]);
    let mut changed = [0; 5];
    changed.copy_from_slice(packet.body());
    changed[1] = 1;
    assert!(
        arena
            .admit(ReceiveEvidence::Initial(receipt), &changed)
            .is_err()
    );
    assert_eq!(arena.live_packets(), 0);
    let scope = authenticated_scope(&arena, &[0]);
    let different = [packet::AckRange {
        smallest: 1,
        largest: 1,
    }];
    assert!(
        arena
            .grant_ack(
                scope,
                0,
                packet::AckRanges::new(&different).unwrap(),
                0,
                None
            )
            .is_err()
    );
    assert_eq!(arena.live_effects(), 0);
    let original = grant(&arena, scope, 0, 0);
    let (_, frame) = arena.consume_ack(original).unwrap();
    assert_eq!(frame.ranges()[0], accounting::AckRange { start: 0, end: 0 });
    arena.finish(scope).unwrap();
}

#[test]
fn reserved_flight_binding_cannot_name_different_crypto_or_control_bytes() {
    let mut owner = owner();
    let flight = owner
        .flights
        .append(Level::Initial, 12, b"exact retained flight")
        .unwrap();
    let ticket = owner.reserve(descriptor(1), plan(Some(flight))).unwrap();
    let binding = ticket.flight().unwrap();
    assert!(binding.matches_crypto(12, b"exact retained flight"));
    assert!(!binding.matches_crypto(13, b"exact retained flight"));
    assert!(!binding.matches_crypto(12, b"other retained flight"));
    assert!(!binding.is_handshake_done());
    let control = owner.flights.append_handshake_done().unwrap();
    let ticket = owner
        .reserve(
            descriptor(2),
            SendPlan {
                kind: PacketKind::OneRtt,
                flight: Some(control),
                ..plan(None)
            },
        )
        .unwrap();
    let binding = ticket.flight().unwrap();
    assert!(binding.is_handshake_done());
    assert!(!binding.matches_crypto(0, &[0x1e]));
}

#[test]
fn probe_request_requires_real_pto_budget_and_late_rejection_cannot_restore_revoked_credit() {
    let mut owner = owner();
    let probe = SendPlan {
        pto_probe: true,
        ..plan(None)
    };
    assert_eq!(
        owner.reserve(descriptor(1), probe),
        Err(Rejection::ProbeUnavailable)
    );
    assert_eq!(owner.snapshot().next_packet_number[0], Some(0));
    let original = owner.reserve(descriptor(2), plan(None)).unwrap();
    owner
        .accepted(original, 10, Codepoint::NotEct, None)
        .unwrap();
    owner
        .timer(TimerCommand::Update {
            now: 10,
            keys_available: [true, false, false],
            context: TimerContext {
                is_server: false,
                handshake_confirmed: false,
                handshake_ack_received: false,
                server_amplification_blocked: false,
            },
            max_ack_delay_us: 0,
        })
        .unwrap();
    let at = owner.snapshot().timer.unwrap().at;
    let Outcome::Timeout(timeout) = owner.timer(TimerCommand::Expire { now: at }).unwrap() else {
        panic!("timeout")
    };
    assert!(timeout.path.is_none());
    assert!(timeout.stream.is_none());
    assert_eq!(owner.snapshot().pto_probe_credits, 2);
    let first = owner.reserve(descriptor(3), probe).unwrap();
    assert!(
        first.is_pto_probe(),
        "validated probe authority survives the publication ticket"
    );
    let second = owner.reserve(descriptor(4), probe).unwrap();
    assert_eq!(
        owner.reserve(descriptor(5), probe),
        Err(Rejection::ProbeUnavailable)
    );
    owner.rejected(first).unwrap();
    assert_eq!(owner.snapshot().pto_probe_credits, 1);
    let replacement = owner.reserve(descriptor(6), probe).unwrap();
    assert_eq!(owner.snapshot().pto_probe_credits, 0);
    let arena = Arena::<1, 1>::new(GENERATION);
    let scope = authenticated_scope(&arena, &[0]);
    owner
        .ack(&arena, grant(&arena, scope, 0, 0), at, context())
        .unwrap();
    assert_eq!(owner.snapshot().pto_probe_space, None);
    owner.rejected(second).unwrap();
    owner.rejected(replacement).unwrap();
    assert_eq!(owner.snapshot().pto_probe_credits, 0);
    assert_eq!(
        owner.reserve(descriptor(7), probe),
        Err(Rejection::ProbeUnavailable)
    );
    arena.finish(scope).unwrap();
}

#[test]
fn another_paths_acks_do_not_supply_packet_threshold_evidence() {
    let old = PathIdentity {
        connection_generation: GENERATION,
        slot: 0,
        path_generation: 0,
    };
    let new = PathIdentity {
        connection_generation: GENERATION,
        slot: 1,
        path_generation: 0,
    };
    let mut owner = owner();
    owner.config.active_path = Some(new);
    for n in 0..4 {
        let packet = owner.reserve(descriptor(n + 1), plan(None)).unwrap();
        owner
            .accepted(
                packet,
                10 + n * 10,
                Codepoint::NotEct,
                Some(if n == 0 { old } else { new }),
            )
            .unwrap();
    }
    let arena = Arena::<1, 1>::new(GENERATION);
    let scope = authenticated_scope(&arena, &[3]);
    owner
        .ack(
            &arena,
            grant(&arena, scope, 0, 3),
            1000,
            AckContext {
                received_path: Some(new),
                ..context()
            },
        )
        .unwrap();
    assert_eq!(
        owner
            .detect_loss(1000)
            .unwrap()
            .newly
            .iter()
            .flatten()
            .count(),
        0
    );
    let lost = owner.detect_loss(5000).unwrap();
    assert_eq!(lost.newly.iter().flatten().count(), 2);
    assert!(
        lost.newly
            .iter()
            .flatten()
            .all(|p| p.sent.path == Some(new))
    );
    assert_eq!(owner.snapshot().bytes_in_flight, 1200);
    assert_eq!(owner.snapshot().active_bytes_in_flight, 0);
    arena.finish(scope).unwrap();
}

#[test]
fn key_ack_grants_require_newly_acked_one_rtt_not_shared_space_zero_rtt_or_duplicates() {
    const PARAMETERS: &[u8] = &[15, 8, b'c', b'l', b'i', b'e', b'n', b't', b'i', b'd'];
    let payload = [2, 2, 0, 0, 2, 2, 2, 0, 0, 2]; // Two actual ACK frames covering PN 0..2.
    let (_, opened) = crate::roles::stream_owner::test_evidence::application_evidence(
        GENERATION, PARAMETERS, &payload,
    );
    let receive_generation = opened.receipt.key_generation();
    let arena = Arena::<1, 1>::new(GENERATION);
    let scope = arena
        .admit(ReceiveEvidence::Tls(opened.receipt), opened.packet.body())
        .unwrap();
    let mut owner = owner();
    for (n, kind) in [PacketKind::ZeroRtt, PacketKind::OneRtt, PacketKind::OneRtt]
        .into_iter()
        .enumerate()
    {
        let send = owner
            .reserve(descriptor(n as u64 + 1), SendPlan { kind, ..plan(None) })
            .unwrap();
        owner
            .accepted(send, 10 + n as u64 * 10, Codepoint::NotEct, None)
            .unwrap();
    }
    let ranges = [packet::AckRange {
        smallest: 0,
        largest: 2,
    }];
    let grant = arena
        .grant_ack(scope, 0, packet::AckRanges::new(&ranges).unwrap(), 0, None)
        .unwrap();
    let ack = owner
        .ack(
            &arena,
            grant,
            1030,
            AckContext {
                handshake_confirmed: true,
                ..context()
            },
        )
        .unwrap();
    assert_eq!(ack.summary.newly_acknowledged, 3);
    assert_eq!(ack.keys.iter().flatten().count(), 2);
    assert!(
        ack.keys
            .iter()
            .flatten()
            .all(|k| k.sent_packet_number() != 0
                && k.generation() == GENERATION
                && k.received_key_generation() == receive_generation)
    );
    let grant = arena
        .grant_ack(scope, 1, packet::AckRanges::new(&ranges).unwrap(), 0, None)
        .unwrap();
    let repeated = owner.ack(&arena, grant, 1030, context()).unwrap();
    assert!(repeated.keys.iter().all(Option::is_none));
    assert_eq!(repeated.summary.newly_acknowledged, 0);
    arena.finish(scope).unwrap();
}

fn ecn_owner(path: PathIdentity) -> RecoveryOwner<8, 2, 64, 16> {
    RecoveryOwner::new(Config {
        generation: GENERATION,
        initial_rtt_us: recovery::INITIAL_RTT_US,
        max_datagram_size: 1200,
        active_path: Some(path),
        ecn: Some(path),
        max_ack_delay_us: 25_000,
    })
    .unwrap()
}
fn ecn_grant<const P: usize, const E: usize>(
    arena: &Arena<P, E>,
    scope: packet_authority::PacketTicket,
    ordinal: u32,
    pn: u64,
    counts: packet::EcnCounts,
) -> AckGrant {
    let ranges = [packet::AckRange {
        smallest: pn,
        largest: pn,
    }];
    arena
        .grant_ack(
            scope,
            ordinal,
            packet::AckRanges::new(&ranges).unwrap(),
            0,
            Some(counts),
        )
        .unwrap()
}
#[test]
fn only_authenticated_validated_ack_ecn_feedback_can_reduce_newreno() {
    let path = PathIdentity {
        connection_generation: GENERATION,
        slot: 0,
        path_generation: 0,
    };
    let mut owner = ecn_owner(path);
    let arena = Arena::<1, 1>::new(GENERATION);
    assert!(matches!(
        owner
            .apply(&arena, descriptor(0), Command::EcnMarking { path, now: 0 })
            .unwrap(),
        Outcome::EcnMarking(Codepoint::Ect0)
    ));
    for n in 0..3 {
        let send = owner.reserve(descriptor(n + 1), plan(None)).unwrap();
        owner
            .accepted(send, 10 + n * 10, Codepoint::Ect0, Some(path))
            .unwrap();
    }
    let payload = [
        3, 0, 0, 0, 0, 0, 0, 1, 3, 0, 0, 0, 0, 0, 0, 1, 3, 1, 0, 0, 0, 0, 0, 2, 3, 3, 0, 0, 0, 0,
        0, 63,
    ];
    let (receipt, packet) = authenticated_payload(&payload);
    let scope = arena
        .admit(ReceiveEvidence::Initial(receipt), packet.body())
        .unwrap();
    let counts = packet::EcnCounts {
        ect0: 0,
        ect1: 0,
        ce: 1,
    };
    let ack = owner
        .ack(
            &arena,
            ecn_grant(&arena, scope, 0, 0, counts),
            100,
            AckContext {
                received_path: Some(path),
                ..context()
            },
        )
        .unwrap();
    assert_eq!(
        ack.ecn,
        Some(crate::ecn::Feedback::Validated { ce_increase: 1 })
    );
    assert_eq!(owner.snapshot().congestion_window, 6000);
    assert_eq!(owner.snapshot().bytes_in_flight, 2400);
    let ecn = owner.snapshot().ecn.unwrap();
    assert_eq!((ecn.validated_ce, ecn.congestion_events), (1, 1));
    owner
        .ack(
            &arena,
            ecn_grant(&arena, scope, 1, 0, counts),
            100,
            context(),
        )
        .unwrap();
    assert_eq!(owner.snapshot().ecn.unwrap().validated_ce, 1);
    owner
        .ack(
            &arena,
            ecn_grant(&arena, scope, 2, 1, packet::EcnCounts { ce: 2, ..counts }),
            101,
            context(),
        )
        .unwrap();
    let ecn = owner.snapshot().ecn.unwrap();
    assert_eq!((ecn.validated_ce, ecn.congestion_events), (2, 1));
    assert_eq!(owner.snapshot().congestion_window, 6000);
    assert!(matches!(
        owner.ack(
            &arena,
            ecn_grant(&arena, scope, 3, 3, packet::EcnCounts { ce: 63, ..counts }),
            102,
            context()
        ),
        Err(Rejection::Accounting(
            accounting::AccountingError::UnsentPacket
        ))
    ));
    assert_eq!(owner.snapshot().ecn.unwrap().validated_ce, 2);
    assert_eq!(owner.snapshot().bytes_in_flight, 1200);
    arena.finish(scope).unwrap();
}
#[test]
fn invalid_ecn_counts_disable_marking_without_undoing_a_valid_ack() {
    let path = PathIdentity {
        connection_generation: GENERATION,
        slot: 0,
        path_generation: 0,
    };
    let mut owner = ecn_owner(path);
    let send = owner.reserve(descriptor(1), plan(None)).unwrap();
    owner
        .accepted(send, 10, Codepoint::Ect0, Some(path))
        .unwrap();
    let arena = Arena::<1, 1>::new(GENERATION);
    let (receipt, packet) = authenticated_payload(&[3, 0, 0, 0, 0, 0, 0, 2]);
    let scope = arena
        .admit(ReceiveEvidence::Initial(receipt), packet.body())
        .unwrap();
    let ack = owner
        .ack(
            &arena,
            ecn_grant(
                &arena,
                scope,
                0,
                0,
                packet::EcnCounts {
                    ect0: 0,
                    ect1: 0,
                    ce: 2,
                },
            ),
            100,
            context(),
        )
        .unwrap();
    assert!(matches!(
        ack.ecn,
        Some(crate::ecn::Feedback::Failed(
            crate::ecn::Failure::ExcessCounts
        ))
    ));
    assert_eq!(owner.snapshot().bytes_in_flight, 0);
    assert_eq!(owner.snapshot().congestion_window, 13200);
    assert_eq!(owner.snapshot().ecn.unwrap().validated_ce, 0);
    assert!(matches!(
        owner
            .apply(
                &arena,
                descriptor(2),
                Command::EcnMarking { path, now: 100 }
            )
            .unwrap(),
        Outcome::EcnMarking(Codepoint::NotEct)
    ));
    arena.finish(scope).unwrap();
}
#[test]
fn optional_ecn_failure_never_relabels_actual_udp_acceptance_as_rejection() {
    let path = PathIdentity {
        connection_generation: GENERATION,
        slot: 0,
        path_generation: 0,
    };
    let mut owner = ecn_owner(path);
    let first = owner.reserve(descriptor(1), plan(None)).unwrap();
    let second = owner.reserve(descriptor(2), plan(None)).unwrap();
    owner
        .accepted(second, 10, Codepoint::Ect0, Some(path))
        .unwrap();
    owner
        .accepted(first, 11, Codepoint::Ect0, Some(path))
        .unwrap();
    assert_eq!(owner.snapshot().bytes_in_flight, 2400);
    assert_eq!(owner.snapshot().reserved_in_flight, 0);
    assert_eq!(owner.snapshot().accepted_ecn[0].ect0, 2);
    let ecn = owner.snapshot().ecn.unwrap();
    assert_eq!(ecn.disabled_error, Some(crate::ecn::Error::RepeatedSend));
    assert!(!ecn.active);
    let arena = Arena::<1, 1>::new(GENERATION);
    assert!(matches!(
        owner
            .apply(&arena, descriptor(3), Command::EcnMarking { path, now: 11 })
            .unwrap(),
        Outcome::EcnMarking(Codepoint::NotEct)
    ));
}
fn actual_retry_rejection(generation: u64) -> crate::roles::tls_owner::EarlyRejectedGrant {
    let mut retry = crate::retry::ClientRetry::<64>::new(b"original", b"clientid").unwrap();
    let mut wire = [0; 128];
    let mut scratch = [0; 256];
    let len = crate::retry::encode_retry(
        b"original",
        b"clientid",
        b"retrycid",
        b"token",
        0,
        &mut wire,
        &mut scratch,
    )
    .unwrap();
    let checked = retry.validate(&wire[..len], &mut scratch).unwrap();
    retry.commit(checked).unwrap();
    assert_eq!(retry.retry_source_id(), Some(&b"retrycid"[..]));
    crate::roles::tls_owner::EarlyRejectedGrant::after_validated_retry(generation)
}
#[test]
fn authentic_early_rejection_returns_its_grant_while_adapter_is_pending() {
    let mut owner = owner();
    let early = owner
        .reserve(
            descriptor(1),
            SendPlan {
                kind: PacketKind::ZeroRtt,
                ..plan(None)
            },
        )
        .unwrap();
    owner.accepted(early, 10, Codepoint::NotEct, None).unwrap();
    let ordinary = owner
        .reserve(
            descriptor(2),
            SendPlan {
                kind: PacketKind::OneRtt,
                ..plan(None)
            },
        )
        .unwrap();
    owner
        .accepted(ordinary, 20, Codepoint::NotEct, None)
        .unwrap();
    let pending = owner
        .reserve(
            descriptor(3),
            SendPlan {
                kind: PacketKind::ZeroRtt,
                ..plan(None)
            },
        )
        .unwrap();
    let Outcome::ZeroRttPending(grant) = owner
        .reject_zero_rtt(actual_retry_rejection(GENERATION))
        .unwrap()
    else {
        panic!("must retain grant")
    };
    assert_eq!(owner.snapshot().bytes_in_flight, 2400);
    assert_eq!(owner.snapshot().reserved_in_flight, 1200);
    owner.rejected(pending).unwrap();
    assert!(matches!(
        owner.reject_zero_rtt(grant).unwrap(),
        Outcome::ZeroRttRejected {
            bytes_removed: 1200
        }
    ));
    assert_eq!(owner.snapshot().bytes_in_flight, 1200);
    assert_eq!(owner.snapshot().congestion_window, 12000);
    assert_eq!(owner.snapshot().next_packet_number[2], Some(3));
    assert!(owner.sent.is_new_ack(ordinary.packet()));
    assert_eq!(
        owner.sent.validate_ack(
            PacketNumberSpace::ApplicationData,
            &[accounting::AckRange { start: 0, end: 0 }]
        ),
        Err(accounting::AccountingError::UnsentPacket)
    );
}
#[test]
fn key_pto_query_uses_owned_rtt_and_overflow_does_not_mutate_recovery() {
    let mut owner = owner();
    let arena = Arena::<1, 1>::new(GENERATION);
    let before = owner.snapshot();
    assert!(matches!(
        owner
            .apply(
                &arena,
                descriptor(1),
                Command::KeyPto {
                    max_ack_delay_us: 25_000
                }
            )
            .unwrap(),
        Outcome::KeyPto(1_024_000)
    ));
    assert!(matches!(
        owner.apply(
            &arena,
            descriptor(2),
            Command::KeyPto {
                max_ack_delay_us: u64::MAX
            }
        ),
        Err(Rejection::Recovery(recovery::RecoveryError::Overflow))
    ));
    assert_eq!(owner.snapshot().bytes_in_flight, before.bytes_in_flight);
    assert_eq!(owner.snapshot().congestion_window, before.congestion_window);
}
