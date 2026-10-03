use super::*;
#[path = "../../../tests/support/early_owner_fixture.rs"]
mod auth;
use crate::{
    carrier::CarrierStorage,
    mailbox::Mailbox,
    roles::{connection_authority, protocol_early::early_choreography},
    runtime,
};
use hibana::runtime::{SessionKitStorage, ids::SessionId, program::project};
const POLICY: ServerPolicy = ServerPolicy::BufferedReplaySafeRequests {
    max_bytes: 16,
    max_streams: 1,
};
const PAYLOAD: &[u8] = &[0x0b, 0, 3, b'g', b'e', b't', 0x10, 16];
fn context() -> PathContext {
    PathContext {
        address: crate::path::Address {
            local: "127.0.0.1:4433".parse().unwrap(),
            remote: "127.0.0.1:5000".parse().unwrap(),
        },
        destination: super::super::path_owner::Destination::new(&[]).unwrap(),
        datagram_id: 1,
        datagram_bytes: 1200,
        now: 1000,
    }
}
fn path(generation: u64) -> PathIdentity {
    PathIdentity {
        connection_generation: generation,
        path_generation: 1,
        slot: 0,
    }
}
fn ready(receipt: super::super::tls_owner::FinishedReceipt) -> EarlyReady {
    connection_authority::verify_and_split(
        receipt,
        auth::CLIENT_PARAMETERS,
        crate::parameters::Peer::Client,
        &[],
        None,
        None,
    )
    .unwrap()
    .early
}
fn packet<const N: usize>(receipt: EarlyOpenReceipt, payload: &[u8]) -> AuthenticatedPacket<N> {
    let generation = receipt.generation();
    AuthenticatedPacket::new(receipt, payload, context(), path(generation)).unwrap()
}
fn large(body: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(body)
        .unwrap()
        .join()
        .unwrap();
}
#[test]
fn exact_tls_plaintext_binding_and_wrong_generation_are_rejected() {
    large(|| {
        let mut evidence = auth::evidence(1601, PAYLOAD);
        assert!(matches!(
            AuthenticatedPacket::<128>::new(
                evidence.packets[0].take().unwrap(),
                &[1],
                context(),
                path(1601)
            ),
            Err(Fault::Binding)
        ));
        assert!(matches!(
            AuthenticatedPacket::<128>::new(
                evidence.packets[1].take().unwrap(),
                PAYLOAD,
                context(),
                path(1602)
            ),
            Err(Fault::WrongGeneration)
        ));
        let mut slots = [QuarantineSlot::EMPTY];
        let mut controls = [ControlSlot::<32>::EMPTY];
        let mut state =
            State::<16, 32, 128>::new(POLICY, evidence.grant, &mut slots, &mut controls).unwrap();
        assert!(matches!(state.release(), Err(Fault::NotReady)));
        let mut wrong = auth::evidence(1602, PAYLOAD);
        assert!(matches!(
            state.begin_admission(packet(wrong.packets[0].take().unwrap(), PAYLOAD)),
            Err(Fault::WrongGeneration)
        ));
        assert_eq!(
            state.finish(ready(wrong.finished)),
            Err(Fault::WrongGeneration)
        );
        assert_eq!(state.snapshot().charged, 0);
        assert!(!state.snapshot().release_ready);
    });
}
#[test]
fn pending_path_check_is_effect_free_and_cancellation_preserves_freshness() {
    large(|| {
        let mut evidence = auth::evidence(1603, PAYLOAD);
        let mut slots = [QuarantineSlot::EMPTY];
        let mut controls = [ControlSlot::<32>::EMPTY];
        let mut state =
            State::<16, 32, 128>::new(POLICY, evidence.grant, &mut slots, &mut controls).unwrap();
        let check = state
            .begin_admission(packet(evidence.packets[0].take().unwrap(), PAYLOAD))
            .unwrap()
            .unwrap();
        assert_eq!(state.snapshot().charged, 0);
        assert_eq!(state.snapshot().admitted_packets, 0);
        assert_eq!(state.snapshot().deferred_controls, 0);
        assert!(matches!(
            state.commit_admission(check.cancel()).unwrap(),
            Admission::Cancelled
        ));
        let check = state
            .begin_admission(packet(evidence.packets[1].take().unwrap(), PAYLOAD))
            .unwrap()
            .unwrap();
        assert!(matches!(
            state.commit_admission(check.complete()).unwrap(),
            Admission::Admitted(_)
        ));
        assert_eq!(state.snapshot().charged, 3);
        assert_eq!(state.snapshot().deferred_controls, 1);
        assert_eq!(state.snapshot().admitted_packets, 1);
        assert!(matches!(state.release(), Err(Fault::NotReady)));
        drop(state);
        assert_eq!(controls[0].bytes, [0; 32]);
        assert!(controls[0].context.is_none());
    });
}
#[test]
fn actual_finished_releases_bound_frames_once_and_settlement_handles_backpressure() {
    large(|| {
        let mut evidence = auth::evidence(1604, PAYLOAD);
        let mut slots = [QuarantineSlot::EMPTY];
        let mut controls = [ControlSlot::<32>::EMPTY];
        let mut state =
            State::<16, 32, 128>::new(POLICY, evidence.grant, &mut slots, &mut controls).unwrap();
        let check = state
            .begin_admission(packet(evidence.packets[0].take().unwrap(), PAYLOAD))
            .unwrap()
            .unwrap();
        state.commit_admission(check.complete()).unwrap();
        assert!(
            state
                .begin_admission(packet(evidence.packets[1].take().unwrap(), PAYLOAD))
                .unwrap()
                .is_none()
        );
        state.finish(ready(evidence.finished)).unwrap();
        let Some(Release::Application(grant)) = state.release().unwrap() else {
            panic!("stream first")
        };
        assert_eq!(
            grant.frame().unwrap(),
            Frame::Stream {
                id: 0,
                offset: 0,
                fin: true,
                data: b"get"
            }
        );
        assert!(matches!(state.release(), Err(Fault::Busy)));
        let id = grant.id;
        assert_eq!(
            state.settle(ReleaseCompletion {
                id: ReleaseId {
                    binding: id.binding,
                    generation: id.generation + 1,
                    sequence: id.sequence
                },
                accepted: true
            }),
            Err(Fault::Stale)
        );
        assert_eq!(
            state.settle(ReleaseCompletion {
                id: ReleaseId {
                    binding: id.binding,
                    generation: id.generation,
                    sequence: id.sequence + 1
                },
                accepted: true
            }),
            Err(Fault::Stale)
        );
        assert!(state.snapshot().pending_release);
        let mut other_storage = early_data::ReplayStorage::<1>::new();
        let other_binding = early_data::ReplayLedger::bind([99; 16], &mut other_storage)
            .unwrap()
            .claim_after_authentication([99; 16], [5; 12], 100, 0, id.generation)
            .unwrap()
            .owner_binding();
        assert_eq!(
            state.settle(ReleaseCompletion {
                id: ReleaseId {
                    binding: other_binding,
                    generation: id.generation,
                    sequence: id.sequence
                },
                accepted: true
            }),
            Err(Fault::Stale)
        );
        state.settle(grant.cancel()).unwrap();
        let Some(Release::Application(grant)) = state.release().unwrap() else {
            panic!("retry stream")
        };
        assert_eq!(
            grant.frame().unwrap(),
            Frame::Stream {
                id: 0,
                offset: 0,
                fin: true,
                data: b"get"
            }
        );
        state.settle(grant.complete()).unwrap();
        let Some(Release::Application(grant)) = state.release().unwrap() else {
            panic!("control next")
        };
        assert_eq!(grant.frame().unwrap(), Frame::MaxData { maximum: 16 });
        state.settle(grant.complete()).unwrap();
        assert!(state.release().unwrap().is_none());
        // A later authenticated copy of an already released STREAM contributes no
        // duplicate bytes or FIN; its separate control remains a real new frame.
        let check = state
            .begin_admission(packet(evidence.packets[2].take().unwrap(), PAYLOAD))
            .unwrap()
            .unwrap();
        state.commit_admission(check.complete()).unwrap();
        let Some(Release::Application(grant)) = state.release().unwrap() else {
            panic!("new control")
        };
        assert_eq!(grant.frame().unwrap(), Frame::MaxData { maximum: 16 });
        state.settle(grant.complete()).unwrap();
        assert!(state.release().unwrap().is_none());
    });
}
#[test]
fn control_capacity_failure_does_not_mark_packet_or_charge_stream_bytes() {
    large(|| {
        let mut evidence = auth::evidence(1605, PAYLOAD);
        let mut slots = [QuarantineSlot::EMPTY];
        let mut controls = [];
        let mut state =
            State::<16, 32, 128>::new(POLICY, evidence.grant, &mut slots, &mut controls).unwrap();
        assert!(matches!(
            state.begin_admission(packet(evidence.packets[0].take().unwrap(), PAYLOAD)),
            Err(Fault::Capacity)
        ));
        assert_eq!(state.snapshot().charged, 0);
        assert_eq!(state.snapshot().admitted_packets, 0);
        assert!(state.fresh(1));
    });
}
#[test]
fn terminal_close_wipes_quarantine_without_finished_and_preserves_reason() {
    large(|| {
        let payload = &[0x1d, 7, 3, b'b', b'y', b'e'];
        let mut evidence = auth::evidence(1606, payload);
        let mut slots = [QuarantineSlot::EMPTY];
        let mut controls = [];
        let mut state =
            State::<16, 32, 128>::new(POLICY, evidence.grant, &mut slots, &mut controls).unwrap();
        let check = state
            .begin_admission(packet(evidence.packets[0].take().unwrap(), payload))
            .unwrap()
            .unwrap();
        let Admission::PeerClose(close) = state.commit_admission(check.complete()).unwrap() else {
            panic!("terminal")
        };
        assert_eq!(
            close.frame().unwrap(),
            Frame::ConnectionClose {
                error_code: 7,
                frame_type: None,
                reason: b"bye"
            }
        );
        assert!(state.snapshot().retired);
        assert!(matches!(state.release(), Err(Fault::NotReady)));
    });
}
#[test]
fn q1_projected_holding_and_release_continuations_use_real_owned_resources() {
    large(|| {
        let mut evidence = auth::evidence(1607, PAYLOAD);
        let mut slots = [QuarantineSlot::EMPTY];
        let mut controls = [ControlSlot::<32>::EMPTY];
        let state =
            State::<16, 32, 128>::new(POLICY, evidence.grant, &mut slots, &mut controls).unwrap();
        let carrier = CarrierStorage::<1, 16, 48>::new();
        let mut slab = [0; 65536];
        let mut storage = SessionKitStorage::uninit();
        let kit = storage.init();
        let sid = SessionId::new(1607);
        let rv = kit
            .rendezvous(&mut slab, carrier.bind(sid).unwrap())
            .unwrap();
        let global = early_choreography::<32, 33>();
        let cp = project::<32, _>(&global);
        let op = project::<33, _>(&global);
        let mut c = rv.enter(sid, &cp).unwrap();
        let mut o = rv.enter(sid, &op).unwrap();
        let mut cq = [None];
        let mut rq = [None];
        let cq = Mailbox::new(&mut cq).unwrap();
        let rq = Mailbox::new(&mut rq).unwrap();
        let (tx, rx) = cq.split().unwrap();
        let (rtx, rrx) = rq.split().unwrap();
        let mut exchange = Exchange::new();
        let workload = async {
            let mut client = Client::connect(tx, rrx, 1607).await.unwrap();
            let Outcome::Check(check) = client
                .request(Command::Receive(packet(
                    evidence.packets[0].take().unwrap(),
                    PAYLOAD,
                )))
                .await
                .unwrap()
            else {
                panic!("path check")
            };
            assert_eq!(client.snapshot().charged, 0);
            assert!(matches!(
                client
                    .request(Command::Checked(check.complete()))
                    .await
                    .unwrap(),
                Outcome::Admission(Admission::Admitted(_))
            ));
            assert!(matches!(
                client
                    .request(Command::Finish(ready(evidence.finished)))
                    .await
                    .unwrap(),
                Outcome::Ready
            ));
            for expected in [b"get".as_slice(), b"".as_slice()] {
                let Outcome::Release(Some(Release::Application(grant))) =
                    client.request(Command::Release).await.unwrap()
                else {
                    panic!("release")
                };
                if !expected.is_empty() {
                    assert!(
                        matches!(grant.frame().unwrap(),Frame::Stream {data,..} if data==expected)
                    );
                }
                assert!(matches!(
                    client
                        .request(Command::Settle(grant.complete()))
                        .await
                        .unwrap(),
                    Outcome::Settled
                ));
            }
            assert!(matches!(
                client.request(Command::Release).await.unwrap(),
                Outcome::Release(None)
            ));
            client.retire().await.unwrap();
            Ok(())
        };
        auth::drive(runtime::join2(
            run_borrowed(&mut c, &mut o, state, rx, rtx, &mut exchange),
            workload,
        ))
        .unwrap();
        assert!(exchange.is_empty());
        assert_eq!(controls[0].bytes, [0; 32]);
    });
}

#[test]
fn cancelling_a_live_q1_role_erases_held_controls_and_clears_exchange() {
    large(|| {
        use core::{
            future::Future,
            task::{Context, Poll, Waker},
        };
        let mut evidence = auth::evidence(1608, PAYLOAD);
        let mut slots = [QuarantineSlot::EMPTY];
        let mut controls = [ControlSlot::<32>::EMPTY];
        let state =
            State::<16, 32, 128>::new(POLICY, evidence.grant, &mut slots, &mut controls).unwrap();
        let carrier = CarrierStorage::<1, 16, 48>::new();
        let mut slab = [0; 65536];
        let mut storage = SessionKitStorage::uninit();
        let kit = storage.init();
        let sid = SessionId::new(1608);
        let rv = kit
            .rendezvous(&mut slab, carrier.bind(sid).unwrap())
            .unwrap();
        let global = early_choreography::<32, 33>();
        let cp = project::<32, _>(&global);
        let op = project::<33, _>(&global);
        let mut c = rv.enter(sid, &cp).unwrap();
        let mut o = rv.enter(sid, &op).unwrap();
        let mut cq = [None];
        let mut rq = [None];
        let cq = Mailbox::new(&mut cq).unwrap();
        let rq = Mailbox::new(&mut rq).unwrap();
        let (tx, rx) = cq.split().unwrap();
        let (rtx, rrx) = rq.split().unwrap();
        let mut exchange = Exchange::new();
        let workload = async {
            let mut client = Client::connect(tx, rrx, 1608).await.unwrap();
            let Outcome::Check(check) = client
                .request(Command::Receive(packet(
                    evidence.packets[0].take().unwrap(),
                    PAYLOAD,
                )))
                .await
                .unwrap()
            else {
                panic!("path check")
            };
            assert!(matches!(
                client
                    .request(Command::Checked(check.complete()))
                    .await
                    .unwrap(),
                Outcome::Admission(Admission::Admitted(_))
            ));
            assert_eq!(client.snapshot().charged, 3);
            assert_eq!(client.snapshot().deferred_controls, 1);
            core::future::pending::<Result<(), ServiceError>>().await
        };
        {
            let mut running = core::pin::pin!(runtime::join2(
                run_borrowed(&mut c, &mut o, state, rx, rtx, &mut exchange),
                workload
            ));
            let mut cx = Context::from_waker(Waker::noop());
            for _ in 0..64 {
                assert!(matches!(running.as_mut().poll(&mut cx), Poll::Pending));
            }
        }
        assert!(exchange.is_empty());
        assert_eq!(controls[0].bytes, [0; 32]);
        assert!(controls[0].context.is_none());
    });
}

#[test]
fn authenticated_zero_rtt_ack_cannot_mint_any_effect_authority() {
    large(|| {
        let payload = &[2, 0, 0, 0, 0];
        let mut evidence = auth::evidence(1609, payload);
        let mut slots = [QuarantineSlot::EMPTY];
        let mut controls = [ControlSlot::<32>::EMPTY];
        let mut state =
            State::<16, 32, 128>::new(POLICY, evidence.grant, &mut slots, &mut controls).unwrap();
        assert!(matches!(
            state.begin_admission(packet(evidence.packets[0].take().unwrap(), payload)),
            Err(Fault::Packet(packet::Error::FrameNotAllowed { .. }))
        ));
        assert_eq!(state.snapshot().admitted_packets, 0);
        assert_eq!(state.snapshot().charged, 0);
        assert_eq!(state.snapshot().deferred_controls, 0);
    });
}

#[test]
fn non_accepted_actual_finished_erases_quarantine_and_deferred_controls() {
    large(|| {
        let mut evidence = auth::evidence(1610, PAYLOAD);
        let mut slots = [QuarantineSlot::EMPTY];
        let mut controls = [ControlSlot::<32>::EMPTY];
        let mut state =
            State::<16, 32, 128>::new(POLICY, evidence.grant, &mut slots, &mut controls).unwrap();
        let check = state
            .begin_admission(packet(evidence.packets[0].take().unwrap(), PAYLOAD))
            .unwrap()
            .unwrap();
        state.commit_admission(check.complete()).unwrap();
        assert_eq!(state.snapshot().charged, 3);
        assert_eq!(
            state.finish(ready(auth::disabled_finished(1610))),
            Err(Fault::RejectedDecision)
        );
        assert!(state.snapshot().retired);
        assert_eq!(state.snapshot().charged, 0);
        assert_eq!(state.snapshot().deferred_controls, 0);
        assert!(matches!(state.release(), Err(Fault::NotReady)));
        drop(state);
        assert_eq!(controls[0].bytes, [0; 32]);
    });
}

#[test]
fn first_finished_then_repeated_inspection_and_retirement_needs_no_dummy_packet() {
    large(|| {
        let evidence = auth::evidence(1611, PAYLOAD);
        let mut slots = [QuarantineSlot::EMPTY];
        let mut controls = [ControlSlot::<32>::EMPTY];
        let state =
            State::<16, 32, 128>::new(POLICY, evidence.grant, &mut slots, &mut controls).unwrap();
        let carrier = CarrierStorage::<1, 16, 48>::new();
        let mut slab = [0; 65536];
        let mut storage = SessionKitStorage::uninit();
        let kit = storage.init();
        let sid = SessionId::new(1611);
        let rv = kit
            .rendezvous(&mut slab, carrier.bind(sid).unwrap())
            .unwrap();
        let global = early_choreography::<32, 33>();
        let cp = project::<32, _>(&global);
        let op = project::<33, _>(&global);
        let mut c = rv.enter(sid, &cp).unwrap();
        let mut o = rv.enter(sid, &op).unwrap();
        let mut cq = [None];
        let mut rq = [None];
        let cq = Mailbox::new(&mut cq).unwrap();
        let rq = Mailbox::new(&mut rq).unwrap();
        let (tx, rx) = cq.split().unwrap();
        let (rtx, rrx) = rq.split().unwrap();
        let mut exchange = Exchange::new();
        let work = async {
            let mut client = Client::connect(tx, rrx, 1611).await.unwrap();
            assert!(matches!(
                client
                    .request(Command::Finish(ready(evidence.finished)))
                    .await
                    .unwrap(),
                Outcome::Ready
            ));
            for _ in 0..3 {
                assert!(matches!(
                    client.request(Command::Inspect).await.unwrap(),
                    Outcome::Inspected
                ));
            }
            assert!(matches!(
                client.request(Command::Release).await.unwrap(),
                Outcome::Release(None)
            ));
            client.retire().await.unwrap();
            Ok(())
        };
        auth::drive(runtime::join2(
            run_borrowed(&mut c, &mut o, state, rx, rtx, &mut exchange),
            work,
        ))
        .unwrap();
        assert!(exchange.is_empty());
        assert!(cq.is_empty());
        assert!(rq.is_empty());
    });
}
