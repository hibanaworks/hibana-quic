//! Numerical owner tests; authority is never fabricated to exercise delivery.
//! Private numerical helpers test atomic storage invariants separately from the
//! authenticated grant ingress covered by the connection/recovery actor tests.
use super::*;

pub(super) const LIMITS: Limits = Limits {
    max_data: 128,
    max_streams_bidi: 2,
    max_streams_uni: 2,
    stream_data_bidi_local: 32,
    stream_data_bidi_remote: 32,
    stream_data_uni: 32,
};
fn with_state(body: impl FnOnce(&mut State<'_, 32, 16, 2, 4>)) {
    let mut slots = [StreamSlot::EMPTY; 8];
    let mut chunks = [SendChunk::EMPTY; 4];
    let mut references = [PacketReference::EMPTY; 8];
    let mut state = State::new(
        911,
        Role::Server,
        LIMITS,
        &mut slots,
        &mut chunks,
        &mut references,
        80,
        None,
    )
    .unwrap();
    body(&mut state);
}
pub(super) fn numeric_ready(state: &mut State<'_, 32, 16, 2, 4>) {
    const RAW: &[u8] = &[
        15, 8, b'c', b'l', b'i', b'e', b'n', b't', b'i', b'd', 4, 2, 0x40, 128, 5, 1, 32, 6, 1, 32,
        7, 1, 32, 8, 1, 2, 9, 1, 2,
    ];
    let finished = crate::driver::test_support::finished_with_parameters(911, RAW);
    let grants = crate::roles::connection_authority::verify_and_split(
        finished,
        RAW,
        crate::parameters::Peer::Client,
        b"clientid",
        None,
        None,
    )
    .unwrap();
    state.peer_ready(grants.application).unwrap();
}
fn open(state: &mut State<'_, 32, 16, 2, 4>) -> StreamHandle {
    state.table.open_local(true).unwrap()
}
fn applied(result: Result<Outcome<64>, Fault>) {
    assert!(matches!(result, Ok(Outcome::Applied)));
}

#[test]
fn admission_starts_closed_until_actual_finished_grant() {
    with_state(|state| {
        let authority = packet_authority::Arena::<1, 2>::new(911);
        assert!(matches!(
            state.execute::<64, 1, 2>(
                Command::Open {
                    bidirectional: true
                },
                &authority
            ),
            Err(Fault::NotReady)
        ));
        assert_eq!(state.snapshot().live_count, 0);
    });
}

fn committed_retry(generation: u64) -> packet_authority::StreamRetryGrant {
    let mut retry = crate::retry::ClientRetry::<64>::new(b"original", b"clientid").unwrap();
    let mut packet = [0; 128];
    let mut scratch = [0; 256];
    let len = crate::retry::encode_retry(
        b"original",
        b"clientid",
        b"retrycid",
        b"token",
        0,
        &mut packet,
        &mut scratch,
    )
    .unwrap();
    let checked = retry.validate(&packet[..len], &mut scratch).unwrap();
    packet_authority::split_retry(generation, retry.commit_with_receipt(checked).unwrap()).stream
}

#[test]
fn retry_requires_actual_commit_and_matching_client_generation() {
    let mut slots = [StreamSlot::<32>::EMPTY];
    let mut chunks = [SendChunk::<16>::EMPTY];
    let mut references = [PacketReference::EMPTY];
    let mut state = State::<32, 16, 2, 4>::new(
        911,
        Role::Client,
        Limits::ZERO,
        &mut slots,
        &mut chunks,
        &mut references,
        83,
        None,
    )
    .unwrap();
    let arena = packet_authority::Arena::<1, 2>::new(911);
    assert!(matches!(
        state.execute::<64, 1, 2>(Command::Retry(committed_retry(912)), &arena),
        Err(Fault::WrongGeneration)
    ));
    assert!(matches!(
        state.execute::<64, 1, 2>(Command::Retry(committed_retry(911)), &arena),
        Ok(Outcome::Applied)
    ));
    assert_eq!(state.table.live_count(), 0);
    with_state(|server| {
        assert!(matches!(
            server.execute::<64, 1, 2>(Command::Retry(committed_retry(911)), &arena),
            Err(Fault::NotReady)
        ));
        assert_eq!(server.table.live_count(), 0);
    });
}
#[test]
fn validated_peer_parameters_enable_only_matching_generation() {
    const RAW: &[u8] = &[
        15, 8, b'c', b'l', b'i', b'e', b'n', b't', b'i', b'd', 4, 2, 0x40, 128, 5, 1, 32, 6, 1, 32,
        7, 1, 32, 8, 1, 2, 9, 1, 2,
    ];
    let receipt = crate::driver::test_support::finished_with_parameters(911, RAW);
    let grants = crate::roles::connection_authority::verify_and_split(
        receipt,
        RAW,
        crate::parameters::Peer::Client,
        b"clientid",
        None,
        None,
    )
    .unwrap();
    with_state(|state| {
        state.peer_ready(grants.application).unwrap();
        assert!(state.snapshot().ready);
        assert_eq!(state.table.peer_limits(), LIMITS);
        assert_eq!(open(state).id(), 1);
        state.early_ready(grants.early).unwrap();
    });
    let receipt = crate::driver::test_support::finished_with_parameters(912, RAW);
    let grants = crate::roles::connection_authority::verify_and_split(
        receipt,
        RAW,
        crate::parameters::Peer::Client,
        b"clientid",
        None,
        None,
    )
    .unwrap();
    with_state(|state| {
        assert_eq!(
            state.peer_ready(grants.application),
            Err(Fault::WrongGeneration)
        );
        assert!(!state.ready());
        assert_eq!(state.table.peer_limits(), Limits::ZERO);
    });
}
#[test]
fn copied_read_wraps_without_exposing_owner_borrow() {
    with_state(|state| {
        numeric_ready(state);
        let h = state.table.get_or_accept(0).unwrap();
        state
            .deliver(Frame::Stream {
                id: 0,
                offset: 0,
                fin: false,
                data: &[7; 24],
            })
            .unwrap();
        state.consume(h, 24).unwrap();
        state
            .deliver(Frame::Stream {
                id: 0,
                offset: 24,
                fin: true,
                data: b"abcdefghijklmnop",
            })
            .unwrap();
        let authority = packet_authority::Arena::<1, 2>::new(911);
        let Outcome::Read(first) = state
            .execute::<64, 1, 2>(
                Command::Read {
                    stream: h,
                    maximum: 10,
                },
                &authority,
            )
            .unwrap()
        else {
            panic!("missing read")
        };
        assert_eq!(first.bytes.as_bytes(), b"abcdefghij");
        assert!(!first.fin);
        assert_eq!(first.remaining, 6);
        // Owner mutates while the copied result remains owned by the application.
        state.consume(h, 10).unwrap();
        assert_eq!(first.bytes.as_bytes(), b"abcdefghij");
        let Outcome::Read(second) = state
            .execute::<64, 1, 2>(
                Command::Read {
                    stream: h,
                    maximum: 64,
                },
                &authority,
            )
            .unwrap()
        else {
            panic!("missing read")
        };
        assert_eq!(second.bytes.as_bytes(), b"klmnop");
        assert!(second.fin);
    });
}

#[test]
fn large_receive_ring_is_drained_through_bounded_copied_replies() {
    let mut slots = [StreamSlot::<16384>::EMPTY; 2];
    let mut chunks = [SendChunk::<16>::EMPTY];
    let mut references = [PacketReference::EMPTY];
    let local = Limits {
        max_data: 16384,
        max_streams_bidi: 1,
        stream_data_bidi_remote: 16384,
        ..Limits::ZERO
    };
    let mut state = State::<16384, 16, 2, 4>::new(
        911,
        Role::Server,
        local,
        &mut slots,
        &mut chunks,
        &mut references,
        81,
        None,
    )
    .unwrap();
    const RAW: &[u8] = &[15, 8, b'c', b'l', b'i', b'e', b'n', b't', b'i', b'd'];
    let receipt = crate::driver::test_support::finished_with_parameters(911, RAW);
    let grants = crate::roles::connection_authority::verify_and_split(
        receipt,
        RAW,
        crate::parameters::Peer::Client,
        b"clientid",
        None,
        None,
    )
    .unwrap();
    state.peer_ready(grants.application).unwrap();
    state
        .deliver(Frame::Stream {
            id: 0,
            offset: 0,
            fin: true,
            data: &[7; 128],
        })
        .unwrap();
    let handle = state.table.lookup(0).unwrap();
    let arena = packet_authority::Arena::<1, 2>::new(911);
    let Outcome::Read(first) = state
        .execute::<64, 1, 2>(
            Command::Read {
                stream: handle,
                maximum: usize::MAX,
            },
            &arena,
        )
        .unwrap()
    else {
        panic!("read reply");
    };
    assert_eq!(first.bytes.as_bytes(), &[7; 64]);
    assert_eq!(first.remaining, 64);
    assert!(!first.fin);
    state.consume(handle, 64).unwrap();
    let Outcome::Read(last) = state
        .execute::<64, 1, 2>(
            Command::Read {
                stream: handle,
                maximum: 64,
            },
            &arena,
        )
        .unwrap()
    else {
        panic!("read reply");
    };
    assert_eq!(last.bytes.as_bytes(), &[7; 64]);
    assert_eq!(last.remaining, 0);
    assert!(last.fin);
    assert_eq!(first.bytes.as_bytes(), &[7; 64]);
}

#[test]
fn equal_generation_and_sequence_do_not_authorize_foreign_prepared_bytes() {
    with_state(|first| {
        numeric_ready(first);
        let stream = open(first);
        first
            .queue
            .enqueue(&mut first.table, stream, b"first", true)
            .unwrap();
        let own = first.prepare::<64>(false, false).unwrap().unwrap();
        with_state(|second| {
            numeric_ready(second);
            let stream = open(second);
            second
                .queue
                .enqueue(&mut second.table, stream, b"other", true)
                .unwrap();
            let foreign = second.prepare::<64>(false, false).unwrap().unwrap();
            assert_eq!(own.id.generation, foreign.id.generation);
            assert_eq!(own.id.sequence, foreign.id.sequence);
            assert_ne!(own.id, foreign.id);
            assert_eq!(first.reserve(foreign.id, 1), Err(Fault::Stale));
            assert!(matches!(first.pending, Some(PendingTx::Prepared(id, _, _)) if id == own.id));
            let copied = own.id;
            let reservation = first.reserve(copied, 1).unwrap();
            assert_eq!(reservation.prepared_id(), own.id);
            assert_eq!(first.reserve(own.id, 2), Err(Fault::Stale));
        });
    });
}
#[test]
fn selected_and_reserved_transmissions_reject_late_retained_ids() {
    with_state(|state| {
        numeric_ready(state);
        let h = open(state);
        state
            .queue
            .enqueue(&mut state.table, h, b"request", true)
            .unwrap();
        let first = state.prepare::<64>(false, false).unwrap().unwrap();
        assert!(matches!(
            state.prepare::<64>(false, false),
            Err(Fault::Busy)
        ));
        let old = state.reserve(first.id, 1).unwrap();
        assert!(matches!(state.reserve(first.id, 2), Err(Fault::Stale)));
        state.adapter_result(old, false).unwrap();
        assert_eq!(state.queue.active_references(), 0);
        assert_eq!(state.queue.queued_chunks(), 1);
        let next = state.prepare::<64>(false, false).unwrap().unwrap();
        assert_ne!(first.id, next.id);
        let current = state.reserve(next.id, 2).unwrap();
        assert_eq!(state.adapter_result(old, true), Err(Fault::Stale));
        state.adapter_result(current, true).unwrap();
        assert_eq!(state.queue.active_references(), 1);
        assert!(state.prepare::<64>(false, false).unwrap().is_none());
        assert!(
            matches!(state.prepare::<64>(true, false), Err(Fault::NotReady)),
            "raw probe boolean is not timer authority"
        );
        let probe = state.queue.probe_chunk().unwrap();
        assert_eq!(state.queue.chunk(probe).unwrap().data, b"request");
    });
}
#[test]
fn capacity_failure_preserves_receive_bytes_and_credit() {
    with_state(|state| {
        numeric_ready(state);
        let a = state.table.get_or_accept(0).unwrap();
        let b = state.table.get_or_accept(4).unwrap();
        state
            .deliver(Frame::Stream {
                id: 0,
                offset: 0,
                fin: false,
                data: b"abc",
            })
            .unwrap();
        state
            .controls
            .push(ControlKind::Stop {
                stream: a,
                error_code: 1,
            })
            .unwrap();
        state
            .controls
            .push(ControlKind::Stop {
                stream: b,
                error_code: 1,
            })
            .unwrap();
        let before = state.table.receive_data_capacity();
        assert_eq!(
            state.consume(a, 3),
            Err(Fault::Streams(streams::Error::Capacity))
        );
        assert_eq!(state.table.receive(a).unwrap().first, b"abc");
        assert_eq!(state.table.receive_data_capacity(), before);
    });
}
#[test]
fn incoming_stop_retains_sent_data_until_reset_is_acked() {
    with_state(|state| {
        numeric_ready(state);
        let h = open(state);
        state
            .queue
            .enqueue(&mut state.table, h, b"data", false)
            .unwrap();
        let first = state.prepare::<64>(false, false).unwrap().unwrap();
        let tx = state.reserve(first.id, 9).unwrap();
        state.adapter_result(tx, true).unwrap();
        state
            .deliver(Frame::StopSending {
                id: h.id(),
                error_code: 42,
            })
            .unwrap();
        let reset = state.prepare::<64>(false, false).unwrap().unwrap();
        // Check control numerics directly, while wire parsing has its own tests.
        assert!(state.controls.entries.iter().any(|entry| matches!(
            entry.kind,
            Some(ControlKind::Reset {
                error_code: 42,
                final_size: 4,
                ..
            })
        )));
        assert!(!reset.bytes.as_bytes().is_empty());
        assert_eq!(state.queue.active_references(), 1);
    });
}
#[test]
fn closing_revokes_pending_transmission_and_table_handles() {
    with_state(|state| {
        numeric_ready(state);
        let h = open(state);
        state
            .queue
            .enqueue(&mut state.table, h, b"data", true)
            .unwrap();
        let prepared = state.prepare::<64>(false, false).unwrap().unwrap();
        let tx = state.reserve(prepared.id, 1).unwrap();
        state.close();
        assert_eq!(state.adapter_result(tx, true), Err(Fault::Stale));
        assert_eq!(state.table.receive(h).err(), Some(streams::Error::Closed));
        assert!(!state.snapshot().pending_transmission);
    });
}

#[test]
fn authenticated_frame_grant_delivers_exact_bytes_and_revocation_blocks_late_delivery() {
    const RAW: &[u8] = &[
        15, 8, b'c', b'l', b'i', b'e', b'n', b't', b'i', b'd', 4, 2, 0x40, 128, 5, 1, 32, 6, 1, 32,
        7, 1, 32, 8, 1, 2, 9, 1, 2,
    ];
    let mut wire = [0; 64];
    let n = packet::encode_frame(
        &Frame::Stream {
            id: 0,
            offset: 0,
            fin: true,
            data: b"authenticated",
        },
        &mut wire,
    )
    .unwrap();
    let second = packet::encode_frame(
        &Frame::Stream {
            id: 4,
            offset: 0,
            fin: true,
            data: b"late",
        },
        &mut wire[n..],
    )
    .unwrap();
    let (finished, opened) =
        super::test_evidence::application_evidence(911, RAW, &wire[..n + second]);
    let grants = crate::roles::connection_authority::verify_and_split(
        finished,
        RAW,
        crate::parameters::Peer::Client,
        b"clientid",
        None,
        None,
    )
    .unwrap();
    let authority = packet_authority::Arena::<1, 2>::new(911);
    let ticket = authority
        .admit(
            packet_authority::ReceiveEvidence::Tls(opened.receipt),
            opened.packet.body(),
        )
        .unwrap();
    let mut parsed = packet::FrameIter::new(
        opened.packet.body(),
        packet::EncryptionLevel::OneRtt,
        packet::ParseLimits::default(),
    )
    .unwrap();
    let frame = parsed.next().unwrap().unwrap();
    let later_frame = parsed.next().unwrap().unwrap();
    let delivery = authority.grant_delivery::<64>(ticket, 0, frame).unwrap();
    with_state(|state| {
        state.peer_ready(grants.application).unwrap();
        applied(state.execute(Command::Deliver(delivery), &authority));
        let h = state.table.lookup(0).unwrap();
        assert_eq!(state.table.receive(h).unwrap().first, b"authenticated");
        assert!(state.table.receive(h).unwrap().fin);
        // Authority cancels the whole packet scope before an already queued grant
        // runs. Its retained ID and copied frame cannot reopen application effects.
        let late = authority
            .grant_delivery::<64>(ticket, 1, later_frame)
            .unwrap();
        authority.cancel(ticket).unwrap();
        assert!(matches!(
            state.execute(Command::Deliver(late), &authority),
            Err(Fault::Authority(packet_authority::Error::InvalidGrant))
        ));
        assert_eq!(state.table.lookup(4), Err(streams::Error::NotOpened));
    });
}

#[test]
fn reliable_controls_keep_loss_copies_until_validated_late_ack() {
    with_state(|state| {
        numeric_ready(state);
        let h = open(state);
        state.reset(h, 9).unwrap();
        let selected = state.prepare::<64>(false, false).unwrap().unwrap();
        let first = state.reserve(selected.id, 3).unwrap();
        // Numeric control validation rejects an unsent reserved ACK before effects.
        let ack = [crate::accounting::AckRange { start: 3, end: 3 }];
        assert_eq!(
            state.controls.validate_ack(&ack),
            Err(streams::Error::UnsentAcknowledgment)
        );
        state.adapter_result(first, true).unwrap();
        state.controls.on_packet_lost(3);
        let retry = state.prepare::<64>(false, false).unwrap().unwrap();
        let second = state.reserve(retry.id, 4).unwrap();
        state.adapter_result(second, true).unwrap();
        assert_eq!(
            state
                .controls
                .refs
                .iter()
                .filter(|reference| reference.state != RefState::Free)
                .count(),
            2
        );
        // This is the private numerical helper, after source authority validation.
        state.controls.acknowledge(&mut state.table, &ack).unwrap();
        assert_eq!(
            state
                .controls
                .entries
                .iter()
                .filter(|control| control.kind.is_some())
                .count(),
            0
        );
        assert_eq!(
            state
                .controls
                .refs
                .iter()
                .filter(|reference| reference.state != RefState::Free)
                .count(),
            0
        );
        assert!(state.table.sending_complete(h).unwrap());
        assert!(state.prepare::<64>(false, false).unwrap().is_none());
    });
}

/// Uses the exact production preparation fragment and both production local
/// continuations, starting with actual Finished-derived application authority.
/// This is component qualification, not a substitute for the full connection.
#[test]
#[allow(long_running_const_eval)]
fn q1_preparation_scope_retries_stale_cancel_without_releasing_next_frame() {
    use crate::{carrier::CarrierStorage, mailbox::Mailbox};
    use core::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };
    use hibana::runtime::{SessionKitStorage, ids::SessionId, program::project};
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::Wake,
    };
    struct Wakes(AtomicUsize);
    impl Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let wakes = Arc::new(Wakes(AtomicUsize::new(0)));
    let waker = Waker::from(wakes.clone());
    with_state(|state| {
        numeric_ready(state);
        let h = open(state);
        state
            .queue
            .enqueue(&mut state.table, h, b"request", true)
            .unwrap();
        let initial = state.snapshot();
        let carrier = CarrierStorage::<1, 16, 32>::new();
        let mut slab = [0; 64 * 1024];
        let mut storage = SessionKitStorage::uninit();
        let kit = storage.init();
        let sid = SessionId::new(998);
        let rv = kit
            .rendezvous(&mut slab, carrier.bind(sid).unwrap())
            .unwrap();
        let global = p::prepare::<28, 29, p::Prepare>().roll();
        let cp = project::<28, _>(&global);
        let op = project::<29, _>(&global);
        let mut c = rv.enter(sid, &cp).unwrap();
        let mut o = rv.enter(sid, &op).unwrap();
        let mut requests: [Option<Command<64>>; 1] = [None];
        let mut responses: [Option<Reply<64>>; 1] = [None];
        let requests = Mailbox::new(&mut requests).unwrap();
        let responses = Mailbox::new(&mut responses).unwrap();
        let (tx, mut rx) = requests.split().unwrap();
        let (mut rtx, rrx) = responses.split().unwrap();
        let exchange = Exchange::new();
        let authority = packet_authority::Arena::<1, 2>::new(911);
        let commands = async {
            let mut sequence = 1;
            for _ in 0..2 {
                let command = rx.recv().await.map_err(|_| Error::CommandsClosed)?;
                assert!(matches!(command, Command::Prepare { probe: false }));
                let descriptor = next_descriptor(911, &mut sequence)?;
                exchange.put_request(Request {
                    descriptor,
                    command,
                })?;
                client_prepare(
                    &mut c,
                    911,
                    &mut sequence,
                    &mut rx,
                    &mut rtx,
                    &exchange,
                    descriptor,
                    false,
                )
                .await?;
            }
            Ok(())
        };
        let owner = async {
            let mut sequence = 1;
            for _ in 0..2 {
                let wire = o.recv::<p::Prepare>().await?;
                let descriptor = next_descriptor(911, &mut sequence)?;
                same(wire, encode(descriptor))?;
                owner_prepare(
                    &mut o,
                    state,
                    &mut sequence,
                    &exchange,
                    &authority,
                    descriptor,
                    p::PREPARE,
                )
                .await?;
            }
            Ok(())
        };
        let workload = async {
            let mut client = Client {
                commands: tx,
                replies: rrx,
                generation: 911,
                sequence: 1,
                snapshot: initial,
            };
            let first = client.prepare(false).await.unwrap().unwrap();
            client.cancel_prepared(first.id()).await.unwrap();
            let second = client.prepare(false).await.unwrap().unwrap();
            assert_ne!(first.id(), second.id());
            assert_eq!(
                client.cancel_prepared(first.id()).await,
                Err(ClientError::Rejected(Fault::Stale))
            );
            assert!(client.snapshot().pending_transmission);
            client.cancel_prepared(second.id()).await.unwrap();
            assert_eq!(client.snapshot().queued_chunks, 1);
            assert!(!client.snapshot().pending_transmission);
            Ok(())
        };
        let mut all = pin!(runtime::join2::<_, _, Error>(
            runtime::join2::<_, _, Error>(commands, owner),
            workload
        ));
        let mut context = Context::from_waker(&waker);
        for _ in 0..8192 {
            let before = wakes.0.load(Ordering::SeqCst);
            match all.as_mut().poll(&mut context) {
                Poll::Ready(result) => {
                    result.unwrap();
                    assert!(exchange.is_empty());
                    return;
                }
                Poll::Pending => assert!(
                    wakes.0.load(Ordering::SeqCst) > before,
                    "runnable scope lost its wake"
                ),
            }
        }
        panic!("preparation scope did not finish");
    });
}

/// Numerical fixture with actual Finished authority and an accepted retained
/// stream reference. The returned receipt follows the real Lost command effect.
pub(crate) fn settle_abandonment_loss(
    grant: super::super::recovery_owner::LostPacket,
) -> super::super::recovery_owner::StreamLossSettled {
    let generation = grant.generation();
    let packet = grant.packet().value;
    let mut slots = [StreamSlot::EMPTY; 8];
    let mut chunks = [SendChunk::EMPTY; 4];
    let mut references = [PacketReference::EMPTY; 8];
    let mut state = State::<32, 16, 2, 4>::new(
        generation,
        Role::Server,
        LIMITS,
        &mut slots,
        &mut chunks,
        &mut references,
        80,
        None,
    )
    .unwrap();
    const RAW: &[u8] = &[
        15, 8, b'c', b'l', b'i', b'e', b'n', b't', b'i', b'd', 4, 2, 0x40, 128, 5, 1, 32, 6, 1, 32,
        7, 1, 32, 8, 1, 2, 9, 1, 2,
    ];
    let finished = crate::driver::test_support::finished_with_parameters(generation, RAW);
    let ready = super::super::connection_authority::verify_and_split(
        finished,
        RAW,
        crate::parameters::Peer::Client,
        b"clientid",
        None,
        None,
    )
    .unwrap();
    state.peer_ready(ready.application).unwrap();
    let stream = state.table.open_local(true).unwrap();
    state
        .queue
        .enqueue(&mut state.table, stream, b"requeue me", true)
        .unwrap();
    let prepared = state.prepare::<64>(false, false).unwrap().unwrap();
    let id = state.reserve(prepared.id, packet).unwrap();
    state.adapter_result(id, true).unwrap();
    assert!(state.prepare::<64>(false, false).unwrap().is_none());
    let arena = packet_authority::Arena::<1, 2>::new(generation);
    let Outcome::LossApplied(Some(proof)) = state
        .execute::<64, 1, 2>(Command::Lost(grant), &arena)
        .unwrap()
    else {
        panic!("loss settlement")
    };
    assert!(state.prepare::<64>(false, false).unwrap().is_some());
    proof
}
