//! Exact production PrepareFlow and local continuations at an admitted phase
//! entry. This fixture does not execute the full bootstrap/early global graph.
//! Its State owns real stream/send kernels and a genuine Finished-derived grant.
use super::*;
use crate::{carrier::CarrierStorage, mailbox::Mailbox};
use core::{
    cell::Cell,
    future::{Future, poll_fn},
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
fn drive(future: impl Future<Output = Result<(), Error>>) {
    let wakes = Arc::new(Wakes(AtomicUsize::new(0)));
    let waker = Waker::from(wakes.clone());
    let mut future = pin!(future);
    let mut cx = Context::from_waker(&waker);
    let measured = actor_test_allocator::NoAlloc::start();
    for _ in 0..8192 {
        let before = wakes.0.load(Ordering::SeqCst);
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(result) => {
                measured.finish();
                return result.unwrap();
            }
            Poll::Pending => assert!(
                wakes.0.load(Ordering::SeqCst) > before,
                "runnable preparation fixture lost its wake"
            ),
        }
    }
    panic!("preparation fixture did not terminate");
}
// Observe that the actual State destructor ran. This guard does not implement
// substitute cleanup or call close itself; capability denial is checked below.
struct ObservedOwner<'a, 's> {
    state: Option<State<'s, 32, 16, 2, 4>>,
    dropped: &'a Cell<bool>,
}
impl Drop for ObservedOwner<'_, '_> {
    fn drop(&mut self) {
        drop(self.state.take());
        self.dropped.set(true);
    }
}
#[derive(Clone, Copy)]
enum Scenario {
    Inspect {
        reserved: bool,
        cancel_request: bool,
    },
    ValidCancellation,
}
fn scenario(scenario: Scenario) {
    let mut slots = [StreamSlot::EMPTY; 8];
    let mut chunks = [SendChunk::EMPTY; 4];
    let mut references = [PacketReference::EMPTY; 8];
    let mut state = State::<32, 16, 2, 4>::new(
        911,
        Role::Server,
        super::tests::LIMITS,
        &mut slots,
        &mut chunks,
        &mut references,
        80,
        None,
    )
    .unwrap();
    super::tests::numeric_ready(&mut state);
    let stream = state.table.open_local(true).unwrap();
    state
        .queue
        .enqueue(&mut state.table, stream, b"request", true)
        .unwrap();
    let initial = state.snapshot();
    let carrier = CarrierStorage::<1, 16, 32>::new();
    let mut slab = [0; 65536];
    let mut storage = SessionKitStorage::uninit();
    let sid = SessionId::new(997);
    let rendezvous = storage
        .init()
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    let global = p::prepare::<28, 29, p::Prepare>().roll();
    let cp = project::<28, _>(&global);
    let op = project::<29, _>(&global);
    let mut c = rendezvous.enter(sid, &cp).unwrap();
    let mut o = rendezvous.enter(sid, &op).unwrap();
    let mut requests: [Option<Command<64>>; 1] = [None];
    let mut replies: [Option<Reply<64>>; 1] = [None];
    let requests = Mailbox::new(&mut requests).unwrap();
    let replies = Mailbox::new(&mut replies).unwrap();
    let (tx, rx) = requests.split().unwrap();
    let (rtx, rrx) = replies.split().unwrap();
    let exchange = Exchange::new();
    let authority = packet_authority::Arena::<1, 2>::new(911);
    let owner_dropped = Cell::new(false);
    let service_rejected = Cell::new(false);
    let count = if matches!(scenario, Scenario::ValidCancellation) {
        2
    } else {
        1
    };
    let exchange_ref = &exchange;
    let rejected_ref = &service_rejected;
    let client_endpoint = &mut c;
    let commands = async move {
        let mut rx = rx;
        let mut rtx = rtx;
        let mut sequence = 1;
        for _ in 0..count {
            let command = rx.recv().await.map_err(|_| Error::CommandsClosed)?;
            assert!(matches!(command, Command::Prepare { probe: false }));
            let descriptor = next_descriptor(911, &mut sequence)?;
            exchange_ref.put_request(Request {
                descriptor,
                command,
            })?;
            let result = client_prepare(
                client_endpoint,
                911,
                &mut sequence,
                &mut rx,
                &mut rtx,
                exchange_ref,
                descriptor,
                false,
            )
            .await;
            match scenario {
                Scenario::ValidCancellation => result?,
                Scenario::Inspect {
                    reserved,
                    cancel_request,
                } => {
                    let error = result
                        .expect_err("ordinary mailbox command escaped preparation continuation");
                    assert!(
                        matches!(error, Error::UnexpectedCommand)
                            || (cancel_request && matches!(error, Error::CommandsClosed)),
                        "setup or continuation failed before the intended boundary: {error:?}"
                    );
                    // A forbidden command is rejected before consuming a new
                    // descriptor or publishing to the owner's shared arena.
                    assert_eq!(sequence, if reserved { 3 } else { 2 });
                    assert!(
                        exchange_ref.is_empty(),
                        "forbidden Inspect reached the owner arena or produced a reply"
                    );
                    rejected_ref.set(true);
                    return Err(error);
                }
            }
        }
        Ok(())
    };
    let dropped_ref = &owner_dropped;
    let authority_ref = &authority;
    let owner_endpoint = &mut o;
    let owner = async move {
        let mut owned = ObservedOwner {
            state: Some(state),
            dropped: dropped_ref,
        };
        let mut sequence = 1;
        for _ in 0..count {
            let wire = owner_endpoint.recv::<p::Prepare>().await?;
            let descriptor = next_descriptor(911, &mut sequence)?;
            same(wire, encode(descriptor))?;
            owner_prepare(
                owner_endpoint,
                owned.state.as_mut().unwrap(),
                &mut sequence,
                exchange_ref,
                authority_ref,
                descriptor,
                p::PREPARE,
            )
            .await?;
        }
        Ok(())
    };
    let service = async {
        let _clear = Clear(&exchange);
        let result = runtime::join2::<_, _, Error>(commands, owner).await;
        match scenario {
            Scenario::ValidCancellation => result?,
            Scenario::Inspect { cancel_request, .. } => {
                assert!(
                    matches!(result, Err(Error::UnexpectedCommand))
                        || (cancel_request && matches!(result, Err(Error::CommandsClosed))),
                    "setup failed or a forbidden request was not terminal: {result:?}"
                );
                assert!(service_rejected.get());
            }
        }
        Ok(())
    };
    let workload = async {
        // This is the capability at the component phase entry, not a fabricated
        // AppReady grant or a second mutation interface to the owner.
        let mut client = Client {
            commands: tx,
            replies: rrx,
            generation: 911,
            sequence: 1,
            snapshot: initial,
        };
        let frame = client.prepare(false).await.unwrap().unwrap();
        assert!(client.snapshot().pending_transmission);
        let parsed = packet::FrameIter::new(
            frame.bytes(),
            packet::EncryptionLevel::OneRtt,
            packet::ParseLimits::default(),
        )
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
        assert!(
            matches!(parsed, Frame::Stream { id, data: b"request", fin: true, .. } if id == stream.id())
        );
        match scenario {
            Scenario::ValidCancellation => {
                let transmission = client.reserve(frame.id(), 0).await.unwrap();
                let cancellation =
                    super::super::path_owner::cancellation_fixture::cancel_stream(transmission);
                client.cancel_transmission(cancellation).await.unwrap();
                assert!(!client.snapshot().pending_transmission);
                assert_eq!(client.snapshot().send_references, 0);
                assert_eq!(client.snapshot().queued_chunks, 1);
                let next = client.prepare(false).await.unwrap().unwrap();
                assert_ne!(frame.id(), next.id());
                assert_eq!(frame.bytes(), next.bytes());
                client.cancel_prepared(next.id()).await.unwrap();
            }
            Scenario::Inspect {
                reserved,
                cancel_request,
            } => {
                if reserved {
                    client.reserve(frame.id(), 0).await.unwrap();
                }
                let before = *client.snapshot();
                if cancel_request {
                    {
                        let mut request = pin!(client.inspect(None));
                        poll_fn(|cx| {
                            assert!(request.as_mut().poll(cx).is_pending());
                            assert_eq!(
                                requests.len(),
                                1,
                                "cancel after ordinary command publication"
                            );
                            Poll::Ready(())
                        })
                        .await;
                    }
                } else {
                    assert_eq!(
                        client.inspect(None).await,
                        Err(ClientError::Closed),
                        "no Inspected outcome may be returned"
                    );
                }
                assert_eq!(
                    *client.snapshot(),
                    before,
                    "forbidden request cannot apply an owner result"
                );
                assert_eq!(
                    client.reserve(frame.id(), 9).await,
                    Err(ClientError::Closed),
                    "retained selection ID cannot revive closed admission"
                );
                assert_eq!(
                    client.cancel_prepared(frame.id()).await,
                    Err(ClientError::Closed)
                );
                assert_eq!(client.inspect(None).await, Err(ClientError::Closed));
            }
        }
        Ok(())
    };
    drive(runtime::join2::<_, _, Error>(service, workload));
    assert!(
        owner_dropped.get(),
        "real owner State must be destroyed at service teardown"
    );
    assert!(exchange.is_empty());
    assert!(requests.is_empty());
    assert!(replies.is_empty());
    assert_eq!(authority.live_packets(), 0);
    assert_eq!(authority.live_effects(), 0);
}
#[test]
#[allow(long_running_const_eval)]
fn prepared_selection_rejects_ordinary_mailbox_inspect_and_revokes_capability() {
    scenario(Scenario::Inspect {
        reserved: false,
        cancel_request: false,
    });
}
#[test]
#[allow(long_running_const_eval)]
fn reserved_transmission_rejects_ordinary_mailbox_inspect_and_revokes_capability() {
    scenario(Scenario::Inspect {
        reserved: true,
        cancel_request: false,
    });
}
#[test]
#[allow(long_running_const_eval)]
fn cancelling_ordinary_mailbox_request_revokes_prepared_and_reserved_capabilities() {
    for reserved in [false, true] {
        scenario(Scenario::Inspect {
            reserved,
            cancel_request: true,
        });
    }
}
#[test]
#[allow(long_running_const_eval)]
fn genuine_prepublication_cancellation_settles_reserved_scope_and_preserves_data() {
    scenario(Scenario::ValidCancellation);
}
