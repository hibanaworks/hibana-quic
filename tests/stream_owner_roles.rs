//! Q1 projected application owner qualification, with caller-backed storage.
#![allow(long_running_const_eval)]
#[path = "support/stream_early_fixture.rs"]
mod early_fixture;
use core::{
    cell::Cell,
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use hibana::{
    Endpoint,
    runtime::{SessionKitStorage, ids::SessionId, program::project},
};
use hibana_quic::{
    carrier::CarrierStorage,
    early_send::RequestSlot,
    mailbox::Mailbox,
    roles::{
        packet_authority::Arena,
        protocol_stream::stream_choreography,
        stream_owner::{self, Client, Command, Exchange, Reply, State},
    },
    runtime::join2,
    streams::{Limits, PacketReference, Role, SendChunk, StreamSlot},
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::Wake,
};

struct Counting;
thread_local! { static TRACK: Cell<Option<usize>> = const { Cell::new(None) }; }
fn allocation() {
    let _ = TRACK.try_with(|n| {
        if let Some(c) = n.get() {
            n.set(Some(c + 1));
        }
    });
}
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        allocation();
        unsafe { System.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        allocation();
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        allocation();
        unsafe { System.realloc(p, l, n) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
}
#[global_allocator]
static ALLOCATOR: Counting = Counting;
struct NoAlloc;
impl NoAlloc {
    fn start() -> Self {
        TRACK.with(|n| {
            assert!(n.get().is_none());
            n.set(Some(0));
        });
        Self
    }
    fn finish(self) {
        assert_eq!(TRACK.with(|n| n.replace(None).unwrap()), 0);
    }
}
impl Drop for NoAlloc {
    fn drop(&mut self) {
        TRACK.with(|n| n.set(None));
    }
}
struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
fn waker() -> (Arc<WakeCount>, Waker) {
    let count = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = Waker::from(count.clone());
    (count, waker)
}
fn drive<F: Future>(future: F, count: &WakeCount, waker: &Waker) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(waker);
    for _ in 0..8192 {
        let before = count.0.load(Ordering::SeqCst);
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(result) => return result,
            Poll::Pending => assert!(
                count.0.load(Ordering::SeqCst) > before,
                "runnable scenario parked without wake"
            ),
        }
    }
    panic!("actor scenario did not terminate")
}
fn with_pair<T>(
    body: impl for<'r> FnOnce(Endpoint<'r, 28>, Endpoint<'r, 29>, &CarrierStorage<1, 16, 32>) -> T,
) -> T {
    let carrier = CarrierStorage::<1, 16, 32>::new();
    let mut slab = [0; 64 * 1024];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init();
    let sid = SessionId::new(96);
    let rv = kit
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    let global = stream_choreography::<28, 29>();
    let cp = project::<28, _>(&global);
    let op = project::<29, _>(&global);
    body(
        rv.enter(sid, &cp).unwrap(),
        rv.enter(sid, &op).unwrap(),
        &carrier,
    )
}
const LIMITS: Limits = Limits {
    max_data: 128,
    max_streams_bidi: 2,
    max_streams_uni: 2,
    stream_data_bidi_local: 32,
    stream_data_bidi_remote: 32,
    stream_data_uni: 32,
};
#[test]
fn q1_owner_moves_and_copies_early_intent_without_heap() {
    let (count, waker) = waker();
    let early_permission = early_fixture::early_send_ready(911);
    with_pair(|mut c, mut o, carrier| {
        let no_alloc = NoAlloc::start();
        let mut slots = [StreamSlot::<32>::EMPTY; 4];
        let mut chunks = [SendChunk::<16>::EMPTY; 4];
        let mut references = [PacketReference::EMPTY; 8];
        let mut early = [RequestSlot::<16>::EMPTY; 2];
        let state = State::<32, 16, 2, 4>::new(
            911,
            Role::Client,
            LIMITS,
            &mut slots,
            &mut chunks,
            &mut references,
            80,
            Some(&mut early),
        )
        .unwrap();
        let mut requests: [Option<Command<64>>; 1] = [None];
        let mut responses: [Option<Reply<64>>; 1] = [None];
        let commands = Mailbox::new(&mut requests).unwrap();
        let replies = Mailbox::new(&mut responses).unwrap();
        let (tx, rx) = commands.split().unwrap();
        let (rtx, rrx) = replies.split().unwrap();
        let mut exchange = Exchange::new();
        let authority = Arena::<1, 2>::new(911);
        let consumer = async {
            let mut client = Client::connect(tx, rrx, 911).await.unwrap();
            assert!(!client.snapshot().ready);
            client.early_send_ready(early_permission).await.unwrap();
            let handle = client.enqueue_early(b"GET / HTTP/1.0").await.unwrap();
            assert_eq!(client.early_stream_id(handle).await.unwrap(), 0);
            let first = client.prepare_early(false).await.unwrap().unwrap();
            assert!(first.is_early());
            assert!(!first.bytes().is_empty());
            assert!(client.snapshot().pending_transmission);
            client.cancel_prepared(first.id()).await.unwrap();
            let second = client.prepare_early(false).await.unwrap().unwrap();
            assert_ne!(first.id(), second.id());
            assert_eq!(first.bytes(), second.bytes());
            // Retained old IDs cannot cancel the next preparation.
            assert!(client.cancel_prepared(first.id()).await.is_err());
            client.cancel_prepared(second.id()).await.unwrap();
            client.inspect(None).await.unwrap();
            assert!(client.snapshot().early_intent);
            client.retire().await.unwrap();
            Ok(())
        };
        drive(
            join2(
                stream_owner::run_borrowed(
                    &mut c,
                    &mut o,
                    state,
                    rx,
                    rtx,
                    &mut exchange,
                    &authority,
                ),
                consumer,
            ),
            &count,
            &waker,
        )
        .unwrap();
        assert!(exchange.is_empty());
        assert!(!carrier.is_closed());
        no_alloc.finish();
    });
}
#[test]
fn cancelling_after_command_publication_revokes_the_admission_capability() {
    let (count, waker) = waker();
    with_pair(|mut c, mut o, _carrier| {
        let mut slots = [StreamSlot::<32>::EMPTY; 4];
        let mut chunks = [SendChunk::<16>::EMPTY; 4];
        let mut references = [PacketReference::EMPTY; 8];
        let state = State::<32, 16, 2, 4>::new(
            911,
            Role::Client,
            LIMITS,
            &mut slots,
            &mut chunks,
            &mut references,
            80,
            None,
        )
        .unwrap();
        let mut requests: [Option<Command<64>>; 1] = [None];
        let mut responses: [Option<Reply<64>>; 1] = [None];
        let commands = Mailbox::new(&mut requests).unwrap();
        let replies = Mailbox::new(&mut responses).unwrap();
        let (tx, rx) = commands.split().unwrap();
        let (rtx, rrx) = replies.split().unwrap();
        let mut exchange = Exchange::new();
        let authority = Arena::<1, 2>::new(911);
        {
            let mut service = pin!(stream_owner::run_borrowed(
                &mut c,
                &mut o,
                state,
                rx,
                rtx,
                &mut exchange,
                &authority
            ));
            let mut connection = pin!(Client::connect(tx, rrx, 911));
            let mut cx = Context::from_waker(&waker);
            let mut client = loop {
                assert!(service.as_mut().poll(&mut cx).is_pending());
                if let Poll::Ready(result) = connection.as_mut().poll(&mut cx) {
                    break result.unwrap();
                }
            };
            // Let the role park on an actual empty command mailbox.
            assert!(service.as_mut().poll(&mut cx).is_pending());
            let before = count.0.load(Ordering::SeqCst);
            assert!(service.as_mut().poll(&mut cx).is_pending());
            assert_eq!(
                count.0.load(Ordering::SeqCst),
                before,
                "idle owner must not self-wake"
            );
            {
                let mut pending = pin!(client.inspect(None));
                assert!(pending.as_mut().poll(&mut cx).is_pending());
                assert!(
                    count.0.load(Ordering::SeqCst) > before,
                    "request publication wakes role"
                );
            }
            let mut later = pin!(client.inspect(None));
            assert!(matches!(
                later.as_mut().poll(&mut cx),
                Poll::Ready(Err(stream_owner::ClientError::Closed))
            ));
            let mut ended = false;
            for _ in 0..64 {
                if let Poll::Ready(result) = service.as_mut().poll(&mut cx) {
                    assert!(result.is_err());
                    ended = true;
                    break;
                }
            }
            assert!(ended, "cancelled client must terminate service");
        }
        assert!(exchange.is_empty());
    });
}

#[test]
fn projected_bootstrap_has_no_application_open_edge() {
    use hibana_quic::roles::protocol_stream as p;
    let (count, waker) = waker();
    with_pair(|mut c, mut o, _| {
        let wire = [0; 16];
        let requester = async {
            c.send::<p::Install>(&wire).await.unwrap();
            c.recv::<p::Installed>().await.unwrap();
            assert!(
                c.send::<p::Open>(&wire).await.is_err(),
                "global projection must reject Open before AppReady"
            );
            Err::<(), ()>(())
        };
        let owner = async {
            o.recv::<p::Install>().await.unwrap();
            o.send::<p::Installed>(&wire).await.unwrap();
            core::future::pending::<Result<(), ()>>().await
        };
        assert!(drive(join2(requester, owner), &count, &waker).is_err());
    });
}

// The former blanket raw-label Inspect rejection test is preserved in
// artifacts/stream-preparation-contract/historical/stream_owner_roles.rs.
// Completed older rolls are elastic, so Inspect can denote an older occurrence.
// tests/stream_elastic_reentry.rs records that scoped graph contract; actual
// client_prepare mailbox denial is tested in stream_owner::tests instead.

/// Exercise actual projected choice visibility on both sides. The first run
/// takes the real PeerReady exit immediately; no operation primes the roll.
#[test]
fn projected_factored_requests_keep_outcomes_and_stage_exits() {
    use hibana_quic::roles::protocol_stream as p;
    let (count, waker) = waker();
    for bootstrap_operations in [false, true] {
        with_pair(|mut c, mut o, _| {
            let wire = [19; 16];
            let requester = async {
                c.send::<p::Install>(&wire).await.unwrap();
                assert_eq!(c.recv::<p::Installed>().await.unwrap(), wire);
                if bootstrap_operations {
                    c.send::<p::Inspect>(&wire).await.unwrap();
                    let reply = c.offer().await.unwrap();
                    assert_eq!(reply.label(), p::APPLIED);
                    assert_eq!(reply.recv::<p::Applied>().await.unwrap(), wire);
                    c.send::<p::ResultTaken>(&wire).await.unwrap();
                    c.send::<p::Retry>(&wire).await.unwrap();
                    let reply = c.offer().await.unwrap();
                    assert_eq!(reply.label(), p::REJECTED);
                    assert_eq!(reply.recv::<p::Rejected>().await.unwrap(), wire);
                    c.send::<p::ResultTaken>(&wire).await.unwrap();
                }
                c.send::<p::PeerReady>(&wire).await.unwrap();
                let ready = c.offer().await.unwrap();
                assert_eq!(ready.label(), p::READY);
                assert_eq!(ready.recv::<p::Ready>().await.unwrap(), wire);
                c.send::<p::ResultTaken>(&wire).await.unwrap();
                c.send::<p::Open>(&wire).await.unwrap();
                let reply = c.offer().await.unwrap();
                assert_eq!(reply.label(), p::APPLIED);
                assert_eq!(reply.recv::<p::Applied>().await.unwrap(), wire);
                c.send::<p::ResultTaken>(&wire).await.unwrap();
                c.send::<p::Consume>(&wire).await.unwrap();
                let reply = c.offer().await.unwrap();
                assert_eq!(reply.label(), p::REJECTED);
                assert_eq!(reply.recv::<p::Rejected>().await.unwrap(), wire);
                c.send::<p::ResultTaken>(&wire).await.unwrap();
                c.send::<p::Inspect>(&wire).await.unwrap();
                let reply = c.offer().await.unwrap();
                assert_eq!(reply.label(), p::APPLIED);
                assert_eq!(reply.recv::<p::Applied>().await.unwrap(), wire);
                c.send::<p::ResultTaken>(&wire).await.unwrap();
                c.send::<p::RetireRequested>(&wire).await.unwrap();
                assert_eq!(c.recv::<p::Retired>().await.unwrap(), wire);
                c.send::<p::RetirementAcknowledged>(&wire).await.unwrap();
                Ok::<(), ()>(())
            };
            let owner = async {
                assert_eq!(o.recv::<p::Install>().await.unwrap(), wire);
                o.send::<p::Installed>(&wire).await.unwrap();
                if bootstrap_operations {
                    let request = o.offer().await.unwrap();
                    assert_eq!(request.label(), p::INSPECT);
                    assert_eq!(request.recv::<p::Inspect>().await.unwrap(), wire);
                    o.send::<p::Applied>(&wire).await.unwrap();
                    assert_eq!(o.recv::<p::ResultTaken>().await.unwrap(), wire);
                    let request = o.offer().await.unwrap();
                    assert_eq!(request.label(), p::RETRY);
                    assert_eq!(request.recv::<p::Retry>().await.unwrap(), wire);
                    o.send::<p::Rejected>(&wire).await.unwrap();
                    assert_eq!(o.recv::<p::ResultTaken>().await.unwrap(), wire);
                }
                let request = o.offer().await.unwrap();
                assert_eq!(request.label(), p::PEER_READY);
                assert_eq!(request.recv::<p::PeerReady>().await.unwrap(), wire);
                o.send::<p::Ready>(&wire).await.unwrap();
                assert_eq!(o.recv::<p::ResultTaken>().await.unwrap(), wire);
                let request = o.offer().await.unwrap();
                assert_eq!(request.label(), p::OPEN);
                assert_eq!(request.recv::<p::Open>().await.unwrap(), wire);
                o.send::<p::Applied>(&wire).await.unwrap();
                assert_eq!(o.recv::<p::ResultTaken>().await.unwrap(), wire);
                let request = o.offer().await.unwrap();
                assert_eq!(request.label(), p::CONSUME);
                assert_eq!(request.recv::<p::Consume>().await.unwrap(), wire);
                o.send::<p::Rejected>(&wire).await.unwrap();
                assert_eq!(o.recv::<p::ResultTaken>().await.unwrap(), wire);
                let request = o.offer().await.unwrap();
                assert_eq!(request.label(), p::INSPECT);
                assert_eq!(request.recv::<p::Inspect>().await.unwrap(), wire);
                o.send::<p::Applied>(&wire).await.unwrap();
                assert_eq!(o.recv::<p::ResultTaken>().await.unwrap(), wire);
                let request = o.offer().await.unwrap();
                assert_eq!(request.label(), p::RETIRE_REQUESTED);
                assert_eq!(request.recv::<p::RetireRequested>().await.unwrap(), wire);
                o.send::<p::Retired>(&wire).await.unwrap();
                assert_eq!(o.recv::<p::RetirementAcknowledged>().await.unwrap(), wire);
                Ok::<(), ()>(())
            };
            drive(join2(requester, owner), &count, &waker).unwrap();
        });
    }
}

#[test]
fn projected_common_result_and_receipt_cannot_be_skipped() {
    use hibana_quic::roles::protocol_stream as p;
    let (count, waker) = waker();
    for skip_receipt in [false, true] {
        with_pair(|mut c, mut o, _| {
            let wire = [23; 16];
            let requester = async {
                c.send::<p::Install>(&wire).await.unwrap();
                c.recv::<p::Installed>().await.unwrap();
                c.send::<p::PeerReady>(&wire).await.unwrap();
                c.offer().await.unwrap().recv::<p::Ready>().await.unwrap();
                c.send::<p::ResultTaken>(&wire).await.unwrap();
                c.send::<p::Open>(&wire).await.unwrap();
                if skip_receipt {
                    c.offer().await.unwrap().recv::<p::Applied>().await.unwrap();
                }
                assert!(
                    c.send::<p::Read>(&wire).await.is_err(),
                    "a new request cannot skip the owner outcome or ResultTaken"
                );
                Err::<(), ()>(())
            };
            let owner = async {
                o.recv::<p::Install>().await.unwrap();
                o.send::<p::Installed>(&wire).await.unwrap();
                o.offer()
                    .await
                    .unwrap()
                    .recv::<p::PeerReady>()
                    .await
                    .unwrap();
                o.send::<p::Ready>(&wire).await.unwrap();
                o.recv::<p::ResultTaken>().await.unwrap();
                o.offer().await.unwrap().recv::<p::Open>().await.unwrap();
                if skip_receipt {
                    o.send::<p::Applied>(&wire).await.unwrap();
                }
                core::future::pending::<Result<(), ()>>().await
            };
            assert!(drive(join2(requester, owner), &count, &waker).is_err());
        });
    }
}
