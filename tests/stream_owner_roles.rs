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

#[test]
fn projected_preparation_cannot_escape_without_owner_settlement_suffix() {
    use hibana_quic::roles::protocol_stream as p;
    let (count, waker) = waker();
    with_pair(|mut c, mut o, _| {
        let wire = [0; 16];
        let requester = async {
            c.send::<p::Install>(&wire).await.unwrap();
            c.recv::<p::Installed>().await.unwrap();
            c.send::<p::EarlySendReady>(&wire).await.unwrap();
            c.offer()
                .await
                .unwrap()
                .recv::<p::EarlySendInstalled>()
                .await
                .unwrap();
            c.send::<p::ResultTaken>(&wire).await.unwrap();
            c.send::<p::PrepareEarly>(&wire).await.unwrap();
            c.offer()
                .await
                .unwrap()
                .recv::<p::FramePrepared>()
                .await
                .unwrap();
            c.send::<p::ResultTaken>(&wire).await.unwrap();
            assert!(
                c.send::<p::Inspect>(&wire).await.is_err(),
                "outer Inspect cannot bypass reservation/cancellation suffix"
            );
            Err::<(), ()>(())
        };
        let owner = async {
            o.recv::<p::Install>().await.unwrap();
            o.send::<p::Installed>(&wire).await.unwrap();
            o.offer()
                .await
                .unwrap()
                .recv::<p::EarlySendReady>()
                .await
                .unwrap();
            o.send::<p::EarlySendInstalled>(&wire).await.unwrap();
            o.recv::<p::ResultTaken>().await.unwrap();
            o.offer()
                .await
                .unwrap()
                .recv::<p::PrepareEarly>()
                .await
                .unwrap();
            o.send::<p::FramePrepared>(&wire).await.unwrap();
            // Whether ResultTaken is received before the deliberately invalid
            // edge closes the carrier is immaterial to this projection check.
            let _ = o.recv::<p::ResultTaken>().await;
            core::future::pending::<Result<(), ()>>().await
        };
        assert!(drive(join2(requester, owner), &count, &waker).is_err());
    });
}
