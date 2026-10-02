//! Real cryptographic work through the production role implementation.
use core::{
    cell::Cell,
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use hibana::{
    Endpoint,
    runtime::{SessionKitStorage, ids::SessionId},
};
use hibana_quic::{
    carrier::CarrierStorage,
    crypto::{self, IntegrityBudget},
    mailbox::Mailbox,
    roles::{
        packet_protection::{self, Command, Exchange, Outcome, Packet, Reply},
        protocol::{KEY_CLIENT, KEY_CRYPTO, key_program},
    },
    runtime::join2,
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
thread_local! { static COUNTING: Cell<bool> = const { Cell::new(false) }; static ALLOCATIONS: Cell<usize> = const { Cell::new(0) }; }
fn count_alloc() {
    let _ = COUNTING.try_with(|enabled| {
        if enabled.get() {
            let _ = ALLOCATIONS.try_with(|n| n.set(n.get() + 1));
        }
    });
}
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        count_alloc();
        unsafe { System.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        count_alloc();
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        count_alloc();
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
        ALLOCATIONS.with(|n| n.set(0));
        COUNTING.with(|v| v.set(true));
        Self
    }
}
impl Drop for NoAlloc {
    fn drop(&mut self) {
        COUNTING.with(|v| v.set(false));
    }
}
struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref()
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
fn waker() -> (Arc<WakeCount>, Waker) {
    let count = Arc::new(WakeCount(AtomicUsize::new(0)));
    let w = Waker::from(count.clone());
    (count, w)
}
fn drive<F: Future>(future: F, count: &WakeCount, waker: &Waker) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(waker);
    for _ in 0..256 {
        let before = count.0.load(Ordering::SeqCst);
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(result) => return result,
            Poll::Pending => assert!(
                count.0.load(Ordering::SeqCst) > before,
                "service parked without expected input/wake"
            ),
        }
    }
    panic!("test work did not terminate")
}
fn with_roles<R>(
    body: impl for<'r> FnOnce(Endpoint<'r, KEY_CLIENT>, Endpoint<'r, KEY_CRYPTO>) -> R,
) -> R {
    let carrier = CarrierStorage::<1, 16, 16>::new();
    let mut slab = [0; 32 * 1024];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init();
    let sid = SessionId::new(81);
    let rv = kit
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    let client = key_program::<KEY_CLIENT>();
    let crypto = key_program::<KEY_CRYPTO>();
    body(
        rv.enter(sid, &client).unwrap(),
        rv.enter(sid, &crypto).unwrap(),
    )
}

#[test]
fn real_aead_outcomes_nonce_guard_shared_integrity_budget_and_retirement_do_not_allocate() {
    let (count, waker) = waker();
    with_roles(|client, crypto_endpoint| {
        let mut requests: [Option<Command<128>>; 2] = [const { None }; 2];
        let mut responses: [Option<Reply<128>>; 1] = [None];
        let commands = Mailbox::new(&mut requests).unwrap();
        let replies = Mailbox::new(&mut responses).unwrap();
        let (mut sender, receiver) = commands.split().unwrap();
        let (reply_sender, mut reply_receiver) = replies.split().unwrap();
        let mut exchange = Exchange::new();
        let key = crypto::initial_keys(b"actor-key").unwrap().client;
        let reference = crypto::initial_keys(b"actor-key").unwrap().client;
        let sample = [5; 16];
        let expected_mask = reference.header_mask(&sample).unwrap();
        let client_work = async {
            assert!(matches!(
                reply_receiver.recv().await.unwrap().outcome,
                Outcome::Installed
            ));
            sender
                .send(Command::Seal(
                    Packet::new(42, b"header", b"owned plaintext").unwrap(),
                ))
                .await
                .unwrap_or_else(|_| panic!("closed"));
            let reply = reply_receiver.recv().await.unwrap();
            assert_eq!(reply.descriptor.sequence, 1);
            let Outcome::Sealed(sealed) = reply.outcome else {
                panic!("not sealed")
            };
            assert_eq!(sealed.header(), b"header");
            assert_ne!(sealed.body(), b"owned plaintext");
            let mut corrupt = [0; 64];
            let cipher_len = sealed.body().len();
            corrupt[..cipher_len].copy_from_slice(sealed.body());
            corrupt[0] ^= 1;
            sender
                .send(Command::Open {
                    packet: sealed,
                    budget: IntegrityBudget::new(),
                })
                .await
                .unwrap_or_else(|_| panic!("closed"));
            let Outcome::Opened {
                packet,
                receipt,
                budget,
            } = reply_receiver.recv().await.unwrap().outcome
            else {
                panic!("not authenticated")
            };
            assert_eq!(packet.body(), b"owned plaintext");
            assert_eq!(receipt.generation(), 17);
            assert_eq!(receipt.packet_number(), 42);
            assert_eq!(receipt.operation_id(), 2);
            assert_eq!(receipt.kind(), crypto::KeyKind::Initial);
            assert_eq!(budget.failed_packets(), 0);
            drop(packet);
            sender
                .send(Command::Open {
                    packet: Packet::new(42, b"header", &corrupt[..cipher_len]).unwrap(),
                    budget,
                })
                .await
                .unwrap_or_else(|_| panic!("closed"));
            let Outcome::AuthenticationRejected { error, budget } =
                reply_receiver.recv().await.unwrap().outcome
            else {
                panic!("forged packet accepted")
            };
            assert_eq!(error, crypto::Error::AuthenticationFailed);
            assert_eq!(budget.failed_packets(), 1);
            sender
                .send(Command::Open {
                    packet: Packet::new(42, b"header", &corrupt[..cipher_len]).unwrap(),
                    budget,
                })
                .await
                .unwrap_or_else(|_| panic!("closed"));
            let Outcome::AuthenticationRejected { budget, .. } =
                reply_receiver.recv().await.unwrap().outcome
            else {
                panic!("forged packet accepted")
            };
            assert_eq!(budget.failed_packets(), 2);
            sender
                .send(Command::Seal(
                    Packet::new(42, b"header", b"nonce reuse").unwrap(),
                ))
                .await
                .unwrap_or_else(|_| panic!("closed"));
            assert!(matches!(
                reply_receiver.recv().await.unwrap().outcome,
                Outcome::SealFailed(crypto::Error::PacketNumberReuse)
            ));
            sender
                .send(Command::HeaderMask(sample))
                .await
                .unwrap_or_else(|_| panic!("closed"));
            let Outcome::HeaderMask(mask) = reply_receiver.recv().await.unwrap().outcome else {
                panic!("no real mask")
            };
            assert_eq!(mask, expected_mask);
            sender
                .send(Command::Retire)
                .await
                .unwrap_or_else(|_| panic!("closed"));
            // Already queued work cannot acquire a post-retirement operation.
            sender
                .send(Command::Seal(Packet::new(43, b"header", b"stale").unwrap()))
                .await
                .unwrap_or_else(|_| panic!("queue unexpectedly full"));
            assert!(matches!(
                reply_receiver.recv().await.unwrap().outcome,
                Outcome::Retired
            ));
            assert!(sender.send(Command::HeaderMask([0; 16])).await.is_err());
            assert!(reply_receiver.recv().await.is_err());
            Ok(())
        };
        let no_alloc = NoAlloc::start();
        drive(
            join2(
                packet_protection::run(
                    client,
                    crypto_endpoint,
                    17,
                    key,
                    receiver,
                    reply_sender,
                    &mut exchange,
                ),
                client_work,
            ),
            &count,
            &waker,
        )
        .unwrap();
        drop(no_alloc);
        assert_eq!(ALLOCATIONS.with(Cell::get), 0);
        assert!(exchange.is_empty());
        assert!(sender.is_closed());
    });
}

#[test]
fn cancellation_closes_stale_command_capability_and_clears_queued_owned_packets() {
    with_roles(|client, crypto_endpoint| {
        let mut requests: [Option<Command<128>>; 2] = [const { None }; 2];
        let mut responses: [Option<Reply<128>>; 1] = [None];
        let commands = Mailbox::new(&mut requests).unwrap();
        let replies = Mailbox::new(&mut responses).unwrap();
        let (mut sender, receiver) = commands.split().unwrap();
        let (reply_sender, mut reply_receiver) = replies.split().unwrap();
        let mut exchange = Exchange::new();
        let key = crypto::initial_keys(b"cancel-key").unwrap().client;
        let (count, waker) = waker();
        let mut cx = Context::from_waker(&waker);
        {
            let mut running = pin!(packet_protection::run(
                client,
                crypto_endpoint,
                18,
                key,
                receiver,
                reply_sender,
                &mut exchange
            ));
            for _ in 0..8 {
                assert!(running.as_mut().poll(&mut cx).is_pending());
            }
            assert!(matches!(
                drive(reply_receiver.recv(), &count, &waker)
                    .unwrap()
                    .outcome,
                Outcome::Installed
            ));
            drive(
                sender.send(Command::Seal(
                    Packet::new(1, b"header", b"cancelled plaintext").unwrap(),
                )),
                &count,
                &waker,
            )
            .unwrap_or_else(|_| panic!("closed early"));
            // Dropping the aggregate cancels both actors and their key/slots.
        }
        assert!(exchange.is_empty());
        assert!(sender.is_closed());
        assert!(drive(sender.send(Command::HeaderMask([0; 16])), &count, &waker).is_err());
        assert!(drive(reply_receiver.recv(), &count, &waker).is_err());
    });
}

#[test]
fn unused_key_can_retire_without_a_dummy_crypto_operation() {
    with_roles(|client, crypto_endpoint| {
        let mut requests: [Option<Command<64>>; 1] = [None];
        let mut responses: [Option<Reply<64>>; 1] = [None];
        let commands = Mailbox::new(&mut requests).unwrap();
        let replies = Mailbox::new(&mut responses).unwrap();
        let (mut sender, receiver) = commands.split().unwrap();
        let (reply_sender, mut reply_receiver) = replies.split().unwrap();
        let mut exchange = Exchange::new();
        let key = crypto::initial_keys(b"unused-key").unwrap().server;
        let (count, waker) = waker();
        let consumer = async {
            assert!(matches!(
                reply_receiver.recv().await.unwrap().outcome,
                Outcome::Installed
            ));
            sender
                .send(Command::Retire)
                .await
                .unwrap_or_else(|_| panic!("closed"));
            assert!(matches!(
                reply_receiver.recv().await.unwrap().outcome,
                Outcome::Retired
            ));
            Ok(())
        };
        drive(
            join2(
                packet_protection::run(
                    client,
                    crypto_endpoint,
                    19,
                    key,
                    receiver,
                    reply_sender,
                    &mut exchange,
                ),
                consumer,
            ),
            &count,
            &waker,
        )
        .unwrap();
        assert!(exchange.is_empty());
    });
}

#[test]
fn one_global_par_keeps_other_owned_key_live_when_first_facet_retires() {
    use hibana::{g, runtime::program::project};
    use hibana_quic::roles::{client::KeyClient, protocol::key_choreography};
    let carrier = CarrierStorage::<1, 16, 32>::new();
    let mut slab = [0; 32 * 1024];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init();
    let sid = SessionId::new(82);
    let rv = kit
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    let global = g::par(key_choreography::<16, 17>(), key_choreography::<18, 19>());
    let p16 = project::<16, _>(&global);
    let p17 = project::<17, _>(&global);
    let p18 = project::<18, _>(&global);
    let p19 = project::<19, _>(&global);
    let mut e16 = rv.enter(sid, &p16).unwrap();
    let mut e17 = rv.enter(sid, &p17).unwrap();
    let mut e18 = rv.enter(sid, &p18).unwrap();
    let mut e19 = rv.enter(sid, &p19).unwrap();
    let mut left_requests: [Option<Command<128>>; 1] = [None];
    let mut left_replies: [Option<Reply<128>>; 1] = [None];
    let mut right_requests: [Option<Command<128>>; 1] = [None];
    let mut right_replies: [Option<Reply<128>>; 1] = [None];
    let left_requests = Mailbox::new(&mut left_requests).unwrap();
    let left_replies = Mailbox::new(&mut left_replies).unwrap();
    let right_requests = Mailbox::new(&mut right_requests).unwrap();
    let right_replies = Mailbox::new(&mut right_replies).unwrap();
    let (left_client_send, left_role_recv) = left_requests.split().unwrap();
    let (left_role_send, left_client_recv) = left_replies.split().unwrap();
    let (right_client_send, right_role_recv) = right_requests.split().unwrap();
    let (right_role_send, right_client_recv) = right_replies.split().unwrap();
    let mut left_exchange = Exchange::new();
    let mut right_exchange = Exchange::new();
    let keys = crypto::initial_keys(b"one-global").unwrap();
    let (count, waker) = waker();
    let consumer = async {
        let left = KeyClient::connect(left_client_send, left_client_recv, 20)
            .await
            .unwrap();
        let mut right = KeyClient::connect(right_client_send, right_client_recv, 20)
            .await
            .unwrap();
        left.retire().await.unwrap();
        assert!(
            !carrier.is_closed(),
            "completed facet must retain endpoint values"
        );
        let ciphertext = right
            .seal(Packet::new(1, b"right header", b"right still live").unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_ne!(ciphertext.body(), b"right still live");
        right.retire().await.unwrap();
        Ok(())
    };
    drive(
        join2(
            join2(
                packet_protection::run_borrowed(
                    &mut e16,
                    &mut e17,
                    20,
                    keys.client,
                    left_role_recv,
                    left_role_send,
                    &mut left_exchange,
                ),
                packet_protection::run_borrowed(
                    &mut e18,
                    &mut e19,
                    20,
                    keys.server,
                    right_role_recv,
                    right_role_send,
                    &mut right_exchange,
                ),
            ),
            consumer,
        ),
        &count,
        &waker,
    )
    .unwrap();
    assert!(!carrier.is_closed());
    assert!(left_exchange.is_empty() && right_exchange.is_empty());
}

#[test]
fn packet_copy_rejects_unrepresentable_packet_numbers_and_buffer_overflow() {
    assert!(matches!(
        Packet::<64>::new(1 << 62, b"header", b"body"),
        Err(crypto::Error::InvalidPacketNumber)
    ));
    assert!(matches!(
        Packet::<4>::new(1, b"header", b"body"),
        Err(crypto::Error::BufferTooSmall)
    ));
}

#[test]
fn actor_owned_retry_rekey_preserves_nonce_guard_and_returns_same_integrity_budget() {
    use hibana_quic::roles::client::KeyClient;
    with_roles(|client_endpoint, crypto_endpoint| {
        let mut requests: [Option<Command<128>>; 1] = [None];
        let mut responses: [Option<Reply<128>>; 1] = [None];
        let commands = Mailbox::new(&mut requests).unwrap();
        let replies = Mailbox::new(&mut responses).unwrap();
        let (sender, receiver) = commands.split().unwrap();
        let (reply_sender, reply_receiver) = replies.split().unwrap();
        let mut exchange = Exchange::new();
        let key = crypto::initial_keys(b"old-initial").unwrap().client;
        let (count, waker) = waker();
        let consumer = async {
            let mut client = KeyClient::connect(sender, reply_receiver, 21)
                .await
                .unwrap();
            assert_eq!(client.generation(), 21);
            let old = client
                .seal(Packet::new(9, b"header", b"before retry").unwrap())
                .await
                .unwrap()
                .unwrap();
            let mut corrupt = [0; 64];
            let len = old.body().len();
            corrupt[..len].copy_from_slice(old.body());
            corrupt[0] ^= 1;
            let (rejected, budget) = client
                .open(
                    Packet::new(9, b"header", &corrupt[..len]).unwrap(),
                    IntegrityBudget::new(),
                )
                .await
                .unwrap();
            assert!(matches!(rejected, Err(crypto::Error::AuthenticationFailed)));
            assert_eq!(budget.failed_packets(), 1);
            // Re-deriving identical material must not restore nonce permission.
            client
                .rekey_initial(b"old-initial", true)
                .await
                .unwrap()
                .unwrap();
            assert!(matches!(
                client
                    .seal(Packet::new(9, b"header", b"reuse").unwrap())
                    .await
                    .unwrap(),
                Err(crypto::Error::PacketNumberReuse)
            ));
            client
                .rekey_initial(b"new-initial", true)
                .await
                .unwrap()
                .unwrap();
            assert!(matches!(
                client
                    .seal(Packet::new(9, b"header", b"still reuse").unwrap())
                    .await
                    .unwrap(),
                Err(crypto::Error::PacketNumberReuse)
            ));
            let sealed = client
                .seal(Packet::new(10, b"header", b"after retry").unwrap())
                .await
                .unwrap()
                .unwrap();
            let reference = crypto::initial_keys(b"new-initial").unwrap().client;
            let mut body = [0; 64];
            body[..sealed.body().len()].copy_from_slice(sealed.body());
            let n = reference
                .open(
                    10,
                    sealed.header(),
                    &mut body[..sealed.body().len()],
                    &mut IntegrityBudget::new(),
                )
                .unwrap();
            assert_eq!(&body[..n], b"after retry");
            let (opened, budget) = client.open(sealed, budget).await.unwrap();
            let opened = opened.unwrap();
            assert_eq!(opened.packet.body(), b"after retry");
            assert_eq!(opened.receipt.packet_number(), 10);
            assert_eq!(
                budget.failed_packets(),
                1,
                "Retry cannot reset connection-wide authentication failures"
            );
            client.retire().await.unwrap();
            Ok(())
        };
        let no_alloc = NoAlloc::start();
        drive(
            join2(
                packet_protection::run(
                    client_endpoint,
                    crypto_endpoint,
                    21,
                    key,
                    receiver,
                    reply_sender,
                    &mut exchange,
                ),
                consumer,
            ),
            &count,
            &waker,
        )
        .unwrap();
        drop(no_alloc);
        assert_eq!(ALLOCATIONS.with(Cell::get), 0);
    });
}

#[test]
fn initial_rekey_rejects_other_levels_without_losing_their_real_key() {
    use hibana_quic::roles::client::KeyClient;
    with_roles(|client_endpoint, crypto_endpoint| {
        let mut requests: [Option<Command<128>>; 1] = [None];
        let mut responses: [Option<Reply<128>>; 1] = [None];
        let commands = Mailbox::new(&mut requests).unwrap();
        let replies = Mailbox::new(&mut responses).unwrap();
        let (sender, receiver) = commands.split().unwrap();
        let (reply_sender, reply_receiver) = replies.split().unwrap();
        let mut exchange = Exchange::new();
        let key = crypto::PacketKey::from_secret(
            crypto::CipherSuite::Aes128GcmSha256,
            crypto::KeyKind::Handshake,
            &[7; 32],
        )
        .unwrap();
        let (count, waker) = waker();
        let consumer = async {
            let mut client = KeyClient::connect(sender, reply_receiver, 22)
                .await
                .unwrap();
            assert!(matches!(
                client.rekey_initial(&[1; 21], true).await.unwrap(),
                Err(crypto::Error::InvalidConnectionId)
            ));
            assert!(matches!(
                client.rekey_initial(b"new-initial", true).await.unwrap(),
                Err(crypto::Error::KeyUpdateNotAllowed)
            ));
            assert!(
                client
                    .seal(Packet::new(1, b"header", b"still handshake").unwrap())
                    .await
                    .unwrap()
                    .is_ok()
            );
            client.retire().await.unwrap();
            Ok(())
        };
        drive(
            join2(
                packet_protection::run(
                    client_endpoint,
                    crypto_endpoint,
                    22,
                    key,
                    receiver,
                    reply_sender,
                    &mut exchange,
                ),
                consumer,
            ),
            &count,
            &waker,
        )
        .unwrap();
    });
}
