use super::*;
use crate::{carrier::CarrierStorage, mailbox::Mailbox};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use hibana::{
    g,
    runtime::{SessionKitStorage, ids::SessionId, program::project},
};
use std::{
    format,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::Wake,
};

struct Random {
    value: u64,
    fail: bool,
}
impl RngCore for Random {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.value ^= self.value << 13;
        self.value ^= self.value >> 7;
        self.value ^= self.value << 17;
        self.value
    }
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        for chunk in bytes.chunks_mut(8) {
            chunk.copy_from_slice(&self.next_u64().to_le_bytes()[..chunk.len()]);
        }
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rand_core::Error> {
        if self.fail {
            return Err(rand_core::Error::from(
                core::num::NonZeroU32::new(rand_core::Error::CUSTOM_START).unwrap(),
            ));
        }
        self.fill_bytes(bytes);
        Ok(())
    }
}
impl CryptoRng for Random {}
const GENERATION: u64 = 931;
fn address(port: u16) -> Address {
    Address {
        local: "127.0.0.1:4433".parse().unwrap(),
        remote: format!("127.0.0.1:{port}").parse().unwrap(),
    }
}
fn config(role: Role) -> Config {
    Config {
        generation: GENERATION,
        role,
        initial: address(5000),
        local_cid: Destination::new(b"serverid").unwrap(),
        bootstrap_destination: Destination::new(b"clientid").unwrap(),
        local_active_limit: 2,
        local_reset_token: None,
        preferred_server: None,
        now: 0,
        pto: 100,
    }
}
fn descriptor(sequence: u64) -> Descriptor {
    Descriptor {
        generation: GENERATION,
        sequence,
    }
}
fn number(value: u64) -> PacketNumber {
    PacketNumber {
        space: PacketNumberSpace::ApplicationData,
        value,
    }
}
fn with_unlearned_state<T>(config: Config, body: impl FnOnce(&mut State<'_, Random>) -> T) -> T {
    let mut paths = [const { PathSlot::empty() }; PATHS];
    let mut local = [LocalCidSlot::EMPTY; LOCAL_CIDS];
    let mut peer = [PeerCidSlot::EMPTY; PEER_CIDS];
    let mut state = State::new(
        config,
        Resources {
            paths: &mut paths,
            local_cids: &mut local,
            peer_cids: &mut peer,
        },
        Random {
            value: 97,
            fail: false,
        },
    )
    .unwrap();
    body(&mut state)
}
fn learn(state: &mut State<'_, Random>) {
    let (receipt, packet) = super::test_auth::initial(
        state.config.generation,
        state.config.bootstrap_destination.as_bytes(),
        state.config.local_cid.as_bytes(),
    );
    let arena = authority::Arena::<1, 2>::new(state.config.generation);
    let ticket = arena
        .admit(authority::ReceiveEvidence::Initial(receipt), packet.body())
        .unwrap();
    let grant = arena
        .grant_initial_peer_cid(ticket, packet.header())
        .unwrap();
    state.learn_peer_cid(&arena, grant).unwrap();
    arena.finish(ticket).unwrap();
}
fn with_state<T>(config: Config, body: impl FnOnce(&mut State<'_, Random>) -> T) -> T {
    with_unlearned_state(config, |state| {
        learn(state);
        body(state)
    })
}
fn context(id: u64, address: Address) -> PathContext {
    PathContext {
        address,
        destination: Destination::new(b"serverid").unwrap(),
        datagram_id: id,
        datagram_bytes: 1200,
        now: 0,
    }
}
fn install(state: &mut State<'_, Random>) {
    state
        .install(VerifiedParameters {
            peer_cid: Destination::new(b"clientid").unwrap(),
            peer_active_limit: 2,
            disable_active_migration: false,
            initial_reset_token: None,
            preferred: None,
        })
        .unwrap();
    state.confirmed = true;
    state.migration.handshake_confirmed();
}
struct Wakes(AtomicUsize);
impl Wake for Wakes {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref()
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
pub(super) fn drive<F: Future>(future: F) -> F::Output {
    let wakes = Arc::new(Wakes(AtomicUsize::new(0)));
    let waker = Waker::from(wakes.clone());
    let mut cx = Context::from_waker(&waker);
    let mut future = pin!(future);
    for _ in 0..8192 {
        let before = wakes.0.load(Ordering::SeqCst);
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(value) => return value,
            Poll::Pending => assert!(
                wakes.0.load(Ordering::SeqCst) > before,
                "ready actors lost a wake"
            ),
        }
    }
    panic!("bounded actor scenario did not finish")
}

#[test]
fn server_credit_is_once_per_exact_udp_tuple_and_rejection_releases_it() {
    with_state(config(Role::Server), |state| {
        let path = state.original;
        assert!(matches!(
            state.reserve(descriptor(1), path, 1, number(0), false, 0),
            Err(Error::Path(_))
        ));
        assert_eq!(state.ingress(context(1, address(5000))).unwrap(), path);
        assert_eq!(state.ingress(context(1, address(5000))).unwrap(), path);
        assert_eq!(state.paths.snapshot(path).unwrap().received, 1200);
        let mut altered = context(1, address(5000));
        altered.datagram_bytes = 2400;
        assert_eq!(state.ingress(altered), Err(Error::StaleIngress));
        assert!(matches!(
            state.reserve(descriptor(2), path, 3600, number(1), false, 0),
            Err(Error::Path(path::Error::InvalidDatagramSize))
        ));
        let pending = state
            .reserve(descriptor(3), path, 1200, number(1), false, 0)
            .unwrap();
        assert_eq!(state.paths.snapshot(path).unwrap().reserved, 1200);
        state.complete(pending.reject()).unwrap();
        let snapshot = state.paths.snapshot(path).unwrap();
        assert_eq!(
            (snapshot.sent, snapshot.reserved, snapshot.available_bytes),
            (0, 0, 3600)
        );
    });
}
#[test]
fn altered_or_replayed_callback_does_not_release_another_reservation() {
    with_state(config(Role::Client), |state| {
        let path = state.original;
        let pending = state
            .reserve(descriptor(1), path, 1200, number(1), false, 0)
            .unwrap();
        let mut changed = pending.record;
        changed.address.remote = address(7000).remote;
        assert_eq!(
            state.complete(AdapterCompletion {
                record: changed,
                accepted_at: Some(0),
                advertisement: None
            }),
            Err(Error::InvalidDescriptor)
        );
        assert_eq!(state.paths.snapshot(path).unwrap().reserved, 1200);
        let copy = pending.record;
        state.complete(pending.reject()).unwrap();
        assert_eq!(
            state.complete(AdapterCompletion {
                record: copy,
                accepted_at: Some(0),
                advertisement: None
            }),
            Err(Error::InvalidDescriptor)
        );
        assert_eq!(state.paths.snapshot(path).unwrap().sent, 0);
    });
}
#[test]
fn stale_path_identity_cannot_reserve_after_slot_reuse() {
    with_state(config(Role::Client), |state| {
        let stale = state.original;
        state.paths.retire(stale).unwrap();
        let fresh = state
            .paths
            .insert(address(5000), InitialValidation::ClientUnvalidated, 0)
            .unwrap();
        assert_ne!(fresh.path_generation, stale.path_generation);
        assert!(matches!(
            state.reserve(descriptor(1), stale, 10, number(1), false, 0),
            Err(Error::Path(path::Error::StalePath))
        ));
    });
}
#[test]
fn entropy_failure_leaves_no_pending_probe_or_bytes() {
    with_state(config(Role::Client), |state| {
        state.rng.fail = true;
        assert!(matches!(
            state.reserve(descriptor(1), state.original, 1200, number(1), true, 0),
            Err(Error::Path(path::Error::Entropy))
        ));
        let snapshot = state.paths.snapshot(state.original).unwrap();
        assert_eq!((snapshot.reserved, snapshot.attempts), (0, 0));
        assert_eq!(state.snapshot().pending_transmits, 0);
    });
}
#[test]
fn fixed_zero_cid_rejects_rebinding_and_nonzero_replacement() {
    let mut c = config(Role::Server);
    c.bootstrap_destination = Destination::new(b"").unwrap();
    with_state(c, |state| {
        state
            .install(VerifiedParameters {
                peer_cid: Destination::new(b"").unwrap(),
                peer_active_limit: 2,
                disable_active_migration: false,
                initial_reset_token: Some(ResetToken::new([7; 16])),
                preferred: None,
            })
            .unwrap();
        state.confirmed = true;
        state.migration.handshake_confirmed();
        assert_eq!(
            state.ingress(context(1, address(6000))),
            Err(Error::FixedZeroCid)
        );
        assert!(state.peer.is_none());
        let path = state
            .paths
            .insert(address(6000), InitialValidation::Unvalidated, 0)
            .unwrap();
        assert_eq!(state.destination(path), Err(Error::FixedZeroCid));
        assert_eq!(state.destination(state.original).unwrap().0.as_bytes(), b"");
    });
}
#[test]
fn timeout_requires_unchanged_current_observation_and_due_deadline() {
    with_state(config(Role::Client), |state| {
        let before = state.timer().unwrap();
        assert_eq!(before.deadline(), 300);
        assert_eq!(state.timeout(before, 299), Err(Error::TimerNotDue));
        let stale = state.timer().unwrap();
        state.revision += 1;
        assert_eq!(state.timeout(stale, 300), Err(Error::StaleTimer));
        let current = state.timer().unwrap();
        assert_eq!(state.timeout(current, 300), Ok(None));
        assert!(matches!(
            state.abandonment.as_ref().unwrap().resume,
            AbandonResume::Terminal
        ));
        assert!(state.paths.snapshot(state.original).unwrap().failed);
        assert!(state.timer().is_none());
    });
}
#[test]
fn unadvertised_local_cid_and_current_destination_cannot_retire() {
    with_state(config(Role::Server), |state| {
        install(state);
        let Some(Control::NewConnectionId { sequence, cid, .. }) = state.issue_cid().unwrap()
        else {
            panic!("CID")
        };
        assert_eq!(
            state.local.retire_authenticated(sequence, b"serverid"),
            Err(CidError::UnknownSequence)
        );
        let handle = state.local.route(cid.as_bytes()).unwrap();
        state.local.mark_advertised(handle).unwrap();
        assert_eq!(
            state.local.retire_authenticated(sequence, cid.as_bytes()),
            Err(CidError::CurrentDestinationCid)
        );
        assert!(
            state
                .local
                .retire_authenticated(sequence, b"serverid")
                .unwrap()
        );
        assert_eq!(state.local.route(cid.as_bytes()), None);
    });
}
#[test]
fn challenge_matches_original_exact_tuple_and_only_accepted_full_size_send_proves_mtu() {
    with_state(config(Role::Client), |state| {
        let path = state.original;
        let pending = state
            .reserve(descriptor(1), path, 1200, number(1), true, 0)
            .unwrap();
        let Some(Control::Challenge(data)) = pending.control() else {
            panic!("challenge")
        };
        assert!(state.paths.response(data, 0).unwrap().is_none());
        // Unit-level adversarial callback fixture: production creates this value
        // only from ProtectedDatagram submission and the real adapter's return.
        state
            .complete(AdapterCompletion {
                record: pending.record,
                accepted_at: Some(0),
                advertisement: None,
            })
            .unwrap();
        let other = state
            .paths
            .insert(address(6000), InitialValidation::Unvalidated, 0)
            .unwrap();
        let validated = state.paths.response(data, 1).unwrap().unwrap();
        assert_eq!(validated.path, path);
        assert_eq!(validated.address, address(5000));
        assert!(validated.mtu_validated);
        assert!(!state.paths.snapshot(other).unwrap().address_validated);
        assert!(state.paths.response(data, 1).unwrap().is_none());
    });
}
#[test]
fn owner_drop_releases_all_caller_owned_path_slots() {
    let mut paths = [const { PathSlot::empty() }; PATHS];
    let mut local = [LocalCidSlot::EMPTY; LOCAL_CIDS];
    let mut peer = [PeerCidSlot::EMPTY; PEER_CIDS];
    {
        let mut state = State::new(
            config(Role::Client),
            Resources {
                paths: &mut paths,
                local_cids: &mut local,
                peer_cids: &mut peer,
            },
            Random {
                value: 97,
                fail: false,
            },
        )
        .unwrap();
        let _pending = state
            .reserve(descriptor(1), state.original, 1200, number(1), false, 0)
            .unwrap();
    }
    let state = State::new(
        config(Role::Client),
        Resources {
            paths: &mut paths,
            local_cids: &mut local,
            peer_cids: &mut peer,
        },
        Random {
            value: 98,
            fail: false,
        },
    )
    .unwrap();
    assert_eq!(state.snapshot().pending_transmits, 0);
    assert_eq!(state.paths.snapshot(state.original).unwrap().reserved, 0);
}

#[test]
#[allow(long_running_const_eval)]
fn q1_projected_reservation_branch_waits_for_exact_callback_then_retires() {
    let mut paths = [const { PathSlot::empty() }; PATHS];
    let mut local = [LocalCidSlot::EMPTY; LOCAL_CIDS];
    let mut peer = [PeerCidSlot::EMPTY; PEER_CIDS];
    let state = State::new(
        config(Role::Client),
        Resources {
            paths: &mut paths,
            local_cids: &mut local,
            peer_cids: &mut peer,
        },
        Random {
            value: 97,
            fail: false,
        },
    )
    .unwrap();
    let carrier = CarrierStorage::<1, 16, 32>::new();
    let mut slab = [0; 65536];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init();
    let sid = SessionId::new(931);
    let rv = kit
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    let global = p::path_choreography::<30, 31>();
    let cp = project::<30, _>(&global);
    let op = project::<31, _>(&global);
    let mut c = rv.enter(sid, &cp).unwrap();
    let mut o = rv.enter(sid, &op).unwrap();
    let mut commands = [None];
    let mut replies = [None];
    let commands = Mailbox::new(&mut commands).unwrap();
    let replies = Mailbox::new(&mut replies).unwrap();
    let (tx, rx) = commands.split().unwrap();
    let (rtx, rrx) = replies.split().unwrap();
    let mut exchange = Exchange::new();
    let arena = authority::Arena::<2, 8>::new(GENERATION);
    let workload = async {
        let mut client = Client::connect(tx, rrx, GENERATION).await.unwrap();
        let path = client.snapshot().active;
        assert!(matches!(
            client
                .request(Command::ReserveControl {
                    path,
                    bytes: 1200,
                    packet: number(0),
                    now: 0
                })
                .await
                .unwrap(),
            Outcome::Rejected(Error::HandshakeNotInstalled)
        ));
        assert_eq!(client.snapshot().pending_transmits, 0);
        let Outcome::Reserved(pending) = client
            .request(Command::Reserve {
                path,
                bytes: 1200,
                packet: number(1),
                now: 0,
            })
            .await
            .unwrap()
        else {
            panic!("reservation")
        };
        assert_eq!(client.snapshot().pending_transmits, 1);
        assert_eq!(client.snapshot().paths[0].unwrap().1.reserved, 1200);
        runtime::yield_now().await;
        assert!(matches!(
            client.reject(pending).await.unwrap(),
            Outcome::AdapterCompleted
        ));
        assert_eq!(client.snapshot().pending_transmits, 0);
        assert_eq!(client.snapshot().paths[0].unwrap().1.sent, 0);
        let retired = client.retire().await.unwrap();
        assert!(retired.paths.iter().all(Option::is_none));
        Ok(())
    };
    drive(runtime::join2(
        run_borrowed(&mut c, &mut o, state, &arena, rx, rtx, &mut exchange),
        workload,
    ))
    .unwrap();
    assert!(exchange.is_empty());
    assert!(carrier.queued() == 0);
}
#[test]
#[allow(long_running_const_eval)]
fn independent_path_pairs_compose_under_real_par() {
    let global = g::par(
        p::path_choreography::<30, 31>(),
        p::path_choreography::<32, 33>(),
    );
    let carrier = CarrierStorage::<1, 16, 64>::new();
    let mut slab = [0; 65536];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init();
    let sid = SessionId::new(932);
    let rv = kit
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    let cp1 = project::<30, _>(&global);
    let op1 = project::<31, _>(&global);
    let cp2 = project::<32, _>(&global);
    let op2 = project::<33, _>(&global);
    let mut c1 = rv.enter(sid, &cp1).unwrap();
    let mut o1 = rv.enter(sid, &op1).unwrap();
    let mut c2 = rv.enter(sid, &cp2).unwrap();
    let mut o2 = rv.enter(sid, &op2).unwrap();
    let mut paths1 = [const { PathSlot::empty() }; PATHS];
    let mut local1 = [LocalCidSlot::EMPTY; LOCAL_CIDS];
    let mut peer1 = [PeerCidSlot::EMPTY; PEER_CIDS];
    let mut paths2 = [const { PathSlot::empty() }; PATHS];
    let mut local2 = [LocalCidSlot::EMPTY; LOCAL_CIDS];
    let mut peer2 = [PeerCidSlot::EMPTY; PEER_CIDS];
    let state1 = State::new(
        config(Role::Client),
        Resources {
            paths: &mut paths1,
            local_cids: &mut local1,
            peer_cids: &mut peer1,
        },
        Random {
            value: 97,
            fail: false,
        },
    )
    .unwrap();
    let state2 = State::new(
        config(Role::Client),
        Resources {
            paths: &mut paths2,
            local_cids: &mut local2,
            peer_cids: &mut peer2,
        },
        Random {
            value: 99,
            fail: false,
        },
    )
    .unwrap();
    let mut cq1 = [None];
    let mut rq1 = [None];
    let mut cq2 = [None];
    let mut rq2 = [None];
    let cq1 = Mailbox::new(&mut cq1).unwrap();
    let rq1 = Mailbox::new(&mut rq1).unwrap();
    let cq2 = Mailbox::new(&mut cq2).unwrap();
    let rq2 = Mailbox::new(&mut rq2).unwrap();
    let (cs1, cr1) = cq1.split().unwrap();
    let (rs1, rr1) = rq1.split().unwrap();
    let (cs2, cr2) = cq2.split().unwrap();
    let (rs2, rr2) = rq2.split().unwrap();
    let mut exchange1 = Exchange::new();
    let mut exchange2 = Exchange::new();
    let arena1 = authority::Arena::<2, 8>::new(GENERATION);
    let arena2 = authority::Arena::<2, 8>::new(GENERATION);
    let first_pending = core::cell::Cell::new(false);
    let second_progressed = core::cell::Cell::new(false);
    let first = async {
        let mut client = Client::connect(cs1, rr1, GENERATION).await.unwrap();
        let Outcome::Reserved(pending) = client
            .request(Command::Reserve {
                path: client.snapshot().active,
                bytes: 1200,
                packet: number(1),
                now: 0,
            })
            .await
            .unwrap()
        else {
            panic!("reserve");
        };
        first_pending.set(true);
        for _ in 0..128 {
            if second_progressed.get() {
                break;
            }
            runtime::yield_now().await;
        }
        assert!(
            second_progressed.get(),
            "independent owner stalled behind another adapter"
        );
        client.reject(pending).await.unwrap();
        client.retire().await.unwrap();
        Ok(())
    };
    let second = async {
        let mut client = Client::connect(cs2, rr2, GENERATION).await.unwrap();
        for _ in 0..128 {
            if first_pending.get() {
                break;
            }
            runtime::yield_now().await;
        }
        assert!(first_pending.get());
        assert!(matches!(
            client.request(Command::Inspect).await.unwrap(),
            Outcome::Snapshot
        ));
        assert_eq!(client.snapshot().pending_transmits, 0);
        second_progressed.set(true);
        client.retire().await.unwrap();
        Ok(())
    };
    drive(runtime::join2(
        runtime::join2(
            run_borrowed(&mut c1, &mut o1, state1, &arena1, cr1, rs1, &mut exchange1),
            run_borrowed(&mut c2, &mut o2, state2, &arena2, cr2, rs2, &mut exchange2),
        ),
        runtime::join2(first, second),
    ))
    .unwrap();
    assert!(exchange1.is_empty() && exchange2.is_empty());
    assert_eq!(carrier.queued(), 0);
}

/// Recovery tests obtain their accepted callback from the same production
/// submission boundary as an endpoint. This fixture's adapter really parks,
/// wakes its caller, then reports its complete-datagram acceptance timestamp.
pub(crate) async fn submit_recovery(
    ticket: crate::roles::recovery_owner::SendTicket,
    sealed: crate::roles::sealed_packet::SealedPacket<1200>,
    plaintext: &[u8],
    mask: [u8; 5],
) -> crate::roles::datagram::RecoveryCompletion {
    struct Adapter;
    impl UdpAdapter for Adapter {
        async fn send(&mut self, datagram: Datagram<'_>) -> Result<u64, ()> {
            assert_eq!(datagram.address, address(5000));
            assert!(!datagram.bytes.is_empty());
            runtime::yield_now().await;
            Ok(10)
        }
    }
    let mut paths = [const { PathSlot::empty() }; PATHS];
    let mut local = [LocalCidSlot::EMPTY; LOCAL_CIDS];
    let mut peer = [PeerCidSlot::EMPTY; PEER_CIDS];
    let mut config = config(Role::Client);
    config.generation = ticket.descriptor().generation;
    let mut state = State::new(
        config,
        Resources {
            paths: &mut paths,
            local_cids: &mut local,
            peer_cids: &mut peer,
        },
        Random {
            value: 91,
            fail: false,
        },
    )
    .unwrap();
    let pending = state
        .reserve(
            Descriptor {
                generation: config.generation,
                sequence: 1,
            },
            state.original,
            sealed.bytes().len() as u64,
            ticket.packet(),
            false,
            0,
        )
        .unwrap();
    let offset = sealed.header().len() - 1;
    let protected = crate::roles::datagram::ProtectedDatagram::from_sealed::<1>(
        &pending,
        ticket,
        None,
        crate::ecn::Codepoint::NotEct,
        sealed,
        plaintext,
        offset,
        mask,
    )
    .unwrap();
    let completions = pending.submit(&mut Adapter, protected).await.unwrap();
    assert!(completions.recovery.accepted_at().is_some());
    state.complete(completions.path.into()).unwrap();
    completions.recovery
}

#[test]
fn authenticated_frame_grant_is_affine_cancelled_and_ordinal_bound() {
    let data = [23; 8];
    let mut wire = [0; 9];
    wire[0] = 0x1a;
    wire[1..].copy_from_slice(&data);
    let (evidence, ready) = super::test_auth::authenticated(GENERATION, &wire, 7);
    let arena = authority::Arena::<2, 8>::new(GENERATION);
    let ticket = arena.admit(evidence, &wire).unwrap();
    with_state(config(Role::Server), |state| {
        state.handshake(ready).unwrap();
        arena
            .bind_path_context(ticket, context(1, address(5000)))
            .unwrap();
        assert!(matches!(
            arena.grant_path(
                ticket,
                0,
                PathFrame::Challenge([99; 8]),
                context(1, address(5000))
            ),
            Err(authority::Error::InvalidFrame)
        ));
        assert!(matches!(
            arena.grant_path(
                ticket,
                0,
                PathFrame::Challenge(data),
                context(1, address(6000))
            ),
            Err(authority::Error::InvalidFrame)
        ));
        let grant = arena
            .grant_path(
                ticket,
                0,
                PathFrame::Challenge(data),
                context(1, address(5000)),
            )
            .unwrap();
        assert!(matches!(
            arena.grant_path(
                ticket,
                0,
                PathFrame::Challenge([99; 8]),
                context(1, address(5000))
            ),
            Err(authority::Error::InvalidFrame)
        ));
        assert!(
            matches!(state.frame(&arena,grant).unwrap(),Outcome::Frame{path,..} if path==state.original)
        );
        let pending = state
            .reserve(descriptor(1), state.original, 1200, number(1), true, 0)
            .unwrap();
        assert_eq!(pending.control(), Some(Control::Response(data)));
        state.complete(pending.reject()).unwrap();
        let stale = arena
            .grant_path(
                ticket,
                0,
                PathFrame::PacketProcessed { non_probing: false },
                context(1, address(5000)),
            )
            .unwrap();
        arena.cancel(ticket).unwrap();
        assert!(matches!(
            state.frame(&arena, stale),
            Err(Error::Authority(authority::Error::InvalidGrant))
        ));
        assert_eq!(state.paths.snapshot(state.original).unwrap().received, 1200);
    });
}
#[test]
fn actual_authenticated_rebinding_keeps_cid_on_same_local_and_requires_probe() {
    let (evidence, ready) = super::test_auth::authenticated(GENERATION, &[1], 7);
    let arena = authority::Arena::<2, 8>::new(GENERATION);
    let ticket = arena.admit(evidence, &[1]).unwrap();
    with_state(config(Role::Server), |state| {
        state.handshake(ready).unwrap();
        arena
            .bind_path_context(ticket, context(1, address(6000)))
            .unwrap();
        state.inbound[0] = Some(Destination::new(b"serverid").unwrap());
        let initial = state.bindings[0].unwrap();
        state
            .peer
            .as_mut()
            .unwrap()
            .record_sent(initial, address(5000).local, address(5000).remote)
            .unwrap();
        let grant = arena
            .grant_path(
                ticket,
                0,
                PathFrame::PacketProcessed { non_probing: true },
                context(1, address(6000)),
            )
            .unwrap();
        let Outcome::Frame { path, decision, .. } = state.frame(&arena, grant).unwrap() else {
            panic!("frame")
        };
        assert_ne!(path, state.original);
        assert!(matches!(decision, Decision::Switched(_)));
        assert_eq!(state.bindings[usize::from(path.slot)], Some(initial));
        let snapshot = state.paths.snapshot(path).unwrap();
        assert!(!snapshot.address_validated);
        assert!(!snapshot.mtu_validated);
        assert_eq!(snapshot.available_bytes, 3600);
        let pending = state
            .reserve(descriptor(1), path, 1200, number(1), true, 0)
            .unwrap();
        assert!(matches!(pending.control(), Some(Control::Challenge(_))));
        assert_eq!(pending.address(), address(6000));
        state.complete(pending.reject()).unwrap();
        arena.finish(ticket).unwrap();
    });
}
#[test]
fn actual_finished_generation_cannot_install_another_connection() {
    let (_, ready) = super::test_auth::authenticated(GENERATION + 1, &[1], 0);
    with_state(config(Role::Server), |state| {
        assert_eq!(state.handshake(ready), Err(Error::WrongGeneration));
        assert!(!state.installed);
        assert!(
            !state
                .paths
                .snapshot(state.original)
                .unwrap()
                .address_validated
        );
    });
}

#[test]
fn ciphertext_receipt_rejects_substituted_plaintext_before_any_path_admission() {
    let (evidence, _) = super::test_auth::authenticated(GENERATION, &[1], 9);
    let arena = authority::Arena::<2, 8>::new(GENERATION);
    assert!(matches!(
        arena.admit(evidence, &[0]),
        Err(authority::Error::InvalidFrame)
    ));
    assert_eq!(arena.live_packets(), 0);
    assert_eq!(arena.live_effects(), 0);
}
#[test]
fn cid_grant_rejects_changed_sequence_cid_and_reset_token() {
    let cid = Cid::new(b"newcid01").unwrap();
    let mut wire = [0; 28];
    wire[..4].copy_from_slice(&[0x18, 1, 0, 8]);
    wire[4..12].copy_from_slice(cid.as_bytes());
    wire[12..].fill(23);
    let (evidence, ready) = super::test_auth::authenticated(GENERATION, &wire, 8);
    let arena = authority::Arena::<2, 8>::new(GENERATION);
    let ticket = arena.admit(evidence, &wire).unwrap();
    let context = context(1, address(5000));
    arena.bind_path_context(ticket, context).unwrap();
    let actual = PathFrame::NewConnectionId {
        sequence: 1,
        retire_prior_to: 0,
        id: cid,
        reset_token: ResetToken::new([23; 16]),
    };
    for altered in [
        PathFrame::NewConnectionId {
            sequence: 2,
            retire_prior_to: 0,
            id: cid,
            reset_token: ResetToken::new([23; 16]),
        },
        PathFrame::NewConnectionId {
            sequence: 1,
            retire_prior_to: 0,
            id: Cid::new(b"wrongcid").unwrap(),
            reset_token: ResetToken::new([23; 16]),
        },
        PathFrame::NewConnectionId {
            sequence: 1,
            retire_prior_to: 0,
            id: cid,
            reset_token: ResetToken::new([24; 16]),
        },
    ] {
        assert!(matches!(
            arena.grant_path(ticket, 0, altered, context),
            Err(authority::Error::InvalidFrame)
        ));
    }
    with_state(config(Role::Server), |state| {
        state.handshake(ready).unwrap();
        let grant = arena.grant_path(ticket, 0, actual, context).unwrap();
        state.frame(&arena, grant).unwrap();
        assert_eq!(state.peer.as_ref().unwrap().active().count(), 2);
        assert!(
            state
                .peer
                .as_ref()
                .unwrap()
                .active()
                .any(|item| item.cid == cid)
        );
    });
    arena.finish(ticket).unwrap();
}

#[test]
fn invalid_preferred_cid_does_not_leave_path_storage_in_use() {
    let mut paths = [const { PathSlot::empty() }; PATHS];
    let mut local = [LocalCidSlot::EMPTY; LOCAL_CIDS];
    let mut peer = [PeerCidSlot::EMPTY; PEER_CIDS];
    let mut bad = config(Role::Server);
    bad.preferred_server = Some(PreferredLocal {
        address: "127.0.0.1:4444".parse().unwrap(),
        cid: Cid::new(b"serverid").unwrap(),
        reset_token: ResetToken::new([7; 16]),
    });
    assert!(matches!(
        State::new(
            bad,
            Resources {
                paths: &mut paths,
                local_cids: &mut local,
                peer_cids: &mut peer
            },
            Random {
                value: 1,
                fail: false
            }
        ),
        Err(Error::Cid(CidError::ConnectionIdReused))
    ));
    let good = State::new(
        config(Role::Server),
        Resources {
            paths: &mut paths,
            local_cids: &mut local,
            peer_cids: &mut peer,
        },
        Random {
            value: 1,
            fail: false,
        },
    )
    .unwrap();
    assert_eq!(good.snapshot().paths.iter().flatten().count(), 1);
}
#[test]
fn preferred_local_tuple_waits_for_actual_complete_advertisement_proof() {
    let mut config = config(Role::Server);
    let preferred = "127.0.0.1:4444".parse().unwrap();
    config.preferred_server = Some(PreferredLocal {
        address: preferred,
        cid: Cid::new(b"prefcid1").unwrap(),
        reset_token: ResetToken::new([9; 16]),
    });
    with_state(config, |state| {
        install(state);
        assert!(state.snapshot().preferred_advertisement_pending);
        assert_eq!(
            state.local.retire_authenticated(1, b"serverid"),
            Err(CidError::UnknownSequence)
        );
        let mut incoming = context(1, address(5000));
        incoming.address.local = preferred;
        assert_eq!(
            state.ingress(incoming),
            Err(Error::PreferredAdvertisementRequired)
        );
        assert!(!state.preferred_advertised);
    });
}

#[test]
#[allow(long_running_const_eval)]
fn cancelling_pending_actor_releases_reservation_and_prevents_reuse() {
    let mut paths = [const { PathSlot::empty() }; PATHS];
    let mut local = [LocalCidSlot::EMPTY; LOCAL_CIDS];
    let mut peer = [PeerCidSlot::EMPTY; PEER_CIDS];
    let state = State::new(
        config(Role::Client),
        Resources {
            paths: &mut paths,
            local_cids: &mut local,
            peer_cids: &mut peer,
        },
        Random {
            value: 97,
            fail: false,
        },
    )
    .unwrap();
    let carrier = CarrierStorage::<1, 16, 32>::new();
    let mut slab = [0; 65536];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init();
    let sid = SessionId::new(935);
    let rv = kit
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    let global = p::path_choreography::<30, 31>();
    let cp = project::<30, _>(&global);
    let op = project::<31, _>(&global);
    let mut c = rv.enter(sid, &cp).unwrap();
    let mut o = rv.enter(sid, &op).unwrap();
    let mut commands = [None];
    let mut replies = [None];
    let commands = Mailbox::new(&mut commands).unwrap();
    let replies = Mailbox::new(&mut replies).unwrap();
    let (tx, rx) = commands.split().unwrap();
    let (rtx, rrx) = replies.split().unwrap();
    let mut exchange = Exchange::new();
    let arena = authority::Arena::<2, 8>::new(GENERATION);
    let workload = async {
        let mut client = Client::connect(tx, rrx, GENERATION).await.unwrap();
        let Outcome::Reserved(pending) = client
            .request(Command::Reserve {
                path: client.snapshot().active,
                bytes: 1200,
                packet: number(1),
                now: 0,
            })
            .await
            .unwrap()
        else {
            panic!("reservation");
        };
        assert_eq!(client.snapshot().paths[0].unwrap().1.reserved, 1200);
        drop(pending);
        drop(client);
        Ok(())
    };
    assert!(matches!(
        drive(runtime::join2(
            run_borrowed(&mut c, &mut o, state, &arena, rx, rtx, &mut exchange),
            workload
        )),
        Err(ServiceError::CommandsClosed | ServiceError::RepliesClosed)
    ));
    assert!(exchange.is_empty());
    let replacement = State::new(
        config(Role::Client),
        Resources {
            paths: &mut paths,
            local_cids: &mut local,
            peer_cids: &mut peer,
        },
        Random {
            value: 99,
            fail: false,
        },
    )
    .unwrap();
    assert_eq!(replacement.snapshot().pending_transmits, 0);
    assert_eq!(
        replacement
            .paths
            .snapshot(replacement.original)
            .unwrap()
            .reserved,
        0
    );
}

#[test]
fn early_cid_preflight_combines_prior_and_new_frames_without_live_mutation() {
    with_state(config(Role::Server), |state| {
        let context = context(1, address(5000));
        let one = PathFrame::NewConnectionId {
            sequence: 1,
            retire_prior_to: 0,
            id: Cid::new(b"cidone01").unwrap(),
            reset_token: ResetToken::new([1; 16]),
        };
        let two = PathFrame::NewConnectionId {
            sequence: 2,
            retire_prior_to: 0,
            id: Cid::new(b"cidtwo02").unwrap(),
            reset_token: ResetToken::new([2; 16]),
        };
        assert!(
            state
                .preflight_early_network(state.original, context, 2, [(one, context)])
                .is_ok()
        );
        assert!(
            state
                .preflight_early_network(state.original, context, 2, [(two, context)])
                .is_ok()
        );
        assert_eq!(
            state.preflight_early_network(
                state.original,
                context,
                2,
                [(one, context), (two, context)]
            ),
            Err(Error::Cid(CidError::ActiveLimit))
        );
        assert!(state.peer.is_none());
        assert_eq!(state.paths.snapshot(state.original).unwrap().received, 0);
        assert!(
            !state
                .paths
                .snapshot(state.original)
                .unwrap()
                .address_validated
        );
    });
}
#[test]
fn early_network_preflight_rejects_response_changed_tuple_and_unsent_retirement() {
    with_state(config(Role::Server), |state| {
        let context = context(1, address(5000));
        assert_eq!(
            state.preflight_early_network(
                state.original,
                context,
                2,
                [(PathFrame::Response([1; 8]), context)]
            ),
            Err(Error::WrongLevel)
        );
        let mut changed = context;
        changed.address.remote = address(6000).remote;
        assert_eq!(
            state.preflight_early_network(
                state.original,
                changed,
                2,
                [(PathFrame::Challenge([1; 8]), changed)]
            ),
            Err(Error::FixedZeroCid)
        );
        assert_eq!(
            state.preflight_early_network(
                state.original,
                context,
                2,
                [(PathFrame::RetireConnectionId { sequence: 1 }, context)]
            ),
            Err(Error::Cid(CidError::UnknownSequence))
        );
    });
}
#[test]
fn zero_cid_early_preflight_rejects_new_connection_id() {
    let mut config = config(Role::Server);
    config.bootstrap_destination = Destination::new(b"").unwrap();
    with_state(config, |state| {
        let context = context(1, address(5000));
        let frame = PathFrame::NewConnectionId {
            sequence: 1,
            retire_prior_to: 0,
            id: Cid::new(b"newcid01").unwrap(),
            reset_token: ResetToken::new([1; 16]),
        };
        assert_eq!(
            state.preflight_early_network(state.original, context, 2, [(frame, context)]),
            Err(Error::FixedZeroCid)
        );
    });
}

#[path = "../../../tests/support/early_owner_fixture.rs"]
mod early_fixture;

#[test]
#[allow(long_running_const_eval)]
fn real_early_quarantine_path_preflight_credit_and_release_compose_under_par() {
    std::thread::Builder::new().stack_size(8*1024*1024).spawn(|| {
        use crate::roles::{connection_authority,early_owner as early,protocol_early};
        const PAYLOAD:&[u8]=&[0x1a,1,2,3,4,5,6,7,8];
        const GEN:u64=947;
        let mut evidence=early_fixture::evidence(GEN,PAYLOAD);
        let ready=connection_authority::verify_and_split(evidence.finished,early_fixture::CLIENT_PARAMETERS,crate::parameters::Peer::Client,&[],None,None).unwrap();
        let mut config=config(Role::Server);
        config.generation=GEN;
        config.local_cid=Destination::new(&[]).unwrap();
        config.bootstrap_destination=Destination::new(&[]).unwrap();
        config.now=1000;
        let mut paths=[const {PathSlot::empty()};PATHS];
        let mut local=[LocalCidSlot::EMPTY;LOCAL_CIDS];
        let mut peer=[PeerCidSlot::EMPTY;PEER_CIDS];
        let path_state=State::new(config,Resources {paths:&mut paths,local_cids:&mut local,peer_cids:&mut peer},Random {value:19,fail:false}).unwrap();
        let original=path_state.initial_path();
        let context=PathContext {address:config.initial,destination:Destination::new(&[]).unwrap(),datagram_id:1,datagram_bytes:1200,now:1000};
        let mut quarantine=[crate::early_data::QuarantineSlot::<16>::EMPTY];
        let mut controls=[early::ControlSlot::<32>::EMPTY];
        let early_state=early::State::<16,32,128>::new(crate::early_data::ServerPolicy::BufferedReplaySafeRequests {max_bytes:16,max_streams:1},evidence.grant,&mut quarantine,&mut controls).unwrap();
        let carrier=CarrierStorage::<1,16,64>::new();
        let mut slab=[0;65536];let mut storage=SessionKitStorage::uninit();let kit=storage.init();let sid=SessionId::new(u32::try_from(GEN).unwrap());
        let rv=kit.rendezvous(&mut slab,carrier.bind(sid).unwrap()).unwrap();
        let global=g::par(p::path_choreography::<30,31>(),protocol_early::early_choreography::<32,33>());
        let p30=project::<30,_>(&global);let p31=project::<31,_>(&global);let p32=project::<32,_>(&global);let p33=project::<33,_>(&global);
        let mut pclient=rv.enter(sid,&p30).unwrap();let mut powner=rv.enter(sid,&p31).unwrap();let mut eclient=rv.enter(sid,&p32).unwrap();let mut eowner=rv.enter(sid,&p33).unwrap();
        let mut pcq=[None];let mut prq=[None];let mut ecq=[None];let mut erq=[None];
        let pcq=Mailbox::new(&mut pcq).unwrap();let prq=Mailbox::new(&mut prq).unwrap();let ecq=Mailbox::new(&mut ecq).unwrap();let erq=Mailbox::new(&mut erq).unwrap();
        let(ptx,prx)=pcq.split().unwrap();let(prtx,prrx)=prq.split().unwrap();let(etx,erx)=ecq.split().unwrap();let(ertx,errx)=erq.split().unwrap();
        let mut pexchange=Exchange::new();let mut eexchange=early::Exchange::new();let arena=authority::Arena::<1,4>::new(GEN);
        let (receipt,packet)=super::test_auth::initial(GEN,&[],&[]);
        let initial_ticket=arena.admit(authority::ReceiveEvidence::Initial(receipt),packet.body()).unwrap();
        let initial_grant=arena.grant_initial_peer_cid(initial_ticket,packet.header()).unwrap();
        let workload=async {
            let mut path=Client::connect(ptx,prrx,GEN).await.unwrap();
            let mut early=early::Client::connect(etx,errx,GEN).await.unwrap();
            assert!(matches!(path.request(Command::LearnPeerCid(initial_grant)).await.unwrap(),Outcome::PeerCidLearned));
            arena.finish(initial_ticket).unwrap();
            let packet=early::AuthenticatedPacket::<128>::new(evidence.packets[0].take().unwrap(),PAYLOAD,context,original).unwrap();
            let early::Outcome::Check(check)=early.request(early::Command::Receive(packet)).await.unwrap()else{panic!("read-only path check")};
            let Outcome::EarlyChecked(checked)=path.request(Command::EarlyPreflight(check)).await.unwrap()else{panic!("path preflight")};
            assert_eq!(path.snapshot().paths[0].unwrap().1.received,0);
            assert_eq!(early.snapshot().admitted_packets,0);
            let early::Outcome::Admission(early::Admission::Admitted(admission))=early.request(early::Command::Checked(checked)).await.unwrap()else{panic!("admission")};
            assert!(matches!(path.request(Command::EarlyAdmission(admission)).await.unwrap(),Outcome::EarlyAdmitted {path} if path==original));
            let received=path.snapshot().paths[0].unwrap().1;
            assert_eq!((received.received,received.available_bytes),(1200,3600));
            assert!(!received.address_validated);
            assert!(matches!(path.request(Command::Handshake(ready.path)).await.unwrap(),Outcome::HandshakeInstalled { .. }));
            assert_eq!(path.snapshot().next_control_path,None,"deferred challenge applied before release");
            assert!(matches!(early.request(early::Command::Finish(ready.early)).await.unwrap(),early::Outcome::Ready));
            let early::Outcome::Release(Some(early::Release::Path(release)))=early.request(early::Command::Release).await.unwrap()else{panic!("bound path release")};
            assert_eq!(release.original_path(),original);
            assert_eq!(release.context(),context);
            let Outcome::EarlyReleased(completion)=path.request(Command::EarlyRelease(release)).await.unwrap()else{panic!("path effect")};
            assert!(matches!(early.request(early::Command::Settle(completion)).await.unwrap(),early::Outcome::Settled));
            assert_eq!(path.snapshot().next_control_path,Some(original));
            let Outcome::Reserved(pending)=path.request(Command::ReserveControl {path:original,bytes:1200,packet:PacketNumber {space:PacketNumberSpace::ApplicationData,value:1},now:1000}).await.unwrap()else{panic!("exact response reservation")};
            assert_eq!(pending.control(),Some(Control::Response([1,2,3,4,5,6,7,8])));
            assert_eq!(pending.address(),context.address);
            path.reject(pending).await.unwrap();
            assert!(matches!(early.request(early::Command::Release).await.unwrap(),early::Outcome::Release(None)));
            early.retire().await.unwrap();path.retire().await.unwrap();Ok(())
        };
        let early_service=async {early::run_borrowed(&mut eclient,&mut eowner,early_state,erx,ertx,&mut eexchange).await.unwrap();Ok(())};
        drive(runtime::join2(runtime::join2(run_borrowed(&mut pclient,&mut powner,path_state,&arena,prx,prtx,&mut pexchange),early_service),workload)).unwrap();
        assert!(pexchange.is_empty()&&eexchange.is_empty());assert_eq!(carrier.queued(),0);
    }).unwrap().join().unwrap();
}

fn initial_grant<const P: usize, const E: usize>(
    arena: &authority::Arena<P, E>,
    generation: u64,
    source: &[u8],
    destination: &[u8],
) -> (authority::PacketTicket, authority::InitialPeerCid) {
    let (receipt, packet) = super::test_auth::initial(generation, source, destination);
    let ticket = arena
        .admit(authority::ReceiveEvidence::Initial(receipt), packet.body())
        .unwrap();
    let grant = arena
        .grant_initial_peer_cid(ticket, packet.header())
        .unwrap();
    (ticket, grant)
}
#[test]
fn bootstrap_destination_is_distinct_from_learned_zero_peer_scid() {
    let mut config = config(Role::Client);
    config.bootstrap_destination = Destination::new(b"bootstrap").unwrap();
    with_unlearned_state(config, |state| {
        assert_eq!(
            state.destination(state.original).unwrap().0.as_bytes(),
            b"bootstrap"
        );
        assert!(!state.zero_peer);
        let arena = authority::Arena::<2, 4>::new(GENERATION);
        let (ticket, grant) = initial_grant(&arena, GENERATION, &[], b"serverid");
        state.learn_peer_cid(&arena, grant).unwrap();
        assert_eq!(state.destination(state.original).unwrap().0.as_bytes(), b"");
        assert!(state.zero_peer);
        arena.finish(ticket).unwrap();
        let (ticket, conflict) = initial_grant(&arena, GENERATION, b"changed1", b"serverid");
        assert_eq!(
            state.learn_peer_cid(&arena, conflict),
            Err(Error::PeerCidMismatch)
        );
        assert!(state.zero_peer);
        arena.finish(ticket).unwrap();
    });
}
#[test]
fn cancelled_initial_learning_grant_cannot_reopen_a_reused_arena_slot() {
    with_unlearned_state(config(Role::Client), |state| {
        let arena = authority::Arena::<1, 2>::new(GENERATION);
        let (old, stale) = initial_grant(&arena, GENERATION, b"oldpeer1", b"serverid");
        assert!(matches!(
            arena.finish(old),
            Err(authority::Error::OutstandingEffects)
        ));
        arena.cancel(old).unwrap();
        let (current, fresh) = initial_grant(&arena, GENERATION, b"newpeer2", b"serverid");
        assert!(matches!(
            state.learn_peer_cid(&arena, stale),
            Err(Error::Authority(authority::Error::InvalidGrant))
        ));
        assert!(state.learned_peer_initial.is_none());
        state.learn_peer_cid(&arena, fresh).unwrap();
        assert_eq!(state.learned_peer_initial.unwrap().as_bytes(), b"newpeer2");
        arena.finish(current).unwrap();
    });
}
#[test]
fn source_learning_rejects_substituted_header_and_wrong_client_destination() {
    with_unlearned_state(config(Role::Client), |state| {
        let arena = authority::Arena::<2, 4>::new(GENERATION);
        let (receipt, packet) = super::test_auth::initial(GENERATION, b"clientid", b"serverid");
        let ticket = arena
            .admit(authority::ReceiveEvidence::Initial(receipt), packet.body())
            .unwrap();
        let mut changed = [0; 64];
        changed[..packet.header().len()].copy_from_slice(packet.header());
        changed[7] ^= 1;
        assert!(matches!(
            arena.grant_initial_peer_cid(ticket, &changed[..packet.header().len()]),
            Err(authority::Error::InvalidFrame)
        ));
        let grant = arena
            .grant_initial_peer_cid(ticket, packet.header())
            .unwrap();
        assert!(matches!(
            arena.grant_initial_peer_cid(ticket, packet.header()),
            Err(authority::Error::InvalidFrame)
        ));
        state.learn_peer_cid(&arena, grant).unwrap();
        arena.finish(ticket).unwrap();
        let (ticket, wrong) = initial_grant(&arena, GENERATION, b"clientid", b"wrongcid");
        assert_eq!(
            state.learn_peer_cid(&arena, wrong),
            Err(Error::WrongDestination)
        );
        arena.finish(ticket).unwrap();
    });
}
#[test]
fn server_retains_integrity_checked_original_dcid_for_initial_and_early_only() {
    with_unlearned_state(config(Role::Server), |state| {
        let arena = authority::Arena::<1, 2>::new(GENERATION);
        let (ticket, grant) = initial_grant(&arena, GENERATION, b"clientid", b"original");
        state.learn_peer_cid(&arena, grant).unwrap();
        arena.finish(ticket).unwrap();
        let mut incoming = context(1, address(5000));
        incoming.destination = Destination::new(b"original").unwrap();
        assert_eq!(
            state
                .ingress_packet(incoming, None, IngressKind::Initial)
                .unwrap(),
            state.original
        );
        assert!(
            state
                .preflight_early_network(state.original, incoming, 2, [])
                .is_ok()
        );
        assert_eq!(
            state.ingress_packet(incoming, None, IngressKind::Ordinary),
            Err(Error::WrongDestination)
        );
        assert_eq!(state.paths.snapshot(state.original).unwrap().received, 1200);
    });
}
fn retry_grant(
    generation: u64,
    original: &[u8],
    local: &[u8],
    source: &[u8],
) -> authority::RetryPeerCid {
    let mut client = crate::retry::ClientRetry::<64>::new(original, local).unwrap();
    let mut bytes = [0; 128];
    let mut scratch = [0; 256];
    let len = crate::retry::encode_retry(
        original,
        local,
        source,
        b"token",
        0,
        &mut bytes,
        &mut scratch,
    )
    .unwrap();
    let checked = client.validate(&bytes[..len], &mut scratch).unwrap();
    authority::RetryPeerCid::from_committed(
        generation,
        client.commit_with_receipt(checked).unwrap(),
    )
}
#[test]
fn retry_changes_only_bootstrap_destination_and_is_once_only_before_peer_initial() {
    with_unlearned_state(config(Role::Client), |state| {
        let original = state.config.bootstrap_destination;
        state
            .apply_retry(retry_grant(
                GENERATION,
                original.as_bytes(),
                b"serverid",
                b"retrycid",
            ))
            .unwrap();
        assert_eq!(
            state.destination(state.original).unwrap().0.as_bytes(),
            b"retrycid"
        );
        assert!(state.learned_peer_initial.is_none());
        assert_eq!(
            state.apply_retry(retry_grant(
                GENERATION,
                original.as_bytes(),
                b"serverid",
                b"retrytwo"
            )),
            Err(Error::RetryNotAllowed)
        );
    });
    with_state(config(Role::Client), |state| {
        assert_eq!(
            state.apply_retry(retry_grant(
                GENERATION,
                b"clientid",
                b"serverid",
                b"retrycid"
            )),
            Err(Error::RetryNotAllowed)
        );
    });
}
#[test]
fn retry_proof_must_match_this_connection_and_role() {
    with_unlearned_state(config(Role::Client), |state| {
        assert_eq!(
            state.apply_retry(retry_grant(
                GENERATION,
                b"otherone",
                b"serverid",
                b"retrycid"
            )),
            Err(Error::WrongDestination)
        );
        assert_eq!(
            state.apply_retry(retry_grant(
                GENERATION + 1,
                b"clientid",
                b"serverid",
                b"retrycid"
            )),
            Err(Error::WrongGeneration)
        );
        assert!(!state.retry_seen);
    });
    with_unlearned_state(config(Role::Server), |state| {
        assert_eq!(
            state.apply_retry(retry_grant(
                GENERATION,
                b"clientid",
                b"serverid",
                b"retrycid"
            )),
            Err(Error::RetryNotAllowed)
        );
    });
}

/// The test bridge receives proof from an actual current validation timeout.
/// The live Path owner remains borrowed until the callback completes.
pub(crate) fn with_abandonment<T>(
    generation: u64,
    body: impl FnOnce(
        PathAbandoned,
        &mut dyn FnMut(
            super::super::recovery_owner::PathLostPacket,
        ) -> super::super::recovery_owner::PathLossSettled,
    ) -> T,
) -> T {
    let mut cfg = config(Role::Client);
    cfg.generation = generation;
    with_unlearned_state(cfg, |state| {
        state.paths.handshake_validated(state.original).unwrap();
        state
            .migration
            .validated(state.original, &state.paths)
            .unwrap();
        let failed = state
            .paths
            .insert(address(6000), InitialValidation::Unvalidated, 0)
            .unwrap();
        state.timeout(state.timer().unwrap(), 300).unwrap();
        let Outcome::AbandonmentRequired(grant) = state.abandonment_outcome().unwrap() else {
            panic!("missing timeout proof")
        };
        assert_eq!(grant.path(), failed);
        body(grant, &mut |loss| {
            state
                .lost(loss)
                .unwrap()
                .expect("abandonment loss settlement")
        })
    })
}

#[test]
fn abandonment_keeps_slot_and_blocks_send_until_recovery_settlement() {
    use super::super::recovery_owner::tests::complete_empty_abandonment;
    with_state(config(Role::Client), |state| {
        install(state);
        let old = state
            .paths
            .insert(address(6000), InitialValidation::Unvalidated, 0)
            .unwrap();
        state.timeout(state.timer().unwrap(), 300).unwrap();
        assert!(state.paths.snapshot(old).unwrap().failed);
        assert!(matches!(
            state.reserve(descriptor(3), state.original, 20, number(3), false, 300),
            Err(Error::AbandonmentPending)
        ));
        assert!(matches!(
            state
                .paths
                .insert(address(7000), InitialValidation::Unvalidated, 300),
            Err(path::Error::Capacity)
        ));
        let Outcome::AbandonmentRequired(grant) = state.abandonment_outcome().unwrap() else {
            panic!("proof")
        };
        let completion = complete_empty_abandonment(grant);
        assert!(matches!(
            state.finish_abandonment(completion).unwrap(),
            Outcome::Expired { .. }
        ));
        assert!(matches!(
            state.paths.snapshot(old),
            Err(path::Error::StalePath)
        ));
        let next = state
            .paths
            .insert(address(7000), InitialValidation::Unvalidated, 300)
            .unwrap();
        assert_eq!(old.slot, next.slot);
        assert_ne!(old.path_generation, next.path_generation);
    });
}

#[test]
fn abandonment_rejects_cross_generation_and_stale_completion_without_cleanup() {
    use super::super::recovery_owner::tests::complete_empty_abandonment;
    let wrong = with_abandonment(GENERATION + 1, |grant, _| complete_empty_abandonment(grant));
    with_state(config(Role::Client), |state| {
        install(state);
        let old = state
            .paths
            .insert(address(6000), InitialValidation::Unvalidated, 0)
            .unwrap();
        state.timeout(state.timer().unwrap(), 300).unwrap();
        assert!(matches!(
            state.finish_abandonment(wrong),
            Err(Error::InvalidDescriptor)
        ));
        assert!(state.paths.snapshot(old).is_ok());
        let Outcome::AbandonmentRequired(grant) = state.abandonment_outcome().unwrap() else {
            panic!("proof")
        };
        let stale = PathAbandoned {
            generation: grant.generation,
            path: grant.path,
            serial: grant.serial + 1,
        };
        let stale = complete_empty_abandonment(stale);
        assert!(matches!(
            state.finish_abandonment(stale),
            Err(Error::InvalidDescriptor)
        ));
        assert!(state.paths.snapshot(old).is_ok());
        state
            .finish_abandonment(complete_empty_abandonment(grant))
            .unwrap();
        assert!(state.paths.snapshot(old).is_err());
    });
}

#[test]
fn reclaimed_ingress_waits_for_cleanup_then_resumes_owned_authenticated_frame() {
    use super::super::recovery_owner::tests::complete_empty_abandonment;
    let (evidence, ready) = super::test_auth::authenticated(GENERATION, &[1], 10);
    let arena = authority::Arena::<1, 2>::new(GENERATION);
    let ticket = arena.admit(evidence, &[1]).unwrap();
    with_state(config(Role::Server), |state| {
        state.handshake(ready).unwrap();
        let discarded = state
            .paths
            .insert(address(6000), InitialValidation::Unvalidated, 0)
            .unwrap();
        let received = context(1, address(7000));
        arena.bind_path_context(ticket, received).unwrap();
        let grant = arena
            .grant_path(
                ticket,
                0,
                PathFrame::PacketProcessed { non_probing: true },
                received,
            )
            .unwrap();
        let Outcome::AbandonmentRequired(grant) = state.frame(&arena, grant).unwrap() else {
            panic!("reclaim must wait")
        };
        assert_eq!(grant.path(), discarded);
        assert!(state.paths.find(received.address).is_none());
        assert!(state.paths.snapshot(discarded).is_ok());
        let Outcome::Frame { path, .. } = state
            .finish_abandonment(complete_empty_abandonment(grant))
            .unwrap()
        else {
            panic!("retained frame resumes")
        };
        assert_eq!(
            state.paths.snapshot(path).unwrap().address,
            received.address
        );
        assert_eq!(state.paths.snapshot(path).unwrap().received, 1200);
        assert!(state.paths.snapshot(discarded).is_err());
        assert_ne!(path.path_generation, discarded.path_generation);
    });
    arena.finish(ticket).unwrap();
}

pub(crate) fn repeated_abandonments(
    generation: u64,
    count: usize,
    mut body: impl FnMut(
        PathAbandoned,
        &mut dyn FnMut(
            super::super::recovery_owner::PathLostPacket,
        ) -> super::super::recovery_owner::PathLossSettled,
    ) -> super::super::recovery_owner::AbandonmentComplete,
) {
    let mut cfg = config(Role::Client);
    cfg.generation = generation;
    with_unlearned_state(cfg, |state| {
        state.paths.handshake_validated(state.original).unwrap();
        state
            .migration
            .validated(state.original, &state.paths)
            .unwrap();
        for index in 0..count {
            state
                .paths
                .insert(
                    address(6000 + index as u16),
                    InitialValidation::Unvalidated,
                    state.now,
                )
                .unwrap();
            let deadline = state.timer().unwrap().deadline();
            state.timeout(state.timer().unwrap(), deadline).unwrap();
            let Outcome::AbandonmentRequired(grant) = state.abandonment_outcome().unwrap() else {
                panic!("timeout proof")
            };
            let completion = body(grant, &mut |loss| state.lost(loss).unwrap().unwrap());
            state.finish_abandonment(completion).unwrap();
        }
    });
}

#[test]
fn cleanup_capacity_preflight_keeps_path_binding_and_retirement_state_unchanged() {
    with_state(config(Role::Client), |state| {
        install(state);
        let path = state
            .paths
            .insert(address(6000), InitialValidation::Unvalidated, 0)
            .unwrap();
        let peer = state.peer.as_mut().unwrap();
        let handle = peer
            .accept_new_authenticated(
                1,
                0,
                Cid::new(b"othercid").unwrap(),
                ResetToken::new([7; 16]),
            )
            .unwrap()
            .handle;
        state.bindings[usize::from(path.slot)] = Some(handle);
        let blocker = ControlRecord {
            kind: ReliableControl::Advertise(state.local_initial.unwrap()),
            ready: true,
            acknowledged: false,
            sent: [None; 4],
            lost: [false; 4],
        };
        state.controls.fill(Some(blocker));
        assert_eq!(
            state.begin_abandonment(path, AbandonResume::Retire),
            Err(Error::Capacity)
        );
        assert!(state.paths.snapshot(path).is_ok());
        assert_eq!(state.bindings[usize::from(path.slot)], Some(handle));
        assert!(state.peer.as_ref().unwrap().get(handle).is_ok());
        assert!(state.abandonment.is_none());
    });
}

fn server_retry_token(
    remote: Address,
    original: &[u8],
    retry: &[u8],
    client: &[u8],
) -> crate::retry::ValidatedToken {
    let address = match remote.remote {
        core::net::SocketAddr::V4(a) => crate::retry::ClientAddress::V4 {
            ip: a.ip().octets(),
            port: a.port(),
        },
        core::net::SocketAddr::V6(a) => crate::retry::ClientAddress::V6 {
            ip: a.ip().octets(),
            port: a.port(),
        },
    };
    let mut rng = Random {
        value: 881,
        fail: false,
    };
    let mut tokens = crate::retry::RetryTokens::<1>::generate(&mut rng, 3, 1000).unwrap();
    let mut bytes = [0; crate::retry::TOKEN_LEN];
    tokens
        .issue(
            0,
            crate::retry::TokenContext {
                original_destination_id: original,
                retry_source_id: retry,
                client_source_id: client,
                address,
            },
            &mut bytes,
        )
        .unwrap();
    let token = tokens.validate(1, address, retry, client, &bytes).unwrap();
    assert_eq!(token.address(), address);
    token
}

#[test]
fn actual_server_retry_admission_releases_only_address_amplification_once() {
    with_unlearned_state(config(Role::Server), |state| {
        let before = state.paths.snapshot(state.original).unwrap();
        assert!(!before.address_validated && !before.mtu_validated);
        state
            .server_retry(server_retry_token(
                address(5000),
                b"clientid",
                b"serverid",
                b"clientid",
            ))
            .unwrap();
        let after = state.paths.snapshot(state.original).unwrap();
        assert!(after.address_validated);
        assert!(after.available_bytes >= 1200);
        assert!(!after.mtu_validated);
        assert!(!state.confirmed && !state.installed);
        assert!(state.tls_confirmation.is_none());
        assert!(state.learned_peer_initial.is_none());
        assert!(state.initial_received_destination.is_none());
        assert_eq!(
            state.server_retry(server_retry_token(
                address(5000),
                b"clientid",
                b"serverid",
                b"clientid"
            )),
            Err(Error::RetryNotAllowed)
        );
        learn(state);
        assert_eq!(
            state.learned_peer_initial,
            Some(Destination::new(b"clientid").unwrap())
        );
    });
}

#[test]
fn server_retry_wrong_peer_address_and_connection_substitution_are_rejected_before_validation() {
    with_unlearned_state(config(Role::Server), |state| {
        assert_eq!(
            state.server_retry(server_retry_token(
                address(6000),
                b"clientid",
                b"serverid",
                b"clientid"
            )),
            Err(Error::WrongDestination)
        );
        assert_eq!(
            state.server_retry(server_retry_token(
                address(5000),
                b"other-id",
                b"serverid",
                b"clientid"
            )),
            Err(Error::WrongDestination)
        );
        let path = state.paths.snapshot(state.original).unwrap();
        assert!(!path.address_validated && !path.mtu_validated);
        assert_eq!(path.available_bytes, 0);
        assert!(state.server_retry.is_none());
    });
    with_unlearned_state(config(Role::Client), |state| {
        assert_eq!(
            state.server_retry(server_retry_token(
                address(5000),
                b"clientid",
                b"serverid",
                b"clientid"
            )),
            Err(Error::RetryNotAllowed)
        );
    });
}

#[test]
fn retry_admission_requires_actual_initial_source_and_destination_to_match_token() {
    for (source, destination) in [
        (b"evilpeer".as_slice(), b"serverid".as_slice()),
        (b"clientid".as_slice(), b"othercid".as_slice()),
    ] {
        with_unlearned_state(config(Role::Server), |state| {
            state
                .server_retry(server_retry_token(
                    address(5000),
                    b"clientid",
                    b"serverid",
                    b"clientid",
                ))
                .unwrap();
            let (receipt, packet) = super::test_auth::initial(GENERATION, source, destination);
            let arena = authority::Arena::<1, 2>::new(GENERATION);
            let ticket = arena
                .admit(authority::ReceiveEvidence::Initial(receipt), packet.body())
                .unwrap();
            let grant = arena
                .grant_initial_peer_cid(ticket, packet.header())
                .unwrap();
            assert_eq!(
                state.learn_peer_cid(&arena, grant),
                Err(Error::PeerCidMismatch)
            );
            assert!(state.learned_peer_initial.is_none());
            assert!(state.initial_received_destination.is_none());
            assert!(!state.paths.snapshot(state.original).unwrap().mtu_validated);
            arena.finish(ticket).unwrap();
        });
    }
}

#[test]
fn owned_recovery_pto_only_extends_validation_and_revokes_old_timer_observations() {
    use super::super::recovery_owner::tests::probe_timeout_for_test;
    with_unlearned_state(config(Role::Client), |state| {
        let arena = authority::Arena::<1, 1>::new(GENERATION);
        let old = state.timer().unwrap();
        let old_deadline = old.deadline();
        let grant = probe_timeout_for_test(GENERATION, 1000);
        let pto = grant.pto_us();
        assert!(matches!(
            state
                .execute(
                    p::PROBE_TIMEOUT,
                    descriptor(1),
                    Command::ProbeTimeout(grant),
                    &arena
                )
                .unwrap(),
            Outcome::ProbeTimeoutUpdated
        ));
        let extended = state.timer().unwrap().deadline();
        assert!(extended > old_deadline);
        assert_eq!(extended, pto * 3);
        assert_eq!(state.timeout(old, old_deadline), Err(Error::StaleTimer));
        let before = state.timer().unwrap();
        let shorter = probe_timeout_for_test(GENERATION, 1);
        assert!(matches!(
            state
                .execute(
                    p::PROBE_TIMEOUT,
                    descriptor(2),
                    Command::ProbeTimeout(shorter),
                    &arena
                )
                .unwrap(),
            Outcome::ProbeTimeoutUpdated
        ));
        assert_eq!(state.timer().unwrap().deadline(), extended);
        assert_eq!(state.timeout(before, extended), Err(Error::StaleTimer));
        let wrong = probe_timeout_for_test(GENERATION + 1, 10000);
        assert!(matches!(
            state
                .execute(
                    p::PROBE_TIMEOUT,
                    descriptor(3),
                    Command::ProbeTimeout(wrong),
                    &arena
                )
                .unwrap(),
            Outcome::Rejected(Error::WrongGeneration)
        ));
        assert_eq!(state.timer().unwrap().deadline(), extended);
        let path = state.paths.snapshot(state.original).unwrap();
        assert!(!path.address_validated && !path.mtu_validated);
        assert!(!state.installed && !state.confirmed);
    });
}

#[path = "preferred_tests.rs"]
mod preferred;
