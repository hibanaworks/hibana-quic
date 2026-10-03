//! Real certificate-authenticated BoundedTls providers owned by projected roles.
//! This qualifies the local actor boundary, not QUIC/network interoperability.
// The bounded, composed two-provider choreography exceeds the default const
// evaluator time lint while producing its four projected role programs.

#[path = "../../../tests/support/tls_actor_fixture.rs"]
mod fixture;

use core::{
    cell::Cell,
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use fixture::{Buffers, TestRandom};
// Actual CID-bound parameters are required by Finished -> Path authority.
const CLIENT_PARAMS: &[u8] = &[
    15, 8, b'c', b'l', b'i', b'e', b'n', b't', b'i', b'd', 4, 1, 42,
];
const SERVER_PARAMS: &[u8] = &[
    0, 8, b's', b'e', b'r', b'v', b'e', b'r', b'i', b'd', 15, 8, b's', b'e', b'r', b'v', b'e',
    b'r', b'i', b'd', 4, 1, 63,
];
const OLD_PAYLOAD: &[u8] = &[1; 24];
const UPDATED_PAYLOAD: &[u8] = &[1; 16];
use crate::roles::{
    connection_authority, path_owner::tls_authority_fixture as path_evidence,
    recovery_owner::tls_authority_fixture::Ledger,
};
use hibana::{
    Endpoint, g,
    runtime::{SessionKitStorage, ids::SessionId, program::project},
};
use hibana_quic::{
    bounded_tls::{BoundedTls, ClientConfig, ServerConfig},
    carrier::CarrierStorage,
    crypto,
    mailbox::Mailbox,
    roles::{
        packet_protection::Packet,
        protocol_tls::tls_choreography,
        tls_owner::{self, Command, Exchange, Reply},
    },
    runtime::join2,
    tls::{self, Level, Provider},
    tls_certificate::{CertificateDer, Limits, trust_anchor_from_der},
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::Wake,
};

type Client<'c, 's> = tls_owner::Client<'c, 's, 1536, 32, 1, 1>;

// The same thread-local allocation counter used by the integration suite lives
// in a dev-only helper because the production crate forbids unsafe code.
#[global_allocator]
static ALLOCATOR: actor_test_allocator::Counting = actor_test_allocator::Counting;
use actor_test_allocator::NoAlloc;

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
    for _ in 0..65536 {
        let before = count.0.load(Ordering::SeqCst);
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => return output,
            Poll::Pending => assert!(
                count.0.load(Ordering::SeqCst) > before,
                "actors parked without an expected wake"
            ),
        }
    }
    panic!("bounded actor scenario did not terminate")
}
fn with_two_pairs<R>(
    body: impl for<'r> FnOnce(
        Endpoint<'r, 24>,
        Endpoint<'r, 25>,
        Endpoint<'r, 26>,
        Endpoint<'r, 27>,
        &CarrierStorage<1, 16, 64>,
    ) -> R,
) -> R {
    let carrier = CarrierStorage::<1, 16, 64>::new();
    let mut slab = [0; 64 * 1024];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init();
    let sid = SessionId::new(91);
    let rv = kit
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    let global = g::par(tls_choreography::<24, 25>(), tls_choreography::<26, 27>());
    let p24 = project::<24, _>(&global);
    let p25 = project::<25, _>(&global);
    let p26 = project::<26, _>(&global);
    let p27 = project::<27, _>(&global);
    body(
        rv.enter(sid, &p24).unwrap(),
        rv.enter(sid, &p25).unwrap(),
        rv.enter(sid, &p26).unwrap(),
        rv.enter(sid, &p27).unwrap(),
        &carrier,
    )
}
async fn drain(from: &mut Client<'_, '_>, to: &mut Client<'_, '_>, fragment: usize) -> bool {
    let mut progressed = false;
    for _ in 0..8192 {
        let Some((level, bytes)) = from.take_crypto_flight(fragment).await.unwrap().unwrap() else {
            return progressed;
        };
        assert!(!bytes.as_bytes().is_empty());
        for fragment in bytes.as_bytes().chunks(fragment) {
            to.receive_crypto(level, fragment).await.unwrap().unwrap();
        }
        progressed = true;
    }
    panic!("unbounded CRYPTO output")
}
async fn handshake(client: &mut Client<'_, '_>, server: &mut Client<'_, '_>, fragment: usize) {
    for _ in 0..16 {
        let c = drain(client, server, fragment).await;
        let s = drain(server, client, fragment).await;
        if !c && !s {
            assert!(!client.snapshot().handshaking);
            assert!(!server.snapshot().handshaking);
            return;
        }
    }
    panic!("real TLS handshake did not finish")
}
fn packet(pn: u64, text: &[u8]) -> Packet<1536> {
    phase_packet(pn, false, text)
}
fn phase_packet(pn: u64, phase: bool, text: &[u8]) -> Packet<1536> {
    let mut header = *b"\x40serverid\x00";
    header[0] = if phase { 0x44 } else { 0x40 };
    header[9] = u8::try_from(pn).unwrap();
    Packet::new(pn, &header, text).unwrap()
}
fn response_packet(pn: u64, phase: bool, text: &[u8]) -> Packet<1536> {
    let mut header = *b"\x40clientid\x00";
    header[0] = if phase { 0x44 } else { 0x40 };
    header[9] = u8::try_from(pn).unwrap();
    Packet::new(pn, &header, text).unwrap()
}
fn copied(source: &Packet<1536>) -> Packet<1536> {
    Packet::new(source.packet_number(), source.header(), source.body()).unwrap()
}
fn corrupt(source: &Packet<1536>) -> Packet<1536> {
    let mut bytes = [0; 1536];
    let n = source.body().len();
    bytes[..n].copy_from_slice(source.body());
    bytes[n - 1] ^= 1;
    Packet::new(source.packet_number(), source.header(), &bytes[..n]).unwrap()
}

async fn packet_mask(
    client: &mut Client<'_, '_>,
    sealed: &crate::roles::sealed_packet::SealedPacket<1536>,
) -> [u8; 5] {
    let offset = sealed.header().len() - 1;
    let mut sample = [0; 16];
    sample.copy_from_slice(&sealed.bytes()[offset + 4..offset + 20]);
    client
        .header_mask(Level::OneRtt, true, sample)
        .await
        .unwrap()
        .unwrap()
}

async fn handshake_packet(sender: &mut Client<'_, '_>, receiver: &mut Client<'_, '_>) {
    let sealed = sender
        .seal_handshake(packet(7, b"real handshake keys"))
        .await
        .unwrap()
        .unwrap();
    assert_ne!(sealed.body(), b"real handshake keys");
    assert!(matches!(
        receiver.open_handshake(corrupt(&sealed)).await.unwrap(),
        Err(tls::Error::Authentication)
    ));
    let opened = receiver
        .open_handshake(copied(&sealed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(opened.packet.body(), b"real handshake keys");
    assert_eq!(opened.receipt.level(), Level::Handshake);
    assert_eq!(opened.receipt.packet_number(), 7);
    assert!(matches!(
        sender
            .seal_handshake(packet(7, b"nonce reuse"))
            .await
            .unwrap(),
        Err(tls::Error::PacketNumberReuse)
    ));
    let local = sender
        .header_mask(Level::Handshake, true, [7; 16])
        .await
        .unwrap()
        .unwrap();
    let remote = receiver
        .header_mask(Level::Handshake, false, [7; 16])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(local, remote);
}

async fn packets_and_updates(
    client: &mut Client<'_, '_>,
    server: &mut Client<'_, '_>,
    client_initial: (crate::roles::packet_protection::OpenReceipt, Packet<128>),
    server_initial: (crate::roles::packet_protection::OpenReceipt, Packet<128>),
) {
    let original = *client.snapshot();
    assert!(original.handshake_keys && original.one_rtt_keys);
    assert!(!original.early_keys);
    assert_eq!(original.peer_parameters(), Some(SERVER_PARAMS));
    assert_eq!(server.snapshot().peer_parameters(), Some(CLIENT_PARAMS));
    assert_eq!(original.negotiated_group, Some(0x001d));
    assert_eq!(
        (
            original.send_generation,
            original.receive_generation,
            original.key_phase
        ),
        (0, 0, false)
    );
    let initial_header_mask = client
        .header_mask(Level::OneRtt, true, [9; 16])
        .await
        .unwrap()
        .unwrap();
    handshake_packet(client, server).await;
    handshake_packet(server, client).await;
    // Each role receives a distinct affine permission from real Path policy.
    let client_ready = connection_authority::verify_and_split(
        client.take_finished_receipt().unwrap(),
        SERVER_PARAMS,
        crate::parameters::Peer::Server,
        b"serverid",
        Some(b"serverid"),
        None,
    )
    .unwrap()
    .path;
    let server_ready = connection_authority::verify_and_split(
        server.take_finished_receipt().unwrap(),
        CLIENT_PARAMS,
        crate::parameters::Peer::Client,
        b"clientid",
        None,
        None,
    )
    .unwrap()
    .path;
    let done = server
        .seal_one_rtt(response_packet(0, false, &[0x1e]))
        .await
        .unwrap()
        .unwrap();
    let done = client
        .open_one_rtt(copied(&done), false, 0, 10)
        .await
        .unwrap()
        .unwrap();
    let client_confirmation = path_evidence::confirmation(
        client_ready,
        client_initial,
        Some((done.receipt, done.packet)),
    );
    let server_confirmation = path_evidence::confirmation(server_ready, server_initial, None);
    client
        .confirm_handshake(client_confirmation)
        .await
        .unwrap()
        .unwrap();
    server
        .confirm_handshake(server_confirmation)
        .await
        .unwrap()
        .unwrap();
    let mut ledger = Ledger::new(9);
    client.maintain_keys(0, 10).await.unwrap().unwrap();
    server.maintain_keys(0, 10).await.unwrap().unwrap();
    assert_eq!(
        client.initiate_key_update(0, 10).await.unwrap(),
        Err(tls::Error::KeyUpdateNotAllowed)
    );
    assert!(matches!(
        client
            .seal_one_rtt(phase_packet(0, true, b"incorrect outgoing phase"))
            .await
            .unwrap(),
        Err(tls::Error::InvalidInput)
    ));
    let old = client
        .seal_one_rtt(packet(0, OLD_PAYLOAD))
        .await
        .unwrap()
        .unwrap();
    let old_copy = copied(&old);
    let wire = copied(&old);
    let sent = ledger.reserve(old.bytes().len());
    assert_eq!(sent.packet().value, 0);
    let mask = packet_mask(client, &old).await;
    ledger.complete(path_evidence::submit(sent, old, OLD_PAYLOAD, mask, 0).await);
    let initial = server
        .open_one_rtt(copied(&wire), false, 0, 10)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(initial.packet.body(), OLD_PAYLOAD);
    assert_eq!((initial.generation, initial.key_updated), (0, false));
    let response = server
        .seal_one_rtt(response_packet(20, false, &[2, 1, 0, 0, 0, 2, 0, 0, 0, 0]))
        .await
        .unwrap()
        .unwrap();
    let response = client
        .open_one_rtt(copied(&response), false, 0, 10)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.generation, 0);
    let ack = ledger
        .ack(response.receipt, response.packet.body(), 0, Some(1), 0)
        .unwrap()
        .unwrap();
    assert_eq!(ack.sent_packet_number(), 0);
    assert_eq!(ack.received_key_generation(), response.generation);
    // Invalid PN/generation probes run at the Provider seam in this exact
    // actor-owned state; only this genuine Recovery grant enters the actor.
    client
        .acknowledge_one_rtt(ack, 0, 10)
        .await
        .unwrap()
        .unwrap();
    client.initiate_key_update(0, 10).await.unwrap().unwrap();
    assert_eq!(
        (
            client.snapshot().send_generation,
            client.snapshot().receive_generation
        ),
        (1, 0)
    );
    assert!(client.snapshot().key_phase);
    let updated = client
        .seal_one_rtt(phase_packet(1, true, UPDATED_PAYLOAD))
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        server
            .open_one_rtt(corrupt(&updated), true, 1, 10)
            .await
            .unwrap(),
        Err(tls::Error::Authentication)
    ));
    assert_eq!(
        (
            server.snapshot().send_generation,
            server.snapshot().receive_generation
        ),
        (0, 0)
    );
    let opened = server
        .open_one_rtt(copied(&updated), true, 1, 10)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(opened.packet.body(), UPDATED_PAYLOAD);
    assert_eq!((opened.generation, opened.key_updated), (1, true));
    let sent = ledger.reserve(updated.bytes().len());
    assert_eq!(sent.packet().value, 1);
    let mask = packet_mask(client, &updated).await;
    ledger.complete(path_evidence::submit(sent, updated, UPDATED_PAYLOAD, mask, 1).await);
    assert_eq!(
        (
            server.snapshot().send_generation,
            server.snapshot().receive_generation
        ),
        (1, 1)
    );
    let response = server
        .seal_one_rtt(response_packet(21, true, &[2, 1, 0, 0, 0]))
        .await
        .unwrap()
        .unwrap();
    let opened = client
        .open_one_rtt(copied(&response), true, 1, 10)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((opened.generation, opened.key_updated), (1, true));
    assert_eq!(
        (
            client.snapshot().send_generation,
            client.snapshot().receive_generation
        ),
        (1, 1)
    );
    let delayed = server
        .open_one_rtt(copied(&wire), false, 30, 10)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((delayed.generation, delayed.key_updated), (0, false));
    assert_eq!(delayed.packet.body(), OLD_PAYLOAD);
    server.maintain_keys(31, 10).await.unwrap().unwrap();
    assert!(matches!(
        server.open_one_rtt(old_copy, false, 31, 10).await.unwrap(),
        Err(tls::Error::Authentication)
    ));
    let ack = ledger
        .ack(opened.receipt, opened.packet.body(), 1, None, 1)
        .unwrap()
        .unwrap();
    assert_eq!(ack.received_key_generation(), opened.generation);
    client
        .acknowledge_one_rtt(ack, 1, 10)
        .await
        .unwrap()
        .unwrap();
    client.maintain_keys(30, 10).await.unwrap().unwrap();
    assert_eq!(
        client.initiate_key_update(30, 10).await.unwrap(),
        Err(tls::Error::KeyUpdateNotAllowed)
    );
    client.maintain_keys(31, 10).await.unwrap().unwrap();
    client.initiate_key_update(31, 10).await.unwrap().unwrap();
    assert_eq!(
        (
            client.snapshot().send_generation,
            client.snapshot().receive_generation
        ),
        (2, 1)
    );
    assert!(!client.snapshot().key_phase);
    let phase_wrapped = client
        .seal_one_rtt(packet(2, b"phase bit wrapped"))
        .await
        .unwrap()
        .unwrap();
    let wrapped = server
        .open_one_rtt(copied(&phase_wrapped), false, 31, 10)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((wrapped.generation, wrapped.key_updated), (2, true));
    assert_eq!(wrapped.packet.body(), b"phase bit wrapped");
    assert_eq!(
        client.maintain_keys(30, 10).await.unwrap(),
        Err(tls::Error::InvalidInput)
    );
    assert_eq!(
        client.maintain_keys(31, 0).await.unwrap(),
        Err(tls::Error::InvalidInput)
    );
    assert!(matches!(
        client
            .seal_one_rtt(packet(1, b"nonce reuse across update"))
            .await
            .unwrap(),
        Err(tls::Error::PacketNumberReuse)
    ));
    let local = client
        .header_mask(Level::OneRtt, true, [9; 16])
        .await
        .unwrap()
        .unwrap();
    let remote = server
        .header_mask(Level::OneRtt, false, [9; 16])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        local, remote,
        "header protection keys stay stable across updates"
    );
    assert_eq!(local, initial_header_mask);
    client.discard_handshake().await.unwrap().unwrap();
    assert!(!client.snapshot().handshake_keys);
    assert!(client.snapshot().one_rtt_keys);
    // The immediate discard hook preserves both exact KeysUnavailable
    // negatives. Application-phase actor rejection is tested separately.
    assert_eq!(
        original.send_generation, 0,
        "snapshots are copied observations"
    );
    assert!(original.handshake_keys);
    assert_eq!(original.peer_parameters(), Some(SERVER_PARAMS));
}

#[test]
fn real_full_handshake_packets_metadata_and_key_updates_allocate_zero() {
    large_stack(|| full_handshake_with_fragments(&[900]));
}

#[test]
fn fragmented_full_handshake_packets_and_key_updates_allocate_zero() {
    large_stack(|| full_handshake_with_fragments(&[17]));
}

#[test]
#[ignore = "explicit 1-byte composed-role stress; expensive in the debug interpreter"]
fn one_byte_full_handshake_actor_stress_allocates_zero() {
    large_stack(|| full_handshake_with_fragments(&[1]));
}

fn full_handshake_with_fragments(fragments: &[usize]) {
    for &fragment in fragments {
        full_handshake_case(fragment, None);
    }
}

#[test]
fn retired_handshake_selectors_close_admission_without_calling_crypto() {
    large_stack(|| {
        for stale in 0..3 {
            full_handshake_case(900, Some(stale));
        }
    });
}
fn large_stack(body: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(body)
        .unwrap()
        .join()
        .unwrap();
}

fn full_handshake_case(fragment: usize, stale: Option<u8>) {
    with_two_pairs(|mut c, mut co, mut s, mut so, carrier| {
        let mut cr = [None::<Command<1536>>];
        let mut cp = [None::<Reply<1536, 32>>];
        let mut sr = [None::<Command<1536>>];
        let mut sp = [None::<Reply<1536, 32>>];
        let cr = Mailbox::new(&mut cr).unwrap();
        let cp = Mailbox::new(&mut cp).unwrap();
        let sr = Mailbox::new(&mut sr).unwrap();
        let sp = Mailbox::new(&mut sp).unwrap();
        let (cs, cor) = cr.split().unwrap();
        let (cos, crr) = cp.split().unwrap();
        let (ss, sor) = sr.split().unwrap();
        let (sos, srr) = sp.split().unwrap();
        let mut ce = Exchange::new();
        let mut se = Exchange::new();
        let root = CertificateDer::from(fixture::ROOT_DER);
        let anchors = [trust_anchor_from_der(&root).unwrap()];
        let chain = [fixture::LEAF_DER];
        let signing = fixture::signing_key();
        let mut cb = Buffers::new();
        let mut sb = Buffers::new();
        let (count, waker) = waker();
        let client_initial = path_evidence::initial(9, true);
        let server_initial = path_evidence::initial(10, false);
        let actor_rejected = Cell::new(false);
        let observations = Observations::default();
        let server_observations = Observations::default();
        let measured = NoAlloc::start();
        let mut client = BoundedTls::client(
            ClientConfig {
                server_name: "localhost",
                trust_anchors: &anchors,
                now: fixture::now(),
                certificate_limits: Limits::default(),
                transport_parameters: CLIENT_PARAMS,
            },
            cb.storage(),
            &mut TestRandom(123),
        )
        .unwrap();
        assert_eq!(client.confirm_handshake(), Err(tls::Error::KeysUnavailable));
        let client = Probed {
            provider: client,
            observations: &observations,
            probe_ack: true,
        };
        let server = BoundedTls::server(
            ServerConfig {
                certificate_chain: &chain,
                signing_key: &signing,
                transport_parameters: SERVER_PARAMS,
            },
            sb.storage(),
            &mut TestRandom(456),
        )
        .unwrap();
        let server = Probed {
            provider: server,
            observations: &server_observations,
            probe_ack: false,
        };
        let work = async {
            let mut client = Client::connect(cs, crr, 9).await.unwrap();
            let mut server = Client::connect(ss, srr, 10).await.unwrap();
            assert!(client.snapshot().handshaking);
            assert!(!client.snapshot().handshake_keys && !client.snapshot().one_rtt_keys);
            assert_eq!(client.snapshot().peer_parameters(), None);
            assert!(matches!(
                client.take_crypto_flight(0).await.unwrap(),
                Err(tls::Error::Capacity)
            ));
            assert!(matches!(
                client.take_crypto_flight(1537).await.unwrap(),
                Err(tls::Error::Capacity)
            ));
            handshake(&mut client, &mut server, fragment).await;
            packets_and_updates(&mut client, &mut server, client_initial, server_initial).await;
            if let Some(stale) = stale {
                // Retire the peer first so the failed client phase has no
                // unrelated live provider left to cancel in this session.
                server.retire().await.unwrap();
                match stale {
                    0 => assert!(matches!(
                        client.seal_handshake(packet(8, b"retired handshake")).await,
                        Err(tls_owner::ClientError::Closed)
                    )),
                    1 => assert_eq!(
                        client.header_mask(Level::Handshake, true, [0; 16]).await,
                        Err(tls_owner::ClientError::Closed)
                    ),
                    2 => assert!(matches!(
                        client.open_handshake(packet(8, b"retired handshake")).await,
                        Err(tls_owner::ClientError::Closed)
                    )),
                    _ => unreachable!(),
                }
                assert!(
                    matches!(
                        client.take_crypto_flight(128).await,
                        Err(tls_owner::ClientError::Closed)
                    ),
                    "the rejected old-phase request cannot continue the session"
                );
                assert_eq!(observations.post_retirement_calls.get(), 0);
            } else {
                client.retire().await.unwrap();
                assert!(
                    !carrier.is_closed(),
                    "one completed TLS facet must not close its peer"
                );
                let _ = server
                    .seal_one_rtt(response_packet(22, false, b"other provider still live"))
                    .await
                    .unwrap()
                    .unwrap();
                server.retire().await.unwrap();
            }
            Ok(())
        };
        drive(
            join2(
                join2(
                    async {
                        let result =
                            tls_owner::run_borrowed(&mut c, &mut co, 9, client, cor, cos, &mut ce)
                                .await;
                        if stale.is_some() {
                            assert!(matches!(result, Err(tls_owner::Error::UnexpectedCommand)));
                            actor_rejected.set(true);
                            Ok(())
                        } else {
                            result
                        }
                    },
                    tls_owner::run_borrowed(&mut s, &mut so, 10, server, sor, sos, &mut se),
                ),
                work,
            ),
            &count,
            &waker,
        )
        .unwrap();
        measured.finish();
        assert_eq!(actor_rejected.get(), stale.is_some());
        assert_eq!(observations.ack_negative_probes.get(), 2);
        assert_eq!(observations.before_confirmation.get(), 1);
        assert_eq!(observations.retired_handshake.get(), 1);
        assert_eq!(observations.post_retirement_calls.get(), 0);
        assert!(ce.is_empty() && se.is_empty());
        assert!(cr.is_empty() && cp.is_empty() && sr.is_empty() && sp.is_empty());
    });
}

/// Instrumentation delegates all successful work to the real provider. It
/// never creates receipts/grants, supplies substitute keys, or invents success.
#[derive(Default)]
struct Observations {
    ack_negative_probes: Cell<usize>,
    before_confirmation: Cell<usize>,
    retired_handshake: Cell<usize>,
    post_retirement_calls: Cell<usize>,
}
struct Probed<'a, P> {
    provider: P,
    observations: &'a Observations,
    probe_ack: bool,
}
impl<P> Probed<'_, P> {
    fn observe_crypto(&self, level: Level) {
        if level == Level::Handshake && self.observations.retired_handshake.get() != 0 {
            self.observations
                .post_retirement_calls
                .set(self.observations.post_retirement_calls.get() + 1);
        }
    }
}
impl<P: Provider> Provider for Probed<'_, P> {
    fn receive(&mut self, level: Level, bytes: &[u8]) -> Result<(), tls::Error> {
        self.provider.receive(level, bytes)
    }
    fn transmit(&mut self, output: &mut [u8]) -> Result<Option<tls::Output>, tls::Error> {
        self.provider.transmit(output)
    }
    fn has_keys(&self, level: Level) -> bool {
        self.provider.has_keys(level)
    }
    fn discard_keys(&mut self, level: Level) {
        self.provider.discard_keys(level);
        if level == Level::Handshake {
            let mut packet = [0; 64];
            packet[..17].copy_from_slice(b"retired handshake");
            assert_eq!(
                self.provider
                    .seal(Level::Handshake, 8, b"header", &mut packet, 17),
                Err(tls::Error::KeysUnavailable)
            );
            assert_eq!(
                self.provider.header_mask(Level::Handshake, true, &[0; 16]),
                Err(tls::Error::KeysUnavailable)
            );
            self.observations
                .retired_handshake
                .set(self.observations.retired_handshake.get() + 1);
        }
    }
    fn is_handshaking(&self) -> bool {
        self.provider.is_handshaking()
    }
    fn peer_transport_parameters(&self) -> Option<&[u8]> {
        self.provider.peer_transport_parameters()
    }
    fn seal(
        &mut self,
        level: Level,
        pn: u64,
        header: &[u8],
        buffer: &mut [u8],
        plaintext_len: usize,
    ) -> Result<usize, tls::Error> {
        self.observe_crypto(level);
        self.provider.seal(level, pn, header, buffer, plaintext_len)
    }
    fn open(
        &mut self,
        level: Level,
        pn: u64,
        header: &[u8],
        buffer: &mut [u8],
    ) -> Result<usize, tls::Error> {
        self.observe_crypto(level);
        self.provider.open(level, pn, header, buffer)
    }
    fn header_mask(
        &self,
        level: Level,
        local: bool,
        sample: &[u8; 16],
    ) -> Result<[u8; 5], tls::Error> {
        self.observe_crypto(level);
        self.provider.header_mask(level, local, sample)
    }
    fn negotiated_group(&self) -> Option<u16> {
        self.provider.negotiated_group()
    }
    fn key_phase(&self) -> bool {
        self.provider.key_phase()
    }
    fn integrity_budget(&mut self) -> Option<&mut crypto::IntegrityBudget> {
        self.provider.integrity_budget()
    }
    fn receive_key_generation(&self) -> u64 {
        self.provider.receive_key_generation()
    }
    fn key_generation(&self) -> u64 {
        self.provider.key_generation()
    }
    fn confirm_handshake(&mut self) -> Result<(), tls::Error> {
        // Same underlying provider state as the old pre-confirmation assertion.
        // No command selector exists for this operation in Unconfirmed.
        assert_eq!(
            self.provider.initiate_key_update(0, 10),
            Err(tls::Error::KeyUpdateNotAllowed)
        );
        self.observations
            .before_confirmation
            .set(self.observations.before_confirmation.get() + 1);
        self.provider.confirm_handshake()
    }
    fn maintain_keys(&mut self, now: u64, pto: u64) -> Result<(), tls::Error> {
        self.provider.maintain_keys(now, pto)
    }
    fn initiate_key_update(&mut self, now: u64, pto: u64) -> Result<(), tls::Error> {
        self.provider.initiate_key_update(now, pto)
    }
    fn acknowledge_one_rtt(
        &mut self,
        pn: u64,
        generation: u64,
        now: u64,
        pto: u64,
    ) -> Result<(), tls::Error> {
        if self.probe_ack {
            // These are negative provider probes, not manufactured actor grants.
            // Neither failure changes the successful operation's input/output.
            assert_eq!(
                self.provider
                    .acknowledge_one_rtt(pn + 1, generation, now, pto),
                Err(tls::Error::InvalidInput),
                "an unsent packet number is not valid ACK evidence"
            );
            assert_eq!(
                self.provider
                    .acknowledge_one_rtt(pn, generation + 1, now, pto),
                Err(tls::Error::InvalidInput),
                "an unseen receive generation is not valid ACK evidence"
            );
            self.observations.ack_negative_probes.set(2);
            self.probe_ack = false;
        }
        self.provider.acknowledge_one_rtt(pn, generation, now, pto)
    }
    fn open_one_rtt(
        &mut self,
        pn: u64,
        phase: bool,
        header: &[u8],
        buffer: &mut [u8],
        now: u64,
        pto: u64,
    ) -> Result<crypto::Opened, tls::Error> {
        self.provider
            .open_one_rtt(pn, phase, header, buffer, now, pto)
    }
}
