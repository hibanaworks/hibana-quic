use super::*;
use crate::crypto::CipherSuite;
use crate::crypto::IntegrityBudget;
use crate::crypto::KeyKind;
use crate::crypto::PacketKey;
use crate::crypto::directional::{ApplicationKeyScope, ApplicationWriteKeys};
use crate::quic::IoError;
use crate::quic::Side;
use crate::quic::imp::kernel::streams::Limits;
use crate::quic::imp::kernel::streams::PacketReference;
use crate::quic::imp::kernel::streams::Role;
use crate::quic::imp::kernel::streams::SendChunk;
use crate::quic::imp::kernel::streams::StreamSlot;
use crate::quic::imp::{
    application_wire,
    kernel::{
        accounting::AccountingError,
        packet::{self, Frame},
    },
};
use core::cell::Cell;
use core::task::{Context, Waker};

const PACKET: usize = 256;
const CHUNK: usize = 32;

fn key(secret: u8) -> PacketKey {
    PacketKey::from_secret(CipherSuite::Aes128GcmSha256, KeyKind::OneRtt, &[secret; 32]).unwrap()
}

// Use the actual one-shot installation, packet arena binding and stream
// queue. No authentication, accepted-ACK or key-update receipt is forged.
macro_rules! fixture {
    ($book:ident, $write:ident, $streams:ident, $scope:ident) => {
        let mut key_scope = ApplicationKeyScope::new(146);
        let mut installation = key_scope.claim().unwrap();
        let recovery = installation.take_recovery().unwrap();
        let (_read, mut $write) =
            crate::crypto::directional::ApplicationReadKeys::install(installation, key(1), key(2))
                .unwrap();
        let $scope = $write.scope();
        let mut $book =
            recovery::Recovery::<PACKET>::new(recovery, Side::Client, 333_000, 1200, 3).unwrap();
        let mut slots = [StreamSlot::<CHUNK>::EMPTY];
        let mut chunks = [SendChunk::<CHUNK>::EMPTY];
        // Exactly one reference makes any leaked Reserved entry observable.
        let mut references = [PacketReference::EMPTY];
        let peer = Limits {
            max_data: 1024,
            max_streams_bidi: 1,
            stream_data_bidi_local: 1024,
            stream_data_bidi_remote: 1024,
            ..Limits::ZERO
        };
        // Receive credit is backed by this one CHUNK-sized slot. Peer
        // send credit is independent and may legitimately be larger.
        let local = Limits {
            max_data: CHUNK as u64,
            stream_data_bidi_local: CHUNK as u64,
            stream_data_bidi_remote: CHUNK as u64,
            ..Limits::ZERO
        };
        let mut $streams = stream::StreamNumbers::new(
            $scope,
            Role::Client,
            peer,
            local,
            &mut slots,
            &mut chunks,
            &mut references,
        )
        .unwrap();
    };
}

fn stream_packet<'book, 'streams>(
    book: &mut recovery::Tx<'book, '_, PACKET>,
    streams: &mut stream::Tx<'streams, '_, '_, CHUNK, CHUNK>,
    keys: &mut ApplicationWriteKeys<'_>,
) -> Pending<'book, 'streams, PACKET> {
    let prepared = streams
        .prepare::<PACKET>(false)
        .unwrap()
        .expect("queued STREAM");
    let reservation = book
        .reserve_application(
            prepared.bytes(),
            keys.generation(),
            (prepared.bytes().len() + 21) as u64,
            false,
            0,
        )
        .unwrap();
    let scope = reservation.scope();
    let stream = streams
        .reserve_transmission(&prepared, reservation.packet().value)
        .unwrap();
    let sealed = match application_wire::seal(keys, reservation, &[], prepared.bytes()) {
        Ok(sealed) => sealed,
        Err(_) => panic!("actual reserved STREAM must seal"),
    };
    Pending {
        scope,
        sealed: Sealed::Application(sealed),
        stream: Some(stream),
        acknowledgment: None,
        close_deadline: None,
        response: None,
        cid: None,
        path: None,
        probe: None,
        peer_cid: None,
        retirement: None,
    }
}

fn assert_cancelled(snapshot: recovery::Snapshot, next_packet: u64) {
    assert_eq!(snapshot.pending_publications, [0; 3]);
    assert_eq!(snapshot.reserved_bytes, 0);
    assert_eq!(snapshot.reserved_in_flight, 0);
    assert_eq!(snapshot.accepted_bytes, 0);
    assert_eq!(snapshot.bytes_in_flight, 0);
    assert_eq!(snapshot.next_packet_number[2], Some(next_packet));
}

#[test]
fn dropping_staged_state_cancels_recovery_and_the_only_stream_reference() {
    fixture!(book, write, numbers, scope);
    let _ = scope;
    let stream::Facets {
        mut app,
        mut tx,
        publication,
        ..
    } = numbers.split();
    let stream = app.open_local().unwrap();
    let mut production = app.take_production(stream).unwrap();
    assert_eq!(
        app.enqueue_prefix(&mut production, b"GET /\r\n", true)
            .unwrap(),
        (b"GET /\r\n").len()
    );
    let (mut book_tx, _, _, book_publication, mut retirement) = book.split().unwrap();
    let guard = actor_test_allocator::NoAlloc::start();
    let state = Exchange::new(
        book_publication,
        publication,
        None,
        crate::quic::path::imp::observations::Paths::new(None, quic::Side::Client, None, None),
        None,
    );
    let packet = stream_packet(&mut book_tx, &mut tx, &mut write);
    assert!(state.put(packet).is_ok());
    assert_eq!(book_tx.snapshot().pending_publications, [0, 0, 1]);
    assert!(tx.prepare::<PACKET>(false).unwrap().is_none());
    assert_eq!(write.last_sealed_packet_number(), Some(0));

    // No publisher has taken the slot. Dropping the whole continuation
    // must nevertheless cancel the actual Recovery and SendQueue entries.
    drop(state);
    assert_cancelled(book_tx.snapshot(), 1);
    assert!(!app.send_complete(stream).unwrap());
    assert_eq!(app.queued_chunks().unwrap(), 1);
    let retry = stream_packet(&mut book_tx, &mut tx, &mut write);
    assert_eq!(retry.stream.as_ref().unwrap().packet_number(), 1);
    cancel_prepared(retry, &mut book_tx, &mut tx).unwrap();
    assert_cancelled(book_tx.snapshot(), 2);
    retirement.disarm();
    guard.finish();
}

struct Dropped<'a>(&'a Cell<bool>);
impl Drop for Dropped<'_> {
    fn drop(&mut self) {
        self.0.set(true);
    }
}
struct PendingSocket<'a> {
    polls: &'a Cell<usize>,
    dropped: &'a Cell<bool>,
}
impl DatagramTx for PendingSocket<'_> {
    async fn send(&mut self, bytes: &[u8], _ecn: crate::io::Codepoint) -> Result<u64, IoError> {
        let _dropped = Dropped(self.dropped);
        poll_fn(|_| {
            assert!(!bytes.is_empty());
            self.polls.set(self.polls.get() + 1);
            Poll::<Result<u64, IoError>>::Pending
        })
        .await
    }
}

#[test]
fn dropping_actual_pending_udp_future_cancels_both_owned_reservations() {
    fixture!(book, write, numbers, scope);
    let _ = scope;
    let stream::Facets {
        mut app,
        mut tx,
        publication,
        ..
    } = numbers.split();
    let stream = app.open_local().unwrap();
    let mut production = app.take_production(stream).unwrap();
    assert_eq!(
        app.enqueue_prefix(&mut production, b"GET /pending\r\n", true)
            .unwrap(),
        (b"GET /pending\r\n").len()
    );
    let (mut book_tx, _, _, book_publication, mut retirement) = book.split().unwrap();
    let guard = actor_test_allocator::NoAlloc::start();
    let state = Exchange::new(
        book_publication,
        publication,
        None,
        crate::quic::path::imp::observations::Paths::new(None, quic::Side::Client, None, None),
        None,
    );
    let packet = stream_packet(&mut book_tx, &mut tx, &mut write);
    assert!(state.put(packet).is_ok());
    let polls = Cell::new(0);
    let dropped = Cell::new(false);
    let mut socket = PendingSocket {
        polls: &polls,
        dropped: &dropped,
    };
    {
        let mut send = pin!(async {
            let mut pending = InFlight {
                packet: Some(state.take().unwrap()),
                state: &state,
            };
            let accepted_at = socket
                .send(pending.bytes(), crate::io::Codepoint::NotEct)
                .await
                .unwrap();
            pending
                .complete(Some(accepted_at), crate::io::Codepoint::NotEct)
                .unwrap();
        });
        let mut context = Context::from_waker(Waker::noop());
        assert!(send.as_mut().poll(&mut context).is_pending());
        assert_eq!(polls.get(), 1);
        assert!(!dropped.get());
        assert!(state.pending.borrow().is_none());
        assert_eq!(book_tx.snapshot().pending_publications, [0, 0, 1]);
        assert!(tx.prepare::<PACKET>(false).unwrap().is_none());
        // Leaving this scope drops the actual socket future and InFlight.
    }
    assert!(dropped.get());
    assert_eq!(polls.get(), 1);
    assert_cancelled(book_tx.snapshot(), 1);
    assert!(!app.send_complete(stream).unwrap());
    let retry = stream_packet(&mut book_tx, &mut tx, &mut write);
    assert_eq!(retry.stream.as_ref().unwrap().packet_number(), 1);
    state
        .settle(retry, None, crate::io::Codepoint::NotEct)
        .unwrap();
    assert_cancelled(book_tx.snapshot(), 2);
    drop(state);
    retirement.disarm();
    guard.finish();
}

struct AcceptedSocket {
    at: u64,
}
impl DatagramTx for AcceptedSocket {
    fn send(
        &mut self,
        bytes: &[u8],
        _ecn: crate::io::Codepoint,
    ) -> impl Future<Output = Result<u64, IoError>> {
        assert!(!bytes.is_empty());
        core::future::ready(Ok(self.at))
    }
}

#[test]
fn full_ordinary_ledger_close_preserves_accepted_and_cancelled_packet_number_burns() {
    let mut scratch_0 = [0; PACKET];

    fixture!(book, write, numbers, scope);
    let stream::Facets { publication, .. } = numbers.split();
    let (mut book_tx, _, _, book_publication, mut retirement) = book.split().unwrap();
    let guard = actor_test_allocator::NoAlloc::start();
    let state = Exchange::new(
        book_publication,
        publication,
        None,
        crate::quic::path::imp::observations::Paths::new(None, quic::Side::Client, None, None),
        None,
    );
    // Burn numbers before filling the ordinary admission quota. PTO headroom
    // remains reserved, while close still requires actual ordinary retirement.
    for expected in 0..3 {
        let reservation = book_tx
            .reserve_application(&[1], write.generation(), 22, false, 0)
            .unwrap();
        assert_eq!(reservation.packet().value, expected);
        book_tx.cancel(reservation).unwrap();
    }
    let mut socket = AcceptedSocket { at: 10 };
    for offset in 0..recovery::ORDINARY_RECORD_CAPACITY as u64 {
        socket.at = 10 + offset;
        let reservation = book_tx
            .reserve_application(&[1], write.generation(), 22, false, socket.at)
            .unwrap();
        assert_eq!(reservation.packet().value, 3 + offset);
        let sealed = match application_wire::seal(&mut write, reservation, &[], &[1]) {
            Ok(sealed) => sealed,
            Err(_) => panic!("real reserved PING must seal"),
        };
        let packet = Pending {
            scope,
            sealed: Sealed::Application(sealed),
            stream: None,
            acknowledgment: None,
            close_deadline: None,
            response: None,
            cid: None,
            path: None,
            probe: None,
            peer_cid: None,
            retirement: None,
        };
        let mut pending = InFlight {
            packet: Some(packet),
            state: &state,
        };
        let accepted_at = {
            let mut send = pin!(socket.send_on_path(
                pending.bytes(),
                crate::io::Codepoint::NotEct,
                pending.path()
            ));
            let mut context = Context::from_waker(Waker::noop());
            match send.as_mut().poll(&mut context) {
                Poll::Ready(Ok(at)) => at,
                _ => panic!("fixture adapter must accept immediately"),
            }
        };
        pending
            .complete(Some(accepted_at), crate::io::Codepoint::NotEct)
            .unwrap();
    }
    let next = recovery::ORDINARY_RECORD_CAPACITY as u64 + 3;
    let full = book_tx.snapshot();
    assert_eq!(full.retained_packets, recovery::ORDINARY_RECORD_CAPACITY);
    assert_eq!(full.pending_publications, [0; 3]);
    assert_eq!(
        full.bytes_in_flight,
        22 * recovery::ORDINARY_RECORD_CAPACITY as u64
    );
    assert_eq!(full.next_packet_number[2], Some(next));
    assert!(matches!(
        book_tx.reserve_application(&[1], write.generation(), 22, false, 80),
        Err(recovery::Error::Accounting(AccountingError::Full))
    ));

    // Only this module's test can construct the private global-join token.
    // Production obtains it after all projected ordinary roles retire.
    book_tx
        .discard_for_close(super::super::OrdinaryRetired { scope })
        .unwrap();
    assert_eq!(book_tx.snapshot().retained_packets, 0);
    assert_eq!(book_tx.snapshot().next_packet_number[2], Some(next));
    let mut stream_plaintext = [0; 32];
    let stream_len = packet::encode_frame(
        &Frame::Stream {
            id: 0,
            offset: 0,
            fin: false,
            data: b"x",
        },
        &mut stream_plaintext,
    )
    .unwrap();
    assert!(matches!(
        book_tx.reserve_application(
            &stream_plaintext[..stream_len],
            write.generation(),
            (21 + stream_len) as u64,
            false,
            80
        ),
        Err(recovery::Error::Accounting(AccountingError::Retired))
    ));
    let peer = ConnectionId::new(&[]).unwrap();
    let close = close_packet(&mut write, &mut book_tx, &peer, true, 0, 1000, 80)
        .unwrap()
        .expect("full ordinary ledger must permit close after retirement");
    assert_eq!(write.last_sealed_packet_number(), Some(next));
    assert_eq!(book_tx.snapshot().next_packet_number[2], Some(next + 1));

    // Authenticate the actual protected close bytes with installed peer keys.
    let mut peer_scope = ApplicationKeyScope::new(147);
    let (mut peer_read, _peer_write) = crate::crypto::directional::ApplicationReadKeys::install(
        peer_scope.claim().unwrap(),
        key(2),
        key(1),
    )
    .unwrap();
    let opened = application_wire::open::<PACKET>(
        &mut peer_read,
        &mut IntegrityBudget::new(),
        {
            let bytes = close.sealed.bytes();
            let len = bytes.len();
            scratch_0[..len].copy_from_slice(bytes);
            &mut scratch_0[..len]
        },
        &[],
        Some(next - 1),
        80,
        1000,
    )
    .unwrap();
    assert_eq!(opened.packet_number(), next);
    let frame = packet::FrameIter::new(
        opened.plaintext(),
        packet::EncryptionLevel::OneRtt,
        packet::ParseLimits::default(),
    )
    .unwrap()
    .next()
    .unwrap()
    .unwrap();
    assert!(
        matches!(frame, Frame::ConnectionClose { error_code: 0, frame_type: None, reason } if reason.is_empty())
    );
    state
        .settle(close, None, crate::io::Codepoint::NotEct)
        .unwrap();
    assert_eq!(book_tx.snapshot().pending_publications, [0; 3]);
    assert_eq!(book_tx.snapshot().next_packet_number[2], Some(next + 1));
    let second = close_packet(&mut write, &mut book_tx, &peer, true, 0, 1000, 81)
        .unwrap()
        .expect("cancelled close burns its number");
    assert_eq!(write.last_sealed_packet_number(), Some(next + 1));
    state
        .settle(second, Some(81), crate::io::Codepoint::NotEct)
        .unwrap();
    assert_eq!(book_tx.snapshot().next_packet_number[2], Some(next + 2));
    drop(state);
    retirement.disarm();
    guard.finish();
}
