use super::*;
use crate::crypto::directional::ApplicationKeyScope;
use crate::quic::early_data::{global as p, local::*};
use crate::{runtime::TaskSet, runtime::carrier::CarrierStorage};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use hibana::runtime::{
    SessionKitStorage,
    ids::SessionId,
    program::{RoleProgram, project},
};

fn run_discard(cancel: bool, missing_finished: bool, release: bool, controls: bool) {
    let global = p::choreography();
    let ip: RoleProgram<{ p::INPUT }> = project(&global);
    let op: RoleProgram<{ p::OWNER }> = project(&global);
    let tp: RoleProgram<{ p::TLS }> = project(&global);
    let ap: RoleProgram<{ p::APPLICATION }> = project(&global);
    let carrier = CarrierStorage::<1, 16, 16>::new();
    let mut slab = [0; 65536];
    let mut storage = SessionKitStorage::uninit();
    let sid = SessionId::new(1108);
    let rv = storage
        .init()
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    let mut input = rv.enter(sid, &ip).unwrap();
    let mut owner = rv.enter(sid, &op).unwrap();
    let mut tls = rv.enter(sid, &tp).unwrap();
    let mut app = rv.enter(sid, &ap).unwrap();
    let mut scope_storage = ApplicationKeyScope::new(1108);
    let params = [0, 0, 15, 0, 4, 1, 8, 5, 1, 8, 6, 1, 8, 8, 1, 1];
    let policy = ServerPolicy::BufferedReplaySafeRequests {
        max_bytes: 8,
        max_streams: 1,
    };
    let mut replay = ReplayStorage::<4>::new();
    let (admission, finished, issuer, nonce) =
        genuine::admission_and_finished(&mut scope_storage, 7, &params, policy, &mut replay);
    let scope = finished.scope();
    let mut slots = [QuarantineSlot::<8>::EMPTY];
    let exchange = Exchange::<64>::new();
    let allocation = actor_test_allocator::NoAlloc::start();
    {
        let mut fi = pin!(async {
            let mut bytes = [0; 64];
            let mut len = crate::quic::imp::kernel::packet::encode_frame(
                &crate::quic::imp::kernel::packet::Frame::Stream {
                    id: 0,
                    offset: 0,
                    fin: true,
                    data: b"secret",
                },
                &mut bytes,
            )
            .unwrap();
            if controls {
                len += crate::quic::imp::kernel::packet::encode_frame(
                    &crate::quic::imp::kernel::packet::Frame::MaxData { maximum: 42 },
                    &mut bytes[len..],
                )
                .unwrap();
            }
            exchange
                .input
                .put(AuthenticatedInput {
                    scope,
                    generation: 7,
                    packet: 0,
                    bytes,
                    len,
                    ecn: Some(crate::quic::ecn::imp::Codepoint::Ce),
                })
                .unwrap();
            input.send::<p::Packet>(&0).await?;
            assert_eq!(input.offer().await?.recv::<p::PacketStored>().await?, 0);
            let stored = exchange.take_stored()?;
            assert_eq!(stored.packet_number(), 0);
            assert_eq!(stored.ecn(), Some(crate::quic::ecn::imp::Codepoint::Ce));
            input.send::<p::InputEnd>(&7).await?;
            assert_eq!(input.recv::<p::InputEnded>().await?, 7);
            input.send::<p::InputRetired>(&7).await?;
            Ok::<_, Failure>(())
        });
        let mut fo = pin!(run(&mut owner, admission, policy, &mut slots, &exchange));
        let mut ft = pin!(async {
            assert_eq!(tls.recv::<p::InputRetired>().await?, 7);
            if release {
                exchange.finished.put(finished).unwrap();
                tls.send::<p::Verified>(&7).await?;
                assert_eq!(tls.recv::<p::VerifiedTaken>().await?, 7);
                let returned = exchange.returned_finished.take().unwrap();
                assert!(core::ptr::eq(returned.scope(), scope));
            } else if missing_finished {
                tls.send::<p::Verified>(&7).await?;
                let _ = tls.recv::<p::VerifiedTaken>().await?;
            } else if cancel {
                tls.send::<p::Cancel>(&7).await?;
            } else {
                tls.send::<p::Reject>(&7).await?;
            }
            assert_eq!(tls.recv::<p::Retired>().await?, 7);
            Ok::<_, Failure>(())
        });
        let mut fa = pin!(async {
            if release {
                if controls {
                    assert_eq!(app.offer().await?.recv::<p::Controls>().await?, 7);
                    let block = exchange.take_controls().unwrap();
                    let mut frames = crate::quic::imp::kernel::packet::FrameIter::new(
                        block.bytes(),
                        crate::quic::imp::kernel::packet::EncryptionLevel::ZeroRtt,
                        crate::quic::imp::kernel::packet::ParseLimits::default(),
                    )
                    .unwrap();
                    assert!(matches!(
                        frames.next(),
                        Some(Ok(crate::quic::imp::kernel::packet::Frame::MaxData {
                            maximum: 42
                        }))
                    ));
                    assert!(frames.next().is_none());
                    drop(block);
                    app.send::<p::ControlsApplied>(&7).await?;
                }
                assert_eq!(app.offer().await?.recv::<p::Range>().await?, 0);
                let bytes = exchange.output.take().unwrap();
                assert_eq!((bytes.id, bytes.offset, bytes.fin), (0, 0, true));
                assert_eq!(&bytes.bytes[..bytes.len], b"secret");
                drop(bytes);
                app.send::<p::RangeApplied>(&0).await?;
                assert_eq!(app.offer().await?.recv::<p::Released>().await?, 7);
                app.send::<p::ReleaseSeen>(&7).await?;
            } else {
                assert_eq!(app.offer().await?.recv::<p::Discarded>().await?, 7);
                app.send::<p::DiscardSeen>(&7).await?;
            }
            Ok::<_, Failure>(())
        });
        let mut all = pin!(TaskSet::new([
            fi.as_mut(),
            fo.as_mut(),
            ft.as_mut(),
            fa.as_mut()
        ]));
        let mut outcome = None;
        for _ in 0..200 {
            if let Poll::Ready(value) = all.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
                outcome = Some(value);
                break;
            }
        }
        let result = outcome.expect("early lifecycle must finish without polling forever");
        if missing_finished {
            assert!(matches!(result, Err(Failure::Binding)));
        } else {
            result.unwrap();
        }
    }
    assert!(exchange.output.is_empty());
    assert!(
        slots
            .iter()
            .all(|slot| slot.bytes == [0; 8] && slot.present == [0; 8])
    );
    assert!(matches!(
        ReplayLedger::bind(issuer, &mut replay)
            .unwrap()
            .claim_after_authentication(issuer, nonce, 61000, 1001, 8),
        Err(Error::Replay)
    ));
    allocation.finish();
}

#[test]
fn projected_reject_and_cancel_wipe_actual_storage_without_refunding_claim() {
    run_discard(false, false, false, false);
    run_discard(true, false, false, false);
}
#[test]
fn copied_verified_label_without_actual_finished_receipt_cannot_release() {
    run_discard(false, true, false, false);
}
#[test]
fn projected_owner_cannot_publish_before_finished() {
    let global = p::choreography();
    let op: RoleProgram<{ p::OWNER }> = project(&global);
    let carrier = CarrierStorage::<1, 16, 16>::new();
    let mut slab = [0; 65536];
    let mut storage = SessionKitStorage::uninit();
    let sid = SessionId::new(1109);
    let rv = storage
        .init()
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    let mut owner = rv.enter(sid, &op).unwrap();
    let mut send = pin!(owner.send::<p::Range>(&0));
    assert!(matches!(
        send.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Err(_))
    ));
}

#[test]
fn projected_release_consumes_and_returns_a_real_owned_tls_receipt() {
    run_discard(false, false, true, false);
}

#[test]
fn deferred_controls_require_finished_and_consumer_ack_before_data() {
    run_discard(false, false, true, true);
}

#[path = "../../../../tests/support/early_owned_fixture.rs"]
mod genuine;
