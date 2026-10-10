//! Real constructor, queue wrap, rejection, cancellation and reuse allocations.
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use hibana_quic::{
    io::Address,
    quic::routing::{Delivery, Dispatcher, Error, Slot},
};
#[global_allocator]
static ALLOCATOR: actor_test_allocator::Counting = actor_test_allocator::Counting;
#[test]
fn caller_owned_routes_allocate_nothing_and_preserve_queued_prefixes() {
    let address = Address {
        local: "127.0.0.1:443".parse().unwrap(),
        remote: "127.0.0.1:9999".parse().unwrap(),
    };
    let guard = actor_test_allocator::NoAlloc::start();
    let mut slots = [Slot::<8, 2>::new()];
    let mut routes = Dispatcher::new(&mut slots).unwrap();
    let mut receiver = routes.register(address, &[b"cid"]).unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    let mut output = [0xa5; 12];
    {
        let mut pending = pin!(receiver.receive(&mut output));
        assert!(pending.as_mut().poll(&mut cx).is_pending());
    }
    for cycle in 0..8u8 {
        assert_eq!(
            routes.deliver(address, b"cid", &[cycle; 8], None),
            Delivery::Queued
        );
        assert_eq!(
            routes.deliver(address, b"cid", b"x", None),
            Delivery::Queued
        );
        assert_eq!(
            routes.deliver(address, b"cid", b"overflow", None),
            Delivery::Full
        );
        {
            let mut too_short = [0; 7];
            let mut pending = pin!(receiver.receive(&mut too_short));
            assert!(matches!(
                pending.as_mut().poll(&mut cx),
                Poll::Ready(Err(Error::Capacity))
            ));
        }
        for expected in [&[cycle; 8][..], &b"x"[..]] {
            let packet = {
                let mut pending = pin!(receiver.receive(&mut output));
                let Poll::Ready(Ok(packet)) = pending.as_mut().poll(&mut cx) else {
                    panic!("queued data missing");
                };
                packet
            };
            assert_eq!(&output[..packet.len], expected);
            assert_eq!(&output[8..], &[0xa5; 4]);
        }
    }
    drop(receiver);
    let mut receiver = routes.register(address, &[b"new"]).unwrap();
    assert_eq!(
        routes.deliver(address, b"cid", b"old", None),
        Delivery::Unknown
    );
    drop(routes);
    {
        let mut pending = pin!(receiver.receive(&mut output));
        assert!(matches!(
            pending.as_mut().poll(&mut cx),
            Poll::Ready(Err(Error::Closed))
        ));
    }
    drop(receiver);
    guard.finish();
}
