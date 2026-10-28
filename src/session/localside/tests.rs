use super::*;
use core::{
    cell::Cell,
    future::{Future, pending, poll_fn},
    pin::pin,
    task::{Context, Poll, Waker},
};
use hibana::runtime::transport::{Outgoing, PortOpen, ReceivedFrame, Transport, TransportError};

fn drive<T>(future: impl Future<Output = T>) -> T {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..32 {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
    }
    panic!("test future did not complete");
}

// A test carrier whose actual pending send expires. No successful operation or
// application return is translated into a deadline error.
struct DeadlineCarrier {
    polled: Cell<bool>,
}
impl Transport for DeadlineCarrier {
    type Tx<'a> = ();
    type Rx<'a> = ();
    fn open<'a>(&'a self, _: PortOpen) -> (Self::Tx<'a>, Self::Rx<'a>) {
        ((), ())
    }
    fn poll_send<'f>(
        &self,
        _: &mut Self::Tx<'_>,
        _: Outgoing<'f>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), TransportError>> {
        if self.polled.replace(true) {
            Poll::Ready(Err(TransportError::Deadline))
        } else {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
    fn cancel_send(&self, _: &mut Self::Tx<'_>) {}
    fn poll_recv<'a>(
        &'a self,
        _: &'a mut Self::Rx<'_>,
        _: &mut Context<'_>,
    ) -> Poll<Result<ReceivedFrame<'a>, TransportError>> {
        Poll::Pending
    }
    fn requeue<'a>(&self, _: &mut Self::Rx<'a>) -> Result<(), TransportError> {
        Err(TransportError::Failed)
    }
}

#[test]
fn carrier_deadline_propagates_and_cancels_parked_network() {
    struct Retired<'a>(&'a Cell<bool>);
    impl Drop for Retired<'_> {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }
    let graph = hibana::g::send::<0, 1, hibana::g::Msg<41, u8>>();
    let program = hibana::runtime::program::project::<0>(&graph);
    let storage = Storage::new();
    let sid = SessionId::new(55);
    let binding = storage.carrier.bind(sid, &[]).unwrap();
    let bridge = storage.carrier.peer(0, 1).unwrap();
    let mut slab = [0; 65536];
    let retired = Cell::new(false);
    let result = drive(run_on(
        DeadlineCarrier {
            polled: Cell::new(false),
        },
        &bridge,
        &mut slab,
        sid,
        &program,
        async |endpoint| endpoint.send::<hibana::g::Msg<41, u8>>(&7).await,
        async |_, admission| {
            let _retired = Retired(&retired);
            admission.open().await.expect("admission");
            pending::<Result<(), hibana::EndpointError>>().await
        },
    ));
    let Err(Error::Local(error)) = result else {
        panic!("carrier deadline must remain an application endpoint error");
    };
    assert!(std::format!("{error:?}").contains("Transport(D)"));
    assert!(retired.get());
    drop(binding);
}

#[test]
fn application_return_keeps_queued_output_alive_until_network_drains() {
    let graph = hibana::g::send::<0, 1, hibana::g::Msg<42, u8>>();
    let program = hibana::runtime::program::project::<0>(&graph);
    let mut storage = Storage::new();
    let mut slab = [0; 65536];
    let returned = Cell::new(false);
    let drained = Cell::new(false);
    let result: Result<(), Error<()>> = drive(run(
        &mut storage,
        &mut slab,
        SessionId::new(56),
        1,
        &program,
        async |endpoint| {
            endpoint
                .send::<hibana::g::Msg<42, u8>>(&7)
                .await
                .map_err(|_| ())?;
            returned.set(true);
            Ok(())
        },
        async |bridge, admission| {
            admission.open().await.map_err(|_| ())?;
            while !returned.get() {
                crate::runtime::yield_now().await;
            }
            let frame = poll_fn(|cx| bridge.poll_outgoing(cx))
                .await
                .map_err(|_| ())?
                .expect("committed output remains queued after application return");
            assert_eq!(frame.payload(), &[7]);
            assert!(
                poll_fn(|cx| bridge.poll_outgoing(cx))
                    .await
                    .map_err(|_| ())?
                    .is_none()
            );
            drained.set(true);
            Ok(())
        },
    ));
    assert!(result.is_ok());
    assert!(returned.get() && drained.get());
}
