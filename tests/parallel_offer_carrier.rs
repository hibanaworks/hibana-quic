//! Delayed parallel ingress on QUIC's actual capacity-one carrier.
//! Adapted from Hibana 8302a07b parallel_offer_delayed_ingress; the choreography
//! and finite poll bound are retained, with the production QUIC carrier/executor.
mod control {
    use hibana::g;
    pub type Plain = g::Msg<238, ()>;
    pub type PlainSink = g::Msg<240, ()>;
    pub type StartupSettled = g::Msg<242, ()>;
}
use hibana::{
    g,
    runtime::{
        SessionKitStorage,
        ids::SessionId,
        program::{RoleProgram, project},
    },
};
use hibana_quic::carrier::CarrierStorage;
use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
type Data = g::Msg<6, u64>;
type Ack = g::Msg<7, u64>;
type End = g::Msg<9, ()>;
type Fin = g::Msg<8, u64>;
type Failed = g::Msg<217, u64>;
type Interrupted = g::Msg<219, u64>;
type Retired = g::Msg<10, ()>;
type Reclaim = g::Msg<193, u64>;
type NoReclaim = g::Msg<195, u64>;
type Stored = g::Msg<194, u64>;
type Done = g::Msg<196, ()>;
type Closed = g::Msg<197, ()>;
const PAYLOADS: [u64; 6] = [17, u64::MAX, 0, 0x0102_0304_0506_0708, 31, 99];
#[test]
fn delayed_parallel_offer_retains_cancelled_ingress_and_acknowledges_every_payload() {
    let packets = g::seq(
        g::route(
            g::seq(
                g::send::<10, 11, Data>(),
                g::route(
                    g::send::<11, 10, Ack>(),
                    g::route(
                        g::send::<11, 10, Fin>(),
                        g::route(
                            g::send::<11, 10, Failed>(),
                            g::send::<11, 10, Interrupted>(),
                        ),
                    ),
                ),
            ),
            g::send::<10, 11, End>(),
        )
        .roll(),
        g::send::<11, 10, Retired>(),
    );
    let receipts = g::route(
        g::seq(
            g::route(g::send::<11, 28, Reclaim>(), g::send::<11, 28, NoReclaim>()),
            g::send::<28, 11, Stored>(),
        ),
        g::seq(g::send::<11, 28, Done>(), g::send::<28, 11, Closed>()),
    )
    .roll();
    let body = g::par(packets, receipts);
    let production = g::par(
        g::send::<8, 9, g::Msg<168, ()>>(),
        g::send::<9, 27, g::Msg<189, u64>>(),
    );
    let global = g::par(
        g::par(production, body),
        g::route(
            g::seq(
                g::send::<8, 19, control::Plain>(),
                g::seq(
                    g::send::<19, 11, control::PlainSink>(),
                    g::send::<19, 8, control::StartupSettled>(),
                ),
            ),
            g::seq(
                g::send::<8, 19, g::Msg<239, ()>>(),
                g::seq(
                    g::send::<19, 11, g::Msg<241, ()>>(),
                    g::send::<19, 8, control::StartupSettled>(),
                ),
            ),
        ),
    );
    let a: RoleProgram<8> = project(&global);
    let b: RoleProgram<10> = project(&global);
    let c: RoleProgram<11> = project(&global);
    let d: RoleProgram<19> = project(&global);
    let e: RoleProgram<28> = project(&global);
    let queues = Box::new(CarrierStorage::<1, 32, 128>::new());
    let mut slab = vec![0; 65536];
    let mut storage = Box::new(SessionKitStorage::uninit());
    let kit = storage.init();
    let sid = SessionId::new(1);
    let rendezvous = kit
        .rendezvous(&mut slab, queues.bind(sid).unwrap())
        .unwrap();
    let mut a = rendezvous.enter(sid, &a).unwrap();
    let mut b = rendezvous.enter(sid, &b).unwrap();
    let mut c = rendezvous.enter(sid, &c).unwrap();
    let mut d = rendezvous.enter(sid, &d).unwrap();
    let mut e = rendezvous.enter(sid, &e).unwrap();
    let source = async {
        a.send::<control::Plain>(&()).await?;
        a.recv::<control::StartupSettled>().await?;
        Ok::<_, hibana::EndpointError>(())
    };
    let sink = async {
        c.recv::<control::PlainSink>().await?;
        for expected in PAYLOADS {
            // Abandon the first preview; the owned frame must survive one
            // cancellation before its subsequent committed receive.
            let preview = c.offer().await?;
            assert_eq!(preview.label(), 6);
            drop(preview);
            let o = c.offer().await?;
            assert_eq!(o.label(), 6);
            let v = o.recv::<Data>().await?;
            assert_eq!(v, expected);
            c.send::<Ack>(&v).await?;
        }
        c.offer().await?.recv::<End>().await?;
        c.send::<Done>(&()).await?;
        c.recv::<Closed>().await?;
        c.send::<Retired>(&()).await?;
        Ok::<_, hibana::EndpointError>(())
    };
    let receive = async {
        for value in PAYLOADS {
            for _ in 0..5 {
                // This test peer delays the physical arrival by one executor turn.
                // Unlike the offer path, the finite delay must schedule itself.
                hibana_quic::runtime::yield_now().await;
            }
            b.send::<Data>(&value).await?;
            let ack = b.recv::<Ack>().await?;
            assert_eq!(ack, value);
        }
        b.send::<End>(&()).await?;
        b.recv::<Retired>().await?;
        Ok::<_, hibana::EndpointError>(())
    };
    let owner = async {
        let o = d.offer().await?;
        o.recv::<control::Plain>().await?;
        d.send::<control::PlainSink>(&()).await?;
        d.send::<control::StartupSettled>(&()).await?;
        Ok::<_, hibana::EndpointError>(())
    };
    let collector = async {
        e.recv::<Done>().await?;
        e.send::<Closed>(&()).await?;
        Ok::<_, hibana::EndpointError>(())
    };
    let mut all = pin!(hibana_quic::runtime::join6(
        source,
        sink,
        receive,
        owner,
        collector,
        async { Ok::<_, hibana::EndpointError>(()) },
    ));
    struct WakeCount(std::sync::atomic::AtomicUsize);
    impl std::task::Wake for WakeCount {
        fn wake(self: std::sync::Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &std::sync::Arc<Self>) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    let wakes = std::sync::Arc::new(WakeCount(std::sync::atomic::AtomicUsize::new(0)));
    let waker = Waker::from(wakes.clone());
    let mut cx = Context::from_waker(&waker);
    for _ in 0..128 {
        let before = wakes.0.load(std::sync::atomic::Ordering::SeqCst);
        if let Poll::Ready(result) = all.as_mut().poll(&mut cx) {
            assert!(result.is_ok(), "{result:?}");
            assert_eq!(queues.queued(), 0, "all frames must be consumed once");
            return;
        }
        assert!(
            wakes.0.load(std::sync::atomic::Ordering::SeqCst) > before,
            "the in-process peers are parked without a registered wake"
        );
    }
    panic!("delayed ingress exceeded its 128-poll schedule on capacity-one QUIC carrier");
}
