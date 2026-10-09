//! Admission feasibility for an explicit transcript completion exchange.
//! This is not a replacement TLS implementation or an interop verdict.
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use hibana::{
    EndpointError, g,
    runtime::{SessionKitStorage, ids::SessionId, program::project},
};
use hibana_quic::runtime::{Task, TaskSet, carrier::CarrierStorage};
type Flight = g::Msg<1, ()>;
type Published = g::Msg<2, ()>;
type Finished = g::Msg<3, ()>;
type Verified = g::Msg<4, ()>;
type Completion = g::Msg<6, ()>;
#[test]
fn completion_receipt_does_not_block_peer_finished_at_capacity_one() {
    for a in 0..4 {
        for b in 0..4 {
            for c in 0..4 {
                for d in 0..4 {
                    let order = [a, b, c, d];
                    if a == b || a == c || a == d || b == c || b == d || c == d {
                        continue;
                    }
                    for delay in [0, 1, 8] {
                        run_completion_exchange(order, delay);
                    }
                }
            }
        }
    }
}

fn run_completion_exchange(order: [usize; 4], peer_delay: usize) {
    let graph = g::par(
        g::seq(g::send::<2, 3, Flight>(), g::send::<3, 0, Published>()),
        g::seq(
            g::send::<0, 1, Finished>(),
            g::seq(g::send::<1, 0, Verified>(), g::send::<1, 2, Completion>()),
        ),
    );
    let carrier = CarrierStorage::<1, 16, 16>::new();
    let mut slab = [0; 65536];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init();
    let id = SessionId::new(9001);
    let rv = kit
        .rendezvous(&mut slab, carrier.bind(id).unwrap())
        .unwrap();
    let rx_program = project::<0, _>(&graph);
    let verify_program = project::<1, _>(&graph);
    let source_program = project::<2, _>(&graph);
    let tx_program = project::<3, _>(&graph);
    let mut rx = rv.enter(id, &rx_program).unwrap();
    let mut verify = rv.enter(id, &verify_program).unwrap();
    let mut source = rv.enter(id, &source_program).unwrap();
    let mut tx = rv.enter(id, &tx_program).unwrap();
    let mut source = pin!(async {
        source.send::<Flight>(&()).await?;
        source.recv::<Completion>().await?;
        Ok::<(), EndpointError>(())
    });
    let mut tx = pin!(async {
        tx.recv::<Flight>().await?;
        tx.send::<Published>(&()).await?;
        Ok::<(), EndpointError>(())
    });
    let mut rx = pin!(async {
        rx.recv::<Published>().await?;
        for _ in 0..peer_delay {
            hibana_quic::runtime::yield_now().await;
        }
        rx.send::<Finished>(&()).await?;
        rx.recv::<Verified>().await?;
        Ok::<(), EndpointError>(())
    });
    let mut verify = pin!(async {
        verify.recv::<Finished>().await?;
        verify.send::<Verified>(&()).await?;
        verify.send::<Completion>(&()).await?;
        Ok::<(), EndpointError>(())
    });
    let mut available: [Option<Task<'_, EndpointError>>; 4] = [
        Some(source.as_mut()),
        Some(tx.as_mut()),
        Some(rx.as_mut()),
        Some(verify.as_mut()),
    ];
    let scheduled = order.map(|index| available[index].take().unwrap());
    let mut tasks = pin!(TaskSet::new(scheduled));
    for _ in 0..64 {
        if let Poll::Ready(result) = tasks.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            result.unwrap();
            return;
        }
    }
    panic!("completion receipt blocks Finished at Q=1, order={order:?}, peer_delay={peer_delay}");
}
