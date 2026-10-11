//! Deadline progress is independent of a pending UDP publication.
use super::global as p;
use super::*;
use core::{future::Future, pin::pin};
use hibana::g::Message;

pub(in crate::quic) async fn run<const N: usize, const P: usize>(
    endpoint: &mut Endpoint<'_, { p::TIMER }>,
    stop: &mut Endpoint<'_, { p::TIMER_STOP }>,
    slots: &Storage<'_, '_, N, P>,
    keys: &RefCell<wire::WriteKeys<'_, '_>>,
    book: &mut recovery::Clock<'_, '_, N>,
    clock: &impl Clock,
) -> Result<(), Error> {
    {
        let mut stopping = pin!(stop.recv::<p::StopTimer>());
        loop {
            let revision = slots.schedule.revision.get();
            let available = {
                let owned = keys.borrow();
                [owned.initial.available(), owned.handshake.is_some()]
            };
            let deadline = book.update(clock.now(), available)?;
            let event = {
                let mut changed = pin!(slots.schedule.wait_changed(2, revision));
                let mut wait = pin!(async {
                    match deadline.as_ref() {
                        Some(deadline) => clock.wait_until(deadline.at()).await,
                        None => core::future::pending::<()>().await,
                    }
                });
                poll_fn(|cx| {
                    if let Poll::Ready(result) = stopping.as_mut().poll(cx) {
                        return Poll::Ready(
                            result
                                .map(core::ops::ControlFlow::Break)
                                .map_err(Error::from),
                        );
                    }
                    if changed.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(Ok(core::ops::ControlFlow::Continue(false)));
                    }
                    wait.as_mut()
                        .poll(cx)
                        .map(|()| Ok(core::ops::ControlFlow::Continue(true)))
                })
                .await?
            };
            match event {
                core::ops::ControlFlow::Break(()) => break,
                core::ops::ControlFlow::Continue(false) => continue,
                core::ops::ControlFlow::Continue(true) => {}
            }
            match book.expire(deadline.ok_or(Error::Binding)?, clock.now()) {
                Ok(Some(_)) => {
                    // Keep the independent stop receive runnable even while
                    // this committed expiry awaits its acknowledgement. With a
                    // capacity-one carrier, StopTimer can otherwise occupy the
                    // slot needed by TimerTaken. Retain and finish the exact
                    // expiry future before consuming retirement; never cancel
                    // a half-completed projected exchange or manufacture ACK.
                    let mut expiry = pin!(async {
                        endpoint.send::<p::TimerExpired>(&()).await?;
                        endpoint.recv::<p::TimerTaken>().await?;
                        Ok::<(), Error>(())
                    });
                    match crate::runtime::select(stopping.as_mut(), expiry.as_mut()).await {
                        core::ops::ControlFlow::Break(result) => {
                            result?;
                            expiry.await?;
                            break;
                        }
                        core::ops::ControlFlow::Continue(result) => result?,
                    }
                }
                Ok(None) | Err(recovery::Error::StaleDeadline) => {}
                Err(error) => return Err(error.into()),
            }
            crate::runtime::yield_now().await;
        }
    };
    endpoint.send::<p::TimerRetired>(&()).await?;
    endpoint.recv::<p::TimerAcknowledged>().await?;
    stop.send::<p::TimerStopped>(&()).await?;
    Ok(())
}

/// Keep the timer facet runnable while TX waits for UDP settlement. The
/// numeric expiry has already been committed when its projected edge arrives;
/// acknowledging that edge releases the timer before waking packet preparation.
pub(in crate::quic) async fn receive(
    endpoint: &mut Endpoint<'_, { p::TIMER_TX }>,
    schedule: &Schedule,
) -> Result<(), Error> {
    loop {
        let branch = endpoint.offer().await?;
        match branch.label() {
            label if label == p::TimerExpired::LOGICAL_LABEL => {
                branch.recv::<p::TimerExpired>().await?;
                endpoint.send::<p::TimerTaken>(&()).await?;
                schedule.changed()?;
            }
            label if label == p::TimerRetired::LOGICAL_LABEL => {
                branch.recv::<p::TimerRetired>().await?;
                endpoint.send::<p::TimerAcknowledged>(&()).await?;
                return Ok(());
            }
            label => return Err(Error::UnexpectedLabel(label)),
        }
        crate::runtime::yield_now().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::carrier::CarrierStorage;
    use core::{
        future::pending,
        task::{Context, Waker},
    };
    use hibana::{
        g,
        runtime::{
            SessionKitStorage,
            ids::SessionId,
            program::{RoleProgram, project},
        },
    };

    struct PendingUdp;
    impl DatagramTx for PendingUdp {
        async fn send(
            &mut self,
            _bytes: &[u8],
            _ecn: crate::io::Codepoint,
        ) -> Result<u64, IoError> {
            pending().await
        }
    }

    #[test]
    fn real_timer_consumes_projected_stop_while_clock_and_udp_are_pending() {
        struct QuietClock;
        impl Clock for QuietClock {
            fn now(&self) -> u64 {
                0
            }
            async fn wait_until(&self, _: u64) {
                pending::<()>().await
            }
        }
        let global = g::par(
            g::route(
                g::seq(
                    g::send::<{ p::TIMER }, { p::TIMER_TX }, p::TimerExpired>(),
                    g::send::<{ p::TIMER_TX }, { p::TIMER }, p::TimerTaken>(),
                ),
                g::seq(
                    g::send::<{ p::TIMER }, { p::TIMER_TX }, p::TimerRetired>(),
                    g::send::<{ p::TIMER_TX }, { p::TIMER }, p::TimerAcknowledged>(),
                ),
            )
            .roll(),
            g::seq(
                g::send::<{ p::TX_WIRE }, { p::TIMER_STOP }, p::StopTimer>(),
                g::send::<{ p::TIMER_STOP }, { p::TX_WIRE }, p::TimerStopped>(),
            ),
        );
        let timer_program: RoleProgram<{ p::TIMER }> = project(&global);
        let receiver_program: RoleProgram<{ p::TIMER_TX }> = project(&global);
        let stop_program: RoleProgram<{ p::TIMER_STOP }> = project(&global);
        let sender_program: RoleProgram<{ p::TX_WIRE }> = project(&global);
        let carrier = CarrierStorage::<1, 16, 64>::new();
        let mut slab = [0; 65536];
        let mut kit = SessionKitStorage::uninit();
        let sid = SessionId::new(2);
        let rv = kit
            .init()
            .rendezvous(&mut slab, carrier.bind(sid).unwrap())
            .unwrap();
        let mut timer_endpoint = rv.enter(sid, &timer_program).unwrap();
        let mut receiver_endpoint = rv.enter(sid, &receiver_program).unwrap();
        let mut stop_endpoint = rv.enter(sid, &stop_program).unwrap();
        let mut sender_endpoint = rv.enter(sid, &sender_program).unwrap();
        let mut scope = ApplicationKeyScope::new(200);
        let mut installation = scope.claim().unwrap();
        let mut book = recovery::Recovery::<1536>::new(
            installation.take_recovery().unwrap(),
            Side::Client,
            333_000,
            1200,
            3,
        )
        .unwrap();
        let key_scope = book.scope();
        let (_, _, mut clock_book, _, _retirement) = book.split().unwrap();
        let storage = Storage::<1536, 64>::new(b"peer").unwrap();
        let initial_pair = crypto::initial_keys(b"peer").unwrap();
        let initial_keys = crate::quic::imp::initial::Keys::new(
            key_scope,
            initial_pair.server,
            initial_pair.client,
        )
        .unwrap();
        let write_keys = RefCell::new(wire::WriteKeys {
            initial: &initial_keys,
            handshake: None,
            application: None,
        });
        let mut timer = pin!(run(
            &mut timer_endpoint,
            &mut stop_endpoint,
            &storage,
            &write_keys,
            &mut clock_book,
            &QuietClock
        ));
        let mut receiver = pin!(receive(&mut receiver_endpoint, &storage.schedule));
        let mut sender = pin!(async {
            sender_endpoint.send::<p::StopTimer>(&()).await?;
            sender_endpoint.recv::<p::TimerStopped>().await?;
            Ok::<(), Error>(())
        });
        let mut udp = PendingUdp;
        let mut publication = pin!(udp.send(&[0], crate::io::Codepoint::NotEct));
        let mut tasks = pin!(crate::runtime::TaskSet::new([
            timer.as_mut(),
            receiver.as_mut(),
            sender.as_mut()
        ]));
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..128 {
            assert!(publication.as_mut().poll(&mut cx).is_pending());
            if let Poll::Ready(result) = tasks.as_mut().poll(&mut cx) {
                result.unwrap();
                assert_eq!(carrier.queued(), 0);
                return;
            }
        }
        panic!("projected timer stop did not complete independently");
    }

    #[test]
    fn stop_received_during_expiry_ack_does_not_block_capacity_one() {
        struct QuietClock(core::cell::Cell<u64>);
        impl Clock for QuietClock {
            fn now(&self) -> u64 {
                self.0.get()
            }
            async fn wait_until(&self, deadline: u64) {
                self.0.set(deadline);
            }
        }
        let global = g::par(
            g::route(
                g::seq(
                    g::send::<{ p::TIMER }, { p::TIMER_TX }, p::TimerExpired>(),
                    g::send::<{ p::TIMER_TX }, { p::TIMER }, p::TimerTaken>(),
                ),
                g::seq(
                    g::send::<{ p::TIMER }, { p::TIMER_TX }, p::TimerRetired>(),
                    g::send::<{ p::TIMER_TX }, { p::TIMER }, p::TimerAcknowledged>(),
                ),
            )
            .roll(),
            g::seq(
                g::send::<{ p::TX_WIRE }, { p::TIMER_STOP }, p::StopTimer>(),
                g::send::<{ p::TIMER_STOP }, { p::TX_WIRE }, p::TimerStopped>(),
            ),
        );
        let timer_program: RoleProgram<{ p::TIMER }> = project(&global);
        let receiver_program: RoleProgram<{ p::TIMER_TX }> = project(&global);
        let stop_program: RoleProgram<{ p::TIMER_STOP }> = project(&global);
        let sender_program: RoleProgram<{ p::TX_WIRE }> = project(&global);
        let carrier = CarrierStorage::<1, 16, 64>::new();
        let mut slab = [0; 65536];
        let mut kit = SessionKitStorage::uninit();
        let sid = SessionId::new(2);
        let rv = kit
            .init()
            .rendezvous(&mut slab, carrier.bind(sid).unwrap())
            .unwrap();
        let mut timer_endpoint = rv.enter(sid, &timer_program).unwrap();
        let mut receiver_endpoint = rv.enter(sid, &receiver_program).unwrap();
        let mut stop_endpoint = rv.enter(sid, &stop_program).unwrap();
        let mut sender_endpoint = rv.enter(sid, &sender_program).unwrap();
        let mut scope = ApplicationKeyScope::new(200);
        let mut installation = scope.claim().unwrap();
        let mut book = recovery::Recovery::<1536>::new(
            installation.take_recovery().unwrap(),
            Side::Client,
            333_000,
            1200,
            3,
        )
        .unwrap();
        let key_scope = book.scope();
        let (_, _, mut clock_book, _, _retirement) = book.split().unwrap();
        let storage = Storage::<1536, 64>::new(b"peer").unwrap();
        let initial_pair = crypto::initial_keys(b"peer").unwrap();
        let initial_keys = crate::quic::imp::initial::Keys::new(
            key_scope,
            initial_pair.server,
            initial_pair.client,
        )
        .unwrap();
        let write_keys = RefCell::new(wire::WriteKeys {
            initial: &initial_keys,
            handshake: None,
            application: None,
        });
        let clock = QuietClock(core::cell::Cell::new(0));
        let mut timer = pin!(run(
            &mut timer_endpoint,
            &mut stop_endpoint,
            &storage,
            &write_keys,
            &mut clock_book,
            &clock
        ));
        let mut sender = pin!(async {
            sender_endpoint.send::<p::StopTimer>(&()).await?;
            sender_endpoint.recv::<p::TimerStopped>().await?;
            Ok::<(), Error>(())
        });
        let mut cx = Context::from_waker(Waker::noop());
        assert!(timer.as_mut().poll(&mut cx).is_pending());
        // Consume the expiry, but deliberately let the independent stop occupy
        // the single carrier slot before its physical acknowledgement is sent.
        {
            let mut expired = pin!(receiver_endpoint.recv::<p::TimerExpired>());
            assert!(matches!(
                expired.as_mut().poll(&mut cx),
                Poll::Ready(Ok(()))
            ));
        }
        assert!(sender.as_mut().poll(&mut cx).is_pending());
        let mut receiver = pin!(async {
            receiver_endpoint.send::<p::TimerTaken>(&()).await?;
            receiver_endpoint.recv::<p::TimerRetired>().await?;
            receiver_endpoint.send::<p::TimerAcknowledged>(&()).await?;
            Ok::<(), Error>(())
        });
        let mut tasks = pin!(crate::runtime::TaskSet::new([
            timer.as_mut(),
            receiver.as_mut(),
            sender.as_mut()
        ]));
        for _ in 0..128 {
            if let Poll::Ready(result) = tasks.as_mut().poll(&mut cx) {
                result.unwrap();
                assert_eq!(carrier.queued(), 0);
                return;
            }
        }
        panic!("stop blocked the in-progress timer acknowledgement");
    }

    #[test]
    fn expiry_and_retirement_progress_while_udp_publication_is_pending() {
        let global = g::route(
            g::seq(
                g::send::<{ p::TIMER }, { p::TIMER_TX }, p::TimerExpired>(),
                g::send::<{ p::TIMER_TX }, { p::TIMER }, p::TimerTaken>(),
            ),
            g::seq(
                g::send::<{ p::TIMER }, { p::TIMER_TX }, p::TimerRetired>(),
                g::send::<{ p::TIMER_TX }, { p::TIMER }, p::TimerAcknowledged>(),
            ),
        )
        .roll();
        let producer_program: RoleProgram<{ p::TIMER }> = project(&global);
        let receiver_program: RoleProgram<{ p::TIMER_TX }> = project(&global);
        let carrier = CarrierStorage::<1, 16, 128>::new();
        let mut slab = [0; 262144];
        let mut kit = SessionKitStorage::uninit();
        let sid = SessionId::new(1);
        let rendezvous = kit
            .init()
            .rendezvous(&mut slab, carrier.bind(sid).unwrap())
            .unwrap();
        let mut producer_endpoint = rendezvous.enter(sid, &producer_program).unwrap();
        let mut receiver_endpoint = rendezvous.enter(sid, &receiver_program).unwrap();
        let schedule = Schedule::new();
        let mut udp = PendingUdp;
        let mut publication = pin!(udp.send(&[0], crate::io::Codepoint::NotEct));
        let mut producer = pin!(async {
            for _ in 0..3 {
                producer_endpoint
                    .send::<p::TimerExpired>(&())
                    .await
                    .unwrap();
                producer_endpoint.recv::<p::TimerTaken>().await.unwrap();
            }
            producer_endpoint
                .send::<p::TimerRetired>(&())
                .await
                .unwrap();
            producer_endpoint
                .recv::<p::TimerAcknowledged>()
                .await
                .unwrap();
        });
        let mut receiver = pin!(receive(&mut receiver_endpoint, &schedule));
        let mut cx = Context::from_waker(Waker::noop());
        let mut producer_done = false;
        let mut receiver_done = false;
        for _ in 0..128 {
            assert!(publication.as_mut().poll(&mut cx).is_pending());
            if !producer_done {
                producer_done = producer.as_mut().poll(&mut cx).is_ready();
            }
            if !receiver_done && let Poll::Ready(result) = receiver.as_mut().poll(&mut cx) {
                result.unwrap();
                receiver_done = true;
            }
            if producer_done && receiver_done {
                break;
            }
        }
        assert!(
            producer_done && receiver_done,
            "timer progress depends on stalled UDP"
        );
        assert_eq!(
            schedule.revision.get(),
            3,
            "each observed expiry must wake packet preparation"
        );
        assert!(publication.as_mut().poll(&mut cx).is_pending());
    }
}
