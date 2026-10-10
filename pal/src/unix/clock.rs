//! Monotonic physical time and executor deadline waiting.
use crate::unix::reactor::Reactor;
use crate::unix::{Instant, error as io};
use core::{
    cell::RefCell,
    future::{Future, poll_fn},
    pin::pin,
    task::Poll,
    time::Duration,
};
use hibana_quic::io::Clock as ClockCapability;
pub struct Clock<'a, const S: usize = 4, const T: usize = 8> {
    pub reactor: &'a Reactor<S, T>,
    pub start: Instant,
    fault: RefCell<Option<io::Error>>,
}
impl<'a, const S: usize, const T: usize> Clock<'a, S, T> {
    pub fn new(reactor: &'a Reactor<S, T>, start: Instant) -> Self {
        Self {
            reactor,
            start,
            fault: RefCell::new(None),
        }
    }
    pub fn fail(&self, error: io::Error) {
        let mut fault = self.fault.borrow_mut();
        if fault.is_none() {
            *fault = Some(error);
        }
    }
    fn take_fault(&self) -> Option<io::Error> {
        self.fault.borrow_mut().take()
    }
}
impl<const S: usize, const T: usize> ClockCapability for Clock<'_, S, T> {
    fn now(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_micros()).unwrap_or(u64::MAX)
    }
    async fn wait_until(&self, deadline: u64) {
        let Some(deadline) = self.start.checked_add(Duration::from_micros(deadline)) else {
            self.fail(io::ErrorKind::InvalidInput.into());
            return;
        };
        if let Err(error) = self.reactor.sleep_until(deadline).await {
            self.fail(error);
        }
    }
}
#[derive(Debug)]
pub enum DeadlineError<E> {
    Operation(E),
    Clock(io::Error),
    Expired,
}
impl<E: core::fmt::Display> core::fmt::Display for DeadlineError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Operation(e) => e.fmt(f),
            Self::Clock(e) => write!(f, "clock: {e}"),
            Self::Expired => f.write_str("operation deadline expired"),
        }
    }
}

/// The operation and its absolute deadline are pinned once. A Pending
/// datagram is never recreated, and hard expiry wins before another syscall.
pub async fn before_deadline<T, E, const S: usize, const N: usize>(
    clock: &Clock<'_, S, N>,
    deadline: Instant,
    future: impl Future<Output = Result<T, E>>,
) -> Result<T, DeadlineError<E>> {
    let mut operation = pin!(future);
    let mut timer = pin!(clock.reactor.sleep_until(deadline));
    poll_fn(|cx| {
        if let Some(error) = clock.take_fault() {
            return Poll::Ready(Err(DeadlineError::Clock(error)));
        }
        if Instant::now() >= deadline {
            return Poll::Ready(Err(DeadlineError::Expired));
        }
        let result = operation.as_mut().poll(cx);
        if let Some(error) = clock.take_fault() {
            return Poll::Ready(Err(DeadlineError::Clock(error)));
        }
        if result.is_ready() {
            return result.map_err(DeadlineError::Operation);
        }
        match timer.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Err(DeadlineError::Expired)),
            Poll::Ready(Err(error)) => Poll::Ready(Err(DeadlineError::Clock(error))),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use std::boxed::Box;
    #[test]
    fn clock_uses_one_physical_timer_and_cancels_that_same_timer() {
        use super::*;
        use std::task::{Context, Waker};
        let reactor = {
            static WAKE: crate::unix::reactor::WakeStorage =
                crate::unix::reactor::WakeStorage::new();
            Reactor::<1, 2>::new(&WAKE)
        }
        .unwrap();
        let physical = Clock::new(&reactor, Instant::now());
        let mut wait = Box::pin(physical.wait_until(physical.now() + 1_000_000));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(wait.as_mut().poll(&mut cx).is_pending());
        assert_eq!(reactor.active_resources(), (0, 1));
        drop(wait);
        assert_eq!(reactor.active_resources(), (0, 0));
        let mut expired = Box::pin(physical.wait_until(0));
        assert!(expired.as_mut().poll(&mut cx).is_ready());
        drop(expired);
        assert_eq!(reactor.active_resources(), (0, 0));
        assert!(physical.take_fault().is_none());
    }
}
