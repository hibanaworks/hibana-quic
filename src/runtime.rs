//! Bounded, executor-neutral scheduling for caller-owned async role tasks.
//!
//! Hibana supplies endpoint futures and the carrier stores their wakers. This
//! module supplies only cooperative scheduling: each unfinished task receives
//! one poll per sweep, using the caller's actual [`Context`]. Idle tasks stay
//! pending without a self-wake. No thread, allocation, clock, or protocol state
//! machine is hidden here.
//!
//! A caller pins the returned aggregate future and polls it from its executor.
//! The same parent waker reaches every child; a wake during a sweep must arrange
//! another parent poll under the executor's normal wake contract. A wake is not
//! consumed or reset by this scheduler. Polling from a waker callback reentrantly
//! is invalid; callbacks schedule future work instead.
//!
//! Each role actor uniquely borrows its own endpoint and writes its real
//! `send`, `recv`, and `offer` awaits directly. Keep the endpoints owned by the
//! outer aggregate until all actors finish. Dropping one completed actor's owned
//! endpoint early can close the shared carrier before peers consume its final
//! frame. [`join6`] owns the child futures and cancels them on error/drop; an
//! outer async owner should also own the endpoints and any terminal reply guard.
//!
//! A sweep bounds the number of child polls, not arbitrary work inside a poll.
//! Actors with always-ready loops must call [`yield_now`] at a bounded work
//! boundary. A parked carrier operation already yields and requires no extra
//! polling loop or artificial readiness assumption.

use core::{
    future::{Future, poll_fn},
    pin::{Pin, pin},
    task::{Context, Poll},
};

/// A pinned, borrowed role task. Type erasure here stores a reference and vtable,
/// never a heap allocation. Futures may borrow caller-owned storage and be
/// `!Send` and `!Unpin`.
pub type Task<'a, E> = Pin<&'a mut dyn Future<Output = Result<(), E>>>;

/// A fixed set of caller-pinned futures, fairly polled with the parent context.
///
/// Each sweep polls every unfinished task at most once and rotates its starting
/// slot. Completed tasks are never repolled. The first error ends the aggregate.
/// Empty sets finish immediately.
///
/// This type owns only pinned references. Dropping it, or receiving an error,
/// releases those references but cannot drop the caller's actual futures. Drop
/// the futures in their enclosing scope to cancel operations. Prefer [`join2`]
/// or [`join6`] when the aggregate should own and cancel its child futures.
#[must_use = "role tasks do nothing until the task set is polled"]
pub struct TaskSet<'a, E, const N: usize> {
    tasks: [Option<Task<'a, E>>; N],
    next: usize,
    remaining: usize,
    finished: bool,
}

impl<'a, E, const N: usize> TaskSet<'a, E, N> {
    pub fn new(tasks: [Task<'a, E>; N]) -> Self {
        Self {
            tasks: tasks.map(Some),
            next: 0,
            remaining: N,
            finished: false,
        }
    }
}

impl<E, const N: usize> Future for TaskSet<'_, E, N> {
    type Output = Result<(), E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        assert!(!this.finished, "completed task set polled again");
        let mut index = this.next;
        for _ in 0..N {
            if let Some(task) = this.tasks[index].as_mut() {
                match task.as_mut().poll(cx) {
                    Poll::Ready(Ok(())) => {
                        this.tasks[index] = None;
                        this.remaining -= 1;
                    }
                    Poll::Ready(Err(error)) => {
                        this.tasks = [const { None }; N];
                        this.finished = true;
                        return Poll::Ready(Err(error));
                    }
                    Poll::Pending => {}
                }
            }
            index = (index + 1) % N;
        }
        if this.remaining == 0 {
            this.finished = true;
            Poll::Ready(Ok(()))
        } else {
            // `remaining != 0` implies N > 0.
            this.next = (this.next + 1) % N;
            Poll::Pending
        }
    }
}

/// Run two owned, heterogeneous futures with one fixed fair task set.
///
/// Returning an error or dropping this future drops both child futures and
/// cancels their outstanding borrows. Successful children remain stored until
/// the whole aggregate finishes, but values owned inside a child async body may
/// already be dropped when that child returns. Keep shared-session endpoints
/// owned by the enclosing session rather than individual child bodies.
pub async fn join2<A, B, E>(first: A, second: B) -> Result<(), E>
where
    A: Future<Output = Result<(), E>>,
    B: Future<Output = Result<(), E>>,
{
    let mut first = pin!(first);
    let mut second = pin!(second);
    TaskSet::new([first.as_mut(), second.as_mut()]).await
}

/// Run six owned, heterogeneous role futures with a fixed fair task set.
///
/// Error/drop cancellation and endpoint ownership follow [`join2`]. No task
/// needs a `'static` lifetime, `Send`, `Unpin`, or heap-allocated task storage.
pub async fn join6<A, B, C, D, F, G, E>(
    first: A,
    second: B,
    third: C,
    fourth: D,
    fifth: F,
    sixth: G,
) -> Result<(), E>
where
    A: Future<Output = Result<(), E>>,
    B: Future<Output = Result<(), E>>,
    C: Future<Output = Result<(), E>>,
    D: Future<Output = Result<(), E>>,
    F: Future<Output = Result<(), E>>,
    G: Future<Output = Result<(), E>>,
{
    let mut first = pin!(first);
    let mut second = pin!(second);
    let mut third = pin!(third);
    let mut fourth = pin!(fourth);
    let mut fifth = pin!(fifth);
    let mut sixth = pin!(sixth);
    TaskSet::new([
        first.as_mut(),
        second.as_mut(),
        third.as_mut(),
        fourth.as_mut(),
        fifth.as_mut(),
        sixth.as_mut(),
    ])
    .await
}

/// Yield after a bounded unit of ready work, scheduling one more parent poll.
///
/// The first poll wakes the parent and returns `Pending`; the next returns
/// `Ready`. Use this between runnable actor iterations, never in an idle retry
/// loop. Idle work must await its real event source and that source's waker.
pub async fn yield_now() {
    let mut yielded = false;
    poll_fn(|cx| {
        if yielded {
            Poll::Ready(())
        } else {
            yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await
}
