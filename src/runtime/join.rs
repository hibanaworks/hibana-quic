//! Fixed-storage heterogeneous output collection for existing role futures.
//! No endpoint operations or protocol decisions occur in this executor helper.
use super::TaskSet;
use core::{future::Future, pin::pin};
macro_rules! values {
    ($name:ident; $( $future:ident $ty:ident $output:ident $value:ident ),+) => {
        pub(crate) async fn $name<E, $($ty, $value),+>($($future: $ty),+) -> Result<($($value,)+), E>
        where $($ty: Future<Output = Result<$value, E>>),+ {
            $(let mut $output = None;)+
            {
                $(let mut $future = pin!(async {
                    $output = Some($future.await?);
                    Ok::<(), E>(())
                });)+
                TaskSet::new([$($future.as_mut(),)+]).await?;
            }
            Ok(($($output.expect("successful task set wrote every output"),)+))
        }
    };
}
values!(values3; a A ao X, b B bo Y, c C co Z);
values!(values4; a A ao W, b B bo X, c C co Y, d D od Z);
values!(values5; a A ao V, b B bo W, c C co X, d D od Y, e F oe Z);

#[cfg(test)]
mod tests {
    use super::*;
    use core::{
        cell::Cell,
        future::{pending, ready},
        task::{Context, Poll, Waker},
    };
    struct Owned<'a>(&'a Cell<usize>);
    impl Drop for Owned<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1)
        }
    }
    #[test]
    fn outputs_survive_until_the_aggregate_completes() {
        let drops = Cell::new(0);
        let a = Owned(&drops);
        let b = Owned(&drops);
        let c = Owned(&drops);
        let mut joined = pin!(values3(ready(Ok::<_, ()>(a)), ready(Ok(b)), ready(Ok(c))));
        let Poll::Ready(Ok(result)) = joined
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        else {
            panic!("ready tasks parked")
        };
        assert_eq!(drops.get(), 0);
        drop(result);
        assert_eq!(drops.get(), 3);
    }
    #[test]
    fn error_drops_completed_outputs_and_cancels_pending_children() {
        let drops = Cell::new(0);
        let completed = Owned(&drops);
        let parked = Owned(&drops);
        let slow = async move {
            let _owned = parked;
            pending::<Result<(), u8>>().await
        };
        let mut joined = pin!(values3(
            ready(Ok(completed)),
            slow,
            ready(Err::<(), _>(7u8))
        ));
        assert!(matches!(
            joined
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(7))
        ));
        assert_eq!(drops.get(), 2);
    }
    #[test]
    fn aggregate_cancellation_drops_each_owned_child_once() {
        let drops = Cell::new(0);
        {
            let a = Owned(&drops);
            let b = Owned(&drops);
            let slow = async move {
                let _owned = b;
                pending::<Result<(), ()>>().await
            };
            let mut joined = pin!(values3(ready(Ok(a)), slow, ready(Ok(()))));
            assert!(
                joined
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            assert_eq!(drops.get(), 0);
        }
        assert_eq!(drops.get(), 2);
    }
}
