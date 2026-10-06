//! Reconstructed regression tests; require fresh execution.
use super::*;
use std::{boxed::Box, sync::Arc, task::Wake};
std::thread_local! {
 static REENTER: Cell<Option<&'static Schedule>> = const {Cell::new(None)};
 static DROPS: Cell<usize> = const {Cell::new(0)};
}
struct ReenterOnDrop;
impl Wake for ReenterOnDrop {
    fn wake(self: Arc<Self>) {}
}
impl Drop for ReenterOnDrop {
    fn drop(&mut self) {
        DROPS.with(|count| count.set(count.get() + 1));
        let target = REENTER.with(Cell::get);
        if let Some(schedule) = target {
            schedule.changed().unwrap();
        }
    }
}
#[test]
fn replacing_waker_allows_reentrant_drop_and_observes_its_revision() {
    let schedule = Box::leak(Box::new(Schedule::new()));
    DROPS.with(|count| count.set(0));
    REENTER.with(|target| target.set(Some(schedule)));
    *schedule.wakers[1].borrow_mut() = Some(Waker::from(Arc::new(ReenterOnDrop)));
    let mut future = core::pin::pin!(schedule.wait_changed(1, 0));
    let mut cx = core::task::Context::from_waker(Waker::noop());
    assert!(matches!(future.as_mut().poll(&mut cx), Poll::Ready(())));
    assert_eq!(schedule.revision.get(), 1);
    DROPS.with(|count| assert_eq!(count.get(), 1));
    REENTER.with(|target| target.set(None));
}
#[test]
fn fixed_connection_preflight_bounds_original_id_without_banning_zero_peer_id() {
    let ids = [0; 21];
    for length in 0..=21 {
        let config = Config {
            side: Side::Client,
            local_connection_id: &[],
            original_destination_id: &ids[..length],
            retry_source_id: None,
            initial_token: &[],
            peer_connection_id: &[],
        };
        assert_eq!(config.validate().is_ok(), (8..=20).contains(&length));
    }
    let valid = Config {
        side: Side::Client,
        local_connection_id: &[],
        original_destination_id: &ids[..8],
        retry_source_id: None,
        initial_token: &[],
        peer_connection_id: &[],
    };
    assert!(valid.validate().is_ok());
    assert!(
        Config {
            local_connection_id: &ids,
            ..valid
        }
        .validate()
        .is_err()
    );
    assert!(
        Config {
            peer_connection_id: &ids,
            ..valid
        }
        .validate()
        .is_err()
    );
}
