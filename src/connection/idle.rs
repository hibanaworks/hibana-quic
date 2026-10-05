//! RFC 9000 10.1 numerical activity accounting, not a protocol controller.
//! Only authenticated receive and actual ack-eliciting publication update it.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Activity {
    received: Option<u64>,
    first_sent_after_receive: Option<u64>,
}
impl Activity {
    pub(super) fn received(&mut self, at: u64) {
        self.received = Some(at);
        self.first_sent_after_receive = None;
    }
    pub(super) fn accepted_ack_eliciting(&mut self, at: u64) {
        // Publication receipts retain producer time. A delayed receipt for a
        // send before a more recent receive must not restart the timer.
        if self.received.is_none_or(|received| at >= received) {
            self.first_sent_after_receive =
                Some(self.first_sent_after_receive.map_or(at, |old| old.min(at)));
        }
    }
    pub(super) fn deadline(
        &self,
        local_ms: u64,
        peer_ms: u64,
        pto_us: u64,
    ) -> Option<Result<u64, ()>> {
        let millis = match (local_ms, peer_ms) {
            (0, 0) => return None,
            (0, b) => b,
            (a, 0) => a,
            (a, b) => a.min(b),
        };
        let base = match (self.received, self.first_sent_after_receive) {
            (None, None) => return None,
            (Some(a), None) | (None, Some(a)) => a,
            (Some(a), Some(b)) => a.max(b),
        };
        Some((|| {
            let interval = millis
                .checked_mul(1000)
                .ok_or(())?
                .max(pto_us.checked_mul(3).ok_or(())?);
            base.checked_add(interval).ok_or(())
        })())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn negotiated_minimum_and_three_pto_floor() {
        let mut a = Activity::default();
        a.received(10);
        assert_eq!(a.deadline(0, 0, 10), None);
        assert_eq!(a.deadline(30, 60, 20_000), Some(Ok(60_010)));
        assert_eq!(a.deadline(0, 30, 1), Some(Ok(30_010)));
        assert_eq!(a.deadline(30, 0, 1), Some(Ok(30_010)));
    }
    #[test]
    fn only_first_publication_after_receive_restarts() {
        let mut a = Activity::default();
        a.received(100);
        a.accepted_ack_eliciting(200);
        let expected = a.deadline(10, 20, 1);
        a.accepted_ack_eliciting(9000);
        assert_eq!(a.deadline(10, 20, 1), expected);
        a.received(10_000);
        a.accepted_ack_eliciting(11_000);
        assert_eq!(a.deadline(10, 20, 1), Some(Ok(21_000)));
    }
    #[test]
    fn late_receipts_cannot_extend_new_receive_epoch() {
        let mut a = Activity::default();
        a.received(100);
        a.accepted_ack_eliciting(99);
        assert_eq!(a.deadline(1, 1, 1), Some(Ok(1100)));
        a.accepted_ack_eliciting(200);
        a.accepted_ack_eliciting(150);
        assert_eq!(a.deadline(1, 1, 1), Some(Ok(1150)));
    }
    #[test]
    fn overflow_is_not_a_wrapped_deadline() {
        let mut a = Activity::default();
        a.received(u64::MAX - 1);
        assert_eq!(a.deadline(1, 1, 1), Some(Err(())));
        assert_eq!(a.deadline(u64::MAX, u64::MAX, 1), Some(Err(())));
    }
}
