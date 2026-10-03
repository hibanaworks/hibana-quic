//! Fixed-storage idle timeout policy for RFC 9000 section 10.1.
//!
//! Transport parameters are milliseconds; injected clocks and PTOs are
//! microseconds. Zero disables one endpoint's preference, and both zero disable
//! the timer. The effective period is the nonzero minimum, raised to three
//! current PTOs. Updating that floor preserves the last activity timestamp.
//!
//! # Engine integration contract
//!
//! * Construct once with the endpoint's never-reused connection generation,
//!   its actual advertised local timeout, initial clock and current PTO.
//! * Poll before processing input, preparing output, submitting a reserved
//!   output and running other timers. On `Expired`, silently cancel output,
//!   discard keys and connection state, and implicitly reset open streams.
//!   Do not enter the CONNECTION_CLOSE retransmission lifecycle.
//! * Call `on_processed_receive` only after a packet authenticates and all its
//!   frames are successfully processed. ACK-only packets qualify. Malformed,
//!   unauthenticated, discarded, duplicate/unprocessed packets, Retry and
//!   Version Negotiation do not qualify. For a coalesced datagram, account for
//!   each successfully processed packet, even if a later packet is discarded.
//! * After processing the packet that makes peer transport parameters trusted,
//!   call `negotiate_peer` with the validated max_idle_timeout (absent means
//!   zero). Do not install unauthenticated or remembered 0-RTT parameters here.
//! * Call `on_accepted_send` only after validating the engine's opaque output
//!   descriptor and actual adapter submission acceptance. Pass true iff any
//!   accepted packet is ack-eliciting. Preparation, pacing, local rejection and
//!   eventual delivery notifications are not sends. Serialize acceptance and
//!   receive events in their actual order; delayed or duplicate callbacks must
//!   be rejected by the engine before they reach this policy.
//! * Include `deadline()` in the scheduler's minimum deadline. A queued
//!   scheduler uses `DeadlineToken`; direct current-clock polling uses `poll`.
//!   Supply an up-to-date PTO estimate on every call, rather than an absolute
//!   recovery-timer deadline. Only valid activity changes the activity anchor.
//! * Call `stop` on immediate close, peer close or other retirement so old idle
//!   timer callbacks cannot interfere with closing/draining retention.
//!
//! Arithmetic errors are local clock/range failures, not proof of a malformed
//! peer transport parameter. Negotiate the minimum before converting units so
//! a very large valid peer timeout remains usable with a smaller local limit.
//! This kernel does not itself authenticate packets, prove adapter acceptance,
//! generate keepalive traffic, or enforce an independent handshake timeout.
//! Source: <https://www.rfc-editor.org/rfc/rfc9000.html#section-10.1>.

const MAX_TRANSPORT_INTEGER: u64 = (1_u64 << 62) - 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidTimeout,
    InvalidPto,
    DurationOverflow,
    DeadlineOverflow,
    TimeWentBackwards,
    PeerTimeoutAlreadySet,
    StaleTimer,
    TimerNotDue,
    RevisionExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Active,
    /// Terminal and silent. The caller must discard connection state.
    Expired,
    /// Another terminal connection policy has taken ownership.
    Stopped,
}

/// One scheduler registration, bound to one endpoint lifetime and revision.
/// Its fields are private; copying it does not authorize repeated delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeadlineToken {
    generation: u64,
    revision: u64,
    at: u64,
}

impl DeadlineToken {
    pub fn at(&self) -> u64 {
        self.at
    }
}

/// No allocator, atomics, wall clock, I/O or peer-controlled storage.
/// Deliberately not Clone: timer ownership belongs to one endpoint instance.
#[derive(Debug)]
pub struct IdleTimeout {
    generation: u64,
    revision: u64,
    local_timeout_ms: u64,
    peer_timeout_ms: Option<u64>,
    now: u64,
    last_activity: u64,
    deadline: Option<u64>,
    sent_since_receive: bool,
    state: State,
}

impl IdleTimeout {
    /// Generations must not be reused while old descriptors can exist.
    /// Before peer parameters arrive, only the local advertised limit applies.
    /// The first accepted ack-eliciting send can restart this initial timer.
    pub fn new(
        generation: u64,
        local_timeout_ms: u64,
        now_us: u64,
        current_pto_us: u64,
    ) -> Result<Self, Error> {
        validate_timeout(local_timeout_ms)?;
        let deadline = deadline_for(now_us, local_timeout_ms, current_pto_us)?;
        Ok(Self {
            generation,
            revision: 0,
            local_timeout_ms,
            peer_timeout_ms: None,
            now: now_us,
            last_activity: now_us,
            deadline,
            sent_since_receive: false,
            state: State::Active,
        })
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// Zero means disabled. The three-PTO floor is applied separately.
    pub fn negotiated_timeout_ms(&self) -> u64 {
        nonzero_min(self.local_timeout_ms, self.peer_timeout_ms.unwrap_or(0))
    }

    pub fn peer_parameters_known(&self) -> bool {
        self.peer_timeout_ms.is_some()
    }

    /// Current cached deadline; refresh via `poll` when the PTO changes.
    pub fn deadline(&self) -> Option<u64> {
        self.deadline
    }

    pub fn deadline_token(&self) -> Option<DeadlineToken> {
        self.deadline.map(|at| DeadlineToken {
            generation: self.generation,
            revision: self.revision,
            at,
        })
    }

    /// Install authenticated, validated transport parameters once. An exact
    /// duplicate is harmless; a different second value fails without effects.
    /// This does not restart activity. Account for the successful packet first.
    pub fn negotiate_peer(
        &mut self,
        peer_timeout_ms: u64,
        now_us: u64,
        current_pto_us: u64,
    ) -> Result<State, Error> {
        validate_timeout(peer_timeout_ms)?;
        if let Some(previous) = self.peer_timeout_ms {
            if previous != peer_timeout_ms {
                return Err(Error::PeerTimeoutAlreadySet);
            }
            return self.poll(now_us, current_pto_us);
        }
        self.check_clock(now_us)?;
        if self.state != State::Active {
            self.now = now_us;
            return Ok(self.state);
        }
        // Do not resurrect a locally expired connection by negotiating a
        // different period. Unit/range failures leave all state unchanged.
        let old_deadline = self.current_deadline(current_pto_us)?;
        if is_due(old_deadline, now_us) {
            return Ok(self.expire(now_us));
        }
        let timeout_ms = nonzero_min(self.local_timeout_ms, peer_timeout_ms);
        let deadline = deadline_for(self.last_activity, timeout_ms, current_pto_us)?;
        if is_due(deadline, now_us) {
            self.peer_timeout_ms = Some(peer_timeout_ms);
            return Ok(self.expire(now_us));
        }
        let revision = self.next_revision(deadline, false)?;
        self.peer_timeout_ms = Some(peer_timeout_ms);
        self.commit(
            now_us,
            self.last_activity,
            deadline,
            revision,
            self.sent_since_receive,
        );
        Ok(self.state)
    }

    /// Successful peer packet processing restarts the timer, even for ACK-only
    /// packets, and permits one subsequent accepted ack-eliciting send restart.
    pub fn on_processed_receive(
        &mut self,
        now_us: u64,
        current_pto_us: u64,
    ) -> Result<State, Error> {
        self.advance(now_us, current_pto_us, true, false)
    }

    /// Call only for a validated, actually adapter-accepted output descriptor.
    /// ACK/PADDING/CONNECTION_CLOSE-only sends neither restart nor consume the
    /// one ack-eliciting send allowance. Repeated data/probe sends cannot defer
    /// expiry indefinitely without a successfully processed peer packet.
    pub fn on_accepted_send(
        &mut self,
        ack_eliciting: bool,
        now_us: u64,
        current_pto_us: u64,
    ) -> Result<State, Error> {
        let restart = ack_eliciting && !self.sent_since_receive;
        self.advance(
            now_us,
            current_pto_us,
            restart,
            self.sent_since_receive || ack_eliciting,
        )
    }

    /// Poll before all effects. A changed current PTO adjusts the period from
    /// the existing activity anchor, never from the time this method is called.
    /// Expiry at the deadline is terminal, including for a packet arriving then.
    pub fn poll(&mut self, now_us: u64, current_pto_us: u64) -> Result<State, Error> {
        self.advance(now_us, current_pto_us, false, self.sent_since_receive)
    }

    /// A queued callback must match both endpoint generation and schedule
    /// revision. Foreign, superseded, duplicate and premature callbacks have
    /// no effects, including on the monotonic clock. A valid due callback can
    /// rearm instead of expire if the current PTO requires a longer period.
    pub fn on_timeout_token(
        &mut self,
        token: DeadlineToken,
        now_us: u64,
        current_pto_us: u64,
    ) -> Result<State, Error> {
        if self.deadline_token() != Some(token) {
            return Err(Error::StaleTimer);
        }
        self.check_clock(now_us)?;
        if now_us < token.at {
            return Err(Error::TimerNotDue);
        }
        self.poll(now_us, current_pto_us)
    }

    /// Cancel idle policy when closing, draining or otherwise retiring. This
    /// invalidates outstanding tokens and cannot undo an already idle expiry.
    pub fn stop(&mut self) {
        if self.state == State::Active {
            self.state = State::Stopped;
            self.deadline = None;
        }
    }

    fn advance(
        &mut self,
        now_us: u64,
        current_pto_us: u64,
        restart: bool,
        sent_since_receive: bool,
    ) -> Result<State, Error> {
        self.check_clock(now_us)?;
        if self.state != State::Active {
            self.now = now_us;
            return Ok(self.state);
        }
        let current_deadline = self.current_deadline(current_pto_us)?;
        if is_due(current_deadline, now_us) {
            return Ok(self.expire(now_us));
        }
        let last_activity = if restart { now_us } else { self.last_activity };
        let deadline = if restart {
            deadline_for(last_activity, self.negotiated_timeout_ms(), current_pto_us)?
        } else {
            current_deadline
        };
        let revision = self.next_revision(deadline, restart)?;
        self.commit(
            now_us,
            last_activity,
            deadline,
            revision,
            sent_since_receive,
        );
        Ok(self.state)
    }

    fn current_deadline(&self, current_pto_us: u64) -> Result<Option<u64>, Error> {
        deadline_for(
            self.last_activity,
            self.negotiated_timeout_ms(),
            current_pto_us,
        )
    }

    fn check_clock(&self, now_us: u64) -> Result<(), Error> {
        if now_us < self.now {
            Err(Error::TimeWentBackwards)
        } else {
            Ok(())
        }
    }

    fn next_revision(&self, deadline: Option<u64>, restarted: bool) -> Result<u64, Error> {
        if deadline != self.deadline || (restarted && deadline.is_some()) {
            self.revision.checked_add(1).ok_or(Error::RevisionExhausted)
        } else {
            Ok(self.revision)
        }
    }

    fn commit(
        &mut self,
        now: u64,
        last_activity: u64,
        deadline: Option<u64>,
        revision: u64,
        sent_since_receive: bool,
    ) {
        self.now = now;
        self.last_activity = last_activity;
        self.deadline = deadline;
        self.revision = revision;
        self.sent_since_receive = sent_since_receive;
    }

    fn expire(&mut self, now: u64) -> State {
        self.now = now;
        self.state = State::Expired;
        self.deadline = None;
        self.state
    }
}

fn validate_timeout(timeout_ms: u64) -> Result<(), Error> {
    if timeout_ms > MAX_TRANSPORT_INTEGER {
        Err(Error::InvalidTimeout)
    } else {
        Ok(())
    }
}

fn nonzero_min(local: u64, peer: u64) -> u64 {
    match (local, peer) {
        (0, other) | (other, 0) => other,
        _ => local.min(peer),
    }
}

fn deadline_for(anchor: u64, timeout_ms: u64, pto_us: u64) -> Result<Option<u64>, Error> {
    if pto_us == 0 {
        return Err(Error::InvalidPto);
    }
    if timeout_ms == 0 {
        return Ok(None);
    }
    let timeout_us = timeout_ms
        .checked_mul(1_000)
        .ok_or(Error::DurationOverflow)?;
    let floor = pto_us.checked_mul(3).ok_or(Error::DurationOverflow)?;
    anchor
        .checked_add(timeout_us.max(floor))
        .map(Some)
        .ok_or(Error::DeadlineOverflow)
}

fn is_due(deadline: Option<u64>, now: u64) -> bool {
    deadline.is_some_and(|at| now >= at)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timer(local: u64, peer: u64) -> IdleTimeout {
        let mut timer = IdleTimeout::new(7, local, 0, 100).unwrap();
        assert_eq!(timer.negotiate_peer(peer, 0, 100), Ok(State::Active));
        timer
    }

    #[test]
    fn minimum_nonzero_negotiation_and_disabled_timer() {
        for (local, peer, expected) in [
            (0, 0, 0),
            (10, 0, 10),
            (0, 20, 20),
            (10, 20, 10),
            (30, 20, 20),
        ] {
            let mut timer = timer(local, peer);
            assert_eq!(timer.negotiated_timeout_ms(), expected);
            assert_eq!(
                timer.deadline(),
                (expected != 0).then_some(expected * 1_000)
            );
            assert!(timer.peer_parameters_known());
            if expected == 0 {
                assert_eq!(timer.poll(u64::MAX, u64::MAX), Ok(State::Active));
                assert_eq!(timer.deadline_token(), None);
            }
        }
    }

    #[test]
    fn local_limit_applies_before_peer_parameters() {
        let mut timer = IdleTimeout::new(7, 10, 50, 100).unwrap();
        assert!(!timer.peer_parameters_known());
        assert_eq!(timer.deadline(), Some(10_050));
        timer.on_processed_receive(5_000, 100).unwrap();
        timer.negotiate_peer(2, 5_000, 100).unwrap();
        assert_eq!(timer.deadline(), Some(7_000));
        assert_eq!(timer.poll(6_999, 100), Ok(State::Active));
        assert_eq!(timer.poll(7_000, 100), Ok(State::Expired));
    }

    #[test]
    fn negotiation_itself_does_not_create_activity() {
        let mut timer = IdleTimeout::new(1, 0, 0, 100).unwrap();
        assert_eq!(timer.negotiate_peer(2, 3_000, 100), Ok(State::Expired));
        assert_eq!(timer.deadline(), None);
    }

    #[test]
    fn first_accepted_ack_eliciting_send_only_restarts_once() {
        let mut timer = timer(10, 0);
        timer.on_accepted_send(false, 1_000, 100).unwrap();
        assert_eq!(timer.deadline(), Some(10_000));
        timer.on_accepted_send(true, 2_000, 100).unwrap();
        assert_eq!(timer.deadline(), Some(12_000));
        timer.on_accepted_send(true, 8_000, 100).unwrap();
        timer.on_accepted_send(false, 11_000, 100).unwrap();
        assert_eq!(timer.deadline(), Some(12_000));
        assert_eq!(timer.poll(12_000, 100), Ok(State::Expired));
    }

    #[test]
    fn successful_ack_only_receive_rearms_one_send_allowance() {
        let mut timer = timer(10, 0);
        timer.on_accepted_send(true, 1_000, 100).unwrap();
        timer.on_processed_receive(5_000, 100).unwrap();
        assert_eq!(timer.deadline(), Some(15_000));
        timer.on_accepted_send(false, 6_000, 100).unwrap();
        timer.on_accepted_send(true, 7_000, 100).unwrap();
        timer.on_accepted_send(true, 14_000, 100).unwrap();
        assert_eq!(timer.deadline(), Some(17_000));
        timer.on_processed_receive(16_000, 100).unwrap();
        assert_eq!(timer.deadline(), Some(26_000));
    }

    #[test]
    fn corrupt_unprocessed_and_rejected_events_only_poll() {
        let mut timer = timer(10, 10);
        for event_at in [1_000, 2_000, 3_000, 9_999] {
            // Engine dispatch for corrupt packets, discarded duplicates,
            // prepared outputs and local rejection contains no activity hook.
            assert_eq!(timer.poll(event_at, 100), Ok(State::Active));
            assert_eq!(timer.deadline(), Some(10_000));
        }
        // A rejected ack-eliciting output did not consume this allowance.
        timer.on_accepted_send(true, 9_999, 100).unwrap();
        assert_eq!(timer.deadline(), Some(19_999));
    }

    #[test]
    fn current_three_pto_floor_does_not_restart_activity() {
        let mut timer = timer(1, 0);
        timer.poll(500, 1_000).unwrap();
        assert_eq!(timer.deadline(), Some(3_000));
        timer.poll(1_000, 2_000).unwrap();
        assert_eq!(timer.deadline(), Some(6_000));
        timer.poll(2_000, 1_000).unwrap();
        assert_eq!(timer.deadline(), Some(3_000));
        assert_eq!(timer.poll(3_000, 1_000), Ok(State::Expired));
    }

    #[test]
    fn a_shorter_current_pto_can_expire_without_a_new_activity_anchor() {
        let mut timer = IdleTimeout::new(1, 1, 0, 2_000).unwrap();
        assert_eq!(timer.deadline(), Some(6_000));
        assert_eq!(timer.poll(2_000, 100), Ok(State::Expired));
    }

    #[test]
    fn exact_expiry_is_silent_terminal_and_cannot_be_revived() {
        for receive in [false, true] {
            let mut timer = timer(1, 0);
            let outcome = if receive {
                timer.on_processed_receive(1_000, 100)
            } else {
                timer.on_accepted_send(true, 1_000, 100)
            };
            assert_eq!(outcome, Ok(State::Expired));
            assert_eq!(
                timer.on_processed_receive(2_000, 10_000),
                Ok(State::Expired)
            );
            assert_eq!(
                timer.on_accepted_send(true, 3_000, 10_000),
                Ok(State::Expired)
            );
            timer.stop();
            assert_eq!(timer.state(), State::Expired);
            assert_eq!(timer.deadline(), None);
        }
    }

    #[test]
    fn stopped_policy_cannot_replace_closing_or_draining_retention() {
        let mut timer = timer(1, 0);
        let old = timer.deadline_token().unwrap();
        timer.stop();
        timer.stop();
        assert_eq!(
            timer.on_timeout_token(old, 1_000, 100),
            Err(Error::StaleTimer)
        );
        assert_eq!(timer.poll(20_000, 100), Ok(State::Stopped));
        assert_eq!(timer.on_processed_receive(30_000, 100), Ok(State::Stopped));
        assert_eq!(timer.deadline(), None);
    }

    #[test]
    fn timers_reject_foreign_superseded_duplicate_and_early_callbacks() {
        let mut timer = timer(10, 0);
        let old = timer.deadline_token().unwrap();
        let foreign = IdleTimeout::new(8, 10, 0, 100)
            .unwrap()
            .deadline_token()
            .unwrap();
        assert_eq!(
            timer.on_timeout_token(foreign, 80_000, 100),
            Err(Error::StaleTimer)
        );
        assert_eq!(
            timer.on_timeout_token(old, 1_000, 100),
            Err(Error::TimerNotDue)
        );
        timer.on_processed_receive(500, 100).unwrap();
        let current = timer.deadline_token().unwrap();
        assert_eq!(current.at(), 10_500);
        assert_eq!(
            timer.on_timeout_token(old, 80_000, 100),
            Err(Error::StaleTimer)
        );
        assert_eq!(timer.poll(501, 100), Ok(State::Active));
        assert_eq!(
            timer.on_timeout_token(current, 10_500, 100),
            Ok(State::Expired)
        );
        assert_eq!(
            timer.on_timeout_token(current, 80_000, 100),
            Err(Error::StaleTimer)
        );
        assert_eq!(timer.poll(10_501, 100), Ok(State::Expired));
    }

    #[test]
    fn callback_refreshes_changed_pto_then_old_token_is_stale() {
        let mut timer = timer(1, 0);
        let old = timer.deadline_token().unwrap();
        assert_eq!(timer.on_timeout_token(old, 1_000, 1_000), Ok(State::Active));
        let new = timer.deadline_token().unwrap();
        assert_eq!(new.at(), 3_000);
        assert_ne!(old, new);
        assert_eq!(
            timer.on_timeout_token(old, 9_000, 100),
            Err(Error::StaleTimer)
        );
        assert_eq!(
            timer.on_timeout_token(new, 3_000, 1_000),
            Ok(State::Expired)
        );
    }

    #[test]
    fn activity_at_same_timestamp_still_invalidates_queued_timer() {
        let mut timer = timer(10, 0);
        let old = timer.deadline_token().unwrap();
        timer.on_processed_receive(0, 100).unwrap();
        assert_eq!(timer.deadline(), Some(old.at()));
        assert_ne!(timer.deadline_token(), Some(old));
        assert_eq!(
            timer.on_timeout_token(old, 10_000, 100),
            Err(Error::StaleTimer)
        );
    }

    #[test]
    fn time_rollback_and_bad_inputs_leave_state_unchanged() {
        let mut timer = timer(10, 0);
        timer.poll(500, 100).unwrap();
        let before = timer.deadline_token();
        assert_eq!(
            timer.on_processed_receive(499, 100),
            Err(Error::TimeWentBackwards)
        );
        assert_eq!(
            timer.on_accepted_send(true, 499, 100),
            Err(Error::TimeWentBackwards)
        );
        assert_eq!(timer.poll(1_000, 0), Err(Error::InvalidPto));
        assert_eq!(
            timer.negotiate_peer(20, 80_000, 100),
            Err(Error::PeerTimeoutAlreadySet)
        );
        assert_eq!(timer.deadline_token(), before);
        assert_eq!(timer.poll(501, 100), Ok(State::Active));
    }

    #[test]
    fn timeout_conversion_and_deadline_overflow_are_checked() {
        assert!(matches!(
            IdleTimeout::new(0, MAX_TRANSPORT_INTEGER + 1, 0, 1),
            Err(Error::InvalidTimeout)
        ));
        assert!(matches!(
            IdleTimeout::new(0, MAX_TRANSPORT_INTEGER, 0, 1),
            Err(Error::DurationOverflow)
        ));
        assert!(matches!(
            IdleTimeout::new(0, 1, 0, u64::MAX),
            Err(Error::DurationOverflow)
        ));
        assert!(matches!(
            IdleTimeout::new(0, 1, u64::MAX, 1),
            Err(Error::DeadlineOverflow)
        ));
        let mut timer = IdleTimeout::new(0, 1, u64::MAX - 2_000, 1).unwrap();
        let before = timer.deadline_token();
        assert_eq!(
            timer.on_processed_receive(u64::MAX - 1_500, 600),
            Err(Error::DeadlineOverflow)
        );
        assert_eq!(timer.deadline_token(), before);
        assert_eq!(timer.poll(u64::MAX - 1_999, 1), Ok(State::Active));
    }

    #[test]
    fn very_large_peer_parameter_is_minimized_before_unit_conversion() {
        let mut timer = IdleTimeout::new(0, 10, 0, 100).unwrap();
        timer.negotiate_peer(MAX_TRANSPORT_INTEGER, 0, 100).unwrap();
        assert_eq!(timer.deadline(), Some(10_000));
        let mut unbounded = IdleTimeout::new(0, 0, 0, 100).unwrap();
        assert_eq!(
            unbounded.negotiate_peer(MAX_TRANSPORT_INTEGER, 0, 100),
            Err(Error::DurationOverflow)
        );
        assert!(!unbounded.peer_parameters_known());
        assert_eq!(unbounded.deadline(), None);
    }

    #[test]
    fn negotiation_is_idempotent_and_does_not_reset_a_send_allowance() {
        let mut timer = IdleTimeout::new(0, 10, 0, 100).unwrap();
        timer.on_accepted_send(true, 1_000, 100).unwrap();
        timer.negotiate_peer(20, 2_000, 100).unwrap();
        let token = timer.deadline_token();
        timer.negotiate_peer(20, 3_000, 100).unwrap();
        timer.on_accepted_send(true, 4_000, 100).unwrap();
        assert_eq!(timer.deadline_token(), token);
        assert_eq!(timer.deadline(), Some(11_000));
    }

    #[test]
    fn revision_exhaustion_is_checked_but_cannot_prevent_silent_expiry() {
        let mut timer = timer(1, 0);
        timer.revision = u64::MAX;
        let token = timer.deadline_token();
        assert_eq!(
            timer.on_processed_receive(1, 100),
            Err(Error::RevisionExhausted)
        );
        assert_eq!(timer.deadline_token(), token);
        assert_eq!(timer.poll(1_000, 100), Ok(State::Expired));
        assert_eq!(timer.deadline(), None);
    }
}
