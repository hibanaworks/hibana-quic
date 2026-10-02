//! Bounded immediate-close policy for RFC 9000 sections 10.2 and 19.19.
//!
//! Time and PTO are injected monotonic microseconds. The first local close or
//! peer close fixes a three-PTO retention deadline. Repeated events cannot move
//! it. This module owns no sockets, packet keys, CIDs, stream state or allocator.
//! It is a policy component, not evidence that the endpoint sends a wire close.
//!
//! # Engine integration contract
//!
//! * On a local fatal error/application request, first reconcile or cancel any
//!   prepared ordinary output, then call `local_close`. Stop stream, ACK,
//!   handshake, loss-probe and key-update output immediately. Implicitly reset
//!   open streams, but retain CID routing and enough keys/output for the close.
//! * `poll_transmit` reserves one bounded close flight. The engine may emit at
//!   most one packet at each of the three protection levels, then reports one
//!   aggregate result (accepted if at least one datagram was submitted). Encode `reason().frame(level)`
//!   and choose protection levels using RFC 9000 section 10.2.3: after handshake
//!   confirmation only 1-RTT is permitted; before confirmation additional lower
//!   levels can be coalesced. Packet-number allocation and protection are still
//!   the engine's responsibility. Do not add this non-ack-eliciting frame to
//!   ordinary retransmission/PTO scheduling.
//! * Enforce the actual path/byte amplification budget before submission. A
//!   packet from a new unvalidated address must be discarded or subject to its
//!   own three-times-received budget. CID/version attribution is not address
//!   validation. This module neither grants path validation nor grants bytes.
//! * Report actual adapter acceptance/rejection with `adapter_result` at its
//!   monotonic event time. Preparing output is not a send. At most one output is
//!   reserved. A prepared token must still pass `transmit_permitted` immediately
//!   before submission. Serialize submission and receive/timer changes; the
//!   token cannot authorize bytes after draining or expiry. An asynchronous
//!   adapter reports submission acceptance, not eventual network delivery.
//! * In Closing, use `on_attributed_packet` to request a rate-limited response.
//!   Ignore ordinary frames. If retained receive keys authenticate a valid
//!   CONNECTION_CLOSE, call `on_peer_close` instead. Do not pass unauthenticated
//!   close-frame contents to that hook. Authenticated close takes precedence
//!   over a response request from the same datagram.
//! * On entry to Draining, cancel any unsubmitted output and discard packet
//!   keys. Never send a packet in Draining. On Closed, release the remaining
//!   CID/tombstone state. Keep the connection routed through Closing/Draining so
//!   a delayed packet cannot elicit a stateless reset from a shared listener.
//!
//! Our local policy sends initially, then only when peer traffic requests a
//! response (or a local adapter rejected a send). Requests coalesce in one bit.
//! Attempts wait PTO/4, PTO/2, PTO, ... after the preceding adapter result,
//! rounded up to at least one microsecond and capped by the immutable deadline.
//! A hard eight-flight cap also bounds repeated local rejection; an integrated
//! engine emitting all three levels sends at most24 close packets. Silent peers
//! do not cause autonomous retransmission. Receiving peer close never sends the
//! optional final response allowed by the RFC.
//!
//! Idle-timeout calculation and stateless-reset authentication are separate.
//! The caller supplies a never-reused, checked connection generation to `new`;
//! both adapter and queued timer tokens are bound to that endpoint lifetime.
//! Source: <https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2>.

use crate::{packet::Frame, tls::Level};

pub const MAX_REASON_LEN: usize = 128;
pub const MAX_CLOSE_ATTEMPTS: u8 = 8;
pub const MAX_ERROR_CODE: u64 = (1_u64 << 62) - 1;
pub const APPLICATION_ERROR: u64 = 0x0c;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidCode,
    InvalidFrameType,
    ReasonTooLong,
    InvalidPto,
    TimeWentBackwards,
    DeadlineOverflow,
    StaleTransmit,
    StaleTimer,
    TimerNotDue,
    RevisionExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Active,
    Closing,
    Draining,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseKind {
    /// Use zero when the triggering frame type is unknown.
    Transport {
        frame_type: u64,
    },
    Application,
}

/// Owned, bounded local diagnostics. Peer reason phrases need not fit this
/// local limit: the engine can discard their text and still enter Draining.
#[derive(Debug, Eq, PartialEq)]
pub struct CloseReason {
    kind: CloseKind,
    code: u64,
    reason: [u8; MAX_REASON_LEN],
    len: usize,
}

impl CloseReason {
    pub fn transport(code: u64, frame_type: u64, reason: &str) -> Result<Self, Error> {
        if frame_type > MAX_ERROR_CODE {
            return Err(Error::InvalidFrameType);
        }
        Self::new(CloseKind::Transport { frame_type }, code, reason)
    }

    pub fn application(code: u64, reason: &str) -> Result<Self, Error> {
        Self::new(CloseKind::Application, code, reason)
    }

    fn new(kind: CloseKind, code: u64, reason: &str) -> Result<Self, Error> {
        if code > MAX_ERROR_CODE {
            return Err(Error::InvalidCode);
        }
        if reason.len() > MAX_REASON_LEN {
            return Err(Error::ReasonTooLong);
        }
        let mut stored = [0; MAX_REASON_LEN];
        stored[..reason.len()].copy_from_slice(reason.as_bytes());
        Ok(Self {
            kind,
            code,
            reason: stored,
            len: reason.len(),
        })
    }

    pub fn kind(&self) -> CloseKind {
        self.kind
    }

    pub fn code(&self) -> u64 {
        self.code
    }

    pub fn reason(&self) -> &[u8] {
        &self.reason[..self.len]
    }

    /// Builds the existing borrowed frame representation. Application details
    /// are removed from Initial and Handshake packets, per section 10.2.3.
    /// Selecting a usable protection level remains the engine's responsibility.
    pub fn frame(&self, level: Level) -> Frame<'_> {
        match self.kind {
            CloseKind::Transport { frame_type } => Frame::ConnectionClose {
                error_code: self.code,
                frame_type: Some(frame_type),
                reason: self.reason(),
            },
            CloseKind::Application if level == Level::OneRtt => Frame::ConnectionClose {
                error_code: self.code,
                frame_type: None,
                reason: self.reason(),
            },
            CloseKind::Application => Frame::ConnectionClose {
                error_code: APPLICATION_ERROR,
                frame_type: Some(0),
                reason: &[],
            },
        }
    }
}

/// One opaque output reservation, scoped to the Lifecycle that issued it.
/// It is not evidence of UDP acceptance or permission to bypass path budgets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CloseTransmit {
    generation: u64,
    attempt: u8,
}

/// A queued timer notification. Tokens belong to one connection lifetime and
/// one scheduling revision, and are consumed once. Use `on_timeout(now)` when
/// directly polling the current clock instead of dispatching queued callbacks.
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

#[derive(Debug)]
pub struct Lifecycle {
    generation: u64,
    revision: u64,
    state: State,
    reason: Option<CloseReason>,
    now: Option<u64>,
    deadline: Option<u64>,
    next_response_at: u64,
    backoff: u64,
    response_pending: bool,
    pending: Option<CloseTransmit>,
    attempts: u8,
    accepted: u8,
}

impl Lifecycle {
    /// `generation` must be allocated without reuse across endpoint lifetimes
    /// by the caller; checked counters require neither allocation nor atomics.
    /// Reusing a generation can make an old callback look current and violates
    /// this constructor's contract. There is deliberately no Default instance.
    pub const fn new(generation: u64) -> Self {
        Self {
            generation,
            revision: 0,
            state: State::Active,
            reason: None,
            now: None,
            deadline: None,
            next_response_at: 0,
            backoff: 0,
            response_pending: false,
            pending: None,
            attempts: 0,
            accepted: 0,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// Absolute, immutable retention deadline until expiry. None in Active or
    /// Closed. It is not restarted by sends, packets or duplicate close events.
    pub fn deadline(&self) -> Option<u64> {
        self.deadline
    }

    pub fn reason(&self) -> Option<&CloseReason> {
        self.reason.as_ref()
    }

    pub fn attempts(&self) -> u8 {
        self.attempts
    }

    pub fn accepted_transmits(&self) -> u8 {
        self.accepted
    }

    /// The next useful wake-up: a requested send becoming eligible, or final
    /// expiry. Repeated wakeups are harmless; call `poll_transmit` to reserve.
    /// Pending adapter output suppresses additional send wakeups.
    pub fn next_deadline(&self) -> Option<u64> {
        let deadline = self.deadline?;
        if self.state == State::Closing
            && self.response_pending
            && self.pending.is_none()
            && self.attempts < MAX_CLOSE_ATTEMPTS
        {
            Some(self.next_response_at.min(deadline))
        } else {
            Some(deadline)
        }
    }

    pub fn deadline_token(&self) -> Option<DeadlineToken> {
        Some(DeadlineToken {
            generation: self.generation,
            revision: self.revision,
            at: self.next_deadline()?,
        })
    }

    /// Initiates a local immediate close. Returns true only for Active→Closing.
    /// A repeated request preserves the first reason, PTO and deadline. `pto`
    /// is consulted only when entering the state, and must be positive.
    /// Closing starts at the request even if the adapter subsequently rejects
    /// output, so unavailable I/O cannot keep application state active forever.
    pub fn local_close(&mut self, reason: CloseReason, now: u64, pto: u64) -> Result<bool, Error> {
        self.check_time(now)?;
        if self.state != State::Active {
            self.advance(now)?;
            return Ok(false);
        }
        let deadline = retention_deadline(now, pto)?;
        self.invalidate_timer()?;
        self.now = Some(now);
        self.state = State::Closing;
        self.reason = Some(reason);
        self.deadline = Some(deadline);
        self.next_response_at = now;
        self.backoff = (pto / 4).max(1);
        self.response_pending = true;
        Ok(true)
    }

    /// Call only after a valid peer CONNECTION_CLOSE has been authenticated and
    /// checked for its encryption level. Returns true on entry to Draining.
    /// From Closing, preserves the original deadline and invalidates prepared
    /// output. Duplicate peer close and late close after Closed have no effect.
    pub fn on_peer_close(&mut self, now: u64, pto: u64) -> Result<bool, Error> {
        self.check_time(now)?;
        let new_deadline = if self.state == State::Active {
            Some(retention_deadline(now, pto)?)
        } else {
            None
        };
        self.advance(now)?;
        match self.state {
            State::Active | State::Closing => {
                self.invalidate_timer()?;
                if let Some(deadline) = new_deadline {
                    self.deadline = Some(deadline);
                }
                self.state = State::Draining;
                self.response_pending = false;
                self.pending = None;
                Ok(true)
            }
            State::Draining | State::Closed => Ok(false),
        }
    }

    /// Marks an attributed incoming packet as needing a closing response.
    /// The caller separately enforces CID/version attribution, acceptable path
    /// and the actual send's amplification budget. Multiple packets coalesce;
    /// they never reset a response backoff or the retention deadline.
    pub fn on_attributed_packet(&mut self, now: u64) -> Result<(), Error> {
        self.advance(now)?;
        if self.state == State::Closing && !self.response_pending {
            self.invalidate_timer()?;
            self.response_pending = true;
        }
        Ok(())
    }

    /// Reserves at most one close datagram; no send is counted until accepted.
    /// In particular, timer calls without incoming traffic do not retransmit
    /// an already accepted close. Local adapter rejection retains a request.
    pub fn poll_transmit(&mut self, now: u64) -> Result<Option<CloseTransmit>, Error> {
        self.advance(now)?;
        if self.state != State::Closing
            || !self.response_pending
            || self.pending.is_some()
            || self.attempts == MAX_CLOSE_ATTEMPTS
            || now < self.next_response_at
        {
            return Ok(None);
        }
        self.invalidate_timer()?;
        self.attempts += 1;
        let token = CloseTransmit {
            generation: self.generation,
            attempt: self.attempts,
        };
        self.pending = Some(token);
        self.response_pending = false;
        Ok(Some(token))
    }

    /// Check immediately before submitting prepared bytes. A timer or peer
    /// close invalidates unsent reservations. The integration must serialize
    /// this check/submission with those events, and must still check path bytes.
    pub fn transmit_permitted(&mut self, token: CloseTransmit, now: u64) -> Result<bool, Error> {
        if self.state != State::Closing || self.pending != Some(token) {
            return Ok(false);
        }
        self.advance(now)?;
        Ok(self.state == State::Closing && self.pending == Some(token))
    }

    /// Report the matching adapter submission result once. Rejection does not
    /// increment accepted sends, but does back off retries to avoid a busy loop.
    /// A stale token never consumes or changes a newer output reservation.
    /// Use the monotonic adapter acceptance/rejection event time, not a later
    /// delivery-completion time; accepted does not imply that the peer received.
    pub fn adapter_result(
        &mut self,
        token: CloseTransmit,
        accepted: bool,
        now: u64,
    ) -> Result<(), Error> {
        if self.state != State::Closing || self.pending != Some(token) {
            return Err(Error::StaleTransmit);
        }
        self.advance(now)?;
        if self.state != State::Closing || self.pending != Some(token) {
            return Err(Error::StaleTransmit);
        }
        self.invalidate_timer()?;
        self.pending = None;
        if accepted {
            self.accepted += 1;
        } else {
            self.response_pending = true;
        }
        // A mathematically overflowing response time is necessarily beyond the
        // already checked retention deadline, so clipping here cannot wrap it.
        let deadline = self.deadline.expect("Closing retains a deadline");
        self.next_response_at = now
            .checked_add(self.backoff)
            .unwrap_or(deadline)
            .min(deadline);
        self.backoff = self.backoff.saturating_mul(2);
        Ok(())
    }

    /// Advances time, returning true only when retention expires. Duplicate or
    /// stale timer notifications with a current timestamp are harmless. A
    /// genuinely backwards clock value is rejected without changing state.
    pub fn on_timeout(&mut self, now: u64) -> Result<bool, Error> {
        let previous = self.state;
        self.advance(now)?;
        Ok(previous != State::Closed && self.state == State::Closed)
    }

    /// Dispatch one queued notification, rejecting a foreign, superseded or
    /// duplicate token before changing clock or connection state. Early firing
    /// is also rejected without consuming a valid token. A successful response
    /// wakeup is consumed even before the caller reserves output.
    pub fn on_timeout_token(&mut self, token: DeadlineToken, now: u64) -> Result<bool, Error> {
        if self.deadline_token() != Some(token) {
            return Err(Error::StaleTimer);
        }
        self.check_time(now)?;
        if now < token.at {
            return Err(Error::TimerNotDue);
        }
        // Expiry itself changes the revision in advance; an earlier response
        // wakeup must also consume its token without changing the deadline.
        if self.deadline.is_none_or(|deadline| now < deadline) {
            self.invalidate_timer()?;
        }
        self.on_timeout(now)
    }

    fn invalidate_timer(&mut self) -> Result<(), Error> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(Error::RevisionExhausted)?;
        Ok(())
    }

    fn check_time(&self, now: u64) -> Result<(), Error> {
        if self.now.is_some_and(|previous| now < previous) {
            Err(Error::TimeWentBackwards)
        } else {
            Ok(())
        }
    }

    fn advance(&mut self, now: u64) -> Result<(), Error> {
        self.check_time(now)?;
        if self.deadline.is_some_and(|deadline| now >= deadline) {
            self.invalidate_timer()?;
            self.state = State::Closed;
            self.deadline = None;
            self.reason = None;
            self.response_pending = false;
            self.pending = None;
        }
        self.now = Some(now);
        Ok(())
    }
}

fn retention_deadline(now: u64, pto: u64) -> Result<u64, Error> {
    if pto == 0 {
        return Err(Error::InvalidPto);
    }
    pto.checked_mul(3)
        .and_then(|period| now.checked_add(period))
        .ok_or(Error::DeadlineOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reason() -> CloseReason {
        CloseReason::application(0x1d, "finished").unwrap()
    }

    fn closing(now: u64, pto: u64) -> Lifecycle {
        let mut lifecycle = Lifecycle::new(1);
        assert!(lifecycle.local_close(reason(), now, pto).unwrap());
        lifecycle
    }

    #[test]
    fn reason_bounds_and_handshake_privacy() {
        assert_eq!(
            CloseReason::application(MAX_ERROR_CODE + 1, ""),
            Err(Error::InvalidCode)
        );
        assert_eq!(
            CloseReason::transport(0, MAX_ERROR_CODE + 1, ""),
            Err(Error::InvalidFrameType)
        );
        let full = [b'x'; MAX_REASON_LEN];
        assert!(
            CloseReason::application(MAX_ERROR_CODE, core::str::from_utf8(&full).unwrap()).is_ok()
        );
        let excessive = [b'x'; MAX_REASON_LEN + 1];
        assert_eq!(
            CloseReason::application(0, core::str::from_utf8(&excessive).unwrap()),
            Err(Error::ReasonTooLong)
        );
        let local = CloseReason::application(0x1234, "private application detail 🦀").unwrap();
        assert_eq!(local.kind(), CloseKind::Application);
        for level in [Level::Initial, Level::Handshake] {
            assert!(matches!(
                local.frame(level),
                Frame::ConnectionClose {
                    error_code: APPLICATION_ERROR,
                    frame_type: Some(0),
                    reason: []
                }
            ));
        }
        assert!(
            matches!(local.frame(Level::OneRtt), Frame::ConnectionClose {
            error_code: 0x1234, frame_type: None, reason
        } if reason == local.reason())
        );
        let transport =
            CloseReason::transport(MAX_ERROR_CODE, MAX_ERROR_CODE, "transport").unwrap();
        for level in [Level::Initial, Level::Handshake, Level::OneRtt] {
            assert!(matches!(
                transport.frame(level),
                Frame::ConnectionClose {
                    error_code: MAX_ERROR_CODE,
                    frame_type: Some(MAX_ERROR_CODE),
                    reason: b"transport"
                }
            ));
            assert!(!transport.frame(level).ack_eliciting());
        }
    }

    #[test]
    fn three_pto_expiry_and_duplicate_close_do_not_extend() {
        let mut life = closing(10, 100);
        assert_eq!(life.state(), State::Closing);
        assert_eq!(life.deadline(), Some(310));
        assert_eq!(life.next_deadline(), Some(10));
        assert!(
            !life
                .local_close(CloseReason::transport(1, 0, "different").unwrap(), 20, 999)
                .unwrap()
        );
        assert_eq!(life.deadline(), Some(310));
        assert_eq!(life.reason().unwrap().code(), 0x1d);
        assert!(!life.on_timeout(309).unwrap());
        assert!(life.on_timeout(310).unwrap());
        assert_eq!(life.state(), State::Closed);
        assert_eq!(life.deadline(), None);
        assert_eq!(life.reason(), None);
        assert!(!life.on_timeout(310).unwrap());
        assert!(!life.local_close(reason(), 311, 100).unwrap());
        assert!(!life.on_peer_close(312, 100).unwrap());
        assert_eq!(life.poll_transmit(313).unwrap(), None);
    }

    #[test]
    fn peer_close_never_responds_and_preserves_closing_deadline() {
        let mut active = Lifecycle::new(1);
        assert!(active.on_peer_close(50, 40).unwrap());
        assert_eq!(active.state(), State::Draining);
        assert_eq!(active.deadline(), Some(170));
        assert!(!active.on_peer_close(60, 9_999).unwrap());
        assert!(!active.local_close(reason(), 70, 9_999).unwrap());
        active.on_attributed_packet(80).unwrap();
        assert_eq!(active.poll_transmit(80).unwrap(), None);
        assert_eq!(active.next_deadline(), Some(170));
        assert!(active.on_timeout(170).unwrap());

        let mut life = closing(10, 100);
        let token = life.poll_transmit(10).unwrap().unwrap();
        assert!(life.on_peer_close(30, 10_000).unwrap());
        assert_eq!(life.deadline(), Some(310));
        assert_eq!(life.state(), State::Draining);
        assert!(!life.transmit_permitted(token, 30).unwrap());
        assert_eq!(
            life.adapter_result(token, false, 30),
            Err(Error::StaleTransmit)
        );
        assert_eq!(life.accepted_transmits(), 0);
        life.on_attributed_packet(40).unwrap();
        assert_eq!(life.poll_transmit(40).unwrap(), None);
        assert!(life.on_timeout(310).unwrap());
    }

    #[test]
    fn accepted_send_has_no_autonomous_retransmission() {
        let mut life = closing(0, 100);
        let first = life.poll_transmit(0).unwrap().unwrap();
        assert_eq!(life.attempts(), 1);
        assert_eq!(life.accepted_transmits(), 0);
        assert_eq!(life.poll_transmit(0).unwrap(), None);
        assert_eq!(life.next_deadline(), Some(300));
        assert!(life.transmit_permitted(first, 1).unwrap());
        life.adapter_result(first, true, 1).unwrap();
        assert_eq!(life.accepted_transmits(), 1);
        for now in [26, 50, 100, 299] {
            assert!(!life.on_timeout(now).unwrap());
            assert_eq!(life.poll_transmit(now).unwrap(), None);
            assert_eq!(life.next_deadline(), Some(300));
        }
        assert!(life.on_timeout(300).unwrap());
    }

    #[test]
    fn incoming_requests_coalesce_and_back_off() {
        let mut life = closing(0, 100);
        let first = life.poll_transmit(0).unwrap().unwrap();
        life.adapter_result(first, true, 0).unwrap();
        for now in 1..25 {
            life.on_attributed_packet(now).unwrap();
            assert_eq!(life.poll_transmit(now).unwrap(), None);
            assert_eq!(life.next_deadline(), Some(25));
        }
        let second = life.poll_transmit(25).unwrap().unwrap();
        assert_ne!(first, second);
        // Traffic arriving during adapter ownership is retained for the next
        // response; accepting this reservation cannot erase that newer event.
        life.on_attributed_packet(26).unwrap();
        life.adapter_result(second, true, 26).unwrap();
        assert_eq!(life.next_deadline(), Some(76));
        assert_eq!(life.poll_transmit(75).unwrap(), None);
        let third = life.poll_transmit(76).unwrap().unwrap();
        life.adapter_result(third, true, 76).unwrap();
        life.on_attributed_packet(77).unwrap();
        assert_eq!(life.next_deadline(), Some(176));
        let fourth = life.poll_transmit(176).unwrap().unwrap();
        life.adapter_result(fourth, true, 176).unwrap();
        life.on_attributed_packet(177).unwrap();
        assert_eq!(life.next_deadline(), Some(300));
        assert_eq!(life.poll_transmit(299).unwrap(), None);
        assert_eq!(life.poll_transmit(300).unwrap(), None);
        assert_eq!(life.accepted_transmits(), 4);
    }

    #[test]
    fn rejected_adapter_retries_without_send_credit_or_busy_loop() {
        let mut life = closing(0, 100);
        for now in [0, 25, 75, 175] {
            let token = life.poll_transmit(now).unwrap().unwrap();
            life.adapter_result(token, false, now).unwrap();
            assert_eq!(life.accepted_transmits(), 0);
            assert_eq!(life.poll_transmit(now).unwrap(), None);
            assert_eq!(
                life.adapter_result(token, true, now),
                Err(Error::StaleTransmit)
            );
        }
        assert_eq!(life.attempts(), 4);
        assert_eq!(life.poll_transmit(299).unwrap(), None);
        assert_eq!(life.poll_transmit(300).unwrap(), None);
        assert_eq!(life.state(), State::Closed);
    }

    #[test]
    fn stale_adapter_result_cannot_consume_new_reservation() {
        let mut life = closing(0, 100);
        let first = life.poll_transmit(0).unwrap().unwrap();
        life.adapter_result(first, false, 0).unwrap();
        let next = life.poll_transmit(25).unwrap().unwrap();
        assert_eq!(
            life.adapter_result(first, true, 25),
            Err(Error::StaleTransmit)
        );
        assert!(life.transmit_permitted(next, 25).unwrap());
        life.adapter_result(next, true, 25).unwrap();
        assert_eq!(life.accepted_transmits(), 1);
        assert_eq!(
            life.adapter_result(next, false, 25),
            Err(Error::StaleTransmit)
        );
    }

    #[test]
    fn foreign_generation_never_changes_state_or_clock() {
        let mut old = closing(10, 10);
        let old_output = old.poll_transmit(10).unwrap().unwrap();
        let old_timer = old.deadline_token().unwrap();
        let mut fresh = Lifecycle::new(2);
        fresh.local_close(reason(), 10, 10).unwrap();
        let output = fresh.poll_transmit(10).unwrap().unwrap();
        assert_ne!(output, old_output);
        assert_eq!(
            fresh.adapter_result(old_output, true, u64::MAX),
            Err(Error::StaleTransmit)
        );
        assert!(!fresh.transmit_permitted(old_output, u64::MAX).unwrap());
        assert_eq!(
            fresh.on_timeout_token(old_timer, u64::MAX),
            Err(Error::StaleTimer)
        );
        assert_eq!(fresh.state(), State::Closing);
        assert_eq!(fresh.deadline(), Some(40));
        assert!(fresh.transmit_permitted(output, 10).unwrap());
        fresh.adapter_result(output, true, 10).unwrap();
        assert_eq!(fresh.accepted_transmits(), 1);
    }

    #[test]
    fn queued_timer_tokens_reject_superseded_duplicate_and_early_callbacks() {
        let mut life = closing(0, 100);
        let initial = life.deadline_token().unwrap();
        let first = life.poll_transmit(0).unwrap().unwrap();
        let while_reserved = life.deadline_token().unwrap();
        assert_eq!(while_reserved.at(), 300);
        assert_eq!(
            life.on_timeout_token(initial, u64::MAX),
            Err(Error::StaleTimer)
        );
        life.adapter_result(first, true, 0).unwrap();
        assert_eq!(
            life.on_timeout_token(while_reserved, u64::MAX),
            Err(Error::StaleTimer)
        );
        let idle_expiry = life.deadline_token().unwrap();
        life.on_attributed_packet(1).unwrap();
        let response = life.deadline_token().unwrap();
        assert_eq!(response.at(), 25);
        assert_eq!(
            life.on_timeout_token(idle_expiry, 300),
            Err(Error::StaleTimer)
        );
        assert_eq!(life.on_timeout_token(response, 24), Err(Error::TimerNotDue));
        assert_eq!(life.deadline_token(), Some(response));
        // A queued due-time remains stable while traffic only coalesces.
        life.on_attributed_packet(25).unwrap();
        assert_eq!(life.deadline_token(), Some(response));
        assert!(!life.on_timeout_token(response, 25).unwrap());
        assert_eq!(life.on_timeout_token(response, 25), Err(Error::StaleTimer));
        let send_wakeup = life.deadline_token().unwrap();
        let second = life.poll_transmit(25).unwrap().unwrap();
        assert_eq!(
            life.on_timeout_token(send_wakeup, 300),
            Err(Error::StaleTimer)
        );
        life.adapter_result(second, true, 25).unwrap();
        let closing_expiry = life.deadline_token().unwrap();
        life.on_peer_close(30, 100).unwrap();
        let draining_expiry = life.deadline_token().unwrap();
        assert_eq!(closing_expiry.at(), draining_expiry.at());
        assert_ne!(closing_expiry, draining_expiry);
        assert_eq!(
            life.on_timeout_token(closing_expiry, 300),
            Err(Error::StaleTimer)
        );
        assert!(life.on_timeout_token(draining_expiry, 300).unwrap());
        assert_eq!(
            life.on_timeout_token(draining_expiry, 300),
            Err(Error::StaleTimer)
        );
    }

    #[test]
    fn expiry_invalidates_unsent_output_and_stale_timers_are_idempotent() {
        let mut life = closing(10, 10);
        let token = life.poll_transmit(10).unwrap().unwrap();
        assert!(!life.on_timeout(20).unwrap());
        assert!(!life.on_timeout(20).unwrap());
        assert!(life.transmit_permitted(token, 39).unwrap());
        assert!(!life.transmit_permitted(token, 40).unwrap());
        assert_eq!(life.state(), State::Closed);
        assert_eq!(
            life.adapter_result(token, true, 40),
            Err(Error::StaleTransmit)
        );
        assert!(!life.on_timeout(40).unwrap());
        assert!(!life.on_timeout(100).unwrap());
        assert_eq!(life.next_deadline(), None);
    }

    #[test]
    fn invalid_clock_and_overflow_cannot_mutate_pending_or_reopen() {
        let mut fresh = Lifecycle::new(1);
        assert_eq!(fresh.local_close(reason(), 1, 0), Err(Error::InvalidPto));
        assert_eq!(
            fresh.on_peer_close(1, u64::MAX / 3 + 1),
            Err(Error::DeadlineOverflow)
        );
        assert_eq!(
            fresh.local_close(reason(), u64::MAX - 2, 1),
            Err(Error::DeadlineOverflow)
        );
        assert_eq!(fresh.state(), State::Active);
        assert_eq!(fresh.deadline(), None);
        let mut life = closing(100, 10);
        let token = life.poll_transmit(100).unwrap().unwrap();
        assert_eq!(
            life.adapter_result(token, true, 99),
            Err(Error::TimeWentBackwards)
        );
        assert_eq!(life.on_peer_close(99, 10), Err(Error::TimeWentBackwards));
        assert_eq!(life.on_attributed_packet(99), Err(Error::TimeWentBackwards));
        assert_eq!(life.on_timeout(99), Err(Error::TimeWentBackwards));
        assert_eq!(life.poll_transmit(99), Err(Error::TimeWentBackwards));
        assert!(life.transmit_permitted(token, 100).unwrap());
        life.adapter_result(token, true, 100).unwrap();
        assert!(life.on_timeout(130).unwrap());
        assert_eq!(
            life.local_close(reason(), 129, 10),
            Err(Error::TimeWentBackwards)
        );
        assert_eq!(life.state(), State::Closed);
    }

    #[test]
    fn extreme_time_and_small_pto_bound_all_attempts() {
        // Sweep response and rejection branches at the earliest permitted
        // instants. Tiny PTO rounding and large timestamps remain finite.
        for pto in [1, 2, 3, 4, 5, 7, 100, u64::MAX / 6] {
            let start = u64::MAX - 3 * pto;
            for accepted in [false, true] {
                let mut life = closing(start, pto);
                while life.state() != State::Closed {
                    let now = life.next_deadline().unwrap();
                    if let Some(token) = life.poll_transmit(now).unwrap() {
                        life.adapter_result(token, accepted, now).unwrap();
                        life.on_attributed_packet(now).unwrap();
                    }
                }
                assert!(life.attempts() <= MAX_CLOSE_ATTEMPTS);
                assert!(life.attempts() <= 5);
                assert_eq!(
                    life.accepted_transmits(),
                    if accepted { life.attempts() } else { 0 }
                );
            }
        }
        assert!(core::mem::size_of::<Lifecycle>() <= 320);
    }
}
