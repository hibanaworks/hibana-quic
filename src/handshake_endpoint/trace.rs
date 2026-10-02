//! Optional metadata-only observation. This never grants protocol authority.
use super::*;
use crate::trace::{Event, QlogWriter, VantagePoint};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceSetupError {
    AlreadyEnabled,
    IoStarted,
    Writer(crate::trace::Error),
}

/// Status for the implemented event subset only, not complete qlog coverage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceStatus {
    pub recorded_events: u64,
    pub lost_events: u64,
    pub pending_bytes: usize,
    pub first_error: Option<crate::trace::Error>,
    pub sink_failed: bool,
    pub counter_overflow: bool,
    /// Sticky even after draining; never qualify a complete capture if true.
    pub incomplete: bool,
}

pub(super) struct State<'s> {
    writer: QlogWriter<'s>,
    origin: u64,
    recorded: u64,
    lost: u64,
    first_error: Option<crate::trace::Error>,
    sink_failed: bool,
    overflow: bool,
}
impl State<'_> {
    fn increment(value: &mut u64, overflow: &mut bool) {
        match value.checked_add(1) {
            Some(next) => *value = next,
            None => *overflow = true,
        }
    }
    pub(super) fn observation_lost(&mut self, error: crate::trace::Error) {
        if self.first_error.is_none() {
            self.first_error = Some(error);
        }
        Self::increment(&mut self.lost, &mut self.overflow);
    }
    fn record(&mut self, now: u64, event: Event) {
        let result = match now.checked_sub(self.origin) {
            Some(elapsed) => self.writer.push(elapsed, event),
            None => Err(crate::trace::Error::TimeWentBackwards),
        };
        match result {
            Ok(()) => Self::increment(&mut self.recorded, &mut self.overflow),
            Err(error) => self.observation_lost(error),
        }
    }
    fn status(&self) -> TraceStatus {
        TraceStatus {
            recorded_events: self.recorded,
            lost_events: self.lost,
            pending_bytes: self.writer.pending().len(),
            first_error: self.first_error,
            sink_failed: self.sink_failed,
            counter_overflow: self.overflow,
            incomplete: self.lost != 0
                || self.first_error.is_some()
                || self.sink_failed
                || self.overflow,
        }
    }
}

impl<'r, 's, 'tc, 'ts, K: InitialKeyProtection> HandshakeEndpoint<'r, 's, 'tc, 'ts, K> {
    /// Opt in before I/O. Storage belongs to the caller; no file, callback or
    /// environment access is performed. Overflow drops only observations and
    /// makes trace_status().incomplete sticky, never changing transport state.
    pub fn enable_trace(&mut self, buffer: &'s mut [u8]) -> Result<(), TraceSetupError> {
        if self.trace.is_some() {
            return Err(TraceSetupError::AlreadyEnabled);
        }
        if self.io_started || self.retired {
            return Err(TraceSetupError::IoStarted);
        }
        let writer =
            QlogWriter::new(buffer, self.trace_vantage()).map_err(TraceSetupError::Writer)?;
        self.trace = Some(State {
            writer,
            origin: self.now,
            recorded: 0,
            lost: 0,
            first_error: None,
            sink_failed: false,
            overflow: false,
        });
        Ok(())
    }
    pub fn trace_status(&self) -> Option<TraceStatus> {
        self.trace.as_ref().map(State::status)
    }
    /// May still be drained after retirement. Consume only actual sink writes.
    pub fn trace_pending(&self) -> &[u8] {
        self.trace
            .as_ref()
            .map_or(&[], |trace| trace.writer.pending())
    }
    pub fn consume_trace(&mut self, bytes: usize) -> Result<(), crate::trace::Error> {
        let Some(trace) = self.trace.as_mut() else {
            return if bytes == 0 {
                Ok(())
            } else {
                Err(crate::trace::Error::InvalidConsume)
            };
        };
        let result = trace.writer.consume(bytes);
        if let Err(error) = result {
            trace.sink_failed = true;
            if trace.first_error.is_none() {
                trace.first_error = Some(error);
            }
        }
        result
    }
    /// A sink write/flush failure is separate from the transport result.
    pub fn mark_trace_sink_failed(&mut self) {
        if let Some(trace) = self.trace.as_mut() {
            trace.sink_failed = true;
        }
    }
    pub(super) fn trace_vantage(&self) -> VantagePoint {
        match self.side {
            Side::Client => VantagePoint::Client,
            Side::Server => VantagePoint::Server,
        }
    }
    pub(super) fn trace_peer_vantage(&self) -> VantagePoint {
        match self.side {
            Side::Client => VantagePoint::Server,
            Side::Server => VantagePoint::Client,
        }
    }
    pub(super) fn trace_event_at(&mut self, now: u64, event: Event) {
        if let Some(trace) = self.trace.as_mut() {
            trace.record(now, event);
        }
    }
    pub(super) fn trace_event(&mut self, event: Event) {
        self.trace_event_at(self.now, event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn state(buffer: &mut [u8]) -> State<'_> {
        State {
            writer: QlogWriter::new(buffer, VantagePoint::Client).unwrap(),
            origin: 10,
            recorded: 0,
            lost: 0,
            first_error: None,
            sink_failed: false,
            overflow: false,
        }
    }
    fn event() -> Event {
        Event::Packet {
            direction: crate::trace::Direction::Received,
            header: crate::trace::PacketHeader {
                packet_type: crate::trace::PacketType::Initial,
                packet_number: Some(0),
                key_phase: None,
            },
            datagram_id: None,
        }
    }
    #[test]
    fn overflow_remains_visible_after_drain_and_later_success() {
        let mut bytes = [0; 512];
        let mut trace = state(&mut bytes);
        for _ in 0..10 {
            trace.record(10, event());
        }
        assert!(trace.status().incomplete);
        let lost = trace.lost;
        let recorded = trace.recorded;
        let count = trace.writer.pending().len();
        trace.writer.consume(count).unwrap();
        trace.record(11, event());
        assert_eq!(trace.recorded, recorded + 1);
        assert_eq!(trace.lost, lost);
        assert!(trace.status().incomplete);
    }
    #[test]
    fn clock_error_is_loss_not_fabricated_timestamp() {
        let mut bytes = [0; 1024];
        let mut trace = state(&mut bytes);
        let pending = trace.writer.pending().len();
        trace.record(9, event());
        assert_eq!(trace.writer.pending().len(), pending);
        assert_eq!(trace.recorded, 0);
        assert_eq!(trace.lost, 1);
        assert_eq!(
            trace.first_error,
            Some(crate::trace::Error::TimeWentBackwards)
        );
        trace.record(10, event());
        assert_eq!(trace.recorded, 1);
        assert!(trace.status().incomplete);
    }
    #[test]
    fn diagnostic_counter_exhaustion_is_sticky_and_does_not_wrap() {
        let mut bytes = [0; 1024];
        let mut trace = state(&mut bytes);
        trace.recorded = u64::MAX;
        trace.record(10, event());
        assert_eq!(trace.recorded, u64::MAX);
        assert!(trace.status().counter_overflow);
        trace.lost = u64::MAX;
        trace.record(9, event());
        assert_eq!(trace.lost, u64::MAX);
        assert!(trace.status().incomplete);
    }
}
