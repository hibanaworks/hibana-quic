//! Bounded chunks, owned requests and observed delivery counts.
use crate::quic::application::imp::stream::{MAX_LIVE_STREAMS, Production};
use crate::quic::application::{Error, MAX_REQUEST_BYTES, MAX_REQUESTS};
use crate::quic::imp::{kernel::streams::StreamHandle, tls::Inbox};
use core::cell::{Cell, RefCell};
pub(in crate::quic::application) const REQUEST_BYTES: usize = MAX_REQUEST_BYTES;
// One retained complete request per admitted stream slot. A response body may
// be blocked on transport ACKs, so RX must be able to hand off every admitted
// request without waiting for that body's source to drain this queue.
pub(in crate::quic::application) const REQUEST_CAPACITY: usize = MAX_LIVE_STREAMS;

pub(in crate::quic::application) struct Chunk<const CHUNK: usize> {
    pub bytes: [u8; CHUNK],
    pub len: usize,
}

pub(in crate::quic::application) struct PendingRequest {
    pub stream: StreamHandle,
    pub bytes: [u8; REQUEST_BYTES],
    pub len: usize,
}

pub(in crate::quic::application) struct OwnedRequest<'book> {
    pub(in crate::quic::application) production: Production<'book>,
    pub(in crate::quic::application) bytes: [u8; REQUEST_BYTES],
    pub(in crate::quic::application) len: usize,
}

// The data edge carries either bounded request bytes or the actual response
// reader. This is owned input data, not an independently advanced phase.
pub(in crate::quic::application) enum Input<B, const CHUNK: usize> {
    Chunk(Chunk<CHUNK>),
    Body(B),
}

/// Application observations; protocol progression stays in the local awaits.
pub(in crate::quic::application) struct Exchange<'book, const CHUNK: usize, B> {
    pub(in crate::quic::application) data: Inbox<Input<B, CHUNK>>,
    pub(in crate::quic::application) opened: Inbox<Production<'book>>,
    pub(in crate::quic::application) submitted: Cell<usize>,
    pub(in crate::quic::application) bodies_finished: Cell<usize>,
    pub(in crate::quic::application) completed: RefCell<[Option<StreamHandle>; MAX_LIVE_STREAMS]>,
    pub(in crate::quic::application) completed_total: Cell<usize>,
}
impl<const CHUNK: usize, B> Exchange<'_, CHUNK, B> {
    pub(in crate::quic::application) const fn new() -> Self {
        Self {
            data: Inbox::new(),
            opened: Inbox::new(),
            submitted: Cell::new(0),
            bodies_finished: Cell::new(0),
            completed: RefCell::new([None; MAX_LIVE_STREAMS]),
            completed_total: Cell::new(0),
        }
    }
    pub(in crate::quic::application) fn submitted_count(&self) -> usize {
        self.submitted.get()
    }
    pub(in crate::quic::application) fn bodies_finished(&self) -> usize {
        self.bodies_finished.get()
    }
    pub(in crate::quic::application) fn completed_count(&self) -> usize {
        self.completed_total.get()
    }
    pub(in crate::quic::application) fn is_complete(&self, stream_id: u64) -> bool {
        self.completed
            .borrow()
            .iter()
            .flatten()
            .any(|stream| stream.id() == stream_id)
    }
    pub(in crate::quic::application) fn submitted(&self) -> Result<(), Error> {
        let count = self.submitted.get().checked_add(1).ok_or(Error::Capacity)?;
        if count > MAX_REQUESTS {
            return Err(Error::Capacity);
        }
        self.submitted.set(count);
        Ok(())
    }
    pub(in crate::quic::application) fn complete(&self, stream: StreamHandle) -> Result<(), Error> {
        // A new handle in this slot can only originate after the existing
        // three-receipt Hibana reclaim released the old storage. Keep only
        // the live slot's completion identity, plus a cumulative observation.
        let mut completed = self
            .completed
            .try_borrow_mut()
            .map_err(|_| Error::Binding)?;
        let slot = completed.get_mut(stream.slot()).ok_or(Error::Capacity)?;
        if *slot == Some(stream) {
            return Ok(());
        }
        let total = self
            .completed_total
            .get()
            .checked_add(usize::from(stream.id() & 2 == 0))
            .ok_or(Error::Capacity)?;
        *slot = Some(stream);
        self.completed_total.set(total);
        Ok(())
    }
}

// Results of one actual ingress exchange, not connection/stream phases.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::quic::application) enum Admission {
    Accepted,
    Stopped,
    Interrupted,
    Failed,
}
