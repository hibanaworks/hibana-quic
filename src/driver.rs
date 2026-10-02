//! Single-owner, bounded-poll driver for the internal Hibana service protocol.
//!
//! The caller owns the SessionKit, carrier, runtime slab, and connection state.
//! It attaches all six roles of [`crate::protocol::service_program`] and moves
//! those endpoints here. No endpoint is shared, cloned, or concurrently polled.
//! Each method has a fixed operation bound and never leaves a borrowed future
//! behind. An unexpected Pending is terminal, never an inferred success.
//!
//! `begin_receive` consumes successful key-owner authentication evidence; finish
//! it after authenticated effects have been applied. Reserve actual accounting
//! resources before `reserve_transmit`, publish only after its success, and
//! call `adapter_result` only after the corresponding adapter callback. This
//! driver enforces effect order; the projected key owners perform cryptography
//! and keep every key lifecycle out of this numerical effect ledger.

mod early;
mod path;
#[cfg(test)]
pub(crate) mod test_support;
pub use early::{
    EarlyBufferTicket, EarlyControlBufferTicket, EarlyControlReleaseTicket, EarlyIntentTicket,
    EarlyPeerCloseTicket, EarlyReceiveTicket, EarlyReleaseTicket,
};
pub use path::{
    CidAdvertisementTicket, CidInstallTicket, CidRetirementTicket, PathAcceptedTicket, PathEffect,
    PathEffectTicket, PathReservationTicket, TimerTicket,
};

use crate::protocol::{
    ADAPTER, APPLICATION, INGRESS, PACKET, RECOVERY, RxDatagram, RxProcessed, TIMER, TimerExpired,
    TimerHandled, TxComplete, TxRequest, TxReserved, TxResult,
};
use crate::protocol::{
    AckReleaseCompleted, AckReleaseRequest, AuthenticatedPacket, DeliveryCompleted, DeliveryRequest,
};
use crate::protocol::{StreamRetiredAcknowledged, StreamRetiredRequest};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use hibana::{Endpoint, EndpointError};

/// All six independently attached roles from one session and service image.
/// Fields are public only to allow moving caller-attached endpoints into the
/// driver. The endpoints are not returned once execution begins.
pub struct Roles<'r> {
    pub ingress: Endpoint<'r, INGRESS>,
    pub packet: Endpoint<'r, PACKET>,
    pub application: Endpoint<'r, APPLICATION>,
    pub recovery: Endpoint<'r, RECOVERY>,
    pub adapter: Endpoint<'r, ADAPTER>,
    pub timer: Endpoint<'r, TIMER>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Descriptor {
    generation: u64,
    id: u32,
}

/// One successfully authenticated packet, minted only by its actual key owner.
/// The variants deliberately exclude 0-RTT, whose effects require quarantine.
/// Consuming this affine value admits one numeric receive record; it cannot be
/// recreated from a key snapshot, packet number, or copied generation.
///
/// Evidence cannot be reused for another receive:
/// ```compile_fail
/// use hibana_quic::driver::ReceiveEvidence;
/// fn duplicate(receipt: ReceiveEvidence) {
///     let first = receipt;
///     let second = receipt;
/// }
/// ```
/// Early authentication cannot grant ordinary ACK/delivery authority:
/// ```compile_fail
/// use hibana_quic::{driver::ReceiveEvidence, roles::tls_owner::EarlyOpenReceipt};
/// fn substitute(early: EarlyOpenReceipt) -> ReceiveEvidence {
///     ReceiveEvidence::Tls(early)
/// }
/// ```
pub enum ReceiveEvidence {
    Initial(crate::roles::packet_protection::OpenReceipt),
    Tls(crate::roles::tls_owner::OpenReceipt),
}
impl ReceiveEvidence {
    fn generation(&self) -> Result<u64, DriverError> {
        match self {
            Self::Initial(opened) if opened.kind() == crate::crypto::KeyKind::Initial => {
                Ok(opened.generation())
            }
            Self::Tls(opened)
                if matches!(
                    opened.level(),
                    crate::tls::Level::Handshake | crate::tls::Level::OneRtt
                ) =>
            {
                Ok(opened.generation())
            }
            _ => Err(DriverError::InvalidTicket),
        }
    }
}

/// A handle checked against the driver's single live receive record. Copying
/// it does not create another right to complete a receive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiveTicket(Descriptor);
impl ReceiveTicket {
    pub const fn descriptor_id(self) -> u32 {
        self.0.id
    }
    pub const fn generation(self) -> u64 {
        self.0.generation
    }
}

/// A handle checked against the driver's single live transmit record. It is a
/// local descriptor-table ID, never a packet number truncated to 32 bits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransmitTicket(Descriptor);
impl TransmitTicket {
    pub const fn descriptor_id(self) -> u32 {
        self.0.id
    }
    pub const fn generation(self) -> u64 {
        self.0.generation
    }
}

/// One checked ACK effect bound to an authenticated receive record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AckTicket {
    descriptor: Descriptor,
    receive: ReceiveTicket,
}
impl AckTicket {
    pub const fn descriptor_id(self) -> u32 {
        self.descriptor.id
    }
    pub const fn generation(self) -> u64 {
        self.descriptor.generation
    }
}
/// One checked stream delivery, carrying a full-width QUIC stream identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryTicket {
    descriptor: Descriptor,
    receive: ReceiveTicket,
    stream_id: u64,
}
impl DeliveryTicket {
    pub const fn descriptor_id(self) -> u32 {
        self.descriptor.id
    }
    pub const fn generation(self) -> u64 {
        self.descriptor.generation
    }
    pub const fn stream_id(self) -> u64 {
        self.stream_id
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReceiveEffect {
    Ack(AckTicket),
    Delivery(DeliveryTicket),
    Path(PathEffectTicket),
    CidInstall(CidInstallTicket),
    CidRetirement(CidRetirementTicket),
}

#[derive(Clone, Copy, Debug)]
pub enum DriverError {
    Retired,
    ReceiveBusy,
    TransmitBusy,
    ReceiveEffectBusy,
    InvalidStreamId,
    InvalidTicket,
    ClockWentBackwards,
    DescriptorIdsExhausted,
    UnexpectedPending,
    DescriptorMismatch,
    Hibana(EndpointError),
}
impl DriverError {
    /// Fatal errors retire all roles. Busy, stale input, and backward time are
    /// rejected before any endpoint operation and leave the live work intact.
    pub const fn is_fatal(self) -> bool {
        matches!(
            self,
            Self::Retired
                | Self::DescriptorIdsExhausted
                | Self::UnexpectedPending
                | Self::DescriptorMismatch
                | Self::Hibana(_)
        )
    }
}

/// One connection's cooperative service owner, with at most one outstanding
/// receive and one transmit. Timers can progress during either outstanding
/// operation. Numeric QUIC state remains with the caller's connection owner.
pub struct Driver<'r> {
    roles: Option<Roles<'r>>,
    generation: u64,
    next_descriptor: Option<u32>,
    receive: Option<ReceiveTicket>,
    transmit: Option<TransmitTicket>,
    last_timer: Option<u64>,
    receive_effect: Option<ReceiveEffect>,
    early: early::State,
    path: path::State,
}
impl<'r> Driver<'r> {
    /// `generation` must distinguish this connection from other live drivers
    /// or retired drivers whose tickets can still arrive. All roles must come
    /// from the same rendezvous/session and unadvanced `service_program` image.
    pub fn new(generation: u64, roles: Roles<'r>) -> Self {
        Self {
            roles: Some(roles),
            generation,
            next_descriptor: Some(1),
            receive: None,
            transmit: None,
            last_timer: None,
            receive_effect: None,
            early: early::State::new(),
            path: path::State::new(),
        }
    }
    pub fn is_retired(&self) -> bool {
        self.roles.is_none()
    }
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub const fn receive_in_flight(&self) -> bool {
        self.receive.is_some()
    }
    pub const fn transmit_in_flight(&self) -> bool {
        self.transmit.is_some()
    }

    /// Retire the generation and discard all live descriptor rights. Dropping
    /// the endpoints causes the carrier to quarantine its pending frames and
    /// wake parked operations. Retirement is idempotent.
    pub fn retire(&mut self) {
        self.receive = None;
        self.transmit = None;
        self.receive_effect = None;
        self.early = early::State::retired();
        self.path = path::State::retired();
        drop(self.roles.take());
    }

    /// Consume successful owner-produced Open evidence before notifying
    /// Recovery. Full packet syntax, replay, ACK ranges and resource admission
    /// remain the connection's checked numerical obligations.
    pub fn begin_receive(&mut self, opened: ReceiveEvidence) -> Result<ReceiveTicket, DriverError> {
        self.ensure_live()?;
        if opened.generation()? != self.generation {
            return Err(DriverError::InvalidTicket);
        }
        if self.receive.is_some() || self.early.receiving() {
            return Err(DriverError::ReceiveBusy);
        }
        let descriptor = self.issue_descriptor()?;
        self.execute(|roles| {
            poll_ready(roles.ingress.send::<RxDatagram>(&descriptor.id))?;
            match_id(
                poll_ready(roles.packet.recv::<RxDatagram>())?,
                descriptor.id,
            )?;
            poll_ready(roles.packet.send::<AuthenticatedPacket>(&descriptor.id))?;
            match_id(
                poll_ready(roles.recovery.recv::<AuthenticatedPacket>())?,
                descriptor.id,
            )
        })?;
        let ticket = ReceiveTicket(descriptor);
        self.receive = Some(ticket);
        Ok(ticket)
    }

    /// Complete the authenticated effects for the exact live receive record
    /// (two bounded polls). A stale ticket cannot finish a newer receive.
    pub fn finish_receive(&mut self, ticket: ReceiveTicket) -> Result<(), DriverError> {
        self.ensure_live()?;
        if self.receive != Some(ticket) || ticket.generation() != self.generation {
            return Err(DriverError::InvalidTicket);
        }
        if self.receive_effect.is_some() {
            return Err(DriverError::ReceiveEffectBusy);
        }
        self.execute(|roles| {
            poll_ready(roles.packet.send::<RxProcessed>(&ticket.0.id))?;
            match_id(
                poll_ready(roles.ingress.recv::<RxProcessed>())?,
                ticket.0.id,
            )
        })?;
        self.receive = None;
        Ok(())
    }

    /// Record an already reserved accounting/buffer entry and grant its adapter
    /// publication step (four bounded polls). One Tx can await its callback.
    pub fn reserve_transmit(&mut self) -> Result<TransmitTicket, DriverError> {
        self.ensure_live()?;
        if self.transmit.is_some() {
            return Err(DriverError::TransmitBusy);
        }
        let descriptor = self.issue_descriptor()?;
        self.execute(|roles| {
            poll_ready(roles.application.send::<TxRequest>(&descriptor.id))?;
            match_id(
                poll_ready(roles.recovery.recv::<TxRequest>())?,
                descriptor.id,
            )?;
            poll_ready(roles.recovery.send::<TxReserved>(&descriptor.id))?;
            match_id(
                poll_ready(roles.adapter.recv::<TxReserved>())?,
                descriptor.id,
            )
        })?;
        let ticket = TransmitTicket(descriptor);
        self.transmit = Some(ticket);
        Ok(ticket)
    }

    /// Consume the matching adapter callback, whether it accepted or rejected
    /// the external datagram (four bounded polls). The caller applies the real
    /// adapter outcome to its accounting; this method does not invent success.
    pub fn adapter_result(&mut self, ticket: TransmitTicket) -> Result<(), DriverError> {
        self.ensure_live()?;
        if self.path.transmitting() {
            return Err(DriverError::TransmitBusy);
        }
        if self.transmit != Some(ticket) || ticket.generation() != self.generation {
            return Err(DriverError::InvalidTicket);
        }
        self.execute(|roles| {
            poll_ready(roles.adapter.send::<TxResult>(&ticket.0.id))?;
            match_id(poll_ready(roles.recovery.recv::<TxResult>())?, ticket.0.id)?;
            poll_ready(roles.recovery.send::<TxComplete>(&ticket.0.id))?;
            match_id(
                poll_ready(roles.application.recv::<TxComplete>())?,
                ticket.0.id,
            )
        })?;
        self.transmit = None;
        Ok(())
    }

    /// Deliver one injected monotonic timer observation (four bounded polls).
    /// Equal timestamps are legal; no OS time or sleep is hidden inside.
    pub fn timer(&mut self, now: u64) -> Result<(), DriverError> {
        self.ensure_live()?;
        if self.last_timer.is_some_and(|last| now < last) {
            return Err(DriverError::ClockWentBackwards);
        }
        self.path.supersede_timer()?;
        self.execute(|roles| {
            poll_ready(roles.timer.send::<TimerExpired>(&now))?;
            if poll_ready(roles.recovery.recv::<TimerExpired>())? != now {
                return Err(DriverError::DescriptorMismatch);
            }
            poll_ready(roles.recovery.send::<TimerHandled>(&now))?;
            if poll_ready(roles.timer.recv::<TimerHandled>())? != now {
                return Err(DriverError::DescriptorMismatch);
            }
            Ok(())
        })?;
        self.last_timer = Some(now);
        Ok(())
    }

    /// Grant an ACK mutation after the caller validates the complete ACK. The
    /// ticket must name the receive whose typed authentication notice was sent.
    pub fn begin_ack_release(&mut self, receive: ReceiveTicket) -> Result<AckTicket, DriverError> {
        self.validate_receive(receive)?;
        if self.receive_effect.is_some() {
            return Err(DriverError::ReceiveEffectBusy);
        }
        let ticket = AckTicket {
            descriptor: self.issue_descriptor()?,
            receive,
        };
        let wire = effect_descriptor(receive, ticket.descriptor);
        self.execute(|roles| {
            poll_ready(roles.packet.send::<AckReleaseRequest>(&wire))?;
            match_bytes(
                poll_ready(roles.recovery.recv::<AckReleaseRequest>())?,
                wire,
            )
        })?;
        self.receive_effect = Some(ReceiveEffect::Ack(ticket));
        Ok(ticket)
    }
    pub fn finish_ack_release(&mut self, ticket: AckTicket) -> Result<(), DriverError> {
        self.validate_receive(ticket.receive)?;
        if self.receive_effect != Some(ReceiveEffect::Ack(ticket)) {
            return Err(DriverError::InvalidTicket);
        }
        let wire = effect_descriptor(ticket.receive, ticket.descriptor);
        self.execute(|roles| {
            poll_ready(roles.recovery.send::<AckReleaseCompleted>(&wire))?;
            match_bytes(
                poll_ready(roles.packet.recv::<AckReleaseCompleted>())?,
                wire,
            )
        })?;
        self.receive_effect = None;
        Ok(())
    }
    /// Grant one stream-handler call using the complete 62-bit QUIC stream ID.
    pub fn begin_stream_delivery(
        &mut self,
        receive: ReceiveTicket,
        stream_id: u64,
    ) -> Result<DeliveryTicket, DriverError> {
        self.validate_receive(receive)?;
        if self.receive_effect.is_some() {
            return Err(DriverError::ReceiveEffectBusy);
        }
        if stream_id > (1_u64 << 62) - 1 {
            return Err(DriverError::InvalidStreamId);
        }
        let ticket = DeliveryTicket {
            descriptor: self.issue_descriptor()?,
            receive,
            stream_id,
        };
        let wire = delivery_descriptor(ticket);
        self.execute(|roles| {
            poll_ready(roles.packet.send::<DeliveryRequest>(&wire))?;
            match_bytes(
                poll_ready(roles.application.recv::<DeliveryRequest>())?,
                wire,
            )
        })?;
        self.receive_effect = Some(ReceiveEffect::Delivery(ticket));
        Ok(ticket)
    }
    pub fn finish_stream_delivery(&mut self, ticket: DeliveryTicket) -> Result<(), DriverError> {
        self.validate_receive(ticket.receive)?;
        if self.receive_effect != Some(ReceiveEffect::Delivery(ticket)) {
            return Err(DriverError::InvalidTicket);
        }
        let wire = delivery_descriptor(ticket);
        self.execute(|roles| {
            poll_ready(roles.application.send::<DeliveryCompleted>(&wire))?;
            match_bytes(poll_ready(roles.packet.recv::<DeliveryCompleted>())?, wire)
        })?;
        self.receive_effect = None;
        Ok(())
    }
    /// Emit actual stream-retirement notification and acknowledgement after
    /// StreamTable has confirmed both directions terminal and retired its slot.
    /// The table's bounded prefix/live ledger rejects reused stream IDs/handles;
    /// this driver does not keep an unbounded retired-ID set or prove that table.
    pub fn stream_retired(&mut self, stream_id: u64) -> Result<(), DriverError> {
        self.ensure_live()?;
        if stream_id > (1_u64 << 62) - 1 {
            return Err(DriverError::InvalidStreamId);
        }
        let descriptor = self.issue_descriptor()?;
        let mut wire = [0; 12];
        wire[..4].copy_from_slice(&descriptor.id.to_be_bytes());
        wire[4..].copy_from_slice(&stream_id.to_be_bytes());
        self.execute(|roles| {
            poll_ready(roles.application.send::<StreamRetiredRequest>(&wire))?;
            match_bytes(
                poll_ready(roles.recovery.recv::<StreamRetiredRequest>())?,
                wire,
            )?;
            poll_ready(roles.recovery.send::<StreamRetiredAcknowledged>(&wire))?;
            match_bytes(
                poll_ready(roles.application.recv::<StreamRetiredAcknowledged>())?,
                wire,
            )
        })
    }

    fn validate_receive(&self, receive: ReceiveTicket) -> Result<(), DriverError> {
        self.ensure_live()?;
        if self.receive != Some(receive) || receive.generation() != self.generation {
            return Err(DriverError::InvalidTicket);
        }
        Ok(())
    }

    fn ensure_live(&self) -> Result<(), DriverError> {
        if self.is_retired() {
            Err(DriverError::Retired)
        } else {
            Ok(())
        }
    }
    fn issue_descriptor(&mut self) -> Result<Descriptor, DriverError> {
        let Some(id) = self.next_descriptor else {
            self.retire();
            return Err(DriverError::DescriptorIdsExhausted);
        };
        self.next_descriptor = id.checked_add(1);
        Ok(Descriptor {
            generation: self.generation,
            id,
        })
    }
    fn execute<T>(
        &mut self,
        operation: impl FnOnce(&mut Roles<'r>) -> Result<T, DriverError>,
    ) -> Result<T, DriverError> {
        let result = operation(self.roles.as_mut().ok_or(DriverError::Retired)?);
        if result.is_err() {
            self.retire();
        }
        result
    }
}

fn effect_descriptor(receive: ReceiveTicket, descriptor: Descriptor) -> [u8; 8] {
    let mut wire = [0; 8];
    wire[..4].copy_from_slice(&receive.descriptor_id().to_be_bytes());
    wire[4..].copy_from_slice(&descriptor.id.to_be_bytes());
    wire
}
fn delivery_descriptor(ticket: DeliveryTicket) -> [u8; 16] {
    let mut wire = [0; 16];
    wire[..8].copy_from_slice(&effect_descriptor(ticket.receive, ticket.descriptor));
    wire[8..].copy_from_slice(&ticket.stream_id.to_be_bytes());
    wire
}
fn match_bytes<const N: usize>(observed: [u8; N], expected: [u8; N]) -> Result<(), DriverError> {
    if observed == expected {
        Ok(())
    } else {
        Err(DriverError::DescriptorMismatch)
    }
}

fn match_id(observed: u32, expected: u32) -> Result<(), DriverError> {
    if observed == expected {
        Ok(())
    } else {
        Err(DriverError::DescriptorMismatch)
    }
}
fn poll_ready<T>(future: impl Future<Output = Result<T, EndpointError>>) -> Result<T, DriverError> {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(Ok(value)) => Ok(value),
        Poll::Ready(Err(error)) => Err(DriverError::Hibana(error)),
        Poll::Pending => Err(DriverError::UnexpectedPending),
    }
    // `future` is dropped/cancelled before the caller can retire its roles.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        carrier::{CarrierStorage, LocalCarrier},
        protocol::service_program,
    };
    use hibana::runtime::{SessionKitStorage, ids::SessionId};

    pub(super) fn with_driver<const BYTES: usize, R>(
        generation: u64,
        f: impl FnOnce(
            &mut Driver<'_>,
            &CarrierStorage<1, BYTES, { crate::protocol::SERVICE_PORTS }>,
        ) -> R,
    ) -> R {
        let queues = CarrierStorage::<1, BYTES, { crate::protocol::SERVICE_PORTS }>::new();
        let sid = SessionId::new(1);
        let carrier = queues.bind(sid).unwrap();
        let mut slab = [0_u8; 32 * 1024];
        let mut storage = SessionKitStorage::<
            LocalCarrier<'_, 1, BYTES, { crate::protocol::SERVICE_PORTS }>,
        >::uninit();
        let kit = storage.init();
        let rv = kit.rendezvous(&mut slab, carrier).unwrap();
        let p0 = service_program::<INGRESS>();
        let p1 = service_program::<PACKET>();
        let p2 = service_program::<APPLICATION>();
        let p3 = service_program::<RECOVERY>();
        let p4 = service_program::<ADAPTER>();
        let p5 = service_program::<TIMER>();
        let roles = Roles {
            ingress: rv.enter(sid, &p0).unwrap(),
            packet: rv.enter(sid, &p1).unwrap(),
            application: rv.enter(sid, &p2).unwrap(),
            recovery: rv.enter(sid, &p3).unwrap(),
            adapter: rv.enter(sid, &p4).unwrap(),
            timer: rv.enter(sid, &p5).unwrap(),
        };
        let mut driver = Driver::new(generation, roles);
        f(&mut driver, &queues)
    }

    #[test]
    fn runtime_driver_progresses_independently_and_rejects_stale_completions() {
        with_driver::<16, _>(90, |driver, queues| {
            let rx = driver
                .begin_receive(super::test_support::initial(driver.generation()))
                .unwrap();
            let tx = driver.reserve_transmit().unwrap();
            assert!(driver.receive_in_flight());
            assert!(driver.transmit_in_flight());
            assert!(matches!(
                driver.begin_receive(super::test_support::initial(driver.generation())),
                Err(DriverError::ReceiveBusy)
            ));
            assert!(matches!(
                driver.reserve_transmit(),
                Err(DriverError::TransmitBusy)
            ));
            for now in [10, 11, 11, 12] {
                driver.timer(now).unwrap();
            }
            assert!(matches!(
                driver.timer(11),
                Err(DriverError::ClockWentBackwards)
            ));
            driver.finish_receive(rx).unwrap();
            let next_rx = driver
                .begin_receive(super::test_support::initial(driver.generation()))
                .unwrap();
            assert_ne!(rx.descriptor_id(), next_rx.descriptor_id());
            assert!(matches!(
                driver.finish_receive(rx),
                Err(DriverError::InvalidTicket)
            ));
            driver.finish_receive(next_rx).unwrap();
            driver.adapter_result(tx).unwrap();
            let next_tx = driver.reserve_transmit().unwrap();
            assert_ne!(tx.descriptor_id(), next_tx.descriptor_id());
            assert!(matches!(
                driver.adapter_result(tx),
                Err(DriverError::InvalidTicket)
            ));
            driver.timer(13).unwrap();
            driver.adapter_result(next_tx).unwrap();
            assert!(!driver.receive_in_flight());
            assert!(!driver.transmit_in_flight());
            assert!(!driver.is_retired());
            assert_eq!(queues.queued(), 0);
        });
    }

    #[test]
    fn retired_and_wrong_generation_tickets_cannot_advance_runtime() {
        let stale = with_driver::<16, _>(100, |driver, _| driver.reserve_transmit().unwrap());
        with_driver::<16, _>(101, |driver, queues| {
            let current = driver.reserve_transmit().unwrap();
            assert_eq!(
                stale.descriptor_id(),
                current.descriptor_id(),
                "numeric table index alone is insufficient"
            );
            assert!(matches!(
                driver.adapter_result(stale),
                Err(DriverError::InvalidTicket)
            ));
            assert!(driver.transmit_in_flight());
            driver.adapter_result(current).unwrap();
            let rx = driver
                .begin_receive(super::test_support::initial(driver.generation()))
                .unwrap();
            driver.retire();
            assert!(queues.is_closed());
            assert!(matches!(
                driver.begin_receive(super::test_support::initial(driver.generation())),
                Err(DriverError::Retired)
            ));
            assert!(matches!(
                driver.finish_receive(rx),
                Err(DriverError::Retired)
            ));
            assert!(matches!(
                driver.reserve_transmit(),
                Err(DriverError::Retired)
            ));
            assert!(matches!(
                driver.adapter_result(current),
                Err(DriverError::Retired)
            ));
            assert!(matches!(driver.timer(20), Err(DriverError::Retired)));
            driver.retire();
        });
    }

    #[test]
    fn finite_descriptor_namespace_exhaustion_is_terminal_not_wraparound() {
        with_driver::<16, _>(102, |driver, queues| {
            driver.next_descriptor = Some(u32::MAX);
            let last = driver
                .begin_receive(super::test_support::initial(driver.generation()))
                .unwrap();
            assert_eq!(last.descriptor_id(), u32::MAX);
            driver.finish_receive(last).unwrap();
            assert!(matches!(
                driver.reserve_transmit(),
                Err(DriverError::DescriptorIdsExhausted)
            ));
            assert!(driver.is_retired());
            assert!(queues.is_closed());
        });
    }

    #[test]
    fn insufficient_carrier_payload_capacity_fails_closed_without_ticket() {
        with_driver::<0, _>(103, |driver, queues| {
            assert!(matches!(
                driver.reserve_transmit(),
                Err(DriverError::Hibana(_))
            ));
            assert!(driver.is_retired());
            assert!(!driver.transmit_in_flight());
            assert!(queues.is_closed());
            assert_eq!(queues.queued(), 0);
        });
    }

    // Deliberately blocked receive fixture: the first message is accepted by
    // the real carrier before the receive unexpectedly parks. The driver must
    // quarantine it on retirement instead of issuing a successful ticket.
    struct BlockReceive {
        inner: LocalCarrier<'static, 1, 16, { crate::protocol::SERVICE_PORTS }>,
        waiter: core::cell::RefCell<Option<Waker>>,
    }
    impl hibana::runtime::transport::Transport for BlockReceive {
        type Tx<'a>
            = crate::carrier::Sender<'a, 1, 16, { crate::protocol::SERVICE_PORTS }>
        where
            Self: 'a;
        type Rx<'a>
            = crate::carrier::Receiver<'a, 1, 16, { crate::protocol::SERVICE_PORTS }>
        where
            Self: 'a;
        fn open<'a>(
            &'a self,
            port: hibana::runtime::transport::PortOpen,
        ) -> (Self::Tx<'a>, Self::Rx<'a>) {
            self.inner.open(port)
        }
        fn poll_send<'a, 'f>(
            &self,
            tx: &'a mut crate::carrier::Sender<'a, 1, 16, { crate::protocol::SERVICE_PORTS }>,
            outgoing: hibana::runtime::transport::Outgoing<'f>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), hibana::runtime::transport::TransportError>>
        where
            'a: 'f,
        {
            self.inner.poll_send(tx, outgoing, cx)
        }
        fn cancel_send<'a>(
            &self,
            tx: &'a mut crate::carrier::Sender<'a, 1, 16, { crate::protocol::SERVICE_PORTS }>,
        ) {
            self.inner.cancel_send(tx);
        }
        fn poll_recv<'a>(
            &'a self,
            _rx: &'a mut Self::Rx<'a>,
            cx: &mut Context<'_>,
        ) -> Poll<
            Result<
                hibana::runtime::transport::ReceivedFrame<'a>,
                hibana::runtime::transport::TransportError,
            >,
        > {
            let next = cx.waker().clone();
            let old = self.waiter.replace(Some(next));
            drop(old);
            Poll::Pending
        }
        fn requeue<'a>(
            &self,
            rx: &mut crate::carrier::Receiver<'a, 1, 16, { crate::protocol::SERVICE_PORTS }>,
        ) -> Result<(), hibana::runtime::transport::TransportError> {
            self.inner.requeue(rx)
        }
    }

    #[test]
    fn unexpected_pending_after_carrier_acceptance_retires_without_ghost_success() {
        let queues = std::boxed::Box::leak(std::boxed::Box::new(CarrierStorage::<
            1,
            16,
            { crate::protocol::SERVICE_PORTS },
        >::new()));
        let sid = SessionId::new(2);
        let carrier = BlockReceive {
            inner: queues.bind(sid).unwrap(),
            waiter: core::cell::RefCell::new(None),
        };
        let mut slab = [0_u8; 32 * 1024];
        let mut storage = SessionKitStorage::<BlockReceive>::uninit();
        let kit = storage.init();
        let rv = kit.rendezvous(&mut slab, carrier).unwrap();
        let p0 = service_program::<INGRESS>();
        let p1 = service_program::<PACKET>();
        let p2 = service_program::<APPLICATION>();
        let p3 = service_program::<RECOVERY>();
        let p4 = service_program::<ADAPTER>();
        let p5 = service_program::<TIMER>();
        let roles = Roles {
            ingress: rv.enter(sid, &p0).unwrap(),
            packet: rv.enter(sid, &p1).unwrap(),
            application: rv.enter(sid, &p2).unwrap(),
            recovery: rv.enter(sid, &p3).unwrap(),
            adapter: rv.enter(sid, &p4).unwrap(),
            timer: rv.enter(sid, &p5).unwrap(),
        };
        let mut driver = Driver::new(104, roles);
        assert!(matches!(
            driver.begin_receive(super::test_support::initial(driver.generation())),
            Err(DriverError::UnexpectedPending)
        ));
        assert!(driver.is_retired());
        assert!(queues.is_closed());
        assert_eq!(queues.queued(), 0);
        assert!(!driver.receive_in_flight());
        assert!(matches!(driver.timer(1), Err(DriverError::Retired)));
    }
    #[test]
    fn only_matching_generation_and_ordinary_actor_receipts_admit_receive() {
        with_driver::<16, _>(119, |driver, queues| {
            assert!(matches!(
                driver.begin_receive(super::test_support::initial(120)),
                Err(DriverError::InvalidTicket)
            ));
            assert!(matches!(
                driver.begin_receive(super::test_support::key_evidence(
                    119,
                    crate::crypto::KeyKind::ZeroRtt
                )),
                Err(DriverError::InvalidTicket)
            ));
            assert!(!driver.receive_in_flight());
            assert!(!driver.is_retired());
            let receive = driver
                .begin_receive(super::test_support::initial(119))
                .unwrap();
            driver.finish_receive(receive).unwrap();
            assert_eq!(queues.queued(), 0);
        });
    }

    #[test]
    fn ack_and_delivery_require_live_authenticated_receive_and_exact_effect_ticket() {
        with_driver::<16, _>(120, |driver, queues| {
            let absent = ReceiveTicket(Descriptor {
                generation: 120,
                id: 999,
            });
            assert!(matches!(
                driver.begin_ack_release(absent),
                Err(DriverError::InvalidTicket)
            ));
            assert!(matches!(
                driver.begin_stream_delivery(absent, 3),
                Err(DriverError::InvalidTicket)
            ));
            assert_eq!(queues.queued(), 0);
            let receive = driver
                .begin_receive(super::test_support::initial(driver.generation()))
                .unwrap();
            let ack = driver.begin_ack_release(receive).unwrap();
            assert!(matches!(
                driver.begin_ack_release(receive),
                Err(DriverError::ReceiveEffectBusy)
            ));
            assert!(matches!(
                driver.begin_stream_delivery(receive, 3),
                Err(DriverError::ReceiveEffectBusy)
            ));
            assert!(matches!(
                driver.finish_receive(receive),
                Err(DriverError::ReceiveEffectBusy)
            ));
            driver.timer(100).unwrap();
            driver.finish_ack_release(ack).unwrap();
            assert!(matches!(
                driver.finish_ack_release(ack),
                Err(DriverError::InvalidTicket)
            ));
            let stream_id = (1_u64 << 60) + 3;
            let delivery = driver.begin_stream_delivery(receive, stream_id).unwrap();
            assert_eq!(
                delivery.stream_id(),
                stream_id,
                "full-width stream ID survives typed payload"
            );
            assert!(matches!(
                driver.finish_receive(receive),
                Err(DriverError::ReceiveEffectBusy)
            ));
            driver.finish_stream_delivery(delivery).unwrap();
            assert!(matches!(
                driver.finish_stream_delivery(delivery),
                Err(DriverError::InvalidTicket)
            ));
            driver.finish_receive(receive).unwrap();
            assert!(matches!(
                driver.begin_ack_release(receive),
                Err(DriverError::InvalidTicket)
            ));
            assert!(matches!(
                driver.begin_stream_delivery(receive, 3),
                Err(DriverError::InvalidTicket)
            ));
            let following = driver
                .begin_receive(super::test_support::initial(driver.generation()))
                .unwrap();
            assert!(matches!(
                driver.finish_ack_release(ack),
                Err(DriverError::InvalidTicket)
            ));
            assert!(matches!(
                driver.begin_stream_delivery(following, 1_u64 << 62),
                Err(DriverError::InvalidStreamId)
            ));
            let last = driver.begin_stream_delivery(following, 7).unwrap();
            driver.retire();
            assert!(matches!(
                driver.finish_stream_delivery(last),
                Err(DriverError::Retired)
            ));
            assert!(matches!(
                driver.finish_receive(following),
                Err(DriverError::Retired)
            ));
            assert!(queues.is_closed());
        });
    }

    #[test]
    fn complete_service_profile_fits_declared_slab_ports_and_message_budget() {
        with_driver::<16, _>(121, |driver, queues| {
            let receive = driver
                .begin_receive(super::test_support::initial(driver.generation()))
                .unwrap();
            let ack = driver.begin_ack_release(receive).unwrap();
            driver.finish_ack_release(ack).unwrap();
            let delivery = driver
                .begin_stream_delivery(receive, (1_u64 << 62) - 1)
                .unwrap();
            driver.finish_stream_delivery(delivery).unwrap();
            driver.finish_receive(receive).unwrap();
            for id in [0, 4, 8, (1_u64 << 62) - 1] {
                driver.stream_retired(id).unwrap();
            }
            assert!(matches!(
                driver.stream_retired(1_u64 << 62),
                Err(DriverError::InvalidStreamId)
            ));
            let tx = driver.reserve_transmit().unwrap();
            driver.timer(1).unwrap();
            driver.adapter_result(tx).unwrap();
            assert!(!driver.is_retired());
            assert_eq!(queues.queued(), 0);
        });
    }
}
