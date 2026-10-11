//! Endpoint ownership and attachment for this global's localsides.
//!
//! [`Endpoints`] lists the actual affine endpoints and their consumers.
//! [`Endpoints::attach`] creates them by projecting [`global::choreography`] for each Role and entering the session.
//! [`run`] constructs the actual futures, moves/borrows their resources, joins
//! the concurrent localsides, and completes their ordered retirement.
//! The outer executor polls those futures; endpoint operations enforce the global.
use super::global as p;
use super::wire::WriteKeys;
use super::*;
use crate::crypto::directional::ApplicationKeyScope;
use crate::quic::imp::kernel::packet::Frame;
use crate::quic::imp::kernel::parameters::Parameters;
use crate::quic::imp::kernel::parameters::Peer;
use core::{future::Future, pin::pin};
use hibana::g::Message;

pub(crate) mod timer;
pub(crate) mod transcript;
use crate::quic::retry::localside::client as retry_client;
mod publication;
mod receive;
mod transmit;
use crate::quic::imp::sealing::prepare;
use crate::quic::imp::sealing::{RecoveryPacket, prepare_recovery_packet};
pub(super) use publication::publish;
pub(super) use receive::receive;
pub(super) use transmit::transmit;

/// The connection's affine endpoints, indexed by the endpoints in [`global`].
pub struct Endpoints<'a> {
    /// Packet receive continuation; also owns receive-stop acknowledgment.
    pub rx: Endpoint<'a, { global::RX }>,
    /// TLS transcript receive continuation.
    pub tls_rx: Endpoint<'a, { global::TLS_RX }>,
    /// Packet preparation and transmission continuation.
    pub tx: Endpoint<'a, { global::TX }>,
    /// Retry/early startup, then the TLS transcript transmit continuation.
    pub tls_tx: Endpoint<'a, { global::TLS_TX }>,
    /// TLS transmit completion, consumed before key handoff.
    pub tls_complete: Endpoint<'a, { global::TLS_COMPLETE }>,
    /// Transfers actual authenticated key and Finished ownership.
    pub tls_handoff: Endpoint<'a, { global::TLS_HANDOFF }>,
    /// Physical publication continuation; shares no endpoint with the packet producer.
    pub udp: Endpoint<'a, { global::UDP }>,
    /// Loss/PTO clock continuation.
    pub timer: Endpoint<'a, { global::TIMER }>,
    /// Initial-key retirement event.
    pub initial_event: Endpoint<'a, { global::INITIAL_EVENT }>,
    /// Initial-key retirement owner.
    pub initial_owner: Endpoint<'a, { global::INITIAL_OWNER }>,
    /// Clock retirement acknowledgment.
    pub timer_stop: Endpoint<'a, { global::TIMER_STOP }>,
    /// Receive retirement acknowledgment.
    pub receive_stop: Endpoint<'a, { global::RECEIVE_STOP }>,
    /// Independent receiver of loss/PTO events.
    pub timer_tx: Endpoint<'a, { global::TIMER_TX }>,
    /// Publication admission and settlement owned by the transmit continuation.
    pub tx_wire: Endpoint<'a, { global::TX_WIRE }>,
}

#[derive(Debug)]
pub enum AttachmentError {
    Resolver(hibana::runtime::resolver::ResolverError),
    Endpoint(hibana::runtime::AttachError),
}

use hibana::runtime::{RendezvousKit, ids::SessionId, transport::Transport};

impl<'kit> Endpoints<'kit> {
    /// Bind the handshake role set and its one physical submission resolver.
    /// The returned endpoints borrow the caller's session; this does not run a
    /// handshake, allocate a carrier or create an additional progress owner.
    pub fn attach<'cfg: 'kit, T: Transport + 'cfg>(
        rendezvous: &RendezvousKit<'kit, 'cfg, T>,
        session: SessionId,
        graph: &impl hibana::runtime::program::Projectable,
        outcome: &'cfg Outcome,
    ) -> Result<Self, AttachmentError> {
        let rx = hibana::runtime::program::project(graph);
        let tls_rx = hibana::runtime::program::project(graph);
        let tx = hibana::runtime::program::project(graph);
        let tls_tx = hibana::runtime::program::project(graph);
        let tls_complete = hibana::runtime::program::project(graph);
        let tls_handoff = hibana::runtime::program::project(graph);
        let udp = hibana::runtime::program::project(graph);
        let timer = hibana::runtime::program::project(graph);
        let timer_tx = hibana::runtime::program::project(graph);
        let tx_wire = hibana::runtime::program::project(graph);
        let initial_event = hibana::runtime::program::project(graph);
        let initial_owner = hibana::runtime::program::project(graph);
        let timer_stop = hibana::runtime::program::project(graph);
        let receive_stop = hibana::runtime::program::project(graph);
        rendezvous
            .set_resolver(&udp, outcome.resolver::<{ global::ADAPTER_RESULT }>())
            .map_err(AttachmentError::Resolver)?;
        macro_rules! enter {
            ($name:ident) => {
                rendezvous
                    .enter(session, &$name)
                    .map_err(AttachmentError::Endpoint)?
            };
        }
        Ok(Self {
            rx: enter!(rx),
            tls_rx: enter!(tls_rx),
            tx: enter!(tx),
            tx_wire: enter!(tx_wire),
            tls_tx: enter!(tls_tx),
            tls_complete: enter!(tls_complete),
            tls_handoff: enter!(tls_handoff),
            udp: enter!(udp),
            timer: enter!(timer),
            timer_tx: enter!(timer_tx),
            initial_event: enter!(initial_event),
            initial_owner: enter!(initial_owner),
            timer_stop: enter!(timer_stop),
            receive_stop: enter!(receive_stop),
        })
    }
}

/// Actual localside composition, including concurrent polling and retirement.
pub mod run;
pub use run::handshake;
pub(crate) use run::handshake_with_early;

pub(crate) mod initial;

pub mod early_client;

/// Allocator-backed handshake resource owner.
pub mod owned;
