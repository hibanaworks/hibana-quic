//! Endpoint ownership and attachment for this global's localsides.
//!
//! [`Endpoints`] lists the actual affine endpoints and their consumers.
//! [`Endpoints::attach`] creates them from projected [`global::Programs`].
//! [`run`] constructs the actual futures, moves/borrows their resources, joins
//! the concurrent localsides, and completes their ordered retirement.
//! The outer executor polls those futures; endpoint operations enforce the global.
mod acknowledgments;
mod early;
mod early_client;
mod http3;
mod io;
pub(super) mod keys;
pub(super) mod ownership;
mod receive;
pub(in crate::quic) mod reclaim;
mod reset;
mod termination;
mod timer;
mod transmit;

use super::*;
use crate::quic;
use crate::quic::Clock;
use crate::quic::ConnectionId;
use crate::quic::DatagramRx;
use crate::quic::DatagramTx;
use crate::quic::Side;
use crate::quic::Storage;
use crate::quic::application::imp::stream;
use crate::quic::application::imp::stream::StreamNumbers;
use crate::quic::imp::kernel::streams;
use crate::quic::imp::publication_gate::Issuer;
use crate::quic::imp::publication_gate::Stop;
use crate::quic::imp::recovery::Recovery;
use crate::quic::imp::tls::Transcript;
use crate::runtime::mailbox::Mailbox;
use core::cell::RefCell;

/// The connection's affine endpoints, indexed by the roles in [`global`].
pub struct Endpoints<'a> {
    /// ECN observation and validation localside.
    pub ecn_owner: Endpoint<'a, { crate::quic::ecn::global::OWNER }>,
    /// The same handshake endpoints continue into the connected application graph.
    pub handshake: crate::quic::local::Endpoints<'a>,
    /// Client request source or server response source, selected for this endpoint side.
    pub source: Endpoint<'a, { global::SOURCE }>,
    /// Actual source retirement consumed by the completion localside.
    pub source_join: Endpoint<'a, { global::SOURCE_JOIN }>,
    /// Ingress localside that receives and hands off stream chunks.
    pub ingress: Endpoint<'a, { global::INGRESS }>,
    /// Authenticated packet receive localside.
    pub receive: Endpoint<'a, { global::RECEIVE }>,
    /// Client response sink or server request sink.
    pub sink: Endpoint<'a, { global::SINK }>,
    /// Read-key operations owned by receive, then affine key retirement.
    pub rx_keys: Endpoint<'a, { global::RX_KEYS }>,
    /// Write-key owner localside.
    pub tx_keys: Endpoint<'a, { global::TX_KEYS }>,
    /// Independent loss/PTO timer localside.
    pub clock: Endpoint<'a, { global::CLOCK }>,
    /// Timer-event receiver; remains runnable during a pending UDP send.
    pub tx_clock: Endpoint<'a, { global::TX_CLOCK }>,
    /// Packet preparation localside, then the closing continuation.
    pub transmit: Endpoint<'a, { global::TRANSMIT }>,
    /// Physical publication localside, then closing publication and draining.
    pub adapter: Endpoint<'a, { global::ADAPTER }>,
    /// Peer terminal observation emitted by the receive localside.
    pub peer_event: Endpoint<'a, { global::PEER_EVENT }>,
    /// Consumes peer terminal permission before retirement.
    pub peer_close: Endpoint<'a, { global::PEER_CLOSE }>,
    /// Application completion and idle-timeout observation localside.
    pub files_event: Endpoint<'a, { global::FILES_EVENT }>,
    /// Consumes the actual application terminal permission.
    pub files_close: Endpoint<'a, { global::FILES_CLOSE }>,
    /// Joins publication, key and terminal retirement grants before closing.
    pub close_join: Endpoint<'a, { global::CLOSE_JOIN }>,
    /// Retires actual source-owned buffers.
    pub source_collector: Endpoint<'a, { global::SOURCE_COLLECTOR }>,
    /// Retires actual input-owned buffers.
    pub input_collector: Endpoint<'a, { global::INPUT_COLLECTOR }>,
    /// Retires actual delivery-owned buffers.
    pub delivery_collector: Endpoint<'a, { global::DELIVERY_COLLECTOR }>,
}

use crate::quic::AttachmentError;

use hibana::runtime::{RendezvousKit, ids::SessionId, transport::Transport};

impl<'kit> Endpoints<'kit> {
    /// Bind the complete handshake/application graph to an existing session.
    /// Keep outcomes and session storage alive until all locals have retired.
    /// An attachment failure is terminal for this attempted session.
    pub fn attach<'cfg: 'kit, T: Transport + 'cfg>(
        rendezvous: &RendezvousKit<'kit, 'cfg, T>,
        session: SessionId,
        programs: &global::Programs,
        outcomes: &'cfg Outcomes,
    ) -> Result<Self, AttachmentError> {
        rendezvous
            .set_resolver(
                &programs.adapter,
                outcomes
                    .application_adapter
                    .resolver::<{ global::SUBMISSION_RESULT }>(),
            )
            .map_err(AttachmentError::Resolver)?;
        rendezvous
            .set_resolver(
                &programs.adapter,
                outcomes
                    .application_reset
                    .resolver::<{ global::STOP_RESULT }>(),
            )
            .map_err(AttachmentError::Resolver)?;
        macro_rules! enter {
            ($program:expr) => {
                rendezvous
                    .enter(session, &$program)
                    .map_err(AttachmentError::Endpoint)?
            };
        }
        Ok(Self {
            ecn_owner: enter!(programs.ecn_owner),
            handshake: crate::quic::local::Endpoints::attach(
                rendezvous,
                session,
                &programs.handshake,
                &outcomes.handshake_adapter,
            )?,
            source: enter!(programs.source),
            source_join: enter!(programs.source_join),
            ingress: enter!(programs.ingress),
            receive: enter!(programs.receive),
            sink: enter!(programs.sink),
            rx_keys: enter!(programs.rx_keys),
            tx_keys: enter!(programs.tx_keys),
            clock: enter!(programs.clock),
            tx_clock: enter!(programs.tx_clock),
            transmit: enter!(programs.transmit),
            adapter: enter!(programs.adapter),
            peer_event: enter!(programs.peer_event),
            peer_close: enter!(programs.peer_close),
            files_event: enter!(programs.files_event),
            files_close: enter!(programs.files_close),
            close_join: enter!(programs.close_join),
            source_collector: enter!(programs.source_collector),
            input_collector: enter!(programs.input_collector),
            delivery_collector: enter!(programs.delivery_collector),
        })
    }
}

/// Actual localside composition, including concurrent polling and retirement.
pub mod run;
pub use run::{client, client_early, server, server_stream};

/// Own and attach bounded resources using any executor-neutral I/O capability.
#[cfg(feature = "alloc")]
pub mod owned;

/// Allocation-free connection attachment with caller-owned memory.
pub mod borrowed;
