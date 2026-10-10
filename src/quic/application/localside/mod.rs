//! Endpoint ownership and attachment for this global's localsides.
//!
//! [`Endpoints`] lists the actual affine endpoints and their consumers.
//! [`Endpoints::attach`] creates them by projecting [`global::choreography`] for each Role and entering the session.
//! [`run`] constructs the actual futures, moves/borrows their resources, joins
//! the concurrent localsides, and completes their ordered retirement.
//! The outer executor polls those futures; endpoint operations enforce the global.
use crate::quic::application::imp::acknowledgments;
mod early;
mod early_client;
mod ingress;
#[cfg(test)]
mod io_tests;
pub(super) mod keys;
pub(super) mod ownership;
mod receive;
pub(in crate::quic) mod reclaim;
mod sink;
mod source;
use crate::quic::application::imp::reset;
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

/// The connection's affine endpoints, indexed by the endpoints in [`global`].
pub struct Endpoints<'a> {
    /// Path validation endpoint.
    pub path_owner: Endpoint<'a, { crate::quic::path::global::OWNER }>,
    /// HTTP/3 control endpoint.
    pub http3_owner: Endpoint<'a, { crate::http3::global::OWNER }>,
    /// ECN observation and validation localside.
    pub ecn_owner: Endpoint<'a, { crate::quic::ecn::global::OWNER }>,
    /// The same handshake endpoints continue into the connected application graph.
    pub handshake: crate::quic::localside::Endpoints<'a>,
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
        graph: &impl hibana::runtime::program::Projectable,
        outcomes: &'cfg Outcomes,
    ) -> Result<Self, AttachmentError> {
        let path_owner = hibana::runtime::program::project(graph);
        let http3_owner = hibana::runtime::program::project(graph);
        let ecn_owner = hibana::runtime::program::project(graph);
        let source = hibana::runtime::program::project(graph);
        let source_join = hibana::runtime::program::project(graph);
        let ingress = hibana::runtime::program::project(graph);
        let receive = hibana::runtime::program::project(graph);
        let sink = hibana::runtime::program::project(graph);
        let rx_keys = hibana::runtime::program::project(graph);
        let tx_keys = hibana::runtime::program::project(graph);
        let clock = hibana::runtime::program::project(graph);
        let tx_clock = hibana::runtime::program::project(graph);
        let transmit = hibana::runtime::program::project(graph);
        let adapter = hibana::runtime::program::project(graph);
        let peer_event = hibana::runtime::program::project(graph);
        let peer_close = hibana::runtime::program::project(graph);
        let files_event = hibana::runtime::program::project(graph);
        let files_close = hibana::runtime::program::project(graph);
        let close_join = hibana::runtime::program::project(graph);
        let source_collector = hibana::runtime::program::project(graph);
        let input_collector = hibana::runtime::program::project(graph);
        let delivery_collector = hibana::runtime::program::project(graph);
        rendezvous
            .set_resolver(
                &adapter,
                outcomes
                    .application_adapter
                    .resolver::<{ global::SUBMISSION_RESULT }>(),
            )
            .map_err(AttachmentError::Resolver)?;
        rendezvous
            .set_resolver(
                &adapter,
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
            path_owner: enter!(path_owner),
            http3_owner: enter!(http3_owner),
            ecn_owner: enter!(ecn_owner),
            handshake: crate::quic::localside::Endpoints::attach(
                rendezvous,
                session,
                graph,
                &outcomes.handshake_adapter,
            )?,
            source: enter!(source),
            source_join: enter!(source_join),
            ingress: enter!(ingress),
            receive: enter!(receive),
            sink: enter!(sink),
            rx_keys: enter!(rx_keys),
            tx_keys: enter!(tx_keys),
            clock: enter!(clock),
            tx_clock: enter!(tx_clock),
            transmit: enter!(transmit),
            adapter: enter!(adapter),
            peer_event: enter!(peer_event),
            peer_close: enter!(peer_close),
            files_event: enter!(files_event),
            files_close: enter!(files_close),
            close_join: enter!(close_join),
            source_collector: enter!(source_collector),
            input_collector: enter!(input_collector),
            delivery_collector: enter!(delivery_collector),
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
