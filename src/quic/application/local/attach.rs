//! One canonical attachment of all projected application roles.
//! Resolver installation and endpoint creation happen before any local runs.
use crate::quic::AttachmentError;
use crate::quic::application::{Outcomes, Roles, global};
use hibana::runtime::{RendezvousKit, ids::SessionId, transport::Transport};

impl<'kit> Roles<'kit> {
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
            handshake: crate::quic::Roles::attach(
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
