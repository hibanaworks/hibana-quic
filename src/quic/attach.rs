//! Attach the projected roles to caller-owned Hibana session storage.
//! No role is polled here. Errors require dropping this attempted session;
//! partially attached endpoints must never be reused as a successful connection.
use super::{Outcome, Roles, global};
use hibana::runtime::{RendezvousKit, ids::SessionId, transport::Transport};

#[derive(Debug)]
pub enum Error {
    Resolver(hibana::runtime::resolver::ResolverError),
    Endpoint(hibana::runtime::AttachError),
}

impl<'kit> Roles<'kit> {
    /// Bind the handshake role set and its one physical submission resolver.
    /// The returned endpoints borrow the caller's session; this does not run a
    /// handshake, allocate a carrier or create an additional progress owner.
    pub fn attach<'cfg: 'kit, T: Transport + 'cfg>(
        rendezvous: &RendezvousKit<'kit, 'cfg, T>,
        session: SessionId,
        programs: &global::Programs,
        outcome: &'cfg Outcome,
    ) -> Result<Self, Error> {
        rendezvous
            .set_resolver(
                &programs.udp,
                outcome.resolver::<{ global::ADAPTER_RESULT }>(),
            )
            .map_err(Error::Resolver)?;
        macro_rules! enter {
            ($name:ident) => {
                rendezvous
                    .enter(session, &programs.$name)
                    .map_err(Error::Endpoint)?
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
