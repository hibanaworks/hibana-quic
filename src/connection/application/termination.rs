//! APPROXIMATE RECOVERY ARTIFACT: reconstructed from the coordinator's design
//! after execution storage loss. This file has not been compiled or tested.
//!
//! Independent peer and application terminal edges carry actual affine close
//! permissions. Wire payloads are correlation observations, never authority.
use super::{CloseKind, Control, Error, io, protocol as p};
use crate::{
    connection::{Side, application_stream::App, tls::Inbox},
    crypto::directional::ApplicationKeyScope,
};
use core::{
    cell::RefCell,
    future::{Future, poll_fn},
    pin::pin,
    task::Poll,
};
use hibana::Endpoint;

/// Only these trusted producer continuations construct terminal permission.
/// It cannot be cloned or reconstructed from a copied error code or sequence.
pub(crate) struct Permission<'scope> {
    scope: &'scope ApplicationKeyScope,
    kind: CloseKind,
}

impl<'scope> Permission<'scope> {
    pub(crate) fn scope(&self) -> &'scope ApplicationKeyScope { self.scope }
    pub(crate) fn kind(&self) -> CloseKind { self.kind }
}

pub(crate) struct Exchange<'a, 'gate, 'scope> {
    control: &'a Control<'gate, 'scope>,
    scope: &'scope ApplicationKeyScope,
    peer: Inbox<Permission<'scope>>,
    files: Inbox<Permission<'scope>>,
}

impl<'a, 'gate, 'scope> Exchange<'a, 'gate, 'scope> {
    pub(crate) const fn new(
        control: &'a Control<'gate, 'scope>,
        scope: &'scope ApplicationKeyScope,
    ) -> Self {
        Self {
            control,
            scope,
            peer: Inbox::new(),
            files: Inbox::new(),
        }
    }

    fn check_scope(&self, scope: &ApplicationKeyScope) -> Result<(), Error> {
        if core::ptr::eq(self.scope, scope) {
            Ok(())
        } else {
            Err(Error::Binding)
        }
    }

    fn apply(&self, permission: &Permission<'scope>) -> Result<(), Error> {
        self.check_scope(permission.scope)?;
        self.control.revoke()
    }

    fn sequence(&self) -> u64 {
        self.scope.connection_generation()
    }
}

/// Called only by RX after actual packet authentication and frame validation.
pub(crate) async fn peer_close<'scope>(
    endpoint: &mut Endpoint<'_, { p::PEER_EVENT }>,
    exchange: &Exchange<'_, '_, 'scope>,
    scope: &'scope ApplicationKeyScope,
    code: u64,
) -> Result<(), Error> {
    exchange.check_scope(scope)?;
    exchange
        .peer
        .put(Permission { scope, kind: CloseKind::Peer { code } })
        .map_err(|_| Error::Binding)?;
    let sequence = exchange.sequence();
    endpoint.send::<p::PeerClose>(&sequence).await?;
    exchange.control.revoke()?;
    check(endpoint.recv::<p::PeerSeen>().await?, sequence)
}

/// An authenticated protocol violation requests a transport CONNECTION_CLOSE.
/// This private producer is not available to arbitrary callers with raw bytes.
pub(crate) async fn protocol_failed<'scope>(
    endpoint: &mut Endpoint<'_, { p::PEER_EVENT }>,
    exchange: &Exchange<'_, '_, 'scope>,
    scope: &'scope ApplicationKeyScope,
    code: u64,
) -> Result<(), Error> {
    exchange.check_scope(scope)?;
    exchange
        .peer
        .put(Permission {
            scope,
            kind: CloseKind::Local { application: false, code },
        })
        .map_err(|_| Error::Binding)?;
    let sequence = exchange.sequence();
    endpoint.send::<p::PeerFailed>(&sequence).await?;
    exchange.control.revoke()?;
    check(endpoint.recv::<p::PeerSeen>().await?, sequence)
}

/// Cancellation is a separate global arm and carries no close permission.
pub(crate) async fn cancel_peer(
    endpoint: &mut Endpoint<'_, { p::PEER_EVENT }>,
    exchange: &Exchange<'_, '_, '_>,
) -> Result<(), Error> {
    if !exchange.peer.is_empty() {
        return Err(Error::Binding);
    }
    let sequence = exchange.sequence();
    endpoint.send::<p::PeerCancelled>(&sequence).await?;
    check(endpoint.recv::<p::PeerSeen>().await?, sequence)
}

/// Observe completion independently of UDP receive and publication. A client
/// finishes only when its source retired, at least one request was submitted,
/// each sink consumed FIN, and no retransmittable request chunks remain.
pub(crate) async fn completion<const N: usize, const RX: usize, const CHUNK: usize>(
    endpoint: &mut Endpoint<'_, { p::FILES_EVENT }>,
    exchange: &Exchange<'_, '_, '_>,
    state: &io::State<CHUNK>,
    app: &RefCell<App<'_, '_, '_, RX, CHUNK>>,
    book: &crate::connection::recovery::CompletionObserver<'_, '_, N>,
    side: Side,
) -> Result<(), Error> {
    let sequence = exchange.sequence();
    loop {
        let revision = exchange.control.revision();
        if exchange.control.stopping() {
            if !exchange.files.is_empty() {
                return Err(Error::Binding);
            }
            endpoint.send::<p::CompletionCancelled>(&sequence).await?;
            exchange.control.revoke()?;
            return check(endpoint.recv::<p::CompletionSeen>().await?, sequence);
        }
        // Actual failed application IO raises this readiness observation.
        // The actual wire permission retains the close reason; no outer phase
        // flag supplies it. An existing stop takes cancellation priority.
        if exchange.control.failed() {
            exchange.files.put(Permission {
                scope: exchange.scope,
                kind: CloseKind::Local { application: true, code: 0x100 },
            }).map_err(|_| Error::Binding)?;
            endpoint.send::<p::ApplicationFailed>(&sequence).await?;
            exchange.control.revoke()?;
            return check(endpoint.recv::<p::CompletionSeen>().await?, sequence);
        }
        if side == Side::Client
            && state.source_done()
            && state.submitted_count() != 0
            && state.completed_count() == state.submitted_count()
        {
            let queued = app
                .try_borrow()
                .map_err(|_| Error::Binding)?
                .queued_chunks()?;
            if queued == 0 && book.handshake_confirmed()? && book.ordinary_settled()? {
                exchange.files.put(Permission {
                    scope: exchange.scope,
                    kind: CloseKind::Local { application: true, code: 0 },
                }).map_err(|_| Error::Binding)?;
                endpoint.send::<p::FilesComplete>(&sequence).await?;
                exchange.control.revoke()?;
                return check(endpoint.recv::<p::CompletionSeen>().await?, sequence);
            }
        }
        exchange.control.wait(7, revision).await;
    }
}

/// Consume the two independent projected terminal lanes concurrently. Each
/// permission is applied only after receiving its declared wire arm. Finishing
/// one lane does not cancel or impersonate retirement of the other lane.
pub(crate) async fn receive<'scope>(
    peer: &mut Endpoint<'_, { p::PEER_CLOSE }>,
    files: &mut Endpoint<'_, { p::FILES_CLOSE }>,
    exchange: &Exchange<'_, '_, 'scope>,
) -> Result<Permission<'scope>, Error> {
    let sequence = exchange.sequence();
    let mut peer_permission = None;
    let mut files_permission = None;
    let mut peer_done = false;
    let mut files_done = false;
    while !peer_done || !files_done {
        let (peer_offer, files_offer) = if peer_done {
            (None, Some(files.offer().await))
        } else if files_done {
            (Some(peer.offer().await), None)
        } else {
            let mut peer_wait = pin!(peer.offer());
            let mut files_wait = pin!(files.offer());
            poll_fn(|cx| {
                if let Poll::Ready(offered) = peer_wait.as_mut().poll(cx) {
                    return Poll::Ready((Some(offered), None));
                }
                files_wait.as_mut().poll(cx).map(|offered| (None, Some(offered)))
            }).await
        };
        match (peer_offer, files_offer) {
            (Some(offered), None) => {
                let offered = offered?;
                match offered.label() {
                    44 => {
                        check(offered.recv::<p::PeerClose>().await?, sequence)?;
                        let permission = exchange.peer.take().map_err(|_| Error::Binding)?;
                        if !matches!(permission.kind, CloseKind::Peer { .. }) {
                            return Err(Error::Binding);
                        }
                        exchange.apply(&permission)?;
                        peer_permission = Some(permission);
                    }
                    45 => {
                        check(offered.recv::<p::PeerFailed>().await?, sequence)?;
                        let permission = exchange.peer.take().map_err(|_| Error::Binding)?;
                        if !matches!(permission.kind, CloseKind::Local { application: false, .. }) {
                            return Err(Error::Binding);
                        }
                        exchange.apply(&permission)?;
                        peer_permission = Some(permission);
                    }
                    46 => {
                        check(offered.recv::<p::PeerCancelled>().await?, sequence)?;
                        if !exchange.peer.is_empty() {
                            return Err(Error::Binding);
                        }
                    }
                    label => return Err(Error::UnexpectedLabel(label)),
                }
                peer.send::<p::PeerSeen>(&sequence).await?;
                peer_done = true;
            }
            (None, Some(offered)) => {
                let offered = offered?;
                match offered.label() {
                    48 => {
                        check(offered.recv::<p::FilesComplete>().await?, sequence)?;
                        let permission = exchange.files.take().map_err(|_| Error::Binding)?;
                        if !matches!(permission.kind, CloseKind::Local { application: true, code: 0 }) {
                            return Err(Error::Binding);
                        }
                        exchange.apply(&permission)?;
                        files_permission = Some(permission);
                    }
                    49 => {
                        check(offered.recv::<p::ApplicationFailed>().await?, sequence)?;
                        let permission = exchange.files.take().map_err(|_| Error::Binding)?;
                        if !matches!(permission.kind, CloseKind::Local { application: true, code: 0x100 }) {
                            return Err(Error::Binding);
                        }
                        exchange.apply(&permission)?;
                        files_permission = Some(permission);
                    }
                    50 => {
                        check(offered.recv::<p::CompletionCancelled>().await?, sequence)?;
                        if !exchange.files.is_empty() {
                            return Err(Error::Binding);
                        }
                    }
                    label => return Err(Error::UnexpectedLabel(label)),
                }
                files.send::<p::CompletionSeen>(&sequence).await?;
                files_done = true;
            }
            _ => return Err(Error::Binding),
        }
    }
    // Both lanes have independently settled. The file facet transfers its
    // actual optional permission to the peer facet before one closing owner
    // may choose between local closing and authenticated peer draining.
    let handoff = Inbox::new();
    handoff.put(files_permission).map_err(|_| Error::Binding)?;
    let mut from_files = None;
    crate::runtime::join2(
        async { files.send::<p::FilesOutcome>(&sequence).await?; Ok::<(), Error>(()) },
        async {
            check(peer.recv::<p::FilesOutcome>().await?, sequence)?;
            from_files = Some(handoff.take().map_err(|_| Error::Binding)?);
            Ok::<(), Error>(())
        },
    ).await?;
    peer_permission.or(from_files.ok_or(Error::Binding)?).ok_or(Error::Binding)
}

fn check(actual: u64, expected: u64) -> Result<(), Error> {
    if actual == expected { Ok(()) } else { Err(Error::Binding) }
}
