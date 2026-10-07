//! Independent peer and application terminal edges carry actual affine close
//! permissions. Wire payloads are correlation observations, never authority.
use super::{CloseKind, Control, Error, global as p, io};
use crate::{
    crypto::directional::ApplicationKeyScope,
    quic::{Side, application_stream::App, tls::Inbox},
};
use core::{
    cell::RefCell,
    future::{Future, poll_fn},
    pin::pin,
};
use hibana::Endpoint;

/// Only these trusted producer continuations construct terminal permission.
/// It cannot be cloned or reconstructed from a copied error code or sequence.
pub(crate) struct Permission<'scope> {
    pub(super) scope: &'scope ApplicationKeyScope,
    pub(super) kind: CloseKind,
}

impl<'scope> Permission<'scope> {
    pub(crate) fn scope(&self) -> &'scope ApplicationKeyScope {
        self.scope
    }
    pub(crate) fn kind(&self) -> CloseKind {
        self.kind
    }
}

pub(crate) struct Exchange<'a, 'gate, 'scope> {
    pub(super) protocol: crate::http3::Protocol,
    control: &'a Control<'gate, 'scope>,
    scope: &'scope ApplicationKeyScope,
    pub(super) peer: Inbox<Permission<'scope>>,
    files: Inbox<Permission<'scope>>,
}

impl<'a, 'gate, 'scope> Exchange<'a, 'gate, 'scope> {
    pub(crate) const fn new(
        control: &'a Control<'gate, 'scope>,
        scope: &'scope ApplicationKeyScope,
        protocol: crate::http3::Protocol,
    ) -> Self {
        Self {
            protocol,
            control,
            scope,
            peer: Inbox::new(),
            files: Inbox::new(),
        }
    }

    pub(super) fn check_scope(&self, scope: &ApplicationKeyScope) -> Result<(), Error> {
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
}

/// Observe completion independently of UDP receive and publication. A client
/// finishes only when its source retired, at least one request was submitted,
/// each sink consumed FIN, and pending native publications have settled.
/// Missing request ACKs remain missing: response completion permits an explicit
/// application close, not a transport acknowledgment. Servers still require
/// acknowledgment of their response chunks before locally finishing.
pub(crate) async fn completion<const N: usize, const RX: usize, const CHUNK: usize, B>(
    endpoint: &mut Endpoint<'_, { p::FILES_EVENT }>,
    source_join: &mut Endpoint<'_, { p::SOURCE_JOIN }>,
    exchange: &Exchange<'_, '_, '_>,
    state: &io::State<'_, CHUNK, B>,
    app: &RefCell<App<'_, '_, '_, RX, CHUNK>>,
    book: &crate::quic::recovery::CompletionObserver<'_, '_, N>,
    side: Side,
    idle: (u64, &impl crate::quic::Clock),
) -> Result<(), Error> {
    let (local_idle_timeout_ms, clock) = idle;
    // Normal completion cannot even inspect the final numerical conditions
    // before consuming the source's actual projected retirement message.
    let mut normal = pin!(async {
        let offered = source_join.offer().await?;
        match offered.label() {
            213 => {
                offered.recv::<p::SourceJoined>().await?;
            }
            214 => {
                offered.recv::<p::SourceFailed>().await?;
                return Ok::<_, Error>(Some(CloseKind::Local {
                    application: true,
                    code: exchange.protocol.failure_code(),
                }));
            }
            label => return Err(Error::UnexpectedLabel(label)),
        }
        loop {
            let revision = exchange.control.revision();
            if exchange.control.stopping() {
                return Ok::<_, Error>(None);
            }
            if (side == Side::Client || state.bodies_finished() == state.submitted_count())
                && state.submitted_count() != 0
                && state.completed_count() == state.submitted_count()
            {
                let queued = app
                    .try_borrow()
                    .map_err(|_| Error::Binding)?
                    .queued_chunks()?;
                if (side == Side::Client || queued == 0)
                    && book.handshake_confirmed()?
                    && book.ordinary_settled()?
                {
                    return Ok(Some(CloseKind::Local {
                        application: true,
                        code: exchange.protocol.success_code(),
                    }));
                }
            }
            exchange.control.wait(7, revision).await;
        }
    });
    // Peer cancellation, failed IO and the actual idle clock remain independent
    // of source completion. They must be able to stop an unfinished body read.
    let mut interrupted = pin!(async {
        loop {
            let revision = exchange.control.revision();
            if exchange.control.stopping() {
                return Ok::<_, Error>(None);
            }
            if let Some(deadline) = book.idle_deadline(local_idle_timeout_ms)? {
                if clock.now() >= deadline {
                    return Ok(Some(CloseKind::IdleExpired));
                }
                let mut changed = pin!(exchange.control.wait(7, revision));
                let mut elapsed = pin!(clock.wait_until(deadline));
                poll_fn(|cx| {
                    if changed.as_mut().poll(cx).is_ready() {
                        return core::task::Poll::Ready(());
                    }
                    elapsed.as_mut().poll(cx)
                })
                .await;
            } else {
                exchange.control.wait(7, revision).await;
            }
        }
    });
    let decision = poll_fn(|cx| {
        if let core::task::Poll::Ready(result) = interrupted.as_mut().poll(cx) {
            return core::task::Poll::Ready(core::ops::ControlFlow::Break(result));
        }
        normal
            .as_mut()
            .poll(cx)
            .map(core::ops::ControlFlow::Continue)
    })
    .await;
    let reason = match decision {
        core::ops::ControlFlow::Break(result) => {
            let reason = result?;
            // Stop actual producer work before joining its still-live receive.
            // Never drop that receive and fabricate its SourceJoined message.
            exchange.control.revoke()?;
            normal.await?;
            reason
        }
        core::ops::ControlFlow::Continue(result) => match result? {
            Some(reason) => Some(reason),
            None => interrupted.await?,
        },
    };
    if let Some(kind) = reason {
        exchange
            .files
            .put(Permission {
                scope: exchange.scope,
                kind,
            })
            .map_err(|_| Error::Binding)?;
    } else if !exchange.files.is_empty() {
        return Err(Error::Binding);
    }
    exchange.control.revoke()?;
    match reason {
        Some(CloseKind::Local {
            application: true,
            code,
        }) if code == exchange.protocol.success_code() => match side {
            Side::Client => endpoint.send::<p::ResponsesComplete>(&()).await?,
            Side::Server => endpoint.send::<p::FilesComplete>(&()).await?,
        },
        Some(CloseKind::Local {
            application: true,
            code,
        }) if code == exchange.protocol.failure_code() => {
            endpoint.send::<p::ApplicationFailed>(&()).await?;
        }
        Some(CloseKind::IdleExpired) => {
            endpoint.send::<p::IdleExpired>(&()).await?;
        }
        None => endpoint.send::<p::CompletionCancelled>(&()).await?,
        _ => return Err(Error::Binding),
    }
    endpoint.recv::<p::CompletionSeen>().await?;
    Ok(())
}

/// The two terminal facets retain their separate affine results until the
/// post-ordinary close owner requests and consumes each result.
pub(crate) struct TerminalOutcomes<'scope> {
    peer: Option<Permission<'scope>>,
    files: Option<Permission<'scope>>,
}
impl<'scope> TerminalOutcomes<'scope> {
    pub(crate) fn into_parts(self) -> (Option<Permission<'scope>>, Option<Permission<'scope>>) {
        (self.peer, self.files)
    }
}

/// Consume the two independent projected terminal lanes concurrently. Each
/// permission is applied only after receiving its declared wire arm. Finishing
/// one lane does not cancel or impersonate retirement of the other lane.
pub(crate) async fn receive<'scope>(
    peer: &mut Endpoint<'_, { p::PEER_CLOSE }>,
    files: &mut Endpoint<'_, { p::FILES_CLOSE }>,
    exchange: &Exchange<'_, '_, 'scope>,
) -> Result<TerminalOutcomes<'scope>, Error> {
    let mut peer_permission = None;
    let mut files_permission = None;
    // The two projected terminal locals run independently. Each performs its
    // actual offer/recv/ack once; the executor joins futures, not protocol flags.
    crate::runtime::join2(
        async {
            let offered = peer.offer().await?;
            let permission = match offered.label() {
                44 => {
                    offered.recv::<p::PeerClose>().await?;
                    let permission = exchange.peer.take().map_err(|_| Error::Binding)?;
                    if !matches!(
                        permission.kind,
                        CloseKind::Peer { .. } | CloseKind::PeerApplication { .. }
                    ) {
                        return Err(Error::Binding);
                    }
                    exchange.apply(&permission)?;
                    Some(permission)
                }
                45 => {
                    offered.recv::<p::PeerFailed>().await?;
                    let permission = exchange.peer.take().map_err(|_| Error::Binding)?;
                    if !matches!(
                        permission.kind,
                        CloseKind::Local {
                            application: false,
                            ..
                        }
                    ) {
                        return Err(Error::Binding);
                    }
                    exchange.apply(&permission)?;
                    Some(permission)
                }
                218 => {
                    offered.recv::<p::PeerApplicationFailed>().await?;
                    let permission = exchange.peer.take().map_err(|_| Error::Binding)?;
                    if !matches!(
                        permission.kind,
                        CloseKind::Local {
                            application: true,
                            code
                        } if code == exchange.protocol.failure_code()
                    ) {
                        return Err(Error::Binding);
                    }
                    exchange.apply(&permission)?;
                    Some(permission)
                }
                46 => {
                    offered.recv::<p::PeerCancelled>().await?;
                    if !exchange.peer.is_empty() {
                        return Err(Error::Binding);
                    }
                    None
                }
                label => return Err(Error::UnexpectedLabel(label)),
            };
            peer_permission = permission;
            peer.send::<p::PeerSeen>(&()).await?;
            Ok::<(), Error>(())
        },
        async {
            let offered = files.offer().await?;
            let permission = match offered.label() {
                220 => {
                    offered.recv::<p::ResponsesComplete>().await?;
                    let permission = exchange.files.take().map_err(|_| Error::Binding)?;
                    if !matches!(
                        permission.kind,
                        CloseKind::Local {
                            application: true,
                            code
                        } if code == exchange.protocol.success_code()
                    ) {
                        return Err(Error::Binding);
                    }
                    exchange.apply(&permission)?;
                    Some(permission)
                }
                48 => {
                    offered.recv::<p::FilesComplete>().await?;
                    let permission = exchange.files.take().map_err(|_| Error::Binding)?;
                    if !matches!(
                        permission.kind,
                        CloseKind::Local {
                            application: true,
                            code
                        } if code == exchange.protocol.success_code()
                    ) {
                        return Err(Error::Binding);
                    }
                    exchange.apply(&permission)?;
                    Some(permission)
                }
                49 => {
                    offered.recv::<p::ApplicationFailed>().await?;
                    let permission = exchange.files.take().map_err(|_| Error::Binding)?;
                    if !matches!(
                        permission.kind,
                        CloseKind::Local {
                            application: true,
                            code
                        } if code == exchange.protocol.failure_code()
                    ) {
                        return Err(Error::Binding);
                    }
                    exchange.apply(&permission)?;
                    Some(permission)
                }
                52 => {
                    offered.recv::<p::IdleExpired>().await?;
                    let permission = exchange.files.take().map_err(|_| Error::Binding)?;
                    if !matches!(permission.kind, CloseKind::IdleExpired) {
                        return Err(Error::Binding);
                    }
                    exchange.apply(&permission)?;
                    Some(permission)
                }
                50 => {
                    offered.recv::<p::CompletionCancelled>().await?;
                    if !exchange.files.is_empty() {
                        return Err(Error::Binding);
                    }
                    None
                }
                label => return Err(Error::UnexpectedLabel(label)),
            };
            files_permission = permission;
            files.send::<p::CompletionSeen>(&()).await?;
            Ok::<(), Error>(())
        },
    )
    .await?;
    Ok(TerminalOutcomes {
        peer: peer_permission,
        files: files_permission,
    })
}
