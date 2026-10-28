//! Independent peer and application outcomes follow the projected terminal branches.
use super::{CloseKind, Control, Error, global as p};
use crate::quic::Side;
use crate::quic::application::imp::stream::App;
use core::{
    cell::RefCell,
    future::{Future, poll_fn},
    pin::pin,
};
use hibana::Endpoint;

/// Terminal observations share the connection's I/O cancellation and protocol.
pub(crate) struct Exchange<'a, 'gate, 'scope> {
    pub(super) protocol: crate::http3::Protocol,
    control: &'a Control<'gate, 'scope>,
}

impl<'a, 'gate, 'scope> Exchange<'a, 'gate, 'scope> {
    pub(crate) const fn new(
        control: &'a Control<'gate, 'scope>,
        protocol: crate::http3::Protocol,
    ) -> Self {
        Self { protocol, control }
    }
}

/// Observe completion independently of UDP receive and publication. A client
/// finishes only when its source retired, at least one request was submitted,
/// each sink consumed FIN, and pending native publications have settled.
/// Missing request ACKs remain missing: response completion permits an explicit
/// application close, not a transport acknowledgment. Servers still require
/// acknowledgment of their response chunks before locally finishing.
// Separate projected endpoints and resource owners are passed explicitly.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn completion<const N: usize, const RX: usize, const CHUNK: usize, B>(
    endpoint: &mut Endpoint<'_, { p::FILES_EVENT }>,
    source_join: &mut Endpoint<'_, { p::SOURCE_JOIN }>,
    exchange: &Exchange<'_, '_, '_>,
    state: &crate::quic::application::imp::io::Exchange<CHUNK, B>,
    app: &RefCell<App<'_, '_, '_, RX, CHUNK>>,
    book: &crate::quic::imp::recovery::CompletionObserver<'_, '_, N>,
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

/// Receive both terminal outcomes concurrently and acknowledge each branch.
pub(crate) async fn receive(
    peer: &mut Endpoint<'_, { p::PEER_CLOSE }>,
    files: &mut Endpoint<'_, { p::FILES_CLOSE }>,
    exchange: &Exchange<'_, '_, '_>,
) -> Result<(Option<CloseKind>, Option<CloseKind>), Error> {
    crate::runtime::join::values2(
        async {
            let offered = peer.offer().await?;
            let reason = match offered.label() {
                44 => Some(CloseKind::Peer {
                    code: offered.recv::<p::PeerClose>().await?,
                }),
                224 => Some(CloseKind::PeerApplication {
                    code: offered.recv::<p::PeerApplicationClose>().await?,
                }),
                45 => Some(CloseKind::Local {
                    application: false,
                    code: offered.recv::<p::PeerFailed>().await?,
                }),
                218 => {
                    offered.recv::<p::PeerApplicationFailed>().await?;
                    Some(CloseKind::Local {
                        application: true,
                        code: exchange.protocol.failure_code(),
                    })
                }
                46 => {
                    offered.recv::<p::PeerCancelled>().await?;
                    None
                }
                label => return Err(Error::UnexpectedLabel(label)),
            };
            if reason.is_some() {
                exchange.control.revoke()?;
            }
            peer.send::<p::PeerSeen>(&()).await?;
            Ok::<_, Error>(reason)
        },
        async {
            let offered = files.offer().await?;
            let reason = match offered.label() {
                220 => {
                    offered.recv::<p::ResponsesComplete>().await?;
                    Some(CloseKind::Local {
                        application: true,
                        code: exchange.protocol.success_code(),
                    })
                }
                48 => {
                    offered.recv::<p::FilesComplete>().await?;
                    Some(CloseKind::Local {
                        application: true,
                        code: exchange.protocol.success_code(),
                    })
                }
                49 => {
                    offered.recv::<p::ApplicationFailed>().await?;
                    Some(CloseKind::Local {
                        application: true,
                        code: exchange.protocol.failure_code(),
                    })
                }
                52 => {
                    offered.recv::<p::IdleExpired>().await?;
                    Some(CloseKind::IdleExpired)
                }
                50 => {
                    offered.recv::<p::CompletionCancelled>().await?;
                    None
                }
                label => return Err(Error::UnexpectedLabel(label)),
            };
            if reason.is_some() {
                exchange.control.revoke()?;
            }
            files.send::<p::CompletionSeen>(&()).await?;
            Ok::<_, Error>(reason)
        },
    )
    .await
}
