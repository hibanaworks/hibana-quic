//! Endpoint-owning path validation and migration continuation.
//! [`super::global`] fixes the permitted request/probe/retirement order.
use super::global as p;
use super::imp::observations::Paths;
use crate::quic::{Clock, application::Error};
use hibana::Endpoint;

pub(crate) async fn owner(
    endpoint: &mut Endpoint<'_, { p::OWNER }>,
    paths: &Paths<'_>,
    clock: &impl Clock,
) -> Result<(), Error> {
    endpoint.recv::<p::Request>().await?;
    let mut request = paths.request.take().map_err(|_| Error::Binding)?;
    while let Some(wanted) = request {
        if let Some(grant) = wanted.response_path.and_then(|path| paths.reply(path)) {
            paths.grant.put(grant).map_err(|_| Error::Binding)?;
            endpoint.send::<p::Reply>(&()).await?;
            endpoint.recv::<p::Settled>().await?;
            endpoint.recv::<p::Request>().await?;
            request = paths.request.take().map_err(|_| Error::Binding)?;
            continue;
        }
        if let Some(candidate) = paths.candidate(wanted.confirmed) {
            paths.begin(candidate, clock.now(), wanted.pto)?;
            endpoint.send::<p::Begin>(&()).await?;
            endpoint.recv::<p::Settled>().await?;
            endpoint.recv::<p::Request>().await?;
            request = paths.request.take().map_err(|_| Error::Binding)?;
            while request.is_some() {
                if let Some(valid) = paths.finished(clock.now())? {
                    if !valid || paths.mtu_verified()? {
                        break;
                    }
                    paths.expand(clock.now())?;
                    endpoint.send::<p::Expand>(&()).await?;
                    endpoint.recv::<p::Settled>().await?;
                    endpoint.recv::<p::Request>().await?;
                    request = paths.request.take().map_err(|_| Error::Binding)?;
                    continue;
                }
                if let Some(grant) = paths.probe(clock.now())? {
                    paths.grant.put(grant).map_err(|_| Error::Binding)?;
                    endpoint.send::<p::Probe>(&()).await?;
                } else if let Some(grant) = request
                    .as_ref()
                    .and_then(|wanted| wanted.response_path)
                    .and_then(|path| paths.reply(path))
                {
                    paths.grant.put(grant).map_err(|_| Error::Binding)?;
                    endpoint.send::<p::ProbeReply>(&()).await?;
                } else {
                    paths
                        .grant
                        .put(paths.current())
                        .map_err(|_| Error::Binding)?;
                    endpoint.send::<p::Hold>(&()).await?;
                }
                endpoint.recv::<p::Settled>().await?;
                endpoint.recv::<p::Request>().await?;
                request = paths.request.take().map_err(|_| Error::Binding)?;
            }
            endpoint.send::<p::ProbePause>(&()).await?;
            endpoint.recv::<p::ProbePaused>().await?;
            let valid = paths.finished(clock.now())? == Some(true);
            paths.resolve(valid)?;
            if valid {
                endpoint.send::<p::Resolved>(&()).await?;
            } else {
                endpoint.send::<p::Abandoned>(&()).await?;
            }
            endpoint.recv::<p::Settled>().await?;
            endpoint.recv::<p::Request>().await?;
            request = paths.request.take().map_err(|_| Error::Binding)?;
        } else {
            paths
                .grant
                .put(paths.current())
                .map_err(|_| Error::Binding)?;
            endpoint.send::<p::Current>(&()).await?;
            endpoint.recv::<p::Settled>().await?;
            endpoint.recv::<p::Request>().await?;
            request = paths.request.take().map_err(|_| Error::Binding)?;
        }
    }
    endpoint.send::<p::Pause>(&()).await?;
    endpoint.recv::<p::Paused>().await?;
    endpoint.send::<p::End>(&()).await?;
    endpoint.recv::<p::Joined>().await?;
    Ok(())
}
