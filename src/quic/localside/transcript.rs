//! Direct projected TLS and key-handoff locals; numerical CRYPTO offsets stay here.
use super::global as p;
use super::*;
use core::{ops::ControlFlow, pin::pin};

use crate::quic::imp::transcript::Numbers;
pub(in crate::quic) async fn receive<'r, 'scope, const N: usize, const P: usize>(
    endpoint: &mut Endpoint<'r, { p::TLS_RX }>,
    keys: Endpoint<'r, { hibana_tls::handshake::global::owned::MATERIAL }>,
    source: &Numbers<'_, 'scope, '_, '_>,
    slots: &Storage<'scope, '_, N, P>,
    message: &hibana_tls::handshake::MessageSlot<'_>,
    side: Side,
) -> Result<Endpoint<'r, { hibana_tls::handshake::global::owned::MATERIAL }>, Error> {
    use hibana_tls::handshake::localside;
    let install =
        |handshake: Option<hibana_tls::handshake::keys::HandshakeKeyMaterial<'scope>>,
         application: Option<hibana_tls::handshake::keys::ApplicationKeyMaterial<'scope>>,
         finished: Option<hibana_tls::handshake::keys::Finished<'scope, P>>| {
            if let Some(keys) = handshake {
                let (read, write) = keys.install();
                slots.read_handshake.put(read)?;
                slots.write_handshake.put(write)?;
            }
            if let Some(keys) = application {
                let (installation, local, remote) = keys.into_parts();
                let (read, write) = crate::crypto::directional::ApplicationReadKeys::install(
                    installation,
                    local,
                    remote,
                )?;
                slots.read_application.put(read)?;
                slots.write_application.put(write)?;
            }
            if let Some(finished) = finished {
                slots.finished.put(finished)?;
            }
            slots.schedule.changed()?;
            Ok::<(), Error>(())
        };
    let keys = match side {
        Side::Client => {
            localside::verify::client_owned(endpoint, keys, &source.source, message, install)
                .await?
        }
        Side::Server => {
            localside::verify::server_owned(endpoint, keys, &source.source, message, install)
                .await?
        }
    };
    endpoint.send::<p::TranscriptComplete>(&()).await?;
    endpoint.recv::<p::ReceiveComplete>().await?;
    endpoint.send::<p::ReceiveContinuation>(&()).await?;
    Ok(keys)
}
pub(in crate::quic) async fn transmit<'r, 'scope, const N: usize, const P: usize>(
    endpoint: &mut Endpoint<'r, { p::TLS_TX }>,
    source: &Numbers<'_, 'scope, '_, '_>,
    slots: &Storage<'scope, '_, N, P>,
) -> Result<(), Error> {
    use hibana_tls::handshake::global::owned as tls;
    let keys = endpoint.recv::<tls::Keys<'_>>().await?;
    endpoint.send::<tls::Keys<'_>>(keys).await?;
    loop {
        endpoint.recv::<p::InitialTaken>().await?;
        if let Some(flight) = source.transmit::<N>(Level::Initial)? {
            slots.flight.put(flight)?;
            endpoint.send::<p::InitialFlight>(&()).await?;
        } else {
            endpoint.send::<p::InitialBoundary>(&()).await?;
            endpoint.recv::<p::InitialPhaseSettled>().await?;
            break;
        }
    }
    let [mut endpoint] = endpoint.par()?;
    let keys = {
        let [mut installation, mut output] = endpoint.par().map_err(|error| Error::EndpointAt {
            role: p::TLS_TX,
            expected_label: p::HandshakeFlight::LOGICAL_LABEL,
            error,
        })?;
        let mut installed = pin!(installation.recv::<tls::Keys<'_>>());
        let keys = loop {
            let revision = slots.schedule.revision.get();
            let mut cycle = pin!(async {
                output.recv::<p::HandshakeTaken>().await?;
                if let Some(flight) = source.transmit::<N>(Level::Handshake)? {
                    slots.flight.put(flight)?;
                    output.send::<p::HandshakeFlight>(&()).await?;
                } else {
                    output.send::<p::HandshakeIdle>(&revision).await?;
                }
                Ok::<(), Error>(())
            });
            match crate::runtime::select(installed.as_mut(), cycle.as_mut()).await {
                ControlFlow::Break(result) => {
                    let keys = result?;
                    cycle.await?;
                    break keys;
                }
                ControlFlow::Continue(result) => {
                    result?;
                    // The projected response is complete. A new numeric input
                    // is needed only while installation is still pending.
                    match crate::runtime::select(
                        installed.as_mut(),
                        slots.schedule.wait_changed(1, revision),
                    )
                    .await
                    {
                        ControlFlow::Break(result) => break result?,
                        ControlFlow::Continue(()) => {}
                    }
                }
            }
            crate::runtime::yield_now().await;
        };
        loop {
            output.recv::<p::HandshakeTaken>().await?;
            if let Some(flight) = source.transmit::<N>(Level::Handshake)? {
                slots.flight.put(flight)?;
                output.send::<p::HandshakeFlight>(&()).await?;
            } else {
                output.send::<p::HandshakeBoundary>(&()).await?;
                output.recv::<p::HandshakePhaseSettled>().await?;
                break;
            }
        }
        keys
    };
    endpoint.send::<p::WriteApplication<'_>>(keys).await?;
    {
        let [mut endpoint] = endpoint.par()?;
        {
            let [mut completion, mut output] =
                endpoint.par().map_err(|error| Error::EndpointAt {
                    role: p::TLS_TX,
                    expected_label: p::TranscriptComplete::LOGICAL_LABEL,
                    error,
                })?;
            let mut completed = pin!(completion.recv::<p::TranscriptComplete>());
            loop {
                let revision = slots.schedule.revision.get();
                let mut cycle = pin!(async {
                    output.recv::<p::ApplicationTaken>().await?;
                    if let Some(flight) = source.transmit::<N>(Level::OneRtt)? {
                        slots.flight.put(flight)?;
                        output.send::<p::ApplicationFlight>(&()).await?;
                    } else {
                        output.send::<p::ApplicationIdle>(&revision).await?;
                    }
                    Ok::<(), Error>(())
                });
                match crate::runtime::select(completed.as_mut(), cycle.as_mut()).await {
                    ControlFlow::Break(result) => {
                        result?;
                        cycle.await?;
                        break;
                    }
                    ControlFlow::Continue(result) => {
                        result?;
                        match crate::runtime::select(
                            completed.as_mut(),
                            slots.schedule.wait_changed(1, revision),
                        )
                        .await
                        {
                            ControlFlow::Break(result) => {
                                result?;
                                break;
                            }
                            ControlFlow::Continue(()) => {}
                        }
                    }
                }
                crate::runtime::yield_now().await;
            }
            while let Some(flight) = source.transmit::<N>(Level::OneRtt)? {
                output.recv::<p::ApplicationTaken>().await?;
                slots.flight.put(flight)?;
                output.send::<p::ApplicationFlight>(&()).await?;
            }
            output.recv::<p::ApplicationTaken>().await?;
            output.send::<p::ApplicationInputEnd>(&()).await?;
        }
        endpoint.send::<p::ApplicationBoundary>(&()).await?;
    }
    endpoint.recv::<p::ApplicationPhaseSettled>().await?;
    endpoint.recv::<p::TransmitComplete>().await?;
    endpoint.send::<p::TransmitContinuation>(&()).await?;
    Ok(())
}
