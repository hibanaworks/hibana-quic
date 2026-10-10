//! Direct projected TLS and key-handoff locals; numerical CRYPTO offsets stay here.
use super::global as p;
use super::*;
use core::{ops::ControlFlow, pin::pin};
use hibana_tls::handshake::keys::Handoff;

use crate::quic::imp::transcript::Numbers;
pub(in crate::quic) async fn receive<'scope, const P: usize>(
    endpoint: &mut Endpoint<'_, { p::TLS_RX }>,
    source: &Numbers<'_, 'scope, '_, '_>,
    handoff: &Handoff<'scope, P>,
    message: &hibana_tls::handshake::MessageSlot<'_>,
    side: Side,
) -> Result<(), Error> {
    use hibana_tls::handshake::global as tls;
    use hibana_tls::handshake::localside;
    match side {
        Side::Client => {
            endpoint.send::<tls::ClientStart>(&()).await?;
            localside::verify::client_owned(endpoint, &source.source, message, handoff)
                .await
                .map_err(Error::Transcript)?;
        }
        Side::Server => {
            endpoint.send::<tls::ServerStart>(&()).await?;
            localside::verify::server_owned(endpoint, &source.source, message, handoff)
                .await
                .map_err(Error::Transcript)?;
        }
    }
    endpoint.send::<p::TranscriptComplete>(&()).await?;
    endpoint.recv::<p::ReceiveComplete>().await?;
    endpoint.send::<p::ReceiveContinuation>(&()).await?;
    Ok(())
}
pub(in crate::quic) async fn transmit<'scope, const N: usize, const P: usize>(
    endpoint: &mut Endpoint<'_, { p::TLS_TX }>,
    completion: &mut Endpoint<'_, { p::TLS_COMPLETE }>,
    source: &Numbers<'_, 'scope, '_, '_>,
    slots: &Storage<'scope, '_, N, P>,
) -> Result<(), Error> {
    {
        let mut completed = pin!(completion.recv::<p::TranscriptComplete>());
        let arrival = {
            let prefix = async {
                // Initial source local: each exchange is written here in contract order.
                loop {
                    endpoint.recv::<p::InitialRequest>().await?;
                    if !slots.write_handshake.is_empty() {
                        endpoint.send::<p::InitialBoundary>(&()).await?;
                        endpoint.recv::<p::InitialPhaseSettled>().await?;
                        break;
                    }
                    let flight = source.transmit::<N>()?;
                    if let Some(flight) = flight {
                        slots.flight.put(flight)?;
                        endpoint.send::<p::InitialFlight>(&()).await?;
                    } else {
                        endpoint
                            .send::<p::InitialIdle>(&slots.schedule.revision.get())
                            .await?;
                    }
                    endpoint.recv::<p::InitialTaken>().await?;
                }
                endpoint.send::<p::WriteHandshake>(&()).await?;
                // Handshake source local: each exchange is written here in contract order.
                loop {
                    endpoint.recv::<p::HandshakeRequest>().await?;
                    if !slots.write_application.is_empty() {
                        endpoint.send::<p::HandshakeBoundary>(&()).await?;
                        endpoint.recv::<p::HandshakePhaseSettled>().await?;
                        break;
                    }
                    let flight = source.transmit::<N>()?;
                    if let Some(flight) = flight {
                        slots.flight.put(flight)?;
                        endpoint.send::<p::HandshakeFlight>(&()).await?;
                    } else {
                        endpoint
                            .send::<p::HandshakeIdle>(&slots.schedule.revision.get())
                            .await?;
                    }
                    endpoint.recv::<p::HandshakeTaken>().await?;
                }
                endpoint.send::<p::WriteApplication>(&()).await?;
                Ok::<(), Error>(())
            };
            let mut prefix = pin!(prefix);
            match crate::runtime::select(completed.as_mut(), prefix.as_mut()).await {
                ControlFlow::Break(result) => {
                    result?;
                    slots.schedule.changed()?;
                    prefix.await?;
                    ControlFlow::Break(())
                }
                ControlFlow::Continue(result) => {
                    result?;
                    ControlFlow::Continue(())
                }
            }
        };
        if let ControlFlow::Continue(()) = arrival {
            // Each live source cycle remains owned until its actual Taken.
            // A completion arrival never cancels a half-finished exchange.
            loop {
                let mut cycle = pin!(async {
                    endpoint.recv::<p::ApplicationRequest>().await?;
                    let flight = source.transmit::<N>()?;
                    if let Some(flight) = flight {
                        slots.flight.put(flight)?;
                        endpoint.send::<p::ApplicationFlight>(&()).await?;
                    } else {
                        endpoint
                            .send::<p::ApplicationIdle>(&slots.schedule.revision.get())
                            .await?;
                    }
                    endpoint.recv::<p::ApplicationTaken>().await?;
                    Ok::<(), Error>(())
                });
                match crate::runtime::select(completed.as_mut(), cycle.as_mut()).await {
                    ControlFlow::Break(result) => {
                        result?;
                        // Wake TX before settling a cycle that may still be
                        // awaiting its Request; TX may be parked after Idle.
                        slots.schedule.changed()?;
                        cycle.await?;
                        slots.schedule.changed()?;
                        break;
                    }
                    ControlFlow::Continue(result) => result?,
                }
                crate::runtime::yield_now().await;
            }
        }
    }
    // The real projected receipt has now arrived. Drain any final generated
    // flight, then close the source phase; no mirrored Connected flag is read.
    loop {
        endpoint.recv::<p::ApplicationRequest>().await?;
        let flight = source.transmit::<N>()?;
        if let Some(flight) = flight {
            slots.flight.put(flight)?;
            endpoint.send::<p::ApplicationFlight>(&()).await?;
        } else {
            endpoint.send::<p::ApplicationBoundary>(&()).await?;
            endpoint.recv::<p::ApplicationPhaseSettled>().await?;
            break;
        }
        endpoint.recv::<p::ApplicationTaken>().await?;
        crate::runtime::yield_now().await;
    }
    endpoint.recv::<p::TransmitComplete>().await?;
    endpoint.send::<p::TransmitContinuation>(&()).await?;
    Ok(())
}

fn publish_material<'scope, const N: usize, const P: usize>(
    material: &Handoff<'scope, P>,
    slots: &Storage<'scope, '_, N, P>,
) -> Result<(), Error> {
    if let Some(keys) = material.take_handshake() {
        let (read, write) = keys.install();
        slots.read_handshake.put(read)?;
        slots.write_handshake.put(write)?;
    }
    if let Some(keys) = material.take_application() {
        let (installation, local, remote) = keys.into_parts();
        let (read, write) =
            crate::crypto::directional::ApplicationReadKeys::install(installation, local, remote)?;
        slots.read_application.put(read)?;
        slots.write_application.put(write)?;
    }
    if let Some(finished) = material.take_finished() {
        slots.finished.put(finished)?;
    }
    slots.schedule.changed()?;
    Ok(())
}
pub(in crate::quic) async fn handoff<'scope, const N: usize, const P: usize>(
    endpoint: &mut Endpoint<'_, { hibana_tls::handshake::global::owned::HANDOFF }>,
    material: &Handoff<'scope, P>,
    slots: &Storage<'scope, '_, N, P>,
) -> Result<(), Error> {
    use hibana_tls::handshake::global::owned as h;
    let start = endpoint.offer().await?;
    let client = match start.label() {
        247 => {
            start.recv::<h::ClientKeys>().await?;
            true
        }
        248 => {
            start.recv::<h::ServerKeys>().await?;
            false
        }
        _ => return Err(Error::Binding),
    };
    endpoint.recv::<h::KeysReady>().await?;
    publish_material(material, slots)?;
    endpoint.send::<h::KeysTaken>(&()).await?;
    let hello = endpoint.offer().await?;
    match hello.label() {
        242 => {
            hello.recv::<h::RetryKeys>().await?;
            endpoint.recv::<h::KeysReady>().await?;
            publish_material(material, slots)?;
            endpoint.send::<h::KeysTaken>(&()).await?;
        }
        243 => hello.recv::<h::HelloKeys>().await?,
        _ => return Err(Error::Binding),
    };
    if client {
        endpoint.recv::<h::KeysReady>().await?;
        publish_material(material, slots)?;
        endpoint.send::<h::KeysTaken>(&()).await?;
        let auth = endpoint.offer().await?;
        match auth.label() {
            244 => auth.recv::<h::ResumedKeys>().await?,
            245 => {
                auth.recv::<h::FullKeys>().await?;
                endpoint.recv::<h::KeysReady>().await?;
                publish_material(material, slots)?;
                endpoint.send::<h::KeysTaken>(&()).await?;
                endpoint.recv::<h::KeysReady>().await?;
                publish_material(material, slots)?;
                endpoint.send::<h::KeysTaken>(&()).await?;
            }
            _ => return Err(Error::Binding),
        };
    }
    endpoint.recv::<h::KeysReady>().await?;
    publish_material(material, slots)?;
    endpoint.send::<h::KeysTaken>(&()).await?;
    endpoint.recv::<h::CompleteKeys>().await?;
    Ok(())
}
