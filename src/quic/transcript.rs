//! Direct projected TLS and key-handoff locals; numerical CRYPTO offsets stay here.
use super::global as p;
use super::*;
use core::{ops::ControlFlow, pin::pin};
use hibana_tls::handshake::key_source::{Handoff, KeySource};

pub(super) struct Numbers<'source, 'scope, 'cfg, 'buf> {
    source: RefCell<&'source mut KeySource<'scope, 'cfg, 'buf>>,
    sent: RefCell<&'source mut [u64; 3]>,
    received: RefCell<&'source mut [u64; 3]>,
}
impl<'source, 'scope, 'cfg, 'buf> Numbers<'source, 'scope, 'cfg, 'buf> {
    pub fn new(source: &'source mut Transcript<'scope, 'cfg, 'buf>) -> Self {
        Self {
            source: RefCell::new(&mut source.source),
            sent: RefCell::new(&mut source.sent),
            received: RefCell::new(&mut source.received),
        }
    }
    fn transmit<const N: usize>(&self) -> Result<Option<CryptoFlight<N>>, crate::tls::Error> {
        let mut source = self.source.borrow_mut();
        if source.last_failure().is_some() {
            return Err(crate::tls::Error::Handshake);
        }
        let mut bytes = [0; N];
        let Some(output) = source.transmit(&mut bytes)? else {
            return Ok(None);
        };
        if output.len == 0 || output.len > N {
            return Err(crate::tls::Error::InvalidInput);
        }
        let index = super::tls::level_index(output.level);
        let mut sent = self.sent.borrow_mut();
        let offset = sent[index];
        sent[index] = super::tls::range_end(offset, output.len)?;
        Ok(Some(CryptoFlight {
            level: output.level,
            offset,
            bytes,
            len: output.len,
        }))
    }
    pub(super) fn record_verified_consumed(&self, consumed: [u64; 2]) -> Result<(), Error> {
        let mut received = self.received.borrow_mut();
        for (index, end) in consumed.into_iter().enumerate() {
            if end < received[index] || end > super::kernel::packet::MAX_VARINT {
                return Err(crate::tls::Error::InvalidInput.into());
            }
            received[index] = end;
        }
        Ok(())
    }
    pub(super) fn restore_buffer(&self, bytes: &'buf mut [u8]) -> Result<(), Error> {
        self.source
            .borrow_mut()
            .restore_message_buffer(bytes)
            .map_err(Error::from)
    }
}
pub(super) async fn receive<'scope, const P: usize>(
    endpoint: &mut Endpoint<'_, { p::TLS_RX }>,
    source: &Numbers<'_, 'scope, '_, '_>,
    handoff: &Handoff<'scope, P>,
    message: &crate::tls::handshake::local::MessageSlot<'_>,
    side: Side,
) -> Result<(), Error> {
    use crate::tls::handshake::{global as tls, local};
    match side {
        Side::Client => {
            endpoint.send::<tls::ClientStart>(&()).await?;
            local::client_owned(endpoint, &source.source, message, handoff)
                .await
                .map_err(Error::Transcript)?;
        }
        Side::Server => {
            endpoint.send::<tls::ServerStart>(&()).await?;
            local::server_owned(endpoint, &source.source, message, handoff)
                .await
                .map_err(Error::Transcript)?;
        }
    }
    endpoint.send::<p::TranscriptComplete>(&()).await?;
    endpoint.recv::<p::ReceiveComplete>().await?;
    endpoint.send::<p::ReceiveContinuation>(&()).await?;
    Ok(())
}
pub(super) async fn transmit<'scope, const N: usize, const P: usize>(
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
pub(super) async fn handoff<'scope, const N: usize, const P: usize>(
    endpoint: &mut Endpoint<'_, { hibana_tls::owned_global::HANDOFF }>,
    material: &Handoff<'scope, P>,
    slots: &Storage<'scope, '_, N, P>,
) -> Result<(), Error> {
    use hibana_tls::owned_global as h;
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
