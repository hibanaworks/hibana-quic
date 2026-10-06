//! Recovered from root's complete readback at 05:50 UTC, not revalidated.
//! Synchronous, private numerical access to one TLS transcript. The two async
//! facets below follow their projected finite key milestones independently.
use super::protocol as p;
use super::*;
use crate::bounded_tls::State;

pub(super) struct Numbers<'source, 'scope, 'cfg, 'buf> {
    source: RefCell<&'source mut Transcript<'scope, 'cfg, 'buf>>,
}
impl<'source, 'scope, 'cfg, 'buf> Numbers<'source, 'scope, 'cfg, 'buf> {
    pub fn new(source: &'source mut Transcript<'scope, 'cfg, 'buf>) -> Self {
        Self {
            source: RefCell::new(source),
        }
    }
    fn harvest<const N: usize, const P: usize>(
        &self,
        slots: &Storage<'scope, '_, N, P>,
    ) -> Result<(), Error> {
        let mut source = self.source.borrow_mut();
        match source.take_handshake_keys() {
            Ok((read, write)) => {
                slots.read_handshake.put(read)?;
                slots.write_handshake.put(write)?;
            }
            Err(crate::tls::Error::KeysUnavailable) => {}
            Err(error) => return Err(error.into()),
        }
        match source.take_application_keys() {
            Ok((read, write)) => {
                slots.read_application.put(read)?;
                slots.write_application.put(write)?;
            }
            Err(crate::tls::Error::KeysUnavailable) => {}
            Err(error) => return Err(error.into()),
        }
        match source.take_finished() {
            Ok(finished) => slots.finished.put(finished)?,
            Err(crate::tls::Error::KeysUnavailable) => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }
    fn transmit<const N: usize>(&self) -> Result<Option<CryptoFlight<N>>, crate::tls::Error> {
        self.source.borrow_mut().transmit()
    }
    pub(super) fn record_verified_consumed(&self, consumed: [u64; 2]) -> Result<(), Error> {
        self.source
            .borrow_mut()
            .record_verified_consumed(consumed)
            .map_err(Error::from)
    }
    pub(super) fn restore_buffer(&self, bytes: &'buf mut [u8]) {
        self.source
            .borrow_mut()
            .material()
            .restore_message_buffer(bytes);
    }
    fn connected(&self) -> bool {
        self.source.borrow().state() == State::Connected
    }
}
struct NumericOwner<'a, 'source, 'scope, 'cfg, 'buf, 'book, const N: usize, const P: usize> {
    numbers: &'a Numbers<'source, 'scope, 'cfg, 'buf>,
    slots: &'a Storage<'scope, 'book, N, P>,
}
impl<const N: usize, const P: usize> crate::bounded_tls::locals::CryptoAccess
    for NumericOwner<'_, '_, '_, '_, '_, '_, N, P>
{
    fn with_crypto<R>(
        &self,
        f: impl FnOnce(&mut crate::bounded_tls::BoundedTls<'_, '_>) -> R,
    ) -> R {
        f(self.numbers.source.borrow_mut().material())
    }
    fn applied(&self) -> Result<(), crate::bounded_tls::locals::Error> {
        self.numbers
            .harvest(self.slots)
            .map_err(|_| crate::bounded_tls::locals::Error::Binding)?;
        self.slots
            .schedule
            .changed()
            .map_err(|_| crate::bounded_tls::locals::Error::Binding)
    }
}
pub(super) async fn receive<'scope, const N: usize, const P: usize>(
    endpoint: &mut Endpoint<'_, { p::TLS_RX }>,
    source: &Numbers<'_, 'scope, '_, '_>,
    slots: &Storage<'scope, '_, N, P>,
    message: &crate::bounded_tls::locals::MessageSlot<'_>,
    side: Side,
) -> Result<(), Error> {
    use crate::bounded_tls::{locals, protocol as tls};
    let owner = NumericOwner {
        numbers: source,
        slots,
    };
    match side {
        Side::Client => {
            endpoint.send::<tls::ClientStart>(&()).await?;
            locals::client_owner(endpoint, &owner, message)
                .await
                .map_err(Error::Transcript)?;
        }
        Side::Server => {
            endpoint.send::<tls::ServerStart>(&()).await?;
            locals::server_owner(endpoint, &owner, message)
                .await
                .map_err(Error::Transcript)?;
        }
    }
    endpoint.recv::<p::ReceiveComplete>().await?;
    endpoint.send::<p::ReceiveContinuation>(&()).await?;
    Ok(())
}
pub(super) async fn transmit<'scope, const N: usize, const P: usize>(
    endpoint: &mut Endpoint<'_, { p::TLS_TX }>,
    source: &Numbers<'_, 'scope, '_, '_>,
    slots: &Storage<'scope, '_, N, P>,
) -> Result<(), Error> {
    // Initial source local: each exchange is written here in contract order.
    loop {
        endpoint.recv::<p::InitialRequest>().await?;
        if !slots.write_handshake.is_empty() {
            endpoint.send::<p::InitialBoundary>(&()).await?;
            endpoint.recv::<p::InitialPhaseSettled>().await?;
            break;
        }
        let flight = source.transmit::<N>()?;
        source.harvest(slots)?;
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
        source.harvest(slots)?;
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
    loop {
        endpoint.recv::<p::ApplicationRequest>().await?;
        let flight = source.transmit::<N>()?;
        source.harvest(slots)?;
        if let Some(flight) = flight {
            slots.flight.put(flight)?;
            endpoint.send::<p::ApplicationFlight>(&()).await?;
        } else if source.connected() {
            endpoint.send::<p::ApplicationBoundary>(&()).await?;
            endpoint.recv::<p::ApplicationPhaseSettled>().await?;
            break;
        } else {
            endpoint
                .send::<p::ApplicationIdle>(&slots.schedule.revision.get())
                .await?;
        }
        endpoint.recv::<p::ApplicationTaken>().await?;
        crate::runtime::yield_now().await;
    }
    endpoint.recv::<p::TransmitComplete>().await?;
    endpoint.send::<p::TransmitContinuation>(&()).await?;
    Ok(())
}
