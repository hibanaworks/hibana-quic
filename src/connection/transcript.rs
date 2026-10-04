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
fn check(actual: u64, expected: u64) -> Result<(), Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(Error::Binding)
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
    _outcome: &Outcome,
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
            endpoint.send::<tls::ClientStart>(&0).await?;
            locals::client_owner(endpoint, &owner, message)
                .await
                .map_err(Error::Transcript)?;
        }
        Side::Server => {
            endpoint.send::<tls::ServerStart>(&0).await?;
            locals::server_owner(endpoint, &owner, message)
                .await
                .map_err(Error::Transcript)?;
        }
    }
    check(endpoint.recv::<p::ReceiveComplete>().await?, 0)?;
    endpoint.send::<p::ReceiveContinuation>(&0).await?;
    Ok(())
}
async fn output_before_key<'scope, Stage, T, const N: usize, const P: usize>(
    endpoint: &mut Endpoint<'_, { p::TLS_TX }>,
    source: &Numbers<'_, 'scope, '_, '_>,
    slots: &Storage<'scope, '_, N, P>,
    boundary: &Inbox<T>,
    id: &mut u64,
) -> Result<(), Error>
where
    Stage: p::TransmitPhase,
{
    loop {
        check(endpoint.recv::<Stage::Request>().await?, *id)?;
        if !boundary.is_empty() {
            endpoint.send::<Stage::Boundary>(id).await?;
            check(endpoint.recv::<Stage::PhaseSettled>().await?, *id)?;
            *id = id.checked_add(1).ok_or(Error::Binding)?;
            return Ok(());
        }
        output::<Stage, N, P>(endpoint, source, slots, *id).await?;
        *id = id.checked_add(1).ok_or(Error::Binding)?;
    }
}
async fn output<'scope, Stage: p::TransmitPhase, const N: usize, const P: usize>(
    endpoint: &mut Endpoint<'_, { p::TLS_TX }>,
    source: &Numbers<'_, 'scope, '_, '_>,
    slots: &Storage<'scope, '_, N, P>,
    id: u64,
) -> Result<(), Error> {
    let flight = source.transmit::<N>()?;
    source.harvest(slots)?;
    if let Some(flight) = flight {
        slots.flight.put(flight)?;
        endpoint.send::<Stage::Flight>(&id).await?;
    } else {
        endpoint
            .send::<Stage::Idle>(&slots.schedule.revision.get())
            .await?;
    }
    check(endpoint.recv::<Stage::Taken>().await?, id)?;
    Ok(())
}
pub(super) async fn transmit<'scope, const N: usize, const P: usize>(
    endpoint: &mut Endpoint<'_, { p::TLS_TX }>,
    source: &Numbers<'_, 'scope, '_, '_>,
    slots: &Storage<'scope, '_, N, P>,
) -> Result<(), Error> {
    let mut id = 0;
    output_before_key::<p::InitialTransmit, _, N, P>(
        endpoint,
        source,
        slots,
        &slots.write_handshake,
        &mut id,
    )
    .await?;
    endpoint.send::<p::WriteHandshake>(&id).await?;
    output_before_key::<p::HandshakeTransmit, _, N, P>(
        endpoint,
        source,
        slots,
        &slots.write_application,
        &mut id,
    )
    .await?;
    endpoint.send::<p::WriteApplication>(&id).await?;
    output_until_connected::<p::ApplicationTransmit, N, P>(endpoint, source, slots, &mut id)
        .await?;
    check(endpoint.recv::<p::TransmitComplete>().await?, id)?;
    endpoint.send::<p::TransmitContinuation>(&id).await?;
    Ok(())
}
async fn output_until_connected<'scope, Stage: p::TransmitPhase, const N: usize, const P: usize>(
    endpoint: &mut Endpoint<'_, { p::TLS_TX }>,
    source: &Numbers<'_, 'scope, '_, '_>,
    slots: &Storage<'scope, '_, N, P>,
    id: &mut u64,
) -> Result<(), Error> {
    loop {
        check(endpoint.recv::<Stage::Request>().await?, *id)?;
        let flight = source.transmit::<N>()?;
        source.harvest(slots)?;
        if let Some(flight) = flight {
            slots.flight.put(flight)?;
            endpoint.send::<Stage::Flight>(id).await?;
        } else if source.connected() {
            endpoint.send::<Stage::Boundary>(id).await?;
            check(endpoint.recv::<Stage::PhaseSettled>().await?, *id)?;
            *id = id.checked_add(1).ok_or(Error::Binding)?;
            break;
        } else {
            endpoint
                .send::<Stage::Idle>(&slots.schedule.revision.get())
                .await?;
        }
        check(endpoint.recv::<Stage::Taken>().await?, *id)?;
        *id = id.checked_add(1).ok_or(Error::Binding)?;
        crate::runtime::yield_now().await;
    }
    Ok(())
}
