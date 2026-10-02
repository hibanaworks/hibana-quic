//! Initial packet protection is owned by independently scheduled key roles.
//!
//! The endpoint holds only their affine mailbox capabilities. It never borrows
//! a key, polls a role future, or recreates a service after cancellation. The
//! generic capability keeps mailbox and backing-storage lifetimes independent
//! of the endpoint's Driver and CRYPTO buffers.
use super::*;
use crate::crypto::IntegrityBudget;
use crate::roles::{
    client::KeyClient,
    packet_protection::{OpenedPacket, Packet},
};
use core::future::Future;

/// Bounded Initial packet arena. Locally produced Initials are 1200 bytes;
/// larger peer packets up to this limit are supported, and larger ones dropped.
pub const INITIAL_PACKET_BYTES: usize = 1536;
pub type InitialKeyClient<'channel, 'storage> =
    KeyClient<'channel, 'storage, INITIAL_PACKET_BYTES, 1, 1>;

mod sealed {
    pub trait Sealed {}
}

/// Sealed, asynchronous admission to actual actor-owned Initial keys.
///
/// This is an implementation capability, not a replacement QUIC control FSM.
/// The only implementation below owns connected mailbox halves. Generics avoid
/// tying their two storage lifetimes to the endpoint's unrelated buffers.
pub trait InitialKeyProtection:
    sealed::Sealed + crate::roles::tls_owner::InitialOpen<INITIAL_PACKET_BYTES>
{
    fn receive_mask(&mut self, sample: [u8; 16]) -> impl Future<Output = Result<[u8; 5], Error>>;
    fn transmit_mask(&mut self, sample: [u8; 16]) -> impl Future<Output = Result<[u8; 5], Error>>;
    fn seal(
        &mut self,
        pn: u64,
        header: &[u8],
        body: &mut [u8],
        len: usize,
    ) -> impl Future<Output = Result<(), Error>>;
    fn rekey(&mut self, destination: &[u8], side: Side) -> impl Future<Output = Result<(), Error>>;
    fn retire(&mut self) -> impl Future<Output = Result<(), Error>>;
    /// Close admission on abort/cancellation. The enclosing actor aggregate
    /// must observe closure or be dropped, which destroys actor-owned keys.
    fn close(&mut self);
}

pub struct InitialProtection<'channel, 'storage> {
    receive: Option<InitialKeyClient<'channel, 'storage>>,
    transmit: Option<InitialKeyClient<'channel, 'storage>>,
    generation: u64,
}
impl<'c, 's> InitialProtection<'c, 's> {
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    /// Both clients must have completed the real actor installation exchange,
    /// and their actors must protect opposite directions of this connection.
    /// Keep the enclosing actor/session owner alive while this value is used.
    pub fn new(
        receive: InitialKeyClient<'c, 's>,
        transmit: InitialKeyClient<'c, 's>,
    ) -> Result<Self, Error> {
        if receive.generation() != transmit.generation() {
            return Err(Error::InvalidConfig);
        }
        let generation = receive.generation();
        Ok(Self {
            receive: Some(receive),
            transmit: Some(transmit),
            generation,
        })
    }
}
impl sealed::Sealed for InitialProtection<'_, '_> {}
impl crate::roles::tls_owner::initial_open_seal::Sealed for InitialProtection<'_, '_> {}
impl crate::roles::tls_owner::InitialOpen<INITIAL_PACKET_BYTES> for InitialProtection<'_, '_> {
    fn generation(&self) -> u64 {
        self.generation
    }
    async fn open_with_budget(
        &mut self,
        packet: Packet<INITIAL_PACKET_BYTES>,
        budget: IntegrityBudget,
    ) -> Result<
        (
            Result<OpenedPacket<INITIAL_PACKET_BYTES>, crypto::Error>,
            IntegrityBudget,
        ),
        crate::roles::tls_owner::ClientError,
    > {
        self.receive
            .as_mut()
            .ok_or(crate::roles::tls_owner::ClientError::Closed)?
            .open(packet, budget)
            .await
            .map_err(|_| crate::roles::tls_owner::ClientError::InitialProtection)
    }
}
impl InitialKeyProtection for InitialProtection<'_, '_> {
    async fn receive_mask(&mut self, sample: [u8; 16]) -> Result<[u8; 5], Error> {
        Ok(self
            .receive
            .as_mut()
            .ok_or(Error::Retired)?
            .header_mask(sample)
            .await
            .map_err(Error::Protection)??)
    }
    async fn transmit_mask(&mut self, sample: [u8; 16]) -> Result<[u8; 5], Error> {
        Ok(self
            .transmit
            .as_mut()
            .ok_or(Error::Retired)?
            .header_mask(sample)
            .await
            .map_err(Error::Protection)??)
    }
    async fn seal(
        &mut self,
        pn: u64,
        header: &[u8],
        body: &mut [u8],
        len: usize,
    ) -> Result<(), Error> {
        let packet = Packet::new(pn, header, body.get(..len).ok_or(Error::Capacity)?)?;
        let packet = self
            .transmit
            .as_mut()
            .ok_or(Error::Retired)?
            .seal(packet)
            .await
            .map_err(Error::Protection)??;
        let destination = body.get_mut(..packet.body().len()).ok_or(Error::Capacity)?;
        destination.copy_from_slice(packet.body());
        Ok(())
    }
    async fn rekey(&mut self, destination: &[u8], side: Side) -> Result<(), Error> {
        self.receive
            .as_mut()
            .ok_or(Error::Retired)?
            .rekey_initial(destination, side == Side::Server)
            .await
            .map_err(Error::Protection)??;
        self.transmit
            .as_mut()
            .ok_or(Error::Retired)?
            .rekey_initial(destination, side == Side::Client)
            .await
            .map_err(Error::Protection)??;
        Ok(())
    }
    async fn retire(&mut self) -> Result<(), Error> {
        if let Some(receive) = self.receive.take() {
            receive.retire().await.map_err(Error::Protection)?;
        }
        if let Some(transmit) = self.transmit.take() {
            transmit.retire().await.map_err(Error::Protection)?;
        }
        Ok(())
    }
    fn close(&mut self) {
        // Drop closes each client's unique command/reply halves. No replacement
        // capability can be manufactured from these one-shot mailbox splits.
        self.receive.take();
        self.transmit.take();
    }
}

/// Dropping any pending public packet-I/O operation abandons this connection.
/// In particular, cancellation after Open publication cannot expose an endpoint
/// with a fresh integrity budget or a resumable half-finished send reservation.
struct CancelOnDrop<'a, 'r, 's, 'tc, 'ts, K: InitialKeyProtection> {
    endpoint: &'a mut HandshakeEndpoint<'r, 's, 'tc, 'ts, K>,
    complete: bool,
}
impl<'a, 'r, 's, 'tc, 'ts, K: InitialKeyProtection> CancelOnDrop<'a, 'r, 's, 'tc, 'ts, K> {
    fn new(endpoint: &'a mut HandshakeEndpoint<'r, 's, 'tc, 'ts, K>) -> Self {
        Self {
            endpoint,
            complete: false,
        }
    }
}
impl<K: InitialKeyProtection> Drop for CancelOnDrop<'_, '_, '_, '_, '_, K> {
    fn drop(&mut self) {
        if !self.complete {
            self.endpoint.retire();
        }
    }
}

impl<'r, 's, 'tc, 'ts, K: InitialKeyProtection> HandshakeEndpoint<'r, 's, 'tc, 'ts, K> {
    pub(super) async fn open_initial(
        &mut self,
        pn: u64,
        header: &[u8],
        body: &mut [u8],
    ) -> Result<(usize, crate::roles::packet_protection::OpenReceipt), Error> {
        let packet = Packet::new(pn, header, body)?;
        let mut loan = self
            .tls
            .as_mut()
            .ok_or(Error::Retired)?
            .loan_integrity()
            .await?
            .ok_or(Error::IntegrityLoanUnavailable)?;
        let result = loan.open_initial(&mut self.initial, packet).await?;
        loan.return_to_owner().await?;
        let opened = result?;
        let len = opened.packet.body().len();
        body.get_mut(..len)
            .ok_or(Error::Capacity)?
            .copy_from_slice(opened.packet.body());
        Ok((len, opened.receipt))
    }
    /// Gracefully retire actor-owned keys without sending a QUIC close frame.
    /// Use after the enclosing application has finished its accepted output.
    /// Aborting a suspended shutdown still terminally retires the connection.
    pub async fn retire_owned(&mut self) -> Result<(), Error> {
        let mut guard = CancelOnDrop::new(self);
        let result = async {
            guard.endpoint.initial.retire().await?;
            guard.endpoint.retire_tls().await?;
            Ok::<(), Error>(())
        }
        .await;
        guard.endpoint.retire();
        guard.complete = true;
        result
    }
    pub async fn timer(&mut self, now: u64) -> Result<(), Error> {
        let mut guard = CancelOnDrop::new(self);
        let result = guard.endpoint.timer_impl(now).await;
        if matches!(&result, Err(Error::Protection(_) | Error::TlsOwner(_))) {
            guard.endpoint.retire();
        }
        guard.complete = true;
        result
    }
    pub async fn close(&mut self, reason: CloseReason) -> Result<(), Error> {
        let mut guard = CancelOnDrop::new(self);
        let result = guard.endpoint.close_impl(reason).await;
        if matches!(&result, Err(Error::Protection(_) | Error::TlsOwner(_))) {
            guard.endpoint.retire();
        }
        guard.complete = true;
        result
    }
    pub async fn initiate_key_update(&mut self) -> Result<(), Error> {
        let mut guard = CancelOnDrop::new(self);
        let result = guard.endpoint.initiate_key_update_impl().await;
        if matches!(&result, Err(Error::Protection(_) | Error::TlsOwner(_))) {
            guard.endpoint.retire();
        }
        guard.complete = true;
        result
    }
    pub async fn reject_early_packets(&mut self) -> Result<u64, Error> {
        let mut guard = CancelOnDrop::new(self);
        let result = guard.endpoint.reject_early_packets_impl().await;
        if matches!(&result, Err(Error::Protection(_) | Error::TlsOwner(_))) {
            guard.endpoint.retire();
        }
        guard.complete = true;
        result
    }
    pub async fn transmit_early_application(
        &mut self,
        encoded: &[u8],
        out: &mut [u8],
    ) -> Result<Option<Transmit>, Error> {
        let mut guard = CancelOnDrop::new(self);
        let result = guard
            .endpoint
            .transmit_early_application_impl(encoded, out)
            .await;
        if matches!(&result, Err(Error::Protection(_) | Error::TlsOwner(_))) {
            guard.endpoint.retire();
        }
        guard.complete = true;
        result
    }
    /// Await packet-key roles while processing one datagram. Cancellation
    /// abandons this connection; retain input and retry only after Busy.
    pub async fn receive_with_metadata<A: ApplicationHandler>(
        &mut self,
        datagram: &[u8],
        scratch: &mut [u8],
        metadata: ecn::Metadata,
        handler: &mut A,
    ) -> Result<Received, Error> {
        let mut guard = CancelOnDrop::new(self);
        let result = guard
            .endpoint
            .receive_with_metadata_impl(datagram, scratch, metadata, handler)
            .await;
        if matches!(&result, Err(Error::Protection(_) | Error::TlsOwner(_))) {
            guard.endpoint.retire();
        }
        guard.complete = true;
        result
    }
    /// Await Initial AEAD and header protection under unique actor ownership.
    /// Cancellation abandons this connection and every pending reservation.
    pub async fn transmit(&mut self, out: &mut [u8]) -> Result<Option<Transmit>, Error> {
        let mut guard = CancelOnDrop::new(self);
        let result = guard.endpoint.transmit_impl(out).await;
        if matches!(&result, Err(Error::Protection(_) | Error::TlsOwner(_))) {
            guard.endpoint.retire();
        }
        guard.complete = true;
        result
    }
    pub async fn transmit_application(
        &mut self,
        encoded_frames: &[u8],
        out: &mut [u8],
    ) -> Result<Option<Transmit>, Error> {
        let mut guard = CancelOnDrop::new(self);
        let result = guard
            .endpoint
            .transmit_application_impl(encoded_frames, out)
            .await;
        if matches!(&result, Err(Error::Protection(_) | Error::TlsOwner(_))) {
            guard.endpoint.retire();
        }
        guard.complete = true;
        result
    }
    /// Reporting adapter completion can retire or replace actor-owned Initial
    /// keys, so it is asynchronous even though accounting itself is numerical.
    pub async fn adapter_result(
        &mut self,
        output: Transmit,
        accepted: bool,
        now: u64,
    ) -> Result<(), Error> {
        let mut guard = CancelOnDrop::new(self);
        let result = guard
            .endpoint
            .adapter_result_impl(output, accepted, now)
            .await;
        if matches!(&result, Err(Error::Protection(_) | Error::TlsOwner(_))) {
            guard.endpoint.retire();
        }
        guard.complete = true;
        result
    }
    pub async fn receive_from<A: ApplicationHandler>(
        &mut self,
        datagram: &[u8],
        scratch: &mut [u8],
        address: crate::path::Address,
        codepoint: Option<Codepoint>,
        handler: &mut A,
    ) -> Result<Received, Error> {
        let mut guard = CancelOnDrop::new(self);
        let result = guard
            .endpoint
            .receive_from_impl(datagram, scratch, address, codepoint, handler)
            .await;
        if matches!(&result, Err(Error::Protection(_) | Error::TlsOwner(_))) {
            guard.endpoint.retire();
        }
        guard.complete = true;
        result
    }
}
