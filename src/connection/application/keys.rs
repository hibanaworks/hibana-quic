//! Synchronous application write ownership with an independent projected
//! key-control continuation. No key borrow survives a wire or UDP await.
use super::protocol as p;
use crate::{
    bounded_tls::key_source::TransmitPacketKey,
    connection::{
        self, TransmitContinuation,
        application_wire::{self, SealedApplicationDatagram},
        recovery::Reservation,
        tls::{Inbox, InboxError},
    },
    crypto::{
        self, PacketKey,
        directional::{
            ApplicationKeyScope, ApplicationWriteKeys, PeerUpdateAuthenticated,
            ScopedHandshakeConfirmation, ValidatedKeyAck, WriteEpochInstalled,
        },
    },
};
use core::cell::RefCell;
use hibana::{Endpoint, EndpointError};

#[derive(Debug)]
pub(crate) enum Error {
    Endpoint(EndpointError),
    Crypto(crypto::Error),
    Slot(InboxError),
    Binding,
    Retired,
    UnexpectedLabel(u8),
}

impl From<EndpointError> for Error {
    fn from(error: EndpointError) -> Self {
        Self::Endpoint(error)
    }
}
impl From<crypto::Error> for Error {
    fn from(error: crypto::Error) -> Self {
        Self::Crypto(error)
    }
}
impl From<InboxError> for Error {
    fn from(error: InboxError) -> Self {
        Self::Slot(error)
    }
}

struct Owned<'scope> {
    initial: Option<PacketKey>,
    handshake: Option<TransmitPacketKey<'scope>>,
    application: Option<ApplicationWriteKeys<'scope>>,
    retired: bool,
}

/// TX sealing and key-control may share this owner. Each operation is entirely
/// synchronous, including release of the interior borrow. A sealed datagram
/// owns its reservation and can remain pending while key control progresses.
pub(crate) struct KeyOwner<'scope> {
    scope: &'scope ApplicationKeyScope,
    owned: RefCell<Owned<'scope>>,
}

impl<'scope> KeyOwner<'scope> {
    pub(crate) fn new(
        scope: &'scope ApplicationKeyScope,
        continuation: TransmitContinuation<'scope>,
    ) -> Result<Self, Error> {
        if !core::ptr::eq(scope, continuation.application.scope())
            || !core::ptr::eq(scope, continuation.handshake.scope())
        {
            return Err(Error::Binding);
        }
        Ok(Self {
            scope,
            owned: RefCell::new(Owned {
                initial: Some(continuation.initial),
                handshake: Some(continuation.handshake),
                application: Some(continuation.application),
                retired: false,
            }),
        })
    }

    pub(crate) const fn scope(&self) -> &'scope ApplicationKeyScope {
        self.scope
    }

    pub(crate) fn generation(&self) -> Result<u64, Error> {
        let owned = self.owned.try_borrow().map_err(|_| Error::Binding)?;
        Ok(owned.application.as_ref().ok_or(Error::Retired)?.generation())
    }

    pub(crate) fn phase(&self) -> Result<bool, Error> {
        let owned = self.owned.try_borrow().map_err(|_| Error::Binding)?;
        Ok(owned.application.as_ref().ok_or(Error::Retired)?.phase())
    }

    pub(crate) fn seal<'book, const N: usize>(
        &self,
        reservation: Reservation<'book>,
        destination_cid: &[u8],
        plaintext: &[u8],
    ) -> Result<SealedApplicationDatagram<'book, N>, (connection::Error, Reservation<'book>)>
    {
        let Ok(mut owned) = self.owned.try_borrow_mut() else {
            return Err((connection::Error::Binding, reservation));
        };
        if owned.retired {
            return Err((connection::Error::Binding, reservation));
        }
        let Some(keys) = owned.application.as_mut() else {
            return Err((connection::Error::Binding, reservation));
        };
        application_wire::seal(keys, reservation, destination_cid, plaintext)
    }

    fn install_peer_update(
        &self,
        request: PeerUpdate<'scope>,
    ) -> Result<WriteEpochInstalled<'scope>, Error> {
        let mut owned = self.owned.try_borrow_mut().map_err(|_| Error::Binding)?;
        if owned.retired {
            return Err(Error::Retired);
        }
        let keys = owned.application.as_mut().ok_or(Error::Retired)?;
        keys.maintain(request.now, request.pto)?;
        Ok(keys.install_peer_update(request.authenticated)?)
    }

    fn acknowledge(&self, request: KeyAck<'scope>) -> Result<(), Error> {
        let mut owned = self.owned.try_borrow_mut().map_err(|_| Error::Binding)?;
        if owned.retired {
            return Err(Error::Retired);
        }
        owned
            .application
            .as_mut()
            .ok_or(Error::Retired)?
            .acknowledge(request.validated, request.now, request.pto)?;
        Ok(())
    }

    fn confirm(&self, confirmation: ScopedHandshakeConfirmation<'scope>) -> Result<(), Error> {
        let mut owned = self.owned.try_borrow_mut().map_err(|_| Error::Binding)?;
        if owned.retired {
            return Err(Error::Retired);
        }
        owned
            .application
            .as_mut()
            .ok_or(Error::Retired)?
            .confirm_handshake(confirmation)?;
        // Only the actual scoped QUIC confirmation retires these transferred
        // write keys; TLS completion and application-key availability do not.
        owned.initial = None;
        owned.handshake = None;
        Ok(())
    }

    fn retire(&self) -> Result<KeysQuiesced<'_, 'scope>, Error> {
        let mut owned = self.owned.try_borrow_mut().map_err(|_| Error::Binding)?;
        if owned.retired || owned.application.is_none() {
            return Err(Error::Retired);
        }
        owned.retired = true;
        Ok(KeysQuiesced {
            owner: self,
            scope: self.scope,
        })
    }

    /// The finite close continuation can acquire the actual application key
    /// only after the projected key-control role has retired. The grant and
    /// key are each consumed once; ordinary sealing stays permanently stopped.
    pub(crate) fn take_closing(
        &self,
        quiesced: KeysQuiesced<'_, 'scope>,
    ) -> Result<ApplicationWriteKeys<'scope>, Error> {
        if !core::ptr::eq(self, quiesced.owner) || !core::ptr::eq(self.scope, quiesced.scope) {
            return Err(Error::Binding);
        }
        let mut owned = self.owned.try_borrow_mut().map_err(|_| Error::Binding)?;
        if !owned.retired {
            return Err(Error::Binding);
        }
        owned.application.take().ok_or(Error::Retired)
    }
}

#[must_use = "the closing continuation must consume actual key-role retirement"]
pub(crate) struct KeysQuiesced<'owner, 'scope> {
    owner: &'owner KeyOwner<'scope>,
    scope: &'scope ApplicationKeyScope,
}

struct PeerUpdate<'scope> {
    authenticated: PeerUpdateAuthenticated<'scope>,
    now: u64,
    pto: u64,
}
struct KeyAck<'scope> {
    validated: ValidatedKeyAck<'scope>,
    now: u64,
    pto: u64,
}

/// Each lane carries its actual affine object, beside its corresponding
/// projected wire edge. Numeric wire sequence values are correlation only.
pub(crate) struct Exchange<'owner, 'scope> {
    owner: &'owner KeyOwner<'scope>,
    peer_update: Inbox<PeerUpdate<'scope>>,
    write_installed: Inbox<Result<WriteEpochInstalled<'scope>, Error>>,
    key_ack: Inbox<KeyAck<'scope>>,
    key_ack_applied: Inbox<Result<(), Error>>,
    confirmation: Inbox<ScopedHandshakeConfirmation<'scope>>,
    confirmation_applied: Inbox<Result<(), Error>>,
    quiesced: Inbox<KeysQuiesced<'owner, 'scope>>,
}

impl<'owner, 'scope> Exchange<'owner, 'scope> {
    pub(crate) const fn new(owner: &'owner KeyOwner<'scope>) -> Self {
        Self {
            owner,
            peer_update: Inbox::new(),
            write_installed: Inbox::new(),
            key_ack: Inbox::new(),
            key_ack_applied: Inbox::new(),
            confirmation: Inbox::new(),
            confirmation_applied: Inbox::new(),
            quiesced: Inbox::new(),
        }
    }
}

/// The receive role serializes its actual affine transitions on RX_KEYS.
/// Only ApplicationReadKeys::accept_write_epoch can turn peer_update's result
/// into ACK eligibility; neither this client nor the write owner can mint it.
pub(crate) struct RxControl<'lane, 'owner, 'scope> {
    exchange: &'lane Exchange<'owner, 'scope>,
    sequence: u64,
    retired: bool,
}

impl<'lane, 'owner, 'scope> RxControl<'lane, 'owner, 'scope> {
    pub(crate) const fn new(exchange: &'lane Exchange<'owner, 'scope>) -> Self {
        Self {
            exchange,
            sequence: 0,
            retired: false,
        }
    }

    fn active(&self) -> Result<u64, Error> {
        if self.retired {
            Err(Error::Retired)
        } else {
            Ok(self.sequence)
        }
    }

    fn advance(&mut self) -> Result<(), Error> {
        self.sequence = self.sequence.checked_add(1).ok_or(Error::Binding)?;
        Ok(())
    }

    pub(crate) async fn peer_update(
        &mut self,
        endpoint: &mut Endpoint<'_, { p::RX_KEYS }>,
        authenticated: PeerUpdateAuthenticated<'scope>,
        now: u64,
        pto: u64,
    ) -> Result<WriteEpochInstalled<'scope>, Error> {
        let sequence = self.active()?;
        self.exchange.peer_update.put(PeerUpdate {
            authenticated,
            now,
            pto,
        })?;
        endpoint.send::<p::PeerUpdate>(&sequence).await?;
        let response = endpoint.offer().await?;
        let accepted = match response.label() {
            12 => {
                check(response.recv::<p::WriteInstalled>().await?, sequence)?;
                true
            }
            13 => {
                check(response.recv::<p::UpdateFailed>().await?, sequence)?;
                false
            }
            label => return Err(Error::UnexpectedLabel(label)),
        };
        let result = self.exchange.write_installed.take()?;
        check_result(&result, accepted)?;
        self.advance()?;
        result
    }

    pub(crate) async fn acknowledge(
        &mut self,
        endpoint: &mut Endpoint<'_, { p::RX_KEYS }>,
        validated: ValidatedKeyAck<'scope>,
        now: u64,
        pto: u64,
    ) -> Result<(), Error> {
        let sequence = self.active()?;
        self.exchange.key_ack.put(KeyAck { validated, now, pto })?;
        endpoint.send::<p::KeyAck>(&sequence).await?;
        let response = endpoint.offer().await?;
        let accepted = match response.label() {
            15 => {
                check(response.recv::<p::KeyAckApplied>().await?, sequence)?;
                true
            }
            16 => {
                check(response.recv::<p::KeyAckFailed>().await?, sequence)?;
                false
            }
            label => return Err(Error::UnexpectedLabel(label)),
        };
        let result = self.exchange.key_ack_applied.take()?;
        check_result(&result, accepted)?;
        self.advance()?;
        result
    }

    pub(crate) async fn confirm(
        &mut self,
        endpoint: &mut Endpoint<'_, { p::RX_KEYS }>,
        confirmation: ScopedHandshakeConfirmation<'scope>,
    ) -> Result<(), Error> {
        let sequence = self.active()?;
        self.exchange.confirmation.put(confirmation)?;
        endpoint.send::<p::Confirmed>(&sequence).await?;
        let response = endpoint.offer().await?;
        let accepted = match response.label() {
            18 => {
                check(response.recv::<p::ConfirmationApplied>().await?, sequence)?;
                true
            }
            19 => {
                check(response.recv::<p::ConfirmationFailed>().await?, sequence)?;
                false
            }
            label => return Err(Error::UnexpectedLabel(label)),
        };
        let result = self.exchange.confirmation_applied.take()?;
        check_result(&result, accepted)?;
        self.advance()?;
        result
    }

    pub(crate) async fn retire(
        &mut self,
        endpoint: &mut Endpoint<'_, { p::RX_KEYS }>,
    ) -> Result<KeysQuiesced<'owner, 'scope>, Error> {
        let sequence = self.active()?;
        endpoint.send::<p::KeysRetire>(&sequence).await?;
        check(endpoint.recv::<p::KeysRetired>().await?, sequence)?;
        let quiesced = self.exchange.quiesced.take()?;
        self.retired = true;
        Ok(quiesced)
    }
}

/// Owns only the key-control endpoint. Its synchronous owner is also available
/// to the independent TX sealing future, so a pending UDP syscall cannot hold
/// the key-update continuation hostage.
pub(crate) async fn run<'owner, 'scope>(
    endpoint: &mut Endpoint<'_, { p::TX_KEYS }>,
    owner: &'owner KeyOwner<'scope>,
    exchange: &Exchange<'owner, 'scope>,
) -> Result<(), Error> {
    if !core::ptr::eq(owner, exchange.owner) {
        return Err(Error::Binding);
    }
    let mut sequence = 0u64;
    loop {
        let request = endpoint.offer().await?;
        match request.label() {
            11 => {
                check(request.recv::<p::PeerUpdate>().await?, sequence)?;
                let result = owner.install_peer_update(exchange.peer_update.take()?);
                let accepted = result.is_ok();
                exchange.write_installed.put(result)?;
                if accepted {
                    endpoint.send::<p::WriteInstalled>(&sequence).await?;
                } else {
                    endpoint.send::<p::UpdateFailed>(&sequence).await?;
                }
            }
            14 => {
                check(request.recv::<p::KeyAck>().await?, sequence)?;
                let result = owner.acknowledge(exchange.key_ack.take()?);
                let accepted = result.is_ok();
                exchange.key_ack_applied.put(result)?;
                if accepted {
                    endpoint.send::<p::KeyAckApplied>(&sequence).await?;
                } else {
                    endpoint.send::<p::KeyAckFailed>(&sequence).await?;
                }
            }
            17 => {
                check(request.recv::<p::Confirmed>().await?, sequence)?;
                let result = owner.confirm(exchange.confirmation.take()?);
                let accepted = result.is_ok();
                exchange.confirmation_applied.put(result)?;
                if accepted {
                    endpoint.send::<p::ConfirmationApplied>(&sequence).await?;
                } else {
                    endpoint.send::<p::ConfirmationFailed>(&sequence).await?;
                }
            }
            20 => {
                check(request.recv::<p::KeysRetire>().await?, sequence)?;
                exchange.quiesced.put(owner.retire()?)?;
                endpoint.send::<p::KeysRetired>(&sequence).await?;
                return Ok(());
            }
            label => return Err(Error::UnexpectedLabel(label)),
        }
        sequence = sequence.checked_add(1).ok_or(Error::Binding)?;
        crate::runtime::yield_now().await;
    }
}

fn check(received: u64, expected: u64) -> Result<(), Error> {
    if received == expected {
        Ok(())
    } else {
        Err(Error::Binding)
    }
}

fn check_result<T>(result: &Result<T, Error>, accepted: bool) -> Result<(), Error> {
    if result.is_ok() == accepted {
        Ok(())
    } else {
        Err(Error::Binding)
    }
}
