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
            ApplicationKeyScope, ApplicationReadKeys, ApplicationWriteKeys, LocalUpdateReady,
            LocalUpdateRejected, LocalWriteEpochInstalled, PeerUpdateAuthenticated,
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
                initial: continuation.initial,
                handshake: Some(continuation.handshake),
                application: Some(continuation.application),
            }),
        })
    }

    pub(crate) const fn scope(&self) -> &'scope ApplicationKeyScope {
        self.scope
    }

    pub(crate) fn generation(&self) -> Result<u64, Error> {
        let owned = self.owned.try_borrow().map_err(|_| Error::Binding)?;
        Ok(owned
            .application
            .as_ref()
            .ok_or(Error::Retired)?
            .generation())
    }

    /// Only short synchronous inspection; no key borrow escapes this call.
    pub(crate) fn available_levels(&self) -> Result<[bool; 3], Error> {
        let owned = self.owned.try_borrow().map_err(|_| Error::Binding)?;
        Ok([
            owned.initial.is_some(),
            owned.handshake.is_some(),
            owned.application.is_some(),
        ])
    }

    /// Retained Handshake CRYPTO/ACK packets are sealed while borrowing only
    /// their actual key. Application key control remains independently usable.
    pub(crate) fn seal_long<'book, const N: usize>(
        &self,
        level: crate::tls::Level,
        plain: connection::wire::PlainPacket<N>,
        reservation: Reservation<'book>,
        acknowledgment: Option<connection::recovery::AckSnapshot<'book>>,
    ) -> Result<connection::wire::Datagram<'book, N>, (connection::Error, Reservation<'book>)> {
        let Ok(mut owned) = self.owned.try_borrow_mut() else {
            return Err((connection::Error::Binding, reservation));
        };
        if !core::ptr::eq(self.scope, reservation.scope()) {
            return Err((connection::Error::Binding, reservation));
        }
        match level {
            crate::tls::Level::Initial => match owned.initial.as_mut() {
                Some(key) => plain.seal_initial(key, reservation, acknowledgment),
                None => Err((connection::Error::UnsupportedLevel, reservation)),
            },
            crate::tls::Level::Handshake => match owned.handshake.as_mut() {
                Some(key) => plain.seal_handshake(key, reservation, acknowledgment),
                None => Err((connection::Error::UnsupportedLevel, reservation)),
            },
            crate::tls::Level::OneRtt => Err((connection::Error::UnsupportedLevel, reservation)),
        }
    }

    pub(crate) fn seal<'book, const N: usize>(
        &self,
        reservation: Reservation<'book>,
        destination_cid: &[u8],
        plaintext: &[u8],
    ) -> Result<SealedApplicationDatagram<'book, N>, (connection::Error, Reservation<'book>)> {
        let Ok(mut owned) = self.owned.try_borrow_mut() else {
            return Err((connection::Error::Binding, reservation));
        };
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
        let keys = owned.application.as_mut().ok_or(Error::Retired)?;
        keys.maintain(request.now, request.pto)?;
        Ok(keys.install_peer_update(request.authenticated)?)
    }

    fn local_update(
        &self,
        request: LocalUpdateRequest<'scope>,
    ) -> Result<LocalWriteEpochInstalled<'scope>, LocalUpdateRejected<'scope>> {
        let LocalUpdateRequest { ready, now, pto } = request;
        let mut owned = match self.owned.try_borrow_mut() {
            Ok(owned) => owned,
            Err(_) => {
                return Err(LocalUpdateRejected {
                    error: crypto::Error::KeyUpdateNotAllowed,
                    ready,
                });
            }
        };
        let Some(keys) = owned.application.as_mut() else {
            return Err(LocalUpdateRejected {
                error: crypto::Error::KeyDiscarded,
                ready,
            });
        };
        if let Err(error) = keys.maintain(now, pto) {
            return Err(LocalUpdateRejected { error, ready });
        }
        keys.initiate(ready, now, pto)
    }

    fn acknowledge(&self, request: KeyAck<'scope>) -> Result<(), Error> {
        let mut owned = self.owned.try_borrow_mut().map_err(|_| Error::Binding)?;
        owned
            .application
            .as_mut()
            .ok_or(Error::Retired)?
            .acknowledge(request.validated, request.now, request.pto)?;
        Ok(())
    }

    fn confirm(&self, confirmation: ScopedHandshakeConfirmation<'scope>) -> Result<(), Error> {
        let mut owned = self.owned.try_borrow_mut().map_err(|_| Error::Binding)?;
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
        // The projected retirement edge transfers the actual final write key.
        // No parallel boolean keeps a second authority to ordinary sealing.
        let application = owned.application.take().ok_or(Error::Retired)?;
        owned.initial = None;
        owned.handshake = None;
        Ok(KeysQuiesced {
            owner: self,
            scope: self.scope,
            application,
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
        Ok(quiesced.application)
    }
}

#[must_use = "the closing continuation must consume actual key-role retirement"]
pub(crate) struct KeysQuiesced<'owner, 'scope> {
    owner: &'owner KeyOwner<'scope>,
    scope: &'scope ApplicationKeyScope,
    application: ApplicationWriteKeys<'scope>,
}

struct PeerUpdate<'scope> {
    authenticated: PeerUpdateAuthenticated<'scope>,
    now: u64,
    pto: u64,
}
struct LocalUpdateRequest<'scope> {
    ready: LocalUpdateReady<'scope>,
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
    local_update: Inbox<LocalUpdateRequest<'scope>>,
    local_result: Inbox<Result<LocalWriteEpochInstalled<'scope>, LocalUpdateRejected<'scope>>>,
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
            local_update: Inbox::new(),
            local_result: Inbox::new(),
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
}

impl<'lane, 'owner, 'scope> RxControl<'lane, 'owner, 'scope> {
    pub(crate) const fn new(exchange: &'lane Exchange<'owner, 'scope>) -> Self {
        Self {
            exchange,
            sequence: 0,
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
        let sequence = self.sequence;
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

    /// The parked object owns the actual receive key until the projected
    /// write-owner response returns it. No local-update phase flag is stored.
    pub(crate) async fn local_update(
        &mut self,
        endpoint: &mut Endpoint<'_, { p::RX_KEYS }>,
        read: &mut ApplicationReadKeys<'scope>,
        now: u64,
        pto: u64,
    ) -> Result<(), Error> {
        let sequence = self.sequence;
        read.maintain(now, pto)?;
        let ready = read.prepare_local_update()?;
        self.exchange
            .local_update
            .put(LocalUpdateRequest { ready, now, pto })?;
        endpoint.send::<p::LocalUpdate>(&sequence).await?;
        let offered = endpoint.offer().await?;
        let accepted = match offered.label() {
            206 => {
                check(offered.recv::<p::LocalInstalled>().await?, sequence)?;
                true
            }
            207 => {
                check(offered.recv::<p::LocalRejected>().await?, sequence)?;
                false
            }
            label => return Err(Error::UnexpectedLabel(label)),
        };
        let result = self.exchange.local_result.take()?;
        if result.is_ok() != accepted {
            return Err(Error::Binding);
        }
        let result = match result {
            Ok(installed) => read
                .accept_local_write_epoch(installed)
                .map_err(Error::Crypto),
            Err(rejected) => {
                read.cancel_local_update(rejected.ready)?;
                Err(Error::Crypto(rejected.error))
            }
        };
        endpoint.send::<p::LocalSettled>(&sequence).await?;
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
        let sequence = self.sequence;
        self.exchange.key_ack.put(KeyAck {
            validated,
            now,
            pto,
        })?;
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
        let sequence = self.sequence;
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
        self,
        endpoint: &mut Endpoint<'_, { p::RX_KEYS }>,
    ) -> Result<KeysQuiesced<'owner, 'scope>, Error> {
        let sequence = self.sequence;
        endpoint.send::<p::KeysRetire>(&sequence).await?;
        check(endpoint.recv::<p::KeysRetired>().await?, sequence)?;
        let quiesced = self.exchange.quiesced.take()?;
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
            205 => {
                check(request.recv::<p::LocalUpdate>().await?, sequence)?;
                let result = owner.local_update(exchange.local_update.take()?);
                let accepted = result.is_ok();
                exchange.local_result.put(result)?;
                if accepted {
                    endpoint.send::<p::LocalInstalled>(&sequence).await?;
                } else {
                    endpoint.send::<p::LocalRejected>(&sequence).await?;
                }
                check(endpoint.recv::<p::LocalSettled>().await?, sequence)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{carrier::CarrierStorage, runtime::TaskSet};
    use core::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };
    use hibana::runtime::{
        SessionKitStorage,
        ids::SessionId,
        program::{RoleProgram, project},
    };

    fn run_local_update(authorized_fixture: bool) {
        // Raw cryptographic fixture only: deliberately no handshake/ACK grant.
        // The actual projected owner must reject update and return the parked key.
        let mut scope = ApplicationKeyScope::new(1200);
        let (mut read, mut write) = scope
            .install(
                PacketKey::from_secret(
                    crypto::CipherSuite::Aes128GcmSha256,
                    crypto::KeyKind::OneRtt,
                    &[1; 32],
                )
                .unwrap(),
                PacketKey::from_secret(
                    crypto::CipherSuite::Aes128GcmSha256,
                    crypto::KeyKind::OneRtt,
                    &[2; 32],
                )
                .unwrap(),
            )
            .unwrap();
        if authorized_fixture {
            crate::crypto::directional::synthetic_confirmed_ack_for_role_test(&mut write);
        }
        let scope = read.scope();
        let owner = KeyOwner {
            scope,
            owned: RefCell::new(Owned {
                initial: None,
                handshake: None,
                application: Some(write),
            }),
        };
        let exchange = Exchange::new(&owner);
        let mut control = RxControl::new(&exchange);
        let global = p::key_choreography();
        let rxp: RoleProgram<{ p::RX_KEYS }> = project(&global);
        let txp: RoleProgram<{ p::TX_KEYS }> = project(&global);
        let carrier = CarrierStorage::<1, 16, 16>::new();
        let mut slab = [0; 65536];
        let mut storage = SessionKitStorage::uninit();
        let sid = SessionId::new(1200);
        let rv = storage
            .init()
            .rendezvous(&mut slab, carrier.bind(sid).unwrap())
            .unwrap();
        let mut rx = rv.enter(sid, &rxp).unwrap();
        let mut tx = rv.enter(sid, &txp).unwrap();
        let expected = read.header_mask(&[0; 16]).unwrap();
        let measured = actor_test_allocator::NoAlloc::start();
        {
            let mut receiving = pin!(async {
                let result = control.local_update(&mut rx, &mut read, 0, 10).await;
                if authorized_fixture {
                    result.unwrap();
                    assert_eq!(owner.generation().unwrap(), 1);
                } else {
                    assert!(matches!(
                        result,
                        Err(Error::Crypto(crypto::Error::KeyUpdateNotAllowed))
                    ));
                    assert_eq!(owner.generation().unwrap(), 0);
                }
                assert_eq!(read.header_mask(&[0; 16]).unwrap(), expected);
                let closing = control.retire(&mut rx).await?;
                assert!(matches!(owner.generation(), Err(Error::Retired)));
                let _actual_closing_key = owner.take_closing(closing)?;
                Ok::<_, Error>(())
            });
            let mut writing = pin!(run(&mut tx, &owner, &exchange));
            let mut all = pin!(TaskSet::new([receiving.as_mut(), writing.as_mut()]));
            let mut outcome = None;
            for _ in 0..200 {
                if let Poll::Ready(result) =
                    all.as_mut().poll(&mut Context::from_waker(Waker::noop()))
                {
                    outcome = Some(result);
                    break;
                }
            }
            outcome.expect("projected retirement must settle").unwrap();
        }
        measured.finish();
    }
    #[test]
    fn projected_local_rejection_returns_actual_read_key_then_retires_write_owner() {
        run_local_update(false);
    }
    #[test]
    fn projected_local_installation_transfers_real_keys_with_synthetic_ack_fixture() {
        run_local_update(true);
    }
}
