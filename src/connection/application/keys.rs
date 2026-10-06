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
            ApplicationKeyScope, ApplicationWriteKeys, LocalUpdateReady, LocalUpdateRejected,
            LocalWriteEpochInstalled, PeerUpdateAuthenticated, ScopedHandshakeConfirmation,
            ValidatedKeyAck, WriteEpochInstalled,
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

    fn retire_control(&self) -> Result<(), Error> {
        // This edge retires key-control work, not the independent ordinary TX
        // owner. Keep the actual key until the joined ordinary-retirement
        // receipt is consumed at the finite closing boundary.
        if self
            .owned
            .try_borrow()
            .map_err(|_| Error::Binding)?
            .application
            .is_none()
        {
            return Err(Error::Retired);
        }
        Ok(())
    }

    /// The finite close continuation can acquire the actual application key
    /// only after all ordinary roles, including actual KeysRetired receive and
    /// independent TX settlement, have joined. The existing ordinary receipt
    /// carries that boundary; no second key-control completion token is needed.
    pub(crate) fn take_closing(
        &self,
        ordinary: &super::OrdinaryRetired<'scope>,
    ) -> Result<ApplicationWriteKeys<'scope>, Error> {
        if !core::ptr::eq(self.scope, ordinary.scope()) {
            return Err(Error::Binding);
        }
        let mut owned = self.owned.try_borrow_mut().map_err(|_| Error::Binding)?;
        owned.initial = None;
        owned.handshake = None;
        owned.application.take().ok_or(Error::Retired)
    }
}

pub(super) struct PeerUpdate<'scope> {
    pub(super) authenticated: PeerUpdateAuthenticated<'scope>,
    pub(super) now: u64,
    pub(super) pto: u64,
}
pub(super) struct LocalUpdateRequest<'scope> {
    pub(super) ready: LocalUpdateReady<'scope>,
    pub(super) now: u64,
    pub(super) pto: u64,
}
pub(super) struct KeyAck<'scope> {
    pub(super) validated: ValidatedKeyAck<'scope>,
    pub(super) now: u64,
    pub(super) pto: u64,
}

/// Each lane carries its actual affine object, beside its corresponding
/// projected edge. Scope and epoch binding belong to these actual objects.
pub(crate) struct Exchange<'owner, 'scope> {
    pub(super) owner: &'owner KeyOwner<'scope>,
    pub(super) peer_update: Inbox<PeerUpdate<'scope>>,
    pub(super) write_installed: Inbox<Result<WriteEpochInstalled<'scope>, Error>>,
    pub(super) local_update: Inbox<LocalUpdateRequest<'scope>>,
    pub(super) local_result:
        Inbox<Result<LocalWriteEpochInstalled<'scope>, LocalUpdateRejected<'scope>>>,
    pub(super) key_ack: Inbox<KeyAck<'scope>>,
    pub(super) key_ack_applied: Inbox<Result<(), Error>>,
    pub(super) confirmation: Inbox<ScopedHandshakeConfirmation<'scope>>,
    pub(super) confirmation_applied: Inbox<Result<(), Error>>,
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
        }
    }
}

/// The receive role serializes its actual affine transitions on RX_KEYS.
/// Only ApplicationReadKeys::accept_write_epoch can turn peer_update's result
/// into ACK eligibility; neither this client nor the write owner can mint it.
pub(crate) struct RxControl<'lane, 'owner, 'scope> {
    pub(super) exchange: &'lane Exchange<'owner, 'scope>,
}

impl<'lane, 'owner, 'scope> RxControl<'lane, 'owner, 'scope> {
    pub(crate) const fn new(exchange: &'lane Exchange<'owner, 'scope>) -> Self {
        Self { exchange }
    }

    pub(crate) fn local_update_due(&self, target: u64, now: u64) -> Result<bool, Error> {
        let owned = self
            .exchange
            .owner
            .owned
            .try_borrow()
            .map_err(|_| Error::Binding)?;
        Ok(owned
            .application
            .as_ref()
            .ok_or(Error::Retired)?
            .local_update_due(target, now)?)
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
    loop {
        let request = endpoint.offer().await?;
        match request.label() {
            11 => {
                request.recv::<p::PeerUpdate>().await?;
                let result = owner.install_peer_update(exchange.peer_update.take()?);
                let accepted = result.is_ok();
                exchange.write_installed.put(result)?;
                if accepted {
                    endpoint.send::<p::WriteInstalled>(&()).await?;
                } else {
                    endpoint.send::<p::UpdateFailed>(&()).await?;
                }
            }
            14 => {
                request.recv::<p::KeyAck>().await?;
                let result = owner.acknowledge(exchange.key_ack.take()?);
                let accepted = result.is_ok();
                exchange.key_ack_applied.put(result)?;
                if accepted {
                    endpoint.send::<p::KeyAckApplied>(&()).await?;
                } else {
                    endpoint.send::<p::KeyAckFailed>(&()).await?;
                }
            }
            17 => {
                request.recv::<p::Confirmed>().await?;
                let result = owner.confirm(exchange.confirmation.take()?);
                let accepted = result.is_ok();
                exchange.confirmation_applied.put(result)?;
                if accepted {
                    endpoint.send::<p::ConfirmationApplied>(&()).await?;
                } else {
                    endpoint.send::<p::ConfirmationFailed>(&()).await?;
                }
            }
            205 => {
                request.recv::<p::LocalUpdate>().await?;
                let result = owner.local_update(exchange.local_update.take()?);
                let accepted = result.is_ok();
                exchange.local_result.put(result)?;
                if accepted {
                    endpoint.send::<p::LocalInstalled>(&()).await?;
                } else {
                    endpoint.send::<p::LocalRejected>(&()).await?;
                }
                endpoint.recv::<p::LocalSettled>().await?;
            }
            20 => {
                request.recv::<p::KeysRetire>().await?;
                owner.retire_control()?;
                endpoint.send::<p::KeysRetired>(&()).await?;
                return Ok(());
            }
            label => return Err(Error::UnexpectedLabel(label)),
        }

        crate::runtime::yield_now().await;
    }
}

pub(super) fn check_result<T>(result: &Result<T, Error>, accepted: bool) -> Result<(), Error> {
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
        let control = RxControl::new(&exchange);
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
                assert!(!control.local_update_due(0, 0).unwrap());
                assert_eq!(control.local_update_due(1, 0).unwrap(), authorized_fixture);
                let result = async {
                    let endpoint = &mut rx;
                    let read = &mut read;
                    let now = 0;
                    let pto = 10;

                    read.maintain(now, pto)?;
                    let ready = read.prepare_local_update()?;
                    control
                        .exchange
                        .local_update
                        .put(LocalUpdateRequest { ready, now, pto })?;
                    endpoint.send::<p::LocalUpdate>(&()).await?;
                    let offered = endpoint.offer().await?;
                    let accepted = match offered.label() {
                        206 => {
                            offered.recv::<p::LocalInstalled>().await?;
                            true
                        }
                        207 => {
                            offered.recv::<p::LocalRejected>().await?;
                            false
                        }
                        label => {
                            return Err(Error::UnexpectedLabel(label));
                        }
                    };
                    let result = control.exchange.local_result.take()?;
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
                    endpoint.send::<p::LocalSettled>(&()).await?;

                    result
                }
                .await;
                if authorized_fixture {
                    result.unwrap();
                    assert_eq!(owner.generation().unwrap(), 1);
                    assert!(!control.local_update_due(1, 0).unwrap());
                } else {
                    assert!(matches!(
                        result,
                        Err(Error::Crypto(crypto::Error::KeyUpdateNotAllowed))
                    ));
                    assert_eq!(owner.generation().unwrap(), 0);
                }
                assert_eq!(read.header_mask(&[0; 16]).unwrap(), expected);
                async {
                    let endpoint = &mut rx;

                    endpoint.send::<p::KeysRetire>(&()).await?;
                    endpoint.recv::<p::KeysRetired>().await?;
                    Ok::<(), Error>(())
                }
                .await?;
                assert!(
                    owner.generation().is_ok(),
                    "key-control retirement must preserve independent TX ownership"
                );
                // Isolated role fixture: production constructs this receipt
                // only after every ordinary future and adapter has completed.
                let ordinary = super::super::OrdinaryRetired { scope };
                let _actual_closing_key = owner.take_closing(&ordinary)?;
                assert!(matches!(owner.generation(), Err(Error::Retired)));
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
