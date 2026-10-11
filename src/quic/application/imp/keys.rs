//! Actual write keys and affine key-update exchange slots.
use crate::crypto;
use crate::crypto::PacketKey;
use crate::crypto::directional::ApplicationKeyScope;
use crate::crypto::directional::ApplicationWriteKeys;
use crate::crypto::directional::LocalUpdateReady;
use crate::crypto::directional::LocalUpdateRejected;
use crate::crypto::directional::LocalWriteEpochInstalled;
use crate::crypto::directional::PeerUpdateAuthenticated;
use crate::crypto::directional::ScopedHandshakeConfirmation;
use crate::crypto::directional::ValidatedKeyAck;
use crate::crypto::directional::WriteEpochInstalled;
use crate::quic;
use crate::quic::TransmitContinuation;
use crate::quic::imp::application_wire;
use crate::quic::imp::application_wire::SealedApplicationDatagram;
use crate::quic::imp::recovery::Reservation;
use crate::quic::imp::tls::Inbox;
use crate::quic::imp::tls::InboxError;
use core::cell::RefCell;
use hibana::EndpointError;
use hibana_tls::handshake::keys::TransmitPacketKey;

#[derive(Debug)]
pub(in crate::quic::application) enum Error {
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
pub(in crate::quic::application) struct KeyOwner<'scope> {
    scope: &'scope ApplicationKeyScope,
    owned: RefCell<Owned<'scope>>,
}

impl<'scope> KeyOwner<'scope> {
    pub(in crate::quic::application) fn new(
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

    pub(in crate::quic::application) const fn scope(&self) -> &'scope ApplicationKeyScope {
        self.scope
    }

    pub(in crate::quic::application) fn generation(&self) -> Result<u64, Error> {
        let owned = self.owned.try_borrow().map_err(|_| Error::Binding)?;
        Ok(owned
            .application
            .as_ref()
            .ok_or(Error::Retired)?
            .generation())
    }

    /// Only short synchronous inspection; no key borrow escapes this call.
    pub(in crate::quic::application) fn available_levels(&self) -> Result<[bool; 3], Error> {
        let owned = self.owned.try_borrow().map_err(|_| Error::Binding)?;
        Ok([
            owned.initial.is_some(),
            owned.handshake.is_some(),
            owned.application.is_some(),
        ])
    }

    /// Retained Handshake CRYPTO/ACK packets are sealed while borrowing only
    /// their actual key. Application key control remains independently usable.
    pub(in crate::quic::application) fn seal_long<'book, const N: usize>(
        &self,
        level: hibana_tls::quic::Level,
        plain: quic::wire::PlainPacket<N>,
        reservation: Reservation<'book>,
        acknowledgment: Option<quic::imp::recovery::AckSnapshot<'book>>,
    ) -> Result<quic::wire::Datagram<'book, N>, (quic::Error, Reservation<'book>)> {
        let Ok(mut owned) = self.owned.try_borrow_mut() else {
            return Err((quic::Error::Binding, reservation));
        };
        if !core::ptr::eq(self.scope, reservation.scope()) {
            return Err((quic::Error::Binding, reservation));
        }
        match level {
            hibana_tls::quic::Level::Initial => match owned.initial.as_mut() {
                Some(key) => plain.seal_initial(key, reservation, acknowledgment),
                None => Err((quic::Error::UnsupportedLevel, reservation)),
            },
            hibana_tls::quic::Level::Handshake => match owned.handshake.as_mut() {
                Some(key) => plain.seal_handshake(key, reservation, acknowledgment),
                None => Err((quic::Error::UnsupportedLevel, reservation)),
            },
            hibana_tls::quic::Level::OneRtt => Err((quic::Error::UnsupportedLevel, reservation)),
        }
    }

    pub(in crate::quic::application) fn seal<'book, const N: usize>(
        &self,
        reservation: Reservation<'book>,
        destination_cid: &[u8],
        plaintext: &[u8],
    ) -> Result<SealedApplicationDatagram<'book, N>, (quic::Error, Reservation<'book>)> {
        let Ok(mut owned) = self.owned.try_borrow_mut() else {
            return Err((quic::Error::Binding, reservation));
        };
        let Some(keys) = owned.application.as_mut() else {
            return Err((quic::Error::Binding, reservation));
        };
        application_wire::seal(keys, reservation, destination_cid, plaintext)
    }

    pub(in crate::quic::application) fn install_peer_update(
        &self,
        request: PeerUpdate<'scope>,
    ) -> Result<WriteEpochInstalled<'scope>, Error> {
        let mut owned = self.owned.try_borrow_mut().map_err(|_| Error::Binding)?;
        let keys = owned.application.as_mut().ok_or(Error::Retired)?;
        keys.maintain(request.now, request.pto)?;
        Ok(keys.install_peer_update(request.authenticated)?)
    }

    pub(in crate::quic::application) fn local_update(
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

    pub(in crate::quic::application) fn acknowledge(
        &self,
        request: KeyAck<'scope>,
    ) -> Result<(), Error> {
        let mut owned = self.owned.try_borrow_mut().map_err(|_| Error::Binding)?;
        owned
            .application
            .as_mut()
            .ok_or(Error::Retired)?
            .acknowledge(request.validated, request.now, request.pto)?;
        Ok(())
    }

    pub(in crate::quic::application) fn confirm(
        &self,
        confirmation: ScopedHandshakeConfirmation<'scope>,
    ) -> Result<(), Error> {
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

    pub(in crate::quic::application) fn retire_control(&self) -> Result<(), Error> {
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
    pub(in crate::quic::application) fn take_closing(
        &self,
        ordinary: &crate::quic::application::OrdinaryRetired<'scope>,
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

pub(in crate::quic::application) struct PeerUpdate<'scope> {
    pub(in crate::quic::application) authenticated: PeerUpdateAuthenticated<'scope>,
    pub(in crate::quic::application) now: u64,
    pub(in crate::quic::application) pto: u64,
}
pub(in crate::quic::application) struct LocalUpdateRequest<'scope> {
    pub(in crate::quic::application) ready: LocalUpdateReady<'scope>,
    pub(in crate::quic::application) now: u64,
    pub(in crate::quic::application) pto: u64,
}
pub(in crate::quic::application) struct KeyAck<'scope> {
    pub(in crate::quic::application) validated: ValidatedKeyAck<'scope>,
    pub(in crate::quic::application) now: u64,
    pub(in crate::quic::application) pto: u64,
}

/// Each lane carries its actual affine object, beside its corresponding
/// projected edge. Scope and epoch binding belong to these actual objects.
pub(in crate::quic::application) struct Exchange<'owner, 'scope> {
    pub(in crate::quic::application) owner: &'owner KeyOwner<'scope>,
    pub(in crate::quic::application) peer_update: Inbox<PeerUpdate<'scope>>,
    pub(in crate::quic::application) write_installed:
        Inbox<Result<WriteEpochInstalled<'scope>, Error>>,
    pub(in crate::quic::application) local_update: Inbox<LocalUpdateRequest<'scope>>,
    pub(in crate::quic::application) local_result:
        Inbox<Result<LocalWriteEpochInstalled<'scope>, LocalUpdateRejected<'scope>>>,
    pub(in crate::quic::application) key_ack: Inbox<KeyAck<'scope>>,
    pub(in crate::quic::application) key_ack_applied: Inbox<Result<(), Error>>,
    pub(in crate::quic::application) confirmation: Inbox<ScopedHandshakeConfirmation<'scope>>,
    pub(in crate::quic::application) confirmation_applied: Inbox<Result<(), Error>>,
}

impl<'owner, 'scope> Exchange<'owner, 'scope> {
    pub(in crate::quic::application) const fn new(owner: &'owner KeyOwner<'scope>) -> Self {
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
pub(in crate::quic::application) struct RxControl<'lane, 'owner, 'scope> {
    pub(in crate::quic::application) exchange: &'lane Exchange<'owner, 'scope>,
}

impl<'lane, 'owner, 'scope> RxControl<'lane, 'owner, 'scope> {
    pub(in crate::quic::application) const fn new(
        exchange: &'lane Exchange<'owner, 'scope>,
    ) -> Self {
        Self { exchange }
    }

    pub(in crate::quic::application) fn local_update_due(
        &self,
        target: u64,
        now: u64,
    ) -> Result<bool, Error> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::application::{global as p, localside::keys::run};
    use crate::{runtime::TaskSet, runtime::carrier::CarrierStorage};
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
        let (mut read, mut write) = crate::crypto::directional::ApplicationReadKeys::install(
            scope.claim().unwrap(),
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
                let ordinary = crate::quic::application::OrdinaryRetired { scope };
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
