//! Public setup boundary: projected roles, not private CLI initialization.
use hibana::runtime::{SessionKitStorage, ids::SessionId};
use hibana_quic::{quic::{self, application}, runtime::carrier::CarrierStorage};

#[test]
fn handshake_attachment_creates_no_transport_receipt() {
    let programs = quic::global::programs();
    let outcome = quic::Outcome::new();
    let carrier = CarrierStorage::<1, 16, 64>::new();
    let mut slab = vec![0; 64 * 1024];
    let mut kit = Box::new(SessionKitStorage::uninit());
    let sid = SessionId::new(81);
    let rendezvous = kit.init().rendezvous(&mut slab, carrier.bind(sid).unwrap()).unwrap();
    let roles = quic::Roles::attach(&rendezvous, sid, &programs, &outcome).unwrap();
    assert_eq!(carrier.queued(), 0);
    drop(roles);
}

#[test]
fn application_attachment_uses_one_complete_projection() {
    let programs = application::global::programs();
    let outcomes = application::Outcomes::new();
    let carrier = CarrierStorage::<1, 32, 128>::new();
    let mut slab = vec![0; 256 * 1024];
    let mut kit = Box::new(SessionKitStorage::uninit());
    let sid = SessionId::new(82);
    let rendezvous = kit.init().rendezvous(&mut slab, carrier.bind(sid).unwrap()).unwrap();
    let roles = application::Roles::attach(&rendezvous, sid, &programs, &outcomes).unwrap();
    assert_eq!(carrier.queued(), 0);
    assert!(application::Roles::attach(&rendezvous, sid, &programs, &outcomes).is_err());
    drop(roles);
}
