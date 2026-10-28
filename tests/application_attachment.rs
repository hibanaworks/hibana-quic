//! Public setup boundary: projected endpoints, not private CLI initialization.
// The test projects the entire composed connection rather than a small fixture.
#![forbid(long_running_const_eval)]
use hibana::runtime::{SessionKitStorage, ids::SessionId};
use hibana_quic::{
    quic::{self, application},
    runtime::carrier::CarrierStorage,
};

#[test]
fn handshake_attachment_creates_no_transport_receipt() {
    let projection = quic::global::choreography();
    let outcome = quic::Outcome::new();
    let carrier = CarrierStorage::<1, 16, 64>::new();
    let mut slab = vec![0; 64 * 1024];
    let sid = SessionId::new(81);
    // SAFETY: this test owns an isolated installation resource and creates its
    // only binding. No packet-key operation can escape the test.
    let material = unsafe { hibana::runtime::transport::EndpointBinding::new() };
    // SAFETY: the packet-write resource is also isolated to this test.
    let write = unsafe { hibana::runtime::transport::EndpointBinding::new() };
    let bindings = [
        (hibana_tls::handshake::global::owned::MATERIAL, &material),
        (hibana_tls::handshake::global::owned::WRITE_KEYS, &write),
    ];
    let carrier_binding = carrier.bind(sid, &bindings).unwrap();
    let mut kit = Box::new(SessionKitStorage::uninit());
    let rendezvous = kit.init().rendezvous(&mut slab, &carrier_binding).unwrap();
    let endpoints =
        quic::localside::Endpoints::attach(&rendezvous, sid, &projection, &outcome).unwrap();
    assert_eq!(carrier.queued(), 0);
    drop(endpoints);
}

#[test]
fn application_attachment_uses_one_complete_projection() {
    let projection = application::global::choreography();
    let outcomes = application::Outcomes::new();
    let carrier = CarrierStorage::<1, 32, 128>::new();
    let mut slab = vec![0; 256 * 1024];
    let sid = SessionId::new(82);
    // SAFETY: this test owns an isolated installation resource and creates its
    // only binding. No packet-key operation can escape the test.
    let material = unsafe { hibana::runtime::transport::EndpointBinding::new() };
    // SAFETY: the packet-write resource is also isolated to this test.
    let write = unsafe { hibana::runtime::transport::EndpointBinding::new() };
    // SAFETY: this test is the sole issuer of its isolated stream-production resource.
    let production = unsafe { hibana::runtime::transport::EndpointBinding::new() };
    let bindings = [
        (hibana_tls::handshake::global::owned::MATERIAL, &material),
        (hibana_tls::handshake::global::owned::WRITE_KEYS, &write),
        (application::global::PRODUCTION, &production),
    ];
    let carrier_binding = carrier.bind(sid, &bindings).unwrap();
    let mut kit = Box::new(SessionKitStorage::uninit());
    let rendezvous = kit.init().rendezvous(&mut slab, &carrier_binding).unwrap();
    let endpoints =
        application::localside::Endpoints::attach(&rendezvous, sid, &projection, &outcomes)
            .unwrap();
    assert_eq!(carrier.queued(), 0);
    assert!(
        application::localside::Endpoints::attach(&rendezvous, sid, &projection, &outcomes)
            .is_err()
    );
    drop(endpoints);
}

#[test]
fn unrelated_protocol_owners_have_distinct_roles() {
    use hibana_quic::http3;
    use hibana_quic::quic::{global as handshake, path};
    let owners = [
        handshake::INITIAL_EVENT,
        handshake::INITIAL_OWNER,
        path::global::OWNER,
        http3::global::OWNER,
        hibana_tls::handshake::global::owned::MATERIAL,
    ];
    for (i, role) in owners.iter().enumerate() {
        assert!(!owners[..i].contains(role));
    }
}
