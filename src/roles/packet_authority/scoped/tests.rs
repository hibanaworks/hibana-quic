//! RECONSTRUCTED AFTER EXECUTOR RESET; UNVERIFIED.
//! Previous executions do not validate these reconstructed source bytes.
use super::*;
use crate::{
    crypto::{
        CipherSuite, IntegrityBudget, KeyKind, PacketKey,
        directional::{ApplicationReadKeys, AuthenticatedRead},
    },
    packet::{EncryptionLevel, Frame, FrameIter, ParseLimits},
};
use actor_test_allocator::NoAlloc;

const GENERATION: u64 = 711;
const ACK: &[u8] = &[2, 0, 0, 0, 0];

fn key(secret: u8) -> PacketKey {
    PacketKey::from_secret(CipherSuite::Aes128GcmSha256, KeyKind::OneRtt, &[secret; 32]).unwrap()
}
fn setup<'a, const P: usize, const E: usize>(
    scope: &'a mut ApplicationKeyScope,
    storage: &'a mut Arena<P, E>,
) -> (ScopedArena<'a, P, E>, ApplicationReadKeys<'a>) {
    let mut installation = scope.claim().unwrap();
    let arena = ScopedArena::new(storage, installation.take_packet_authority().unwrap()).unwrap();
    let (rx, _tx) = installation.install(key(1), key(2)).unwrap();
    (arena, rx)
}

/// Always perform actual AEAD; never fabricate authentication or copied grants.
fn evidence<'a>(
    rx: &mut ApplicationReadKeys<'a>,
    payload: &[u8],
    packet_number: u64,
) -> ScopedReceiveEvidence<'a> {
    let mut sender = key(2);
    let header = [0x40];
    let mut bytes = [0; 64];
    bytes[..payload.len()].copy_from_slice(payload);
    let len = sender.seal(packet_number, &header, &mut bytes, payload.len()).unwrap();
    let ready = match rx.open(
        packet_number, false, &header, &mut bytes[..len],
        &mut IntegrityBudget::new(), packet_number, 10,
    ).unwrap() {
        AuthenticatedRead::Ready(ready) => ready,
        AuthenticatedRead::PeerUpdate(_) => panic!("no update sent"),
    };
    assert_eq!(&bytes[..payload.len()], payload);
    ScopedReceiveEvidence::from_directional(ready, packet_number + 100, payload).unwrap()
}
fn ack<'a, const P: usize, const E: usize>(
    arena: &ScopedArena<'a, P, E>,
    ticket: &ScopedPacketTicket<'_>,
    payload: &[u8],
    ordinal: u32,
) -> Result<ScopedAckGrant<'a>, Error> {
    let Frame::Ack { ranges, delay, ecn } =
        FrameIter::new(payload, EncryptionLevel::OneRtt, ParseLimits::default())
            .unwrap().nth(ordinal as usize).unwrap().unwrap()
    else { panic!("ACK fixture required") };
    arena.grant_ack(ticket, ordinal, ranges, delay, ecn)
}

#[test]
fn scoped_arena_precedes_install_and_preserves_authenticated_facts_without_allocation() {
    let guard = NoAlloc::start();
    let mut scope = ApplicationKeyScope::new(GENERATION);
    let mut installation = scope.claim().unwrap();
    let mut storage = Arena::<1, 1>::new(GENERATION);
    let arena = ScopedArena::new(&mut storage, installation.take_packet_authority().unwrap()).unwrap();
    let binding = arena.claim_recovery().unwrap();
    assert!(core::ptr::eq(binding.into_arena(), &arena));
    assert!(matches!(arena.claim_recovery(), Err(Error::InvalidGrant)));
    let (mut rx, _tx) = installation.install(key(1), key(2)).unwrap();
    let ticket = arena.admit(evidence(&mut rx, ACK, 9), ACK).unwrap();
    let facts = arena.inspect(&ticket).unwrap();
    assert_eq!(facts.generation(), GENERATION);
    assert_eq!(facts.operation_id(), 109);
    assert_eq!(facts.space(), crate::accounting::PacketNumberSpace::ApplicationData);
    assert_eq!(facts.packet_number(), 9);
    assert_eq!(facts.key_generation(), 0);
    assert_eq!(ticket.generation(), GENERATION);
    assert_eq!(ticket.sequence(), 0);
    assert!(matches!(ack(&arena, &ticket, &[2, 1, 0, 0, 0], 0), Err(Error::InvalidFrame)));
    assert_eq!(arena.live_effects(), 0);
    let grant = ack(&arena, &ticket, ACK, 0).unwrap();
    assert_eq!(arena.finish(&ticket), Err(Error::OutstandingEffects));
    let (consumed, frame) = arena.consume_ack(grant).unwrap();
    assert_eq!(consumed, facts);
    assert_eq!(frame.ranges(), &[crate::accounting::AckRange { start: 0, end: 0 }]);
    assert!(matches!(ack(&arena, &ticket, ACK, 0), Err(Error::InvalidFrame)));
    assert_eq!(arena.finish(&ticket), Ok(facts));
    assert_eq!(arena.inspect(&ticket), Err(Error::InvalidPacket));
    assert_eq!(arena.finish(&ticket), Err(Error::InvalidPacket));
    assert_eq!((arena.live_packets(), arena.live_effects()), (0, 0));
    guard.finish();
}

#[test]
fn equal_generation_foreign_arena_packet_and_ack_cannot_consume_colliding_slots() {
    let mut scope_a = ApplicationKeyScope::new(GENERATION);
    let mut scope_b = ApplicationKeyScope::new(GENERATION);
    let mut storage_a = Arena::<1, 1>::new(GENERATION);
    let mut storage_b = Arena::<1, 1>::new(GENERATION);
    let (arena_a, mut rx_a) = setup(&mut scope_a, &mut storage_a);
    let (arena_b, mut rx_b) = setup(&mut scope_b, &mut storage_b);
    let ticket_a = arena_a.admit(evidence(&mut rx_a, ACK, 1), ACK).unwrap();
    let ticket_b = arena_b.admit(evidence(&mut rx_b, ACK, 2), ACK).unwrap();
    assert_eq!(ticket_a.ticket, ticket_b.ticket);
    assert_eq!(arena_b.inspect(&ticket_a), Err(Error::InvalidGrant));
    assert!(matches!(ack(&arena_b, &ticket_a, ACK, 0), Err(Error::InvalidGrant)));
    assert_eq!(arena_b.cancel(&ticket_a), Err(Error::InvalidGrant));
    let grant_a = ack(&arena_a, &ticket_a, ACK, 0).unwrap();
    let grant_b = ack(&arena_b, &ticket_b, ACK, 0).unwrap();
    assert_eq!(grant_a.grant.id, grant_b.grant.id);
    assert!(matches!(arena_b.consume_ack(grant_a), Err(Error::InvalidGrant)));
    assert_eq!((arena_a.live_effects(), arena_b.live_effects()), (1, 1));
    assert_eq!(arena_b.consume_ack(grant_b).unwrap().0.packet_number(), 2);
    arena_a.cancel(&ticket_a).unwrap();
    arena_b.finish(&ticket_b).unwrap();
}

#[test]
fn equal_generation_foreign_key_scope_receipt_is_rejected_before_admission() {
    let mut scope_a = ApplicationKeyScope::new(GENERATION);
    let mut scope_b = ApplicationKeyScope::new(GENERATION);
    let (mut rx_a, _tx_a) = scope_a.install(key(1), key(2)).unwrap();
    let mut storage = Arena::<1, 1>::new(GENERATION);
    let (arena, mut rx_b) = setup(&mut scope_b, &mut storage);
    assert!(matches!(arena.admit(evidence(&mut rx_a, ACK, 1), ACK), Err(Error::InvalidGrant)));
    assert_eq!((arena.live_packets(), arena.live_effects()), (0, 0));
    let ticket = arena.admit(evidence(&mut rx_b, ACK, 1), ACK).unwrap();
    assert_eq!(ticket.sequence(), 0);
    let grant = ack(&arena, &ticket, ACK, 0).unwrap();
    arena.consume_ack(grant).unwrap();
    arena.finish(&ticket).unwrap();
}

#[test]
fn scoped_receive_checks_plaintext_at_conversion_and_at_admission() {
    let mut scope = ApplicationKeyScope::new(GENERATION);
    let mut storage = Arena::<1, 1>::new(GENERATION);
    let (arena, mut rx) = setup(&mut scope, &mut storage);
    let actual = evidence(&mut rx, ACK, 1);
    assert!(matches!(arena.admit(actual, &[2, 1, 0, 0, 0]), Err(Error::InvalidFrame)));
    assert_eq!(arena.live_packets(), 0);
    let mut sender = key(2);
    let mut bytes = [0; 21];
    bytes[..ACK.len()].copy_from_slice(ACK);
    sender.seal(2, &[0x40], &mut bytes, ACK.len()).unwrap();
    let AuthenticatedRead::Ready(ready) = rx.open(
        2, false, &[0x40], &mut bytes, &mut IntegrityBudget::new(), 2, 10,
    ).unwrap() else { panic!("no update sent") };
    assert!(matches!(
        ScopedReceiveEvidence::from_directional(ready, 102, &[2, 1, 0, 0, 0]),
        Err(Error::InvalidFrame)
    ));
    assert_eq!(arena.live_packets(), 0);
}

#[test]
fn cancelled_ack_stays_invalid_after_slot_reuse_and_duplicate_mint_is_rejected() {
    let mut scope = ApplicationKeyScope::new(GENERATION);
    let mut storage = Arena::<1, 1>::new(GENERATION);
    let (arena, mut rx) = setup(&mut scope, &mut storage);
    let old_ticket = arena.admit(evidence(&mut rx, ACK, 1), ACK).unwrap();
    let old_grant = ack(&arena, &old_ticket, ACK, 0).unwrap();
    assert!(matches!(ack(&arena, &old_ticket, ACK, 0), Err(Error::InvalidFrame)));
    arena.cancel(&old_ticket).unwrap();
    let ticket = arena.admit(evidence(&mut rx, ACK, 2), ACK).unwrap();
    let grant = ack(&arena, &ticket, ACK, 0).unwrap();
    assert_ne!(old_ticket.sequence(), ticket.sequence());
    assert!(matches!(arena.consume_ack(old_grant), Err(Error::InvalidGrant)));
    assert_eq!(arena.inspect(&old_ticket), Err(Error::InvalidPacket));
    assert_eq!(arena.live_effects(), 1);
    assert_eq!(arena.consume_ack(grant).unwrap().0.packet_number(), 2);
    arena.finish(&ticket).unwrap();
}

#[test]
fn scoped_capacity_failure_is_retryable_after_consuming_live_effect() {
    let mut scope = ApplicationKeyScope::new(GENERATION);
    let mut storage = Arena::<1, 1>::new(GENERATION);
    let (arena, mut rx) = setup(&mut scope, &mut storage);
    let payload = [2, 0, 0, 0, 0, 2, 1, 0, 0, 0];
    let ticket = arena.admit(evidence(&mut rx, &payload, 1), &payload).unwrap();
    let first = ack(&arena, &ticket, &payload, 0).unwrap();
    assert!(matches!(ack(&arena, &ticket, &payload, 1), Err(Error::EffectCapacity)));
    arena.consume_ack(first).unwrap();
    let second = ack(&arena, &ticket, &payload, 1).unwrap();
    assert_eq!(arena.consume_ack(second).unwrap().1.ranges()[0].end, 1);
    arena.finish(&ticket).unwrap();
}

#[test]
fn scoped_delivery_rejects_foreign_arena_before_consuming_live_effect() {
    let mut scope_a = ApplicationKeyScope::new(GENERATION);
    let mut scope_b = ApplicationKeyScope::new(GENERATION);
    let mut storage_a = Arena::<1, 1>::new(GENERATION);
    let mut storage_b = Arena::<1, 1>::new(GENERATION);
    let (arena_a, mut rx_a) = setup(&mut scope_a, &mut storage_a);
    let (arena_b, mut rx_b) = setup(&mut scope_b, &mut storage_b);
    let payload = [0x0a, 0, 1, 42];
    let ticket_a = arena_a.admit(evidence(&mut rx_a, &payload, 1), &payload).unwrap();
    let ticket_b = arena_b.admit(evidence(&mut rx_b, &payload, 2), &payload).unwrap();
    let frame = Frame::Stream { id: 0, offset: 0, fin: false, data: &[42] };
    let grant_a = arena_a.grant_delivery::<8>(&ticket_a, 0, frame).unwrap();
    let grant_b = arena_b.grant_delivery::<8>(&ticket_b, 0, frame).unwrap();
    assert!(matches!(arena_b.consume_delivery(grant_a), Err(Error::InvalidGrant)));
    assert_eq!(arena_b.live_effects(), 1);
    let (facts, frame) = arena_b.consume_delivery(grant_b).unwrap();
    assert_eq!(facts.packet_number(), 2);
    assert_eq!(frame.as_frame(), Frame::Stream { id: 0, offset: 0, fin: false, data: &[42] });
    arena_a.cancel(&ticket_a).unwrap();
    arena_b.finish(&ticket_b).unwrap();
}

#[test]
fn scoped_arena_rejects_mismatched_generation_even_with_zero_capacity() {
    let mut scope = ApplicationKeyScope::new(GENERATION);
    let mut installation = scope.claim().unwrap();
    let mut storage = Arena::<0, 0>::new(GENERATION + 1);
    assert!(matches!(
        ScopedArena::new(&mut storage, installation.take_packet_authority().unwrap()),
        Err(Error::WrongGeneration)
    ));
    assert!(matches!(installation.take_packet_authority(), Err(crate::crypto::Error::KeyUpdateNotAllowed)));
    assert!(core::mem::size_of::<Arena<0, 0>>() >= core::mem::size_of::<u64>());
}

#[test]
fn recovery_claim_cannot_be_reissued_after_binding_is_dropped() {
    let mut scope = ApplicationKeyScope::new(GENERATION);
    let mut installation = scope.claim().unwrap();
    let mut storage = Arena::<0, 0>::new(GENERATION);
    let arena = ScopedArena::new(&mut storage, installation.take_packet_authority().unwrap()).unwrap();
    drop(arena.claim_recovery().unwrap());
    assert!(matches!(arena.claim_recovery(), Err(Error::InvalidGrant)));
    assert_eq!((arena.live_packets(), arena.live_effects()), (0, 0));
}

#[test]
fn dropped_construction_tokens_cannot_be_reissued_from_the_same_key_scope() {
    let mut scope = ApplicationKeyScope::new(GENERATION);
    let mut installation = scope.claim().unwrap();
    drop(installation.take_packet_authority().unwrap());
    assert!(matches!(installation.take_packet_authority(), Err(crate::crypto::Error::KeyUpdateNotAllowed)));
    drop(installation.take_publication_gate().unwrap());
    assert!(matches!(installation.take_publication_gate(), Err(crate::crypto::Error::KeyUpdateNotAllowed)));
    drop(installation);
    assert!(matches!(scope.claim(), Err(crate::crypto::Error::KeyUpdateNotAllowed)));
}

#[test]
fn live_arena_blocks_second_arena_even_with_distinct_caller_storage() {
    let mut scope = ApplicationKeyScope::new(GENERATION);
    let mut installation = scope.claim().unwrap();
    let mut first_storage = Arena::<0, 0>::new(GENERATION);
    let mut second_storage = Arena::<0, 0>::new(GENERATION);
    let arena = ScopedArena::new(&mut first_storage, installation.take_packet_authority().unwrap()).unwrap();
    assert!(matches!(
        installation.take_packet_authority().map(|token| ScopedArena::new(&mut second_storage, token)),
        Err(crate::crypto::Error::KeyUpdateNotAllowed)
    ));
    let gate = installation.take_publication_gate().unwrap();
    assert!(core::ptr::eq(gate.into_scope(), arena.scope()));
    assert!(matches!(installation.take_publication_gate(), Err(crate::crypto::Error::KeyUpdateNotAllowed)));
}
