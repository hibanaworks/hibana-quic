//! Full accepted-byte provenance tests. Only the test Recovery support helper
//! exposes its actual Store/reserve transitions; no ticket/proof is fabricated.
use super::*;
use crate::{
    crypto, packet,
    roles::{
        datagram, packet_protection as keys, protocol as kp,
        recovery_owner::tests::AdvertisementRecovery, sealed_packet::SealedPacket,
    },
};

fn preferred_config() -> Config {
    let mut config = config(Role::Server);
    config.preferred_server = Some(PreferredLocal {
        address: "127.0.0.1:4444".parse().unwrap(),
        cid: Cid::new(b"prefcid1").unwrap(),
        reset_token: ResetToken::new([9; 16]),
    });
    config
}
fn encrypted_extensions(preferred: PreferredLocal) -> std::vec::Vec<u8> {
    let mut value = [0; 49];
    let core::net::SocketAddr::V4(address) = preferred.address else {
        panic!("fixture")
    };
    value[..4].copy_from_slice(&address.ip().octets());
    value[4..6].copy_from_slice(&address.port().to_be_bytes());
    value[24] = 8;
    value[25..33].copy_from_slice(preferred.cid.as_bytes());
    value[33..].copy_from_slice(preferred.reset_token.as_bytes());
    let mut parameters = std::vec![0, 8];
    parameters.extend_from_slice(b"clientid");
    parameters.extend_from_slice(&[15, 8]);
    parameters.extend_from_slice(b"serverid");
    parameters.extend_from_slice(&[13, 49]);
    parameters.extend_from_slice(&value);
    let mut bytes = std::vec![0; 256];
    let n = crate::tls_wire::encode_encrypted_extensions(
        &mut bytes,
        crate::tls_wire::ALPN,
        &parameters,
    )
    .unwrap();
    bytes.truncate(n);
    bytes
}
fn seal(
    generation: u64,
    pn: u64,
    header: &[u8],
    plaintext: &[u8],
) -> (SealedPacket<1200>, [u8; 5]) {
    let carrier = CarrierStorage::<1, 16, 16>::new();
    let mut slab = [0; 32768];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init();
    let sid = SessionId::new(941);
    let rv = kit
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    let cp = kp::key_program::<{ kp::KEY_CLIENT }>();
    let op = kp::key_program::<{ kp::KEY_CRYPTO }>();
    let mut client = rv.enter(sid, &cp).unwrap();
    let mut endpoint = rv.enter(sid, &op).unwrap();
    let mut commands: [Option<keys::Command<1200>>; 1] = [None];
    let mut replies: [Option<keys::Reply<1200>>; 1] = [None];
    let commands = Mailbox::new(&mut commands).unwrap();
    let replies = Mailbox::new(&mut replies).unwrap();
    let (mut tx, rx) = commands.split().unwrap();
    let (rtx, mut rrx) = replies.split().unwrap();
    let mut exchange = keys::Exchange::new();
    let mut result = None;
    let workload = async {
        assert!(matches!(
            rrx.recv().await.unwrap().outcome,
            keys::Outcome::Installed
        ));
        tx.send(keys::Command::Seal(
            keys::Packet::new(pn, header, plaintext).unwrap(),
        ))
        .await
        .unwrap_or_else(|_| panic!("closed"));
        let keys::Outcome::Sealed(sealed) = rrx.recv().await.unwrap().outcome else {
            panic!("seal")
        };
        let mut sample = [0; 16];
        sample.copy_from_slice(&sealed.bytes()[header.len() + 3..header.len() + 19]);
        tx.send(keys::Command::HeaderMask(sample))
            .await
            .unwrap_or_else(|_| panic!("closed"));
        let keys::Outcome::HeaderMask(mask) = rrx.recv().await.unwrap().outcome else {
            panic!("mask")
        };
        result = Some((sealed, mask));
        tx.send(keys::Command::Retire)
            .await
            .unwrap_or_else(|_| panic!("closed"));
        assert!(matches!(
            rrx.recv().await.unwrap().outcome,
            keys::Outcome::Retired
        ));
        Ok(())
    };
    // A real projected key owner performs AEAD, proof minting and HP. This
    // fixture does not purport to prove TLS Provider-origin for Flight::Store.
    let key = crypto::PacketKey::from_secret(
        crypto::CipherSuite::Aes128GcmSha256,
        crypto::KeyKind::Handshake,
        &[53; 32],
    )
    .unwrap();
    drive(runtime::join2(
        keys::run_borrowed(
            &mut client,
            &mut endpoint,
            generation,
            key,
            rx,
            rtx,
            &mut exchange,
        ),
        workload,
    ))
    .unwrap();
    result.unwrap()
}
struct Adapter {
    accepted: bool,
    calls: usize,
}
impl UdpAdapter for Adapter {
    async fn send(&mut self, datagram: Datagram<'_>) -> Result<u64, ()> {
        assert!(!datagram.bytes.is_empty());
        self.calls += 1;
        runtime::yield_now().await;
        if self.accepted { Ok(10) } else { Err(()) }
    }
}
fn accepted_fragment(
    state: &mut State<'_, Random>,
    recovery: &mut AdvertisementRecovery,
    offset: u64,
    data: &[u8],
    accepted: bool,
) -> AdapterCompletion {
    let pn = recovery.next_packet_number();
    let mut plaintext = [0; 1200];
    let len = packet::encode_frame(&packet::Frame::Crypto { offset, data }, &mut plaintext)
        .unwrap()
        .max(8);
    let mut header = [0; 64];
    let header_len = packet::encode_long_header(
        &packet::LongHeader {
            kind: packet::LongType::Handshake,
            destination_id: b"clientid",
            source_id: b"serverid",
            token: &[],
            packet_number: pn,
            packet_number_len: 1,
        },
        len + 16,
        &mut header,
    )
    .unwrap();
    let ticket = recovery.reserve(offset, data, (header_len + len + 16) as u64);
    assert_eq!(ticket.packet().value, pn);
    let pending = state
        .reserve(
            Descriptor {
                generation: state.config.generation,
                sequence: pn + 1,
            },
            state.original,
            ticket.bytes(),
            ticket.packet(),
            false,
            state.now,
        )
        .unwrap();
    let (sealed, mask) = seal(
        state.config.generation,
        pn,
        &header[..header_len],
        &plaintext[..len],
    );
    let protected = datagram::ProtectedDatagram::from_sealed::<1>(
        &pending,
        ticket,
        None,
        crate::ecn::Codepoint::NotEct,
        sealed,
        &plaintext[..len],
        header_len - 1,
        mask,
    )
    .unwrap();
    let mut adapter = Adapter { accepted, calls: 0 };
    let completed = drive(pending.submit(&mut adapter, protected)).unwrap();
    assert_eq!(adapter.calls, 1);
    assert_eq!(completed.recovery.accepted_at().is_some(), accepted);
    recovery.complete(completed.recovery);
    completed.path.into()
}
#[test]
fn preferred_advertisement_requires_every_actual_accepted_fragment() {
    let config = preferred_config();
    let bytes = encrypted_extensions(config.preferred_server.unwrap());
    with_state(config, |state| {
        install(state);
        let mut recovery = AdvertisementRecovery::new(config.generation);
        for (offset, data, accepted) in [
            (4, &bytes[4..], true),
            (0, &bytes[..2], false),
            (2, &bytes[2..4], true),
            (4, &bytes[4..], true),
        ] {
            let completion = accepted_fragment(state, &mut recovery, offset, data, accepted);
            state.complete(completion).unwrap();
            assert!(!state.preferred_advertised);
            assert!(state.snapshot().preferred_advertisement_pending);
            assert_ne!(state.local.highest_advertised_sequence(), Some(1));
        }
        let completion = accepted_fragment(state, &mut recovery, 0, &bytes[..2], true);
        state.complete(completion).unwrap();
        assert!(state.preferred_advertised);
        assert!(!state.snapshot().preferred_advertisement_pending);
        assert_eq!(state.local.highest_advertised_sequence(), Some(1));
        let mut incoming = context(1, address(5000));
        incoming.address.local = config.preferred_server.unwrap().address;
        assert!(state.ingress(incoming).is_ok());
    });
}
#[test]
fn actual_rejection_cannot_advertise_either_local_cid() {
    let config = preferred_config();
    let bytes = encrypted_extensions(config.preferred_server.unwrap());
    with_state(config, |state| {
        install(state);
        let mut recovery = AdvertisementRecovery::new(config.generation);
        let completion = accepted_fragment(state, &mut recovery, 0, &bytes, false);
        assert!(completion.advertisement.is_none());
        state.complete(completion).unwrap();
        assert!(!state.preferred_advertised);
        assert_eq!(state.local.highest_advertised_sequence(), None);
        let completion = accepted_fragment(state, &mut recovery, 0, &bytes, true);
        state.complete(completion).unwrap();
        assert!(state.preferred_advertised);
        assert_eq!(state.local.highest_advertised_sequence(), Some(1));
    });
}
#[test]
fn accepted_but_wrong_preferred_tuple_cid_or_token_fails_closed() {
    let config = preferred_config();
    let mut wrong = [config.preferred_server.unwrap(); 3];
    wrong[0].cid = Cid::new(b"wrongcid").unwrap();
    wrong[1].reset_token = ResetToken::new([11; 16]);
    wrong[2].address = "127.0.0.1:4445".parse().unwrap();
    for preferred in wrong {
        with_state(config, |state| {
            install(state);
            let mut recovery = AdvertisementRecovery::new(config.generation);
            let completion = accepted_fragment(
                state,
                &mut recovery,
                0,
                &encrypted_extensions(preferred),
                true,
            );
            assert_eq!(state.complete(completion), Err(Error::InvalidAdvertisement));
            assert!(state.terminal);
            assert_eq!(state.snapshot().pending_transmits, 0);
            assert!(!state.preferred_advertised);
            assert_ne!(state.local.highest_advertised_sequence(), Some(1));
        });
    }
}
#[test]
fn late_stale_and_other_generation_callbacks_cannot_finish_a_prefix() {
    let config = preferred_config();
    let bytes = encrypted_extensions(config.preferred_server.unwrap());
    with_state(config, |state| {
        install(state);
        let mut recovery = AdvertisementRecovery::new(config.generation);
        let first = accepted_fragment(state, &mut recovery, 0, &bytes[..4], true);
        state.complete(first).unwrap();
        let stale = accepted_fragment(state, &mut recovery, 4, &bytes[4..], true);
        // Numeric cancellation models the owner cleanup boundary while keeping
        // the old actual completion available for an adversarial late callback.
        state
            .paths
            .adapter_rejected(stale.record.reservation)
            .unwrap();
        state.pending[usize::from(state.original.slot)] = None;
        let replacement = state
            .reserve(
                descriptor(100),
                state.original,
                64,
                number(10),
                false,
                state.now,
            )
            .unwrap();
        assert_eq!(state.complete(stale), Err(Error::InvalidDescriptor));
        assert!(!state.preferred_advertised);
        assert_eq!(state.paths.snapshot(state.original).unwrap().reserved, 64);
        state.complete(replacement.reject()).unwrap();
        let cross_generation = accepted_fragment(state, &mut recovery, 4, &bytes[4..], true);
        let mut other = config;
        other.generation += 1;
        with_state(other, |other| {
            install(other);
            assert_eq!(
                other.complete(cross_generation),
                Err(Error::InvalidDescriptor)
            );
            assert!(!other.preferred_advertised);
        });
    });
}
