//! Real certificate/Finished and 1-RTT evidence for path ownership tests.
use super::tests::drive;
use crate::{
    bounded_tls::{BoundedTls, ClientConfig, ServerConfig},
    carrier::CarrierStorage,
    mailbox::Mailbox,
    roles::{
        connection_authority, packet_authority, packet_protection::Packet,
        protocol_tls::tls_choreography, tls_owner,
    },
    runtime,
    tls::{Level, Provider},
    tls_certificate::{CertificateDer, Limits, trust_anchor_from_der},
};
use hibana::runtime::{SessionKitStorage, ids::SessionId, program::project};
#[path = "../../../tests/support/tls_actor_fixture.rs"]
mod fixture;
const PARAMETERS: &[u8] = &[15, 8, b'c', b'l', b'i', b'e', b'n', b't', b'i', b'd'];

#[allow(long_running_const_eval)]
pub(super) fn authenticated(
    generation: u64,
    payload: &[u8],
    packet_number: u64,
) -> (
    packet_authority::ReceiveEvidence,
    connection_authority::PathReady,
) {
    let root = CertificateDer::from(fixture::ROOT_DER);
    let anchors = [trust_anchor_from_der(&root).unwrap()];
    let chain = [fixture::LEAF_DER];
    let signer = fixture::signing_key();
    let mut cb = fixture::Buffers::new();
    let mut sb = fixture::Buffers::new();
    let mut crng = fixture::TestRandom(119);
    let mut srng = fixture::TestRandom(223);
    let mut peer = BoundedTls::client(
        ClientConfig {
            server_name: "localhost",
            trust_anchors: &anchors,
            now: fixture::now(),
            certificate_limits: Limits::default(),
            transport_parameters: PARAMETERS,
        },
        cb.storage(),
        &mut crng,
    )
    .unwrap();
    let provider = BoundedTls::server(
        ServerConfig {
            certificate_chain: &chain,
            signing_key: &signer,
            transport_parameters: fixture::SERVER_PARAMS,
        },
        sb.storage(),
        &mut srng,
    )
    .unwrap();
    let carrier = CarrierStorage::<1, 16, 32>::new();
    let mut slab = [0; 65536];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init();
    let sid = SessionId::new(934);
    let rv = kit
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    let global = tls_choreography::<24, 25>();
    let cp = project::<24, _>(&global);
    let op = project::<25, _>(&global);
    let mut c = rv.enter(sid, &cp).unwrap();
    let mut o = rv.enter(sid, &op).unwrap();
    let mut commands: [Option<tls_owner::Command<1536>>; 1] = [None];
    let mut replies: [Option<tls_owner::Reply<1536, 32>>; 1] = [None];
    let commands = Mailbox::new(&mut commands).unwrap();
    let replies = Mailbox::new(&mut replies).unwrap();
    let (tx, rx) = commands.split().unwrap();
    let (rtx, rrx) = replies.split().unwrap();
    let mut exchange = tls_owner::Exchange::new();
    let mut result = None;
    let workload = async {
        let mut client = tls_owner::Client::connect(tx, rrx, generation)
            .await
            .unwrap();
        let mut finished = None;
        let mut output = [0; 1536];
        for _ in 0..32 {
            let mut progress = false;
            while let Some(message) = peer.transmit(&mut output).unwrap() {
                client
                    .receive_crypto(message.level, &output[..message.len])
                    .await
                    .unwrap()
                    .unwrap();
                if let Some(receipt) = client.take_finished_receipt() {
                    assert!(finished.is_none());
                    finished = Some(receipt);
                }
                progress = true;
            }
            while let Some((level, bytes)) = client.take_crypto_flight(1536).await.unwrap().unwrap()
            {
                peer.receive(level, bytes.as_bytes()).unwrap();
                progress = true;
            }
            if !progress {
                break;
            }
        }
        assert!(!peer.is_handshaking());
        assert!(!client.snapshot().handshaking);
        let ready = connection_authority::verify_and_split(
            finished.unwrap(),
            PARAMETERS,
            crate::parameters::Peer::Client,
            b"clientid",
            None,
            None,
        )
        .unwrap()
        .path;
        let mut cipher = [0; 512];
        cipher[..payload.len()].copy_from_slice(payload);
        let len = peer
            .seal(
                Level::OneRtt,
                packet_number,
                b"header",
                &mut cipher,
                payload.len(),
            )
            .unwrap();
        let opened = client
            .open_one_rtt(
                Packet::new(packet_number, b"header", &cipher[..len]).unwrap(),
                false,
                0,
                100,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(opened.packet.body(), payload);
        result = Some((
            packet_authority::ReceiveEvidence::Tls(opened.receipt),
            ready,
        ));
        client.retire().await.unwrap();
        Ok(())
    };
    drive(runtime::join2(
        tls_owner::run_borrowed(&mut c, &mut o, generation, provider, rx, rtx, &mut exchange),
        workload,
    ))
    .unwrap();
    result.unwrap()
}

/// Initial SCID learning uses an actual AEAD header from the key-owning role.
/// This is primitive-level evidence; it does not claim TLS peer identity.
pub(super) fn initial(
    generation: u64,
    source: &[u8],
    destination: &[u8],
) -> (
    crate::roles::packet_protection::OpenReceipt,
    crate::roles::packet_protection::Packet<128>,
) {
    use crate::{
        crypto,
        roles::{client::KeyClient, packet_protection as keys, protocol as key_protocol},
    };
    let key = || crypto::initial_keys(b"path-initial-proof").unwrap().client;
    let mut peer = key();
    let mut header = [0; 64];
    let len = crate::packet::encode_long_header(
        &crate::packet::LongHeader {
            kind: crate::packet::LongType::Initial,
            destination_id: destination,
            source_id: source,
            token: &[],
            packet_number: 0,
            packet_number_len: 1,
        },
        20,
        &mut header,
    )
    .unwrap();
    let mut cipher = [0; 64];
    cipher[0] = 1;
    let protected = peer.seal(0, &header[..len], &mut cipher, 4).unwrap();
    let carrier = CarrierStorage::<1, 16, 16>::new();
    let mut slab = [0; 32768];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init();
    let sid = SessionId::new(948);
    let rv = kit
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    let global = key_protocol::key_choreography::<16, 17>();
    let cp = project::<16, _>(&global);
    let op = project::<17, _>(&global);
    let mut c = rv.enter(sid, &cp).unwrap();
    let mut o = rv.enter(sid, &op).unwrap();
    let mut commands: [Option<keys::Command<128>>; 1] = [None];
    let mut replies: [Option<keys::Reply<128>>; 1] = [None];
    let commands = Mailbox::new(&mut commands).unwrap();
    let replies = Mailbox::new(&mut replies).unwrap();
    let (tx, rx) = commands.split().unwrap();
    let (rtx, rrx) = replies.split().unwrap();
    let mut exchange = keys::Exchange::new();
    let mut result = None;
    let workload = async {
        let mut client = KeyClient::connect(tx, rrx, generation).await.unwrap();
        let (opened, _) = client
            .open(
                keys::Packet::new(0, &header[..len], &cipher[..protected]).unwrap(),
                crypto::IntegrityBudget::new(),
            )
            .await
            .unwrap();
        let opened = opened.unwrap();
        assert!(opened.receipt.authenticates_header(&header[..len]));
        result = Some((opened.receipt, opened.packet));
        client.retire().await.unwrap();
        Ok(())
    };
    drive(runtime::join2(
        keys::run_borrowed(&mut c, &mut o, generation, key(), rx, rtx, &mut exchange),
        workload,
    ))
    .unwrap();
    result.unwrap()
}
