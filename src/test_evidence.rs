//! Certificate-authenticated TLS evidence for independent role regression tests.
//! This module is test-only and contains no central connection controller.
use crate::{carrier::CarrierStorage, mailbox::Mailbox, runtime::join2};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use hibana::runtime::{SessionKitStorage, ids::SessionId, program::project};
#[path = "../tests/support/tls_actor_fixture.rs"]
mod fixture;
fn drive<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..65536 {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
    panic!("real TLS evidence fixture did not terminate")
}
/// Receipt emitted by the real TLS owner after cryptographic peer Finished.
#[allow(long_running_const_eval)]
pub(crate) fn finished_with_parameters(
    generation: u64,
    client_parameters: &[u8],
) -> crate::roles::tls_owner::FinishedReceipt {
    use crate::{
        bounded_tls::{BoundedTls, ClientConfig, ServerConfig},
        roles::{protocol_tls::tls_choreography, tls_owner},
        tls::Provider,
        tls_certificate::{CertificateDer, Limits, trust_anchor_from_der},
    };
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
            transport_parameters: client_parameters,
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
    let mut slab = [0; 64 * 1024];
    let mut storage = SessionKitStorage::uninit();
    let kit = storage.init();
    let sid = SessionId::new(72);
    let rv = kit
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    let global = tls_choreography::<24, 25>();
    let (cp, op) = (project::<24, _>(&global), project::<25, _>(&global));
    let (mut c, mut o) = (rv.enter(sid, &cp).unwrap(), rv.enter(sid, &op).unwrap());
    let (mut cq, mut rq): (
        [Option<tls_owner::Command<1536>>; 1],
        [Option<tls_owner::Reply<1536, 32>>; 1],
    ) = ([None], [None]);
    let (cq, rq) = (
        Mailbox::new(&mut cq).unwrap(),
        Mailbox::new(&mut rq).unwrap(),
    );
    let (cs, cr) = cq.split().unwrap();
    let (rs, rr) = rq.split().unwrap();
    let mut exchange = tls_owner::Exchange::new();
    let mut receipt = None;
    let consumer = async {
        let mut client = tls_owner::Client::connect(cs, rr, generation)
            .await
            .unwrap();
        assert!(client.take_finished_receipt().is_none());
        let mut output = [0; 1536];
        for _ in 0..32 {
            let mut progress = false;
            while let Some(message) = peer.transmit(&mut output).unwrap() {
                client
                    .receive_crypto(message.level, &output[..message.len])
                    .await
                    .unwrap()
                    .unwrap();
                if let Some(finished) = client.take_finished_receipt() {
                    assert!(receipt.is_none());
                    assert_eq!(finished.generation(), generation);
                    receipt = Some(finished);
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
        assert!(client.take_finished_receipt().is_none());
        client.retire().await.unwrap();
        Ok(())
    };
    drive(join2(
        tls_owner::run_borrowed(&mut c, &mut o, generation, provider, cr, rs, &mut exchange),
        consumer,
    ))
    .unwrap();
    assert!(exchange.is_empty());
    receipt.expect("real TLS actor must emit exactly one verified-Finished receipt")
}

