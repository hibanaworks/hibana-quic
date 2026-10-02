//! Shared no-heap exercised paths for allocation counting and target link smoke.
//! No TLS handshake, network endpoint, or hardware execution is represented.
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use hibana::runtime::{SessionKitStorage, ids::SessionId};
use hibana_quic::{
    carrier::{CarrierStorage, LocalCarrier},
    crypto::{
        CipherSuite, IntegrityBudget, KeyKind, PacketKey, initial_keys, retry_integrity_tag,
        verify_retry,
    },
    protocol::*,
};

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("bounded smoke expected ready"),
    }
}

#[path = "certificate_smoke.rs"]
mod certificate_smoke;

pub fn exercise() {
    certificate_smoke::exercise();
    // Test-only supplied traffic secret: this helper is never an endpoint or TLS
    // backend. Production keys must come from authenticated TLS traffic secrets.
    let secret = core::hint::black_box([0x51; 32]);
    for suite in [
        CipherSuite::Aes128GcmSha256,
        CipherSuite::ChaCha20Poly1305Sha256,
    ] {
        let mut write = PacketKey::from_secret(suite, KeyKind::OneRtt, &secret).unwrap();
        let mut read = PacketKey::from_secret(suite, KeyKind::OneRtt, &secret).unwrap();
        let mut budget = IntegrityBudget::new();
        for pn in 0..2 {
            let mut packet = [0; 64];
            packet[0] = 0x40;
            packet[1] = pn as u8;
            packet[2..7].copy_from_slice(b"hello");
            let (header, body) = packet.split_at_mut(2);
            let n = write.seal(pn, header, body, 5).unwrap();
            let total = n + 2;
            write.protect_header(&mut packet[..total], 1).unwrap();
            assert_eq!(read.unprotect_header(&mut packet[..total], 1).unwrap(), 1);
            let (header, body) = packet[..total].split_at_mut(2);
            assert_eq!(read.open(pn, header, body, &mut budget).unwrap(), 5);
            assert_eq!(&body[..5], b"hello");
            write.update_key().unwrap();
            read.update_key().unwrap();
        }
        write.discard();
        read.discard();
    }
    let mut keys = initial_keys(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
    core::hint::black_box(keys.client.header_mask(&[1; 16]).unwrap());
    keys.client.discard();
    keys.server.discard();
    let mut scratch = [0; 64];
    let mut retry = [0; 24];
    retry[..8].copy_from_slice(b"retryhdr");
    let tag = retry_integrity_tag(&[1, 2, 3], &retry[..8], &mut scratch).unwrap();
    retry[8..].copy_from_slice(&tag);
    verify_retry(&[1, 2, 3], &retry, &mut scratch).unwrap();

    let queue = CarrierStorage::<8, 16, { hibana_quic::protocol::SERVICE_PORTS }>::new();
    let carrier = queue.bind(SessionId::new(9)).unwrap();
    let mut slab = [0; 32 * 1024];
    let mut storage = SessionKitStorage::<LocalCarrier<'_, 8, 16, { hibana_quic::protocol::SERVICE_PORTS }>>::uninit();
    let kit = storage.init();
    let rv = kit.rendezvous(&mut slab, carrier).unwrap();
    let p0 = service_program::<INGRESS>();
    let p1 = service_program::<PACKET>();
    let p2 = service_program::<APPLICATION>();
    let p3 = service_program::<RECOVERY>();
    let p4 = service_program::<ADAPTER>();
    let p5 = service_program::<TIMER>();
    let mut ingress = rv.enter(SessionId::new(9), &p0).unwrap();
    let mut packet = rv.enter(SessionId::new(9), &p1).unwrap();
    let mut app = rv.enter(SessionId::new(9), &p2).unwrap();
    let mut recovery = rv.enter(SessionId::new(9), &p3).unwrap();
    let mut adapter = rv.enter(SessionId::new(9), &p4).unwrap();
    let mut timer = rv.enter(SessionId::new(9), &p5).unwrap();
    let mut rx = pin!(packet.recv::<RxDatagram>());
    assert!(
        rx.as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    ready(app.send::<TxRequest>(&1)).unwrap();
    ready(recovery.recv::<TxRequest>()).unwrap();
    ready(recovery.send::<TxReserved>(&1)).unwrap();
    ready(adapter.recv::<TxReserved>()).unwrap();
    ready(timer.send::<TimerExpired>(&123)).unwrap();
    ready(recovery.recv::<TimerExpired>()).unwrap();
    ready(recovery.send::<TimerHandled>(&123)).unwrap();
    ready(timer.recv::<TimerHandled>()).unwrap();
    ready(adapter.send::<TxResult>(&1)).unwrap();
    ready(recovery.recv::<TxResult>()).unwrap();
    ready(recovery.send::<TxComplete>(&1)).unwrap();
    ready(app.recv::<TxComplete>()).unwrap();
    ready(ingress.send::<RxDatagram>(&7)).unwrap();
    assert!(matches!(
        rx.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Ok(7))
    ));
}
