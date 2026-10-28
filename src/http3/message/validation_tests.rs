//! Native response validation remains in the codec even with a permissive app.
use super::{Exchange, Result, global as h, localside};
use crate::runtime::carrier::CarrierStorage;
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use hibana::{
    g,
    runtime::{SessionKitStorage, ids::SessionId, program::project},
};
struct Wire {
    bytes: [u8; 1024],
    len: usize,
}
impl Wire {
    fn new() -> Self {
        Self {
            bytes: [0; 1024],
            len: 0,
        }
    }
    fn frame(&mut self, kind: u64, payload: &[u8]) {
        let n = crate::http3::frame_header(kind, payload.len() as u64, &mut self.bytes[self.len..])
            .unwrap();
        self.len += n;
        self.bytes[self.len..self.len + payload.len()].copy_from_slice(payload);
        self.len += payload.len();
    }
    fn fields(&mut self, fields: &[(&[u8], &[u8])]) {
        let mut encoded = [0; 512];
        let n = crate::http3::encode_fields(fields.iter().copied(), &mut encoded).unwrap();
        self.frame(1, &encoded[..n]);
    }
}
struct Input<'a>(&'a [u8]);
impl crate::quic::application::BodyReader for Input<'_> {
    async fn read(&mut self, out: &mut [u8]) -> core::result::Result<usize, ()> {
        let n = out.len().min(self.0.len()).min(3);
        out[..n].copy_from_slice(&self.0[..n]);
        self.0 = &self.0[n..];
        Ok(n)
    }
}
fn run<T>(f: impl Future<Output = T>) -> T {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..1000 {
        if let Poll::Ready(x) = f.as_mut().poll(&mut cx) {
            return x;
        }
    }
    panic!("response validation stalled")
}
fn decode(wire: &Wire, method: &[u8]) -> Result<()> {
    let graph = h::response::<0, 1>();
    let programs = (project::<0>(&graph), project::<1>(&graph));
    let carrier = CarrierStorage::<4, 16, 128>::new();
    let mut slab = [0; 65536];
    let sid = SessionId::new(78);
    let carrier_binding = carrier.bind(sid, &[])?;
    let mut kit = SessionKitStorage::uninit();
    let r = kit.init().rendezvous(&mut slab, &carrier_binding)?;
    let (mut reader, mut app) = (r.enter(sid, &programs.0)?, r.enter(sid, &programs.1)?);
    let (mut body, mut headers) = ([0; 3], [0; 512]);
    let exchange = Exchange::new(&mut body, &mut headers);
    let mut input = Input(&wire.bytes[..wire.len]);
    let guard = actor_test_allocator::NoAlloc::start();
    let result = run(crate::runtime::join::values2(
        localside::reader::run(&mut reader, &mut input, &exchange, method),
        async {
            loop {
                let offered = app.offer().await?;
                let final_head = match offered.label() {
                    1 => {
                        offered.recv::<h::Information>().await?;
                        false
                    }
                    2 => {
                        offered.recv::<h::Headers>().await?;
                        true
                    }
                    _ => return Err("unexpected headers".into()),
                };
                drop(exchange.fields()?);
                app.send::<h::Stored>(&()).await?;
                if final_head {
                    break;
                }
            }
            loop {
                let offered = app.offer().await?;
                match offered.label() {
                    4 => {
                        let n = offered.recv::<h::Data>().await?;
                        drop(exchange.body(n)?);
                        app.send::<h::Stored>(&()).await?;
                    }
                    5 => {
                        offered.recv::<h::BodyEnd>().await?;
                        break;
                    }
                    _ => return Err("unexpected body".into()),
                }
            }
            let offered = app.offer().await?;
            match offered.label() {
                6 => {
                    offered.recv::<h::Trailers>().await?;
                    drop(exchange.fields()?);
                    app.send::<h::Stored>(&()).await?;
                }
                7 => {
                    offered.recv::<h::NoTrailers>().await?;
                }
                _ => return Err("unexpected trailers".into()),
            }
            app.recv::<h::End>().await?;
            app.send::<h::Done>(&()).await?;
            Ok(())
        },
    ));
    guard.finish();
    result.map(|_| ())
}
#[test]
fn native_reader_rejects_bad_lengths_and_forbidden_bodies() {
    for (method, status, length, body) in [
        (
            b"GET".as_slice(),
            b"200".as_slice(),
            b"1".as_slice(),
            b"xx".as_slice(),
        ),
        (b"GET", b"200", b"2", b"x"),
        (b"HEAD", b"200", b"1", b"x"),
        (b"GET", b"204", b"1", b""),
        (b"GET", b"205", b"1", b""),
        (b"GET", b"304", b"1", b"x"),
    ] {
        let mut w = Wire::new();
        w.fields(&[(b":status", status), (b"content-length", length)]);
        if !body.is_empty() {
            w.frame(0, body);
        }
        assert!(decode(&w, method).is_err());
    }
    let mut w = Wire::new();
    let (mut a, mut b) = ([0; 128], [0; 64]);
    let an = crate::http3::encode_fields(
        [
            (b":status".as_slice(), b"200".as_slice()),
            (b"content-length", b"1"),
        ],
        &mut a,
    )
    .unwrap();
    let bn = crate::http3::encode_fields([(b"content-length".as_slice(), b"2".as_slice())], &mut b)
        .unwrap();
    a[an..an + bn - 2].copy_from_slice(&b[2..bn]);
    w.frame(1, &a[..an + bn - 2]);
    assert!(decode(&w, b"GET").is_err());
}
#[test]
fn native_reader_accepts_head_and_304_metadata_without_body() {
    for (method, status) in [(b"HEAD".as_slice(), b"200".as_slice()), (b"GET", b"304")] {
        let mut w = Wire::new();
        w.fields(&[(b":status", status), (b"content-length", b"123")]);
        decode(&w, method).unwrap();
    }
}
#[test]
fn native_reader_validates_information_and_trailers() {
    let mut valid = Wire::new();
    valid.fields(&[(b":status", b"103"), (b"link", b"</x>")]);
    valid.fields(&[(b":status", b"200")]);
    valid.frame(0, b"abc");
    valid.fields(&[(b"x-checksum", b"ok")]);
    decode(&valid, b"GET").unwrap();
    let mut info = Wire::new();
    info.fields(&[(b":status", b"103"), (b"content-length", b"0")]);
    info.fields(&[(b":status", b"200")]);
    assert!(decode(&info, b"GET").is_err());
    for trailers in [
        &[(b":status".as_slice(), b"200".as_slice())][..],
        &[(b"content-length".as_slice(), b"0".as_slice())][..],
    ] {
        let mut w = Wire::new();
        w.fields(&[(b":status", b"200")]);
        w.fields(trailers);
        assert!(decode(&w, b"GET").is_err());
    }
    let mut after = Wire::new();
    after.fields(&[(b":status", b"200")]);
    after.fields(&[(b"x-end", b"yes")]);
    after.frame(0, b"bad");
    assert!(decode(&after, b"GET").is_err());
}
#[test]
fn application_cannot_send_a_forged_method_back_to_reader() {
    let graph = g::seq(
        g::send::<2, 0, h::RequestMethod>(),
        g::seq(g::send::<0, 1, h::RequestMethod>(), h::response::<0, 1>()),
    );
    let programs = (
        project::<0>(&graph),
        project::<1>(&graph),
        project::<2>(&graph),
    );
    let carrier = CarrierStorage::<4, 16, 128>::new();
    let mut slab = [0; 65536];
    let sid = SessionId::new(79);
    let carrier_binding = carrier.bind(sid, &[]).unwrap();
    let mut kit = SessionKitStorage::uninit();
    let r = kit.init().rendezvous(&mut slab, &carrier_binding).unwrap();
    let (mut read, mut app, mut writer) = (
        r.enter(sid, &programs.0).unwrap(),
        r.enter(sid, &programs.1).unwrap(),
        r.enter(sid, &programs.2).unwrap(),
    );
    run(async {
        writer
            .send::<h::RequestMethod>(&(crate::http3::Method::Head as u8))
            .await
            .unwrap();
        let actual = read.recv::<h::RequestMethod>().await.unwrap();
        read.send::<h::RequestMethod>(&actual).await.unwrap();
        assert_eq!(
            app.recv::<h::RequestMethod>().await.unwrap(),
            crate::http3::Method::Head as u8
        );
        assert!(
            app.send::<h::RequestMethod>(&(crate::http3::Method::Get as u8))
                .await
                .is_err()
        );
    });
}

#[test]
fn acknowledging_a_live_loan_fails_without_overwriting_it() {
    let graph = h::request::<0, 1>();
    let programs = (project::<0>(&graph), project::<1>(&graph));
    let carrier = CarrierStorage::<4, 16, 128>::new();
    let mut slab = [0; 65536];
    let sid = SessionId::new(80);
    let carrier_binding = carrier.bind(sid, &[]).unwrap();
    let mut kit = SessionKitStorage::uninit();
    let r = kit.init().rendezvous(&mut slab, &carrier_binding).unwrap();
    let (mut reader, mut app) = (
        r.enter(sid, &programs.0).unwrap(),
        r.enter(sid, &programs.1).unwrap(),
    );
    let (mut body, mut headers) = ([0; 3], [0; 512]);
    let pointer = body.as_ptr();
    let exchange = Exchange::new(&mut body, &mut headers);
    let mut wire = Wire::new();
    wire.fields(&[
        (b":method", b"POST"),
        (b":scheme", b"https"),
        (b":authority", b"localhost"),
        (b":path", b"/echo"),
    ]);
    wire.frame(0, b"abcdef");
    let mut input = Input(&wire.bytes[..wire.len]);
    let guard = actor_test_allocator::NoAlloc::start();
    let result = run(crate::runtime::join::values2(
        localside::reader::request(&mut reader, &mut input, &exchange),
        async {
            app.recv::<h::Headers>().await?;
            drop(exchange.fields()?);
            app.send::<h::Stored>(&()).await?;
            let n = app.offer().await?.recv::<h::Data>().await?;
            let loan = exchange.body(n)?;
            assert_eq!(loan.bytes(), b"abc");
            assert_eq!(loan.bytes().as_ptr(), pointer);
            app.send::<h::Stored>(&()).await?;
            core::future::pending::<()>().await;
            drop(loan);
            Ok(())
        },
    ));
    assert!(result.is_err());
    let loan = exchange.body(3).unwrap();
    assert_eq!(loan.bytes(), b"abc");
    assert_eq!(loan.bytes().as_ptr(), pointer);
    drop(loan);
    guard.finish();
}
