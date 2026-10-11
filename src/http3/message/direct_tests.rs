//! Tests of actual application-owned globals and direct endpoint localsides.
use super::{Exchange, Result, global as h, localside};
use crate::runtime::carrier::CarrierStorage;
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use hibana::{
    Endpoint, g,
    runtime::{
        SessionKitStorage,
        ids::SessionId,
        program::{Projectable, project},
    },
};
const READ: u8 = 0;
const APP: u8 = 1;
const WRITE: u8 = 2;
const RESULT: u8 = 3;
type Summary = g::Msg<32, u64>;
struct Input<'a>(&'a [u8]);
impl crate::quic::application::BodyReader for Input<'_> {
    async fn read(&mut self, out: &mut [u8]) -> core::result::Result<usize, ()> {
        let n = out.len().min(self.0.len()).min(3);
        out[..n].copy_from_slice(&self.0[..n]);
        self.0 = &self.0[n..];
        Ok(n)
    }
}
struct Output {
    bytes: [u8; 512],
    len: usize,
    finished: bool,
}
impl localside::writer::BodyWriter for Output {
    async fn write(&mut self, bytes: &[u8]) -> core::result::Result<(), ()> {
        let end = self.len.checked_add(bytes.len()).ok_or(())?;
        self.bytes
            .get_mut(self.len..end)
            .ok_or(())?
            .copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }
    async fn finish(&mut self) -> core::result::Result<(), ()> {
        self.finished = true;
        Ok(())
    }
}
fn run<T>(f: impl Future<Output = T>) -> T {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..1000 {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
    panic!("direct localsides stalled")
}
async fn app(
    ep: &mut Endpoint<'_, APP>,
    request: &Exchange<'_>,
    response: &Exchange<'_>,
    early: bool,
    summary: bool,
    bad: bool,
) -> Result<()> {
    ep.recv::<h::Headers>().await?;
    {
        let head = request.fields()?;
        assert_eq!(
            head.section().metadata.method,
            Some(crate::http3::Method::Get)
        );
    }
    ep.send::<h::Stored>(&()).await?;
    if bad {
        ep.send::<h::Data>(&0).await?;
        return Err("out-of-order DATA accepted".into());
    }
    if early {
        response.response(200, &[(b"content-type", b"text/plain")])?;
        ep.send::<h::Headers>(&()).await?;
        ep.recv::<h::Stored>().await?;
    }
    ep.offer().await?.recv::<h::BodyEnd>().await?;
    ep.offer().await?.recv::<h::NoTrailers>().await?;
    ep.recv::<h::End>().await?;
    ep.send::<h::Done>(&()).await?;
    if !early {
        response.response(200, &[(b"content-type", b"text/plain")])?;
        ep.send::<h::Headers>(&()).await?;
        ep.recv::<h::Stored>().await?;
    }
    let n = response.write(b"hello")?;
    ep.send::<h::Data>(&n).await?;
    ep.recv::<h::Stored>().await?;
    ep.send::<h::BodyEnd>(&()).await?;
    response.trailers(&[(b"x-result", b"ok")])?;
    ep.send::<h::Trailers>(&()).await?;
    ep.recv::<h::Stored>().await?;
    ep.send::<h::End>(&()).await?;
    ep.recv::<h::Done>().await?;
    if summary {
        ep.send::<Summary>(&5).await?;
    }
    Ok(())
}
fn exchange(
    graph: &impl Projectable,
    early: bool,
    result_program: Option<&hibana::runtime::program::RoleProgram<RESULT>>,
    bad: bool,
) -> Result<()> {
    let programs = (
        project::<READ>(graph),
        project::<APP>(graph),
        project::<WRITE>(graph),
    );
    let carrier = CarrierStorage::<4, 16, 128>::new();
    let mut slab = [0; 65536];
    let mut kit = SessionKitStorage::uninit();
    let sid = SessionId::new(77);
    let r = kit.init().rendezvous(&mut slab, carrier.bind(sid)?)?;
    let (mut read, mut application, mut write) = (
        r.enter(sid, &programs.0)?,
        r.enter(sid, &programs.1)?,
        r.enter(sid, &programs.2)?,
    );
    let summary = result_program.is_some();
    let mut result = match result_program {
        Some(program) => Some(r.enter(sid, program)?),
        None => None,
    };
    let (mut rb, mut wb, mut rh, mut wh) = ([0; 8], [0; 8], [0; 256], [0; 256]);
    let request = Exchange::new(&mut rb, &mut rh);
    let response = Exchange::new(&mut wb, &mut wh);
    let mut fields = [0; 256];
    let n = crate::http3::encode_fields(
        [
            (b":method".as_slice(), b"GET".as_slice()),
            (b":scheme", b"https"),
            (b":authority", b"localhost"),
            (b":path", b"/hello"),
        ],
        &mut fields,
    )?;
    let mut bytes = [0; 272];
    let prefix = crate::http3::frame_header(1, n as u64, &mut bytes)?;
    bytes[prefix..prefix + n].copy_from_slice(&fields[..n]);
    let mut input = Input(&bytes[..prefix + n]);
    let mut output = Output {
        bytes: [0; 512],
        len: 0,
        finished: false,
    };
    run(crate::runtime::join::values4(
        localside::reader::server(&mut read, &mut input, &request),
        app(&mut application, &request, &response, early, summary, bad),
        async {
            localside::writer::server(&mut write, &mut output, 4096, &response).await?;
            Ok(())
        },
        async {
            if let Some(endpoint) = result.as_mut() {
                assert_eq!(endpoint.recv::<Summary>().await?, 5);
            }
            Ok(())
        },
    ))?;
    assert!(output.finished);
    assert!(output.bytes[..output.len].windows(5).any(|w| w == b"hello"));
    Ok(())
}
#[test]
fn application_parallel_graph_allows_early_response() {
    let graph = g::seq(
        g::send::<READ, WRITE, h::RequestMethod>(),
        g::par(h::request::<READ, APP>(), h::response::<APP, WRITE>()),
    );
    exchange(&graph, true, None, false).unwrap();
}
#[test]
fn application_can_finish_request_before_response() {
    let graph = g::seq(
        g::send::<READ, WRITE, h::RequestMethod>(),
        g::par(h::request::<READ, APP>(), h::response::<APP, WRITE>()),
    );
    exchange(&graph, false, None, false).unwrap();
}
#[test]
fn application_graph_extends_http_with_result_role() {
    let graph = g::seq(
        g::seq(
            g::send::<READ, WRITE, h::RequestMethod>(),
            g::par(h::request::<READ, APP>(), h::response::<APP, WRITE>()),
        ),
        g::send::<APP, RESULT, Summary>(),
    );
    exchange(&graph, true, Some(&project::<RESULT>(&graph)), false).unwrap();
}
#[test]
fn application_graph_rejects_data_before_response_headers() {
    let graph = g::seq(
        g::send::<READ, WRITE, h::RequestMethod>(),
        g::par(h::request::<READ, APP>(), h::response::<APP, WRITE>()),
    );
    assert!(exchange(&graph, true, None, true).is_err());
}

#[path = "../../../examples/hello-http3/server_app.rs"]
mod hello;

#[test]
fn exact_hello_localside_serves_get_head_streaming_post_and_404() {
    for (method, path, request_body, status, expected) in [
        (
            b"GET".as_slice(),
            b"/hello".as_slice(),
            b"".as_slice(),
            200,
            b"hello from Hibana\n".as_slice(),
        ),
        (b"HEAD", b"/hello", b"", 200, b""),
        (b"POST", b"/echo", b"abcdefg", 200, b"abcdefg"),
        (b"GET", b"/missing", b"", 404, b"not found\n"),
        (b"HEAD", b"/missing", b"", 404, b""),
    ] {
        let graph = hello::choreography();
        let programs = (
            project::<READ>(&graph),
            project::<APP>(&graph),
            project::<WRITE>(&graph),
        );
        let carrier = CarrierStorage::<4, 16, 128>::new();
        let mut slab = [0; 65536];
        let mut kit = SessionKitStorage::uninit();
        let sid = SessionId::new(81);
        let r = kit
            .init()
            .rendezvous(&mut slab, carrier.bind(sid).unwrap())
            .unwrap();
        let (mut read, mut app, mut write) = (
            r.enter(sid, &programs.0).unwrap(),
            r.enter(sid, &programs.1).unwrap(),
            r.enter(sid, &programs.2).unwrap(),
        );
        let (mut rb, mut wb, mut rh, mut wh) = ([0; 3], [0; 2], [0; 256], [0; 256]);
        let request = Exchange::new(&mut rb, &mut rh);
        let response = Exchange::new(&mut wb, &mut wh);
        let mut fields = [0; 256];
        let n = crate::http3::encode_fields(
            [
                (b":method".as_slice(), method),
                (b":scheme", b"https"),
                (b":authority", b"localhost"),
                (b":path", path),
            ],
            &mut fields,
        )
        .unwrap();
        let mut wire = [0; 512];
        let prefix = crate::http3::frame_header(1, n as u64, &mut wire).unwrap();
        wire[prefix..prefix + n].copy_from_slice(&fields[..n]);
        let mut len = prefix + n;
        if !request_body.is_empty() {
            let n =
                crate::http3::frame_header(0, request_body.len() as u64, &mut wire[len..]).unwrap();
            len += n;
            wire[len..len + request_body.len()].copy_from_slice(request_body);
            len += request_body.len();
        }
        let mut input = Input(&wire[..len]);
        let mut output = Output {
            bytes: [0; 512],
            len: 0,
            finished: false,
        };
        let guard = actor_test_allocator::NoAlloc::start();
        run(crate::runtime::join::values3(
            localside::reader::server(&mut read, &mut input, &request),
            hello::serve(&mut app, &request, &response),
            async {
                localside::writer::server(&mut write, &mut output, 4096, &response).await?;
                Ok(())
            },
        ))
        .unwrap();
        guard.finish();
        assert!(output.finished);
        let mut offset = 0;
        let mut body = [0; 64];
        let mut count = 0;
        let mut actual_status = None;
        while offset < output.len {
            let frame =
                crate::http3::decode_frame_header(&output.bytes[offset..output.len]).unwrap();
            offset += frame.encoded_len;
            let end = offset + frame.length as usize;
            let payload = &output.bytes[offset..end];
            match frame.kind {
                1 => {
                    actual_status = crate::http3::decode_fields(payload).unwrap().status;
                }
                0 => {
                    body[count..count + payload.len()].copy_from_slice(payload);
                    count += payload.len();
                }
                _ => panic!("unexpected native frame"),
            };
            offset = end;
        }
        assert_eq!(actual_status, Some(status));
        assert_eq!(&body[..count], expected);
    }
}
