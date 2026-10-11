use super::*;
use crate::http3::message::{global, localside};
use crate::quic::application::BodyReader;
use crate::runtime::carrier::CarrierStorage;
use core::{
    cell::Cell,
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use hibana::runtime::{SessionKitStorage, ids::SessionId, program::project};

struct Input<'a> {
    bytes: &'a [u8],
    admitted: &'a Cell<bool>,
}
impl BodyReader for Input<'_> {
    async fn read(&mut self, output: &mut [u8]) -> core::result::Result<usize, ()> {
        core::future::poll_fn(|cx| {
            if self.admitted.get() {
                Poll::Ready(())
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        })
        .await;
        crate::runtime::yield_now().await;
        let n = output.len().min(self.bytes.len()).min(3);
        output[..n].copy_from_slice(&self.bytes[..n]);
        self.bytes = &self.bytes[n..];
        Ok(n)
    }
}

struct Output {
    bytes: [u8; 512],
    len: usize,
    writes: Cell<usize>,
    sealed: bool,
}
impl Output {
    fn new() -> Self {
        Self {
            bytes: [0; 512],
            len: 0,
            writes: Cell::new(0),
            sealed: false,
        }
    }
}
impl BodyWriter for Output {
    async fn write(&mut self, bytes: &[u8]) -> core::result::Result<(), ()> {
        crate::runtime::yield_now().await;
        let end = self.len.checked_add(bytes.len()).ok_or(())?;
        self.bytes
            .get_mut(self.len..end)
            .ok_or(())?
            .copy_from_slice(bytes);
        self.len = end;
        self.writes.set(self.writes.get() + 1);
        Ok(())
    }
    async fn finish(&mut self) -> core::result::Result<(), ()> {
        crate::runtime::yield_now().await;
        self.sealed = true;
        Ok(())
    }
}

fn run<T>(future: impl Future<Output = T>) -> T {
    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    for _ in 0..100_000 {
        if let Poll::Ready(result) = future.as_mut().poll(&mut context) {
            return result;
        }
    }
    panic!("native method handoff parked")
}

fn exchange(
    method: &[u8],
    response_fields: &[(&[u8], &[u8])],
    response_body: &[u8],
    field_limit: u64,
) -> (Result<u64>, Output) {
    let graph = global::server::<0, 1, 2>();
    let reader_program = project::<0>(&graph);
    let app_program = project::<1>(&graph);
    let writer_program = project::<2>(&graph);
    let mut encoded = [0; 256];
    let fields: &[(&[u8], &[u8])] = &[
        (b":method", method),
        (b":scheme", b"https"),
        (b":authority", b"localhost"),
        (b":path", b"/"),
    ];
    let n = crate::http3::encode_fields(fields.iter().copied(), &mut encoded).unwrap();
    let mut wire = [0; 272];
    let prefix = crate::http3::frame_header(1, n as u64, &mut wire).unwrap();
    wire[prefix..prefix + n].copy_from_slice(&encoded[..n]);
    let admitted = Cell::new(false);
    let mut input = Input {
        bytes: &wire[..prefix + n],
        admitted: &admitted,
    };
    let mut inbound_body = [0; 3];
    let mut inbound_headers = [0; 256];
    let inbound = Exchange::new(&mut inbound_body, &mut inbound_headers);
    let mut outbound_body = [0; 2];
    let mut outbound_headers = [0; 256];
    let outbound = Exchange::new(&mut outbound_body, &mut outbound_headers);
    let carrier = CarrierStorage::<4, 16, 128>::new();
    let mut slab = [0; 65536];
    let mut kit = SessionKitStorage::uninit();
    let sid = SessionId::new(35);
    let rendezvous = kit
        .init()
        .rendezvous(&mut slab, carrier.bind(sid).unwrap())
        .unwrap();
    let mut reader = rendezvous.enter(sid, &reader_program).unwrap();
    let mut app = rendezvous.enter(sid, &app_program).unwrap();
    let mut writer = rendezvous.enter(sid, &writer_program).unwrap();
    let mut output = Output::new();
    let attempted = Cell::new(false);
    let response_headers_written = Cell::new(false);
    let guard = actor_test_allocator::NoAlloc::start();
    let result = {
        let tasks = crate::runtime::join::values3(
            localside::reader::server(&mut reader, &mut input, &inbound),
            async {
                let mut request = localside::request::Request::new(&inbound);
                let mut response = localside::producer::Response::new(&outbound);
                // The APP deliberately starts its response before consuming
                // request headers. Only READ supplies the method to WRITE.
                attempted.set(true);
                response.headers(&mut app, 200, response_fields).await?;
                response_headers_written.set(true);
                let head = request.headers(&mut app).await?;
                head.release(&mut app).await?;
                assert!(request.chunk(&mut app).await?.is_none());
                request.trailers(&mut app, |_| Ok(())).await?;
                request.finish(&mut app).await?;
                response.write(&mut app, response_body).await?;
                response.finish(&mut app).await
            },
            server(&mut writer, &mut output, field_limit, &outbound),
        );
        let mut tasks = pin!(tasks);
        let mut context = Context::from_waker(Waker::noop());
        for _ in 0..16 {
            assert!(tasks.as_mut().poll(&mut context).is_pending());
        }
        assert!(attempted.get());
        assert!(!response_headers_written.get());
        admitted.set(true);
        run(tasks)
    };
    if result.is_ok() {
        drop(reader);
        drop(app);
        drop(writer);
    }
    guard.finish();
    (result.map(|(_, _, count)| count), output)
}

#[test]
fn native_writer_waits_for_actual_head_method_and_preserves_metadata_length() {
    let (result, output) = exchange(b"HEAD", &[(b"content-length", b"123")], b"", 4096);
    assert_eq!(result.unwrap(), 0);
    assert!(output.sealed);
    let frame = crate::http3::decode_frame_header(&output.bytes[..output.len]).unwrap();
    assert_eq!(frame.kind, 1);
    assert_eq!(output.len, frame.encoded_len + frame.length as usize);
    let fields = crate::http3::decode_fields(&output.bytes[frame.encoded_len..output.len]).unwrap();
    assert_eq!(fields.content_length, Some(123));
}

#[test]
fn native_writer_rejects_head_data_without_emitting_data_or_fin() {
    let (result, output) = exchange(b"HEAD", &[], b"forbidden", 4096);
    assert!(result.is_err());
    assert!(!output.sealed);
    let frame = crate::http3::decode_frame_header(&output.bytes[..output.len]).unwrap();
    assert_eq!(frame.kind, 1);
    assert_eq!(output.len, frame.encoded_len + frame.length as usize);
}

#[test]
fn native_writer_enforces_decoded_peer_limit_before_any_frame_bytes() {
    // :status=200 occupies three QPACK bytes but 7 + 3 + 32 field-list bytes.
    let (result, output) = exchange(b"POST", &[], b"", 41);
    assert!(result.is_err());
    assert_eq!(output.len, 0);
    assert!(!output.sealed);
    let (result, output) = exchange(b"PATCH", &[], b"ok", 42);
    assert_eq!(result.unwrap(), 2);
    assert!(output.sealed);
}

#[test]
fn every_encoded_field_section_checks_the_limit_before_its_prefix() {
    for (kind, fields) in [
        (0, [(b":status".as_slice(), b"103".as_slice())]),
        (1, [(b":status".as_slice(), b"200".as_slice())]),
        (2, [(b"x-trailer".as_slice(), b"value".as_slice())]),
    ] {
        let mut encoded = [0; 64];
        let n = crate::http3::encode_fields(fields, &mut encoded).unwrap();
        let metadata = crate::http3::decode_fields(&encoded[..n]).unwrap();
        let limit = metadata.field_bytes as u64 - 1;
        assert!((n as u64) < limit);
        let section = FieldSection {
            metadata: &metadata,
            encoded: &encoded[..n],
        };
        let mut output = Output::new();
        let mut encode = Encode {
            output: &mut output,
            max_field_section_size: limit,
        };
        let result = match kind {
            0 => run(encode.information(section)),
            1 => run(encode.headers(section)),
            _ => run(encode.trailers(section)),
        };
        assert!(result.is_err());
        assert_eq!(output.len, 0);
        assert!(!output.sealed);
    }
}

#[test]
fn client_writer_transfers_actual_head_method_to_independent_download_role() {
    struct Consume {
        headers: bool,
        complete: bool,
    }
    impl Consumer for Consume {
        async fn headers(&mut self, fields: FieldSection<'_>) -> Result<()> {
            assert_eq!(fields.metadata.status, Some(200));
            assert_eq!(fields.metadata.content_length, Some(123));
            self.headers = true;
            Ok(())
        }
        async fn data(&mut self, _: u64, _: &[u8]) -> Result<()> {
            panic!("HEAD response cannot deliver body data")
        }
        async fn complete(&mut self, length: u64) -> Result<()> {
            assert_eq!(length, 0);
            self.complete = true;
            Ok(())
        }
    }

    for peer_limit in [4096, 1] {
        let graph = global::client::<1, 2, 0, 3>();
        let read_program = project::<0>(&graph);
        let upload_program = project::<1>(&graph);
        let write_program = project::<2>(&graph);
        let download_program = project::<3>(&graph);
        let mut fields = [0; 64];
        let n = crate::http3::encode_fields(
            [
                (b":status".as_slice(), b"200".as_slice()),
                (b"content-length".as_slice(), b"123".as_slice()),
            ],
            &mut fields,
        )
        .unwrap();
        let mut wire = [0; 80];
        let prefix = crate::http3::frame_header(1, n as u64, &mut wire).unwrap();
        wire[prefix..prefix + n].copy_from_slice(&fields[..n]);
        let admitted = Cell::new(true);
        let mut input = Input {
            bytes: &wire[..prefix + n],
            admitted: &admitted,
        };
        let mut inbound_body = [0; 3];
        let mut inbound_headers = [0; 64];
        let inbound = Exchange::new(&mut inbound_body, &mut inbound_headers);
        let mut outbound_body = [0; 2];
        let mut outbound_headers = [0; 256];
        let outbound = Exchange::new(&mut outbound_body, &mut outbound_headers);
        let carrier = CarrierStorage::<4, 16, 128>::new();
        let mut slab = [0; 65536];
        let mut kit = SessionKitStorage::uninit();
        let sid = SessionId::new(36);
        let rendezvous = kit
            .init()
            .rendezvous(&mut slab, carrier.bind(sid).unwrap())
            .unwrap();
        let mut read = rendezvous.enter(sid, &read_program).unwrap();
        let mut upload = rendezvous.enter(sid, &upload_program).unwrap();
        let mut write = rendezvous.enter(sid, &write_program).unwrap();
        let mut download = rendezvous.enter(sid, &download_program).unwrap();
        let mut output = Output::new();
        let mut consume = Consume {
            headers: false,
            complete: false,
        };
        let guard = actor_test_allocator::NoAlloc::start();
        let result = run(crate::runtime::join::values4(
            localside::reader::client(&mut read, &mut input, &inbound),
            async {
                let mut request = localside::outgoing::Request::new(&outbound);
                request
                    .headers(&mut upload, b"HEAD", b"localhost", b"/", &[])
                    .await?;
                request.finish(&mut upload).await
            },
            client(&mut write, &mut output, peer_limit, &outbound),
            async {
                let method = download
                    .recv::<global::RequestMethod>()
                    .await
                    .map_err(Error::from)?;
                assert_eq!(method, crate::http3::Method::Head as u8);
                let method = request_method(method)?;
                download
                    .send::<global::MethodStored>(&())
                    .await
                    .map_err(Error::from)?;
                localside::consumer::run(&mut download, &mut consume, method, &inbound).await
            },
        ));
        if peer_limit == 4096 {
            let ((), (), written, received) = result.unwrap();
            assert_eq!((written, received), (0, 0));
            assert!(consume.headers && consume.complete && output.sealed);

            drop(read);
            drop(upload);
            drop(write);
            drop(download);
            let frame = crate::http3::decode_frame_header(&output.bytes[..output.len]).unwrap();
            assert_eq!(frame.kind, 1);
            let fields =
                crate::http3::decode_fields(&output.bytes[frame.encoded_len..output.len]).unwrap();
            assert_eq!(fields.method, Some(crate::http3::Method::Head));
        } else {
            assert!(result.is_err());
            assert_eq!(output.len, 0);
            assert!(!consume.headers && !consume.complete && !output.sealed);
        }
        guard.finish();
    }
}
