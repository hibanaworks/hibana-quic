//! Attach the reader/consumer projections and drive their real endpoint-owning futures.
use crate::http3::message::Exchange;
use crate::http3::message::global::*;
use crate::http3::message::*;
use crate::io::RandomAccess;
use crate::runtime::carrier::CarrierStorage;
use hibana::runtime::{SessionKitStorage, ids::SessionId, program::project};
/// Decode only FIN-complete random-access storage. No destination is published here;
/// the caller keeps its existing atomic download-finish ownership contract.
pub async fn decode_response(file: &impl RandomAccess, slab: &mut [u8]) -> Result<u64> {
    let mut input = crate::http3::message::imp::input::Stored::new(file)?;
    let mut bytes = [0; 4096];
    let mut headers = [0; crate::http3::FIELD_LIMIT];
    let mut download = crate::http3::message::imp::download::Download(file);
    receive_response(
        &mut input,
        b"GET",
        ResponseStorage {
            body: &mut bytes,
            headers: &mut headers,
            slab,
        },
        &mut download,
    )
    .await
}

/// Caller-owned memory retained until the response localsides both finish.
pub struct ResponseStorage<'a> {
    pub body: &'a mut [u8],
    pub headers: &'a mut [u8],
    pub slab: &'a mut [u8],
}
/// Consume a standard response byte stream using the actual reader/consumer
/// projections. Input must end at that HTTP stream's FIN, not at a buffer boundary.
/// Successful completion is local message validation and consumption, not QUIC
/// connection close or peer acknowledgment. Effects stay provisional until success.
pub async fn receive_response(
    input: &mut impl crate::quic::application::BodyReader,
    request_method: &[u8],
    storage: ResponseStorage<'_>,
    consumer: &mut impl Consumer,
) -> Result<u64> {
    let global = response::<READER, CONSUMER>();
    let reader = project::<READER>(&global);
    let consumer_program = project::<CONSUMER>(&global);
    let carrier = CarrierStorage::<1, 16, 128>::new();
    let mut kit = SessionKitStorage::uninit();
    let sid = SessionId::new(1);
    let rendezvous = kit
        .init()
        .rendezvous(storage.slab, carrier.bind(sid).map_err(Error::from)?)
        .map_err(Error::from)?;
    let mut reader = rendezvous.enter(sid, &reader).map_err(Error::from)?;
    let mut endpoint = rendezvous
        .enter(sid, &consumer_program)
        .map_err(Error::from)?;
    let exchange = Exchange::new(storage.body, storage.headers);
    let ((), written) = crate::runtime::join::values2(
        localside::reader::run(&mut reader, input, &exchange),
        localside::consumer::run(&mut endpoint, consumer, request_method, &exchange),
    )
    .await?;
    drop(reader);
    drop(endpoint);
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::application::BodyReader;
    use core::{
        cell::RefCell,
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };
    struct Fragments<'a>(&'a [u8]);
    impl BodyReader for Fragments<'_> {
        async fn read(&mut self, out: &mut [u8]) -> core::result::Result<usize, ()> {
            crate::runtime::yield_now().await;
            let count = self.0.len().min(out.len()).min(3);
            out[..count].copy_from_slice(&self.0[..count]);
            self.0 = &self.0[count..];
            Ok(count)
        }
    }
    struct Output(RefCell<std::vec::Vec<u8>>);
    impl RandomAccess for Output {
        fn len(&self) -> core::result::Result<u64, crate::io::IoError> {
            Ok(self.0.borrow().len() as u64)
        }
        fn read_exact_at(
            &self,
            _: &mut [u8],
            _: u64,
        ) -> core::result::Result<(), crate::io::IoError> {
            Err(crate::io::IoError::Rejected)
        }
        fn write_all_at(
            &self,
            bytes: &[u8],
            offset: u64,
        ) -> core::result::Result<(), crate::io::IoError> {
            let mut out = self.0.borrow_mut();
            if offset != out.len() as u64 {
                return Err(crate::io::IoError::Rejected);
            }
            out.extend_from_slice(bytes);
            Ok(())
        }
        fn set_len(&self, length: u64) -> core::result::Result<(), crate::io::IoError> {
            self.0.borrow_mut().resize(length as usize, 0);
            Ok(())
        }
    }
    fn run<T>(future: impl Future<Output = T>) -> T {
        let mut future = pin!(future);
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..1_000_000 {
            if let Poll::Ready(result) = future.as_mut().poll(&mut cx) {
                return result;
            }
        }
        panic!("streaming response did not finish")
    }
    #[derive(Default)]
    struct Inspect {
        status: u16,
        extensions: usize,
        trailers: usize,
        body: [u8; 8],
        complete: u64,
    }
    impl Consumer for Inspect {
        async fn headers(&mut self, section: FieldSection<'_>) -> Result<()> {
            self.status = section.metadata.status.unwrap();
            section.for_each(|name, value| {
                if name == b"x-application" {
                    assert_eq!(value, b"preserved");
                    self.extensions += 1;
                }
                Ok(())
            })
        }
        async fn data(&mut self, offset: u64, bytes: &[u8]) -> Result<()> {
            let offset = offset as usize;
            self.body[offset..offset + bytes.len()].copy_from_slice(bytes);
            Ok(())
        }
        async fn trailers(&mut self, section: FieldSection<'_>) -> Result<()> {
            section.for_each(|name, value| {
                assert_eq!(
                    (name, value),
                    (b"x-trailer".as_slice(), b"checked".as_slice())
                );
                self.trailers += 1;
                Ok(())
            })
        }
        async fn complete(&mut self, length: u64) -> Result<()> {
            self.complete = length;
            Ok(())
        }
    }
    fn frame(kind: u64, bytes: &[u8], output: &mut std::vec::Vec<u8>) {
        let mut header = [0; 16];
        let n = crate::http3::frame_header(kind, bytes.len() as u64, &mut header).unwrap();
        output.extend_from_slice(&header[..n]);
        output.extend_from_slice(bytes);
    }
    #[test]
    fn non_success_response_preserves_extensions_and_trailers_without_allocating() {
        let mut wire = std::vec::Vec::new();
        let mut fields = [0; 256];
        let headers: &[(&[u8], &[u8])] = &[
            (b":status", b"404"),
            (b"x-application", b"preserved"),
            (b"content-length", b"3"),
        ];
        let n = crate::http3::encode_fields(headers.iter().copied(), &mut fields).unwrap();
        frame(1, &fields[..n], &mut wire);
        frame(0, b"abc", &mut wire);
        let n = crate::http3::encode_fields(
            [(b"x-trailer".as_slice(), b"checked".as_slice())],
            &mut fields,
        )
        .unwrap();
        frame(1, &fields[..n], &mut wire);
        let mut input = Fragments(&wire);
        let mut body = [0; 2];
        let mut headers = [0; 256];
        let mut slab = [0; 65536];
        let mut consumer = Inspect::default();
        let guard = actor_test_allocator::NoAlloc::start();
        let length = run(receive_response(
            &mut input,
            b"GET",
            ResponseStorage {
                body: &mut body,
                headers: &mut headers,
                slab: &mut slab,
            },
            &mut consumer,
        ))
        .unwrap();
        guard.finish();
        assert_eq!(
            (
                length,
                consumer.status,
                consumer.extensions,
                consumer.trailers,
                consumer.complete
            ),
            (3, 404, 1, 1, 3)
        );
        assert_eq!(&consumer.body[..3], b"abc");
    }
    #[test]
    fn head_response_metadata_does_not_require_a_body_of_content_length() {
        let mut wire = std::vec::Vec::new();
        let mut fields = [0; 64];
        let headers: &[(&[u8], &[u8])] = &[(b":status", b"200"), (b"content-length", b"123")];
        let n = crate::http3::encode_fields(headers.iter().copied(), &mut fields).unwrap();
        frame(1, &fields[..n], &mut wire);
        let mut input = Fragments(&wire);
        let mut body = [0; 1];
        let mut headers = [0; 64];
        let mut slab = [0; 65536];
        let mut consumer = Inspect::default();
        assert_eq!(
            run(receive_response(
                &mut input,
                b"HEAD",
                ResponseStorage {
                    body: &mut body,
                    headers: &mut headers,
                    slab: &mut slab
                },
                &mut consumer
            ))
            .unwrap(),
            0
        );
    }
    #[test]
    fn real_projected_reader_streams_large_data_through_seven_byte_borrowed_storage() {
        let body: std::vec::Vec<u8> = (0..32768).map(|i| (i % 251) as u8).collect();
        let mut encoded = std::vec![1, 3, 0, 0, 0xd9];
        let mut header = [0; 16];
        let n = crate::http3::frame_header(0, body.len() as u64, &mut header).unwrap();
        encoded.extend_from_slice(&header[..n]);
        encoded.extend_from_slice(&body);
        let mut input = Fragments(&encoded);
        let output = Output(RefCell::new(std::vec::Vec::new()));
        let mut bytes = [0; 7];
        let mut headers = [0; crate::http3::FIELD_LIMIT];
        let exchange = Exchange {
            fields: RefCell::new(None),
            bytes: RefCell::new(&mut bytes),
            headers: RefCell::new(&mut headers),
        };
        let graph = response::<READER, CONSUMER>();
        let reader_program = project::<READER>(&graph);
        let writer_program = project::<CONSUMER>(&graph);
        let carrier = CarrierStorage::<1, 16, 128>::new();
        let mut slab = [0; 65536];
        let mut kit = SessionKitStorage::uninit();
        let sid = SessionId::new(31);
        let rendezvous = kit
            .init()
            .rendezvous(&mut slab, carrier.bind(sid).unwrap())
            .unwrap();
        let mut reader = rendezvous.enter(sid, &reader_program).unwrap();
        let mut writer = rendezvous.enter(sid, &writer_program).unwrap();
        let mut download = crate::http3::message::imp::download::Download(&output);
        let ((), written) = run(crate::runtime::join::values2(
            localside::reader::run(&mut reader, &mut input, &exchange),
            localside::consumer::run(&mut writer, &mut download, b"GET", &exchange),
        ))
        .unwrap();
        drop(reader);
        drop(writer);
        assert_eq!(written, body.len() as u64);
        assert_eq!(&*output.0.borrow(), &body);
    }
    #[test]
    fn cancellation_returns_borrowed_header_and_body_storage() {
        struct Park<'a>(&'a core::cell::Cell<bool>);
        impl Consumer for Park<'_> {
            async fn headers(&mut self, _: FieldSection<'_>) -> Result<()> {
                self.0.set(true);
                core::future::pending().await
            }
            async fn data(&mut self, _: u64, _: &[u8]) -> Result<()> {
                panic!("body cannot precede acknowledged headers")
            }
            async fn complete(&mut self, _: u64) -> Result<()> {
                panic!("parked headers cannot complete")
            }
        }
        let wire = [1, 3, 0, 0, 0xd9];
        let mut body = [0; 2];
        let mut headers = [0; 64];
        let mut slab = [0; 65536];
        let entered = core::cell::Cell::new(false);
        {
            let mut input = Fragments(&wire);
            let mut consumer = Park(&entered);
            let mut receive = pin!(receive_response(
                &mut input,
                b"GET",
                ResponseStorage {
                    body: &mut body,
                    headers: &mut headers,
                    slab: &mut slab
                },
                &mut consumer,
            ));
            let mut cx = Context::from_waker(Waker::noop());
            for _ in 0..64 {
                assert!(receive.as_mut().poll(&mut cx).is_pending());
                if entered.get() {
                    break;
                }
            }
            assert!(entered.get());
        }
        // Dropping the real projected run releases every outstanding borrow.
        body.fill(0xa5);
        headers.fill(0xa5);
        slab.fill(0);
        let mut consumer = Inspect::default();
        assert_eq!(
            run(receive_response(
                &mut Fragments(&wire),
                b"GET",
                ResponseStorage {
                    body: &mut body,
                    headers: &mut headers,
                    slab: &mut slab
                },
                &mut consumer,
            ))
            .unwrap(),
            0
        );
        assert_eq!(consumer.status, 200);
    }
    #[test]
    fn response_fragment_composes_with_an_application_result_on_the_same_endpoint() {
        const INPUT: u8 = 3;
        const APP: u8 = 4;
        const RESULT: u8 = 5;
        type BodyLength = hibana::g::Msg<40, u64>;
        let graph = hibana::g::seq(
            response::<INPUT, APP>(),
            hibana::g::send::<APP, RESULT, BodyLength>(),
        );
        let input_program = project::<INPUT>(&graph);
        let app_program = project::<APP>(&graph);
        let result_program = project::<RESULT>(&graph);
        let carrier = CarrierStorage::<2, 16, 128>::new();
        let mut slab = [0; 65536];
        let mut kit = SessionKitStorage::uninit();
        let sid = SessionId::new(32);
        let rendezvous = kit
            .init()
            .rendezvous(&mut slab, carrier.bind(sid).unwrap())
            .unwrap();
        let mut input_endpoint = rendezvous.enter(sid, &input_program).unwrap();
        let mut app_endpoint = rendezvous.enter(sid, &app_program).unwrap();
        let mut result_endpoint = rendezvous.enter(sid, &result_program).unwrap();
        let wire = [1, 3, 0, 0, 0xd9, 0, 3, b'a', b'b', b'c'];
        let mut input = Fragments(&wire);
        let mut bytes = [0; 2];
        let mut headers = [0; 64];
        let exchange = Exchange::new(&mut bytes, &mut headers);
        let mut consumer = Inspect::default();
        let (_, (), length) = run(crate::runtime::join::values3(
            localside::reader::run(&mut input_endpoint, &mut input, &exchange),
            async {
                let length =
                    localside::consumer::run(&mut app_endpoint, &mut consumer, b"GET", &exchange)
                        .await?;
                app_endpoint
                    .send::<BodyLength>(&length)
                    .await
                    .map_err(Error::from)
            },
            async {
                result_endpoint
                    .recv::<BodyLength>()
                    .await
                    .map_err(Error::from)
            },
        ))
        .unwrap();
        assert_eq!(length, 3);
        assert_eq!(&consumer.body[..3], b"abc");
        drop(input_endpoint);
        drop(app_endpoint);
        drop(result_endpoint);
    }
    #[test]
    fn request_fragment_streams_extension_method_into_application_result() {
        struct Count(u64);
        impl Consumer for Count {
            async fn headers(&mut self, section: FieldSection<'_>) -> Result<()> {
                assert_eq!(section.metadata.method, Some(crate::http3::Method::Other));
                section.for_each(|name, value| {
                    if name == b":method" {
                        assert_eq!(value, b"PATCH");
                    }
                    Ok(())
                })
            }
            async fn data(&mut self, offset: u64, bytes: &[u8]) -> Result<()> {
                assert_eq!(offset, self.0);
                self.0 += bytes.len() as u64;
                Ok(())
            }
            async fn complete(&mut self, length: u64) -> Result<()> {
                assert_eq!(length, self.0);
                Ok(())
            }
        }
        type Counted = hibana::g::Msg<40, u64>;
        let graph = hibana::g::seq(request::<0, 1>(), hibana::g::send::<1, 2, Counted>());
        let reader_program = project::<0>(&graph);
        let app_program = project::<1>(&graph);
        let reply_program = project::<2>(&graph);
        let mut encoded = [0; 256];
        let fields: &[(&[u8], &[u8])] = &[
            (b":method", b"PATCH"),
            (b":scheme", b"https"),
            (b":authority", b"localhost"),
            (b":path", b"/count"),
            (b"content-length", b"5"),
        ];
        let n = crate::http3::encode_fields(fields.iter().copied(), &mut encoded).unwrap();
        let mut wire = std::vec::Vec::new();
        frame(1, &encoded[..n], &mut wire);
        frame(0, b"hello", &mut wire);
        let mut input = Fragments(&wire);
        let mut body = [0; 2];
        let mut headers = [0; 256];
        let exchange = Exchange::new(&mut body, &mut headers);
        let carrier = CarrierStorage::<2, 16, 128>::new();
        let mut slab = [0; 65536];
        let mut kit = SessionKitStorage::uninit();
        let sid = SessionId::new(33);
        let rendezvous = kit
            .init()
            .rendezvous(&mut slab, carrier.bind(sid).unwrap())
            .unwrap();
        let mut reader = rendezvous.enter(sid, &reader_program).unwrap();
        let mut app = rendezvous.enter(sid, &app_program).unwrap();
        let mut reply = rendezvous.enter(sid, &reply_program).unwrap();
        let mut counter = Count(0);
        let (_, (), length) = run(crate::runtime::join::values3(
            localside::reader::request(&mut reader, &mut input, &exchange),
            async {
                let count = localside::consumer::request(&mut app, &mut counter, &exchange).await?;
                app.send::<Counted>(&count).await.map_err(Error::from)
            },
            async { reply.recv::<Counted>().await.map_err(Error::from) },
        ))
        .unwrap();
        assert_eq!(length, 5);
        drop(reader);
        drop(app);
        drop(reply);
    }
    #[test]
    fn shared_application_role_echoes_borrowed_chunks_with_delayed_writer_and_empty_body() {
        struct Output {
            bytes: [u8; 256],
            len: usize,
            sealed: bool,
        }
        impl localside::writer::BodyWriter for Output {
            async fn write(&mut self, bytes: &[u8]) -> core::result::Result<(), ()> {
                crate::runtime::yield_now().await;
                crate::runtime::yield_now().await;
                let end = self.len.checked_add(bytes.len()).ok_or(())?;
                self.bytes
                    .get_mut(self.len..end)
                    .ok_or(())?
                    .copy_from_slice(bytes);
                self.len = end;
                Ok(())
            }
            async fn finish(&mut self) -> core::result::Result<(), ()> {
                crate::runtime::yield_now().await;
                self.sealed = true;
                Ok(())
            }
        }
        for payload in [b"".as_slice(), b"a", b"abcdefg"] {
            let graph = hibana::g::par(request::<0, 1>(), response::<1, 2>());
            let reader_program = project::<0>(&graph);
            let app_program = project::<1>(&graph);
            let writer_program = project::<2>(&graph);
            let mut encoded = [0; 256];
            let fields: &[(&[u8], &[u8])] = &[
                (b":method", b"POST"),
                (b":scheme", b"https"),
                (b":authority", b"localhost"),
                (b":path", b"/echo"),
            ];
            let n = crate::http3::encode_fields(fields.iter().copied(), &mut encoded).unwrap();
            let mut wire = std::vec::Vec::new();
            frame(1, &encoded[..n], &mut wire);
            if !payload.is_empty() {
                frame(0, payload, &mut wire);
            }
            let mut input = Fragments(&wire);
            let mut inbound_body = [0; 3];
            let mut inbound_headers = [0; 256];
            let inbound = Exchange::new(&mut inbound_body, &mut inbound_headers);
            let mut outbound_body = [0; 2];
            let mut outbound_headers = [0; 256];
            let outbound = Exchange::new(&mut outbound_body, &mut outbound_headers);
            // Empty request can enqueue BodyEnd, NoTrailers and End while
            // the APP advances the parallel response. Four slots avoid an
            // artificial cross-direction dependency in this exact graph.
            let carrier = CarrierStorage::<4, 16, 128>::new();
            let mut slab = [0; 65536];
            let mut kit = SessionKitStorage::uninit();
            let sid = SessionId::new(34);
            let rendezvous = kit
                .init()
                .rendezvous(&mut slab, carrier.bind(sid).unwrap())
                .unwrap();
            let mut reader = rendezvous.enter(sid, &reader_program).unwrap();
            let mut app = rendezvous.enter(sid, &app_program).unwrap();
            let mut writer = rendezvous.enter(sid, &writer_program).unwrap();
            let mut output = Output {
                bytes: [0; 256],
                len: 0,
                sealed: false,
            };
            let guard = actor_test_allocator::NoAlloc::start();
            let ((), (), count) = run(crate::runtime::join::values3(
                localside::reader::request(&mut reader, &mut input, &inbound),
                async {
                    let mut request = localside::request::Request::new(&inbound);
                    let mut response = localside::producer::Response::new(&outbound);
                    let head = request.headers(&mut app).await?;
                    assert_eq!(
                        head.fields().metadata.method,
                        Some(crate::http3::Method::Post)
                    );
                    head.release(&mut app).await?;
                    response.headers(&mut app, 200, &[]).await?;
                    while let Some(chunk) = request.chunk(&mut app).await? {
                        response.write(&mut app, chunk.bytes()).await?;
                        chunk.release(&mut app).await?;
                    }
                    request.trailers(&mut app, |_| Ok(())).await?;
                    request.finish(&mut app).await?;
                    response.finish(&mut app).await
                },
                localside::writer::response(&mut writer, &mut output, b"POST", &outbound),
            ))
            .unwrap();
            drop(reader);
            drop(app);
            drop(writer);
            guard.finish();
            assert_eq!(count, payload.len() as u64);
            assert!(output.sealed);
            let mut decoded = Inspect::default();
            let mut body = [0; 2];
            let mut headers = [0; 64];
            let mut slab = [0; 65536];
            assert_eq!(
                run(receive_response(
                    &mut Fragments(&output.bytes[..output.len]),
                    b"POST",
                    ResponseStorage {
                        body: &mut body,
                        headers: &mut headers,
                        slab: &mut slab
                    },
                    &mut decoded,
                ))
                .unwrap(),
                payload.len() as u64
            );
            assert_eq!(&decoded.body[..payload.len()], payload);
        }
    }
}
