//! The application's ordinary HTTPS request-producing projection.
//! Every action advances the supplied endpoint and waits for the writer's
//! actual storage receipt. There is no second message-phase state.
//! Cancel the entire exchange after abandoning an action: a cancelled action
//! may already have committed and must not be retried independently.
use crate::http3::message::{Error, Exchange, Result, global::*};
use hibana::Endpoint;

pub struct Request<'a, 'storage, const ROLE: u8> {
    exchange: &'a Exchange<'storage>,
}
impl<'a, 'storage, const ROLE: u8> Request<'a, 'storage, ROLE> {
    pub const fn new(exchange: &'a Exchange<'storage>) -> Self {
        Self { exchange }
    }

    /// Produce one ordinary HTTPS request field section. Method and target
    /// bytes are borrowed only for this action and encoded into caller storage.
    /// `authority` is a nonempty HTTPS authority; `path` is an absolute path
    /// with an optional query, or `*` for OPTIONS. CONNECT needs a tunnel API.
    /// Additional fields cannot replace pseudo-headers. Original method and
    /// field bytes, including extension methods and repeated ordinary fields,
    /// remain available to the writer through the exchange's field section.
    pub async fn headers(
        &mut self,
        endpoint: &mut Endpoint<'_, ROLE>,
        method: &[u8],
        authority: &[u8],
        path: &[u8],
        fields: &[(&[u8], &[u8])],
    ) -> Result<()> {
        if fields.iter().any(|(name, _)| name.starts_with(b":")) {
            return Err("request fields contain an additional pseudo-header".into());
        }
        {
            let mut storage = self
                .exchange
                .headers
                .try_borrow_mut()
                .map_err(|_| Error::Invalid("request header storage is borrowed"))?;
            let pseudo = [
                (b":method".as_slice(), method),
                (b":scheme".as_slice(), b"https".as_slice()),
                (b":authority".as_slice(), authority),
                (b":path".as_slice(), path),
            ];
            let length = crate::http3::encode_fields(
                pseudo.into_iter().chain(fields.iter().copied()),
                &mut storage,
            )?;
            let metadata = crate::http3::decode_fields(&storage[..length])?;
            crate::http3::message::imp::request::ordinary(&storage[..length], &metadata)?;
            *self
                .exchange
                .fields
                .try_borrow_mut()
                .map_err(|_| Error::Invalid("request field storage is borrowed"))? =
                Some((metadata, length));
        }
        endpoint.send::<Headers>(&()).await.map_err(Error::from)?;
        endpoint.recv::<Stored>().await.map_err(Error::from)?;
        Ok(())
    }

    /// Stream borrowed bytes through bounded caller storage. Each chunk stays
    /// in the exchange until the writer returns its storage receipt. The
    /// writer checks any content-length against the actual transferred bytes.
    pub async fn write(
        &mut self,
        endpoint: &mut Endpoint<'_, ROLE>,
        mut bytes: &[u8],
    ) -> Result<()> {
        while !bytes.is_empty() {
            let count = bytes.len().min(
                self.exchange
                    .bytes
                    .try_borrow()
                    .map_err(|_| Error::Invalid("request body storage is borrowed"))?
                    .len(),
            );
            if count == 0 {
                return Err("empty request body storage".into());
            }
            self.exchange
                .bytes
                .try_borrow_mut()
                .map_err(|_| Error::Invalid("request body storage is borrowed"))?[..count]
                .copy_from_slice(&bytes[..count]);
            endpoint
                .send::<Data>(&(count as u64))
                .await
                .map_err(Error::from)?;
            endpoint.recv::<Stored>().await.map_err(Error::from)?;
            bytes = &bytes[count..];
        }
        Ok(())
    }

    /// Seal this request without trailers. Done is the local writer's receipt,
    /// not a peer acknowledgment or a connection-close receipt. The containing
    /// application still owns and completes its composed endpoint.
    pub async fn finish(self, endpoint: &mut Endpoint<'_, ROLE>) -> Result<()> {
        endpoint.send::<BodyEnd>(&()).await.map_err(Error::from)?;
        endpoint
            .send::<NoTrailers>(&())
            .await
            .map_err(Error::from)?;
        endpoint.send::<End>(&()).await.map_err(Error::from)?;
        endpoint.recv::<Done>().await.map_err(Error::from)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http3::message::{Consumer, FieldSection, localside};
    use crate::runtime::carrier::CarrierStorage;
    use core::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };
    use hibana::runtime::{SessionKitStorage, ids::SessionId, program::project};

    fn run<T>(future: impl Future<Output = T>) -> T {
        let mut future = pin!(future);
        let mut context = Context::from_waker(Waker::noop());
        for _ in 0..100_000 {
            if let Poll::Ready(result) = future.as_mut().poll(&mut context) {
                return result;
            }
        }
        panic!("request choreography did not finish");
    }

    #[derive(Default)]
    struct Inspect {
        bytes: [u8; 16],
        length: usize,
        complete: bool,
    }
    impl Consumer for Inspect {
        async fn headers(&mut self, fields: FieldSection<'_>) -> Result<()> {
            crate::runtime::yield_now().await;
            assert_eq!(fields.metadata.method, Some(crate::http3::Method::Other));
            assert_eq!(fields.metadata.https, Some(true));
            assert_eq!(
                &fields.metadata.path[..fields.metadata.path_len],
                b"/upload?part=1"
            );
            let mut tags = 0;
            fields.for_each(|name, value| {
                if name == b":method" {
                    assert_eq!(value, b"PATCH");
                }
                if name == b"x-tag" {
                    assert_eq!(value, [b'1' + tags]);
                    tags += 1;
                }
                Ok(())
            })?;
            assert_eq!(tags, 2);
            Ok(())
        }
        async fn data(&mut self, offset: u64, bytes: &[u8]) -> Result<()> {
            crate::runtime::yield_now().await;
            crate::runtime::yield_now().await;
            assert_eq!(offset, self.length as u64);
            assert!(bytes.len() <= 2);
            let end = self.length + bytes.len();
            self.bytes[self.length..end].copy_from_slice(bytes);
            self.length = end;
            Ok(())
        }
        async fn complete(&mut self, length: u64) -> Result<()> {
            crate::runtime::yield_now().await;
            assert_eq!(length, self.length as u64);
            self.complete = true;
            Ok(())
        }
    }

    #[test]
    fn request_actions_transfer_borrowed_storage_and_continue_the_application_without_allocating() {
        type Counted = hibana::g::Msg<40, u64>;
        for payload in [b"".as_slice(), b"abcdefg"] {
            let graph = hibana::g::seq(request::<4, 5>(), hibana::g::send::<4, 6, Counted>());
            let app_program = project::<4>(&graph);
            let writer_program = project::<5>(&graph);
            let result_program = project::<6>(&graph);
            let carrier = CarrierStorage::<2, 16, 128>::new();
            let mut slab = [0; 65536];
            let mut kit = SessionKitStorage::uninit();
            let sid = SessionId::new(45);
            let rendezvous = kit
                .init()
                .rendezvous(&mut slab, carrier.bind(sid).unwrap())
                .unwrap();
            let mut app = rendezvous.enter(sid, &app_program).unwrap();
            let mut writer = rendezvous.enter(sid, &writer_program).unwrap();
            let mut result = rendezvous.enter(sid, &result_program).unwrap();
            let mut body = [0; 2];
            let mut headers = [0; 256];
            let exchange = Exchange::new(&mut body, &mut headers);
            let mut output = Inspect::default();
            let content_length = [b'0' + payload.len() as u8];
            let guard = actor_test_allocator::NoAlloc::start();
            let ((), written, count) = run(crate::runtime::join::values3(
                async {
                    let mut request = Request::new(&exchange);
                    request
                        .headers(
                            &mut app,
                            b"PATCH",
                            b"example.com",
                            b"/upload?part=1",
                            &[
                                (b"content-length", &content_length),
                                (b"x-tag", b"1"),
                                (b"x-tag", b"2"),
                            ],
                        )
                        .await?;
                    request.write(&mut app, b"").await?;
                    request.write(&mut app, payload).await?;
                    request.finish(&mut app).await?;
                    app.send::<Counted>(&(payload.len() as u64))
                        .await
                        .map_err(Error::from)
                },
                localside::consumer::request(&mut writer, &mut output, &exchange),
                async { result.recv::<Counted>().await.map_err(Error::from) },
            ))
            .unwrap();
            drop(app);
            drop(writer);
            drop(result);
            guard.finish();
            assert_eq!(written, payload.len() as u64);
            assert_eq!(count, written);
            assert!(output.complete);
            assert_eq!(&output.bytes[..output.length], payload);
        }
    }

    #[test]
    fn invalid_request_fields_are_rejected_before_the_header_transfer() {
        let graph = request::<0, 1>();
        let app_program = project::<0>(&graph);
        let carrier = CarrierStorage::<2, 16, 128>::new();
        let mut slab = [0; 65536];
        let mut kit = SessionKitStorage::uninit();
        let sid = SessionId::new(46);
        let rendezvous = kit
            .init()
            .rendezvous(&mut slab, carrier.bind(sid).unwrap())
            .unwrap();
        let mut app = rendezvous.enter(sid, &app_program).unwrap();
        let mut body = [0; 2];
        let mut headers = [0; 256];
        let exchange = Exchange::new(&mut body, &mut headers);
        let mut request = Request::new(&exchange);
        assert!(matches!(
            run(request.write(&mut app, b"a")),
            Err(Error::Endpoint(_))
        ));
        type Case<'a> = (&'a [u8], &'a [u8], &'a [u8], &'a [(&'a [u8], &'a [u8])]);
        let cases: &[Case<'_>] = &[
            (b"BAD METHOD", b"example.com", b"/", &[]),
            (b"CONNECT", b"example.com", b"/", &[]),
            (b"GET", b"", b"/", &[]),
            (b"GET", b"user@example.com", b"/", &[]),
            (b"GET", b"example.com", b"relative", &[]),
            (b"GET", b"example.com", b"*", &[]),
            (b"GET", b"example.com", b"/#fragment", &[]),
            (b"GET", b"example.com", b"/%zz", &[]),
            (b"GET", b"example.com", b"/", &[(b":method", b"POST")]),
            (b"GET", b"example.com", b"/", &[(b"host", b"other.example")]),
            (b"GET", b"example.com", b"/", &[(b"connection", b"close")]),
            (b"GET", b"example.com", b"/", &[(b"te", b"gzip")]),
        ];
        for &(method, authority, path, fields) in cases {
            assert!(run(request.headers(&mut app, method, authority, path, fields)).is_err());
            assert!(exchange.fields.borrow().is_none());
        }
    }

    #[test]
    fn empty_body_storage_accepts_empty_write_and_rejects_nonempty_write() {
        let graph = request::<0, 1>();
        let app_program = project::<0>(&graph);
        let carrier = CarrierStorage::<2, 16, 128>::new();
        let mut slab = [0; 65536];
        let mut kit = SessionKitStorage::uninit();
        let sid = SessionId::new(47);
        let rendezvous = kit
            .init()
            .rendezvous(&mut slab, carrier.bind(sid).unwrap())
            .unwrap();
        let mut app = rendezvous.enter(sid, &app_program).unwrap();
        let mut body = [];
        let mut headers = [0; 1];
        let exchange = Exchange::new(&mut body, &mut headers);
        let mut request = Request::new(&exchange);
        assert!(run(request.write(&mut app, b"")).is_ok());
        assert!(matches!(
            run(request.write(&mut app, b"a")),
            Err(Error::Invalid("empty request body storage"))
        ));
        assert!(matches!(
            run(request.headers(&mut app, b"GET", b"example.com", b"/", &[])),
            Err(Error::Fields(crate::http3::Error::Capacity))
        ));
        assert!(exchange.fields.borrow().is_none());
    }

    #[test]
    fn content_length_mismatch_never_returns_a_completion_receipt() {
        for content_length in [b"0".as_slice(), b"8"] {
            let graph = request::<0, 1>();
            let app_program = project::<0>(&graph);
            let writer_program = project::<1>(&graph);
            let carrier = CarrierStorage::<2, 16, 128>::new();
            let mut slab = [0; 65536];
            let mut kit = SessionKitStorage::uninit();
            let sid = SessionId::new(48);
            let rendezvous = kit
                .init()
                .rendezvous(&mut slab, carrier.bind(sid).unwrap())
                .unwrap();
            let mut app = rendezvous.enter(sid, &app_program).unwrap();
            let mut writer = rendezvous.enter(sid, &writer_program).unwrap();
            let mut body = [0; 2];
            let mut headers = [0; 256];
            let exchange = Exchange::new(&mut body, &mut headers);
            let mut output = Inspect::default();
            let result = run(crate::runtime::join::values2(
                async {
                    let mut request = Request::new(&exchange);
                    request
                        .headers(
                            &mut app,
                            b"PATCH",
                            b"example.com",
                            b"/upload?part=1",
                            &[
                                (b"content-length", content_length),
                                (b"x-tag", b"1"),
                                (b"x-tag", b"2"),
                            ],
                        )
                        .await?;
                    request.write(&mut app, b"abcdefg").await?;
                    request.finish(&mut app).await
                },
                localside::consumer::request(&mut writer, &mut output, &exchange),
            ));
            assert!(matches!(result, Err(Error::Invalid(_))));
            assert!(!output.complete);
        }
    }
}
