use crate::io::RandomAccess;
use crate::quic::application::{BodyReader, ClientRequests, ServerHandler, StreamSink};
use core::task::{Context, Poll};

/// Borrows the actual remaining requests. The connection's projected source
/// commits removal only after assigning a stream, through `started`.
pub struct Requests<'a> {
    remaining: &'a [&'a str],
}
impl<'a> Requests<'a> {
    pub const fn new(targets: &'a [&'a str]) -> Self {
        Self { remaining: targets }
    }
}
impl ClientRequests for Requests<'_> {
    async fn next(&mut self, output: &mut [u8]) -> Result<Option<usize>, ()> {
        self.remaining
            .first()
            .map(|target| super::codec::encode_request(target, output).map_err(|_| ()))
            .transpose()
    }
    fn started(&mut self, _: u64) -> Result<(), ()> {
        self.remaining = self.remaining.get(1..).ok_or(())?;
        Ok(())
    }
}
/// A single response's caller-owned output. The write offset is physical storage
/// accounting; authentication, stream admission and FIN are owned by QUIC.
pub struct Response<'a, Store> {
    store: &'a Store,
    written: u64,
}
impl<'a, Store: RandomAccess> Response<'a, Store> {
    pub fn new(store: &'a Store) -> Result<Self, crate::io::IoError> {
        store.set_len(0)?;
        Ok(Self { store, written: 0 })
    }
    pub const fn bytes_written(&self) -> u64 {
        self.written
    }
}
impl<Store: RandomAccess> StreamSink for Response<'_, Store> {
    fn poll_write(
        &mut self,
        stream: u64,
        bytes: &[u8],
        _: &mut Context<'_>,
    ) -> Poll<Result<usize, ()>> {
        Poll::Ready((|| {
            if stream != 0 {
                return Err(());
            }
            let next = self.written.checked_add(bytes.len() as u64).ok_or(())?;
            self.store
                .write_all_at(bytes, self.written)
                .map_err(|_| ())?;
            self.written = next;
            Ok(bytes.len())
        })())
    }
    async fn finish(&mut self, stream: u64) -> Result<(), ()> {
        if stream != 0 {
            return Err(());
        }
        self.store.set_len(self.written).map_err(|_| ())
    }
}
/// Owns each opened response store until the core retires its real stream.
pub struct Body<Store> {
    store: Store,
    offset: u64,
    len: u64,
}
impl<Store: RandomAccess> BodyReader for Body<Store> {
    async fn read(&mut self, output: &mut [u8]) -> Result<usize, ()> {
        if output.is_empty() {
            return Err(());
        }
        let n = (self.len - self.offset).min(output.len() as u64) as usize;
        self.store
            .read_exact_at(&mut output[..n], self.offset)
            .map_err(|_| ())?;
        self.offset += n as u64;
        Ok(n)
    }
}
/// The application supplies only its path-to-store policy. No filesystem or OS
/// types cross this boundary and the returned store is transferred by value.
pub struct Service<Open> {
    open: Open,
}
impl<Open> Service<Open> {
    pub const fn new(open: Open) -> Self {
        Self { open }
    }
}
impl<Open, Store> ServerHandler for Service<Open>
where
    Open: FnMut(&str) -> Result<Store, ()>,
    Store: RandomAccess,
{
    type Body = Body<Store>;
    async fn open(&mut self, _: u64, request: &[u8]) -> Result<Self::Body, ()> {
        let target = super::codec::decode_request(request).map_err(|_| ())?;
        let store = (self.open)(target)?;
        let len = store.len().map_err(|_| ())?;
        Ok(Body {
            store,
            offset: 0,
            len,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::IoError;
    use core::{
        cell::{Cell, RefCell},
        future::Future,
        task::Waker,
    };

    struct Store {
        bytes: RefCell<[u8; 16]>,
        len: Cell<usize>,
    }
    impl Store {
        fn new() -> Self {
            Self {
                bytes: RefCell::new([0; 16]),
                len: Cell::new(0),
            }
        }
    }
    impl RandomAccess for Store {
        fn len(&self) -> Result<u64, IoError> {
            Ok(self.len.get() as u64)
        }
        fn set_len(&self, n: u64) -> Result<(), IoError> {
            let n = usize::try_from(n).map_err(|_| IoError::Rejected)?;
            if n > 16 {
                return Err(IoError::Rejected);
            }
            self.len.set(n);
            Ok(())
        }
        fn read_exact_at(&self, out: &mut [u8], offset: u64) -> Result<(), IoError> {
            let start = usize::try_from(offset).map_err(|_| IoError::Rejected)?;
            let end = start.checked_add(out.len()).ok_or(IoError::Rejected)?;
            let bytes = self.bytes.borrow();
            out.copy_from_slice(
                bytes[..self.len.get()]
                    .get(start..end)
                    .ok_or(IoError::Rejected)?,
            );
            Ok(())
        }
        fn write_all_at(&self, input: &[u8], offset: u64) -> Result<(), IoError> {
            let start = usize::try_from(offset).map_err(|_| IoError::Rejected)?;
            let end = start.checked_add(input.len()).ok_or(IoError::Rejected)?;
            let mut bytes = self.bytes.borrow_mut();
            bytes
                .get_mut(start..end)
                .ok_or(IoError::Rejected)?
                .copy_from_slice(input);
            self.len.set(self.len.get().max(end));
            Ok(())
        }
    }
    fn ready<F: Future>(future: F) -> F::Output {
        match core::pin::pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("bounded storage effect unexpectedly suspended"),
        }
    }
    #[test]
    fn request_storage_advances_only_when_stream_is_assigned() {
        let guard = actor_test_allocator::NoAlloc::start();
        let mut requests = Requests::new(&["/a", "/b"]);
        let mut out = [0; 16];
        assert_eq!(ready(requests.next(&mut out)), Ok(Some(8)));
        assert_eq!(&out[..8], b"GET /a\r\n");
        assert_eq!(ready(requests.next(&mut out[..1])), Err(()));
        assert_eq!(ready(requests.next(&mut out)), Ok(Some(8)));
        assert_eq!(&out[..8], b"GET /a\r\n");
        requests.started(0).unwrap();
        assert_eq!(ready(requests.next(&mut out)), Ok(Some(8)));
        assert_eq!(&out[..8], b"GET /b\r\n");
        requests.started(4).unwrap();
        assert_eq!(ready(requests.next(&mut out)), Ok(None));
        assert_eq!(requests.started(8), Err(()));
        guard.finish();
    }
    #[test]
    fn bounded_response_failure_does_not_advance_storage_accounting() {
        let guard = actor_test_allocator::NoAlloc::start();
        let store = Store::new();
        let mut response = Response::new(&store).unwrap();
        let mut cx = Context::from_waker(Waker::noop());
        assert_eq!(
            response.poll_write(4, b"wrong stream", &mut cx),
            Poll::Ready(Err(()))
        );
        assert_eq!(
            response.poll_write(0, b"hello", &mut cx),
            Poll::Ready(Ok(5))
        );
        assert_eq!(
            response.poll_write(0, &[0; 16], &mut cx),
            Poll::Ready(Err(()))
        );
        assert_eq!(response.bytes_written(), 5);
        assert_eq!(ready(response.finish(0)), Ok(()));
        assert_eq!(store.len(), Ok(5));
        assert_eq!(&store.bytes.borrow()[..5], b"hello");
        guard.finish();
    }
    #[test]
    fn service_borrows_target_and_transfers_real_body_store() {
        let guard = actor_test_allocator::NoAlloc::start();
        let mut service = Service::new(|target: &str| {
            if target != "/hello" {
                return Err(());
            }
            let store = Store::new();
            store.write_all_at(b"hello", 0).map_err(|_| ())?;
            Ok(store)
        });
        assert!(ready(service.open(0, b"GET /missing\r\n")).is_err());
        assert!(ready(service.open(0, b"GET /hello HTTP/1.1\r\n")).is_err());
        let mut body = ready(service.open(0, b"GET /hello\r\n")).unwrap();
        let mut out = [0; 3];
        assert_eq!(ready(body.read(&mut out)), Ok(3));
        assert_eq!(&out, b"hel");
        assert_eq!(ready(body.read(&mut out)), Ok(2));
        assert_eq!(&out[..2], b"lo");
        assert_eq!(ready(body.read(&mut out)), Ok(0));
        guard.finish();
    }
}
