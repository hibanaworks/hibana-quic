//! Implement a borrowed response body and handler for the QUIC application roles.
//! Run: cargo run --example response_body
//! This demonstrates application effects; use http3-transfer.sh for real UDP/TLS.
use hibana_quic::quic::application::{BodyReader, ServerHandler};
use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};

struct Body(&'static [u8]);
impl BodyReader for Body {
    async fn read(&mut self, output: &mut [u8]) -> Result<usize, ()> {
        let n = self.0.len().min(output.len());
        output[..n].copy_from_slice(&self.0[..n]);
        self.0 = &self.0[n..];
        Ok(n)
    }
}
struct Hello;
impl ServerHandler for Hello {
    type Body = Body;
    async fn open(&mut self, _stream: u64, request: &[u8]) -> Result<Body, ()> {
        match request {
            b"GET /hello\r\n" => Ok(Body(b"hello from Hibana\n")),
            _ => Err(()),
        }
    }
}
fn main() {
    // These two synchronous effects cannot return Pending. A network program
    // passes the handler to application::server and uses the Host reactor.
    let mut handler = Hello;
    let mut cx = Context::from_waker(Waker::noop());
    let Poll::Ready(Ok(mut body)) = pin!(handler.open(0, b"GET /hello\r\n")).poll(&mut cx) else {
        panic!("the local handler must complete immediately");
    };
    let mut buffer = [0; 64];
    let Poll::Ready(Ok(n)) = pin!(body.read(&mut buffer)).poll(&mut cx) else {
        panic!("the borrowed body must complete immediately");
    };
    assert_eq!(&buffer[..n], b"hello from Hibana\n");
    print!("{}", std::str::from_utf8(&buffer[..n]).unwrap());
}
