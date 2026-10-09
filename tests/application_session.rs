//! The same projected endpoint executes with an executor-neutral stream driver.
use core::{
    future::{Future, poll_fn},
    pin::pin,
    task::{Context, Poll, Waker},
};
use hibana::{Endpoint, g, runtime::ids::SessionId};
use hibana_quic::{
    quic::application::{BodyReader, ClientRequests, ServerHandler, StreamSink},
    runtime::join2,
    session::{self, Protocol, local::stream},
};

const CLIENT: u8 = 0;
const SERVER: u8 = 1;
type Value = g::Msg<0, u64>;
type Answer = g::Msg<1, u64>;
type Exchange = g::Seq<g::Send<CLIENT, SERVER, Value>, g::Send<SERVER, CLIENT, Answer>>;
fn global() -> g::Program<g::Seq<Exchange, Exchange>> {
    g::seq(
        g::seq(
            g::send::<CLIENT, SERVER, Value>(),
            g::send::<SERVER, CLIENT, Answer>(),
        ),
        g::seq(
            g::send::<CLIENT, SERVER, Value>(),
            g::send::<SERVER, CLIENT, Answer>(),
        ),
    )
}
fn drive(
    future: impl Future<Output = Result<(), session::Error<()>>>,
) -> Result<(), session::Error<()>> {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..10000 {
        if let Poll::Ready(result) = future.as_mut().poll(&mut cx) {
            return result;
        }
    }
    panic!("joined application did not complete");
}
async fn client(endpoint: &mut Endpoint<'_, CLIENT>) -> Result<(), ()> {
    for n in [42_u64, 7] {
        endpoint.send::<Value>(&n).await.map_err(|_| ())?;
        assert_eq!(endpoint.recv::<Answer>().await.map_err(|_| ())?, n * n);
    }
    Ok(())
}
#[test]
fn projected_endpoint_rejects_reply_injected_on_the_outbound_route() {
    let mut storage = session::Storage::new();
    let mut slab = [0; 65536];
    let program = hibana::runtime::program::project::<CLIENT, _>(&global());
    let result = drive(session::local::run(
        &mut storage,
        &mut slab,
        SessionId::new(9),
        SERVER,
        &program,
        client,
        async |peer| {
            for n in [42_u64, 7] {
                let frame = poll_fn(|cx| peer.poll_outgoing(cx))
                    .await
                    .map_err(|_| ())?
                    .ok_or(())?;
                assert_eq!(frame.payload(), n.to_be_bytes());
                // Reusing the sent frame route cannot manufacture the projected return edge.
                let mut header = frame.header();
                header[5] = SERVER;
                header[6] = CLIENT;
                header[7] = 1;
                peer.incoming(header, &(n * n).to_be_bytes())
                    .map_err(|_| ())?;
            }
            assert!(
                poll_fn(|cx| peer.poll_outgoing(cx))
                    .await
                    .map_err(|_| ())?
                    .is_none()
            );
            Ok(())
        },
    ));
    assert!(matches!(result, Err(session::Error::Local(()))));
}

#[test]
fn raw_and_http3_streams_carry_multiple_messages_with_single_byte_fragments() {
    for protocol in [Protocol::Quic, Protocol::Http3] {
        let mut storage = session::Storage::new();
        let mut slab = [0; 65536];
        let program = hibana::runtime::program::project::<CLIENT, _>(&global());
        drive(session::local::run(
            &mut storage,
            &mut slab,
            SessionId::new(9),
            SERVER,
            &program,
            client,
            async |peer| {
                // The remote side has its own runtime and the very same global.
                let mut remote = session::Storage::new();
                let mut remote_slab = [0; 65536];
                let remote_program = hibana::runtime::program::project::<SERVER, _>(&global());
                session::local::run(
                    &mut remote,
                    &mut remote_slab,
                    SessionId::new(9),
                    CLIENT,
                    &remote_program,
                    async |endpoint| {
                        for _ in 0..2 {
                            let n = endpoint.recv::<Value>().await.map_err(|_| ())?;
                            endpoint.send::<Answer>(&(n * n)).await.map_err(|_| ())?;
                        }
                        Ok(())
                    },
                    async |remote_peer| {
                        let mut request =
                            stream::Requests::new(peer, protocol, "localhost").map_err(|_| ())?;
                        let mut input = stream::Input::new(remote_peer, protocol, true);
                        let mut service = stream::Service {
                            peer: remote_peer,
                            protocol,
                        };
                        let mut response = service.open(0, &[]).await?;
                        let mut output = stream::Input::new(peer, protocol, false);
                        join2(
                            async {
                                let mut prefix = [0; 1024];
                                let n = request.next(&mut prefix).await?.ok_or(())?;
                                for byte in &prefix[..n] {
                                    input.write(0, core::slice::from_ref(byte)).await?;
                                }
                                loop {
                                    let mut byte = [0; 1];
                                    let n = request.body(0, &mut byte).await?;
                                    if n == 0 {
                                        break;
                                    }
                                    input.write(0, &byte[..n]).await?;
                                }
                                input.finish(0).await?;
                                assert_eq!(request.next(&mut prefix).await?, None);
                                Ok(())
                            },
                            async {
                                loop {
                                    let mut byte = [0; 1];
                                    let n = response.read(&mut byte).await?;
                                    if n == 0 {
                                        break;
                                    }
                                    output.write(0, &byte[..n]).await?;
                                }
                                output.finish(0).await
                            },
                        )
                        .await
                    },
                )
                .await
                .map_err(|_| ())
            },
        ))
        .unwrap();
    }
}

#[test]
fn framed_input_rejects_truncated_wrong_peer_and_oversized_messages() {
    use hibana_quic::runtime::carrier::CarrierStorage;
    for protocol in [Protocol::Quic, Protocol::Http3] {
        for malformed in 0..4 {
            let carrier = CarrierStorage::<4, 256, 8>::new();
            let binding = carrier.bind(SessionId::new(9)).unwrap();
            let peer = carrier.peer(CLIENT, SERVER).unwrap();
            let mut input = stream::Input::new(&peer, protocol, false);
            let future = async {
                let prefix: &[u8] = match protocol {
                    Protocol::Quic => b"HBN1",
                    Protocol::Http3 => &[1, 3, 0, 0, 0xd9],
                };
                input.write(0, prefix).await?;
                match malformed {
                    0 => {
                        input.write(0, &[0]).await?;
                        input.finish(0).await
                    }
                    1 => input.write(4, &[0]).await,
                    2 => {
                        let raw = [0, 0, 0, 8, 0, 0, 0, 9, 0, 2, CLIENT, 1];
                        let framed = [0, 12, 0, 0, 0, 8, 0, 0, 0, 9, 0, 2, CLIENT, 1];
                        input
                            .write(
                                0,
                                match protocol {
                                    Protocol::Quic => &raw,
                                    Protocol::Http3 => &framed,
                                },
                            )
                            .await
                    }
                    _ => {
                        let raw = [0, 0, 1, 9];
                        let framed = [0, 4, 0, 0, 1, 9];
                        input
                            .write(
                                0,
                                match protocol {
                                    Protocol::Quic => &raw,
                                    Protocol::Http3 => &framed,
                                },
                            )
                            .await
                    }
                }
            };
            let mut future = pin!(future);
            assert!(matches!(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Err(()))
            ));
            assert_eq!(carrier.queued(), 0);
            drop(binding);
        }
    }
}
