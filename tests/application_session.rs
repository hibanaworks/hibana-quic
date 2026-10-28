//! Raw QUIC application endpoints execute with an executor-neutral stream driver.
use core::{
    future::{Future, poll_fn},
    pin::pin,
    task::{Context, Poll, Waker},
};
use hibana::runtime::program::Projectable;
use hibana::{Endpoint, g, runtime::ids::SessionId};
use hibana_quic::{
    quic::application::{BodyReader, ClientRequests, ServerHandler, StreamSink},
    runtime::join2,
    session::{self, Protocol, stream},
};

#[global_allocator]
static ALLOCATOR: actor_test_allocator::Counting = actor_test_allocator::Counting;

const CLIENT: u8 = 0;
const SERVER: u8 = 1;
type Value = g::Msg<0, u64>;
type Answer = g::Msg<1, u64>;
fn global() -> impl Projectable {
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
    let program = hibana::runtime::program::project::<CLIENT>(&global());
    let result = drive(session::localside::run(
        &mut storage,
        &mut slab,
        SessionId::new(9),
        SERVER,
        &program,
        client,
        async |peer, admission| {
            admission.open().await.map_err(|_| ())?;
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
                header[7..9].copy_from_slice(&1_u16.to_be_bytes());
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
fn raw_streams_carry_multiple_messages_with_single_byte_fragments() {
    let guard = actor_test_allocator::NoAlloc::start();
    {
        let mut storage = session::Storage::new();
        let mut slab = [0; 65536];
        let program = hibana::runtime::program::project::<CLIENT>(&global());
        drive(session::localside::run(
            &mut storage,
            &mut slab,
            SessionId::new(9),
            SERVER,
            &program,
            client,
            async |peer, admission| {
                admission.open().await.map_err(|_| ())?;
                // The remote side has its own runtime and the very same global.
                let mut remote = session::Storage::new();
                let mut remote_slab = [0; 65536];
                let remote_program = hibana::runtime::program::project::<SERVER>(&global());
                session::localside::run(
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
                    async |remote_peer, admission| {
                        admission.open().await.map_err(|_| ())?;
                        let mut request = stream::Requests::new(peer, async |_| Ok(()));
                        let mut input = stream::Input::new(remote_peer);
                        let mut service = stream::Service {
                            start: Some(async |_| Ok(())),
                            peer: remote_peer,
                        };
                        let mut response = service.open(0, &[]).await?;
                        let mut output = stream::Input::new(peer);
                        join2(
                            async {
                                let mut prefix = [0; 1024];
                                let n = request.next(&mut prefix).await?.ok_or(())?;
                                for byte in &prefix[..n] {
                                    async {
                                        let bytes: &[u8] = core::slice::from_ref(byte);
                                        let n =
                                            poll_fn(|cx| input.poll_write(0, bytes, cx)).await?;
                                        assert_eq!(n, bytes.len());
                                        input.flush(0).await
                                    }
                                    .await?;
                                }
                                request.started(0)?;
                                loop {
                                    let mut byte = [0; 1];
                                    let n = request.body(0, &mut byte).await?;
                                    if n == 0 {
                                        break;
                                    }
                                    async {
                                        let bytes: &[u8] = &byte[..n];
                                        let n =
                                            poll_fn(|cx| input.poll_write(0, bytes, cx)).await?;
                                        assert_eq!(n, bytes.len());
                                        input.flush(0).await
                                    }
                                    .await?;
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
                                    async {
                                        let bytes: &[u8] = &byte[..n];
                                        let n =
                                            poll_fn(|cx| output.poll_write(0, bytes, cx)).await?;
                                        assert_eq!(n, bytes.len());
                                        output.flush(0).await
                                    }
                                    .await?;
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
    guard.finish();
}

#[test]
fn raw_input_rejects_truncated_wrong_peer_and_oversized_messages() {
    use hibana_quic::runtime::carrier::CarrierStorage;
    {
        for malformed in 0..4 {
            let carrier = CarrierStorage::<4, 256, 8>::new();
            let binding = carrier.bind(SessionId::new(9), &[]).unwrap();
            let peer = carrier.peer(CLIENT, SERVER).unwrap();
            let mut input = stream::Input::new(&peer);
            let future = async {
                let prefix: &[u8] = b"HBN2";
                async {
                    let bytes: &[u8] = prefix;
                    let n = poll_fn(|cx| input.poll_write(0, bytes, cx)).await?;
                    assert_eq!(n, bytes.len());
                    input.flush(0).await
                }
                .await?;
                match malformed {
                    0 => {
                        async {
                            let bytes: &[u8] = &[0];
                            let n = poll_fn(|cx| input.poll_write(0, bytes, cx)).await?;
                            assert_eq!(n, bytes.len());
                            input.flush(0).await
                        }
                        .await?;
                        input.finish(0).await
                    }
                    1 => {
                        async {
                            let bytes: &[u8] = &[0];
                            let n = poll_fn(|cx| input.poll_write(4, bytes, cx)).await?;
                            assert_eq!(n, bytes.len());
                            input.flush(4).await
                        }
                        .await
                    }
                    2 => {
                        let raw = [0, 0, 0, 9, 0, 0, 0, 9, 0, 2, CLIENT, 0, 1];
                        async {
                            let bytes: &[u8] = &raw;
                            let n = poll_fn(|cx| input.poll_write(0, bytes, cx)).await?;
                            assert_eq!(n, bytes.len());
                            input.flush(0).await
                        }
                        .await
                    }
                    _ => {
                        let raw = [0, 0, 1, 10];
                        async {
                            let bytes: &[u8] = &raw;
                            let n = poll_fn(|cx| input.poll_write(0, bytes, cx)).await?;
                            assert_eq!(n, bytes.len());
                            input.flush(0).await
                        }
                        .await
                    }
                }
            };
            let mut future = pin!(future);
            assert!(
                matches!(
                    future
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop())),
                    Poll::Ready(Err(()))
                ),
                "malformed case {malformed}"
            );
            assert_eq!(carrier.queued(), 0);
            drop(binding);
        }
    }
}

#[test]
fn raw_adapters_reject_http_settings_and_non_raw_admission() {
    use core::cell::Cell;
    use hibana_quic::{quic::application::Error, runtime::carrier::CarrierStorage};
    for protocol in [
        Protocol::Http3,
        #[cfg(feature = "hq")]
        Protocol::Http09,
    ] {
        let carrier = CarrierStorage::<4, 256, 8>::new();
        let binding = carrier.bind(SessionId::new(10), &[]).unwrap();
        let peer = carrier.peer(CLIENT, SERVER).unwrap();
        let client_calls = Cell::new(0);
        let server_calls = Cell::new(0);
        let mut requests = stream::Requests::new(&peer, async |admitted| {
            assert!(matches!(admitted, Protocol::Raw(_)));
            client_calls.set(client_calls.get() + 1);
            Ok(())
        });
        let mut service = stream::Service {
            start: Some(async |admitted| {
                assert!(matches!(admitted, Protocol::Raw(_)));
                server_calls.set(server_calls.get() + 1);
                Ok(())
            }),
            peer: &peer,
        };
        for max_field_section_size in [0, 512, u64::MAX] {
            let settings = hibana_quic::http3::Settings {
                max_field_section_size,
                qpack_max_table_capacity: 0,
                qpack_blocked_streams: 0,
            };
            assert!(matches!(
                requests.peer_settings(settings),
                Err(Error::Application)
            ));
            assert!(matches!(
                service.peer_settings(settings),
                Err(Error::Application)
            ));
        }
        let mut future = pin!(async {
            assert!(matches!(
                requests.connected(protocol).await,
                Err(Error::Binding)
            ));
            assert!(matches!(
                service.connected(protocol).await,
                Err(Error::Binding)
            ));
            assert_eq!((client_calls.get(), server_calls.get()), (0, 0));
            assert!(requests.connected(Protocol::default()).await.is_ok());
            assert!(service.connected(Protocol::default()).await.is_ok());
            assert_eq!((client_calls.get(), server_calls.get()), (1, 1));
            assert!(matches!(
                requests.connected(Protocol::default()).await,
                Err(Error::Binding)
            ));
            assert!(matches!(
                service.connected(Protocol::default()).await,
                Err(Error::Binding)
            ));
            let mut prefix = [0; 4];
            assert_eq!(requests.next(&mut prefix).await, Ok(Some(4)));
            assert_eq!(&prefix, b"HBN2");
            assert_eq!(requests.started(0), Ok(()));
            assert_eq!(requests.next(&mut prefix).await, Ok(None));
            let mut response = service.open(0, &[]).await.unwrap();
            assert_eq!(response.read(&mut prefix).await, Ok(4));
            assert_eq!(&prefix, b"HBN2");
        });
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
        );
        assert_eq!(carrier.queued(), 0);
        drop(binding);
    }
}

#[test]
fn raw_request_prefix_stays_pending_until_one_successful_start() {
    use hibana_quic::runtime::carrier::CarrierStorage;
    let carrier = CarrierStorage::<4, 256, 8>::new();
    let binding = carrier.bind(SessionId::new(14), &[]).unwrap();
    let peer = carrier.peer(CLIENT, SERVER).unwrap();
    let mut requests = stream::Requests::new(&peer, async |_| Ok(()));
    let guard = actor_test_allocator::NoAlloc::start();
    {
        let mut future = pin!(async {
            let mut prefix = [0; 4];
            assert_eq!(requests.next(&mut prefix[..3]).await, Err(()));
            for _ in 0..3 {
                prefix.fill(0);
                assert_eq!(requests.next(&mut prefix).await, Ok(Some(4)));
                assert_eq!(&prefix, b"HBN2");
            }
            assert_eq!(requests.started(4), Err(()));
            assert_eq!(requests.next(&mut prefix).await, Ok(Some(4)));
            assert_eq!(&prefix, b"HBN2");
            assert_eq!(requests.started(0), Ok(()));
            assert_eq!(requests.next(&mut prefix).await, Ok(None));
            assert_eq!(requests.started(0), Err(()));
            assert_eq!(requests.started(4), Err(()));
            assert_eq!(requests.next(&mut prefix).await, Ok(None));
        });
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
        );
    }
    guard.finish();
    assert_eq!(carrier.queued(), 0);
    drop(binding);
}

#[test]
fn raw_input_rejects_http_headers_instead_of_unwrapping_a_tunnel() {
    use hibana_quic::runtime::carrier::CarrierStorage;
    let carrier = CarrierStorage::<4, 256, 8>::new();
    let binding = carrier.bind(SessionId::new(11), &[]).unwrap();
    let peer = carrier.peer(CLIENT, SERVER).unwrap();
    let mut input = stream::Input::new(&peer);
    // HTTP/3 HEADERS with a static :status 200 field, previously accepted by
    // this adapter as the start of an application-message body tunnel.
    let bytes = [1, 3, 0, 0, 0xd9];
    let mut future = pin!(async {
        assert_eq!(
            poll_fn(|cx| input.poll_write(0, &bytes, cx)).await,
            Ok(bytes.len())
        );
        assert_eq!(input.flush(0).await, Err(()));
        assert_eq!(input.finish(0).await, Err(()));
    });
    assert!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
    );
    assert_eq!(carrier.queued(), 0);
    drop(binding);
}

#[test]
fn connection_failure_never_lends_the_application_endpoint() {
    let mut storage = session::Storage::new();
    let mut slab = [0; 65536];
    let program = hibana::runtime::program::project::<CLIENT>(&global());
    let entered = core::cell::Cell::new(false);
    let result = drive(session::localside::run(
        &mut storage,
        &mut slab,
        SessionId::new(12),
        SERVER,
        &program,
        async |_| {
            entered.set(true);
            Ok(())
        },
        async |_peer, _admission| Err(()),
    ));
    assert!(!entered.get());
    assert!(matches!(result, Err(session::Error::Network(()))));
}

#[test]
fn application_return_does_not_hide_network_failure() {
    let mut storage = session::Storage::new();
    let mut slab = [0; 65536];
    let bare = g::send::<CLIENT, SERVER, Value>();
    let program = hibana::runtime::program::project::<CLIENT>(&bare);
    let entered = core::cell::Cell::new(false);
    let result = drive(session::localside::run(
        &mut storage,
        &mut slab,
        SessionId::new(13),
        SERVER,
        &program,
        async |_| {
            entered.set(true);
            Ok(())
        },
        async |_peer, admission| {
            admission.open().await.map_err(|_| ())?;
            while !entered.get() {
                hibana_quic::runtime::yield_now().await;
            }
            Err(())
        },
    ));
    assert!(entered.get());
    assert!(matches!(result, Err(session::Error::Network(()))));
}
