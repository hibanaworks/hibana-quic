use super::*;
use core::{
    cell::Cell,
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};

fn ready<T>(future: impl Future<Output = T>) -> T {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("operation unexpectedly parked"),
    }
}
fn settings() -> Settings {
    Settings {
        max_field_section_size: 1234,
        qpack_max_table_capacity: 0,
        qpack_blocked_streams: 0,
    }
}

#[test]
fn startup_requires_actual_settings_and_authenticated_admission() {
    let calls = Cell::new(0);
    let start = async |actual| {
        assert_eq!(actual, settings());
        calls.set(calls.get() + 1);
        Ok(())
    };
    let mut bytes = [0; 4];
    let pipe = BytePipe::new(&mut bytes).unwrap();
    let (_writer, reader) = pipe.split().unwrap();
    let mut requests = Requests {
        start: Some(start),
        settings: None,
        pending: Some(Pending {
            body: reader,
            prefix: None,
        }),
        body: None,
    };
    assert!(ready(requests.next(&mut [0])).is_err());
    assert!(requests.started(0).is_err());
    assert!(ready(requests.body(0, &mut [0])).is_err());
    requests.peer_settings(settings()).unwrap();
    ready(requests.connected(crate::http3::Protocol::Http3)).unwrap();
    assert_eq!(calls.get(), 1);
    assert!(ready(requests.connected(crate::http3::Protocol::Http3)).is_err());
    assert_eq!(calls.get(), 1);
}

#[test]
fn next_retains_exact_pending_prefix_until_one_successful_started() {
    let mut bytes = [0; 4];
    let pipe = BytePipe::new(&mut bytes).unwrap();
    let (mut writer, reader) = pipe.split().unwrap();
    let start = async |_: Settings| Ok::<(), application::Error>(());
    let mut requests = Requests {
        start: Some(start),
        settings: Some(settings()),
        pending: Some(Pending {
            body: reader,
            prefix: None,
        }),
        body: None,
    };
    ready(requests.connected(crate::http3::Protocol::Http3)).unwrap();
    assert_eq!(ready(writer.write(&[1, 2, 3])), Ok(3));
    writer.finish().unwrap();
    assert!(ready(requests.next(&mut [])).is_err());
    let mut prefix = [0; 2];
    assert_eq!(ready(requests.next(&mut prefix)), Ok(Some(1)));
    assert_eq!(prefix, [1, 0]);
    assert_eq!(pipe.len(), 2);
    prefix.fill(0);
    assert_eq!(ready(requests.next(&mut prefix)), Ok(Some(1)));
    assert_eq!(prefix, [1, 0]);
    assert_eq!(pipe.len(), 2);
    assert!(requests.started(4).is_err());
    assert_eq!(ready(requests.next(&mut prefix)), Ok(Some(1)));
    requests.started(0).unwrap();
    assert!(requests.started(0).is_err());
    assert_eq!(ready(requests.next(&mut prefix)), Ok(None));
    assert!(ready(requests.body(4, &mut prefix)).is_err());
    assert_eq!(ready(requests.body(0, &mut prefix)), Ok(2));
    assert_eq!(prefix, [2, 3]);
    assert_eq!(ready(requests.body(0, &mut prefix)), Ok(0));
}

#[test]
fn pending_prefix_cancellation_never_loses_or_repeats_a_byte() {
    let mut bytes = [0; 4];
    let pipe = BytePipe::new(&mut bytes).unwrap();
    let (mut writer, reader) = pipe.split().unwrap();
    let start = async |_: Settings| Ok::<(), application::Error>(());
    let mut requests = Requests {
        start: Some(start),
        settings: Some(settings()),
        pending: Some(Pending {
            body: reader,
            prefix: None,
        }),
        body: None,
    };
    ready(requests.connected(crate::http3::Protocol::Http3)).unwrap();
    let mut output = [0; 4];
    {
        let mut next = pin!(requests.next(&mut output));
        assert!(
            next.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    }
    assert!(requests.started(0).is_err());
    assert_eq!(ready(writer.write(b"abc")), Ok(3));
    assert_eq!(ready(requests.next(&mut output)), Ok(Some(1)));
    assert_eq!(output[0], b'a');
    requests.started(0).unwrap();
    assert_eq!(ready(requests.body(0, &mut output)), Ok(2));
    assert_eq!(&output[..2], b"bc");
    drop(writer);
    // Unfinished producer cancellation cannot become a successful request FIN.
    assert!(ready(requests.body(0, &mut output)).is_err());
}

#[test]
fn cancelling_request_owner_releases_pipe_and_wakes_its_producer() {
    let mut bytes = [0; 1];
    let pipe = BytePipe::new(&mut bytes).unwrap();
    let (mut writer, reader) = pipe.split().unwrap();
    let start = async |_: Settings| Ok::<(), application::Error>(());
    let requests = Requests {
        start: Some(start),
        settings: None,
        pending: Some(Pending {
            body: reader,
            prefix: None,
        }),
        body: None,
    };
    assert_eq!(ready(writer.write(b"a")), Ok(1));
    let mut blocked = pin!(writer.write(b"b"));
    assert!(
        blocked
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    drop(requests);
    assert_eq!(
        blocked
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Err(crate::runtime::byte_pipe::Error::Cancelled))
    );
}

struct Parked;
impl application::BodyReader for Parked {
    async fn read(&mut self, _: &mut [u8]) -> Result<usize, ()> {
        core::future::pending().await
    }
}
struct Output;
impl message::localside::writer::BodyWriter for Output {
    async fn write(&mut self, _: &[u8]) -> Result<(), ()> {
        core::future::pending().await
    }
    async fn finish(&mut self) -> Result<(), ()> {
        panic!("incomplete application cannot finish output")
    }
}
fn unfinished_application(early_upload: bool) {
    let graph = message::global::client::<UPLOAD, WRITE, READ, DOWNLOAD>();
    let programs = (
        project::<READ>(&graph),
        project::<UPLOAD>(&graph),
        project::<WRITE>(&graph),
        project::<DOWNLOAD>(&graph),
    );
    let carrier = CarrierStorage::<4, 16, 128>::new();
    let mut slab = [0; 65536];
    let sid = SessionId::new(92);
    let carrier_binding = carrier.bind(sid, &[]).unwrap();
    let mut kit = SessionKitStorage::uninit();
    let rendezvous = kit.init().rendezvous(&mut slab, &carrier_binding).unwrap();
    let (mut reader, mut up, mut writer, mut down) = (
        rendezvous.enter(sid, &programs.0).unwrap(),
        rendezvous.enter(sid, &programs.1).unwrap(),
        rendezvous.enter(sid, &programs.2).unwrap(),
        rendezvous.enter(sid, &programs.3).unwrap(),
    );
    let mut request_bytes = [0; 2];
    let mut response_bytes = [0; 2];
    let mut request_headers = [0; 256];
    let mut response_headers = [0; 256];
    let request = Exchange::new(&mut request_bytes, &mut request_headers);
    let response = Exchange::new(&mut response_bytes, &mut response_headers);
    let mut input = Parked;
    let mut output = Output;
    let mut run = pin!(execute(
        &mut reader,
        &mut up,
        &mut writer,
        &mut down,
        &mut input,
        &mut output,
        &request,
        &response,
        settings(),
        async |_, _| {
            if early_upload {
                Ok(())
            } else {
                core::future::pending().await
            }
        },
        async |_, _| {
            if early_upload {
                core::future::pending().await
            } else {
                Ok(())
            }
        },
    ));
    let mut context = Context::from_waker(Waker::noop());
    assert!(run.as_mut().poll(&mut context).is_pending());
    // The omitted projected terminal action is still pending. This fixture injects
    // a network failure to test aggregate cancellation, not clock expiry.
    let mut joined = pin!(crate::runtime::join::values2(run, async {
        Err::<(), _>(Error::Network(application::Error::Incomplete))
    },));
    assert!(matches!(
        joined.as_mut().poll(&mut context),
        Poll::Ready(Err(Error::Network(application::Error::Incomplete)))
    ));
}

#[test]
fn unfinished_upload_is_cancelled_by_network_failure() {
    unfinished_application(true);
}
#[test]
fn unfinished_download_is_cancelled_by_network_failure() {
    unfinished_application(false);
}
