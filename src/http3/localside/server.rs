//! One native HTTP/3 exchange: reader, application and writer share one global.
use crate::{
    entropy::Entropy,
    http3::{
        Settings,
        message::{self, Exchange},
    },
    io::{Clock, DatagramSocket},
    quic::application::{self, ServerHandler},
    runtime::{
        byte_pipe::{BytePipe, Reader},
        carrier::CarrierStorage,
        mailbox::Mailbox,
    },
    session,
};
use hibana::{
    Endpoint,
    runtime::{
        SessionKitStorage,
        ids::SessionId,
        program::{Projectable, project},
    },
};

pub const READ: u8 = 0;
pub const APP: u8 = 1;
pub const WRITE: u8 = 2;

use crate::http3::Storage;

#[derive(Debug)]
pub enum Error {
    Message(message::Error),
    Network(application::Error),
    Incomplete,
}
impl From<message::Error> for Error {
    fn from(error: message::Error) -> Self {
        Self::Message(error)
    }
}

struct Service<'pipe, 'storage, Start> {
    start: Option<Start>,
    settings: Option<Settings>,
    body: Option<Reader<'pipe, 'storage>>,
}
impl<'pipe, 'storage, Start> ServerHandler for Service<'pipe, 'storage, Start>
where
    Start: AsyncFnOnce(Settings) -> Result<(), application::Error>,
{
    type Body = Reader<'pipe, 'storage>;
    fn request_limit(&self) -> Option<core::num::NonZeroUsize> {
        core::num::NonZeroUsize::new(1)
    }
    fn peer_settings(&mut self, settings: Settings) -> Result<(), application::Error> {
        if self.settings.replace(settings).is_some() {
            return Err(application::Error::Binding);
        }
        Ok(())
    }
    async fn connected(
        &mut self,
        protocol: crate::http3::Protocol,
    ) -> Result<(), application::Error> {
        if protocol != crate::http3::Protocol::Http3 {
            return Err(application::Error::Binding);
        }
        let start = self.start.take().ok_or(application::Error::Binding)?;
        start(self.settings.take().ok_or(application::Error::Binding)?).await
    }
    async fn open(&mut self, stream: u64, prefix: &[u8]) -> Result<Self::Body, ()> {
        if stream != 0 || !prefix.is_empty() {
            return Err(());
        }
        self.body.take().ok_or(())
    }
}

/// Attach the supplied graph and admit its endpoints only after TLS and SETTINGS.
/// This entry serves one bidirectional request stream. Existing End/Done effects
/// complete its HTTP fragments; the network result also requires connection close.
#[allow(clippy::too_many_arguments)]
pub async fn run<const S: usize, const C: usize, const B: usize, const H: usize>(
    config: session::ServerConfig<'_>,
    connection: &mut session::ConnectionMemory<S, C>,
    environment: session::Environment<'_, impl DatagramSocket, impl Clock, impl Entropy>,
    slab: &mut [u8],
    global: &impl Projectable,
    storage: &mut Storage<B, H>,
    application: impl for<'a, 'r, 'exchange, 'storage> AsyncFnOnce(
        &'a mut Endpoint<'r, APP>,
        &'exchange Exchange<'storage>,
        &'exchange Exchange<'storage>,
    ) -> message::Result<()>,
) -> Result<(), Error> {
    if config.protocol != crate::http3::Protocol::Http3 {
        return Err(Error::Network(application::Error::Binding));
    }
    let input = BytePipe::new(&mut storage.input)
        .map_err(|_| message::Error::Invalid("empty HTTP input storage"))?;
    let output = BytePipe::new(&mut storage.output)
        .map_err(|_| message::Error::Invalid("empty HTTP output storage"))?;
    let (input_writer, mut input_reader) = input
        .split()
        .map_err(|_| message::Error::Invalid("HTTP input already split"))?;
    let (mut output_writer, output_reader) = output
        .split()
        .map_err(|_| message::Error::Invalid("HTTP output already split"))?;
    let request = Exchange::new(&mut storage.request_body, &mut storage.request_headers);
    let response = Exchange::new(&mut storage.response_body, &mut storage.response_headers);
    let programs = (
        project::<READ>(global),
        project::<APP>(global),
        project::<WRITE>(global),
    );
    let carrier = CarrierStorage::<4, 16, 128>::new();
    let sid = SessionId::new(1);
    let mut kit = SessionKitStorage::uninit();
    let rendezvous = kit
        .init()
        .rendezvous(slab, carrier.bind(sid).map_err(message::Error::from)?)
        .map_err(message::Error::from)?;
    let endpoints = (
        rendezvous
            .enter(sid, &programs.0)
            .map_err(message::Error::from)?,
        rendezvous
            .enter(sid, &programs.1)
            .map_err(message::Error::from)?,
        rendezvous
            .enter(sid, &programs.2)
            .map_err(message::Error::from)?,
    );
    let mut slots = [None];
    let admission = Mailbox::new(&mut slots).expect("one empty slot");
    let (mut sender, mut receiver) = admission.split().expect("unique halves");
    let start = async move |settings| {
        sender
            .send((endpoints, settings))
            .await
            .map_err(|_| application::Error::Binding)
    };
    let mut service = Service {
        start: Some(start),
        settings: None,
        body: Some(output_reader),
    };
    let mut incoming = crate::http3::imp::stream::Incoming {
        writer: input_writer,
        stream: 0,
    };
    let locals = async {
        let ((mut reader, mut app, mut writer), settings): (_, Settings) =
            receiver.recv().await.map_err(|_| Error::Incomplete)?;
        execute(
            &mut reader,
            &mut app,
            &mut writer,
            &mut input_reader,
            &mut output_writer,
            &request,
            &response,
            settings,
            application,
        )
        .await?;
        Ok::<_, Error>((reader, app, writer))
    };
    let (endpoints, ()) = crate::runtime::join::values2(
        core::pin::pin!(locals),
        core::pin::pin!(async {
            let report = core::pin::pin!(config.accept(
                connection,
                environment,
                &mut service,
                Some(&mut incoming)
            ))
            .await
            .map_err(Error::Network)?;
            if report.termination != application::Termination::Closed || !report.close_completed {
                return Err(Error::Incomplete);
            }
            Ok(())
        }),
    )
    .await?;
    drop(endpoints);
    Ok(())
}

/// Drives the three admitted locals. Endpoints stay owned by the caller until
/// the network has consumed the final output and completed connection close.
#[allow(clippy::too_many_arguments)]
pub async fn execute<'buffers>(
    reader: &mut Endpoint<'_, READ>,
    app: &mut Endpoint<'_, APP>,
    writer: &mut Endpoint<'_, WRITE>,
    input: &mut impl application::BodyReader,
    output: &mut impl message::localside::writer::BodyWriter,
    request: &Exchange<'buffers>,
    response: &Exchange<'buffers>,
    settings: Settings,
    application: impl for<'a, 'r, 'exchange, 'storage> AsyncFnOnce(
        &'a mut Endpoint<'r, APP>,
        &'exchange Exchange<'storage>,
        &'exchange Exchange<'storage>,
    ) -> message::Result<()>,
) -> Result<(), Error> {
    crate::runtime::join::values3(
        async {
            message::localside::reader::server(reader, input, request)
                .await
                .map_err(Error::from)
        },
        async {
            application(app, request, response)
                .await
                .map_err(Error::from)
        },
        async {
            message::localside::writer::server(
                writer,
                output,
                settings.max_field_section_size,
                response,
            )
            .await
            .map_err(Error::from)
        },
    )
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::{
        future::{Future, pending},
        pin::pin,
        task::{Context, Poll, Waker},
    };
    struct Parked;
    impl application::BodyReader for Parked {
        async fn read(&mut self, _: &mut [u8]) -> Result<usize, ()> {
            pending().await
        }
    }
    struct Output;
    impl message::localside::writer::BodyWriter for Output {
        async fn write(&mut self, _: &[u8]) -> Result<(), ()> {
            pending().await
        }
        async fn finish(&mut self) -> Result<(), ()> {
            panic!("incomplete application cannot finish output")
        }
    }
    #[test]
    fn incomplete_application_waits_for_network_failure() {
        let graph = message::global::server::<READ, APP, WRITE>();
        let programs = (
            project::<READ>(&graph),
            project::<APP>(&graph),
            project::<WRITE>(&graph),
        );
        let carrier = CarrierStorage::<4, 16, 128>::new();
        let mut slab = [0; 65536];
        let sid = SessionId::new(91);
        let mut kit = SessionKitStorage::uninit();
        let rendezvous = kit
            .init()
            .rendezvous(&mut slab, carrier.bind(sid).unwrap())
            .unwrap();
        let (mut reader, mut app, mut writer) = (
            rendezvous.enter(sid, &programs.0).unwrap(),
            rendezvous.enter(sid, &programs.1).unwrap(),
            rendezvous.enter(sid, &programs.2).unwrap(),
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
            &mut app,
            &mut writer,
            &mut input,
            &mut output,
            &request,
            &response,
            crate::http3::decode_settings(&[]).unwrap(),
            async |_, _, _| Ok(())
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
    fn buffered_headers_without_stream_fin_never_complete_the_exchange() {
        struct Input<'a>(&'a [u8]);
        impl application::BodyReader for Input<'_> {
            async fn read(&mut self, out: &mut [u8]) -> Result<usize, ()> {
                if self.0.is_empty() {
                    return pending().await;
                }
                let n = out.len().min(self.0.len());
                out[..n].copy_from_slice(&self.0[..n]);
                self.0 = &self.0[n..];
                Ok(n)
            }
        }
        struct Sink<'a>(&'a core::cell::Cell<bool>);
        impl message::localside::writer::BodyWriter for Sink<'_> {
            async fn write(&mut self, _: &[u8]) -> Result<(), ()> {
                Ok(())
            }
            async fn finish(&mut self) -> Result<(), ()> {
                self.0.set(true);
                Ok(())
            }
        }
        let mut encoded = [0; 256];
        let n = crate::http3::encode_fields(
            [
                (b":method".as_slice(), b"POST".as_slice()),
                (b":scheme".as_slice(), b"https".as_slice()),
                (b":authority".as_slice(), b"localhost".as_slice()),
                (b":path".as_slice(), b"/echo".as_slice()),
            ],
            &mut encoded,
        )
        .unwrap();
        let mut wire = [0; 272];
        let prefix = crate::http3::frame_header(1, n as u64, &mut wire).unwrap();
        wire[prefix..prefix + n].copy_from_slice(&encoded[..n]);
        let mut input = Input(&wire[..prefix + n]);
        let finished = core::cell::Cell::new(false);
        let mut output = Sink(&finished);
        let graph = message::global::server::<READ, APP, WRITE>();
        let programs = (
            project::<READ>(&graph),
            project::<APP>(&graph),
            project::<WRITE>(&graph),
        );
        let carrier = CarrierStorage::<4, 16, 128>::new();
        let mut slab = [0; 65536];
        let sid = SessionId::new(92);
        let mut kit = SessionKitStorage::uninit();
        let rendezvous = kit
            .init()
            .rendezvous(&mut slab, carrier.bind(sid).unwrap())
            .unwrap();
        let (mut reader, mut app, mut writer) = (
            rendezvous.enter(sid, &programs.0).unwrap(),
            rendezvous.enter(sid, &programs.1).unwrap(),
            rendezvous.enter(sid, &programs.2).unwrap(),
        );
        let (mut rb, mut wb, mut rh, mut wh) = ([0; 2], [0; 2], [0; 256], [0; 256]);
        let request = Exchange::new(&mut rb, &mut rh);
        let response = Exchange::new(&mut wb, &mut wh);
        {
            let mut run = pin!(execute(
                &mut reader,
                &mut app,
                &mut writer,
                &mut input,
                &mut output,
                &request,
                &response,
                crate::http3::decode_settings(&[]).unwrap(),
                async |app, request, response| {
                    let mut request = message::localside::request::Request::new(request);
                    let mut response = message::localside::producer::Response::new(response);
                    request.headers(app).await?.release(app).await?;
                    response.headers(app, 200, &[]).await?;
                    assert!(request.chunk(app).await?.is_none());
                    request.trailers(app, |_| Ok(())).await?;
                    request.finish(app).await?;
                    response.finish(app).await
                }
            ));
            let mut cx = Context::from_waker(Waker::noop());
            for _ in 0..64 {
                assert!(run.as_mut().poll(&mut cx).is_pending());
            }
            assert!(!finished.get());
        }
        // Aggregate cancellation releases every pending field/body borrow.
        assert!(request.headers.try_borrow_mut().is_ok());
        assert!(response.headers.try_borrow_mut().is_ok());
        assert!(request.bytes.try_borrow_mut().is_ok());
        assert!(response.bytes.try_borrow_mut().is_ok());
        assert!(!finished.get());
    }
}
