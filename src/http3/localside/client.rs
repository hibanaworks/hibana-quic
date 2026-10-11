//! One native HTTP/3 exchange with independent upload and download projections.
//! The application supplies the composed global; this binding admits its actual
//! endpoints after TLS and peer SETTINGS, then joins them with the connection.
use crate::{
    entropy::Entropy,
    http3::{
        Settings,
        message::{self, Exchange},
    },
    io::{Clock, DatagramSocket},
    quic::application::{self, ClientRequests},
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
pub const UPLOAD: u8 = 1;
pub const WRITE: u8 = 2;
pub const DOWNLOAD: u8 = 3;

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

/// Owns the actual unsent request and its retained first byte. `next` borrows
/// this pending request; only `started` transfers its body into the open stream.
struct Pending<'pipe, 'storage> {
    body: Reader<'pipe, 'storage>,
    prefix: Option<u8>,
}
struct Requests<'pipe, 'storage, Start> {
    start: Option<Start>,
    settings: Option<Settings>,
    pending: Option<Pending<'pipe, 'storage>>,
    body: Option<Reader<'pipe, 'storage>>,
}
impl<Start> ClientRequests for Requests<'_, '_, Start>
where
    Start: AsyncFnOnce(Settings) -> Result<(), application::Error>,
{
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
    async fn next(&mut self, output: &mut [u8]) -> Result<Option<usize>, ()> {
        if self.start.is_some() {
            return Err(());
        }
        let Some(pending) = self.pending.as_mut() else {
            return Ok(None);
        };
        let output = output.first_mut().ok_or(())?;
        if pending.prefix.is_none() {
            let mut first = [0];
            if pending.body.read(&mut first).await.map_err(|_| ())? != 1 {
                return Err(());
            }
            pending.prefix = Some(first[0]);
        }
        *output = pending.prefix.ok_or(())?;
        Ok(Some(1))
    }
    async fn body(&mut self, stream: u64, output: &mut [u8]) -> Result<usize, ()> {
        if stream != 0 {
            return Err(());
        }
        self.body
            .as_mut()
            .ok_or(())?
            .read(output)
            .await
            .map_err(|_| ())
    }
    fn started(&mut self, stream: u64) -> Result<(), ()> {
        if stream != 0
            || self.body.is_some()
            || self.pending.as_ref().and_then(|p| p.prefix).is_none()
        {
            return Err(());
        }
        self.body = Some(self.pending.take().ok_or(())?.body);
        Ok(())
    }
}

/// Run exactly one ordinary HTTP/3 exchange on request stream zero. Compose
/// [`message::global::client`] with any additional application choreography.
/// Upload and download receive distinct actual endpoints, so either direction
/// can progress while the other is waiting on bounded storage or peer input.
#[allow(clippy::too_many_arguments)]
pub async fn run<const S: usize, const C: usize, const B: usize, const H: usize>(
    config: session::ClientConfig<'_>,
    connection: &mut session::ConnectionMemory<S, C>,
    environment: session::Environment<'_, impl DatagramSocket, impl Clock, impl Entropy>,
    slab: &mut [u8],
    global: &impl Projectable,
    storage: &mut Storage<B, H>,
    upload: impl for<'a, 'r, 'exchange, 'storage> AsyncFnOnce(
        &'a mut Endpoint<'r, UPLOAD>,
        &'exchange Exchange<'storage>,
    ) -> message::Result<()>,
    download: impl for<'a, 'r, 'exchange, 'storage> AsyncFnOnce(
        &'a mut Endpoint<'r, DOWNLOAD>,
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
        project::<UPLOAD>(global),
        project::<WRITE>(global),
        project::<DOWNLOAD>(global),
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
        rendezvous
            .enter(sid, &programs.3)
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
    let mut requests = Requests {
        start: Some(start),
        settings: None,
        pending: Some(Pending {
            body: output_reader,
            prefix: None,
        }),
        body: None,
    };
    let mut incoming = crate::http3::imp::stream::Incoming {
        writer: input_writer,
        stream: 0,
    };
    let locals = async {
        let ((mut reader, mut up, mut writer, mut down), settings): (_, Settings) =
            receiver.recv().await.map_err(|_| Error::Incomplete)?;
        execute(
            &mut reader,
            &mut up,
            &mut writer,
            &mut down,
            &mut input_reader,
            &mut output_writer,
            &request,
            &response,
            settings,
            upload,
            download,
        )
        .await?;
        Ok::<_, Error>((reader, up, writer, down))
    };
    let (endpoints, ()) = crate::runtime::join::values2(
        core::pin::pin!(locals),
        core::pin::pin!(async {
            let report = core::pin::pin!(config.transfer(
                connection,
                environment,
                &mut requests,
                &mut incoming
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

/// Join the actual message locals through their projected End/Done exchanges.
/// Network failure or cancellation terminates an unfinished exchange.
#[allow(clippy::too_many_arguments)]
pub async fn execute(
    reader: &mut Endpoint<'_, READ>,
    up: &mut Endpoint<'_, UPLOAD>,
    writer: &mut Endpoint<'_, WRITE>,
    down: &mut Endpoint<'_, DOWNLOAD>,
    input: &mut impl application::BodyReader,
    output: &mut impl message::localside::writer::BodyWriter,
    request: &Exchange<'_>,
    response: &Exchange<'_>,
    settings: Settings,
    upload: impl for<'a, 'r, 'exchange, 'storage> AsyncFnOnce(
        &'a mut Endpoint<'r, UPLOAD>,
        &'exchange Exchange<'storage>,
    ) -> message::Result<()>,
    download: impl for<'a, 'r, 'exchange, 'storage> AsyncFnOnce(
        &'a mut Endpoint<'r, DOWNLOAD>,
        &'exchange Exchange<'storage>,
    ) -> message::Result<()>,
) -> Result<(), Error> {
    crate::runtime::join::values4(
        async {
            message::localside::reader::client(reader, input, response)
                .await
                .map_err(Error::from)
        },
        async { upload(up, request).await.map_err(Error::from) },
        async {
            message::localside::writer::client(
                writer,
                output,
                settings.max_field_section_size,
                request,
            )
            .await
            .map_err(Error::from)
        },
        async { download(down, response).await.map_err(Error::from) },
    )
    .await?;

    Ok(())
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
