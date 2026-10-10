//! Request-scoped host file adapters; transport work remains in direct core
//! roles. Selected response bodies use caller-bounded buffers, never whole-file
//! allocation. Request and sink handles share only host download associations.
use super::files::{self, Download, SafeRoot};
use hibana_quic::http3::{self, Protocol};
use hibana_quic::quic::application::{
    BodyReader, ClientRequests, Error as ApplicationError, ServerHandler, StreamSink,
};
use std::io::Cursor;
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{Read, Write},
    path::Path,
    rc::Rc,
};
/// This selects only local file handlers. The library owns the authenticated
/// prefix, affine handoff, stream work, retirement, closing and draining.
pub enum Files {
    Client(Client),
    Server(FileServer),
}

impl Files {
    pub fn local_limits(&self) -> hibana_quic::quic::streams::Limits {
        match self {
            Self::Client(client) => {
                if super::application_storage::client_uses_large_window(client.count) {
                    super::application_storage::local_limits::<
                        { super::application_storage::CLIENT_RECEIVE_BYTES },
                    >(
                        hibana_quic::quic::Side::Client,
                        super::application_storage::capacity(client.protocol, client.count),
                        client.protocol,
                    )
                } else {
                    super::application_storage::local_limits::<
                        { super::application_storage::RECEIVE_BYTES },
                    >(
                        hibana_quic::quic::Side::Client,
                        super::application_storage::capacity(client.protocol, client.count),
                        client.protocol,
                    )
                }
            }
            Self::Server(server) => super::application_storage::local_limits::<
                { super::application_storage::RECEIVE_BYTES },
            >(
                hibana_quic::quic::Side::Server,
                super::application_storage::capacity(
                    server.protocol,
                    super::application_storage::server_capacity(server.completion_limit),
                ),
                server.protocol,
            ),
        }
    }
}

pub const MAX_REQUESTS: usize = hibana_quic::quic::application::MAX_REQUESTS;
#[derive(Clone, Default)]
pub struct Diagnostics(Rc<RefCell<Option<String>>>);
impl Diagnostics {
    fn fail<T>(&self, error: impl Into<String>) -> Result<T, ()> {
        let mut saved = self.0.borrow_mut();
        if saved.is_none() {
            *saved = Some(error.into());
        }
        Err(())
    }
    pub fn take(&self) -> Option<String> {
        self.0.borrow_mut().take()
    }
}
#[derive(Default)]
pub struct Observations {
    pub files_started: Cell<usize>,
    /// Client atomic publication at FIN; server EOF observation only. Core
    /// completion must separately establish peer ACKs and close completion.
    pub files_finished: Cell<usize>,
    pub body_bytes: Cell<u64>,
}
pub struct FileServer {
    pub protocol: Protocol,
    max_field_section_size: u64,
    pub completion_limit: Option<core::num::NonZeroUsize>,
    root: SafeRoot,
    admitted: BTreeSet<u64>,
    max_requests: usize,
    pub observations: Rc<Observations>,
    pub diagnostics: Diagnostics,
}
impl FileServer {
    pub fn new(protocol: Protocol, root: &Path, max_requests: usize) -> Result<Self, String> {
        if max_requests == 0 || max_requests > MAX_REQUESTS {
            return Err("max requests must be 1..=4096".into());
        }
        Ok(Self {
            protocol,
            max_field_section_size: u64::MAX,
            completion_limit: None,
            root: SafeRoot::open(root, false)?,
            admitted: BTreeSet::new(),
            max_requests,
            observations: Rc::default(),
            diagnostics: Diagnostics::default(),
        })
    }
}
pub struct FileBody {
    file: File,
    prefix: Cursor<Vec<u8>>,
    observations: Rc<Observations>,
    diagnostics: Diagnostics,
}
impl ServerHandler for FileServer {
    fn peer_settings(&mut self, settings: http3::Settings) -> Result<(), ApplicationError> {
        if self.protocol != Protocol::Http3 || settings.max_field_section_size < 42 {
            return self
                .diagnostics
                .fail("peer field limit cannot carry the response status")
                .map_err(|_| ApplicationError::Application);
        }
        self.max_field_section_size = settings.max_field_section_size;
        Ok(())
    }

    type Body = FileBody;
    fn request_limit(&self) -> Option<core::num::NonZeroUsize> {
        self.completion_limit
    }
    async fn open(&mut self, stream_id: u64, request: &[u8]) -> Result<FileBody, ()> {
        if !stream_id.is_multiple_of(4)
            || self.admitted.contains(&stream_id)
            || self.admitted.len() >= self.max_requests
        {
            return self
                .diagnostics
                .fail("duplicate, invalid, or over-limit request stream");
        }
        let mut canonical = Vec::new();
        let request = if self.protocol == Protocol::Http3 {
            let fields = super::http3_files::decode_request(request).map_err(|error| {
                let _ = self.diagnostics.fail::<()>(format!("{error:?}"));
            })?;
            canonical.extend_from_slice(b"GET ");
            canonical.extend_from_slice(&fields.path[..fields.path_len]);
            canonical.extend_from_slice(b"\r\n");
            canonical.as_slice()
        } else {
            request
        };
        let components = files::parse_get(request).map_err(|error| {
            let _ = self.diagnostics.fail::<()>(format!("{error:?}"));
        })?;
        let file = self.root.read(&components).map_err(|error| {
            let _ = self.diagnostics.fail::<()>(format!("{error:?}"));
        })?;
        self.admitted.insert(stream_id);
        self.observations
            .files_started
            .set(self.observations.files_started.get() + 1);
        let mut prefix = Vec::new();
        if self.protocol == Protocol::Http3 {
            let body_len = file
                .metadata()
                .map_err(|error| {
                    let _ = self
                        .diagnostics
                        .fail::<()>(format!("response metadata: {error}"));
                })?
                .len();
            let mut header = [0; 16];
            let n = http3::frame_header(1, 3, &mut header).map_err(|_| ())?;
            prefix.extend_from_slice(&header[..n]);
            prefix.extend_from_slice(&[0, 0, 0xd9]);
            let n = http3::frame_header(0, body_len, &mut header).map_err(|_| ())?;
            prefix.extend_from_slice(&header[..n]);
        }
        Ok(FileBody {
            file,
            prefix: Cursor::new(prefix),
            observations: self.observations.clone(),
            diagnostics: self.diagnostics.clone(),
        })
    }
}
impl BodyReader for FileBody {
    async fn read(&mut self, output: &mut [u8]) -> Result<usize, ()> {
        if output.is_empty() {
            return self
                .diagnostics
                .fail("response body read requires a nonempty bounded buffer");
        }
        let prefix = self.prefix.read(output).map_err(|_| ())?;
        if prefix != 0 {
            return Ok(prefix);
        }
        let len = self.file.read(output).map_err(|error| {
            let _ = self
                .diagnostics
                .fail::<()>(format!("read selected response body: {error}"));
        })?;
        if len == 0 {
            self.observations
                .files_finished
                .set(self.observations.files_finished.get() + 1);
        } else {
            self.observations
                .body_bytes
                .set(self.observations.body_bytes.get() + len as u64);
        }
        Ok(len)
    }
}
#[derive(Debug)]
pub struct Request {
    target: String,
    authority: String,
    components: Vec<String>,
}
impl Request {
    pub fn from_url(value: &str, server_name: &str, port: u16) -> Result<Self, String> {
        let target = files::url_target(value, server_name, port)?;
        Ok(Self {
            target: target.to_owned(),
            authority: format!("{server_name}:{port}"),
            components: files::path_components(target)?,
        })
    }
    pub fn same_destination(&self, other: &Self) -> bool {
        self.components == other.components
    }
}
struct ClientFiles {
    protocol: Protocol,
    max_field_section_size: u64,
    root: SafeRoot,
    requests: Vec<Request>,
    next: usize,
    pending: Option<usize>,
    streams: BTreeMap<u64, Download>,
    used_streams: BTreeSet<u64>,
    observations: Rc<Observations>,
    diagnostics: Diagnostics,
}
pub struct Requests(Rc<RefCell<ClientFiles>>);
pub struct Downloads(Rc<RefCell<ClientFiles>>);
pub struct Client {
    pub protocol: Protocol,
    pub requests: Requests,
    pub downloads: Downloads,
    pub observations: Rc<Observations>,
    pub diagnostics: Diagnostics,
    pub count: usize,
}
impl Client {
    pub fn new(protocol: Protocol, root: &Path, requests: Vec<Request>) -> Result<Self, String> {
        if requests.is_empty() || requests.len() > MAX_REQUESTS {
            return Err("client requires 1..=4096 requests".into());
        }
        for (index, request) in requests.iter().enumerate() {
            if requests[..index]
                .iter()
                .any(|previous| request.same_destination(previous))
            {
                return Err("duplicate decoded download destination".into());
            }
        }
        let count = requests.len();
        let observations = Rc::default();
        let diagnostics = Diagnostics::default();
        let files = Rc::new(RefCell::new(ClientFiles {
            protocol,
            max_field_section_size: u64::MAX,
            root: SafeRoot::open(root, true)?,
            requests,
            next: 0,
            pending: None,
            streams: BTreeMap::new(),
            used_streams: BTreeSet::new(),
            observations: Rc::clone(&observations),
            diagnostics: diagnostics.clone(),
        }));
        Ok(Self {
            protocol,
            requests: Requests(files.clone()),
            downloads: Downloads(files),
            observations,
            diagnostics,
            count,
        })
    }
}
impl ClientRequests for Requests {
    fn peer_settings(&mut self, settings: http3::Settings) -> Result<(), ApplicationError> {
        let mut files = self.0.borrow_mut();
        if files.protocol != Protocol::Http3 {
            return files
                .diagnostics
                .fail("HTTP/3 settings on an HQ adapter")
                .map_err(|_| ApplicationError::Application);
        }
        files.max_field_section_size = settings.max_field_section_size;
        Ok(())
    }

    async fn next(&mut self, output: &mut [u8]) -> Result<Option<usize>, ()> {
        let mut files = self.0.borrow_mut();
        if files.pending.is_some() {
            return files
                .diagnostics
                .fail("previous GET has no assigned stream");
        }
        let Some(request) = files.requests.get(files.next) else {
            return Ok(None);
        };
        if files.protocol == Protocol::Http3 {
            let field_size = 165usize
                .checked_add(request.authority.len())
                .and_then(|n| n.checked_add(request.target.len()))
                .ok_or(())?;
            if field_size as u64 > files.max_field_section_size {
                return files
                    .diagnostics
                    .fail("request exceeds peer field section limit");
            }
            let mut fields = [0; 2048];
            let count = http3::request_fields(
                request.authority.as_bytes(),
                request.target.as_bytes(),
                &mut fields,
            )
            .map_err(|_| ())?;
            let head = http3::frame_header(1, count as u64, output).map_err(|_| ())?;
            output
                .get_mut(head..head + count)
                .ok_or(())?
                .copy_from_slice(&fields[..count]);
            files.pending = Some(files.next);
            return Ok(Some(head + count));
        }
        let len = request.target.len() + 6;
        if output.len() < len {
            return files
                .diagnostics
                .fail("GET exceeds caller request capacity");
        }
        output[..4].copy_from_slice(b"GET ");
        output[4..len - 2].copy_from_slice(request.target.as_bytes());
        output[len - 2..len].copy_from_slice(b"\r\n");
        files.pending = Some(files.next);
        Ok(Some(len))
    }
    fn started(&mut self, stream_id: u64) -> Result<(), ()> {
        let mut files = self.0.borrow_mut();
        if !stream_id.is_multiple_of(4) || files.used_streams.contains(&stream_id) {
            return files
                .diagnostics
                .fail("invalid or reused client stream identifier");
        }
        let Some(index) = files.pending else {
            return files
                .diagnostics
                .fail("stream assigned without a pending GET");
        };
        let download = files
            .root
            .create(&files.requests[index].components)
            .map_err(|error| {
                let _ = files.diagnostics.fail::<()>(format!("{error:?}"));
            })?;
        files.streams.insert(stream_id, download);
        files.used_streams.insert(stream_id);
        files.pending = None;
        files.next += 1;
        files
            .observations
            .files_started
            .set(files.observations.files_started.get() + 1);
        Ok(())
    }
}
impl StreamSink for Downloads {
    fn poll_write(
        &mut self,
        stream_id: u64,
        bytes: &[u8],
        _: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<usize, ()>> {
        core::task::Poll::Ready((|| {
            let mut files = self.0.borrow_mut();
            let Some(download) = files.streams.get_mut(&stream_id) else {
                return files
                    .diagnostics
                    .fail("response for unknown or completed stream");
            };
            if let Err(error) = download.file.write_all(bytes) {
                return files
                    .diagnostics
                    .fail(format!("write bounded response chunk: {error}"));
            }
            if files.protocol == Protocol::Http09 {
                files
                    .observations
                    .body_bytes
                    .set(files.observations.body_bytes.get() + bytes.len() as u64);
            }
            Ok(bytes.len())
        })())
    }
    async fn finish(&mut self, stream_id: u64) -> Result<(), ()> {
        let (mut download, protocol, observations, diagnostics) = {
            let mut files = self.0.borrow_mut();
            let Some(download) = files.streams.remove(&stream_id) else {
                return files
                    .diagnostics
                    .fail("FIN for unknown or completed stream");
            };
            (
                download,
                files.protocol,
                files.observations.clone(),
                files.diagnostics.clone(),
            )
        };
        if protocol == Protocol::Http3 {
            let mut slab = vec![0; 65536];
            let bytes = super::http3_files::decode_response(
                &super::native_files::FileStorage(&download.file),
                &mut slab,
            )
            .await
            .map_err(|error| {
                let _ = diagnostics.fail::<()>(format!("{error:?}"));
            })?;
            observations
                .body_bytes
                .set(observations.body_bytes.get() + bytes);
        }
        if let Err(error) = download.finish() {
            return diagnostics.fail(error);
        }
        observations
            .files_finished
            .set(observations.files_finished.get() + 1);
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };
    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "direct-file-service-{:016x}",
                u64::from_be_bytes(crate::random().unwrap())
            ));
            fs::create_dir(&root).unwrap();
            Self(root)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn ready<T>(future: impl Future<Output = T>) -> T {
        match pin!(future)
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("regular-file adapter unexpectedly parked"),
        }
    }
    #[test]
    fn actual_request_selects_its_file_and_body_reads_are_bounded() {
        let root = Fixture::new();
        fs::write(root.0.join("one"), b"first").unwrap();
        fs::write(root.0.join("two"), b"second").unwrap();
        let mut server = FileServer::new(Default::default(), &root.0, 3).unwrap();
        let mut body = ready(server.open(4, b"GET /two\r\n")).unwrap();
        let mut chunk = [0; 2];
        let mut result = Vec::new();
        loop {
            let len = ready(body.read(&mut chunk)).unwrap();
            if len == 0 {
                break;
            }
            result.extend_from_slice(&chunk[..len]);
        }
        assert_eq!(result, b"second");
        assert_eq!(server.observations.body_bytes.get(), 6);
        assert_eq!(server.observations.files_finished.get(), 1);
        assert!(ready(server.open(8, b"GET /../outside\r\n")).is_err());
    }
    #[test]
    fn interleaved_streams_publish_only_their_own_completed_files() {
        let root = Fixture::new();
        let requests = ["/one", "/two", "/empty"]
            .iter()
            .map(|p| Request::from_url(p, "localhost", 4433).unwrap())
            .collect();
        let mut client = Client::new(Default::default(), &root.0, requests).unwrap();
        let mut get = [0; 128];
        for stream in [0, 4, 8] {
            assert!(ready(client.requests.next(&mut get)).unwrap().is_some());
            client.requests.started(stream).unwrap();
        }
        assert_eq!(ready(client.requests.next(&mut get)).unwrap(), None);
        ready(core::future::poll_fn(|cx| {
            client.downloads.poll_write(4, b"second", cx)
        }))
        .unwrap();
        ready(core::future::poll_fn(|cx| {
            client.downloads.poll_write(0, b"first", cx)
        }))
        .unwrap();
        assert!(!root.0.join("one").exists());
        assert!(!root.0.join("two").exists());
        ready(client.downloads.finish(8)).unwrap();
        ready(client.downloads.finish(0)).unwrap();
        ready(client.downloads.finish(4)).unwrap();
        assert_eq!(fs::read(root.0.join("one")).unwrap(), b"first");
        assert_eq!(fs::read(root.0.join("two")).unwrap(), b"second");
        assert!(fs::read(root.0.join("empty")).unwrap().is_empty());
        assert_eq!(client.observations.files_finished.get(), 3);
        assert!(
            ready(core::future::poll_fn(|cx| client
                .downloads
                .poll_write(0, b"late", cx)))
            .is_err()
        );
    }
    #[test]
    fn duplicate_decoded_destinations_and_cancelled_partial_downloads_are_safe() {
        let root = Fixture::new();
        let requests = ["/a", "/%61"]
            .iter()
            .map(|p| Request::from_url(p, "localhost", 4433).unwrap())
            .collect();
        assert!(Client::new(Default::default(), &root.0, requests).is_err());
        {
            let mut client = Client::new(
                Default::default(),
                &root.0,
                vec![Request::from_url("/partial", "localhost", 4433).unwrap()],
            )
            .unwrap();
            ready(client.requests.next(&mut [0; 128])).unwrap();
            client.requests.started(0).unwrap();
            ready(core::future::poll_fn(|cx| {
                client.downloads.poll_write(0, b"not finished", cx)
            }))
            .unwrap();
        }
        assert_eq!(fs::read_dir(&root.0).unwrap().count(), 0);
    }
    #[test]
    fn http3_file_adapters_use_framed_requests_and_publish_decoded_bodies() {
        let root = Fixture::new();
        let destination = Fixture::new();
        fs::write(root.0.join("item"), b"actual file body").unwrap();
        let requests = vec![Request::from_url("/item", "localhost", 4433).unwrap()];
        let mut client = Client::new(Protocol::Http3, &destination.0, requests).unwrap();
        let mut server = FileServer::new(Protocol::Http3, &root.0, 1).unwrap();
        let mut request = [0; 1024];
        let n = ready(client.requests.next(&mut request)).unwrap().unwrap();
        client.requests.started(0).unwrap();
        let mut body = ready(server.open(0, &request[..n])).unwrap();
        let mut chunk = [0; 7];
        loop {
            let n = ready(body.read(&mut chunk)).unwrap();
            if n == 0 {
                break;
            }
            ready(core::future::poll_fn(|cx| {
                client.downloads.poll_write(0, &chunk[..n], cx)
            }))
            .unwrap();
        }
        assert!(!destination.0.join("item").exists());
        let reactor = {
            static WAKE: hibana_quic_pal::unix::reactor::WakeStorage =
                hibana_quic_pal::unix::reactor::WakeStorage::new();
            hibana_quic_pal::unix::reactor::Reactor::<1, 1>::new(&WAKE)
        }
        .unwrap();
        reactor
            .block_on(client.downloads.finish(0))
            .unwrap()
            .unwrap();
        assert_eq!(
            fs::read(destination.0.join("item")).unwrap(),
            b"actual file body"
        );
        assert_eq!(client.observations.body_bytes.get(), 16);
        assert_eq!(client.observations.files_finished.get(), 1);
        assert_eq!(server.observations.body_bytes.get(), 16);
    }
}
