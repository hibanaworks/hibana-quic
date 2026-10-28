//! OS-independent attachment of an application localside to an ordered stream.
//! Application progress remains in its projected Hibana program.

use crate::runtime::carrier::CarrierStorage;
mod imp;
/// Stream adapters for caller-owned connection storage.
pub use imp::stream;
pub mod localside;
pub use hibana_tls::{Protocol, RawProtocol};
/// Borrowed stream-facing half of the application carrier.
pub type StreamPeer<'a> = crate::runtime::carrier::Peer<'a, 4, 256, 8>;

/// Caller-owned runtime storage; no heap or native executor is required.
pub struct Storage {
    pub(crate) carrier: CarrierStorage<4, 256, 8>,
}
impl Storage {
    pub const fn new() -> Self {
        Self {
            carrier: CarrierStorage::new(),
        }
    }
}
impl Default for Storage {
    fn default() -> Self {
        Self::new()
    }
}
#[derive(Debug)]
pub enum Error<E> {
    Admission,
    Transport(hibana::runtime::transport::TransportError),
    Attach(hibana::runtime::AttachError),
    Local(E),
    Network(E),
}

pub const DATAGRAM: usize = crate::quic::application::imp::owned::DATAGRAM;
pub const PARAMETERS: usize = 2048;

/// Finite request/response connection settings. These values do not track progress.
pub struct ClientConfig<'a> {
    pub address: crate::io::Address,
    pub now: hibana_tls::certificate::UnixTime,
    pub server_name: &'a str,
    pub trust_anchors: &'a [hibana_tls::certificate::TrustAnchor<'a>],
    pub protocol: Protocol,
    pub idle_timeout_ms: u64,
}
pub struct ServerConfig<'a> {
    pub protocol: Protocol,
    pub certificate_chain: &'a [&'a [u8]],
    pub signing_key: &'a hibana_tls::handshake::SigningKey,
    pub idle_timeout_ms: u64,
}

/// Physical capabilities borrowed for one connection. Implementations may use an
/// OS, a board driver, or a custom kernel; this value owns no protocol progress.
pub struct Environment<'a, Socket, Timer, Random> {
    pub socket: &'a Socket,
    pub clock: &'a Timer,
    pub entropy: &'a mut Random,
}

/// The actual connection and application arenas, owned by the caller.
/// `STREAMS` bounds concurrent streams; byte capacities can be overridden.
/// Use a const initializer (or static storage) to avoid temporary arena copies.
pub struct Memory<
    const STREAMS: usize,
    const CONNECTION: usize = { 256 * 1024 },
    const APPLICATION: usize = 65536,
> {
    connection: ConnectionMemory<STREAMS, CONNECTION>,
    application: [u8; APPLICATION],
}
impl<const S: usize, const C: usize, const A: usize> Memory<S, C, A> {
    pub const fn new() -> Self {
        Self {
            connection: ConnectionMemory::new(),
            application: [0; A],
        }
    }
}
impl<const S: usize, const C: usize, const A: usize> Default for Memory<S, C, A> {
    fn default() -> Self {
        Self::new()
    }
}
/// Storage for the same authenticated connection without an application carrier.
/// Used when request/response effects directly implement a wire protocol.
pub struct ConnectionMemory<const STREAMS: usize, const BYTES: usize = { 256 * 1024 }> {
    streams: [crate::quic::streams::StreamSlot<
        { crate::quic::application::imp::owned::RECEIVE_BYTES },
    >; STREAMS],
    slab: [u8; BYTES],
    tls: imp::tls::TlsBuffers,
    buffers: crate::quic::application::imp::owned::Storage,
}
impl<const S: usize, const B: usize> ConnectionMemory<S, B> {
    pub const fn new() -> Self {
        Self {
            streams: [const { crate::quic::streams::StreamSlot::EMPTY }; S],
            slab: [0; B],
            tls: imp::tls::TlsBuffers::new(),
            buffers: crate::quic::application::imp::owned::Storage::new(),
        }
    }
}
impl<const S: usize, const B: usize> Default for ConnectionMemory<S, B> {
    fn default() -> Self {
        Self::new()
    }
}

/// An application endpoint's actual borrowed configuration, memory and I/O.
/// Construction does not start TLS or allocate. `run` consumes the binding.
pub struct Client<'a, 'cfg, Socket, Timer, Random, const S: usize, const C: usize, const A: usize> {
    config: ClientConfig<'cfg>,
    memory: &'a mut Memory<S, C, A>,
    environment: Environment<'a, Socket, Timer, Random>,
    peer: u8,
}
pub struct Server<'a, 'cfg, Socket, Timer, Random, const S: usize, const C: usize, const A: usize> {
    config: ServerConfig<'cfg>,
    memory: &'a mut Memory<S, C, A>,
    environment: Environment<'a, Socket, Timer, Random>,
    peer: u8,
}
impl<'cfg> ClientConfig<'cfg> {
    pub fn bind<'a, Socket, Timer, Random, const S: usize, const C: usize, const A: usize>(
        self,
        memory: &'a mut Memory<S, C, A>,
        environment: Environment<'a, Socket, Timer, Random>,
        peer: u8,
    ) -> Client<'a, 'cfg, Socket, Timer, Random, S, C, A> {
        Client {
            config: self,
            memory,
            environment,
            peer,
        }
    }
}
impl<'cfg> ServerConfig<'cfg> {
    pub fn bind<'a, Socket, Timer, Random, const S: usize, const C: usize, const A: usize>(
        self,
        memory: &'a mut Memory<S, C, A>,
        environment: Environment<'a, Socket, Timer, Random>,
        peer: u8,
    ) -> Server<'a, 'cfg, Socket, Timer, Random, S, C, A> {
        Server {
            config: self,
            memory,
            environment,
            peer,
        }
    }
}
