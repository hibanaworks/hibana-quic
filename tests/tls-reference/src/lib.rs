//! Development-only, **allocating** TLS 1.3 backend using rustls's QUIC API.
//!
//! This is a TLS provider, not a reused QUIC transport engine. It exchanges raw
//! handshake messages (never TLS records), verifies certificates and hostnames,
//! and supplies negotiated packet keys. It is NOT the no_alloc/Pico release
//! backend. `Vec`, `VecDeque`, `Arc`, `Box`, OS entropy, and system time are used.
//! Initial packet keys remain the responsibility of `hibana-quic::crypto`.
#![forbid(unsafe_code)]

use std::{collections::VecDeque, sync::Arc};

use hibana_quic::crypto::{
    AuthenticationError, IntegrityBudget, MAX_PACKET_NUMBER, MAX_PROTECTED_PACKET_LEN,
};
use hibana_tls::quic::Error;
use hibana_tls::quic::Level;
use hibana_tls::quic::Output;
use hibana_tls::quic::Provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::quic::{Connection, KeyChange, Keys, Version};
use rustls::{ClientConfig, RootCertStore, ServerConfig};

/// Exact rustls version is pinned in Cargo.toml/Cargo.lock. Re-export its input
/// types so callers do not need a potentially mismatched second rustls version.
pub use rustls;

pub const ALPN: &[u8] = b"hibana/1";
/// Defensive reference-backend message cap; not a no_alloc memory budget.
pub const MAX_TLS_MESSAGE_LEN: usize = 1 << 20;

struct Flight {
    level: Level,
    bytes: Vec<u8>,
    sent: usize,
}

struct KeyState {
    keys: Keys,
    encrypted: u64,
    last_pn: Option<u64>,
}

impl KeyState {
    fn new(keys: Keys) -> Self {
        Self {
            keys,
            encrypted: 0,
            last_pn: None,
        }
    }
}

/// Checks CRYPTO-level boundaries independently of rustls, whose read_hs API
/// accepts only bytes. Parsing here does not interpret handshake contents.
#[derive(Clone, Copy, Default)]
struct Framing {
    header: [u8; 4],
    header_used: usize,
    remaining: usize,
}

impl Framing {
    fn accept(&mut self, level: Level, mut input: &[u8]) -> Result<(), Error> {
        while !input.is_empty() {
            if self.remaining != 0 {
                let n = input.len().min(self.remaining);
                self.remaining -= n;
                input = &input[n..];
                continue;
            }
            let n = input.len().min(4 - self.header_used);
            self.header[self.header_used..self.header_used + n].copy_from_slice(&input[..n]);
            self.header_used += n;
            input = &input[n..];
            let allowed = match level {
                Level::Initial => matches!(self.header[0], 1 | 2),
                Level::Handshake => matches!(self.header[0], 8 | 11 | 13 | 15 | 20),
                Level::OneRtt => self.header[0] == 4,
            };
            if !allowed {
                return Err(Error::InvalidInput);
            }
            if self.header_used == 4 {
                self.remaining = ((self.header[1] as usize) << 16)
                    | ((self.header[2] as usize) << 8)
                    | self.header[3] as usize;
                if self.remaining > MAX_TLS_MESSAGE_LEN {
                    return Err(Error::Capacity);
                }
                self.header_used = 0;
            }
        }
        Ok(())
    }

    fn complete(&self) -> bool {
        self.header_used == 0 && self.remaining == 0
    }
}

/// Single-owner, host-only reference provider. No insecure certificate verifier,
/// TLS key logging, 0-RTT, resumption, or key-update API is enabled by this wrapper.
/// Received transport parameters are exposed only after TLS authentication.
pub struct RustlsProvider {
    connection: Connection,
    pending: VecDeque<Flight>,
    write_level: Level,
    handshake: Option<KeyState>,
    one_rtt: Option<KeyState>,
    incoming: [Framing; 3],
    // The actual connection budget also moves through the projected Initial
    // loan. The backend limit is only a monotonic constraint from rustls keys.
    integrity: IntegrityBudget,
    integrity_limit: u64,
    fatal: Option<Error>,
    last_tls_error: Option<String>,
}

impl RustlsProvider {
    /// Create a verifying client. Roots must be explicitly supplied; WebPKI
    /// verifies the certificate chain, validity, signatures, and server name.
    pub fn client(
        roots: RootCertStore,
        name: ServerName<'static>,
        parameters: Vec<u8>,
    ) -> Result<Self, Error> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| Error::Handshake)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![ALPN.to_vec()];
        config.enable_early_data = false;
        config.resumption = rustls::client::Resumption::disabled();
        let connection =
            rustls::quic::ClientConnection::new(Arc::new(config), Version::V1, name, parameters)
                .map_err(|_| Error::Handshake)?;
        Self::new(Connection::Client(connection))
    }

    /// Verifying client constrained to P-256 for testing the bounded profile
    /// without HRR. This is not the default client's group policy.
    pub fn client_p256(
        roots: RootCertStore,
        name: ServerName<'static>,
        parameters: Vec<u8>,
    ) -> Result<Self, Error> {
        let mut provider = rustls::crypto::ring::default_provider();
        provider.kx_groups = vec![rustls::crypto::ring::kx_group::SECP256R1];
        let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| Error::Handshake)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![ALPN.to_vec()];
        config.enable_early_data = false;
        config.resumption = rustls::client::Resumption::disabled();
        let connection =
            rustls::quic::ClientConnection::new(Arc::new(config), Version::V1, name, parameters)
                .map_err(|_| Error::Handshake)?;
        Self::new(Connection::Client(connection))
    }

    /// Create a certificate-authenticated server. Client certificates are not
    /// requested, matching ordinary server-authenticated raw QUIC sessions.
    pub fn server(
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        parameters: Vec<u8>,
    ) -> Result<Self, Error> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| Error::Handshake)?
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .map_err(|_| Error::Authentication)?;
        config.alpn_protocols = vec![ALPN.to_vec()];
        config.max_early_data_size = 0;
        config.send_tls13_tickets = 0;
        let connection =
            rustls::quic::ServerConnection::new(Arc::new(config), Version::V1, parameters)
                .map_err(|_| Error::Handshake)?;
        Self::new(Connection::Server(connection))
    }

    fn new(connection: Connection) -> Result<Self, Error> {
        let mut this = Self {
            connection,
            pending: VecDeque::new(),
            write_level: Level::Initial,
            handshake: None,
            one_rtt: None,
            incoming: [Framing::default(); 3],
            integrity: IntegrityBudget::new(),
            integrity_limit: u64::MAX,
            fatal: None,
            last_tls_error: None,
        };
        this.collect_output()?;
        Ok(this)
    }

    pub fn last_tls_error(&self) -> Option<&str> {
        self.last_tls_error.as_deref()
    }
    pub fn failed_authentications(&self) -> u64 {
        self.integrity.failed_packets()
    }
    pub fn negotiated_alpn(&self) -> Option<&[u8]> {
        if self.is_handshaking() {
            None
        } else {
            self.connection.alpn_protocol()
        }
    }

    fn active(&self) -> Result<(), Error> {
        self.fatal.map_or(Ok(()), Err)
    }

    fn fail(&mut self, error: Error) -> Error {
        self.fatal = Some(error);
        self.handshake = None;
        self.one_rtt = None;
        self.pending.clear();
        error
    }

    fn keys(&self, level: Level) -> Result<&KeyState, Error> {
        self.active()?;
        match level {
            Level::Initial => None,
            Level::Handshake => self.handshake.as_ref(),
            Level::OneRtt => self.one_rtt.as_ref(),
        }
        .ok_or(Error::KeysUnavailable)
    }

    fn keys_mut(&mut self, level: Level) -> Result<&mut KeyState, Error> {
        self.active()?;
        match level {
            Level::Initial => None,
            Level::Handshake => self.handshake.as_mut(),
            Level::OneRtt => self.one_rtt.as_mut(),
        }
        .ok_or(Error::KeysUnavailable)
    }

    fn collect_output(&mut self) -> Result<(), Error> {
        loop {
            let mut bytes = Vec::new();
            let change = self.connection.write_hs(&mut bytes);
            let empty = bytes.is_empty();
            // Crucial rustls contract: bytes returned WITH KeyChange are still
            // protected at the OLD level. Only subsequent write_hs uses new keys.
            if !empty {
                self.pending.push_back(Flight {
                    level: self.write_level,
                    bytes,
                    sent: 0,
                });
            }
            match change {
                Some(KeyChange::Handshake { keys }) => {
                    if self.handshake.is_some() {
                        return Err(self.fail(Error::Handshake));
                    }
                    self.integrity_limit = self
                        .integrity_limit
                        .min(keys.remote.packet.integrity_limit());
                    self.handshake = Some(KeyState::new(keys));
                    self.write_level = Level::Handshake;
                }
                Some(KeyChange::OneRtt { keys, next: _ }) => {
                    if self.one_rtt.is_some() {
                        return Err(self.fail(Error::Handshake));
                    }
                    self.integrity_limit = self
                        .integrity_limit
                        .min(keys.remote.packet.integrity_limit());
                    self.one_rtt = Some(KeyState::new(keys));
                    self.write_level = Level::OneRtt;
                }
                None if empty => break,
                None => {}
            }
        }
        Ok(())
    }
}

fn level_index(level: Level) -> usize {
    match level {
        Level::Initial => 0,
        Level::Handshake => 1,
        Level::OneRtt => 2,
    }
}

fn packet_size(pn: u64, header: &[u8], payload_len: usize) -> Result<(), Error> {
    if pn > MAX_PACKET_NUMBER {
        return Err(Error::InvalidInput);
    }
    if header
        .len()
        .checked_add(payload_len)
        .is_none_or(|n| n > MAX_PROTECTED_PACKET_LEN)
    {
        return Err(Error::Capacity);
    }
    Ok(())
}

impl Provider for RustlsProvider {
    fn integrity_budget(&mut self) -> Option<&mut IntegrityBudget> {
        Some(&mut self.integrity)
    }
    fn observations(&self) -> hibana_tls::quic::Observations {
        hibana_tls::quic::Observations {
            resumed: self
                .connection
                .handshake_kind()
                .map(|kind| matches!(kind, rustls::HandshakeKind::Resumed)),
            negotiated_suite: self
                .connection
                .negotiated_cipher_suite()
                .map(|suite| u16::from(suite.suite())),
            failed_authentications: Some(self.failed_authentications()),
        }
    }
    fn write_failure_diagnostic(&self, out: &mut dyn core::fmt::Write) -> core::fmt::Result {
        if let Some(failure) = self.last_tls_error() {
            out.write_str(failure)?;
        }
        Ok(())
    }

    fn receive(&mut self, level: Level, bytes: &[u8]) -> Result<(), Error> {
        self.active()?;
        if bytes.is_empty() {
            return Ok(());
        }
        match level {
            Level::Initial if self.handshake.is_some() => {
                return Err(self.fail(Error::InvalidInput));
            }
            Level::Handshake if self.handshake.is_none() => return Err(Error::KeysUnavailable),
            Level::OneRtt if self.connection.is_handshaking() || self.one_rtt.is_none() => {
                return Err(Error::KeysUnavailable);
            }
            _ => {}
        }
        let index = level_index(level);
        if self.incoming[..index]
            .iter()
            .any(|framer| !framer.complete())
        {
            return Err(self.fail(Error::InvalidInput));
        }
        let mut framing = self.incoming[index];
        if let Err(error) = framing.accept(level, bytes) {
            return Err(self.fail(error));
        }
        if let Err(error) = self.connection.read_hs(bytes) {
            self.last_tls_error = Some(error.to_string());
            let error = self
                .connection
                .alert()
                .map(|alert| Error::Alert(u8::from(alert)))
                .unwrap_or_else(|| match error {
                    rustls::Error::InvalidCertificate(_) => Error::Authentication,
                    _ => Error::Handshake,
                });
            return Err(self.fail(error));
        }
        self.incoming[index] = framing;
        self.collect_output()
    }

    fn transmit(&mut self, output: &mut [u8]) -> Result<Option<Output>, Error> {
        self.active()?;
        let Some(front) = self.pending.front_mut() else {
            return Ok(None);
        };
        if output.is_empty() {
            return Err(Error::Capacity);
        }
        let n = output.len().min(front.bytes.len() - front.sent);
        output[..n].copy_from_slice(&front.bytes[front.sent..front.sent + n]);
        front.sent += n;
        let level = front.level;
        if front.sent == front.bytes.len() {
            self.pending.pop_front();
        }
        Ok(Some(Output { level, len: n }))
    }

    fn discard_keys(&mut self, level: Level) {
        match level {
            Level::Initial => {}
            Level::Handshake => {
                self.handshake = None;
            }
            Level::OneRtt => {
                self.one_rtt = None;
            }
        }
    }
    fn has_keys(&self, level: Level) -> bool {
        self.keys(level).is_ok()
    }
    fn is_handshaking(&self) -> bool {
        self.fatal.is_some() || self.connection.is_handshaking()
    }
    fn peer_transport_parameters(&self) -> Option<&[u8]> {
        if self.is_handshaking() {
            None
        } else {
            self.connection.quic_transport_parameters()
        }
    }

    fn seal(
        &mut self,
        level: Level,
        pn: u64,
        header: &[u8],
        buffer: &mut [u8],
        plaintext_len: usize,
    ) -> Result<usize, Error> {
        self.active()?;
        if level == Level::OneRtt && self.connection.is_handshaking() {
            return Err(Error::KeysUnavailable);
        }
        let state = self.keys_mut(level)?;
        let tag_len = state.keys.local.packet.tag_len();
        let used = plaintext_len.checked_add(tag_len).ok_or(Error::Capacity)?;
        if used > buffer.len() {
            return Err(Error::Capacity);
        }
        packet_size(pn, header, used)?;
        if state.last_pn.is_some_and(|last| pn <= last) {
            return Err(Error::PacketNumberReuse);
        }
        if state.encrypted >= state.keys.local.packet.confidentiality_limit() {
            return Err(Error::ConfidentialityLimit);
        }
        state.last_pn = Some(pn);
        state.encrypted += 1;
        let tag =
            match state
                .keys
                .local
                .packet
                .encrypt_in_place(pn, header, &mut buffer[..plaintext_len])
            {
                Ok(tag) => tag,
                Err(_) => {
                    buffer[..used].fill(0);
                    return Err(Error::InvalidInput);
                }
            };
        buffer[plaintext_len..used].copy_from_slice(tag.as_ref());
        Ok(used)
    }

    fn open(
        &mut self,
        level: Level,
        pn: u64,
        header: &[u8],
        buffer: &mut [u8],
    ) -> Result<usize, Error> {
        self.active()?;
        if level == Level::OneRtt && self.connection.is_handshaking() {
            return Err(Error::KeysUnavailable);
        }
        packet_size(pn, header, buffer.len())?;
        // Borrow disjoint key/budget fields so verification is performed inside
        // the connection budget's closure gate, without an outcome supplied by
        // the endpoint or a second failed-authentication counter.
        let state = match level {
            Level::Initial => None,
            Level::Handshake => self.handshake.as_ref(),
            Level::OneRtt => self.one_rtt.as_ref(),
        }
        .ok_or(Error::KeysUnavailable)?;
        if buffer.len() < state.keys.remote.packet.tag_len() {
            return Err(Error::Capacity);
        }
        match self.integrity.authenticate(self.integrity_limit, || {
            state
                .keys
                .remote
                .packet
                .decrypt_in_place(pn, header, buffer)
                .map(|plaintext| plaintext.len())
        }) {
            Ok(len) => Ok(len),
            Err(AuthenticationError::Failed(_)) => {
                buffer.fill(0);
                Err(Error::Authentication)
            }
            Err(AuthenticationError::IntegrityLimit) => {
                buffer.fill(0);
                Err(self.fail(Error::IntegrityLimit))
            }
        }
    }

    fn header_mask(&self, level: Level, local: bool, sample: &[u8; 16]) -> Result<[u8; 5], Error> {
        let state = self.keys(level)?;
        let key = if local {
            &state.keys.local.header
        } else {
            &state.keys.remote.header
        };
        // Encrypt a dummy short header with a four-byte PN. XORing it back gives
        // mask[0]'s low five bits and all four PN mask bytes without secret export.
        let mut first = 0x43;
        let mut pn = [0; 4];
        key.encrypt_in_place(sample, &mut first, &mut pn)
            .map_err(|_| Error::InvalidInput)?;
        Ok([first ^ 0x43, pn[0], pn[1], pn[2], pn[3]])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
    use rustls::pki_types::PrivatePkcs8KeyDer;

    struct Identity {
        ca: CertificateDer<'static>,
        cert: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
    }

    fn identity(name: &str) -> Identity {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_key = KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec![name.to_owned()])
            .unwrap()
            .signed_by(&leaf_key, &ca, &ca_key)
            .unwrap();
        Identity {
            ca: ca.der().clone(),
            cert: leaf.der().clone(),
            key: PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into(),
        }
    }

    fn pair() -> (RustlsProvider, RustlsProvider) {
        let id = identity("localhost");
        let mut roots = RootCertStore::empty();
        roots.add(id.ca.clone()).unwrap();
        let client = RustlsProvider::client(
            roots,
            ServerName::try_from("localhost").unwrap(),
            vec![0x04, 1, 42],
        )
        .unwrap();
        let server = RustlsProvider::server(vec![id.cert], id.key, vec![0x04, 1, 63]).unwrap();
        (client, server)
    }

    fn drain(
        from: &mut RustlsProvider,
        to: &mut RustlsProvider,
        fragment: usize,
        seen: &mut Vec<Level>,
    ) -> Result<bool, Error> {
        let mut progress = false;
        let mut bytes = vec![0; fragment];
        while let Some(output) = from.transmit(&mut bytes)? {
            progress = true;
            seen.push(output.level);
            to.receive(output.level, &bytes[..output.len])?;
        }
        Ok(progress)
    }

    fn handshake(
        client: &mut RustlsProvider,
        server: &mut RustlsProvider,
        fragment: usize,
    ) -> Result<(Vec<Level>, Vec<Level>), Error> {
        let mut c_levels = Vec::new();
        let mut s_levels = Vec::new();
        for _ in 0..16 {
            let c = drain(client, server, fragment, &mut c_levels)?;
            let s = drain(server, client, fragment, &mut s_levels)?;
            if !c && !s {
                if client.is_handshaking() || server.is_handshaking() {
                    return Err(Error::Handshake);
                }
                return Ok((c_levels, s_levels));
            }
        }
        Err(Error::Handshake)
    }

    #[test]
    fn real_tls13_handshake_verifies_cert_hostname_alpn_and_parameters() {
        for fragment in [1, 3, 17, 127, 4096] {
            let (mut client, mut server) = pair();
            assert!(client.peer_transport_parameters().is_none());
            assert!(!client.has_keys(Level::Initial));
            let (c_levels, s_levels) = handshake(&mut client, &mut server, fragment).unwrap();
            assert!(!client.is_handshaking());
            assert!(!server.is_handshaking());
            assert_eq!(client.negotiated_alpn(), Some(ALPN));
            assert_eq!(server.negotiated_alpn(), Some(ALPN));
            assert_eq!(
                client.peer_transport_parameters(),
                Some([0x04, 1, 63].as_slice())
            );
            assert_eq!(
                server.peer_transport_parameters(),
                Some([0x04, 1, 42].as_slice())
            );
            assert_eq!(c_levels[0], Level::Initial);
            assert_eq!(s_levels[0], Level::Initial);
            assert!(c_levels.contains(&Level::Handshake));
            assert!(s_levels.contains(&Level::Handshake));
            assert!(!c_levels.contains(&Level::OneRtt));
            assert!(!s_levels.contains(&Level::OneRtt));
            for level in [Level::Handshake, Level::OneRtt] {
                assert!(client.has_keys(level));
                assert!(server.has_keys(level));
            }
        }
    }

    #[test]
    fn negotiated_packet_keys_work_both_directions_and_reject_corruption() {
        let (mut client, mut server) = pair();
        handshake(&mut client, &mut server, 53).unwrap();
        for level in [Level::Handshake, Level::OneRtt] {
            for client_sends in [true, false] {
                let (sender, receiver) = if client_sends {
                    (&mut client, &mut server)
                } else {
                    (&mut server, &mut client)
                };
                let mut buffer = [0; 30];
                buffer[..14].copy_from_slice(b"real TLS keys!");
                assert_eq!(sender.seal(level, 7, b"header", &mut buffer, 14), Ok(30));
                assert_eq!(
                    sender.header_mask(level, true, &[3; 16]).unwrap(),
                    receiver.header_mask(level, false, &[3; 16]).unwrap()
                );
                for i in 0..buffer.len() {
                    let mut bad = buffer;
                    bad[i] ^= 1;
                    assert_eq!(
                        receiver.open(level, 7, b"header", &mut bad),
                        Err(Error::Authentication)
                    );
                    assert_eq!(bad, [0; 30]);
                }
                let mut wrong_header = buffer;
                assert_eq!(
                    receiver.open(level, 7, b"Header", &mut wrong_header),
                    Err(Error::Authentication)
                );
                assert_eq!(receiver.open(level, 7, b"header", &mut buffer), Ok(14));
                assert_eq!(&buffer[..14], b"real TLS keys!");
                assert_eq!(
                    sender.seal(level, 7, b"header", &mut buffer, 14),
                    Err(Error::PacketNumberReuse)
                );
            }
        }
    }

    #[test]
    fn wrong_ca_and_wrong_hostname_never_complete_or_expose_peer_parameters() {
        for wrong_ca in [true, false] {
            let server_id = identity("localhost");
            let mut roots = RootCertStore::empty();
            roots
                .add(if wrong_ca {
                    identity("localhost").ca
                } else {
                    server_id.ca
                })
                .unwrap();
            let name = if wrong_ca {
                "localhost"
            } else {
                "wrong.example"
            };
            let mut client =
                RustlsProvider::client(roots, ServerName::try_from(name).unwrap(), vec![]).unwrap();
            let mut server =
                RustlsProvider::server(vec![server_id.cert], server_id.key, vec![]).unwrap();
            assert!(handshake(&mut client, &mut server, 13).is_err());
            assert!(client.is_handshaking());
            assert!(client.last_tls_error().is_some());
            assert!(client.peer_transport_parameters().is_none());
            assert!(!client.has_keys(Level::OneRtt));
            assert!(client.transmit(&mut [0; 128]).is_err());
        }
    }

    #[test]
    fn invalid_handshake_wrong_level_and_forbidden_key_update_fail_closed() {
        let (_, mut server) = pair();
        assert!(server.receive(Level::Initial, &[1, 0, 0, 0]).is_err());
        assert!(server.is_handshaking());
        assert!(!server.has_keys(Level::OneRtt));
        let (mut client, mut server) = pair();
        handshake(&mut client, &mut server, 128).unwrap();
        assert_eq!(
            client.receive(Level::OneRtt, &[24, 0, 0, 1, 0]),
            Err(Error::InvalidInput)
        );
        assert!(!client.has_keys(Level::OneRtt));
        let (_, mut server) = pair();
        assert_eq!(
            server.receive(Level::Initial, &[20, 0, 0, 0]),
            Err(Error::InvalidInput)
        );
    }

    #[test]
    fn empty_output_does_not_lose_client_hello_and_key_limits_are_terminal() {
        let (mut client, mut server) = pair();
        assert_eq!(client.transmit(&mut []), Err(Error::Capacity));
        handshake(&mut client, &mut server, 47).unwrap();
        let state = client.one_rtt.as_mut().unwrap();
        state.encrypted = state.keys.local.packet.confidentiality_limit();
        assert_eq!(
            client.seal(Level::OneRtt, 0, b"aad", &mut [0; 16], 0),
            Err(Error::ConfidentialityLimit)
        );
        // A stricter test cap exercises a real final failed attempt without
        // manufacturing or resetting the shared budget's failure count.
        server.integrity_limit = 1;
        assert_eq!(
            server.open(Level::OneRtt, 0, b"aad", &mut [0; 16]),
            Err(Error::IntegrityLimit)
        );
        assert!(!server.has_keys(Level::Handshake));
        assert!(!server.has_keys(Level::OneRtt));
        assert_eq!(
            server.seal(Level::OneRtt, 0, b"aad", &mut [0; 16], 0),
            Err(Error::IntegrityLimit)
        );
    }

    #[test]
    fn initial_and_rustls_authentication_share_one_connection_budget() {
        let (mut client, mut server) = pair();
        let initial = hibana_quic::crypto::initial_keys(b"shared-budget")
            .unwrap()
            .server;
        assert_eq!(
            initial.open(0, b"aad", &mut [0; 16], server.integrity_budget().unwrap()),
            Err(hibana_quic::crypto::Error::AuthenticationFailed)
        );
        assert_eq!(server.failed_authentications(), 1);
        handshake(&mut client, &mut server, 47).unwrap();
        assert_eq!(
            server.failed_authentications(),
            1,
            "key installation must not reset Initial failures"
        );
        assert_eq!(
            server.open(Level::OneRtt, 0, b"aad", &mut [0; 16]),
            Err(Error::Authentication)
        );
        assert_eq!(server.failed_authentications(), 2);
        let mut body = [0; 32];
        body[..5].copy_from_slice(b"hello");
        let len = client.seal(Level::OneRtt, 1, b"aad", &mut body, 5).unwrap();
        assert_eq!(
            server.open(Level::OneRtt, 1, b"aad", &mut body[..len]),
            Ok(5)
        );
        assert_eq!(&body[..5], b"hello");
        assert_eq!(
            server.failed_authentications(),
            2,
            "successful authentication must not reset failures"
        );
        server.integrity_limit = 3;
        assert_eq!(
            server.open(Level::OneRtt, 2, b"aad", &mut [0; 16]),
            Err(Error::IntegrityLimit)
        );
        assert_eq!(server.failed_authentications(), 3);
        assert!(!server.has_keys(Level::OneRtt));
    }
}
