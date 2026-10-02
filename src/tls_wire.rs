//! Bounded TLS 1.3 handshake syntax for the initial QUIC profile.
//!
//! This module only parses/encodes complete handshake messages, including their
//! four-byte headers. It performs no cryptography, transcript update, certificate
//! verification, key installation, or state transition. Those belong to Provider.
//! Profile: TLS 1.3, SHA-256 suites 0x1301/0x1303, P-256/X25519 key shares,
//! ECDSA/P-256 and bounded RSA-PSS/SHA-256 CertificateVerify, hq-interop ALPN,
//! QUIC TP extension 0x39,
//! empty legacy session IDs and certificate-request context. Bounded HRR syntax
//! supports selected-group and cookie-only retries. Explicit *_psk APIs add
//! one bounded identity with a SHA-256 binder and PSK_DHE only; legacy wrappers
//! still reject actual PSK offers/selections. Explicit *_early entry points add
//! early-data syntax; client authentication remains unsupported. NST parsing does not confer
//! trust, cache eligibility or permission to resume; those are Provider duties.
//! Encoders may partially write the caller buffer on error; only an Ok length
//! authorizes structurally encoded bytes. PSK encoders emit a zero binder that
//! the provider MUST replace before publication. Certificate ranges are usable
//! only after a successful parse.
//! Sources: RFC 8446 sections 4.1–4.4; RFC 9001 sections 4 and 8.2.
//! <https://www.rfc-editor.org/rfc/rfc8446#section-4>
//! <https://www.rfc-editor.org/rfc/rfc9001#section-8.2>

/// Construction-time TLS suite policy. `Default` preserves AES-first negotiation;
/// singleton policies offer and accept only that exact SHA-256 suite.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CipherPolicy {
    #[default]
    Default,
    Aes128Only,
    ChaCha20Only,
}
impl CipherPolicy {
    pub const fn permits(self, suite: u16) -> bool {
        match self {
            Self::Default => matches!(suite, 0x1301 | 0x1303),
            Self::Aes128Only => suite == 0x1301,
            Self::ChaCha20Only => suite == 0x1303,
        }
    }
    pub const fn suites(self) -> &'static [u16] {
        match self {
            Self::Default => &[0x1301, 0x1303],
            Self::Aes128Only => &[0x1301],
            Self::ChaCha20Only => &[0x1303],
        }
    }
}

pub const ALPN: &[u8] = b"hq-interop";
pub const GROUP_P256: u16 = 23;
pub const GROUP_X25519: u16 = 29;
pub const SIGNATURE_P256_SHA256: u16 = 0x0403;
pub const SIGNATURE_RSA_PSS_RSAE_SHA256: u16 = 0x0804;
pub const SIGNATURE_RSA_PKCS1_SHA256: u16 = 0x0401;
pub const MAX_EXTENSIONS: usize = 32;
pub const MAX_CERTIFICATES: usize = 9;
/// This profile's caller-buffer cookie limit, below the TLS u16 wire limit.
pub const MAX_COOKIE_BYTES: usize = 256;
pub const MAX_PSK_IDENTITY_BYTES: usize = 4096;
const MAX_LIST_ITEMS: usize = 64;
pub const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Truncated,
    Length,
    UnexpectedMessage,
    Malformed,
    DuplicateExtension,
    MissingExtension,
    Unsupported,
    Capacity,
    BufferTooSmall,
    InvalidQuicEarlyData,
}

#[derive(Clone, Copy, Debug)]
pub struct PskOffer<'a> {
    pub identity: &'a [u8],
    pub obfuscated_age: u32,
    pub binder: &'a [u8],
    /// Transcript prefix excludes the entire binders vector, including u16 length.
    pub binder_prefix: usize,
    /// Start of the one 32-byte binder value in the complete handshake message.
    pub binder_offset: usize,
}
#[derive(Clone, Copy, Debug)]
pub struct NewSessionTicket<'a> {
    pub lifetime_seconds: u32,
    pub age_add: u32,
    pub nonce: &'a [u8],
    pub ticket: &'a [u8],
    pub early_data: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct ClientHello<'a> {
    pub random: &'a [u8; 32],
    /// Empty if the key_share vector contains no P-256 entry. The provider may
    /// request that group only when supports_p256 is true.
    pub key_share: &'a [u8],
    pub supports_p256: bool,
    pub key_share_x25519: &'a [u8],
    pub supports_x25519: bool,
    pub cookie: Option<&'a [u8]>,
    pub server_name: Option<&'a str>,
    pub offers_1301: bool,
    pub offers_1303: bool,
    pub signature_0403: bool,
    pub alpn: &'a [u8],
    pub params: &'a [u8],
    pub psk: Option<PskOffer<'a>>,
    pub psk_dhe_ke: bool,
    pub early_data: bool,
}
#[derive(Clone, Copy, Debug)]
pub struct HelloRetryRequest<'a> {
    pub suite: u16,
    pub selected_group: Option<u16>,
    pub cookie: Option<&'a [u8]>,
}
#[derive(Clone, Copy, Debug)]
pub struct ServerHello<'a> {
    pub random: &'a [u8; 32],
    pub suite: u16,
    pub group: u16,
    pub key_share: &'a [u8],
    /// The ordinary ServerHello parser rejects HRR; use parse_hello_retry_request.
    pub hrr: bool,
    pub selected_psk: Option<u16>,
}
#[derive(Clone, Copy, Debug)]
pub struct EncryptedExtensions<'a> {
    pub alpn: &'a [u8],
    pub params: &'a [u8],
    pub early_data: bool,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DerRange {
    pub offset: usize,
    pub len: usize,
}
#[derive(Clone, Copy, Debug)]
pub struct CertificateVerify<'a> {
    pub scheme: u16,
    pub signature: &'a [u8],
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self.position.checked_add(len).ok_or(Error::Length)?;
        let bytes = self.bytes.get(self.position..end).ok_or(Error::Truncated)?;
        self.position = end;
        Ok(bytes)
    }
    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, Error> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| Error::Truncated)?,
        ))
    }
    fn u24(&mut self) -> Result<usize, Error> {
        let b = self.take(3)?;
        Ok((usize::from(b[0]) << 16) | (usize::from(b[1]) << 8) | usize::from(b[2]))
    }
    fn vector8(&mut self) -> Result<&'a [u8], Error> {
        let n = usize::from(self.u8()?);
        self.take(n)
    }
    fn vector16(&mut self) -> Result<&'a [u8], Error> {
        let n = usize::from(self.u16()?);
        self.take(n)
    }
    fn finished(&self) -> Result<(), Error> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::Length)
        }
    }
}
fn body(message: &[u8], kind: u8) -> Result<&[u8], Error> {
    let mut r = Reader::new(message);
    if r.u8()? != kind {
        return Err(Error::UnexpectedMessage);
    }
    let len = r.u24()?;
    let b = r.take(len)?;
    r.finished()?;
    Ok(b)
}
fn valid_share_group(group: u16, share: &[u8]) -> Result<(), Error> {
    match group {
        GROUP_P256 => valid_share(share),
        GROUP_X25519 if share.len() == 32 => Ok(()),
        GROUP_X25519 => Err(Error::Malformed),
        _ => Err(Error::Unsupported),
    }
}
fn valid_share(share: &[u8]) -> Result<(), Error> {
    if share.len() != 65 || share[0] != 4 {
        Err(Error::Malformed)
    } else {
        Ok(())
    }
}
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.is_ascii()
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
fn contains16(bytes: &[u8], value: u16) -> Result<bool, Error> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(2) {
        return Err(Error::Malformed);
    }
    if bytes.len() / 2 > MAX_LIST_ITEMS {
        return Err(Error::Capacity);
    }
    Ok(bytes
        .chunks_exact(2)
        .any(|b| u16::from_be_bytes([b[0], b[1]]) == value))
}
fn vector16_contains(data: &[u8], value: u16) -> Result<bool, Error> {
    let mut r = Reader::new(data);
    let list = r.vector16()?;
    r.finished()?;
    contains16(list, value)
}
fn extensions<'a>(
    bytes: &'a [u8],
    mut visit: impl FnMut(u16, &'a [u8]) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut r = Reader::new(bytes);
    let mut seen = [0_u16; MAX_EXTENSIONS];
    let mut count = 0;
    while r.position < bytes.len() {
        let kind = r.u16()?;
        let data = r.vector16()?;
        if count == MAX_EXTENSIONS {
            return Err(Error::Capacity);
        }
        if seen[..count].contains(&kind) {
            return Err(Error::DuplicateExtension);
        }
        seen[count] = kind;
        count += 1;
        visit(kind, data)?;
    }
    r.finished()
}
fn parse_sni(data: &[u8]) -> Result<&str, Error> {
    let mut r = Reader::new(data);
    let list = r.vector16()?;
    r.finished()?;
    let mut r = Reader::new(list);
    if r.u8()? != 0 {
        return Err(Error::Unsupported);
    }
    let name = core::str::from_utf8(r.vector16()?).map_err(|_| Error::Malformed)?;
    r.finished()?;
    if !valid_name(name) {
        return Err(Error::Malformed);
    }
    Ok(name)
}
fn parse_alpn(data: &[u8], server: bool) -> Result<&[u8], Error> {
    let mut r = Reader::new(data);
    let list = r.vector16()?;
    r.finished()?;
    let mut r = Reader::new(list);
    let mut found = None;
    let mut count = 0;
    while r.position < list.len() {
        count += 1;
        if count > MAX_LIST_ITEMS {
            return Err(Error::Capacity);
        }
        let name = r.vector8()?;
        if name.is_empty() {
            return Err(Error::Malformed);
        }
        if name == ALPN {
            if found.is_some() {
                return Err(Error::Malformed);
            }
            found = Some(name);
        }
    }
    if count == 0 || (server && count != 1) {
        return Err(Error::Malformed);
    }
    found.ok_or(Error::Unsupported)
}
fn check_share_groups(groups: &[u8], shares: &[u8]) -> Result<(), Error> {
    let mut r = Reader::new(groups);
    let groups = r.vector16()?;
    r.finished()?;
    contains16(groups, GROUP_P256)?;
    for (index, group) in groups.chunks_exact(2).enumerate() {
        if groups[..index * 2].chunks_exact(2).any(|old| old == group) {
            return Err(Error::Malformed);
        }
    }
    let mut r = Reader::new(shares);
    let shares = r.vector16()?;
    r.finished()?;
    let mut r = Reader::new(shares);
    let mut previous = None;
    while r.position < shares.len() {
        let group = r.u16()?;
        r.vector16()?;
        let index = groups
            .chunks_exact(2)
            .position(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]) == group)
            .ok_or(Error::Malformed)?;
        if previous.is_some_and(|prior| index <= prior) {
            return Err(Error::Malformed);
        }
        previous = Some(index);
    }
    Ok(())
}

fn parse_client_shares(data: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    let mut r = Reader::new(data);
    let list = r.vector16()?;
    r.finished()?;
    let mut r = Reader::new(list);
    let mut groups = [0_u16; MAX_LIST_ITEMS];
    let mut count = 0;
    let mut found = None;
    let mut x25519 = None;
    while r.position < list.len() {
        let group = r.u16()?;
        let share = r.vector16()?;
        if share.is_empty() {
            return Err(Error::Malformed);
        }
        if count == MAX_LIST_ITEMS {
            return Err(Error::Capacity);
        }
        if groups[..count].contains(&group) {
            return Err(Error::Malformed);
        }
        groups[count] = group;
        count += 1;
        if group == GROUP_X25519 {
            if share.len() != 32 {
                return Err(Error::Malformed);
            }
            x25519 = Some(share);
        }
        if group == GROUP_P256 {
            valid_share(share)?;
            found = Some(share);
        }
    }
    Ok((found.unwrap_or(&[]), x25519.unwrap_or(&[])))
}

/// Parse exactly one complete ClientHello. Unknown, bounded ClientHello
/// extension offers are ignored, as TLS requires. This is the initial-hello
/// parser: cookies require validate_client_hello_retry and retained CH1 state.
/// PSK/early-data/post-handshake-auth requests are not negotiated.
pub fn parse_client_hello(message: &[u8]) -> Result<ClientHello<'_>, Error> {
    parse_client_hello_context(message, false, false, false)
}
/// Bounded PSK_DHE offer parser. It does not authenticate the binder or ticket.
pub fn parse_client_hello_psk(message: &[u8]) -> Result<ClientHello<'_>, Error> {
    parse_client_hello_context(message, false, true, false)
}
pub fn parse_client_hello_early(message: &[u8]) -> Result<ClientHello<'_>, Error> {
    parse_client_hello_context(message, false, true, true)
}
fn parse_client_hello_context(
    message: &[u8],
    retry: bool,
    allow_psk: bool,
    allow_early: bool,
) -> Result<ClientHello<'_>, Error> {
    let mut r = Reader::new(body(message, 1)?);
    if r.u16()? != 0x0303 {
        return Err(Error::Unsupported);
    }
    let random = r.take(32)?.try_into().map_err(|_| Error::Malformed)?;
    if !r.vector8()?.is_empty() {
        return Err(Error::Unsupported);
    }
    let suites = r.vector16()?;
    let offers_1301 = contains16(suites, 0x1301)?;
    let offers_1303 = contains16(suites, 0x1303)?;
    if !offers_1301 && !offers_1303 {
        return Err(Error::Unsupported);
    }
    if r.vector8()? != [0] {
        return Err(Error::Malformed);
    }
    let ext = r.vector16()?;
    r.finished()?;
    let mut version = false;
    let mut group = false;
    let mut group_x25519 = false;
    let mut group_offer = None;
    let mut share_offer = None;
    let mut signature = false;
    let mut share = None;
    let mut sni = None;
    let mut alpn = None;
    let mut params = None;
    let mut cookie = None;
    let mut psk = None;
    let mut psk_dhe_ke = false;
    let mut early_data = false;
    let mut extension_end = 0;
    extensions(ext, |kind, data| {
        extension_end += 4 + data.len();
        match kind {
            0 => sni = Some(parse_sni(data)?),
            10 => {
                group = vector16_contains(data, GROUP_P256)?;
                group_x25519 = vector16_contains(data, GROUP_X25519)?;
                group_offer = Some(data);
            }
            13 => signature = vector16_contains(data, SIGNATURE_P256_SHA256)?,
            50 => {
                // Certificate-signature offers are a separate vector. They do
                // not authorize PKCS1 for TLS1.3 CertificateVerify.
                vector16_contains(data, SIGNATURE_P256_SHA256)?;
            }
            16 => alpn = Some(parse_alpn(data, false)?),
            21 if data.iter().any(|byte| *byte != 0) => return Err(Error::Malformed),
            43 => {
                let mut versions = Reader::new(data);
                let list = versions.vector8()?;
                versions.finished()?;
                version = contains16(list, 0x0304)?;
            }
            51 => {
                share = Some(parse_client_shares(data)?);
                share_offer = Some(data);
            }
            57 => params = Some(data),
            44 if retry => cookie = Some(parse_cookie(data)?),
            41 if allow_psk => {
                if extension_end != ext.len() {
                    return Err(Error::Malformed);
                }
                psk = Some(parse_psk_offer(data, message.len() - data.len())?);
            }
            42 if allow_early && !retry => {
                if !data.is_empty() {
                    return Err(Error::Malformed);
                }
                early_data = true;
            }
            41 | 42 | 44 | 49 => return Err(Error::Unsupported),
            // Offered modes alone do not establish a PSK. The legacy wrapper
            // ignores valid offers; the PSK parser requires mode1 with an identity.
            45 => {
                let mut modes = Reader::new(data);
                let list = modes.vector8()?;
                modes.finished()?;
                if list.is_empty() {
                    return Err(Error::Malformed);
                }
                psk_dhe_ke = list.contains(&1);
                // RFC8701 §3.2: unknown offered modes (including GREASE)
                // must be ignored, never negotiated. This profile does not
                // negotiate any unknown mode. Legacy parsing still rejects PSK.
            }
            _ => {}
        }
        Ok(())
    })?;
    if !version || !signature {
        return Err(Error::MissingExtension);
    }
    if early_data && psk.is_none() {
        return Err(Error::MissingExtension);
    }
    if psk.is_some() && !psk_dhe_ke {
        return Err(Error::Unsupported);
    }
    check_share_groups(
        group_offer.ok_or(Error::MissingExtension)?,
        share_offer.ok_or(Error::MissingExtension)?,
    )?;
    Ok(ClientHello {
        random,
        key_share: share.ok_or(Error::MissingExtension)?.0,
        key_share_x25519: share.ok_or(Error::MissingExtension)?.1,
        supports_x25519: group_x25519,
        supports_p256: group,
        cookie,
        server_name: sni,
        offers_1301,
        offers_1303,
        signature_0403: signature,
        alpn: alpn.ok_or(Error::MissingExtension)?,
        params: params.ok_or(Error::MissingExtension)?,
        psk,
        psk_dhe_ke,
        early_data,
    })
}

fn parse_psk_offer(data: &[u8], base: usize) -> Result<PskOffer<'_>, Error> {
    let mut r = Reader::new(data);
    let mut identities = Reader::new(r.vector16()?);
    let identity = identities.vector16()?;
    check_psk_identity(identity)?;
    let obfuscated_age = identities.u32()?;
    identities.finished()?; // This bounded profile accepts exactly one identity.
    let binder_prefix = base + r.position;
    let mut binders = Reader::new(r.vector16()?);
    let binder = binders.vector8()?;
    if binder.len() != 32 {
        return Err(Error::Unsupported);
    }
    binders.finished()?;
    r.finished()?;
    Ok(PskOffer {
        identity,
        obfuscated_age,
        binder,
        binder_prefix,
        binder_offset: binder_prefix + 3,
    })
}
fn check_psk_identity(identity: &[u8]) -> Result<(), Error> {
    if identity.is_empty() {
        return Err(Error::Malformed);
    }
    if identity.len() > MAX_PSK_IDENTITY_BYTES {
        return Err(Error::Capacity);
    }
    Ok(())
}

/// Validate a post-handshake NewSessionTicket before discarding it. No ticket
/// or PSK is returned or cached. Unknown NST extensions are ignored per RFC8446
/// §4.6.1; framing, duplicate extensions and the QUIC early_data sentinel remain
/// mandatory even when the client elects not to retain tickets.
pub fn validate_new_session_ticket(message: &[u8]) -> Result<(), Error> {
    parse_new_session_ticket(message).map(|_| ())
}
/// Structural parsing only: cache policy must reject expired/excessive lifetimes.
/// A valid QUIC early_data sentinel is reported, never negotiated by this parser.
pub fn parse_new_session_ticket(message: &[u8]) -> Result<NewSessionTicket<'_>, Error> {
    let mut r = Reader::new(body(message, 4)?);
    let lifetime_seconds = r.u32()?;
    let age_add = r.u32()?;
    let nonce = r.vector8()?;
    let ticket = r.vector16()?;
    if ticket.is_empty() {
        return Err(Error::Malformed);
    }
    let ext = r.vector16()?;
    r.finished()?;
    let mut early_data = false;
    extensions(ext, |kind, value| {
        match kind {
            42 => {
                if value.len() != 4 {
                    return Err(Error::Malformed);
                }
                if value != [0xff; 4] {
                    return Err(Error::InvalidQuicEarlyData);
                }
                early_data = true;
            }
            0 | 10 | 13 | 16 | 41 | 43 | 44 | 45 | 49 | 51 | 57 => return Err(Error::Unsupported),
            _ => {}
        }
        Ok(())
    })?;
    Ok(NewSessionTicket {
        lifetime_seconds,
        age_add,
        nonce,
        ticket,
        early_data,
    })
}

fn parse_cookie(data: &[u8]) -> Result<&[u8], Error> {
    let mut r = Reader::new(data);
    let cookie = r.vector16()?;
    r.finished()?;
    check_cookie(cookie)?;
    Ok(cookie)
}
fn check_cookie(cookie: &[u8]) -> Result<(), Error> {
    if cookie.is_empty() {
        Err(Error::Malformed)
    } else if cookie.len() > MAX_COOKIE_BYTES {
        Err(Error::Capacity)
    } else {
        Ok(())
    }
}

/// Recognize the reserved random before parsing. Deliberately does not validate
/// framing: an apparent but malformed HRR must fail its parser, not fall back to
/// ordinary ServerHello processing.
pub fn is_hello_retry_request(message: &[u8]) -> bool {
    message.first() == Some(&2) && message.get(6..38) == Some(HRR_RANDOM.as_slice())
}

/// Parse HRR syntax only. The provider must also bind this to CH1 with
/// validate_hello_retry_request, reject a second HRR and enforce suite/version
/// continuity in the eventual ServerHello.
pub fn parse_hello_retry_request(message: &[u8]) -> Result<HelloRetryRequest<'_>, Error> {
    let mut r = Reader::new(body(message, 2)?);
    if r.u16()? != 0x0303 {
        return Err(Error::Unsupported);
    }
    if r.take(32)? != HRR_RANDOM {
        return Err(Error::UnexpectedMessage);
    }
    if !r.vector8()?.is_empty() {
        return Err(Error::Unsupported);
    }
    let suite = r.u16()?;
    if !matches!(suite, 0x1301 | 0x1303) {
        return Err(Error::Unsupported);
    }
    if r.u8()? != 0 {
        return Err(Error::Malformed);
    }
    let ext = r.vector16()?;
    r.finished()?;
    let mut version = false;
    let mut selected_group = None;
    let mut cookie = None;
    extensions(ext, |kind, data| {
        match kind {
            43 => {
                if data != [3, 4] {
                    return Err(Error::Unsupported);
                }
                version = true;
            }
            44 => cookie = Some(parse_cookie(data)?),
            51 => {
                let mut group = Reader::new(data);
                let selected = group.u16()?;
                group.finished()?;
                if !matches!(selected, GROUP_P256 | GROUP_X25519) {
                    return Err(Error::Unsupported);
                }
                selected_group = Some(selected);
            }
            _ => return Err(Error::Unsupported),
        }
        Ok(())
    })?;
    if !version {
        return Err(Error::MissingExtension);
    }
    let retry = HelloRetryRequest {
        suite,
        selected_group,
        cookie,
    };
    check_retry(&retry)?;
    Ok(retry)
}

fn check_retry(retry: &HelloRetryRequest<'_>) -> Result<(), Error> {
    if !matches!(retry.suite, 0x1301 | 0x1303)
        || retry
            .selected_group
            .is_some_and(|group| !matches!(group, GROUP_P256 | GROUP_X25519))
    {
        return Err(Error::Unsupported);
    }
    if let Some(cookie) = retry.cookie {
        check_cookie(cookie)?;
    }
    if retry.selected_group.is_none() && retry.cookie.is_none() {
        return Err(Error::Malformed);
    }
    Ok(())
}

/// Check the HRR against the complete initial ClientHello. A selected group
/// already shared by the client is illegal even if HRR also contains a cookie.
pub fn validate_hello_retry_request(
    first: &[u8],
    retry: &HelloRetryRequest<'_>,
) -> Result<(), Error> {
    validate_hello_retry_request_context(first, retry, false, false)
}
pub fn validate_hello_retry_request_psk(
    first: &[u8],
    retry: &HelloRetryRequest<'_>,
) -> Result<(), Error> {
    validate_hello_retry_request_context(first, retry, true, false)
}
pub fn validate_hello_retry_request_early(
    first: &[u8],
    retry: &HelloRetryRequest<'_>,
) -> Result<(), Error> {
    validate_hello_retry_request_context(first, retry, true, true)
}
fn validate_hello_retry_request_context(
    first: &[u8],
    retry: &HelloRetryRequest<'_>,
    allow_psk: bool,
    allow_early: bool,
) -> Result<(), Error> {
    check_retry(retry)?;
    let hello = parse_client_hello_context(first, false, allow_psk, allow_early)?;
    if !(retry.suite == 0x1301 && hello.offers_1301 || retry.suite == 0x1303 && hello.offers_1303) {
        return Err(Error::Malformed);
    }
    if let Some(group) = retry.selected_group {
        let (supported, already_shared) = match group {
            GROUP_P256 => (hello.supports_p256, !hello.key_share.is_empty()),
            GROUP_X25519 => (hello.supports_x25519, !hello.key_share_x25519.is_empty()),
            _ => return Err(Error::Unsupported),
        };
        if !supported || already_shared {
            return Err(Error::Malformed);
        }
    }
    Ok(())
}

// Return the body prefix through compression methods, and extension contents.
// The complete message has already been profile-validated by each caller.
fn client_hello_parts(message: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    let b = body(message, 1)?;
    let mut r = Reader::new(b);
    r.take(34)?;
    r.vector8()?;
    r.vector16()?;
    r.vector8()?;
    let prefix_end = r.position;
    let ext = r.vector16()?;
    r.finished()?;
    Ok((&b[..prefix_end], ext))
}
fn stable_extension<'a>(
    reader: &mut Reader<'a>,
    replace_share: bool,
    allow_psk: bool,
    allow_early: bool,
) -> Result<Option<(u16, &'a [u8])>, Error> {
    while reader.position < reader.bytes.len() {
        let kind = reader.u16()?;
        let data = reader.vector16()?;
        if kind == 21
            || kind == 44
            || (kind == 51 && replace_share)
            || (kind == 41 && allow_psk)
            || (kind == 42 && allow_early)
        {
            continue;
        }
        return Ok(Some((kind, data)));
    }
    Ok(None)
}

/// Validate CH2 against retained CH1 and the actual HRR. All unchanged fields
/// and extensions (including unknown offers) must remain byte-for-byte equal
/// and in order. Only requested key_share replacement, exact cookie echo and
/// zero padding changes are permitted. No PSK/early-data relaxation is made.
/// The provider separately enforces message order and one-HRR-per-connection.
pub fn validate_client_hello_retry<'a>(
    first: &[u8],
    second: &'a [u8],
    retry: &HelloRetryRequest<'_>,
) -> Result<ClientHello<'a>, Error> {
    validate_client_hello_retry_context(first, second, retry, false, false)
}
/// PSK-aware CH2 validation still preserves the exact single identity. Only its
/// age and binder bytes may change; binder authentication belongs to Provider.
pub fn validate_client_hello_retry_psk<'a>(
    first: &[u8],
    second: &'a [u8],
    retry: &HelloRetryRequest<'_>,
) -> Result<ClientHello<'a>, Error> {
    validate_client_hello_retry_context(first, second, retry, true, false)
}
pub fn validate_client_hello_retry_early<'a>(
    first: &[u8],
    second: &'a [u8],
    retry: &HelloRetryRequest<'_>,
) -> Result<ClientHello<'a>, Error> {
    validate_client_hello_retry_context(first, second, retry, true, true)
}
fn validate_client_hello_retry_context<'a>(
    first: &[u8],
    second: &'a [u8],
    retry: &HelloRetryRequest<'_>,
    allow_psk: bool,
    allow_early: bool,
) -> Result<ClientHello<'a>, Error> {
    validate_hello_retry_request_context(first, retry, allow_psk, allow_early)?;
    let original = parse_client_hello_context(first, false, allow_psk, allow_early)?;
    let hello = parse_client_hello_context(second, true, allow_psk, allow_early)?;
    match (original.psk, hello.psk) {
        (None, None) => {}
        (Some(a), Some(b)) if a.identity == b.identity => {}
        _ => return Err(Error::Malformed),
    }
    if hello.cookie != retry.cookie {
        return Err(Error::Malformed);
    }
    let (first_prefix, first_ext) = client_hello_parts(first)?;
    let (second_prefix, second_ext) = client_hello_parts(second)?;
    if first_prefix != second_prefix {
        return Err(Error::Malformed);
    }
    if retry.selected_group.is_some() {
        let mut selected = false;
        extensions(second_ext, |kind, data| {
            if kind == 51 {
                let mut r = Reader::new(data);
                let list = r.vector16()?;
                r.finished()?;
                let mut r = Reader::new(list);
                let group = retry.selected_group.ok_or(Error::Malformed)?;
                if r.u16()? != group {
                    return Err(Error::Malformed);
                }
                valid_share_group(group, r.vector16()?)?;
                r.finished()?;
                selected = true;
            }
            Ok(())
        })?;
        if !selected {
            return Err(Error::MissingExtension);
        }
    }
    let mut first = Reader::new(first_ext);
    let mut second = Reader::new(second_ext);
    loop {
        let a = stable_extension(
            &mut first,
            retry.selected_group.is_some(),
            allow_psk,
            allow_early,
        )?;
        let b = stable_extension(
            &mut second,
            retry.selected_group.is_some(),
            allow_psk,
            allow_early,
        )?;
        if a != b {
            return Err(Error::Malformed);
        }
        if a.is_none() {
            return Ok(hello);
        }
    }
}

pub fn parse_server_hello(message: &[u8]) -> Result<ServerHello<'_>, Error> {
    parse_server_hello_context(message, false)
}
/// Parse selected identity0 with mandatory fresh DHE. Provider must bind it to
/// an actually offered PSK and the associated hash/cipher suite.
pub fn parse_server_hello_psk(message: &[u8]) -> Result<ServerHello<'_>, Error> {
    parse_server_hello_context(message, true)
}
fn parse_server_hello_context(message: &[u8], allow_psk: bool) -> Result<ServerHello<'_>, Error> {
    let mut r = Reader::new(body(message, 2)?);
    if r.u16()? != 0x0303 {
        return Err(Error::Unsupported);
    }
    let random: &[u8; 32] = r.take(32)?.try_into().map_err(|_| Error::Malformed)?;
    if random == &HRR_RANDOM {
        return Err(Error::Unsupported);
    }
    if !r.vector8()?.is_empty() {
        return Err(Error::Unsupported);
    }
    let suite = r.u16()?;
    if !matches!(suite, 0x1301 | 0x1303) {
        return Err(Error::Unsupported);
    }
    if r.u8()? != 0 {
        return Err(Error::Malformed);
    }
    let ext = r.vector16()?;
    r.finished()?;
    let mut version = false;
    let mut key_share = None;
    let mut key_group = None;
    let mut selected_psk = None;
    extensions(ext, |kind, data| {
        match kind {
            43 => {
                if data != [3, 4] {
                    return Err(Error::Unsupported);
                }
                version = true;
            }
            51 => {
                let mut s = Reader::new(data);
                let selected_group = s.u16()?;
                if !matches!(selected_group, GROUP_P256 | GROUP_X25519) {
                    return Err(Error::Unsupported);
                }
                let share = s.vector16()?;
                s.finished()?;
                if selected_group == GROUP_P256 {
                    valid_share(share)?;
                } else if share.len() != 32 {
                    return Err(Error::Malformed);
                }
                key_group = Some(selected_group);
                key_share = Some(share);
            }
            41 if allow_psk => {
                let mut selected = Reader::new(data);
                let identity = selected.u16()?;
                selected.finished()?;
                if identity != 0 {
                    return Err(Error::Malformed);
                }
                selected_psk = Some(identity);
            }
            _ => return Err(Error::Unsupported),
        }
        Ok(())
    })?;
    if !version {
        return Err(Error::MissingExtension);
    }
    Ok(ServerHello {
        random,
        suite,
        group: key_group.ok_or(Error::MissingExtension)?,
        key_share: key_share.ok_or(Error::MissingExtension)?,
        hrr: false,
        selected_psk,
    })
}

pub fn parse_encrypted_extensions(message: &[u8]) -> Result<EncryptedExtensions<'_>, Error> {
    parse_encrypted_extensions_context(message, false)
}
pub fn parse_encrypted_extensions_early(message: &[u8]) -> Result<EncryptedExtensions<'_>, Error> {
    parse_encrypted_extensions_context(message, true)
}
fn parse_encrypted_extensions_context(
    message: &[u8],
    allow_early: bool,
) -> Result<EncryptedExtensions<'_>, Error> {
    let mut r = Reader::new(body(message, 8)?);
    let ext = r.vector16()?;
    r.finished()?;
    let mut alpn = None;
    let mut params = None;
    let mut early_data = false;
    extensions(ext, |kind, data| {
        match kind {
            0 => {
                if !data.is_empty() {
                    return Err(Error::Malformed);
                }
            }
            10 => {
                let mut groups = Reader::new(data);
                let list = groups.vector16()?;
                groups.finished()?;
                contains16(list, GROUP_P256)?;
            }
            16 => alpn = Some(parse_alpn(data, true)?),
            57 => params = Some(data),
            42 if allow_early => {
                if !data.is_empty() {
                    return Err(Error::Malformed);
                }
                early_data = true;
            }
            _ => return Err(Error::Unsupported),
        }
        Ok(())
    })?;
    Ok(EncryptedExtensions {
        alpn: alpn.ok_or(Error::MissingExtension)?,
        params: params.ok_or(Error::MissingExtension)?,
        early_data,
    })
}

/// Fill leaf-first DER byte ranges, relative to the whole input message. All
/// ranges are valid only on Ok; the output may be partially written on error.
/// ASN.1/signatures/trust are deliberately handled by the certificate verifier.
pub fn parse_certificate(message: &[u8], ranges: &mut [DerRange]) -> Result<usize, Error> {
    let data = body(message, 11)?;
    let mut r = Reader::new(data);
    if !r.vector8()?.is_empty() {
        return Err(Error::Unsupported);
    }
    let list_len = r.u24()?;
    let list_start = r.position;
    let list = r.take(list_len)?;
    r.finished()?;
    let mut certs = Reader::new(list);
    let mut count = 0;
    while certs.position < list.len() {
        if count >= MAX_CERTIFICATES || count >= ranges.len() {
            return Err(Error::Capacity);
        }
        let len = certs.u24()?;
        if len == 0 {
            return Err(Error::Malformed);
        }
        let offset = 4 + list_start + certs.position;
        certs.take(len)?;
        if !certs.vector16()?.is_empty() {
            return Err(Error::Unsupported);
        }
        ranges[count] = DerRange { offset, len };
        count += 1;
    }
    if count == 0 {
        return Err(Error::Malformed);
    }
    Ok(count)
}
pub fn parse_certificate_verify(message: &[u8]) -> Result<CertificateVerify<'_>, Error> {
    let mut r = Reader::new(body(message, 15)?);
    let scheme = r.u16()?;
    if !matches!(
        scheme,
        SIGNATURE_P256_SHA256 | SIGNATURE_RSA_PSS_RSAE_SHA256
    ) {
        return Err(Error::Unsupported);
    }
    let signature = r.vector16()?;
    r.finished()?;
    let valid_length = match scheme {
        SIGNATURE_P256_SHA256 => !signature.is_empty() && signature.len() <= 72,
        SIGNATURE_RSA_PSS_RSAE_SHA256 => matches!(signature.len(), 256 | 384 | 512),
        _ => false,
    };
    if !valid_length {
        return Err(Error::Malformed);
    }
    Ok(CertificateVerify { scheme, signature })
}
pub fn parse_finished(message: &[u8]) -> Result<&[u8; 32], Error> {
    body(message, 20)?.try_into().map_err(|_| Error::Length)
}

struct Writer<'a> {
    out: &'a mut [u8],
    position: usize,
}
impl Writer<'_> {
    fn bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let end = self
            .position
            .checked_add(bytes.len())
            .ok_or(Error::Length)?;
        self.out
            .get_mut(self.position..end)
            .ok_or(Error::BufferTooSmall)?
            .copy_from_slice(bytes);
        self.position = end;
        Ok(())
    }
    fn u8(&mut self, n: usize) -> Result<(), Error> {
        self.bytes(&[u8::try_from(n).map_err(|_| Error::Length)?])
    }
    fn u16(&mut self, n: usize) -> Result<(), Error> {
        self.bytes(&u16::try_from(n).map_err(|_| Error::Length)?.to_be_bytes())
    }
    fn u24(&mut self, n: usize) -> Result<(), Error> {
        if n > 0xff_ffff {
            return Err(Error::Length);
        }
        self.bytes(&[(n >> 16) as u8, (n >> 8) as u8, n as u8])
    }
    fn vector(
        &mut self,
        width: usize,
        body: impl FnOnce(&mut Self) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let start = self.position;
        self.bytes(&[0; 3][..width])?;
        body(self)?;
        let len = self.position - start - width;
        match width {
            1 => {
                self.out[start] = u8::try_from(len).map_err(|_| Error::Length)?;
            }
            2 => {
                self.out[start..start + 2]
                    .copy_from_slice(&u16::try_from(len).map_err(|_| Error::Length)?.to_be_bytes());
            }
            3 => {
                if len > 0xff_ffff {
                    return Err(Error::Length);
                }
                self.out[start..start + 3].copy_from_slice(&[
                    (len >> 16) as u8,
                    (len >> 8) as u8,
                    len as u8,
                ]);
            }
            _ => return Err(Error::Length),
        }
        Ok(())
    }
    fn extension(
        &mut self,
        kind: u16,
        body: impl FnOnce(&mut Self) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.u16(usize::from(kind))?;
        self.vector(2, body)
    }
}
fn encode(
    out: &mut [u8],
    kind: u8,
    body: impl FnOnce(&mut Writer<'_>) -> Result<(), Error>,
) -> Result<usize, Error> {
    let mut w = Writer { out, position: 0 };
    w.u8(usize::from(kind))?;
    w.vector(3, body)?;
    Ok(w.position)
}
fn encode_alpn(w: &mut Writer<'_>, alpn: &[u8]) -> Result<(), Error> {
    w.extension(16, |w| w.vector(2, |w| w.vector(1, |w| w.bytes(alpn))))
}

pub fn encode_client_hello(
    out: &mut [u8],
    random: &[u8; 32],
    share: &[u8; 65],
    server_name: &str,
    alpn: &[u8],
    params: &[u8],
) -> Result<usize, Error> {
    encode_client_hello_inner(
        out,
        random,
        share,
        None,
        server_name,
        alpn,
        params,
        false,
        None,
        CipherPolicy::Default,
        false,
    )
}
#[allow(clippy::too_many_arguments)]
pub fn encode_client_hello_dual(
    out: &mut [u8],
    random: &[u8; 32],
    share: &[u8; 65],
    x25519: &[u8; 32],
    server_name: &str,
    alpn: &[u8],
    params: &[u8],
) -> Result<usize, Error> {
    encode_client_hello_inner(
        out,
        random,
        share,
        Some(x25519),
        server_name,
        alpn,
        params,
        false,
        None,
        CipherPolicy::Default,
        false,
    )
}
/// Advertise PSK_DHE support and optionally one identity. The returned message
/// has an all-zero binder; fill it through the parsed offset before transmission.
#[allow(clippy::too_many_arguments)]
pub fn encode_client_hello_dual_psk(
    out: &mut [u8],
    random: &[u8; 32],
    share: &[u8; 65],
    x25519: &[u8; 32],
    name: &str,
    alpn: &[u8],
    params: &[u8],
    offer: Option<(&[u8], u32)>,
) -> Result<usize, Error> {
    encode_client_hello_inner(
        out,
        random,
        share,
        Some(x25519),
        name,
        alpn,
        params,
        true,
        offer,
        CipherPolicy::Default,
        false,
    )
}
/// Encode a policy-constrained ClientHello before transcript/binder processing.
#[allow(clippy::too_many_arguments)]
pub fn encode_client_hello_dual_with_policy(
    out: &mut [u8],
    random: &[u8; 32],
    share: &[u8; 65],
    x25519: &[u8; 32],
    name: &str,
    alpn: &[u8],
    params: &[u8],
    policy: CipherPolicy,
) -> Result<usize, Error> {
    encode_client_hello_inner(
        out,
        random,
        share,
        Some(x25519),
        name,
        alpn,
        params,
        false,
        None,
        policy,
        false,
    )
}
/// The binder is still all-zero and must be filled by the provider.
#[allow(clippy::too_many_arguments)]
pub fn encode_client_hello_dual_psk_with_policy(
    out: &mut [u8],
    random: &[u8; 32],
    share: &[u8; 65],
    x25519: &[u8; 32],
    name: &str,
    alpn: &[u8],
    params: &[u8],
    offer: Option<(&[u8], u32)>,
    policy: CipherPolicy,
) -> Result<usize, Error> {
    encode_client_hello_inner(
        out,
        random,
        share,
        Some(x25519),
        name,
        alpn,
        params,
        true,
        offer,
        policy,
        false,
    )
}
#[allow(clippy::too_many_arguments)]
pub fn encode_client_hello_dual_early_with_policy(
    out: &mut [u8],
    random: &[u8; 32],
    share: &[u8; 65],
    x25519: &[u8; 32],
    name: &str,
    alpn: &[u8],
    params: &[u8],
    offer: Option<(&[u8], u32)>,
    early: bool,
    policy: CipherPolicy,
) -> Result<usize, Error> {
    encode_client_hello_inner(
        out,
        random,
        share,
        Some(x25519),
        name,
        alpn,
        params,
        true,
        offer,
        policy,
        early,
    )
}
#[allow(clippy::too_many_arguments)]
pub fn encode_client_hello_dual_early(
    out: &mut [u8],
    random: &[u8; 32],
    share: &[u8; 65],
    x25519: &[u8; 32],
    name: &str,
    alpn: &[u8],
    params: &[u8],
    offer: Option<(&[u8], u32)>,
    early: bool,
) -> Result<usize, Error> {
    encode_client_hello_dual_early_with_policy(
        out,
        random,
        share,
        x25519,
        name,
        alpn,
        params,
        offer,
        early,
        CipherPolicy::Default,
    )
}
fn encode_psk_offer(w: &mut Writer<'_>, identity: &[u8], age: u32) -> Result<(), Error> {
    check_psk_identity(identity)?;
    w.extension(41, |w| {
        w.vector(2, |w| {
            w.vector(2, |w| w.bytes(identity))?;
            w.bytes(&age.to_be_bytes())
        })?;
        w.vector(2, |w| w.vector(1, |w| w.bytes(&[0; 32])))
    })
}
#[allow(clippy::too_many_arguments)]
fn encode_client_hello_inner(
    out: &mut [u8],
    random: &[u8; 32],
    share: &[u8; 65],
    x25519: Option<&[u8; 32]>,
    server_name: &str,
    alpn: &[u8],
    params: &[u8],
    psk_modes: bool,
    offer: Option<(&[u8], u32)>,
    policy: CipherPolicy,
    early: bool,
) -> Result<usize, Error> {
    if early && offer.is_none() {
        return Err(Error::MissingExtension);
    }
    valid_share(share)?;
    if let Some((identity, _)) = offer {
        check_psk_identity(identity)?;
    }
    if !valid_name(server_name) {
        return Err(Error::Malformed);
    }
    if alpn != ALPN {
        return Err(Error::Unsupported);
    }
    encode(out, 1, |w| {
        w.u16(0x0303)?;
        w.bytes(random)?;
        w.u8(0)?;
        w.vector(2, |w| {
            for suite in policy.suites() {
                w.u16(usize::from(*suite))?;
            }
            Ok(())
        })?;
        w.bytes(&[1, 0])?;
        w.vector(2, |w| {
            w.extension(0, |w| {
                w.vector(2, |w| {
                    w.u8(0)?;
                    w.vector(2, |w| w.bytes(server_name.as_bytes()))
                })
            })?;
            w.extension(10, |w| {
                w.vector(2, |w| {
                    if x25519.is_some() {
                        w.u16(usize::from(GROUP_X25519))?;
                    }
                    w.u16(usize::from(GROUP_P256))
                })
            })?;
            w.extension(13, |w| {
                w.vector(2, |w| {
                    w.u16(usize::from(SIGNATURE_P256_SHA256))?;
                    w.u16(usize::from(SIGNATURE_RSA_PSS_RSAE_SHA256))
                })
            })?;
            w.extension(50, |w| {
                w.vector(2, |w| {
                    w.u16(usize::from(SIGNATURE_P256_SHA256))?;
                    w.u16(usize::from(SIGNATURE_RSA_PSS_RSAE_SHA256))?;
                    w.u16(usize::from(SIGNATURE_RSA_PKCS1_SHA256))
                })
            })?;
            encode_alpn(w, alpn)?;
            w.extension(43, |w| w.bytes(&[2, 3, 4]))?;
            w.extension(51, |w| {
                w.vector(2, |w| {
                    if let Some(x25519) = x25519 {
                        w.u16(usize::from(GROUP_X25519))?;
                        w.vector(2, |w| w.bytes(x25519))?;
                    }
                    w.u16(usize::from(GROUP_P256))?;
                    w.vector(2, |w| w.bytes(share))
                })
            })?;
            if psk_modes {
                w.extension(45, |w| w.bytes(&[1, 1]))?;
            }
            w.extension(57, |w| w.bytes(params))?;
            if early {
                w.extension(42, |_| Ok(()))?;
            }
            if let Some((identity, age)) = offer {
                encode_psk_offer(w, identity, age)?;
            }
            Ok(())
        })
    })
}
/// Encode a legal response to the supplied complete initial ClientHello.
/// Cookie-only retries keep its key share unchanged; selected-group retries
/// replace the vector with one fresh P-256 share. The provider owns that share's
/// private key and the HRR transcript transformation.
pub fn encode_client_hello_retry(
    out: &mut [u8],
    first: &[u8],
    share: &[u8; 65],
    retry: &HelloRetryRequest<'_>,
) -> Result<usize, Error> {
    encode_client_hello_retry_with_share(out, first, share, retry)
}
pub fn encode_client_hello_retry_with_share(
    out: &mut [u8],
    first: &[u8],
    share: &[u8],
    retry: &HelloRetryRequest<'_>,
) -> Result<usize, Error> {
    validate_hello_retry_request(first, retry)?;
    if let Some(group) = retry.selected_group {
        valid_share_group(group, share)?;
    }
    let (prefix, ext) = client_hello_parts(first)?;
    let n = encode(out, 1, |w| {
        w.bytes(prefix)?;
        w.vector(2, |w| {
            extensions(ext, |kind, data| {
                if kind == 51 && retry.selected_group.is_some() {
                    w.extension(51, |w| {
                        w.vector(2, |w| {
                            w.u16(usize::from(retry.selected_group.ok_or(Error::Malformed)?))?;
                            w.vector(2, |w| w.bytes(share))
                        })
                    })
                } else {
                    w.extension(kind, |w| w.bytes(data))
                }
            })?;
            if let Some(cookie) = retry.cookie {
                w.extension(44, |w| w.vector(2, |w| w.bytes(cookie)))?;
            }
            Ok(())
        })
    })?;
    // In particular enforce the same extension-count limit after adding a
    // cookie; encoders never authorize an output their parser cannot accept.
    validate_client_hello_retry(first, &out[..n], retry)?;
    Ok(n)
}

pub fn encode_hello_retry_request(
    out: &mut [u8],
    suite: u16,
    selected_group: Option<u16>,
    cookie: Option<&[u8]>,
) -> Result<usize, Error> {
    check_retry(&HelloRetryRequest {
        suite,
        selected_group,
        cookie,
    })?;
    encode(out, 2, |w| {
        w.u16(0x0303)?;
        w.bytes(&HRR_RANDOM)?;
        w.u8(0)?;
        w.u16(usize::from(suite))?;
        w.u8(0)?;
        w.vector(2, |w| {
            w.extension(43, |w| w.bytes(&[3, 4]))?;
            if let Some(group) = selected_group {
                w.extension(51, |w| w.u16(usize::from(group)))?;
            }
            if let Some(cookie) = cookie {
                w.extension(44, |w| w.vector(2, |w| w.bytes(cookie)))?;
            }
            Ok(())
        })
    })
}

/// CH2 preserves the entire original offer except the requested key share,
/// cookie, and PSK age/binder. The new binder is zero until Provider computes it.
pub fn encode_client_hello_retry_psk(
    out: &mut [u8],
    first: &[u8],
    group: u16,
    share: &[u8],
    retry: &HelloRetryRequest<'_>,
    age: u32,
) -> Result<usize, Error> {
    encode_client_hello_retry_context(out, first, group, share, retry, age, false)
}
pub fn encode_client_hello_retry_early(
    out: &mut [u8],
    first: &[u8],
    group: u16,
    share: &[u8],
    retry: &HelloRetryRequest<'_>,
    age: u32,
) -> Result<usize, Error> {
    encode_client_hello_retry_context(out, first, group, share, retry, age, true)
}
fn encode_client_hello_retry_context(
    out: &mut [u8],
    first: &[u8],
    group: u16,
    share: &[u8],
    retry: &HelloRetryRequest<'_>,
    obfuscated_age: u32,
    allow_early: bool,
) -> Result<usize, Error> {
    validate_hello_retry_request_context(first, retry, true, allow_early)?;
    if let Some(selected) = retry.selected_group {
        if selected != group {
            return Err(Error::Malformed);
        }
        valid_share_group(group, share)?;
    }
    let hello = parse_client_hello_context(first, false, true, allow_early)?;
    let (prefix, ext) = client_hello_parts(first)?;
    let n = encode(out, 1, |w| {
        w.bytes(prefix)?;
        w.vector(2, |w| {
            extensions(ext, |kind, data| {
                if kind == 41 || kind == 42 && allow_early {
                    return Ok(());
                }
                if kind == 51 && retry.selected_group.is_some() {
                    w.extension(51, |w| {
                        w.vector(2, |w| {
                            w.u16(usize::from(group))?;
                            w.vector(2, |w| w.bytes(share))
                        })
                    })
                } else {
                    w.extension(kind, |w| w.bytes(data))
                }
            })?;
            if let Some(cookie) = retry.cookie {
                w.extension(44, |w| w.vector(2, |w| w.bytes(cookie)))?;
            }
            if let Some(psk) = hello.psk {
                encode_psk_offer(w, psk.identity, obfuscated_age)?;
            }
            Ok(())
        })
    })?;
    validate_client_hello_retry_context(first, &out[..n], retry, true, allow_early)?;
    Ok(n)
}

/// Server-issued NST has no early_data capability in this profile.
pub fn encode_new_session_ticket(
    out: &mut [u8],
    lifetime: u32,
    age_add: u32,
    nonce: &[u8],
    ticket: &[u8],
) -> Result<usize, Error> {
    encode_new_session_ticket_early(out, lifetime, age_add, nonce, ticket, false)
}
pub fn encode_new_session_ticket_early(
    out: &mut [u8],
    lifetime_seconds: u32,
    age_add: u32,
    nonce: &[u8],
    ticket: &[u8],
    early: bool,
) -> Result<usize, Error> {
    if lifetime_seconds > 7 * 24 * 60 * 60 || ticket.is_empty() {
        return Err(Error::Malformed);
    }
    encode(out, 4, |w| {
        w.bytes(&lifetime_seconds.to_be_bytes())?;
        w.bytes(&age_add.to_be_bytes())?;
        w.vector(1, |w| w.bytes(nonce))?;
        w.vector(2, |w| w.bytes(ticket))?;
        w.vector(2, |w| {
            if early {
                w.extension(42, |w| w.bytes(&[0xff; 4]))?;
            }
            Ok(())
        })
    })
}

pub fn encode_server_hello(
    out: &mut [u8],
    random: &[u8; 32],
    share: &[u8; 65],
    suite: u16,
) -> Result<usize, Error> {
    encode_server_hello_group(out, random, GROUP_P256, share, suite)
}
pub fn encode_server_hello_group(
    out: &mut [u8],
    random: &[u8; 32],
    group: u16,
    share: &[u8],
    suite: u16,
) -> Result<usize, Error> {
    encode_server_hello_group_psk(out, random, group, share, suite, None)
}
pub fn encode_server_hello_group_psk(
    out: &mut [u8],
    random: &[u8; 32],
    group: u16,
    share: &[u8],
    suite: u16,
    selected_psk: Option<u16>,
) -> Result<usize, Error> {
    if selected_psk.is_some_and(|identity| identity != 0) {
        return Err(Error::Malformed);
    }
    match group {
        GROUP_P256 => valid_share(share)?,
        GROUP_X25519 if share.len() == 32 => {}
        _ => return Err(Error::Unsupported),
    }
    if !matches!(suite, 0x1301 | 0x1303) || random == &HRR_RANDOM {
        return Err(Error::Unsupported);
    }
    encode(out, 2, |w| {
        w.u16(0x0303)?;
        w.bytes(random)?;
        w.u8(0)?;
        w.u16(usize::from(suite))?;
        w.u8(0)?;
        w.vector(2, |w| {
            w.extension(43, |w| w.bytes(&[3, 4]))?;
            w.extension(51, |w| {
                w.u16(usize::from(group))?;
                w.vector(2, |w| w.bytes(share))
            })?;
            if let Some(identity) = selected_psk {
                w.extension(41, |w| w.u16(usize::from(identity)))?;
            }
            Ok(())
        })
    })
}
pub fn encode_encrypted_extensions(
    out: &mut [u8],
    alpn: &[u8],
    params: &[u8],
) -> Result<usize, Error> {
    encode_encrypted_extensions_early(out, alpn, params, false)
}
pub fn encode_encrypted_extensions_early(
    out: &mut [u8],
    alpn: &[u8],
    params: &[u8],
    early: bool,
) -> Result<usize, Error> {
    if alpn != ALPN {
        return Err(Error::Unsupported);
    }
    encode(out, 8, |w| {
        w.vector(2, |w| {
            encode_alpn(w, alpn)?;
            w.extension(57, |w| w.bytes(params))?;
            if early {
                w.extension(42, |_| Ok(()))?;
            }
            Ok(())
        })
    })
}
pub fn encode_certificate(out: &mut [u8], chain: &[&[u8]]) -> Result<usize, Error> {
    if chain.is_empty() {
        return Err(Error::Malformed);
    }
    if chain.len() > MAX_CERTIFICATES {
        return Err(Error::Capacity);
    }
    encode(out, 11, |w| {
        w.u8(0)?;
        w.vector(3, |w| {
            for cert in chain {
                if cert.is_empty() {
                    return Err(Error::Malformed);
                }
                w.u24(cert.len())?;
                w.bytes(cert)?;
                w.u16(0)?;
            }
            Ok(())
        })
    })
}
pub fn encode_certificate_verify(
    out: &mut [u8],
    scheme: u16,
    signature: &[u8],
) -> Result<usize, Error> {
    if scheme != SIGNATURE_P256_SHA256 {
        return Err(Error::Unsupported);
    }
    if signature.is_empty() || signature.len() > 72 {
        return Err(Error::Malformed);
    }
    encode(out, 15, |w| {
        w.u16(usize::from(scheme))?;
        w.vector(2, |w| w.bytes(signature))
    })
}
pub fn encode_finished(out: &mut [u8], verify_data: &[u8; 32]) -> Result<usize, Error> {
    encode(out, 20, |w| w.bytes(verify_data))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn share() -> [u8; 65] {
        let mut key = [7; 65];
        key[0] = 4;
        key
    }
    fn length(message: &mut [u8], len: usize) {
        let body = len - 4;
        message[1..4].copy_from_slice(&[(body >> 16) as u8, (body >> 8) as u8, body as u8]);
    }
    fn ch_extensions(message: &[u8]) -> usize {
        let mut r = Reader::new(&message[4..]);
        r.take(34).unwrap();
        r.vector8().unwrap();
        r.vector16().unwrap();
        r.vector8().unwrap();
        4 + r.position
    }
    fn append_extension(
        message: &mut [u8],
        len: usize,
        at: usize,
        kind: u16,
        data: &[u8],
    ) -> usize {
        let old = u16::from_be_bytes([message[at], message[at + 1]]) as usize;
        message[len..len + 2].copy_from_slice(&kind.to_be_bytes());
        message[len + 2..len + 4].copy_from_slice(&(data.len() as u16).to_be_bytes());
        message[len + 4..len + 4 + data.len()].copy_from_slice(data);
        let new = old + 4 + data.len();
        message[at..at + 2].copy_from_slice(&(new as u16).to_be_bytes());
        let len = len + 4 + data.len();
        length(message, len);
        len
    }
    fn replace_ch_extension(
        out: &mut [u8],
        message: &[u8],
        target: u16,
        replacement: Option<&[u8]>,
    ) -> usize {
        let (prefix, ext) = client_hello_parts(message).unwrap();
        encode(out, 1, |w| {
            w.bytes(prefix)?;
            w.vector(2, |w| {
                extensions(ext, |kind, data| {
                    if kind == target {
                        if let Some(data) = replacement {
                            w.extension(kind, |w| w.bytes(data))?;
                        }
                        Ok(())
                    } else {
                        w.extension(kind, |w| w.bytes(data))
                    }
                })
            })
        })
        .unwrap()
    }
    fn x25519_first_hello(out: &mut [u8]) -> usize {
        let mut old = [0; 1024];
        let n = encode_client_hello(&mut old, &[9; 32], &share(), "localhost", ALPN, &[15, 1, 7])
            .unwrap();
        let n = replace_ch_extension(out, &old[..n], 10, Some(&[0, 4, 0, 29, 0, 23]));
        old[..n].copy_from_slice(&out[..n]);
        let mut x25519 = [5; 38];
        x25519[..6].copy_from_slice(&[0, 36, 0, 29, 0, 32]);
        replace_ch_extension(out, &old[..n], 51, Some(&x25519))
    }

    #[test]
    fn hrr_rfc_layout_cookie_and_every_truncation() {
        let mut out = [0; 512];
        let n = encode_hello_retry_request(&mut out, 0x1301, Some(GROUP_P256), None).unwrap();
        assert_eq!(n, 56);
        assert_eq!(&out[..6], &[2, 0, 0, 52, 3, 3]);
        assert_eq!(&out[6..38], &HRR_RANDOM);
        assert_eq!(
            &out[38..n],
            &[0, 19, 1, 0, 0, 12, 0, 43, 0, 2, 3, 4, 0, 51, 0, 2, 0, 23]
        );
        assert!(is_hello_retry_request(&out[..n]));
        assert!(parse_server_hello(&out[..n]).is_err());
        let hello = parse_hello_retry_request(&out[..n]).unwrap();
        assert_eq!(hello.suite, 0x1301);
        assert_eq!(hello.selected_group, Some(GROUP_P256));
        assert_eq!(hello.cookie, None);
        let cookie = [0xa5; MAX_COOKIE_BYTES];
        for group in [Some(GROUP_P256), None] {
            let n = encode_hello_retry_request(&mut out, 0x1303, group, Some(&cookie)).unwrap();
            let hello = parse_hello_retry_request(&out[..n]).unwrap();
            assert_eq!(hello.cookie, Some(cookie.as_slice()));
            assert_eq!(hello.selected_group, group);
            for end in 0..n {
                assert!(
                    parse_hello_retry_request(&out[..end]).is_err(),
                    "HRR prefix {end}"
                );
            }
            out[n] = 0;
            assert!(parse_hello_retry_request(&out[..n + 1]).is_err());
            out[3] = out[3].wrapping_add(1);
            assert!(is_hello_retry_request(&out[..n]));
            assert!(parse_hello_retry_request(&out[..n]).is_err());
        }
    }

    #[test]
    fn rfc8448_section5_hrr_cookie_vector_parses() {
        // RFC 8448 section 5, independently specified HRR with a 114-byte cookie.
        let hex = b"020000ac0303cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c001301000084003300020017002c0074007271dcd04bb88bc3189119398a00000000eefafc76c146b823b096f8aacad365dd0030953f4edf625636e5f21bb2e23fcc654b1b5b40318d10d137abcbb87574e36e8a1f025f7dfa5d6e50781b5eda4aa15b0c8be778257d16aa3030e9e7841dd9e4c0342267e8ca0caf571fb2b7cff0f934b0002b00020304";
        let mut msg = [0; 176];
        fn nibble(v: u8) -> u8 {
            if v <= b'9' { v - b'0' } else { v - b'a' + 10 }
        }
        for (b, pair) in msg.iter_mut().zip(hex.chunks_exact(2)) {
            *b = nibble(pair[0]) * 16 + nibble(pair[1]);
        }
        let hello = parse_hello_retry_request(&msg).unwrap();
        assert_eq!(hello.suite, 0x1301);
        assert_eq!(hello.selected_group, Some(GROUP_P256));
        assert_eq!(hello.cookie.unwrap().len(), 114);
        assert_eq!(&hello.cookie.unwrap()[..4], &[0x71, 0xdc, 0xd0, 0x4b]);
    }

    #[test]
    fn hrr_rejects_invalid_context_duplicates_cookie_bounds_and_noop() {
        let mut out = [0; 1024];
        assert_eq!(
            encode_hello_retry_request(&mut out, 0x1301, None, None),
            Err(Error::Malformed)
        );
        assert_eq!(
            encode_hello_retry_request(&mut out, 0x1301, None, Some(&[])),
            Err(Error::Malformed)
        );
        assert_eq!(
            encode_hello_retry_request(&mut out, 0x1301, None, Some(&[1; MAX_COOKIE_BYTES + 1])),
            Err(Error::Capacity)
        );
        assert_eq!(
            encode_hello_retry_request(&mut out, 0x1302, Some(23), None),
            Err(Error::Unsupported)
        );
        assert_eq!(
            encode_hello_retry_request(&mut out, 0x1301, Some(24), None),
            Err(Error::Unsupported)
        );
        assert_eq!(
            encode_hello_retry_request(&mut [0; 55], 0x1301, Some(23), None),
            Err(Error::BufferTooSmall)
        );
        for (kind, data) in [(43, &[3, 4][..]), (51, &[0, 23][..])] {
            let n = encode_hello_retry_request(&mut out, 0x1301, Some(23), None).unwrap();
            let n = append_extension(&mut out, n, 42, kind, data);
            assert!(matches!(
                parse_hello_retry_request(&out[..n]),
                Err(Error::DuplicateExtension)
            ));
        }
        for kind in [0, 10, 13, 16, 41, 42, 45, 57, 0x0a0a] {
            let n = encode_hello_retry_request(&mut out, 0x1301, Some(23), None).unwrap();
            let n = append_extension(&mut out, n, 42, kind, &[]);
            assert!(matches!(
                parse_hello_retry_request(&out[..n]),
                Err(Error::Unsupported)
            ));
        }
        for cookie in [&[0, 0][..], &[0, 2, 1][..], &[0, 1, 1, 2][..]] {
            let n = encode_hello_retry_request(&mut out, 0x1301, Some(23), None).unwrap();
            let n = append_extension(&mut out, n, 42, 44, cookie);
            assert!(parse_hello_retry_request(&out[..n]).is_err());
        }
        let n = encode_hello_retry_request(&mut out, 0x1301, None, Some(b"cookie")).unwrap();
        let n = append_extension(&mut out, n, 42, 44, &[0, 1, 1]);
        assert!(matches!(
            parse_hello_retry_request(&out[..n]),
            Err(Error::DuplicateExtension)
        ));
        let n = encode_hello_retry_request(&mut out, 0x1301, Some(23), None).unwrap();
        out[6] ^= 1;
        assert!(!is_hello_retry_request(&out[..n]));
        assert!(matches!(
            parse_hello_retry_request(&out[..n]),
            Err(Error::UnexpectedMessage)
        ));
        let n = encode_hello_retry_request(&mut out, 0x1301, Some(23), None).unwrap();
        out[41] = 1;
        assert!(matches!(
            parse_hello_retry_request(&out[..n]),
            Err(Error::Malformed)
        ));
        let n = encode_hello_retry_request(&mut out, 0x1301, Some(23), None).unwrap();
        out[49] = 3;
        assert!(matches!(
            parse_hello_retry_request(&out[..n]),
            Err(Error::Unsupported)
        ));
        let n = encode_hello_retry_request(&mut out, 0x1301, Some(23), None).unwrap();
        out[55] = 24;
        assert!(matches!(
            parse_hello_retry_request(&out[..n]),
            Err(Error::Unsupported)
        ));
    }

    #[test]
    fn client_hello_distinguishes_supported_group_from_available_share() {
        let mut first = [0; 1024];
        let mut changed = [0; 1024];
        let n = x25519_first_hello(&mut first);
        let hello = parse_client_hello(&first[..n]).unwrap();
        assert!(hello.supports_p256 && hello.key_share.is_empty());
        let n_empty = replace_ch_extension(&mut changed, &first[..n], 51, Some(&[0, 0]));
        let hello = parse_client_hello(&changed[..n_empty]).unwrap();
        assert!(hello.supports_p256 && hello.key_share.is_empty());
        let n_none = replace_ch_extension(&mut changed, &first[..n], 10, Some(&[0, 2, 0, 29]));
        let hello = parse_client_hello(&changed[..n_none]).unwrap();
        assert!(!hello.supports_p256 && hello.key_share.is_empty());
        let retry = HelloRetryRequest {
            suite: 0x1301,
            selected_group: Some(23),
            cookie: None,
        };
        assert!(validate_hello_retry_request(&changed[..n_none], &retry).is_err());
        let n_missing = replace_ch_extension(&mut changed, &first[..n], 51, None);
        assert!(matches!(
            parse_client_hello(&changed[..n_missing]),
            Err(Error::MissingExtension)
        ));
    }

    #[test]
    fn selected_group_retry_preserves_invariants_and_rejects_changes() {
        let mut first = [0; 1024];
        let mut second = [0; 1024];
        let mut changed = [0; 1024];
        let n = x25519_first_hello(&mut first);
        let at = ch_extensions(&first[..n]);
        let n = append_extension(&mut first, n, at, 0x0a0a, &[1, 2, 3]);
        let retry = HelloRetryRequest {
            suite: 0x1301,
            selected_group: Some(23),
            cookie: Some(b"server-cookie"),
        };
        let m = encode_client_hello_retry(&mut second, &first[..n], &share(), &retry).unwrap();
        let hello = validate_client_hello_retry(&first[..n], &second[..m], &retry).unwrap();
        assert_eq!(hello.key_share, &share());
        assert_eq!(hello.cookie, retry.cookie);
        assert_eq!(hello.params, &[15, 1, 7]);
        assert!(
            parse_client_hello(&second[..m]).is_err(),
            "cookie cannot appear in CH1"
        );
        for index in [6, 39, 41] {
            changed[..m].copy_from_slice(&second[..m]);
            changed[index] ^= 1;
            assert!(validate_client_hello_retry(&first[..n], &changed[..m], &retry).is_err());
        }
        for (kind, data) in [
            (57, &[15, 1, 8][..]),
            (10, &[0, 4, 0, 23, 0, 29][..]),
            (0x0a0a, &[1, 2, 4][..]),
            (44, &[0, 1, 1][..]),
        ] {
            let k = replace_ch_extension(&mut changed, &second[..m], kind, Some(data));
            assert!(
                validate_client_hello_retry(&first[..n], &changed[..k], &retry).is_err(),
                "changed extension {kind}"
            );
        }
        for kind in [0, 10, 13, 16, 43, 44, 51, 57, 0x0a0a] {
            let k = replace_ch_extension(&mut changed, &second[..m], kind, None);
            assert!(
                validate_client_hello_retry(&first[..n], &changed[..k], &retry).is_err(),
                "removed extension {kind}"
            );
        }
        changed[..m].copy_from_slice(&second[..m]);
        let at = ch_extensions(&changed[..m]);
        let k = append_extension(&mut changed, m, at, 0x1a1a, &[]);
        assert!(validate_client_hello_retry(&first[..n], &changed[..k], &retry).is_err());
        for end in 0..m {
            assert!(validate_client_hello_retry(&first[..n], &second[..end], &retry).is_err());
        }
    }

    #[test]
    fn cookie_only_retry_keeps_share_and_same_group_retry_is_illegal() {
        let mut first = [0; 1024];
        let mut second = [0; 1024];
        let mut changed = [0; 1024];
        let n =
            encode_client_hello(&mut first, &[9; 32], &share(), "localhost", ALPN, &[]).unwrap();
        for cookie in [None, Some(&b"cookie"[..])] {
            let retry = HelloRetryRequest {
                suite: 0x1301,
                selected_group: Some(23),
                cookie,
            };
            assert_eq!(
                validate_hello_retry_request(&first[..n], &retry),
                Err(Error::Malformed)
            );
            assert!(encode_client_hello_retry(&mut second, &first[..n], &share(), &retry).is_err());
        }
        let retry = HelloRetryRequest {
            suite: 0x1303,
            selected_group: None,
            cookie: Some(b"cookie"),
        };
        let mut different_share = share();
        different_share[2] ^= 1;
        let m =
            encode_client_hello_retry(&mut second, &first[..n], &different_share, &retry).unwrap();
        let hello = validate_client_hello_retry(&first[..n], &second[..m], &retry).unwrap();
        assert_eq!(
            hello.key_share,
            &share(),
            "cookie-only cannot replace even with caller-provided share"
        );
        let mut share_data = [0; 71];
        share_data[..6].copy_from_slice(&[0, 69, 0, 23, 0, 65]);
        share_data[6..].copy_from_slice(&different_share);
        let k = replace_ch_extension(&mut changed, &second[..m], 51, Some(&share_data));
        assert!(validate_client_hello_retry(&first[..n], &changed[..k], &retry).is_err());
        assert!(
            validate_hello_retry_request(&second[..m], &retry).is_err(),
            "CH2 cannot be reused as initial CH"
        );
        // Offered supported suites are checked, not merely this profile's list.
        first[43] = 0x13;
        first[44] = 0x02;
        assert!(parse_client_hello(&first[..n]).unwrap().offers_1301);
        assert_eq!(
            validate_hello_retry_request(&first[..n], &retry),
            Err(Error::Malformed)
        );
    }

    #[test]
    fn retry_padding_changes_allowed_but_nonzero_padding_and_extra_share_fail() {
        let mut first = [0; 1024];
        let mut second = [0; 1024];
        let mut changed = [0; 1024];
        let n = x25519_first_hello(&mut first);
        let retry = HelloRetryRequest {
            suite: 0x1301,
            selected_group: Some(23),
            cookie: None,
        };
        let m = encode_client_hello_retry(&mut second, &first[..n], &share(), &retry).unwrap();
        let at = ch_extensions(&second[..m]);
        let m = append_extension(&mut second, m, at, 21, &[0; 64]);
        assert!(validate_client_hello_retry(&first[..n], &second[..m], &retry).is_ok());
        let k = replace_ch_extension(&mut changed, &second[..m], 21, Some(&[1]));
        assert!(validate_client_hello_retry(&first[..n], &changed[..k], &retry).is_err());
        let mut shares = [0; 107];
        shares[..6].copy_from_slice(&[0, 105, 0, 29, 0, 32]);
        shares[6..38].fill(5);
        shares[38..42].copy_from_slice(&[0, 23, 0, 65]);
        shares[42..].copy_from_slice(&share());
        let k = replace_ch_extension(&mut changed, &second[..m], 51, Some(&shares));
        assert!(parse_client_hello(&changed[..k]).is_ok());
        assert!(
            validate_client_hello_retry(&first[..n], &changed[..k], &retry).is_err(),
            "CH2 must contain just the selected share"
        );
        let at = ch_extensions(&second[..m]);
        let k = append_extension(&mut second, m, at, 41, &[]);
        assert!(validate_client_hello_retry(&first[..n], &second[..k], &retry).is_err());
    }

    #[test]
    fn client_hello_round_trip_preserves_borrowed_profile_fields() {
        let mut out = [0; 1024];
        let random = [9; 32];
        let share = share();
        let params = [15, 1, 7];
        let len =
            encode_client_hello(&mut out, &random, &share, "example.test", ALPN, &params).unwrap();
        let hello = parse_client_hello(&out[..len]).unwrap();
        assert_eq!(hello.random, &random);
        assert_eq!(hello.key_share, &share);
        assert_eq!(hello.server_name, Some("example.test"));
        assert!(hello.offers_1301 && hello.offers_1303 && hello.signature_0403);
        assert_eq!(hello.alpn, ALPN);
        assert_eq!(hello.params, &params);
    }

    #[test]
    fn rsa_certificate_algorithms_do_not_advertise_pkcs1_certificate_verify() {
        let mut out = [0; 1024];
        let n = encode_client_hello(&mut out, &[9; 32], &share(), "localhost", ALPN, &[]).unwrap();
        let (_, ext) = client_hello_parts(&out[..n]).unwrap();
        let mut seen = [false; 2];
        extensions(ext, |kind, data| {
            if kind == 13 {
                assert_eq!(data, &[0, 4, 0x04, 0x03, 0x08, 0x04]);
                assert!(!vector16_contains(data, SIGNATURE_RSA_PKCS1_SHA256)?);
                seen[0] = true;
            } else if kind == 50 {
                assert_eq!(data, &[0, 6, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01]);
                seen[1] = true;
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, [true; 2]);
        let mut changed = [0; 1024];
        for invalid in [
            &[0, 0][..],
            &[0, 1, 4][..],
            &[0, 2, 4][..],
            &[0, 2, 4, 3, 0][..],
        ] {
            let len = replace_ch_extension(&mut changed, &out[..n], 50, Some(invalid));
            assert!(parse_client_hello(&changed[..len]).is_err());
        }
    }

    #[test]
    fn rsa_certificate_verify_requires_supported_scheme_and_exact_modulus_width() {
        let mut out = [0; 1024];
        let signature = [0x5a; 600];
        for width in [256, 384, 512] {
            let n = encode(&mut out, 15, |w| {
                w.u16(usize::from(SIGNATURE_RSA_PSS_RSAE_SHA256))?;
                w.vector(2, |w| w.bytes(&signature[..width]))
            })
            .unwrap();
            let parsed = parse_certificate_verify(&out[..n]).unwrap();
            assert_eq!(parsed.scheme, SIGNATURE_RSA_PSS_RSAE_SHA256);
            assert_eq!(parsed.signature.len(), width);
            for end in 0..n {
                assert!(parse_certificate_verify(&out[..end]).is_err());
            }
        }
        for width in [0, 1, 72, 128, 255, 257, 383, 385, 511, 513] {
            let n = encode(&mut out, 15, |w| {
                w.u16(usize::from(SIGNATURE_RSA_PSS_RSAE_SHA256))?;
                w.vector(2, |w| w.bytes(&signature[..width]))
            })
            .unwrap();
            assert!(matches!(
                parse_certificate_verify(&out[..n]),
                Err(Error::Malformed)
            ));
        }
        for scheme in [SIGNATURE_RSA_PKCS1_SHA256, 0x0809, 0x0805] {
            let n = encode(&mut out, 15, |w| {
                w.u16(usize::from(scheme))?;
                w.vector(2, |w| w.bytes(&signature[..256]))
            })
            .unwrap();
            assert!(matches!(
                parse_certificate_verify(&out[..n]),
                Err(Error::Unsupported)
            ));
        }
    }
    #[test]
    fn server_hello_has_exact_rfc_layout() {
        let mut out = [0; 256];
        let random = [9; 32];
        let share = share();
        let len = encode_server_hello(&mut out, &random, &share, 0x1301).unwrap();
        assert_eq!(len, 123);
        assert_eq!(&out[..6], &[2, 0, 0, 119, 3, 3]);
        assert_eq!(&out[6..38], &random);
        assert_eq!(&out[38..44], &[0, 0x13, 1, 0, 0, 79]);
        assert_eq!(&out[44..50], &[0, 43, 0, 2, 3, 4]);
        assert_eq!(&out[50..58], &[0, 51, 0, 69, 0, 23, 0, 65]);
        assert_eq!(&out[58..123], &share);
        let hello = parse_server_hello(&out[..len]).unwrap();
        assert_eq!(hello.suite, 0x1301);
        assert_eq!(hello.group, 23);
        assert!(!hello.hrr);
        let len = encode_server_hello(&mut out, &random, &share, 0x1303).unwrap();
        assert_eq!(parse_server_hello(&out[..len]).unwrap().suite, 0x1303);
    }
    #[test]
    fn encrypted_extensions_certificate_verify_and_finished_exact_vectors() {
        let mut out = [0; 256];
        let n = encode_encrypted_extensions(&mut out, ALPN, &[15, 1, 7]).unwrap();
        assert_eq!(
            &out[..n],
            &[
                8, 0, 0, 26, 0, 24, 0, 16, 0, 13, 0, 11, 10, b'h', b'q', b'-', b'i', b'n', b't',
                b'e', b'r', b'o', b'p', 0, 57, 0, 3, 15, 1, 7
            ]
        );
        assert_eq!(
            parse_encrypted_extensions(&out[..n]).unwrap().params,
            &[15, 1, 7]
        );
        let n = encode_certificate_verify(&mut out, 0x0403, &[0x30, 1, 7]).unwrap();
        assert_eq!(&out[..n], &[15, 0, 0, 7, 4, 3, 0, 3, 0x30, 1, 7]);
        assert_eq!(
            parse_certificate_verify(&out[..n]).unwrap().signature,
            &[0x30, 1, 7]
        );
        let value = [0xa5; 32];
        let n = encode_finished(&mut out, &value).unwrap();
        assert_eq!(n, 36);
        assert_eq!(&out[..4], &[20, 0, 0, 32]);
        assert_eq!(parse_finished(&out[..n]).unwrap(), &value);
    }
    #[test]
    fn certificate_ranges_are_relative_to_complete_message_and_bounded() {
        let mut out = [0; 256];
        let a = [0x30, 1, 7];
        let b = [0x30, 2, 8, 9];
        let mut ranges = [DerRange::default(); 7];
        let n = encode_certificate(&mut out, &[&a, &b]).unwrap();
        assert_eq!(&out[..8], &[11, 0, 0, 21, 0, 0, 0, 17]);
        let count = parse_certificate(&out[..n], &mut ranges).unwrap();
        assert_eq!(count, 2);
        assert_eq!(ranges[0], DerRange { offset: 11, len: 3 });
        assert_eq!(ranges[1], DerRange { offset: 19, len: 4 });
        for (index, expected) in [&a[..], &b[..]].into_iter().enumerate() {
            let r = ranges[index];
            assert_eq!(&out[r.offset..r.offset + r.len], expected);
        }
        assert_eq!(
            parse_certificate(&out[..n], &mut [DerRange::default(); 1]),
            Err(Error::Capacity)
        );
        assert_eq!(encode_certificate(&mut out, &[]), Err(Error::Malformed));
        assert_eq!(
            encode_certificate(&mut out, &[&a[..]; MAX_CERTIFICATES + 1]),
            Err(Error::Capacity)
        );
        assert_eq!(encode_certificate(&mut out, &[&[]]), Err(Error::Malformed));
    }
    #[test]
    fn every_truncation_and_trailing_byte_is_rejected_for_every_message() {
        let mut out = [0; 1024];
        let key = share();
        for kind in [1, 2, 8, 11, 15, 20] {
            let n = match kind {
                1 => encode_client_hello(&mut out, &[1; 32], &key, "localhost", ALPN, &[15, 1, 8])
                    .unwrap(),
                2 => encode_server_hello(&mut out, &[1; 32], &key, 0x1301).unwrap(),
                8 => encode_encrypted_extensions(&mut out, ALPN, &[15, 1, 8]).unwrap(),
                11 => encode_certificate(&mut out, &[&[0x30, 1, 7]]).unwrap(),
                15 => encode_certificate_verify(&mut out, 0x0403, &[0x30, 1, 7]).unwrap(),
                20 => encode_finished(&mut out, &[3; 32]).unwrap(),
                _ => unreachable!(),
            };
            let valid = |bytes: &[u8]| match kind {
                1 => parse_client_hello(bytes).is_ok(),
                2 => parse_server_hello(bytes).is_ok(),
                8 => parse_encrypted_extensions(bytes).is_ok(),
                11 => parse_certificate(bytes, &mut [DerRange::default(); 7]).is_ok(),
                15 => parse_certificate_verify(bytes).is_ok(),
                20 => parse_finished(bytes).is_ok(),
                _ => unreachable!(),
            };
            assert!(valid(&out[..n]));
            for end in 0..n {
                assert!(!valid(&out[..end]), "kind {kind} prefix {end}");
            }
            out[n] = 0;
            assert!(!valid(&out[..n + 1]), "kind {kind} trailing byte");
            out[3] = out[3].wrapping_add(1);
            assert!(!valid(&out[..n]), "kind {kind} declared length");
        }
    }
    #[test]
    fn duplicate_known_and_unknown_extensions_are_rejected() {
        let mut out = [0; 1024];
        let key = share();
        let n = encode_client_hello(&mut out, &[1; 32], &key, "localhost", ALPN, &[1]).unwrap();
        let at = ch_extensions(&out[..n]);
        let n = append_extension(&mut out, n, at, 57, &[1]);
        assert!(matches!(
            parse_client_hello(&out[..n]),
            Err(Error::DuplicateExtension)
        ));
        let n = encode_client_hello(&mut out, &[1; 32], &key, "localhost", ALPN, &[1]).unwrap();
        let at = ch_extensions(&out[..n]);
        let n = append_extension(&mut out, n, at, 0x0a0a, &[]);
        assert!(parse_client_hello(&out[..n]).is_ok());
        let n = append_extension(&mut out, n, at, 0x0a0a, &[]);
        assert!(matches!(
            parse_client_hello(&out[..n]),
            Err(Error::DuplicateExtension)
        ));
        let n = encode_server_hello(&mut out, &[1; 32], &key, 0x1301).unwrap();
        let n = append_extension(&mut out, n, 42, 43, &[3, 4]);
        assert!(matches!(
            parse_server_hello(&out[..n]),
            Err(Error::DuplicateExtension)
        ));
        let n = encode_encrypted_extensions(&mut out, ALPN, &[1]).unwrap();
        let n = append_extension(&mut out, n, 4, 57, &[2]);
        assert!(matches!(
            parse_encrypted_extensions(&out[..n]),
            Err(Error::DuplicateExtension)
        ));
    }
    #[test]
    fn forbidden_extension_contexts_hrr_psk_and_authentication_messages_fail() {
        let mut out = [0; 1024];
        let key = share();
        for forbidden in [41, 42, 44, 49] {
            let n = encode_client_hello(&mut out, &[1; 32], &key, "localhost", ALPN, &[]).unwrap();
            let at = ch_extensions(&out[..n]);
            let n = append_extension(&mut out, n, at, forbidden, &[]);
            assert!(matches!(
                parse_client_hello(&out[..n]),
                Err(Error::Unsupported)
            ));
        }
        let n = encode_server_hello(&mut out, &[1; 32], &key, 0x1301).unwrap();
        out[6..38].copy_from_slice(&HRR_RANDOM);
        assert!(matches!(
            parse_server_hello(&out[..n]),
            Err(Error::Unsupported)
        ));
        let n = encode_server_hello(&mut out, &[1; 32], &key, 0x1301).unwrap();
        let n = append_extension(&mut out, n, 42, 16, &[0, 2, 1, b'x']);
        assert!(matches!(
            parse_server_hello(&out[..n]),
            Err(Error::Unsupported)
        ));
        let n = encode_encrypted_extensions(&mut out, ALPN, &[]).unwrap();
        let n = append_extension(&mut out, n, 4, 51, &[]);
        assert!(matches!(
            parse_encrypted_extensions(&out[..n]),
            Err(Error::Unsupported)
        ));
        let n = encode_finished(&mut out, &[1; 32]).unwrap();
        out[0] = 24;
        assert_eq!(parse_finished(&out[..n]), Err(Error::UnexpectedMessage));
        let n = encode_certificate(&mut out, &[&[0x30, 1, 1]]).unwrap();
        out[4] = 1;
        assert!(parse_certificate(&out[..n], &mut [DerRange::default(); 7]).is_err());
    }
    #[test]
    fn missing_required_extensions_invalid_vectors_and_capacity_fail_closed() {
        let mut out = [0; 1024];
        let key = share();
        let n = encode_client_hello(&mut out, &[1; 32], &key, "localhost", ALPN, &[]).unwrap();
        let at = ch_extensions(&out[..n]);
        out[at..at + 2].copy_from_slice(&[0, 0]);
        length(&mut out, at + 2);
        assert!(matches!(
            parse_client_hello(&out[..at + 2]),
            Err(Error::MissingExtension)
        ));
        let n = encode_server_hello(&mut out, &[1; 32], &key, 0x1301).unwrap();
        out[41] = 1;
        assert!(matches!(
            parse_server_hello(&out[..n]),
            Err(Error::Malformed)
        ));
        assert_eq!(
            encode_server_hello(&mut out, &[1; 32], &key, 0x1302),
            Err(Error::Unsupported)
        );
        assert_eq!(
            encode_client_hello(&mut out, &[1; 32], &key, "localhost", b"h3", &[]),
            Err(Error::Unsupported)
        );
        for name in ["", "-bad.test", "bad..test", "name\0.test", "bad.test."] {
            assert!(encode_client_hello(&mut out, &[1; 32], &key, name, ALPN, &[]).is_err());
        }
        let mut bad = key;
        bad[0] = 2;
        assert!(encode_server_hello(&mut out, &[1; 32], &bad, 0x1301).is_err());
        assert_eq!(
            encode_finished(&mut [0; 35], &[0; 32]),
            Err(Error::BufferTooSmall)
        );
        assert!(encode_client_hello(&mut [0; 10], &[1; 32], &key, "localhost", ALPN, &[]).is_err());
        assert_eq!(
            encode_certificate_verify(&mut out, 0x0804, &[1; 64]),
            Err(Error::Unsupported)
        );
    }
    #[test]
    fn parser_never_panics_on_bounded_single_byte_mutations() {
        let mut original = [0; 1024];
        let key = share();
        let n = encode_client_hello(&mut original, &[1; 32], &key, "localhost", ALPN, &[1, 2, 3])
            .unwrap();
        for index in 0..n {
            for value in [0, 1, 127, 255] {
                let mut mutated = original;
                mutated[index] = value;
                let _ = parse_client_hello(&mutated[..n]);
            }
        }
    }
    #[test]
    fn key_shares_must_follow_unique_supported_groups() {
        assert_eq!(
            check_share_groups(
                &[0, 4, 0, 23, 0, 29],
                &[0, 10, 0, 23, 0, 1, 4, 0, 29, 0, 1, 9]
            ),
            Ok(())
        );
        assert_eq!(
            check_share_groups(&[0, 2, 0, 23], &[0, 10, 0, 23, 0, 1, 4, 0, 29, 0, 1, 9]),
            Err(Error::Malformed)
        );
        assert_eq!(
            check_share_groups(&[0, 4, 0, 23, 0, 23], &[0, 5, 0, 23, 0, 1, 4]),
            Err(Error::Malformed)
        );
        assert_eq!(
            check_share_groups(
                &[0, 4, 0, 23, 0, 29],
                &[0, 10, 0, 29, 0, 1, 9, 0, 23, 0, 1, 4]
            ),
            Err(Error::Malformed)
        );
    }

    #[test]
    fn extension_count_has_a_hard_bound() {
        let mut out = [0; 1024];
        let mut len =
            encode_client_hello(&mut out, &[1; 32], &share(), "localhost", ALPN, &[]).unwrap();
        let at = ch_extensions(&out[..len]);
        let (_, ext) = client_hello_parts(&out[..len]).unwrap();
        let mut existing = 0;
        extensions(ext, |_, _| {
            existing += 1;
            Ok(())
        })
        .unwrap();
        for kind in 1000..1000 + (MAX_EXTENSIONS - existing) as u16 {
            len = append_extension(&mut out, len, at, kind, &[]);
        }
        assert!(parse_client_hello(&out[..len]).is_ok());
        len = append_extension(&mut out, len, at, 2000, &[]);
        assert!(matches!(
            parse_client_hello(&out[..len]),
            Err(Error::Capacity)
        ));
    }

    #[test]
    fn real_default_group_neqo_clienthello_can_retry_with_p256() {
        // Public local-test ClientHello reconstructed with complete CRYPTO byte
        // coverage from four QUIC Initial datagrams on 2026-10-02. Neqo 0.32.0
        // engine ff4f4c61d14d1ee689b8ee1fdfab236f67c9bd95, NSS 3.126,
        // verifying library wrapper revision 2, default groups (no --group).
        // SHA-256: ca79029ce573a50b3cf009efe8b46ea3ebda60288866d69578c979c1d8f5268b
        // This is codec evidence; peer certificate authentication is not
        // established by inspecting or transforming a ClientHello.
        let hex = concat!(
            "0100060a0303987742cbdee499740dbc19bba70e24c242d52dc6d6daef2b2e5332b13edf95490000081301130313021a",
            "1a010005d90000000e000c0000096c6f63616c686f7374eaea0003000100000d001a0018040305030603020308040805",
            "08060401050106010201eaea000a000e000c11ec001d0017001800198a8a1a1a0000002d000302014900170000003304",
            "f004ee11ec04c027728c258b981c1c1079559cdb6642c89993b1c120de23b90672a190c61870888ec9ec38ac5c10ee07",
            "afbbd7690d87abeef1ce53ca41f5d463cc9c10d56663169829ea60cc1cb0255526b8a8b58fb11bcb6558cbdc3a6fc321",
            "4f59457bea9a77331b6196dabd6f717a4bea7c33c96e9a426d5ed83af33964ab242b4fa3bca474b63db26ef2f963d19c",
            "4e17a293f4d0792ac2ccd711990b88ab88a1ac13a2cb8a4cb2c0316f46cbb7ac95baaef37274102e3c62a193964e5feb",
            "91804c80d340a04d7c67dd8993f2dc66b91327c999920e81c5eee61b4707272683c8029200a3898a70101010055f62eb",
            "349d0091783781e945c38e7696feebccb047b9e9447a83764a864297d42a092eeb8fcc0bc6a2786ac124bb77615ea6e7",
            "b619260340a8c642e9c5b0fa7552c11233054d026b29a2e621e578b9c9c50cea4301808b2daa433905790c4943b39687",
            "4c277a9592c7a25d053f363a9053ec6cd011949663cfe75cc4b40ca6c53c1098496544611ab16a6fbe586663faa250fa",
            "c8f1921737138229aca4cc545dfb2118583331794ab7658a5faaa7a1500a9465a9689eb07d9a7b95d39408f0e6bcf4e7",
            "97a5c43db71acb0e029974a488e872bac21c017172c011f0a1a3eccb2bc48a1ef47e1d9c912832be49d09a6b897961a3",
            "5ee020419622304a969bb7717b87dc0d4d9876aef438fdf504de199cd87c20296723c6e281bc251282705a396879e4f6",
            "435ae232e1e99837488d0a30acdfe05065ac1fc62b0d066339e7488113b68f8f9cb0a498bb4b151aa9f2c2ad64997f22",
            "3f412b878fb81df894b62dd028e05b5da929728df88a9be1b4ed820a6aa6319832ae99ab45295667d670487ae5135d90",
            "adad4aa86f0808d407ba1fd3152e96a7f802403c8912bc997672934351115c77a6b9b50559b5610eff93cccc77bafa53",
            "71039a1549655ae74c7ff1331d6da26b0ae124c5084b2be63273853071ac52ac243f1f843cf10226ac54137f2839256a",
            "3695b31cf3e76f9c021fd1e257cf45a27020c08be26f5979185611a5b123a950c420658c9a46895b8491570a18985232",
            "13c7331a0903d04784867f530cee9c68a0f97c8b798ed64c56df054d07e2b7c26308b72abe715548a2256f6ba3a9b927",
            "2ef041c38e843f800c045eea75ab418fbada6fa5602cf6b0bbca6937a50a5d55024649768758fa9ef734b52d6aa8e31a",
            "8188d85af6bc6a93a464ef0989558831fd8c7fb9b235fd7346f856228c96be6dcc12104563f298c0ef712bc4680555ea",
            "2af95313aa52c08e591ce6f33356410cfb01c273b596dc038cd13aa1802a910eb64723b724ec900e52c62f19e4af526c",
            "c5cb894008157c78eb951bf341a30761b4a90cf3b45ff55950b3f34e9621709989bc4ef4cb0578060f848b2194015e46",
            "4e7a141872fa969b719867ca0e0749cdc012287b5abde8b45948f21176aa4fabea10fd9c052ff9a796668c3e633d1831",
            "8ea0a791242304d81140d551a2a38bca80f76102043d4aca096fa4c87c71cd61f15b273c33635579e5081df479b15234",
            "2ef0f7a01653981be190e1d99a6e535fa7449cba26704cb3a1243511e1c7b3e52a74d67154a5240df9874859a6a65abb",
            "8e5d3b2816b68e38cfdc967ee4a411a62f7919ac60584e2ff6e4b2f62ddb6dacb52bacb0b85198dd0d64a621142a121f",
            "bd3eec290e7fd65e033a7bbef35514cb58df273e4d9f58001d0020dd0d64a621142a121fbd3eec290e7fd65e033a7bbe",
            "f35514cb58df273e4d9f588a8a000200cdff0100010000100010000e0a68712d696e7465726f7002fafa001c00024001",
            "002b00050403046a6a00050005010000000000390058010247d004048020000005048010000006048010000007048010",
            "000008024064090240640b01140e01080f0857875353734b4c3b110c000000010a4abafa000000011d006ab200c00000",
            "00ff02de1a0243e820048000ffff",
        ).as_bytes();
        let mut first = [0; 1550];
        fn nibble(v: u8) -> u8 {
            if v <= b'9' { v - b'0' } else { v - b'a' + 10 }
        }
        for (b, pair) in first.iter_mut().zip(hex.chunks_exact(2)) {
            *b = nibble(pair[0]) * 16 + nibble(pair[1]);
        }
        let hello = parse_client_hello(&first).unwrap();
        assert!(hello.supports_p256);
        assert!(hello.key_share.is_empty());
        assert_eq!(hello.server_name, Some("localhost"));
        let mut hrr = [0; 128];
        let n = encode_hello_retry_request(&mut hrr, 0x1301, Some(GROUP_P256), None).unwrap();
        let retry = parse_hello_retry_request(&hrr[..n]).unwrap();
        let mut second = [0; 2048];
        let n = encode_client_hello_retry(&mut second, &first, &share(), &retry).unwrap();
        let retried = validate_client_hello_retry(&first, &second[..n], &retry).unwrap();
        assert_eq!(retried.key_share, &share());
        assert_eq!(retried.random, hello.random);
        assert_eq!(retried.server_name, hello.server_name);
        assert_eq!(retried.alpn, hello.alpn);
        assert_eq!(retried.params, hello.params);
    }

    #[test]
    fn real_neqo_p256_clienthello_ignores_grease_psk_modes() {
        let message = include_bytes!("../tests/vectors/tls/neqo-p256-grease-clienthello.bin");
        let hello = parse_client_hello(message).unwrap();
        assert_eq!(hello.server_name, Some("localhost"));
        assert_eq!(hello.alpn, ALPN);
        assert_eq!(hello.key_share.len(), 65);
        assert!(hello.offers_1301 && hello.offers_1303 && hello.signature_0403);
        assert!(!hello.params.is_empty());
    }

    #[test]
    fn observed_neqo_retry_with_extra_grease_share_is_rejected() {
        // Exact public Initial CRYPTO messages; provenance and hashes are in
        // tests/vectors/tls/neqo-hrr-observed.json. Unknown CH1 offers remain
        // accepted, but CH2 must contain only the HRR-requested key share.
        // RFC 8446 sections 4.1.2/4.2.8 and its successor RFC 9846 retain this
        // rule; RFC 8701 section 5 does not exempt GREASE from protocol rules.
        let first = include_bytes!("../tests/vectors/tls/neqo-hrr-observed-clienthello1.bin");
        let second = include_bytes!("../tests/vectors/tls/neqo-hrr-observed-clienthello2.bin");
        let hello = parse_client_hello(first).unwrap();
        assert!(hello.supports_p256 && hello.key_share.is_empty());
        assert_eq!(parse_client_hello(second).unwrap().key_share.len(), 65);
        let retry = HelloRetryRequest {
            suite: 0x1301,
            selected_group: Some(GROUP_P256),
            cookie: None,
        };
        assert_eq!(validate_hello_retry_request(first, &retry), Ok(()));
        assert!(matches!(
            validate_client_hello_retry(first, second, &retry),
            Err(Error::Length)
        ));
    }

    #[test]
    fn unknown_psk_modes_are_ignored_without_weakening_vector_or_psk_checks() {
        let mut out = [0; 1024];
        for modes in [&[2, 1, 0x2a][..], &[1, 0xff][..], &[2, 0x0b, 0xe4][..]] {
            let n =
                encode_client_hello(&mut out, &[1; 32], &share(), "localhost", ALPN, &[]).unwrap();
            let at = ch_extensions(&out[..n]);
            let n = append_extension(&mut out, n, at, 45, modes);
            assert!(parse_client_hello(&out[..n]).is_ok());
            let n = append_extension(&mut out, n, at, 41, &[]);
            assert!(matches!(
                parse_client_hello(&out[..n]),
                Err(Error::Unsupported)
            ));
        }
        for modes in [&[0][..], &[2, 1][..], &[1, 1, 0x2a][..]] {
            let n =
                encode_client_hello(&mut out, &[1; 32], &share(), "localhost", ALPN, &[]).unwrap();
            let at = ch_extensions(&out[..n]);
            let n = append_extension(&mut out, n, at, 45, modes);
            assert!(parse_client_hello(&out[..n]).is_err());
        }
    }

    fn ticket(out: &mut [u8], empty_ticket: bool, ext: &[u8]) -> usize {
        encode(out, 4, |w| {
            w.bytes(&[0, 0, 0, 60, 1, 2, 3, 4])?;
            w.vector(1, |w| w.bytes(&[7, 8]))?;
            w.vector(2, |w| {
                if empty_ticket {
                    Ok(())
                } else {
                    w.bytes(b"opaque ticket")
                }
            })?;
            w.vector(2, |w| w.bytes(ext))
        })
        .unwrap()
    }
    #[test]
    fn new_session_ticket_structure_bounds_and_quic_sentinel() {
        let mut out = [0; 512];
        for ext in [
            &[][..],
            &[0, 42, 0, 4, 255, 255, 255, 255][..],
            &[0x0a, 0x0a, 0, 3, 1, 2, 3][..],
        ] {
            let n = ticket(&mut out, false, ext);
            assert_eq!(validate_new_session_ticket(&out[..n]), Ok(()));
            for end in 0..n {
                assert!(validate_new_session_ticket(&out[..end]).is_err());
            }
            out[n] = 0;
            assert!(validate_new_session_ticket(&out[..n + 1]).is_err());
        }
        let n = ticket(&mut out, true, &[]);
        assert_eq!(
            validate_new_session_ticket(&out[..n]),
            Err(Error::Malformed)
        );
        for value in [[0; 4], [0, 0, 0, 1], [255, 255, 255, 254]] {
            let ext = [0, 42, 0, 4, value[0], value[1], value[2], value[3]];
            let n = ticket(&mut out, false, &ext);
            assert_eq!(
                validate_new_session_ticket(&out[..n]),
                Err(Error::InvalidQuicEarlyData)
            );
        }
        let n = ticket(&mut out, false, &[0, 42, 0, 3, 255, 255, 255]);
        assert_eq!(
            validate_new_session_ticket(&out[..n]),
            Err(Error::Malformed)
        );
        let n = ticket(
            &mut out,
            false,
            &[
                0, 42, 0, 4, 255, 255, 255, 255, 0, 42, 0, 4, 255, 255, 255, 255,
            ],
        );
        assert_eq!(
            validate_new_session_ticket(&out[..n]),
            Err(Error::DuplicateExtension)
        );
        let n = ticket(&mut out, false, &[0, 0, 0, 0]);
        assert_eq!(
            validate_new_session_ticket(&out[..n]),
            Err(Error::Unsupported)
        );
    }

    #[test]
    fn client_hello_advertises_no_psk_or_early_data_capability() {
        let mut out = [0; 1024];
        let n = encode_client_hello(&mut out, &[1; 32], &share(), "localhost", ALPN, &[]).unwrap();
        let at = ch_extensions(&out[..n]);
        let mut r = Reader::new(&out[at..n]);
        extensions(r.vector16().unwrap(), |kind, _| {
            assert!(!matches!(kind, 35 | 41 | 42 | 45 | 49));
            Ok(())
        })
        .unwrap();
    }
}

#[cfg(test)]
mod x25519_tests {
    use super::*;
    #[test]
    fn dual_shares_round_trip_and_truncations() {
        let mut p = [7; 65];
        p[0] = 4;
        let x = [9; 32];
        let mut out = [0; 1024];
        let n =
            encode_client_hello_dual(&mut out, &[1; 32], &p, &x, "localhost", ALPN, &[]).unwrap();
        let ch = parse_client_hello(&out[..n]).unwrap();
        assert!(ch.supports_p256 && ch.supports_x25519);
        assert_eq!(ch.key_share, &p);
        assert_eq!(ch.key_share_x25519, &x);
        for len in 0..n {
            assert!(parse_client_hello(&out[..len]).is_err());
        }
        let retry = HelloRetryRequest {
            suite: 0x1301,
            selected_group: Some(GROUP_P256),
            cookie: Some(b"cookie"),
        };
        assert!(validate_hello_retry_request(&out[..n], &retry).is_err());
        let h = encode_server_hello_group(&mut out, &[1; 32], GROUP_X25519, &x, 0x1301).unwrap();
        let sh = parse_server_hello(&out[..h]).unwrap();
        assert_eq!(sh.group, GROUP_X25519);
        assert_eq!(sh.key_share, &x);
        for len in 0..h {
            assert!(parse_server_hello(&out[..len]).is_err());
        }
    }
    #[test]
    fn wrong_x25519_share_lengths_reject() {
        let mut out = [0; 1024];
        for len in [0, 1, 31, 33, 65] {
            assert!(
                encode_server_hello_group(
                    &mut out,
                    &[1; 32],
                    GROUP_X25519,
                    &[7; 65][..len],
                    0x1301
                )
                .is_err()
            );
        }
        let mut p = [7; 65];
        p[0] = 4;
        let n = encode_client_hello_dual(&mut out, &[1; 32], &p, &[9; 32], "localhost", ALPN, &[])
            .unwrap();
        let offset = out[..n]
            .windows(4)
            .position(|w| w == [0, 29, 0, 32])
            .unwrap();
        out[offset + 3] = 31;
        assert!(parse_client_hello(&out[..n]).is_err());
    }
    #[test]
    fn x25519_selected_group_retry_is_single_and_bound_to_first_hello() {
        let mut p = [7; 65];
        p[0] = 4;
        let mut raw = [0; 1024];
        let n = encode_client_hello_dual(&mut raw, &[1; 32], &p, &[9; 32], "localhost", ALPN, &[])
            .unwrap();
        let original_len = n;
        let (prefix, ext) = client_hello_parts(&raw[..n]).unwrap();
        let mut first = [0; 1024];
        let first_len = encode(&mut first, 1, |w| {
            w.bytes(prefix)?;
            w.vector(2, |w| {
                extensions(ext, |kind, data| {
                    if kind == 51 {
                        w.extension(kind, |w| w.vector(2, |_| Ok(())))
                    } else {
                        w.extension(kind, |w| w.bytes(data))
                    }
                })
            })
        })
        .unwrap();
        let retry = HelloRetryRequest {
            suite: 0x1301,
            selected_group: Some(GROUP_X25519),
            cookie: Some(b"cookie"),
        };
        validate_hello_retry_request(&first[..first_len], &retry).unwrap();
        let mut second = [0; 1024];
        let n = encode_client_hello_retry_with_share(
            &mut second,
            &first[..first_len],
            &[9; 32],
            &retry,
        )
        .unwrap();
        let hello = validate_client_hello_retry(&first[..first_len], &second[..n], &retry).unwrap();
        assert!(hello.key_share.is_empty());
        assert_eq!(hello.key_share_x25519, &[9; 32]);
        assert!(validate_hello_retry_request(&raw[..original_len], &retry).is_err());
        let h = encode_hello_retry_request(&mut raw, 0x1301, Some(GROUP_X25519), None).unwrap();
        assert_eq!(
            parse_hello_retry_request(&raw[..h]).unwrap().selected_group,
            Some(GROUP_X25519)
        );
    }
}

#[cfg(test)]
mod psk_tests {
    use super::*;
    fn share() -> [u8; 65] {
        let mut v = [7; 65];
        v[0] = 4;
        v
    }
    fn hello(out: &mut [u8], offer: bool) -> usize {
        encode_client_hello_dual_psk(
            out,
            &[9; 32],
            &share(),
            &[6; 32],
            "localhost",
            ALPN,
            &[15, 0],
            offer.then_some((b"ticket".as_slice(), 0x11223344)),
        )
        .unwrap()
    }
    fn rewrite(
        out: &mut [u8],
        input: &[u8],
        mut change: impl FnMut(&mut Writer<'_>, u16, &[u8]) -> Result<(), Error>,
    ) -> usize {
        let (prefix, ext) = client_hello_parts(input).unwrap();
        encode(out, 1, |w| {
            w.bytes(prefix)?;
            w.vector(2, |w| extensions(ext, |kind, data| change(w, kind, data)))
        })
        .unwrap()
    }
    fn bad_psk(
        out: &mut [u8],
        input: &[u8],
        identities: usize,
        binders: usize,
        binder_len: usize,
    ) -> usize {
        rewrite(out, input, |w, kind, data| {
            if kind != 41 {
                return w.extension(kind, |w| w.bytes(data));
            }
            w.extension(41, |w| {
                w.vector(2, |w| {
                    for _ in 0..identities {
                        w.vector(2, |w| w.bytes(b"ticket"))?;
                        w.bytes(&[0; 4])?;
                    }
                    Ok(())
                })?;
                w.vector(2, |w| {
                    for _ in 0..binders {
                        w.vector(1, |w| w.bytes(&[0; 64][..binder_len]))?;
                    }
                    Ok(())
                })
            })
        })
    }
    #[test]
    fn binder_boundary_is_rfc_truncated_before_vector_length() {
        let mut out = [0; 1024];
        let n = hello(&mut out, true);
        let psk = parse_client_hello_psk(&out[..n]).unwrap().psk.unwrap();
        assert_eq!(psk.identity, b"ticket");
        assert_eq!(psk.obfuscated_age, 0x11223344);
        assert_eq!(psk.binder_prefix, n - 35);
        assert_eq!(psk.binder_offset, n - 32);
        assert_eq!(&out[psk.binder_prefix..psk.binder_offset], &[0, 33, 32]);
        assert_eq!(psk.binder, &[0; 32]);
        let expected = [
            &[0, 41, 0, 49, 0, 12, 0, 6][..],
            b"ticket",
            &[0x11, 0x22, 0x33, 0x44],
            &[0, 33, 32],
            &[0; 32],
        ]
        .concat();
        assert_eq!(&out[n - expected.len()..n], expected);
        assert_eq!(
            (usize::from(out[1]) << 16) | (usize::from(out[2]) << 8) | usize::from(out[3]),
            n - 4
        );
        let (prefix, offset) = (psk.binder_prefix, psk.binder_offset);
        let original = out;
        out[offset..n].fill(0xa5);
        assert_eq!(&out[..prefix], &original[..prefix]);
        assert_eq!(
            parse_client_hello_psk(&out[..n])
                .unwrap()
                .psk
                .unwrap()
                .binder,
            &[0xa5; 32]
        );
        assert!(matches!(
            parse_client_hello(&out[..n]),
            Err(Error::Unsupported)
        ));
    }
    #[test]
    fn modes_can_advertise_ticket_support_without_an_identity() {
        let mut out = [0; 1024];
        let n = hello(&mut out, false);
        let ch = parse_client_hello_psk(&out[..n]).unwrap();
        assert!(ch.psk.is_none() && ch.psk_dhe_ke);
        assert!(parse_client_hello(&out[..n]).unwrap().psk.is_none());
    }
    #[test]
    fn identity_and_binder_lists_are_single_bounded_and_equal_length() {
        let mut first = [0; 1024];
        let n = hello(&mut first, true);
        let mut out = [0; 2048];
        for (ids, binders, len) in [
            (0, 1, 32),
            (2, 1, 32),
            (1, 0, 32),
            (1, 2, 32),
            (2, 2, 32),
            (1, 1, 0),
            (1, 1, 31),
            (1, 1, 33),
        ] {
            let n = bad_psk(&mut out, &first[..n], ids, binders, len);
            assert!(
                parse_client_hello_psk(&out[..n]).is_err(),
                "{ids}/{binders}/{len}"
            );
        }
        let mut large = [0; 8192];
        for identity in [&[][..], &[0; MAX_PSK_IDENTITY_BYTES + 1][..]] {
            assert!(
                encode_client_hello_dual_psk(
                    &mut large,
                    &[9; 32],
                    &share(),
                    &[6; 32],
                    "localhost",
                    ALPN,
                    &[],
                    Some((identity, 0))
                )
                .is_err()
            );
        }
        let n = encode_client_hello_dual_psk(
            &mut large,
            &[9; 32],
            &share(),
            &[6; 32],
            "localhost",
            ALPN,
            &[],
            Some((&[1; MAX_PSK_IDENTITY_BYTES], 0)),
        )
        .unwrap();
        assert_eq!(
            parse_client_hello_psk(&large[..n])
                .unwrap()
                .psk
                .unwrap()
                .identity
                .len(),
            MAX_PSK_IDENTITY_BYTES
        );
    }
    #[test]
    fn dhe_mode_is_required_and_unknown_modes_do_not_negotiate_psk_ke() {
        let mut first = [0; 1024];
        let n = hello(&mut first, true);
        let mut out = [0; 2048];
        let without = rewrite(&mut out, &first[..n], |w, kind, data| {
            if kind == 45 {
                Ok(())
            } else {
                w.extension(kind, |w| w.bytes(data))
            }
        });
        assert!(parse_client_hello_psk(&out[..without]).is_err());
        for modes in [&[1, 0][..], &[1, 42], &[0], &[2, 1]] {
            let m = rewrite(&mut out, &first[..n], |w, kind, data| {
                w.extension(kind, |w| w.bytes(if kind == 45 { modes } else { data }))
            });
            assert!(parse_client_hello_psk(&out[..m]).is_err());
        }
        let m = rewrite(&mut out, &first[..n], |w, kind, data| {
            w.extension(kind, |w| {
                w.bytes(if kind == 45 { &[2, 42, 1] } else { data })
            })
        });
        assert!(parse_client_hello_psk(&out[..m]).unwrap().psk_dhe_ke);
    }
    #[test]
    fn psk_must_be_last_and_early_data_is_rejected() {
        let mut first = [0; 1024];
        let n = hello(&mut first, true);
        let mut out = [0; 2048];
        let (prefix, ext) = client_hello_parts(&first[..n]).unwrap();
        for after in [21, 0xfafa, 41] {
            let m = encode(&mut out, 1, |w| {
                w.bytes(prefix)?;
                w.vector(2, |w| {
                    w.bytes(ext)?;
                    w.extension(after, |_| Ok(()))
                })
            })
            .unwrap();
            assert!(parse_client_hello_psk(&out[..m]).is_err());
        }
        let m = rewrite(&mut out, &first[..n], |w, kind, data| {
            if kind == 41 {
                w.extension(42, |_| Ok(()))?;
            }
            w.extension(kind, |w| w.bytes(data))
        });
        assert!(matches!(
            parse_client_hello_psk(&out[..m]),
            Err(Error::Unsupported)
        ));
    }
    #[test]
    fn psk_cookie_retry_preserves_dual_shares_identity_and_binder_boundary() {
        let mut first = [0; 1024];
        let n = hello(&mut first, true);
        let mut out = [0; 2048];
        let retry = HelloRetryRequest {
            suite: 0x1301,
            selected_group: None,
            cookie: Some(b"cookie"),
        };
        let m =
            encode_client_hello_retry_psk(&mut out, &first[..n], GROUP_P256, &share(), &retry, 5)
                .unwrap();
        let second = validate_client_hello_retry_psk(&first[..n], &out[..m], &retry).unwrap();
        assert_eq!(second.key_share, share());
        assert_eq!(second.key_share_x25519, &[6; 32]);
        let psk = second.psk.unwrap();
        assert_eq!(psk.identity, b"ticket");
        assert_eq!(psk.obfuscated_age, 5);
        let offset = psk.binder_offset;
        out[offset..offset + 32].fill(0x99);
        assert!(validate_client_hello_retry_psk(&first[..n], &out[..m], &retry).is_ok());
        assert!(validate_client_hello_retry(&first[..n], &out[..m], &retry).is_err());
        assert!(parse_client_hello_psk(&out[..m]).is_err()); // Cookie needs retained CH1 context.
    }
    #[test]
    fn psk_retry_rejects_identity_drop_add_and_stable_extension_mutation() {
        let mut first = [0; 1024];
        let n = hello(&mut first, true);
        let mut second = [0; 2048];
        let mut out = [0; 2048];
        let retry = HelloRetryRequest {
            suite: 0x1301,
            selected_group: None,
            cookie: Some(b"cookie"),
        };
        let m = encode_client_hello_retry_psk(
            &mut second,
            &first[..n],
            GROUP_P256,
            &share(),
            &retry,
            5,
        )
        .unwrap();
        for kind_to_change in [41, 45, 57, 0] {
            let k = rewrite(&mut out, &second[..m], |w, kind, data| {
                if kind == kind_to_change {
                    let mut changed = [0; 512];
                    changed[..data.len()].copy_from_slice(data);
                    if kind == 41 {
                        changed[4] ^= 1;
                    } else if kind == 45 {
                        return w.extension(kind, |w| w.bytes(&[2, 42, 1]));
                    } else {
                        changed[data.len() - 1] ^= 1;
                    }
                    w.extension(kind, |w| w.bytes(&changed[..data.len()]))
                } else {
                    w.extension(kind, |w| w.bytes(data))
                }
            });
            assert!(validate_client_hello_retry_psk(&first[..n], &out[..k], &retry).is_err());
        }
        let k = rewrite(&mut out, &second[..m], |w, kind, data| {
            if kind == 41 {
                Ok(())
            } else {
                w.extension(kind, |w| w.bytes(data))
            }
        });
        assert!(validate_client_hello_retry_psk(&first[..n], &out[..k], &retry).is_err());
        let no_psk = hello(&mut out, false);
        assert!(validate_client_hello_retry_psk(&out[..no_psk], &second[..m], &retry).is_err());
        second[6] ^= 1;
        assert!(validate_client_hello_retry_psk(&first[..n], &second[..m], &retry).is_err());
    }
    #[test]
    fn psk_selected_group_retry_contains_exactly_the_requested_share() {
        let mut original = [0; 1024];
        let original_len = hello(&mut original, true);
        let mut first = [0; 1024];
        let mut second = [0; 2048];
        let n = rewrite(&mut first, &original[..original_len], |w, kind, data| {
            if kind == 51 {
                w.extension(51, |w| {
                    w.vector(2, |w| {
                        w.u16(usize::from(GROUP_X25519))?;
                        w.vector(2, |w| w.bytes(&[6; 32]))
                    })
                })
            } else {
                w.extension(kind, |w| w.bytes(data))
            }
        });
        let retry = HelloRetryRequest {
            suite: 0x1301,
            selected_group: Some(GROUP_P256),
            cookie: Some(b"cookie"),
        };
        let m = encode_client_hello_retry_psk(
            &mut second,
            &first[..n],
            GROUP_P256,
            &share(),
            &retry,
            7,
        )
        .unwrap();
        let parsed = validate_client_hello_retry_psk(&first[..n], &second[..m], &retry).unwrap();
        assert_eq!(parsed.key_share, share());
        assert!(parsed.key_share_x25519.is_empty());
        assert!(
            encode_client_hello_retry_psk(
                &mut second,
                &first[..n],
                GROUP_X25519,
                &[6; 32],
                &retry,
                7
            )
            .is_err()
        );
        assert!(validate_hello_retry_request_psk(&original[..original_len], &retry).is_err());
    }
    #[test]
    fn selected_psk_serverhello_requires_dhe_and_only_identity_zero() {
        let mut out = [0; 1024];
        let n = encode_server_hello_group_psk(
            &mut out,
            &[9; 32],
            GROUP_X25519,
            &[6; 32],
            0x1301,
            Some(0),
        )
        .unwrap();
        assert_eq!(
            parse_server_hello_psk(&out[..n]).unwrap().selected_psk,
            Some(0)
        );
        assert!(parse_server_hello(&out[..n]).is_err());
        out[n - 1] = 1;
        assert!(parse_server_hello_psk(&out[..n]).is_err());
        assert!(
            encode_server_hello_group_psk(
                &mut out,
                &[9; 32],
                GROUP_X25519,
                &[6; 32],
                0x1301,
                Some(1)
            )
            .is_err()
        );
        let n = encode(&mut out, 2, |w| {
            w.u16(0x0303)?;
            w.bytes(&[9; 32])?;
            w.u8(0)?;
            w.u16(0x1301)?;
            w.u8(0)?;
            w.vector(2, |w| {
                w.extension(43, |w| w.bytes(&[3, 4]))?;
                w.extension(41, |w| w.u16(0))
            })
        })
        .unwrap();
        assert!(matches!(
            parse_server_hello_psk(&out[..n]),
            Err(Error::MissingExtension)
        ));
    }
    #[test]
    fn nst_round_trip_preserves_fields_without_early_data() {
        let mut out = [0; 1024];
        for nonce in [&[][..], &[3; 255][..]] {
            let n =
                encode_new_session_ticket(&mut out, 604800, 0x12345678, nonce, b"ticket").unwrap();
            let ticket = parse_new_session_ticket(&out[..n]).unwrap();
            assert_eq!(ticket.lifetime_seconds, 604800);
            assert_eq!(ticket.age_add, 0x12345678);
            assert_eq!(ticket.nonce, nonce);
            assert_eq!(ticket.ticket, b"ticket");
            assert!(!ticket.early_data);
            assert!(validate_new_session_ticket(&out[..n]).is_ok());
            out[4..8].fill(0xff);
            assert_eq!(
                parse_new_session_ticket(&out[..n])
                    .unwrap()
                    .lifetime_seconds,
                u32::MAX
            );
        }
        assert!(encode_new_session_ticket(&mut out, 604801, 0, &[], b"x").is_err());
        assert!(encode_new_session_ticket(&mut out, 1, 0, &[], &[]).is_err());
        assert!(encode_new_session_ticket(&mut out, 1, 0, &[0; 256], b"x").is_err());
    }
    #[test]
    fn all_psk_message_truncations_and_short_output_buffers_fail() {
        let mut out = [0; 2048];
        let n = hello(&mut out, true);
        for end in 0..n {
            assert!(parse_client_hello_psk(&out[..end]).is_err());
        }
        assert!(parse_client_hello_psk(&out[..n + 1]).is_err());
        for size in 0..n {
            assert!(
                encode_client_hello_dual_psk(
                    &mut out[..size],
                    &[9; 32],
                    &share(),
                    &[6; 32],
                    "localhost",
                    ALPN,
                    &[15, 0],
                    Some((b"ticket", 0x11223344))
                )
                .is_err()
            );
        }
        let n = encode_server_hello_group_psk(
            &mut out,
            &[9; 32],
            GROUP_X25519,
            &[6; 32],
            0x1301,
            Some(0),
        )
        .unwrap();
        for end in 0..n {
            assert!(parse_server_hello_psk(&out[..end]).is_err());
        }
        let n = encode_new_session_ticket(&mut out, 1, 2, &[3; 8], b"ticket").unwrap();
        for end in 0..n {
            assert!(parse_new_session_ticket(&out[..end]).is_err());
        }
    }
    #[test]
    fn malformed_psk_mutations_never_panic_or_escape_bounds() {
        let mut base = [0; 1024];
        let n = hello(&mut base, true);
        for i in 0..n {
            for bit in 0..8 {
                let mut changed = base;
                changed[i] ^= 1 << bit;
                let _ = parse_client_hello_psk(&changed[..n]);
            }
        }
    }
}

#[cfg(test)]
mod early_tests {
    use super::*;
    fn share() -> [u8; 65] {
        let mut share = [0; 65];
        share[0] = 4;
        share
    }
    fn hello(out: &mut [u8]) -> usize {
        encode_client_hello_dual_early_with_policy(
            out,
            &[3; 32],
            &share(),
            &[7; 32],
            "server.test",
            ALPN,
            b"params",
            Some((b"ticket", 4)),
            true,
            CipherPolicy::ChaCha20Only,
        )
        .unwrap()
    }
    fn rewrite_early(out: &mut [u8], message: &[u8], data: &[u8]) -> usize {
        let (prefix, ext) = client_hello_parts(message).unwrap();
        encode(out, 1, |w| {
            w.bytes(prefix)?;
            w.vector(2, |w| {
                let mut emitted = false;
                extensions(ext, |kind, bytes| {
                    if kind == 42 {
                        return Ok(());
                    }
                    if kind == 41 && !emitted {
                        w.extension(42, |w| w.bytes(data))?;
                        emitted = true;
                    }
                    w.extension(kind, |w| w.bytes(bytes))
                })
            })
        })
        .unwrap()
    }
    #[test]
    fn early_offer_requires_psk_and_is_opt_in_to_syntax() {
        let mut bytes = [0; 2048];
        let n = hello(&mut bytes);
        let parsed = parse_client_hello_early(&bytes[..n]).unwrap();
        assert!(parsed.early_data && parsed.psk.is_some());
        assert!(!parsed.offers_1301 && parsed.offers_1303);
        assert!(parse_client_hello_psk(&bytes[..n]).is_err());
        assert_eq!(
            encode_client_hello_dual_early(
                &mut bytes,
                &[0; 32],
                &share(),
                &[7; 32],
                "server.test",
                ALPN,
                b"",
                None,
                true
            ),
            Err(Error::MissingExtension)
        );
        let n = hello(&mut bytes);
        let mut bad = [0; 2048];
        let k = rewrite_early(&mut bad, &bytes[..n], &[0]);
        assert!(parse_client_hello_early(&bad[..k]).is_err());
    }
    #[test]
    fn hrr_removes_early_offer_preserves_singleton_suite_and_forbids_ch2_reoffer() {
        let mut first = [0; 2048];
        let n = hello(&mut first);
        let hrr = HelloRetryRequest {
            suite: 0x1303,
            selected_group: None,
            cookie: Some(b"cookie"),
        };
        let mut second = [0; 2048];
        let k = encode_client_hello_retry_early(
            &mut second,
            &first[..n],
            GROUP_P256,
            &share(),
            &hrr,
            10,
        )
        .unwrap();
        let parsed = validate_client_hello_retry_early(&first[..n], &second[..k], &hrr).unwrap();
        assert!(!parsed.early_data && !parsed.offers_1301 && parsed.offers_1303);
        assert_eq!(parsed.psk.unwrap().identity, b"ticket");
        assert_eq!(parsed.psk.unwrap().obfuscated_age, 10);
        let mut bad = [0; 2048];
        let j = rewrite_early(&mut bad, &second[..k], &[]);
        assert!(validate_client_hello_retry_early(&first[..n], &bad[..j], &hrr).is_err());
    }
    #[test]
    fn ee_acceptance_is_empty_and_nst_permission_uses_exact_quic_sentinel() {
        let mut bytes = [0; 256];
        let n = encode_encrypted_extensions_early(&mut bytes, ALPN, b"", true).unwrap();
        assert!(
            parse_encrypted_extensions_early(&bytes[..n])
                .unwrap()
                .early_data
        );
        assert!(parse_encrypted_extensions(&bytes[..n]).is_err());
        let n =
            encode_new_session_ticket_early(&mut bytes, 60, 7, b"nonce", b"ticket", true).unwrap();
        assert!(parse_new_session_ticket(&bytes[..n]).unwrap().early_data);
        assert_eq!(&bytes[n - 4..n], &[0xff; 4]);
        bytes[n - 1] = 0;
        assert_eq!(
            parse_new_session_ticket(&bytes[..n]).unwrap_err(),
            Error::InvalidQuicEarlyData
        );
    }
    #[test]
    fn early_message_truncations_are_rejected() {
        let mut bytes = [0; 2048];
        let n = hello(&mut bytes);
        for end in 0..n {
            assert!(parse_client_hello_early(&bytes[..end]).is_err());
        }
        let n = encode_encrypted_extensions_early(&mut bytes, ALPN, b"", true).unwrap();
        for end in 0..n {
            assert!(parse_encrypted_extensions_early(&bytes[..end]).is_err());
        }
        let n =
            encode_new_session_ticket_early(&mut bytes, 60, 7, b"nonce", b"ticket", true).unwrap();
        for end in 0..n {
            assert!(parse_new_session_ticket(&bytes[..end]).is_err());
        }
    }
}
