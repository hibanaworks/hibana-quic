//! Bounded QUIC v1 Retry packets, client acceptance and server address tokens.
//!
//! RFC 9000 §§8.1, 17.2.5 and RFC 9001 §5.8. Retry integrity uses the existing
//! public-constant packet primitive; it does NOT authenticate a server. Tokens
//! use a separate, randomly generated AES-256-GCM secret and authenticate the
//! original DCID, Retry SCID, unchanged client SCID, IP address, port and time.
//!
//! Time is injected monotonic microseconds in one server lifetime. Keys are
//! non-Clone, non-exportable, zeroized on drop and generated with `CryptoRng`.
//! Never recreate an issuer with copied key/counter state. A restart generates a
//! fresh key and invalidates old tokens; no clock persistence is required. Use a
//! separate issuer/key ID during rotation and retain the old issuer until its
//! tokens expire if seamless rotation is required. RNG quality is a caller duty.
//!
//! Replay policy: one NEW CONNECTION admission per token, with a fixed cache that
//! fails closed when full and never evicts an unexpired admission. Subsequent
//! Initial packets for the SAME connection repeat the token and MUST be routed
//! to its existing endpoint, rather than requesting another admission. A token
//! only proves address reachability, never TLS identity or 0-RTT replay safety.
//! All receive workers accepting the same key must share this one issuer/cache.
//!
//! No heap, global clock, sockets or unsafe code. Endpoint reset/retransmission
//! is deliberately separate: Retry MUST NOT reset any packet-number allocator,
//! restart TLS, or erase retained CRYPTO bytes (RFC 9002 §6.3).

use crate::{
    crypto,
    packet::{self, Header, PacketIter},
};
use aes_gcm::{
    Aes256Gcm,
    aead::{AeadInPlace, KeyInit},
};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

/// Fixed opaque token size, independent of CID and address lengths.
pub const TOKEN_LEN: usize = 115;
pub const MAX_TOKEN_LIFETIME_US: u64 = 60_000_000;
pub const DEFAULT_TOKEN_LIFETIME_US: u64 = 10_000_000;
const PREFIX: [u8; 4] = *b"HQR\x01";
const HEADER_LEN: usize = 20;
const CLAIM_LEN: usize = 79;
const DOMAIN: &[u8; 20] = b"hibana-quic-retry-v1";
// Conservative local limits for this short, fixed-size token construction.
const MAX_ISSUED: u64 = 1 << 23;
const MAX_AUTH_FAILURES: u64 = 1 << 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidConnectionId,
    InvalidPacket,
    EmptyToken,
    Capacity,
    ConnectionMismatch,
    InvalidLifetime,
    InvalidTime,
    Entropy,
    KeyLimit,
    InvalidToken,
    Expired,
    Replayed,
    ReplayCapacity,
    Crypto(crypto::Error),
}
impl From<crypto::Error> for Error {
    fn from(value: crypto::Error) -> Self {
        Self::Crypto(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ConnectionId {
    bytes: [u8; 20],
    len: u8,
}
impl ConnectionId {
    fn new(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 20 {
            return Err(Error::InvalidConnectionId);
        }
        let mut value = Self {
            bytes: [0; 20],
            len: bytes.len() as u8,
        };
        value.bytes[..bytes.len()].copy_from_slice(bytes);
        Ok(value)
    }
    fn bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
    fn encode(self, out: &mut [u8]) {
        out[0] = self.len;
        out[1..21].copy_from_slice(&self.bytes);
    }
    fn decode(input: &[u8]) -> Result<Self, Error> {
        let len = usize::from(input[0]);
        if len > 20 || input[1 + len..21].iter().any(|&b| b != 0) {
            return Err(Error::InvalidToken);
        }
        Self::new(&input[1..1 + len])
    }
}

/// Complete peer address. IPv4 and IPv4-mapped IPv6 are deliberately distinct;
/// adapters must use a consistent representation. Port changes invalidate tokens.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientAddress {
    V4 { ip: [u8; 4], port: u16 },
    V6 { ip: [u8; 16], port: u16 },
}
impl ClientAddress {
    fn encode(self) -> [u8; 19] {
        let mut out = [0; 19];
        let port = match self {
            Self::V4 { ip, port } => {
                out[0] = 4;
                out[1..5].copy_from_slice(&ip);
                port
            }
            Self::V6 { ip, port } => {
                out[0] = 6;
                out[1..17].copy_from_slice(&ip);
                port
            }
        };
        out[17..].copy_from_slice(&port.to_be_bytes());
        out
    }
}

/// Inputs from the client's first Initial and the server's chosen Retry.
#[derive(Clone, Copy, Debug)]
pub struct TokenContext<'a> {
    pub original_destination_id: &'a [u8],
    pub retry_source_id: &'a [u8],
    pub client_source_id: &'a [u8],
    pub address: ClientAddress,
}

/// Authentication-checked, consumed connection admission. Fields cannot be
/// fabricated outside this module. Retain the CIDs for server transport parameters.
#[derive(Debug, Eq, PartialEq)]
pub struct ValidatedToken {
    address: ClientAddress,
    original: ConnectionId,
    retry: ConnectionId,
    client: ConnectionId,
    issued_at: u64,
    expires_at: u64,
}
impl ValidatedToken {
    /// Exact peer address authenticated as token AAD during admission.
    pub const fn address(&self) -> ClientAddress {
        self.address
    }
    pub fn original_destination_id(&self) -> &[u8] {
        self.original.bytes()
    }
    pub fn retry_source_id(&self) -> &[u8] {
        self.retry.bytes()
    }
    pub fn client_source_id(&self) -> &[u8] {
        self.client.bytes()
    }
    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

#[derive(Clone, Copy)]
struct Admission {
    nonce: [u8; 12],
    expires_at: u64,
}

/// One random token key, monotonic nonce allocator, and bounded replay cache.
/// Exhaustion returns an error; callers may refuse admission or rotate to a fresh
/// random key. Authentication failures consume a bounded key-wide failure budget.
pub struct RetryTokens<const ADMISSIONS: usize> {
    secret: Zeroizing<[u8; 32]>,
    nonce_prefix: [u8; 4],
    key_id: u32,
    lifetime: u64,
    issued: u64,
    failures: u64,
    last_time: Option<u64>,
    admissions: [Option<Admission>; ADMISSIONS],
}
impl<const N: usize> RetryTokens<N> {
    pub fn generate<R: RngCore + CryptoRng>(
        rng: &mut R,
        key_id: u32,
        lifetime_us: u64,
    ) -> Result<Self, Error> {
        if N == 0 {
            return Err(Error::ReplayCapacity);
        }
        if lifetime_us == 0 || lifetime_us > MAX_TOKEN_LIFETIME_US {
            return Err(Error::InvalidLifetime);
        }
        let mut secret = Zeroizing::new([0; 32]);
        let mut nonce_prefix = [0; 4];
        rng.try_fill_bytes(&mut *secret)
            .map_err(|_| Error::Entropy)?;
        rng.try_fill_bytes(&mut nonce_prefix)
            .map_err(|_| Error::Entropy)?;
        Ok(Self {
            secret,
            nonce_prefix,
            key_id,
            lifetime: lifetime_us,
            issued: 0,
            failures: 0,
            last_time: None,
            admissions: [None; N],
        })
    }
    pub const fn key_id(&self) -> u32 {
        self.key_id
    }
    pub const fn issued_tokens(&self) -> u64 {
        self.issued
    }
    pub const fn failed_authentications(&self) -> u64 {
        self.failures
    }
    fn check_time(&self, now: u64) -> Result<(), Error> {
        if self.last_time.is_some_and(|last| now < last) {
            Err(Error::InvalidTime)
        } else {
            Ok(())
        }
    }
    fn aad(header: &[u8], address: ClientAddress) -> [u8; 59] {
        let mut aad = [0; 59];
        aad[..20].copy_from_slice(DOMAIN);
        aad[20..40].copy_from_slice(header);
        aad[40..].copy_from_slice(&address.encode());
        aad
    }
    /// Generate one token. Precondition errors leave output and nonce state alone.
    /// The nonce is consumed before encryption and can never be reused on error.
    pub fn issue(
        &mut self,
        now: u64,
        context: TokenContext<'_>,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        self.check_time(now)?;
        let expires = now.checked_add(self.lifetime).ok_or(Error::InvalidTime)?;
        let original = ConnectionId::new(context.original_destination_id)?;
        let retry = ConnectionId::new(context.retry_source_id)?;
        let client = ConnectionId::new(context.client_source_id)?;
        if original == retry {
            return Err(Error::ConnectionMismatch);
        }
        if out.len() < TOKEN_LEN {
            return Err(Error::Capacity);
        }
        if self.issued >= MAX_ISSUED || self.failures >= MAX_AUTH_FAILURES {
            return Err(Error::KeyLimit);
        }
        let mut header = [0; HEADER_LEN];
        header[..4].copy_from_slice(&PREFIX);
        header[4..8].copy_from_slice(&self.key_id.to_be_bytes());
        header[8..12].copy_from_slice(&self.nonce_prefix);
        header[12..20].copy_from_slice(&self.issued.to_be_bytes());
        self.issued += 1;
        self.last_time = Some(now);
        let mut plaintext = Zeroizing::new([0; CLAIM_LEN]);
        plaintext[..8].copy_from_slice(&now.to_be_bytes());
        plaintext[8..16].copy_from_slice(&expires.to_be_bytes());
        original.encode(&mut plaintext[16..37]);
        retry.encode(&mut plaintext[37..58]);
        client.encode(&mut plaintext[58..79]);
        let cipher = Aes256Gcm::new((&*self.secret).into());
        let tag = cipher
            .encrypt_in_place_detached(
                header[8..20].into(),
                &Self::aad(&header, context.address),
                &mut *plaintext,
            )
            .map_err(|_| Error::InvalidToken)?;
        out[..HEADER_LEN].copy_from_slice(&header);
        out[HEADER_LEN..TOKEN_LEN - 16].copy_from_slice(&*plaintext);
        out[TOKEN_LEN - 16..TOKEN_LEN].copy_from_slice(&tag);
        Ok(TOKEN_LEN)
    }
    /// Authenticate and consume ONE new-connection admission. The supplied CIDs
    /// are the destination and source of the received, post-Retry Initial. Reject
    /// invalid Retry tokens rather than issuing another Retry. Claims are exposed
    /// only after successful AEAD, field, expiry and replay checks.
    pub fn validate(
        &mut self,
        now: u64,
        address: ClientAddress,
        initial_destination: &[u8],
        initial_source: &[u8],
        token: &[u8],
    ) -> Result<ValidatedToken, Error> {
        self.check_time(now)?;
        // Observe every validation call, including failures. Expired-token
        // rejection must not become reversible after a caller clock regression.
        self.last_time = Some(now);
        if token.len() != TOKEN_LEN
            || token[..4] != PREFIX
            || token[4..8] != self.key_id.to_be_bytes()
        {
            return Err(Error::InvalidToken);
        }
        if self.failures >= MAX_AUTH_FAILURES {
            return Err(Error::KeyLimit);
        }
        let mut plaintext = Zeroizing::new([0; CLAIM_LEN]);
        plaintext.copy_from_slice(&token[HEADER_LEN..TOKEN_LEN - 16]);
        let cipher = Aes256Gcm::new((&*self.secret).into());
        if cipher
            .decrypt_in_place_detached(
                token[8..20].into(),
                &Self::aad(&token[..HEADER_LEN], address),
                &mut *plaintext,
                token[TOKEN_LEN - 16..].into(),
            )
            .is_err()
        {
            self.failures += 1;
            return Err(Error::InvalidToken);
        }
        let issued_at =
            u64::from_be_bytes(plaintext[..8].try_into().map_err(|_| Error::InvalidToken)?);
        let expires_at = u64::from_be_bytes(
            plaintext[8..16]
                .try_into()
                .map_err(|_| Error::InvalidToken)?,
        );
        if issued_at > now || issued_at.checked_add(self.lifetime) != Some(expires_at) {
            return Err(Error::InvalidTime);
        }
        if now >= expires_at {
            return Err(Error::Expired);
        }
        let original = ConnectionId::decode(&plaintext[16..37])?;
        let retry = ConnectionId::decode(&plaintext[37..58])?;
        let client = ConnectionId::decode(&plaintext[58..79])?;
        if retry.bytes() != initial_destination
            || client.bytes() != initial_source
            || original == retry
        {
            return Err(Error::ConnectionMismatch);
        }
        let nonce: [u8; 12] = token[8..20].try_into().map_err(|_| Error::InvalidToken)?;
        if self
            .admissions
            .iter()
            .flatten()
            .any(|a| a.nonce == nonce && now < a.expires_at)
        {
            return Err(Error::Replayed);
        }
        let slot = self
            .admissions
            .iter()
            .position(|a| a.is_none_or(|a| now >= a.expires_at))
            .ok_or(Error::ReplayCapacity)?;
        self.admissions[slot] = Some(Admission { nonce, expires_at });
        self.last_time = Some(now);
        Ok(ValidatedToken {
            address,
            original,
            retry,
            client,
            issued_at,
            expires_at,
        })
    }
}

/// Parsed v1 Retry with integrity and client CID semantics checked. The token is
/// still opaque; only the server can authenticate it. This value borrows input.
#[derive(Clone, Copy, Debug)]
pub struct CheckedRetry<'a> {
    source: &'a [u8],
    token: &'a [u8],
}
impl<'a> CheckedRetry<'a> {
    pub const fn source_id(&self) -> &'a [u8] {
        self.source
    }
    pub const fn token(&self) -> &'a [u8] {
        self.token
    }
}

/// Generate exactly one Retry packet; output is not a coalescible packet. Server
/// adapters enforce one Retry per input datagram and anti-amplification limits.
/// `unused` supplies the four arbitrary low bits and must be at most 15.
pub fn encode_retry(
    original_destination: &[u8],
    client_source: &[u8],
    retry_source: &[u8],
    token: &[u8],
    unused: u8,
    out: &mut [u8],
    scratch: &mut [u8],
) -> Result<usize, Error> {
    ConnectionId::new(original_destination)?;
    ConnectionId::new(client_source)?;
    ConnectionId::new(retry_source)?;
    if original_destination == retry_source {
        return Err(Error::ConnectionMismatch);
    }
    if token.is_empty() {
        return Err(Error::EmptyToken);
    }
    if unused > 15 {
        return Err(Error::InvalidPacket);
    }
    let len = 7usize
        .checked_add(client_source.len())
        .and_then(|n| n.checked_add(retry_source.len()))
        .and_then(|n| n.checked_add(token.len()))
        .and_then(|n| n.checked_add(16))
        .ok_or(Error::Capacity)?;
    if len > crypto::MAX_PROTECTED_PACKET_LEN
        || out.len() < len
        || scratch.len() < 1 + original_destination.len() + len - 16
    {
        return Err(Error::Capacity);
    }
    out[0] = 0xf0 | unused;
    out[1..5].copy_from_slice(&packet::QUIC_V1.to_be_bytes());
    out[5] = client_source.len() as u8;
    let end_client = 6 + client_source.len();
    out[6..end_client].copy_from_slice(client_source);
    out[end_client] = retry_source.len() as u8;
    let end_source = end_client + 1 + retry_source.len();
    out[end_client + 1..end_source].copy_from_slice(retry_source);
    out[end_source..len - 16].copy_from_slice(token);
    let tag = crypto::retry_integrity_tag(original_destination, &out[..len - 16], scratch)?;
    out[len - 16..len].copy_from_slice(&tag);
    Ok(len)
}

/// Pure packet validation. This does not authorize accepting a Retry, changing
/// the destination, reissuing keys or resetting packet numbers. A projected
/// connection continuation must own that one-shot decision and actual resources.
pub fn validate_retry<'a>(
    original_destination: &[u8],
    client_source: &[u8],
    datagram: &'a [u8],
    token_capacity: usize,
    scratch: &mut [u8],
) -> Result<CheckedRetry<'a>, Error> {
    let original = ConnectionId::new(original_destination)?;
    let client = ConnectionId::new(client_source)?;
    let mut packets =
        PacketIter::new(datagram, usize::from(client.len), 1).map_err(|_| Error::InvalidPacket)?;
    let parsed = packets
        .next()
        .ok_or(Error::InvalidPacket)?
        .map_err(|_| Error::InvalidPacket)?;
    let Header::Retry {
        destination_id,
        source_id,
        token,
        ..
    } = parsed.header
    else {
        return Err(Error::InvalidPacket);
    };
    if destination_id != client.bytes() || source_id == original.bytes() {
        return Err(Error::ConnectionMismatch);
    }
    if token.len() > token_capacity {
        return Err(Error::Capacity);
    }
    crypto::verify_retry(original.bytes(), datagram, scratch)?;
    Ok(CheckedRetry {
        source: source_id,
        token,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    struct TestRng {
        next: u8,
        fail: bool,
    }
    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            let mut b = [0; 4];
            self.fill_bytes(&mut b);
            u32::from_le_bytes(b)
        }
        fn next_u64(&mut self) -> u64 {
            let mut b = [0; 8];
            self.fill_bytes(&mut b);
            u64::from_le_bytes(b)
        }
        fn fill_bytes(&mut self, out: &mut [u8]) {
            for b in out {
                *b = self.next;
                self.next = self.next.wrapping_add(1);
            }
        }
        fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
            if self.fail {
                Err(rand_core::Error::from(
                    core::num::NonZeroU32::new(1).unwrap(),
                ))
            } else {
                self.fill_bytes(out);
                Ok(())
            }
        }
    }
    // Test-only deterministic source; not production entropy.
    impl CryptoRng for TestRng {}
    fn issuer<const N: usize>(lifetime: u64) -> RetryTokens<N> {
        RetryTokens::generate(
            &mut TestRng {
                next: 1,
                fail: false,
            },
            7,
            lifetime,
        )
        .unwrap()
    }
    const ADDRESS: ClientAddress = ClientAddress::V4 {
        ip: [192, 0, 2, 1],
        port: 44321,
    };
    fn context() -> TokenContext<'static> {
        TokenContext {
            original_destination_id: b"original",
            retry_source_id: b"retry",
            client_source_id: b"client",
            address: ADDRESS,
        }
    }
    fn issue<const N: usize>(issuer: &mut RetryTokens<N>, now: u64) -> [u8; TOKEN_LEN] {
        let mut out = [0; TOKEN_LEN];
        assert_eq!(issuer.issue(now, context(), &mut out), Ok(TOKEN_LEN));
        out
    }
    fn hex<const N: usize>(value: &str) -> [u8; N] {
        let mut out = [0; N];
        for (i, b) in value.as_bytes().chunks_exact(2).enumerate() {
            let digit = |x: u8| {
                if x.is_ascii_digit() {
                    x - b'0'
                } else {
                    x - b'a' + 10
                }
            };
            out[i] = digit(b[0]) * 16 + digit(b[1]);
        }
        out
    }
    const RFC_PACKET: &str =
        "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba";

    #[test]
    fn rfc9001_a4_retry_encode_and_pure_validate() {
        let odcid = hex::<8>("8394c8f03e515708");
        let retry = hex::<8>("f067a5502a4262b5");
        let mut out = [0; 36];
        assert_eq!(
            encode_retry(&odcid, &[], &retry, b"token", 15, &mut out, &mut [0; 64]),
            Ok(36)
        );
        assert_eq!(out, hex::<36>(RFC_PACKET));
        let checked = validate_retry(&odcid, &[], &out, 5, &mut [0; 64]).unwrap();
        assert_eq!(checked.source_id(), retry);
        assert_eq!(checked.token(), b"token");
    }
    #[test]
    fn corrupt_every_retry_byte_and_truncate_is_rejected() {
        let packet = hex::<36>(RFC_PACKET);
        let odcid = hex::<8>("8394c8f03e515708");
        for i in 0..packet.len() {
            let mut bad = packet;
            bad[i] ^= 1;
            assert!(validate_retry(&odcid, &[], &bad, 64, &mut [0; 100]).is_err());
        }
        for n in 0..packet.len() {
            assert!(validate_retry(&odcid, &[], &packet[..n], 64, &mut [0; 100]).is_err());
        }
        assert!(validate_retry(&odcid, &[], &packet, 64, &mut [0; 100]).is_ok());
    }
    #[test]
    fn retry_cid_identity_and_capacity_are_checked_without_mutation() {
        let packet = hex::<36>(RFC_PACKET);
        let odcid = hex::<8>("8394c8f03e515708");
        assert!(matches!(
            validate_retry(&odcid, &[], &packet, 4, &mut [0; 100]),
            Err(Error::Capacity)
        ));
        assert!(validate_retry(&[0; 21], &[], &packet, 64, &mut [0; 100]).is_err());
        assert!(validate_retry(&odcid, &[0; 21], &packet, 64, &mut [0; 100]).is_err());
        assert!(matches!(
            validate_retry(&odcid, b"client", &packet, 64, &mut [0; 100]),
            Err(Error::ConnectionMismatch)
        ));
        assert!(validate_retry(&odcid, &[], &packet, 5, &mut [0; 100]).is_ok());
    }
    #[test]
    fn builder_preflights_buffers_and_token_semantics() {
        let mut out = [0xaa; 128];
        let before = out;
        for (token, unused, scratch, expected) in [
            (&b""[..], 0, 128, Error::EmptyToken),
            (&b"token"[..], 16, 128, Error::InvalidPacket),
            (&b"token"[..], 0, 0, Error::Capacity),
        ] {
            assert_eq!(
                encode_retry(
                    b"original",
                    b"client",
                    b"retry",
                    token,
                    unused,
                    &mut out,
                    &mut [0; 128][..scratch]
                ),
                Err(expected)
            );
            assert_eq!(out, before);
        }
        assert_eq!(
            encode_retry(
                b"original",
                b"client",
                b"original",
                b"token",
                0,
                &mut out,
                &mut [0; 128]
            ),
            Err(Error::ConnectionMismatch)
        );
        assert_eq!(
            encode_retry(
                b"original",
                b"client",
                b"retry",
                b"token",
                0,
                &mut out[..1],
                &mut [0; 128]
            ),
            Err(Error::Capacity)
        );
        assert_eq!(out, before);
    }
    #[test]
    fn empty_retry_source_is_valid_if_different_from_original() {
        let mut out = [0; 128];
        let n = encode_retry(
            b"original",
            b"client",
            &[],
            b"token",
            0,
            &mut out,
            &mut [0; 160],
        )
        .unwrap();
        assert_eq!(
            validate_retry(b"original", b"client", &out[..n], 64, &mut [0; 160])
                .unwrap()
                .source_id(),
            &[]
        );
    }
    #[test]
    fn unused_retry_bits_are_accepted_when_integrity_is_valid() {
        for bits in 0..16 {
            let mut out = [0; 128];
            let n = encode_retry(
                b"original",
                b"client",
                b"retry",
                b"token",
                bits,
                &mut out,
                &mut [0; 160],
            )
            .unwrap();
            assert!(validate_retry(b"original", b"client", &out[..n], 64, &mut [0; 160]).is_ok());
        }
    }
    #[test]
    fn opaque_token_roundtrip_has_exact_claims() {
        let mut issuer = issuer::<2>(DEFAULT_TOKEN_LIFETIME_US);
        let token = issue(&mut issuer, 1_000);
        assert!(!token.windows(8).any(|w| w == b"original"));
        let claims = issuer
            .validate(2_000, ADDRESS, b"retry", b"client", &token)
            .unwrap();
        assert_eq!(claims.original_destination_id(), b"original");
        assert_eq!(claims.retry_source_id(), b"retry");
        assert_eq!(claims.client_source_id(), b"client");
        assert_eq!(claims.issued_at(), 1_000);
        assert_eq!(claims.expires_at(), 10_001_000);
        assert_eq!(issuer.key_id(), 7);
        assert_eq!(issuer.issued_tokens(), 1);
        assert_eq!(issuer.failed_authentications(), 0);
    }
    #[test]
    fn every_token_byte_and_truncation_is_authenticated_or_rejected() {
        let mut issuer = issuer::<1>(100);
        let token = issue(&mut issuer, 0);
        for i in 0..TOKEN_LEN {
            let mut bad = token;
            bad[i] ^= 1;
            assert_eq!(
                issuer.validate(1, ADDRESS, b"retry", b"client", &bad),
                Err(Error::InvalidToken),
                "byte {i}"
            );
        }
        for end in 0..TOKEN_LEN {
            assert_eq!(
                issuer.validate(1, ADDRESS, b"retry", b"client", &token[..end]),
                Err(Error::InvalidToken)
            );
        }
        assert!(
            issuer
                .validate(1, ADDRESS, b"retry", b"client", &token)
                .is_ok()
        );
    }
    #[test]
    fn tokens_bind_ip_port_and_address_family() {
        let mut issuer = issuer::<2>(100);
        let token = issue(&mut issuer, 0);
        for address in [
            ClientAddress::V4 {
                ip: [192, 0, 2, 2],
                port: 44321,
            },
            ClientAddress::V4 {
                ip: [192, 0, 2, 1],
                port: 44322,
            },
            ClientAddress::V6 {
                ip: [0; 16],
                port: 44321,
            },
        ] {
            assert_eq!(
                issuer.validate(1, address, b"retry", b"client", &token),
                Err(Error::InvalidToken)
            );
        }
        assert!(
            issuer
                .validate(1, ADDRESS, b"retry", b"client", &token)
                .is_ok()
        );
        let address = ClientAddress::V6 {
            ip: [3; 16],
            port: 1,
        };
        let mut v6 = [0; TOKEN_LEN];
        issuer
            .issue(
                2,
                TokenContext {
                    address,
                    ..context()
                },
                &mut v6,
            )
            .unwrap();
        assert!(
            issuer
                .validate(3, address, b"retry", b"client", &v6)
                .is_ok()
        );
    }
    #[test]
    fn cid_mismatch_does_not_consume_admission() {
        let mut issuer = issuer::<1>(100);
        let token = issue(&mut issuer, 0);
        assert_eq!(
            issuer.validate(1, ADDRESS, b"wrong", b"client", &token),
            Err(Error::ConnectionMismatch)
        );
        assert_eq!(
            issuer.validate(1, ADDRESS, b"retry", b"wrong", &token),
            Err(Error::ConnectionMismatch)
        );
        assert!(
            issuer
                .validate(1, ADDRESS, b"retry", b"client", &token)
                .is_ok()
        );
    }
    #[test]
    fn each_token_admits_at_most_one_new_connection() {
        let mut issuer = issuer::<2>(100);
        let token = issue(&mut issuer, 0);
        assert!(
            issuer
                .validate(1, ADDRESS, b"retry", b"client", &token)
                .is_ok()
        );
        assert_eq!(
            issuer.validate(2, ADDRESS, b"retry", b"client", &token),
            Err(Error::Replayed)
        );
        assert_eq!(
            issuer.validate(100, ADDRESS, b"retry", b"client", &token),
            Err(Error::Expired)
        );
    }
    #[test]
    fn full_replay_cache_never_evicts_unexpired_admission() {
        let mut issuer = issuer::<1>(10);
        let first = issue(&mut issuer, 0);
        let second = issue(&mut issuer, 1);
        issuer
            .validate(2, ADDRESS, b"retry", b"client", &first)
            .unwrap();
        assert_eq!(
            issuer.validate(3, ADDRESS, b"retry", b"client", &second),
            Err(Error::ReplayCapacity)
        );
        assert_eq!(
            issuer.validate(4, ADDRESS, b"retry", b"client", &first),
            Err(Error::Replayed)
        );
        // The first cache slot is expired at 10; the second token is still valid.
        assert!(
            issuer
                .validate(10, ADDRESS, b"retry", b"client", &second)
                .is_ok()
        );
        assert_eq!(
            issuer.validate(9, ADDRESS, b"retry", b"client", &first),
            Err(Error::InvalidTime)
        );
    }
    #[test]
    fn expiry_is_exclusive_and_clock_cannot_move_backwards() {
        let mut issuer = issuer::<2>(10);
        let token = issue(&mut issuer, 100);
        assert_eq!(
            issuer.validate(99, ADDRESS, b"retry", b"client", &token),
            Err(Error::InvalidTime)
        );
        assert_eq!(
            issuer.validate(110, ADDRESS, b"retry", b"client", &token),
            Err(Error::Expired)
        );
        assert_eq!(
            issuer.validate(109, ADDRESS, b"retry", b"client", &token),
            Err(Error::InvalidTime)
        );
        assert_eq!(
            issuer.issue(108, context(), &mut [0; TOKEN_LEN]),
            Err(Error::InvalidTime)
        );
    }
    #[test]
    fn issue_errors_preserve_output_nonce_and_clock() {
        let mut issuer = issuer::<1>(10);
        let mut out = [0xaa; TOKEN_LEN];
        for (now, context) in [
            (u64::MAX, context()),
            (
                0,
                TokenContext {
                    retry_source_id: b"original",
                    ..context()
                },
            ),
            (
                0,
                TokenContext {
                    client_source_id: &[0; 21],
                    ..context()
                },
            ),
        ] {
            assert!(issuer.issue(now, context, &mut out).is_err());
            assert_eq!(out, [0xaa; TOKEN_LEN]);
            assert_eq!(issuer.issued_tokens(), 0);
        }
        assert_eq!(
            issuer.issue(0, context(), &mut out[..TOKEN_LEN - 1]),
            Err(Error::Capacity)
        );
        assert_eq!(issuer.issued_tokens(), 0);
        let first = issue(&mut issuer, 0);
        let second = issue(&mut issuer, 0);
        assert_ne!(&first[8..20], &second[8..20]);
        assert_ne!(first, second);
    }
    #[test]
    fn generation_requires_entropy_positive_bounded_lifetime_and_replay_capacity() {
        let mut rng = TestRng {
            next: 1,
            fail: false,
        };
        assert!(matches!(
            RetryTokens::<0>::generate(&mut rng, 1, 10),
            Err(Error::ReplayCapacity)
        ));
        for lifetime in [0, MAX_TOKEN_LIFETIME_US + 1] {
            assert!(matches!(
                RetryTokens::<1>::generate(&mut rng, 1, lifetime),
                Err(Error::InvalidLifetime)
            ));
        }
        rng.fail = true;
        assert!(matches!(
            RetryTokens::<1>::generate(&mut rng, 1, 10),
            Err(Error::Entropy)
        ));
    }
    #[test]
    fn fresh_keys_reject_previous_tokens_and_limits_fail_closed() {
        let mut first = issuer::<1>(100);
        let token = issue(&mut first, 0);
        let mut second = RetryTokens::<1>::generate(
            &mut TestRng {
                next: 99,
                fail: false,
            },
            7,
            100,
        )
        .unwrap();
        assert_eq!(
            second.validate(1, ADDRESS, b"retry", b"client", &token),
            Err(Error::InvalidToken)
        );
        first.issued = MAX_ISSUED;
        assert_eq!(
            first.issue(1, context(), &mut [0; TOKEN_LEN]),
            Err(Error::KeyLimit)
        );
        first.failures = MAX_AUTH_FAILURES;
        assert_eq!(
            first.validate(1, ADDRESS, b"retry", b"client", &token),
            Err(Error::KeyLimit)
        );
    }
    #[test]
    fn max_and_empty_cids_roundtrip_and_noncanonical_claims_reject() {
        let mut issuer = issuer::<1>(100);
        let original = [1; 20];
        let retry = [2; 20];
        let mut token = [0; TOKEN_LEN];
        issuer
            .issue(
                0,
                TokenContext {
                    original_destination_id: &original,
                    retry_source_id: &retry,
                    client_source_id: &[],
                    address: ADDRESS,
                },
                &mut token,
            )
            .unwrap();
        let claims = issuer.validate(1, ADDRESS, &retry, &[], &token).unwrap();
        assert_eq!(claims.original_destination_id(), &original);
        assert!(claims.client_source_id().is_empty());
        let mut invalid = [0; 21];
        invalid[0] = 21;
        assert_eq!(ConnectionId::decode(&invalid), Err(Error::InvalidToken));
        invalid[0] = 0;
        invalid[20] = 1;
        assert_eq!(ConnectionId::decode(&invalid), Err(Error::InvalidToken));
    }
}
