//! RECONSTRUCTED after workspace loss on 2026-10-03; integration is UNVERIFIED.
//! Public baseline plus recovered directional module/split/drop changes.
//! QUIC v1 packet protection (RFC 9001 §§5–6), without allocation.
//!
//! Cryptographic primitives are supplied by RustCrypto, never reimplemented here.
//! This module does not implement TLS or authenticate a peer: Initial and Retry
//! protection use publicly derivable keys. A transport must install real TLS
//! traffic secrets, authenticate the handshake, authorize key updates, maintain
//! packet-number spaces/replay state, and check authenticated reserved bits.
//!
//! One `PacketKey` owns one direction and encryption level. Do not reconstruct a
//! sending key from the same secret: its local nonce-use guard cannot see another
//! instance. Keep one `IntegrityBudget` for the entire quic, including old
//! receive generations. No operation allocates or obtains random numbers.

use crate::version::Version;
use aes::Aes128;
use aes::cipher::{
    BlockEncrypt, KeyInit, KeyIvInit, StreamCipherCore, StreamCipherSeekCore, consts::U10,
};
use aes_gcm::{Aes128Gcm, aead::AeadInPlace};
use chacha20::ChaChaCore;
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

pub mod directional;

pub const TAG_LEN: usize = 16;
pub const HP_SAMPLE_LEN: usize = 16;
pub const MAX_PACKET_NUMBER: u64 = (1 << 62) - 1;
/// Bound assumed by the conservative RFC 9001 §6.6 AEAD usage limits.
pub const MAX_PROTECTED_PACKET_LEN: usize = 65_535;

const INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const INITIAL_SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];
const RETRY_KEY_V2: [u8; 16] = [
    0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2, 0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92,
];
const RETRY_NONCE_V2: [u8; 12] = [
    0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a,
];
// Public Retry integrity constants, not traffic secrets.
const RETRY_KEY: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
const RETRY_NONCE: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidConnectionId,
    InvalidPacketNumber,
    PacketNumberReuse,
    PacketTooLarge,
    BufferTooSmall,
    InvalidHeader,
    KeyDerivation,
    KeyDiscarded,
    KeyUpdateNotAllowed,
    KeyUpdateError,
    InvalidTime,
    InvalidAcknowledgment,
    ConfidentialityLimit,
    IntegrityLimit,
    AuthenticationFailed,
    EncryptionFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CipherSuite {
    Aes128GcmSha256,
    ChaCha20Poly1305Sha256,
}

impl CipherSuite {
    const fn key_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 16,
            Self::ChaCha20Poly1305Sha256 => 32,
        }
    }

    const fn confidentiality_limit(self) -> u64 {
        match self {
            Self::Aes128GcmSha256 => 1 << 23,
            Self::ChaCha20Poly1305Sha256 => 1 << 62,
        }
    }

    const fn integrity_limit(self) -> u64 {
        match self {
            Self::Aes128GcmSha256 => 1 << 52,
            Self::ChaCha20Poly1305Sha256 => 1 << 36,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyKind {
    Initial,
    Handshake,
    ZeroRtt,
    OneRtt,
}

/// Connection-wide failed-authentication counter. It intentionally cannot be
/// cloned or reset. Key updates MUST NOT create a new budget. When a connection
/// uses multiple suites, the smallest encountered limit is retained.
pub struct IntegrityBudget {
    failed: u64,
    limit: u64,
}

/// Outcome of an external packet-protection backend's authentication attempt.
#[derive(Debug, Eq, PartialEq)]
pub enum AuthenticationError<E> {
    /// The connection's smallest observed integrity limit is exhausted.
    IntegrityLimit,
    /// The backend performed an actual attempt and rejected authentication.
    Failed(E),
}

impl Default for IntegrityBudget {
    fn default() -> Self {
        Self::new()
    }
}

impl IntegrityBudget {
    pub const fn new() -> Self {
        Self {
            failed: 0,
            limit: u64::MAX,
        }
    }
    pub const fn failed_packets(&self) -> u64 {
        self.failed
    }

    /// Gate an external cryptographic backend using this same connection budget.
    /// `limit` must be the actual backend key's integrity limit (or a stricter
    /// previously observed limit). The limit only tightens; successful attempts
    /// never reset failures. An exhausted budget never invokes `attempt`.
    ///
    /// This is trusted Provider integration, not proof of authentication: the
    /// closure must perform the real AEAD verification and return its outcome.
    /// No failure-counter setter or reset capability is exposed.
    pub fn authenticate<T, E>(
        &mut self,
        limit: u64,
        attempt: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, AuthenticationError<E>> {
        self.before_attempt_limit(limit)
            .map_err(|_| AuthenticationError::IntegrityLimit)?;
        match attempt() {
            Ok(value) => Ok(value),
            Err(error) => match self.record_failure() {
                Error::IntegrityLimit => Err(AuthenticationError::IntegrityLimit),
                _ => Err(AuthenticationError::Failed(error)),
            },
        }
    }

    /// Transfer the unique connection budget to an async crypto role. Until the
    /// role returns it, this owner is fail-closed, including cancellation paths.
    pub(crate) fn take_for_role(&mut self) -> Self {
        let failed = self.failed;
        core::mem::replace(self, Self { failed, limit: 0 })
    }

    fn before_attempt(&mut self, suite: CipherSuite) -> Result<(), Error> {
        self.before_attempt_limit(suite.integrity_limit())
    }

    fn before_attempt_limit(&mut self, limit: u64) -> Result<(), Error> {
        self.limit = self.limit.min(limit);
        if self.failed >= self.limit {
            Err(Error::IntegrityLimit)
        } else {
            Ok(())
        }
    }

    fn record_failure(&mut self) -> Error {
        // before_attempt guarantees failed < limit <= u64::MAX.
        self.failed += 1;
        if self.failed >= self.limit {
            Error::IntegrityLimit
        } else {
            Error::AuthenticationFailed
        }
    }
}

/// Raw keys are private, non-Clone, not Debug, and zeroized on discard/drop.
/// This does not claim every temporary inside dependencies is zeroized.
pub struct PacketKey {
    version: Version,
    suite: CipherSuite,
    kind: KeyKind,
    secret: [u8; 32],
    key: [u8; 32],
    iv: [u8; 12],
    hp: [u8; 32],
    active: bool,
    last_sealed: Option<u64>,
    sealed: u64,
}

impl PacketKey {
    /// Install a SHA-256 traffic secret supplied by TLS. For Initial keys, prefer
    /// `initial_keys`, which fixes both the v1 salt and mandatory AES suite.
    pub fn from_secret(
        suite: CipherSuite,
        kind: KeyKind,
        secret: &[u8; 32],
    ) -> Result<Self, Error> {
        Self::from_secret_for_version(Version::V1, suite, kind, secret)
    }
    pub fn from_secret_for_version(
        version: Version,
        suite: CipherSuite,
        kind: KeyKind,
        secret: &[u8; 32],
    ) -> Result<Self, Error> {
        if kind == KeyKind::Initial && suite != CipherSuite::Aes128GcmSha256 {
            return Err(Error::KeyDerivation);
        }
        let mut this = Self {
            version,
            suite,
            kind,
            secret: *secret,
            key: [0; 32],
            iv: [0; 12],
            hp: [0; 32],
            active: true,
            last_sealed: None,
            sealed: 0,
        };
        expand_label(
            secret,
            version.key_label(),
            &mut this.key[..suite.key_len()],
        )?;
        expand_label(secret, version.iv_label(), &mut this.iv)?;
        expand_label(secret, version.hp_label(), &mut this.hp[..suite.key_len()])?;
        Ok(this)
    }

    pub const fn version(&self) -> Version {
        self.version
    }
    pub const fn suite(&self) -> CipherSuite {
        self.suite
    }
    pub const fn kind(&self) -> KeyKind {
        self.kind
    }
    pub const fn sealed_packets(&self) -> u64 {
        self.sealed
    }
    pub const fn last_sealed_packet_number(&self) -> Option<u64> {
        self.last_sealed
    }

    pub(crate) fn ensure_active(&self) -> Result<(), Error> {
        if self.active {
            Ok(())
        } else {
            Err(Error::KeyDiscarded)
        }
    }

    /// Retain Initial packet-number and confidentiality accounting across Retry.
    /// A fresh candidate cannot reset either counter, even for an unchanged CID.
    pub(crate) fn inherit_send_usage(&mut self, previous: &Self) -> Result<(), Error> {
        self.ensure_active()?;
        previous.ensure_active()?;
        if self.kind != KeyKind::Initial
            || previous.kind != KeyKind::Initial
            || self.suite != previous.suite
            || self.last_sealed.is_some()
            || self.sealed != 0
        {
            return Err(Error::KeyDerivation);
        }
        self.last_sealed = previous.last_sealed;
        self.sealed = previous.sealed;
        Ok(())
    }

    /// Destroy this instance's stored key material. Discard is terminal.
    pub fn discard(&mut self) {
        self.secret.zeroize();
        self.key.zeroize();
        self.iv.zeroize();
        self.hp.zeroize();
        self.active = false;
    }

    /// Advance a 1-RTT key using RFC 9001 §6. Retains the header protection key
    /// and send-PN high-water mark. The transport MUST authorize this transition
    /// using handshake confirmation and acknowledgment/key-phase state first.
    /// This cryptographic operation alone is not a full key-update state machine.
    pub fn update_key(&mut self) -> Result<(), Error> {
        self.ensure_active()?;
        if self.kind != KeyKind::OneRtt {
            return Err(Error::KeyUpdateNotAllowed);
        }
        let next = Zeroizing::new(next_traffic_secret_for_version(self.version, &self.secret)?);
        let mut key = Zeroizing::new([0; 32]);
        let mut iv = Zeroizing::new([0; 12]);
        expand_label(
            &next,
            self.version.key_label(),
            &mut key[..self.suite.key_len()],
        )?;
        expand_label(&next, self.version.iv_label(), &mut *iv)?;
        self.secret.zeroize();
        self.key.zeroize();
        self.iv.zeroize();
        self.secret.copy_from_slice(&*next);
        self.key.copy_from_slice(&*key);
        self.iv.copy_from_slice(&*iv);
        self.sealed = 0;
        Ok(())
    }

    /// Derive a distinct next-generation owner; never clones a sending key.
    fn derive_next(&self) -> Result<Self, Error> {
        self.ensure_active()?;
        if self.kind != KeyKind::OneRtt {
            return Err(Error::KeyUpdateNotAllowed);
        }
        let secret = Zeroizing::new(next_traffic_secret_for_version(self.version, &self.secret)?);
        let mut next = Self::from_secret_for_version(self.version, self.suite, self.kind, &secret)?;
        next.hp.copy_from_slice(&self.hp);
        Ok(next)
    }

    /// Protect plaintext already in buffer[..plaintext_len], appending a tag.
    /// Returns the used length. Preconditions are checked before mutation. A PN
    /// is consumed before calling AEAD, including on an unexpected crypto error.
    /// Only strictly increasing PNs may be sealed with this key instance.
    pub fn seal(
        &mut self,
        packet_number: u64,
        header: &[u8],
        buffer: &mut [u8],
        plaintext_len: usize,
    ) -> Result<usize, Error> {
        self.ensure_active()?;
        let nonce = packet_nonce(&self.iv, packet_number)?;
        if self.last_sealed.is_some_and(|pn| packet_number <= pn) {
            return Err(Error::PacketNumberReuse);
        }
        if self.sealed >= self.suite.confidentiality_limit() {
            return Err(Error::ConfidentialityLimit);
        }
        let used = plaintext_len
            .checked_add(TAG_LEN)
            .ok_or(Error::BufferTooSmall)?;
        if used > buffer.len() {
            return Err(Error::BufferTooSmall);
        }
        check_packet_len(header.len(), used)?;
        self.last_sealed = Some(packet_number);
        self.sealed += 1;
        let (body, tag_out) = buffer[..used].split_at_mut(plaintext_len);
        let result = match self.suite {
            CipherSuite::Aes128GcmSha256 => Aes128Gcm::new((&self.key[..16]).into())
                .encrypt_in_place_detached((&nonce).into(), header, body),
            CipherSuite::ChaCha20Poly1305Sha256 => ChaCha20Poly1305::new((&self.key).into())
                .encrypt_in_place_detached((&nonce).into(), header, body),
        };
        match result {
            Ok(tag) => {
                tag_out.copy_from_slice(&tag);
                Ok(used)
            }
            Err(_) => {
                buffer[..used].zeroize();
                Err(Error::EncryptionFailed)
            }
        }
    }

    /// Authenticate/decrypt ciphertext with its appended 16-byte tag in place.
    /// Returns plaintext length; only success authorizes using plaintext. On an
    /// authentication failure the entire provided ciphertext/tag buffer is wiped.
    /// Precondition errors leave the buffer unchanged. Does not reject replayed
    /// packet numbers: authenticated duplicate suppression belongs to transport.
    pub fn open(
        &self,
        packet_number: u64,
        header: &[u8],
        buffer: &mut [u8],
        budget: &mut IntegrityBudget,
    ) -> Result<usize, Error> {
        self.ensure_active()?;
        let nonce = packet_nonce(&self.iv, packet_number)?;
        let len = buffer
            .len()
            .checked_sub(TAG_LEN)
            .ok_or(Error::BufferTooSmall)?;
        check_packet_len(header.len(), buffer.len())?;
        budget.before_attempt(self.suite)?;
        let (body, tag) = buffer.split_at_mut(len);
        let result = match self.suite {
            CipherSuite::Aes128GcmSha256 => Aes128Gcm::new((&self.key[..16]).into())
                .decrypt_in_place_detached((&nonce).into(), header, body, (&*tag).into()),
            CipherSuite::ChaCha20Poly1305Sha256 => ChaCha20Poly1305::new((&self.key).into())
                .decrypt_in_place_detached((&nonce).into(), header, body, (&*tag).into()),
        };
        match result {
            Ok(()) => Ok(len),
            Err(_) => {
                buffer.zeroize();
                Err(budget.record_failure())
            }
        }
    }

    /// RFC 9001 §5.4 header-protection mask from exactly 16 ciphertext bytes.
    pub fn header_mask(&self, sample: &[u8; HP_SAMPLE_LEN]) -> Result<[u8; 5], Error> {
        self.ensure_active()?;
        let mut mask = [0; 5];
        match self.suite {
            CipherSuite::Aes128GcmSha256 => {
                let mut block = (*sample).into();
                Aes128::new((&self.hp[..16]).into()).encrypt_block(&mut block);
                mask.copy_from_slice(&block[..5]);
            }
            CipherSuite::ChaCha20Poly1305Sha256 => {
                let counter = u32::from_le_bytes([sample[0], sample[1], sample[2], sample[3]]);
                // QUIC permits every u32 counter, including 0xffffffff. The
                // stream wrapper reserves that last block for exhaustion, so
                // use the library's single-block API and immediately drop it.
                // Exactly one block is generated; a wrapped counter is never used.
                let mut cipher = ChaChaCore::<U10>::new((&self.hp).into(), (&sample[4..]).into());
                cipher.set_block_pos(counter);
                let mut block = aes::cipher::Block::<ChaChaCore<U10>>::default();
                cipher.write_keystream_block(&mut block);
                mask.copy_from_slice(&block[..5]);
                block.zeroize();
            }
        }
        Ok(mask)
    }

    /// Protect a header after payload encryption. `packet` must contain exactly
    /// one packet, not an entire coalesced datagram. PN offset comes from parsing.
    pub fn protect_header(&self, packet: &mut [u8], pn_offset: usize) -> Result<(), Error> {
        self.ensure_active()?;
        let mask = self.packet_mask(packet, pn_offset)?;
        let pn_len = (packet[0] & 3) as usize + 1;
        packet[0] ^= mask[0] & if packet[0] & 0x80 != 0 { 0x0f } else { 0x1f };
        for i in 0..pn_len {
            packet[pn_offset + i] ^= mask[i + 1];
        }
        Ok(())
    }

    /// Remove header protection, returning encoded PN length. The resulting
    /// header is still UNAUTHENTICATED and must not cause transport state changes.
    pub fn unprotect_header(&self, packet: &mut [u8], pn_offset: usize) -> Result<usize, Error> {
        self.ensure_active()?;
        let mask = self.packet_mask(packet, pn_offset)?;
        let first = packet[0] ^ (mask[0] & if packet[0] & 0x80 != 0 { 0x0f } else { 0x1f });
        let pn_len = (first & 3) as usize + 1;
        packet[0] = first;
        for i in 0..pn_len {
            packet[pn_offset + i] ^= mask[i + 1];
        }
        Ok(pn_len)
    }

    fn packet_mask(&self, packet: &[u8], pn_offset: usize) -> Result<[u8; 5], Error> {
        if pn_offset == 0 {
            return Err(Error::InvalidHeader);
        }
        if packet.len() > MAX_PROTECTED_PACKET_LEN {
            return Err(Error::PacketTooLarge);
        }
        let start = pn_offset.checked_add(4).ok_or(Error::InvalidHeader)?;
        let end = start
            .checked_add(HP_SAMPLE_LEN)
            .ok_or(Error::InvalidHeader)?;
        let sample: &[u8; 16] = packet
            .get(start..end)
            .ok_or(Error::BufferTooSmall)?
            .try_into()
            .map_err(|_| Error::InvalidHeader)?;
        self.header_mask(sample)
    }
}

impl Drop for PacketKey {
    fn drop(&mut self) {
        self.discard();
    }
}

/// Authenticated 1-RTT result. The generation is monotonic, unlike the wire bit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Opened {
    pub len: usize,
    pub generation: u64,
    pub key_updated: bool,
}

pub struct InitialKeys {
    /// Protects packets sent by the client (server's receiving key).
    pub client: PacketKey,
    /// Protects packets sent by the server (client's receiving key).
    pub server: PacketKey,
}

/// QUIC v1 Initial keys using the client's Initial Destination Connection ID.
/// After Retry, pass the new destination CID, but do not reset the transport's
/// Initial packet-number space. Initial authentication does not prove identity.
pub fn initial_keys(destination_connection_id: &[u8]) -> Result<InitialKeys, Error> {
    initial_keys_for_version(Version::V1, destination_connection_id)
}
pub fn initial_keys_for_version(
    version: Version,
    destination_connection_id: &[u8],
) -> Result<InitialKeys, Error> {
    if destination_connection_id.len() > 20 {
        return Err(Error::InvalidConnectionId);
    }
    let hkdf = Hkdf::<Sha256>::new(
        Some(match version {
            Version::V1 => &INITIAL_SALT,
            Version::V2 => &INITIAL_SALT_V2,
        }),
        destination_connection_id,
    );
    let mut client = Zeroizing::new([0; 32]);
    let mut server = Zeroizing::new([0; 32]);
    expand_with(&hkdf, b"client in", &mut *client)?;
    expand_with(&hkdf, b"server in", &mut *server)?;
    Ok(InitialKeys {
        client: PacketKey::from_secret_for_version(
            version,
            CipherSuite::Aes128GcmSha256,
            KeyKind::Initial,
            &client,
        )?,
        server: PacketKey::from_secret_for_version(
            version,
            CipherSuite::Aes128GcmSha256,
            KeyKind::Initial,
            &server,
        )?,
    })
}

/// 62-bit packet number, left padded to 96 bits, XOR with IV (RFC 9001 §5.3).
pub fn packet_nonce(iv: &[u8; 12], packet_number: u64) -> Result<[u8; 12], Error> {
    if packet_number > MAX_PACKET_NUMBER {
        return Err(Error::InvalidPacketNumber);
    }
    let mut nonce = *iv;
    for (dst, src) in nonce[4..].iter_mut().zip(packet_number.to_be_bytes()) {
        *dst ^= src;
    }
    Ok(nonce)
}

pub fn next_traffic_secret(secret: &[u8; 32]) -> Result<[u8; 32], Error> {
    next_traffic_secret_for_version(Version::V1, secret)
}
pub fn next_traffic_secret_for_version(
    version: Version,
    secret: &[u8; 32],
) -> Result<[u8; 32], Error> {
    let mut next = [0; 32];
    expand_label(secret, version.ku_label(), &mut next)?;
    Ok(next)
}

fn expand_label(secret: &[u8; 32], label: &[u8], out: &mut [u8]) -> Result<(), Error> {
    let hkdf = Hkdf::<Sha256>::from_prk(secret).map_err(|_| Error::KeyDerivation)?;
    expand_with(&hkdf, label, out)
}

fn expand_with(hkdf: &Hkdf<Sha256>, label: &[u8], out: &mut [u8]) -> Result<(), Error> {
    // All this module's labels fit 10 bytes. Fixed storage deliberately avoids
    // general variable-length TLS label/context allocation.
    if label.len() > 10 || out.len() > 32 {
        return Err(Error::KeyDerivation);
    }
    let mut info = [0; 20];
    info[..2].copy_from_slice(&(out.len() as u16).to_be_bytes());
    info[2] = (6 + label.len()) as u8;
    info[3..9].copy_from_slice(b"tls13 ");
    info[9..9 + label.len()].copy_from_slice(label);
    // Last byte is the zero-length context.
    hkdf.expand(&info[..10 + label.len()], out)
        .map_err(|_| Error::KeyDerivation)
}

fn check_packet_len(header: usize, protected_payload: usize) -> Result<(), Error> {
    if header
        .checked_add(protected_payload)
        .is_none_or(|len| len > MAX_PROTECTED_PACKET_LEN)
    {
        Err(Error::PacketTooLarge)
    } else {
        Ok(())
    }
}

fn retry_pseudo_packet<'a>(
    odcid: &[u8],
    retry_without_tag: &[u8],
    scratch: &'a mut [u8],
) -> Result<&'a [u8], Error> {
    if odcid.len() > 20 {
        return Err(Error::InvalidConnectionId);
    }
    check_packet_len(retry_without_tag.len(), TAG_LEN)?;
    let used = 1 + odcid.len() + retry_without_tag.len();
    if scratch.len() < used {
        return Err(Error::BufferTooSmall);
    }
    scratch[0] = odcid.len() as u8;
    scratch[1..1 + odcid.len()].copy_from_slice(odcid);
    scratch[1 + odcid.len()..used].copy_from_slice(retry_without_tag);
    Ok(&scratch[..used])
}

/// Compute v1 Retry integrity using caller-owned pseudo-packet scratch.
/// This public-constant check detects corruption, not peer impersonation.
/// The caller is responsible for parsing Retry and checking CID/token semantics.
pub fn retry_integrity_tag(
    odcid: &[u8],
    retry_without_tag: &[u8],
    scratch: &mut [u8],
) -> Result<[u8; TAG_LEN], Error> {
    retry_integrity_tag_for_version(Version::V1, odcid, retry_without_tag, scratch)
}
pub fn retry_integrity_tag_for_version(
    version: Version,
    odcid: &[u8],
    retry_without_tag: &[u8],
    scratch: &mut [u8],
) -> Result<[u8; TAG_LEN], Error> {
    let (key, nonce) = match version {
        Version::V1 => (&RETRY_KEY, &RETRY_NONCE),
        Version::V2 => (&RETRY_KEY_V2, &RETRY_NONCE_V2),
    };
    let aad = retry_pseudo_packet(odcid, retry_without_tag, scratch)?;
    let tag = Aes128Gcm::new(key.into())
        .encrypt_in_place_detached(nonce.into(), aad, &mut [])
        .map_err(|_| Error::EncryptionFailed)?;
    Ok(tag.into())
}

/// Verify Retry's appended integrity tag using the AEAD's constant-time check.
pub fn verify_retry(odcid: &[u8], retry_with_tag: &[u8], scratch: &mut [u8]) -> Result<(), Error> {
    verify_retry_for_version(Version::V1, odcid, retry_with_tag, scratch)
}
pub fn verify_retry_for_version(
    version: Version,
    odcid: &[u8],
    retry_with_tag: &[u8],
    scratch: &mut [u8],
) -> Result<(), Error> {
    let (key, nonce) = match version {
        Version::V1 => (&RETRY_KEY, &RETRY_NONCE),
        Version::V2 => (&RETRY_KEY_V2, &RETRY_NONCE_V2),
    };
    let len = retry_with_tag
        .len()
        .checked_sub(TAG_LEN)
        .ok_or(Error::BufferTooSmall)?;
    let (retry, tag) = retry_with_tag.split_at(len);
    let aad = retry_pseudo_packet(odcid, retry, scratch)?;
    Aes128Gcm::new(key.into())
        .decrypt_in_place_detached(nonce.into(), aad, &mut [], tag.into())
        .map_err(|_| Error::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex<const N: usize>(input: &str) -> [u8; N] {
        let mut out = [0; N];
        let mut n = 0;
        for c in input.bytes().filter(|c| !c.is_ascii_whitespace()) {
            let x = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                _ => panic!("bad hex"),
            };
            assert!(n / 2 < N, "hex too long");
            out[n / 2] = (out[n / 2] << 4) | x;
            n += 1;
        }
        assert_eq!(n, N * 2);
        out
    }

    #[test]
    fn rfc9369_initial_keys() {
        let k = initial_keys_for_version(Version::V2, &hex::<8>("8394c8f03e515708")).unwrap();
        assert_eq!(
            k.client.key[..16],
            hex::<16>("8b1a0bc121284290a29e0971b5cd045d")
        );
        assert_eq!(k.client.iv, hex::<12>("91f73e2351d8fa91660e909f"));
        assert_eq!(
            k.client.hp[..16],
            hex::<16>("45b95e15235d6f45a6b19cbcb0294ba9")
        );
        assert_eq!(
            k.server.key[..16],
            hex::<16>("82db637861d55e1d011f19ea71d5d2a7")
        );
        assert_eq!(k.server.iv, hex::<12>("dd13c276499c0249d3310652"));
        assert_eq!(
            k.server.hp[..16],
            hex::<16>("edf6d05c83121201b436e16877593c3a")
        );
        assert_ne!(
            k.client.key,
            initial_keys(&hex::<8>("8394c8f03e515708"))
                .unwrap()
                .client
                .key
        );
    }
    #[test]
    fn version_two_key_update_domain() {
        for suite in [
            CipherSuite::Aes128GcmSha256,
            CipherSuite::ChaCha20Poly1305Sha256,
        ] {
            let mut k =
                PacketKey::from_secret_for_version(Version::V2, suite, KeyKind::OneRtt, &[7; 32])
                    .unwrap();
            let next = k.derive_next().unwrap();
            let hp = k.hp;
            k.update_key().unwrap();
            assert_eq!(k.version(), Version::V2);
            assert_eq!(k.key, next.key);
            assert_eq!(k.iv, next.iv);
            assert_eq!(k.hp, hp);
            assert_eq!(next.hp, hp);
            assert_ne!(
                k.key,
                PacketKey::from_secret(suite, KeyKind::OneRtt, &k.secret)
                    .unwrap()
                    .key
            );
        }
    }
    #[test]
    fn rfc9001_a1_initial_keys() {
        let keys = initial_keys(&hex::<8>("8394c8f03e515708")).unwrap();
        assert_eq!(
            keys.client.secret,
            hex::<32>("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
        );
        assert_eq!(
            &keys.client.key[..16],
            &hex::<16>("1f369613dd76d5467730efcbe3b1a22d")
        );
        assert_eq!(keys.client.iv, hex::<12>("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(
            &keys.client.hp[..16],
            &hex::<16>("9f50449e04a0e810283a1e9933adedd2")
        );
        assert_eq!(
            keys.server.secret,
            hex::<32>("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")
        );
        assert_eq!(
            &keys.server.key[..16],
            &hex::<16>("cf3a5331653c364c88f0f379b6067e37")
        );
        assert_eq!(keys.server.iv, hex::<12>("0ac1493ca1905853b0bba03e"));
        assert_eq!(
            &keys.server.hp[..16],
            &hex::<16>("c206b8d9b9f0f37644430b490eeaa314")
        );
        assert_eq!(
            keys.client
                .header_mask(&hex("d1b1c98dd7689fb8ec11d242b123dc9b"))
                .unwrap(),
            hex::<5>("437b9aec36")
        );
    }

    // Published fixtures: https://www.rfc-editor.org/rfc/rfc9001#appendix-A.2
    #[test]
    fn rfc9001_a2_client_initial_complete_1200_byte_packet() {
        let mut key = initial_keys(&hex::<8>("8394c8f03e515708")).unwrap().client;
        let header = hex::<22>("c300000001088394c8f03e5157080000449e00000002");
        let crypto = hex::<245>(
            "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868
            04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578
            616d706c652e636f6dff01000100000a00080006001d00170018001000070005
            04616c706e000500050100000000003300260024001d00209370b2c9caa47fba
            baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400
            0d0010000e0403050306030203080408050806002d00020101001c0002400100
            3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000
            75300901100f088394c8f03e51570806048000ffff",
        );
        let expected = hex::<1200>(
            "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11
            d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399
            1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c
            8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212
            30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5
            457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208
            4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec
            4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3
            485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db
            059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c
            7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8
            9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556
            be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74
            68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a
            c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00
            f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632
            291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964
            25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd
            14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff
            ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198
            e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd
            c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73
            203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f
            cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e
            fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade
            a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047
            90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2
            162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4
            40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0
            6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e
            8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0
            be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400
            54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab
            760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9
            f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4
            056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064
            7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241
            e221af44860018ab0856972e194cd934",
        );
        let mut packet = [0; 1200];
        packet[..22].copy_from_slice(&header);
        packet[22..267].copy_from_slice(&crypto);
        assert_eq!(key.seal(2, &header, &mut packet[22..], 1162), Ok(1178));
        key.protect_header(&mut packet, 18).unwrap();
        assert_eq!(packet, expected);
        assert_eq!(key.unprotect_header(&mut packet, 18), Ok(4));
        let (aad, ciphertext) = packet.split_at_mut(22);
        assert_eq!(
            key.open(2, aad, ciphertext, &mut IntegrityBudget::new()),
            Ok(1162)
        );
        assert_eq!(&ciphertext[..245], &crypto);
        assert!(ciphertext[245..1162].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn rfc9001_a3_server_initial_complete_packet() {
        let mut keys = initial_keys(&hex::<8>("8394c8f03e515708")).unwrap();
        let header = hex::<20>("c1000000010008f067a5502a4262b50040750001");
        let plaintext = hex::<99>(
            "02000000000600405a020000560303ee fce7f7b37ba1d1632e96677825ddf739
            88cfc79825df566dc5430b9a045a1200 130100002e00330024001d00209d3c94
            0d89690b84d08a60993c144eca684d10 81287c834d5311bcf32bb9da1a002b00 020304",
        );
        let expected = hex::<135>(
            "cf000000010008f067a5502a4262b500 4075c0d95a482cd0991cd25b0aac406a
            5816b6394100f37a1c69797554780bb3 8cc5a99f5ede4cf73c3ec2493a1839b3
            dbcba3f6ea46c5b7684df3548e7ddeb9 c3bf9c73cc3f3bded74b562bfb19fb84
            022f8ef4cdd93795d77d06edbb7aaf2f 58891850abbdca3d20398c276456cbc4 2158407dd074ee",
        );
        let mut packet = [0; 135];
        packet[..20].copy_from_slice(&header);
        packet[20..119].copy_from_slice(&plaintext);
        assert_eq!(keys.server.seal(1, &header, &mut packet[20..], 99), Ok(115));
        keys.server.protect_header(&mut packet, 18).unwrap();
        assert_eq!(packet, expected);
        assert_eq!(keys.server.unprotect_header(&mut packet, 18), Ok(2));
        assert_eq!(&packet[..20], &header);
        let (aad, ciphertext) = packet.split_at_mut(20);
        assert_eq!(
            keys.server
                .open(1, aad, ciphertext, &mut IntegrityBudget::new()),
            Ok(99)
        );
        assert_eq!(&ciphertext[..99], &plaintext);
    }

    #[test]
    fn rfc9001_a4_retry_integrity_and_corruption() {
        let odcid = hex::<8>("8394c8f03e515708");
        let packet =
            hex::<36>("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba");
        let mut scratch = [0; 64];
        assert_eq!(
            retry_integrity_tag(&odcid, &packet[..20], &mut scratch).unwrap(),
            packet[20..]
        );
        verify_retry(&odcid, &packet, &mut scratch).unwrap();
        for i in 0..packet.len() {
            let mut bad = packet;
            bad[i] ^= 1;
            assert_eq!(
                verify_retry(&odcid, &bad, &mut scratch),
                Err(Error::AuthenticationFailed)
            );
        }
        assert_eq!(
            verify_retry(&[0; 8], &packet, &mut scratch),
            Err(Error::AuthenticationFailed)
        );
        assert_eq!(
            verify_retry(&odcid, &packet, &mut [0; 28]),
            Err(Error::BufferTooSmall)
        );
        assert_eq!(
            verify_retry(&odcid, &packet[..15], &mut scratch),
            Err(Error::BufferTooSmall)
        );
    }

    fn chacha_key() -> PacketKey {
        PacketKey::from_secret(
            CipherSuite::ChaCha20Poly1305Sha256,
            KeyKind::OneRtt,
            &hex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b"),
        )
        .unwrap()
    }

    #[test]
    fn rfc9001_a5_chacha_complete_packet() {
        let mut key = chacha_key();
        assert_eq!(
            key.key,
            hex::<32>("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8")
        );
        assert_eq!(key.iv, hex::<12>("e0459b3474bdd0e44a41c144"));
        assert_eq!(
            key.hp,
            hex::<32>("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4")
        );
        assert_eq!(
            next_traffic_secret(&key.secret).unwrap(),
            hex::<32>("1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9")
        );
        assert_eq!(
            packet_nonce(&key.iv, 654360564).unwrap(),
            hex::<12>("e0459b3474bdd0e46d417eb0")
        );
        assert_eq!(
            key.header_mask(&hex("5e5cd55c41f69080575d7999c25a5bfb"))
                .unwrap(),
            hex::<5>("aefefe7d03")
        );
        let header = hex::<4>("4200bff4");
        let mut packet = [0; 21];
        packet[..4].copy_from_slice(&header);
        packet[4] = 1;
        assert_eq!(key.seal(654360564, &header, &mut packet[4..], 1), Ok(17));
        key.protect_header(&mut packet, 1).unwrap();
        assert_eq!(
            packet,
            hex::<21>("4cfe4189655e5cd55c41f69080575d7999c25a5bfb")
        );
        assert_eq!(key.unprotect_header(&mut packet, 1), Ok(3));
        let (aad, ciphertext) = packet.split_at_mut(4);
        assert_eq!(
            key.open(654360564, aad, ciphertext, &mut IntegrityBudget::new()),
            Ok(1)
        );
        assert_eq!(ciphertext[0], 1);
    }

    #[test]
    fn both_suites_reject_every_corrupted_byte_and_wrong_aad_nonce_key() {
        for suite in [
            CipherSuite::Aes128GcmSha256,
            CipherSuite::ChaCha20Poly1305Sha256,
        ] {
            let mut key = PacketKey::from_secret(suite, KeyKind::Handshake, &[7; 32]).unwrap();
            let mut encrypted = [0; 24];
            encrypted[..8].copy_from_slice(b"a secret");
            key.seal(19, b"header", &mut encrypted, 8).unwrap();
            let mut budget = IntegrityBudget::new();
            for i in 0..24 {
                let mut bad = encrypted;
                bad[i] ^= 1;
                assert_eq!(
                    key.open(19, b"header", &mut bad, &mut budget),
                    Err(Error::AuthenticationFailed)
                );
                assert_eq!(bad, [0; 24]);
            }
            for (pn, aad) in [(20, b"header".as_slice()), (19, b"Header".as_slice())] {
                let mut bad = encrypted;
                assert_eq!(
                    key.open(pn, aad, &mut bad, &mut budget),
                    Err(Error::AuthenticationFailed)
                );
                assert_eq!(bad, [0; 24]);
            }
            let wrong = PacketKey::from_secret(suite, KeyKind::Handshake, &[8; 32]).unwrap();
            let mut bad = encrypted;
            assert_eq!(
                wrong.open(19, b"header", &mut bad, &mut budget),
                Err(Error::AuthenticationFailed)
            );
            assert_eq!(budget.failed_packets(), 27);
            let mut good = encrypted;
            assert_eq!(key.open(19, b"header", &mut good, &mut budget), Ok(8));
            assert_eq!(&good[..8], b"a secret");
            assert_eq!(budget.failed_packets(), 27);
        }
    }

    #[test]
    fn nonce_limits_key_use_and_discard_are_enforced() {
        let mut key = initial_keys(b"destination").unwrap().client;
        let mut data = [9; 32];
        let before = data;
        assert_eq!(
            key.seal(0, b"aad", &mut data, 17),
            Err(Error::BufferTooSmall)
        );
        assert_eq!(data, before);
        assert_eq!(key.sealed_packets(), 0);
        key.seal(10, b"aad", &mut data, 16).unwrap();
        let before = data;
        for pn in [0, 9, 10] {
            assert_eq!(
                key.seal(pn, b"aad", &mut data, 16),
                Err(Error::PacketNumberReuse)
            );
        }
        assert_eq!(data, before);
        assert_eq!(
            key.seal(1 << 62, b"aad", &mut data, 16),
            Err(Error::InvalidPacketNumber)
        );
        key.sealed = 1 << 23;
        assert_eq!(
            key.seal(11, b"aad", &mut data, 16),
            Err(Error::ConfidentialityLimit)
        );
        assert_eq!(key.update_key(), Err(Error::KeyUpdateNotAllowed));
        key.discard();
        assert_eq!(key.secret, [0; 32]);
        assert_eq!(key.key, [0; 32]);
        assert_eq!(key.hp, [0; 32]);
        assert_eq!(key.iv, [0; 12]);
        assert_eq!(
            key.seal(11, b"aad", &mut data, 16),
            Err(Error::KeyDiscarded)
        );
        assert_eq!(
            key.open(11, b"aad", &mut data, &mut IntegrityBudget::new()),
            Err(Error::KeyDiscarded)
        );
        assert_eq!(key.header_mask(&[0; 16]), Err(Error::KeyDiscarded));
        assert_eq!(key.update_key(), Err(Error::KeyDiscarded));
        assert_eq!(
            packet_nonce(&[0; 12], MAX_PACKET_NUMBER).unwrap(),
            [0, 0, 0, 0, 63, 255, 255, 255, 255, 255, 255, 255]
        );
        assert_eq!(
            packet_nonce(&[0; 12], u64::MAX),
            Err(Error::InvalidPacketNumber)
        );
    }

    #[test]
    fn updates_preserve_header_key_packet_numbers_and_global_integrity_budget() {
        let mut key = chacha_key();
        let hp = key.hp;
        let old_key = key.key;
        let mut data = [0; 17];
        key.seal(42, b"aad", &mut data, 1).unwrap();
        let mut budget = IntegrityBudget {
            failed: (1 << 36) - 1,
            limit: 1 << 36,
        };
        key.update_key().unwrap();
        assert_eq!(key.hp, hp);
        assert_ne!(key.key, old_key);
        assert_eq!(key.sealed_packets(), 0);
        assert_eq!(
            key.seal(42, b"aad", &mut data, 1),
            Err(Error::PacketNumberReuse)
        );
        key.seal(43, b"aad", &mut data, 1).unwrap();
        data[0] ^= 1;
        assert_eq!(
            key.open(43, b"aad", &mut data, &mut budget),
            Err(Error::IntegrityLimit)
        );
        assert_eq!(budget.failed_packets(), 1 << 36);
        key.update_key().unwrap();
        assert_eq!(
            key.open(43, b"aad", &mut data, &mut budget),
            Err(Error::IntegrityLimit)
        );
    }

    #[test]
    fn header_bounds_reject_without_partial_mutation() {
        let key = chacha_key();
        let mut packet = [0x43; 20];
        let before = packet;
        assert_eq!(
            key.protect_header(&mut packet, 1),
            Err(Error::BufferTooSmall)
        );
        assert_eq!(
            key.unprotect_header(&mut packet, 1),
            Err(Error::BufferTooSmall)
        );
        assert_eq!(
            key.protect_header(&mut packet, 0),
            Err(Error::InvalidHeader)
        );
        assert_eq!(
            key.protect_header(&mut packet, usize::MAX),
            Err(Error::InvalidHeader)
        );
        assert_eq!(packet, before);
        assert!(matches!(
            initial_keys(&[0; 21]),
            Err(Error::InvalidConnectionId)
        ));
    }

    #[test]
    fn chacha_header_protection_accepts_maximum_u32_counter() {
        let mut key = chacha_key();
        key.hp = [0; 32];
        let mut sample = [0; 16];
        sample[..4].fill(0xff);
        // Independently cross-checked with OpenSSL 3.5.7 enc -chacha20,
        // zero 32-byte key, IV ffffffff000000000000000000000000.
        assert_eq!(key.header_mask(&sample).unwrap(), hex::<5>("ace4cd09e2"));
    }

    #[test]
    fn header_roundtrip_all_packet_number_lengths_and_both_forms() {
        for suite in [
            CipherSuite::Aes128GcmSha256,
            CipherSuite::ChaCha20Poly1305Sha256,
        ] {
            let key = PacketKey::from_secret(suite, KeyKind::Handshake, &[4; 32]).unwrap();
            for first in [0x40, 0xc0] {
                for pn_len in 1..=4 {
                    let mut packet = [0x17; 64];
                    packet[0] = first | (pn_len - 1) as u8;
                    let before = packet;
                    key.protect_header(&mut packet, 7).unwrap();
                    assert_eq!(key.unprotect_header(&mut packet, 7), Ok(pn_len));
                    assert_eq!(packet, before);
                }
            }
        }
    }

    #[test]
    fn empty_payload_max_packet_number_and_size_preconditions() {
        for suite in [
            CipherSuite::Aes128GcmSha256,
            CipherSuite::ChaCha20Poly1305Sha256,
        ] {
            let mut key = PacketKey::from_secret(suite, KeyKind::OneRtt, &[4; 32]).unwrap();
            let mut packet = [0; TAG_LEN];
            assert_eq!(
                key.seal(MAX_PACKET_NUMBER, b"aad", &mut packet, 0),
                Ok(TAG_LEN)
            );
            assert_eq!(
                key.open(
                    MAX_PACKET_NUMBER,
                    b"aad",
                    &mut packet,
                    &mut IntegrityBudget::new()
                ),
                Ok(0)
            );
            assert_eq!(
                key.seal(MAX_PACKET_NUMBER, b"aad", &mut packet, 0),
                Err(Error::PacketNumberReuse)
            );
            assert_eq!(
                key.open(0, b"aad", &mut [0; 15], &mut IntegrityBudget::new()),
                Err(Error::BufferTooSmall)
            );
        }
        assert_eq!(check_packet_len(0, MAX_PROTECTED_PACKET_LEN), Ok(()));
        assert_eq!(
            check_packet_len(1, MAX_PROTECTED_PACKET_LEN),
            Err(Error::PacketTooLarge)
        );
        assert_eq!(check_packet_len(usize::MAX, 1), Err(Error::PacketTooLarge));
    }
}

#[cfg(test)]
mod role_transfer_tests {
    use super::*;

    #[test]
    fn fresh_initial_replacement_retains_nonce_and_confidentiality_guards() {
        let mut previous = initial_keys(b"previous").unwrap().client;
        let mut body = [0; 32];
        previous.seal(7, b"header", &mut body, 3).unwrap();
        let mut replacement = initial_keys(b"replacement").unwrap().client;
        replacement.inherit_send_usage(&previous).unwrap();
        assert_eq!(replacement.last_sealed_packet_number(), Some(7));
        assert_eq!(replacement.sealed_packets(), 1);
        assert_eq!(
            replacement.seal(7, b"header", &mut body, 3),
            Err(Error::PacketNumberReuse)
        );
        replacement.seal(8, b"header", &mut body, 3).unwrap();
        assert_eq!(replacement.sealed_packets(), 2);
        assert_eq!(previous.last_sealed_packet_number(), Some(7));
        assert_eq!(previous.sealed_packets(), 1);
    }

    #[test]
    fn usage_transfer_rejects_used_candidates_and_inactive_or_wrong_kind_keys() {
        let previous = initial_keys(b"previous").unwrap().client;
        let mut used = initial_keys(b"used").unwrap().client;
        used.seal(1, b"header", &mut [0; 32], 3).unwrap();
        assert_eq!(
            used.inherit_send_usage(&previous),
            Err(Error::KeyDerivation)
        );
        assert_eq!(used.last_sealed_packet_number(), Some(1));
        assert_eq!(used.sealed_packets(), 1);
        let mut inactive = initial_keys(b"inactive").unwrap().client;
        inactive.discard();
        assert_eq!(
            inactive.inherit_send_usage(&previous),
            Err(Error::KeyDiscarded)
        );
        let mut fresh = initial_keys(b"fresh").unwrap().client;
        assert_eq!(
            fresh.inherit_send_usage(&inactive),
            Err(Error::KeyDiscarded)
        );
        assert_eq!(fresh.last_sealed_packet_number(), None);
        let mut handshake =
            PacketKey::from_secret(CipherSuite::Aes128GcmSha256, KeyKind::Handshake, &[1; 32])
                .unwrap();
        assert_eq!(
            handshake.inherit_send_usage(&previous),
            Err(Error::KeyDerivation)
        );
        assert_eq!(
            fresh.inherit_send_usage(&handshake),
            Err(Error::KeyDerivation)
        );
        // A corrupted/mismatched suite must also fail closed before copying.
        let mut mismatched = initial_keys(b"mismatch").unwrap().client;
        mismatched.suite = CipherSuite::ChaCha20Poly1305Sha256;
        assert_eq!(
            fresh.inherit_send_usage(&mismatched),
            Err(Error::KeyDerivation)
        );
        assert_eq!(fresh.last_sealed_packet_number(), None);
    }

    #[test]
    fn initial_replacement_cannot_reset_an_exhausted_confidentiality_limit() {
        let mut previous = initial_keys(b"same").unwrap().client;
        previous.sealed = previous.suite.confidentiality_limit();
        let mut replacement = initial_keys(b"same").unwrap().client;
        replacement.inherit_send_usage(&previous).unwrap();
        assert_eq!(
            replacement.seal(1, b"header", &mut [0; 32], 3),
            Err(Error::ConfidentialityLimit)
        );
    }

    #[test]
    fn moved_integrity_budget_leaves_exhausted_owner_until_exact_budget_returns() {
        let mut owner = IntegrityBudget {
            failed: 3,
            limit: 10,
        };
        let mut moved = owner.take_for_role();
        assert_eq!(moved.failed, 3);
        assert_eq!(moved.limit, 10);
        assert_eq!(owner.failed, 3);
        assert_eq!(
            owner.before_attempt(CipherSuite::Aes128GcmSha256),
            Err(Error::IntegrityLimit)
        );
        assert_eq!(
            owner
                .take_for_role()
                .before_attempt(CipherSuite::Aes128GcmSha256),
            Err(Error::IntegrityLimit)
        );
        moved.before_attempt(CipherSuite::Aes128GcmSha256).unwrap();
        assert_eq!(moved.record_failure(), Error::AuthenticationFailed);
        owner = moved;
        assert_eq!(owner.failed, 4);
        assert_eq!(owner.limit, 10);
        owner.before_attempt(CipherSuite::Aes128GcmSha256).unwrap();
    }

    #[test]
    fn cancelling_transferred_integrity_budget_cannot_restore_the_source() {
        let mut owner = IntegrityBudget::new();
        {
            let _moved = owner.take_for_role();
        }
        assert_eq!(
            owner.before_attempt(CipherSuite::Aes128GcmSha256),
            Err(Error::IntegrityLimit)
        );
        let exhausted = owner.take_for_role();
        assert_eq!(exhausted.limit, 0);
    }
}

#[cfg(test)]
mod external_authentication_budget_tests {
    use super::{AuthenticationError, IntegrityBudget};
    use core::cell::Cell;

    #[test]
    fn actual_attempts_debit_once_and_success_never_debits() {
        let calls = Cell::new(0);
        let mut budget = IntegrityBudget::new();
        assert_eq!(
            budget.authenticate(4, || {
                calls.set(calls.get() + 1);
                Err::<(), _>(7)
            }),
            Err(AuthenticationError::Failed(7))
        );
        assert_eq!(budget.failed_packets(), 1);
        assert_eq!(
            budget.authenticate(4, || {
                calls.set(calls.get() + 1);
                Ok::<_, u8>(9)
            }),
            Ok(9)
        );
        assert_eq!(budget.failed_packets(), 1);
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn final_failure_is_terminal_and_exhaustion_never_invokes_backend() {
        let calls = Cell::new(0);
        let mut budget = IntegrityBudget::new();
        assert_eq!(
            budget.authenticate(1, || {
                calls.set(calls.get() + 1);
                Err::<(), _>(7)
            }),
            Err(AuthenticationError::IntegrityLimit)
        );
        assert_eq!(budget.failed_packets(), 1);
        assert_eq!(
            budget.authenticate(u64::MAX, || {
                calls.set(calls.get() + 1);
                Ok::<(), u8>(())
            }),
            Err(AuthenticationError::IntegrityLimit)
        );
        assert_eq!(calls.get(), 1);
        assert_eq!(budget.failed_packets(), 1);
    }

    #[test]
    fn encountered_limits_only_tighten_even_after_success() {
        let mut budget = IntegrityBudget::new();
        assert_eq!(
            budget.authenticate(10, || Err::<(), _>(7)),
            Err(AuthenticationError::Failed(7))
        );
        assert_eq!(budget.authenticate(2, || Ok::<(), u8>(())), Ok(()));
        assert_eq!(
            budget.authenticate(10, || Err::<(), _>(8)),
            Err(AuthenticationError::IntegrityLimit)
        );
        assert_eq!(budget.failed_packets(), 2);
        assert_eq!(budget.limit, 2);
    }

    #[test]
    fn loan_tombstone_never_invokes_external_backend() {
        let mut owner = IntegrityBudget::new();
        let mut loan = owner.take_for_role();
        assert_eq!(
            owner.authenticate(u64::MAX, || -> Result<(), u8> {
                panic!("loan tombstone invoked backend")
            }),
            Err(AuthenticationError::IntegrityLimit)
        );
        assert_eq!(
            loan.authenticate(3, || Err::<(), _>(7)),
            Err(AuthenticationError::Failed(7))
        );
        owner = loan;
        assert_eq!(owner.failed_packets(), 1);
        assert_eq!(owner.authenticate(3, || Ok::<(), u8>(())), Ok(()));
    }
}

/// Domain-separated binding to the exact authenticated plaintext.
pub(crate) fn plaintext_digest(plaintext: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(b"hibana-quic:packet-plaintext:v1\0");
    digest.update((plaintext.len() as u64).to_be_bytes());
    digest.update(plaintext);
    digest.finalize().into()
}
