//! Bounded SHA-256 TLS 1.3 transcript and key schedule (RFC 8446 §§4.4, 7).
//!
//! This is NOT a TLS backend or a handshake-completion/authentication oracle.
//! It does not parse negotiation, perform ECDHE, verify CertificateVerify/X.509,
//! authorize 0-RTT, store tickets, or implement QUIC key-phase lifecycle. Callers
//! must supply validated complete handshake messages and a validated fresh ECDHE
//! result, and enforce the client/server handshake state machine separately.
//! No allocation, entropy source, clock, or TLS record I/O is used here.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

pub const HASH_LEN: usize = 32;
pub const MAX_HKDF_OUTPUT: usize = 255 * HASH_LEN;
const MAX_TRANSCRIPT_BYTES: u64 = u64::MAX / 8;
const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Truncated,
    TrailingData,
    InvalidMessage,
    TranscriptOverflow,
    HelloRetryRequestRequired,
    InvalidHelloRetryRequest,
    WrongStage,
    InvalidSharedSecret,
    InvalidPsk,
    InvalidLabel,
    InvalidContext,
    OutputTooLong,
    Derivation,
    FinishedAuthentication,
    Discarded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Side {
    Client,
    Server,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PskKind {
    External,
    Resumption,
}

/// These are key-schedule stages, not authenticated TLS connection states.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    Early,
    Handshake,
    Master,
    Resumption,
    Discarded,
}

/// Non-Clone and non-Debug secret, wiped on drop. Borrowing is necessary to pass
/// traffic secrets to packet protection; callers must not log or retain copies.
/// Dependency-internal temporary zeroization is not claimed by this wrapper.
pub struct Secret32([u8; HASH_LEN]);

impl Secret32 {
    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }
}
impl Drop for Secret32 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A resumption-only owner extracted after the authenticated TLS handshake.
/// It retains no handshake/application/exporter secrets, is non-Clone/non-Debug,
/// and its sole 32-byte secret is zeroized on drop. Ticket nonce uniqueness,
/// lifetime, identity binding and storage policy belong to the ticket manager.
pub struct ResumptionMaster(Secret32);

impl ResumptionMaster {
    pub fn derive(&self, ticket_nonce: &[u8]) -> Result<Secret32, Error> {
        derive_resumption_psk(&self.0, ticket_nonce)
    }
}

fn derive_resumption_psk(master: &Secret32, ticket_nonce: &[u8]) -> Result<Secret32, Error> {
    let mut psk = Secret32([0; HASH_LEN]);
    expand_label(master.as_bytes(), b"resumption", ticket_nonce, &mut psk.0)?;
    Ok(psk)
}

/// Incremental transcript storage has fixed size independent of transcript size.
/// append accepts exactly one complete encoded TLS Handshake message, including
/// its four-byte header. Reassembly/framing and TLS message semantics are external.
pub struct Transcript {
    hash: Sha256,
    bytes: u64,
    messages: u64,
    last_kind: Option<u8>,
    retried: bool,
    last_was_hrr: bool,
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}

impl Transcript {
    pub fn new() -> Self {
        Self {
            hash: Sha256::new(),
            bytes: 0,
            messages: 0,
            last_kind: None,
            retried: false,
            last_was_hrr: false,
        }
    }
    pub fn hash(&self) -> [u8; HASH_LEN] {
        self.hash.clone().finalize().into()
    }
    pub fn encoded_bytes(&self) -> u64 {
        self.bytes
    }
    pub fn message_count(&self) -> u64 {
        self.messages
    }
    pub fn had_hello_retry_request(&self) -> bool {
        self.retried
    }

    /// Framing/state errors leave the existing digest unchanged. A synthetic
    /// message_hash can only be inserted by apply_hello_retry_request.
    pub fn append(&mut self, message: &[u8]) -> Result<(), Error> {
        let kind = validate_message(message)?;
        if kind == 254 || (self.messages == 0 && kind != 1) {
            return Err(Error::InvalidMessage);
        }
        if is_hrr(message) {
            return Err(Error::HelloRetryRequestRequired);
        }
        let bytes = self
            .bytes
            .checked_add(message.len() as u64)
            .filter(|n| *n <= MAX_TRANSCRIPT_BYTES)
            .ok_or(Error::TranscriptOverflow)?;
        let messages = self
            .messages
            .checked_add(1)
            .ok_or(Error::TranscriptOverflow)?;
        self.hash.update(message);
        self.bytes = bytes;
        self.messages = messages;
        self.last_kind = Some(kind);
        self.last_was_hrr = false;
        Ok(())
    }

    /// RFC 8446 §4.4.1: replace ClientHello1 with message_hash(Hash(CH1)),
    /// then append the real HRR. Only one HRR, immediately after CH1, is accepted.
    pub fn apply_hello_retry_request(&mut self, hrr: &[u8]) -> Result<(), Error> {
        validate_message(hrr)?;
        if self.retried || self.messages != 1 || self.last_kind != Some(1) || !is_hrr(hrr) {
            return Err(Error::InvalidHelloRetryRequest);
        }
        let first_hash = self.hash();
        let mut hash = Sha256::new();
        hash.update([254, 0, 0, HASH_LEN as u8]);
        hash.update(first_hash);
        hash.update(hrr);
        self.hash = hash;
        self.bytes = 36 + hrr.len() as u64;
        self.messages = 2;
        self.last_kind = Some(2);
        self.retried = true;
        self.last_was_hrr = true;
        Ok(())
    }

    /// Snapshot for a PSK binder without committing the intentionally truncated
    /// ClientHello. Caller must truncate exactly before the binders vector as
    /// RFC 8446 §4.2.11.2 requires. This is valid before CH1, or just after HRR.
    pub fn binder_hash(&self, client_hello_prefix: &[u8]) -> Result<[u8; HASH_LEN], Error> {
        if self.messages != 0 && !self.last_was_hrr {
            return Err(Error::WrongStage);
        }
        if client_hello_prefix.len() < 4 {
            return Err(Error::Truncated);
        }
        if client_hello_prefix[0] != 1 {
            return Err(Error::InvalidMessage);
        }
        let full_len = body_len(client_hello_prefix) + 4;
        if client_hello_prefix.len() >= full_len {
            return Err(Error::InvalidMessage);
        }
        let mut hash = self.hash.clone();
        hash.update(client_hello_prefix);
        Ok(hash.finalize().into())
    }
}

fn body_len(message: &[u8]) -> usize {
    ((message[1] as usize) << 16) | ((message[2] as usize) << 8) | message[3] as usize
}
fn validate_message(message: &[u8]) -> Result<u8, Error> {
    if message.len() < 4 {
        return Err(Error::Truncated);
    }
    let len = body_len(message) + 4;
    if message.len() < len {
        return Err(Error::Truncated);
    }
    if message.len() > len {
        return Err(Error::TrailingData);
    }
    Ok(message[0])
}
fn is_hrr(message: &[u8]) -> bool {
    message.len() >= 38 && message[0] == 2 && message[6..38] == HRR_RANDOM
}

/// Owned SHA-256 schedule, supporting ECDHE handshakes with an optional PSK.
/// Advancing stages wipes the replaced main secret. Finished verification failure
/// terminally discards every retained secret. The caller still MUST verify the
/// certificate chain/signature and enforce handshake semantics before advancing.
pub struct KeySchedule {
    secret: Option<Secret32>,
    with_psk: bool,
    client_handshake: Option<Secret32>,
    server_handshake: Option<Secret32>,
    client_application: Option<Secret32>,
    server_application: Option<Secret32>,
    exporter: Option<Secret32>,
    resumption: Option<Secret32>,
    server_finished_bytes: u64,
}

impl KeySchedule {
    /// None uses the RFC-mandated Hash.length zeros for the no-PSK schedule.
    /// This zero input is a standard schedule input, never a replacement for ECDHE.
    pub fn new(psk: Option<&[u8]>) -> Result<Self, Error> {
        if psk.is_some_and(|psk| psk.is_empty()) {
            return Err(Error::InvalidPsk);
        }
        let secret = extract(&[0; HASH_LEN], psk.unwrap_or(&[0; HASH_LEN]));
        Ok(Self {
            secret: Some(secret),
            with_psk: psk.is_some(),
            client_handshake: None,
            server_handshake: None,
            client_application: None,
            server_application: None,
            exporter: None,
            resumption: None,
            server_finished_bytes: 0,
        })
    }
    /// Read-only description of actual retained key material, not a stored
    /// protocol controller. TLS ordering belongs to the projected owners.
    pub fn stage(&self) -> Stage {
        if self.resumption.is_some() {
            Stage::Resumption
        } else if self.secret.is_none() {
            Stage::Discarded
        } else if self.client_application.is_some() {
            Stage::Master
        } else if self.client_handshake.is_some() {
            Stage::Handshake
        } else {
            Stage::Early
        }
    }
    fn require(&self, stage: Stage) -> Result<(), Error> {
        if self.stage() == Stage::Discarded {
            Err(Error::Discarded)
        } else if self.stage() != stage {
            Err(Error::WrongStage)
        } else {
            Ok(())
        }
    }

    pub fn discard(&mut self) {
        self.secret = None;
        self.client_handshake = None;
        self.server_handshake = None;
        self.client_application = None;
        self.server_application = None;
        self.exporter = None;
        self.resumption = None;
    }

    /// Generate the PSK binder over the correctly truncated transcript hash.
    /// Ticket lookup, age, PSK identity, anti-replay policy, and binder placement
    /// are external. No early data is authorized by producing this MAC.
    pub fn binder(
        &self,
        kind: PskKind,
        transcript_hash: &[u8; HASH_LEN],
    ) -> Result<[u8; HASH_LEN], Error> {
        self.require(Stage::Early)?;
        if !self.with_psk {
            return Err(Error::InvalidPsk);
        }
        let label = match kind {
            PskKind::External => b"ext binder",
            PskKind::Resumption => b"res binder",
        };
        let binder_key = derive_secret(
            self.secret.as_ref().ok_or(Error::Discarded)?,
            label,
            &empty_hash(),
        )?;
        finished(&binder_key, transcript_hash)
    }

    pub fn client_early_traffic(&self, client_hello: &Transcript) -> Result<Secret32, Error> {
        self.require(Stage::Early)?;
        if !self.with_psk {
            return Err(Error::InvalidPsk);
        }
        if client_hello.messages != 1 || client_hello.last_kind != Some(1) {
            return Err(Error::WrongStage);
        }
        derive_secret(
            self.secret.as_ref().ok_or(Error::Discarded)?,
            b"c e traffic",
            &client_hello.hash(),
        )
    }

    /// Install validated fresh (EC)DHE output and derive both handshake secrets.
    /// Group/public-key validation remains the ECDHE provider's responsibility.
    /// This implementation deliberately does not support PSK-only psk_ke.
    pub fn derive_handshake(
        &mut self,
        shared_secret: &[u8],
        through_server_hello: &Transcript,
    ) -> Result<(), Error> {
        self.require(Stage::Early)?;
        if shared_secret.is_empty()
            || bool::from(shared_secret.iter().fold(0u8, |a, b| a | b).ct_eq(&0))
        {
            return Err(Error::InvalidSharedSecret);
        }
        if through_server_hello.last_kind != Some(2)
            || through_server_hello.last_was_hrr
            || through_server_hello.messages < 2
        {
            return Err(Error::WrongStage);
        }
        let derived = derive_secret(
            self.secret.as_ref().ok_or(Error::Discarded)?,
            b"derived",
            &empty_hash(),
        )?;
        let handshake = extract(derived.as_bytes(), shared_secret);
        let hash = through_server_hello.hash();
        let client = derive_secret(&handshake, b"c hs traffic", &hash)?;
        let server = derive_secret(&handshake, b"s hs traffic", &hash)?;
        self.secret = Some(handshake);
        self.client_handshake = Some(client);
        self.server_handshake = Some(server);
        Ok(())
    }

    pub fn handshake_traffic(&self, side: Side) -> Result<&Secret32, Error> {
        if self.stage() == Stage::Discarded {
            return Err(Error::Discarded);
        }
        match side {
            Side::Client => self.client_handshake.as_ref(),
            Side::Server => self.server_handshake.as_ref(),
        }
        .ok_or(Error::WrongStage)
    }

    /// Compute Finished before adding that Finished to the transcript.
    pub fn finished_verify_data(
        &self,
        side: Side,
        before_finished: &Transcript,
    ) -> Result<[u8; HASH_LEN], Error> {
        self.require(match side {
            Side::Server => Stage::Handshake,
            Side::Client => Stage::Master,
        })?;
        finished(self.handshake_traffic(side)?, &before_finished.hash())
    }

    /// Verify exactly 32 bytes in constant time. Wrong-length or mismatched MAC
    /// terminally destroys this schedule. A success proves possession of the
    /// handshake secret, not certificate/hostname authentication by itself.
    pub fn verify_finished(
        &mut self,
        side: Side,
        before_finished: &Transcript,
        received: &[u8],
    ) -> Result<(), Error> {
        let expected = self.finished_verify_data(side, before_finished)?;
        if received.len() != HASH_LEN || !bool::from(expected.as_slice().ct_eq(received)) {
            self.discard();
            return Err(Error::FinishedAuthentication);
        }
        Ok(())
    }

    /// Derive master, application traffic, and exporter master using the
    /// transcript THROUGH server Finished. This does not declare TLS complete.
    pub fn derive_master(&mut self, through_server_finished: &Transcript) -> Result<(), Error> {
        self.require(Stage::Handshake)?;
        if through_server_finished.last_kind != Some(20) {
            return Err(Error::WrongStage);
        }
        let derived = derive_secret(
            self.secret.as_ref().ok_or(Error::Discarded)?,
            b"derived",
            &empty_hash(),
        )?;
        let master = extract(derived.as_bytes(), &[0; HASH_LEN]);
        let hash = through_server_finished.hash();
        let client = derive_secret(&master, b"c ap traffic", &hash)?;
        let server = derive_secret(&master, b"s ap traffic", &hash)?;
        let exporter = derive_secret(&master, b"exp master", &hash)?;
        self.secret = Some(master);
        self.client_application = Some(client);
        self.server_application = Some(server);
        self.exporter = Some(exporter);
        self.server_finished_bytes = through_server_finished.bytes;
        Ok(())
    }

    pub fn application_traffic(&self, side: Side) -> Result<&Secret32, Error> {
        if self.stage() == Stage::Discarded {
            return Err(Error::Discarded);
        }
        match side {
            Side::Client => self.client_application.as_ref(),
            Side::Server => self.server_application.as_ref(),
        }
        .ok_or(Error::WrongStage)
    }

    /// Derive resumption master using the transcript THROUGH client Finished,
    /// then discard the main master and handshake traffic secrets.
    pub fn derive_resumption(&mut self, through_client_finished: &Transcript) -> Result<(), Error> {
        self.require(Stage::Master)?;
        if through_client_finished.last_kind != Some(20)
            || through_client_finished.bytes <= self.server_finished_bytes
        {
            return Err(Error::WrongStage);
        }
        let resumption = derive_secret(
            self.secret.as_ref().ok_or(Error::Discarded)?,
            b"res master",
            &through_client_finished.hash(),
        )?;
        self.resumption = Some(resumption);
        self.secret = None;
        self.client_handshake = None;
        self.server_handshake = None;
        Ok(())
    }

    /// Derive one ticket's PSK. Enforce unique ticket_nonce and secure bounded
    /// ticket storage in the separate ticket manager; this function stores none.
    pub fn resumption_psk(&self, ticket_nonce: &[u8]) -> Result<Secret32, Error> {
        self.require(Stage::Resumption)?;
        derive_resumption_psk(
            self.resumption.as_ref().ok_or(Error::WrongStage)?,
            ticket_nonce,
        )
    }

    /// Move the resumption master into its own small owner exactly once, then
    /// discard this entire schedule. Only the Resumption stage permits this;
    /// the caller still establishes peer authentication and the transcript.
    pub fn take_resumption_master(&mut self) -> Result<ResumptionMaster, Error> {
        self.require(Stage::Resumption)?;
        let master = self.resumption.take().ok_or(Error::WrongStage)?;
        self.discard();
        Ok(ResumptionMaster(master))
    }

    /// RFC 8446 §7.5 exporter into caller-owned output. Call only after the
    /// surrounding TLS machine has authenticated the peer/handshake.
    pub fn export(&self, label: &[u8], context: &[u8], output: &mut [u8]) -> Result<(), Error> {
        if self.stage() == Stage::Discarded {
            return Err(Error::Discarded);
        }
        let exporter = self.exporter.as_ref().ok_or(Error::WrongStage)?;
        let secret = derive_secret(exporter, label, &empty_hash())?;
        let context_hash: [u8; HASH_LEN] = Sha256::digest(context).into();
        expand_label(secret.as_bytes(), b"exporter", &context_hash, output)
    }
}
impl Drop for KeySchedule {
    fn drop(&mut self) {
        self.discard();
    }
}

fn empty_hash() -> [u8; HASH_LEN] {
    Sha256::digest([]).into()
}
fn extract(salt: &[u8; HASH_LEN], input: &[u8]) -> Secret32 {
    let (mut secret, _) = Hkdf::<Sha256>::extract(Some(salt), input);
    let mut result = Secret32([0; HASH_LEN]);
    result.0.copy_from_slice(&secret);
    secret.zeroize();
    result
}
fn derive_secret(
    secret: &Secret32,
    label: &[u8],
    transcript_hash: &[u8; HASH_LEN],
) -> Result<Secret32, Error> {
    let mut out = Secret32([0; HASH_LEN]);
    expand_label(secret.as_bytes(), label, transcript_hash, &mut out.0)?;
    Ok(out)
}
fn finished(secret: &Secret32, transcript_hash: &[u8; HASH_LEN]) -> Result<[u8; HASH_LEN], Error> {
    let mut key = Secret32([0; HASH_LEN]);
    expand_label(secret.as_bytes(), b"finished", &[], &mut key.0)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).map_err(|_| Error::Derivation)?;
    mac.update(transcript_hash);
    Ok(mac.finalize().into_bytes().into())
}

/// RFC 8446 HkdfLabel serialization via disjoint slices, with fixed-size
/// metadata. No maximum-size label/context staging buffer is allocated.
fn expand_label(
    secret: &[u8; HASH_LEN],
    label: &[u8],
    context: &[u8],
    output: &mut [u8],
) -> Result<(), Error> {
    if label.is_empty() || label.len() > 249 {
        return Err(Error::InvalidLabel);
    }
    if context.len() > 255 {
        return Err(Error::InvalidContext);
    }
    if output.len() > MAX_HKDF_OUTPUT {
        return Err(Error::OutputTooLong);
    }
    let length = (output.len() as u16).to_be_bytes();
    let label_len = [(6 + label.len()) as u8];
    let context_len = [context.len() as u8];
    Hkdf::<Sha256>::from_prk(secret)
        .map_err(|_| Error::Derivation)?
        .expand_multi_info(
            &[&length, &label_len, b"tls13 ", label, &context_len, context],
            output,
        )
        .map_err(|_| Error::Derivation)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex<const N: usize>(text: &str) -> [u8; N] {
        let mut out = [0; N];
        let mut n = 0;
        for ch in text.bytes().filter(|ch| !ch.is_ascii_whitespace()) {
            let x = match ch {
                b'0'..=b'9' => ch - b'0',
                b'a'..=b'f' => ch - b'a' + 10,
                _ => panic!("bad hex"),
            };
            assert!(n / 2 < N);
            out[n / 2] = (out[n / 2] << 4) | x;
            n += 1;
        }
        assert_eq!(n, N * 2);
        out
    }

    // Published binary fixtures from RFC 8448 §§3, 4, 5:
    // https://www.rfc-editor.org/rfc/rfc8448
    fn ch() -> [u8; 196] {
        hex(
            "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef
            6283024dece7000006130113031302010000910000000b000900000673657276
            6572ff01000100000a00140012001d0017001800190100010101020103010400
            230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e
            51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603
            020308040805080604010501060102010402050206020202002d00020101001c
            00024001",
        )
    }
    fn sh() -> [u8; 90] {
        hex(
            "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155
            772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdb
            f7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304",
        )
    }
    fn ee() -> [u8; 40] {
        hex(
            "080000240022000a00140012001d00170018001901000101010201030104001c
            0002400100000000",
        )
    }
    fn cert() -> [u8; 445] {
        hex(
            "0b0001b9000001b50001b0308201ac30820115a003020102020102300d06092a
            864886f70d01010b0500300e310c300a06035504031303727361301e170d3136
            303733303031323335395a170d3236303733303031323335395a300e310c300a
            0603550403130372736130819f300d06092a864886f70d010101050003818d00
            30818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826
            d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced4312
            0998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda4308467480
            30530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a
            8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b060355
            1d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5
            b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a5
            8c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102
            702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0
            a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de10000",
        )
    }
    fn cv() -> [u8; 136] {
        hex(
            "0f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f824cd484145a
            b3ff52f1fda8477b0b7abc90db78e2d33a5c141a078653fa6bef780c5ea248ee
            aaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac027671459e46445c
            9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda65cdf5aea2
            0d53dfacd42f74f3",
        )
    }
    fn server_fin() -> [u8; 36] {
        hex(
            "140000209b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454
            b78f0718",
        )
    }
    fn client_fin() -> [u8; 36] {
        hex(
            "14000020a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2
            edd5ce61",
        )
    }
    fn hrr_ch1() -> [u8; 180] {
        hex(
            "010000b00303b0b1c5a5aa37c5919f2ed1d5c6fff7fcb7849716945a2b8cee92
            58a346677b6f000006130113031302010000810000000b000900000673657276
            6572ff01000100000a00080006001d00170018003300260024001d0020e8e8e3
            f3b93a25ed97a14a7dcacb8a272c6288e585c6484d05262fcad062ad1f002b00
            03020304000d0020001e04030503060302030804080508060401050106010201
            0402050206020202002d00020101001c00024001",
        )
    }
    fn hrr_ch2() -> [u8; 512] {
        hex(
            "010001fc0303b0b1c5a5aa37c5919f2ed1d5c6fff7fcb7849716945a2b8cee92
            58a346677b6f000006130113031302010001cd0000000b000900000673657276
            6572ff01000100000a00080006001d001700180033004700450017004104a6da
            7392ec591e17abfd535964b99894d13befb221b3def2ebe3830eac8f01518126
            77c4d6d2237e85cf01d6910cfb83954e76ba7352830534159897e8065780002b
            0003020304000d0020001e040305030603020308040805080604010501060102
            010402050206020202002c0074007271dcd04bb88bc3189119398a00000000ee
            fafc76c146b823b096f8aacad365dd0030953f4edf625636e5f21bb2e23fcc65
            4b1b5b40318d10d137abcbb87574e36e8a1f025f7dfa5d6e50781b5eda4aa15b
            0c8be778257d16aa3030e9e7841dd9e4c0342267e8ca0caf571fb2b7cff0f934
            b0002d00020101001c00024001001500af000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000",
        )
    }
    fn hrr() -> [u8; 176] {
        hex(
            "020000ac0303cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e
            09e2c8a8339c001301000084003300020017002c0074007271dcd04bb88bc318
            9119398a00000000eefafc76c146b823b096f8aacad365dd0030953f4edf6256
            36e5f21bb2e23fcc654b1b5b40318d10d137abcbb87574e36e8a1f025f7dfa5d
            6e50781b5eda4aa15b0c8be778257d16aa3030e9e7841dd9e4c0342267e8ca0c
            af571fb2b7cff0f934b0002b00020304",
        )
    }
    fn hrr_sh() -> [u8; 123] {
        hex(
            "020000770303bb341d847fd789c47c387172dc0c9bf147fccacb5043d86ca4c5
            98d3ff571b9800130100004f003300450017004104583e054b7a66672ae020ad
            9d2686fcc85b5ad41a134a0f03ee72b893052bd85b4c8de6776f5b04ac07d835
            40eab3e3d9c547bc6528c4317d294686093a6cad7d002b00020304",
        )
    }
    fn psk_prefix() -> [u8; 477] {
        hex(
            "010001fc03031bc3ceb6bbe39cff938355b5a50adb6db21b7a6af649d7b4bc41
            9d7876487d95000006130113031302010001cd0000000b000900000673657276
            6572ff01000100000a00140012001d0017001800190100010101020103010400
            3300260024001d0020e4ffb68ac05f8d96c99da26698346c6be16482badddafe
            051a66b4f18d668f0b002a0000002b0003020304000d0020001e040305030603
            020308040805080604010501060102010402050206020202002d00020101001c
            0002400100150057000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            2900dd00b800b22c035d829359ee5ff7af4ec900000000262a6494dc486d2c8a
            34cb33fa90bf1b0070ad3c498883c9367c09a2be785abc55cd226097a3a98211
            7283f82a03a143efd3ff5dd36d64e861be7fd61d2827db279cce145077d454a3
            664d4e6da4d29ee03725a6a4dafcd0fc67d2aea70529513e3da2677fa5906c5b
            3f7d8f92f228bda40dda721470f9fbf297b5aea617646fac5c03272e970727c6
            21a79141ef5f7de6505e5bfbc388e93343694093934ae4d357fad6aacb",
        )
    }
    fn psk_ch() -> [u8; 512] {
        hex(
            "010001fc03031bc3ceb6bbe39cff938355b5a50adb6db21b7a6af649d7b4bc41
            9d7876487d95000006130113031302010001cd0000000b000900000673657276
            6572ff01000100000a00140012001d0017001800190100010101020103010400
            3300260024001d0020e4ffb68ac05f8d96c99da26698346c6be16482badddafe
            051a66b4f18d668f0b002a0000002b0003020304000d0020001e040305030603
            020308040805080604010501060102010402050206020202002d00020101001c
            0002400100150057000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000000000000000000000000000000000
            2900dd00b800b22c035d829359ee5ff7af4ec900000000262a6494dc486d2c8a
            34cb33fa90bf1b0070ad3c498883c9367c09a2be785abc55cd226097a3a98211
            7283f82a03a143efd3ff5dd36d64e861be7fd61d2827db279cce145077d454a3
            664d4e6da4d29ee03725a6a4dafcd0fc67d2aea70529513e3da2677fa5906c5b
            3f7d8f92f228bda40dda721470f9fbf297b5aea617646fac5c03272e970727c6
            21a79141ef5f7de6505e5bfbc388e93343694093934ae4d357fad6aacb002120
            3add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d",
        )
    }

    fn through_server_hello() -> Transcript {
        let mut transcript = Transcript::new();
        transcript.append(&ch()).unwrap();
        transcript.append(&sh()).unwrap();
        transcript
    }
    fn schedule() -> (KeySchedule, Transcript) {
        let mut schedule = KeySchedule::new(None).unwrap();
        let transcript = through_server_hello();
        schedule
            .derive_handshake(
                &hex::<32>("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"),
                &transcript,
            )
            .unwrap();
        (schedule, transcript)
    }
    fn append_server_authentication(transcript: &mut Transcript) {
        transcript.append(&ee()).unwrap();
        transcript.append(&cert()).unwrap();
        transcript.append(&cv()).unwrap();
    }

    #[test]
    fn rfc8448_section3_full_schedule_transcript_finished_and_ticket() {
        let mut schedule = KeySchedule::new(None).unwrap();
        assert_eq!(
            schedule.secret.as_ref().unwrap().as_bytes(),
            &hex::<32>("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")
        );
        let mut transcript = through_server_hello();
        assert_eq!(
            transcript.hash(),
            hex::<32>("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8")
        );
        schedule
            .derive_handshake(
                &hex::<32>("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"),
                &transcript,
            )
            .unwrap();
        assert_eq!(
            schedule.secret.as_ref().unwrap().as_bytes(),
            &hex::<32>("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac")
        );
        assert_eq!(
            schedule.handshake_traffic(Side::Client).unwrap().as_bytes(),
            &hex::<32>("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
        );
        assert_eq!(
            schedule.handshake_traffic(Side::Server).unwrap().as_bytes(),
            &hex::<32>("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
        );
        append_server_authentication(&mut transcript);
        assert_eq!(
            schedule
                .finished_verify_data(Side::Server, &transcript)
                .unwrap(),
            server_fin()[4..]
        );
        schedule
            .verify_finished(Side::Server, &transcript, &server_fin()[4..])
            .unwrap();
        transcript.append(&server_fin()).unwrap();
        assert_eq!(
            transcript.hash(),
            hex::<32>("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13")
        );
        schedule.derive_master(&transcript).unwrap();
        assert_eq!(
            schedule.secret.as_ref().unwrap().as_bytes(),
            &hex::<32>("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919")
        );
        assert_eq!(
            schedule
                .application_traffic(Side::Client)
                .unwrap()
                .as_bytes(),
            &hex::<32>("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5")
        );
        assert_eq!(
            schedule
                .application_traffic(Side::Server)
                .unwrap()
                .as_bytes(),
            &hex::<32>("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643")
        );
        assert_eq!(
            schedule.exporter.as_ref().unwrap().as_bytes(),
            &hex::<32>("fe22f881176eda18eb8f44529e6792c50c9a3f89452f68d8ae311b4309d3cf50")
        );
        assert_eq!(
            schedule
                .finished_verify_data(Side::Client, &transcript)
                .unwrap(),
            client_fin()[4..]
        );
        schedule
            .verify_finished(Side::Client, &transcript, &client_fin()[4..])
            .unwrap();
        transcript.append(&client_fin()).unwrap();
        assert_eq!(
            transcript.hash(),
            hex::<32>("209145a96ee8e2a122ff810047cc952684658d6049e86429426db87c54ad143d")
        );
        schedule.derive_resumption(&transcript).unwrap();
        assert_eq!(
            schedule.resumption.as_ref().unwrap().as_bytes(),
            &hex::<32>("7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec196c")
        );
        assert_eq!(
            schedule.resumption_psk(&[0, 0]).unwrap().as_bytes(),
            &hex::<32>("4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3")
        );
        assert!(schedule.handshake_traffic(Side::Client).is_err());
        assert!(schedule.secret.is_none());
    }

    #[test]
    fn rfc8448_section5_hrr_transcript_and_handshake_keys() {
        let mut transcript = Transcript::new();
        transcript.append(&hrr_ch1()).unwrap();
        let unchanged = transcript.hash();
        assert_eq!(
            transcript.append(&hrr()),
            Err(Error::HelloRetryRequestRequired)
        );
        assert_eq!(transcript.hash(), unchanged);
        transcript.apply_hello_retry_request(&hrr()).unwrap();
        assert!(transcript.had_hello_retry_request());
        assert_eq!(
            transcript.apply_hello_retry_request(&hrr()),
            Err(Error::InvalidHelloRetryRequest)
        );
        transcript.append(&hrr_ch2()).unwrap();
        transcript.append(&hrr_sh()).unwrap();
        assert_eq!(
            transcript.hash(),
            hex::<32>("8aa8e828ec2f8a884fec95a3139de01c15a3daa7ff5bfc3f4bfcc21b438d7bf8")
        );
        let mut schedule = KeySchedule::new(None).unwrap();
        schedule
            .derive_handshake(
                &hex::<32>("c142ce13ca11b5c2233652e63ad3d97844f1621fbfb9de69d547dc8fedeabeb4"),
                &transcript,
            )
            .unwrap();
        assert_eq!(
            schedule.secret.as_ref().unwrap().as_bytes(),
            &hex::<32>("ce022e5e6e81e50736d773f2d3adfce8220d049bf510f0dbfac927ef4243b148")
        );
        assert_eq!(
            schedule.handshake_traffic(Side::Client).unwrap().as_bytes(),
            &hex::<32>("158aa7ab8855073582b41d674b4055cabcc534728f659314861b4e08e2011566")
        );
        assert_eq!(
            schedule.handshake_traffic(Side::Server).unwrap().as_bytes(),
            &hex::<32>("3403e781e2af7b6508da28574f6e95a1abf162de83a97927c37672a4a0cef8a1")
        );
    }

    #[test]
    fn rfc8448_section4_resumption_binder_and_early_traffic() {
        let psk = hex::<32>("4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3");
        let schedule = KeySchedule::new(Some(&psk)).unwrap();
        assert_eq!(
            schedule.secret.as_ref().unwrap().as_bytes(),
            &hex::<32>("9b2188e9b2fc6d64d71dc329900e20bb41915000f678aa839cbb797cb7d8332c")
        );
        let mut transcript = Transcript::new();
        let hash = transcript.binder_hash(&psk_prefix()).unwrap();
        assert_eq!(
            hash,
            hex::<32>("63224b2e4573f2d3454ca84b9d009a04f6be9e05711a8396473aefa01e924a14")
        );
        assert_eq!(
            schedule.binder(PskKind::Resumption, &hash).unwrap(),
            hex::<32>("3add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d")
        );
        assert_ne!(
            schedule.binder(PskKind::External, &hash).unwrap(),
            schedule.binder(PskKind::Resumption, &hash).unwrap()
        );
        transcript.append(&psk_ch()).unwrap();
        assert_eq!(
            transcript.hash(),
            hex::<32>("08ad0fa05d7c7233b1775ba2ff9f4c5b8b59276b7f227f13a976245f5d960913")
        );
        assert_eq!(
            schedule
                .client_early_traffic(&transcript)
                .unwrap()
                .as_bytes(),
            &hex::<32>("3fbbe6a60deb66c30a32795aba0eff7eaa10105586e7be5c09678d63b6caab62")
        );
    }

    #[test]
    fn every_finished_bit_corruption_and_length_error_is_terminal() {
        for bit in 0..256 {
            let (mut schedule, mut transcript) = schedule();
            append_server_authentication(&mut transcript);
            let mut bad =
                hex::<32>("9b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718");
            bad[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(
                schedule.verify_finished(Side::Server, &transcript, &bad),
                Err(Error::FinishedAuthentication)
            );
            assert_eq!(schedule.stage(), Stage::Discarded);
            assert!(schedule.secret.is_none());
            assert!(schedule.client_handshake.is_none());
            assert_eq!(schedule.derive_master(&transcript), Err(Error::Discarded));
        }
        for n in [0, 1, 31, 33, 64] {
            let (mut schedule, mut transcript) = schedule();
            append_server_authentication(&mut transcript);
            assert_eq!(
                schedule.verify_finished(Side::Server, &transcript, &[0; 64][..n]),
                Err(Error::FinishedAuthentication)
            );
            assert_eq!(schedule.stage(), Stage::Discarded);
        }
    }

    #[test]
    fn transcript_truncation_and_hrr_errors_are_transactional() {
        for n in 0..ch().len() {
            let mut transcript = Transcript::new();
            let hash = transcript.hash();
            assert_eq!(transcript.append(&ch()[..n]), Err(Error::Truncated));
            assert_eq!(transcript.hash(), hash);
            assert_eq!(transcript.message_count(), 0);
        }
        let mut transcript = Transcript::new();
        assert_eq!(transcript.append(&sh()), Err(Error::InvalidMessage));
        assert_eq!(
            transcript.apply_hello_retry_request(&hrr()),
            Err(Error::InvalidHelloRetryRequest)
        );
        transcript.append(&ch()).unwrap();
        let hash = transcript.hash();
        assert_eq!(
            transcript.append(&[254, 0, 0, 0]),
            Err(Error::InvalidMessage)
        );
        assert_eq!(
            transcript.append(&[20, 0, 0, 0, 1]),
            Err(Error::TrailingData)
        );
        assert_eq!(
            transcript.apply_hello_retry_request(&sh()),
            Err(Error::InvalidHelloRetryRequest)
        );
        assert_eq!(transcript.hash(), hash);
        transcript.bytes = MAX_TRANSCRIPT_BYTES;
        assert_eq!(transcript.append(&sh()), Err(Error::TranscriptOverflow));
        assert_eq!(transcript.hash(), hash);
    }

    #[test]
    fn key_schedule_state_and_input_bounds_fail_closed() {
        let mut early = KeySchedule::new(None).unwrap();
        let transcript = through_server_hello();
        assert_eq!(early.derive_master(&transcript), Err(Error::WrongStage));
        assert_eq!(early.derive_resumption(&transcript), Err(Error::WrongStage));
        assert_eq!(
            early.derive_handshake(&[], &transcript),
            Err(Error::InvalidSharedSecret)
        );
        assert_eq!(
            early.derive_handshake(&[0; 32], &transcript),
            Err(Error::InvalidSharedSecret)
        );
        assert_eq!(early.stage(), Stage::Early);
        assert!(matches!(
            KeySchedule::new(Some(&[])),
            Err(Error::InvalidPsk)
        ));
        assert_eq!(
            early.binder(PskKind::Resumption, &[0; 32]),
            Err(Error::InvalidPsk)
        );
        assert_eq!(
            early.finished_verify_data(Side::Server, &transcript),
            Err(Error::WrongStage)
        );
        let (mut schedule, mut transcript) = schedule();
        assert_eq!(
            schedule.derive_handshake(&[1; 32], &transcript),
            Err(Error::WrongStage)
        );
        assert_eq!(schedule.derive_master(&transcript), Err(Error::WrongStage));
        append_server_authentication(&mut transcript);
        transcript.append(&server_fin()).unwrap();
        schedule.derive_master(&transcript).unwrap();
        assert_eq!(schedule.derive_master(&transcript), Err(Error::WrongStage));
        assert_eq!(
            schedule.derive_resumption(&transcript),
            Err(Error::WrongStage)
        );
        assert_eq!(
            schedule.finished_verify_data(Side::Server, &transcript),
            Err(Error::WrongStage)
        );
        transcript.append(&client_fin()).unwrap();
        schedule.derive_resumption(&transcript).unwrap();
        assert!(matches!(
            schedule.resumption_psk(&[0; 256]),
            Err(Error::InvalidContext)
        ));
        let mut out = [7; 32];
        assert_eq!(
            schedule.export(&[], b"context", &mut out),
            Err(Error::InvalidLabel)
        );
        assert_eq!(out, [7; 32]);
        assert_eq!(
            schedule.export(&[b'a'; 250], b"context", &mut out),
            Err(Error::InvalidLabel)
        );
        schedule.discard();
        assert_eq!(
            schedule.export(b"export", b"context", &mut out),
            Err(Error::Discarded)
        );
    }

    #[test]
    fn resumption_master_is_one_shot_and_discards_every_other_secret() {
        let mut early = KeySchedule::new(None).unwrap();
        assert!(matches!(
            early.take_resumption_master(),
            Err(Error::WrongStage)
        ));
        assert_eq!(early.stage(), Stage::Early);
        let (mut schedule, mut transcript) = schedule();
        assert!(matches!(
            schedule.take_resumption_master(),
            Err(Error::WrongStage)
        ));
        append_server_authentication(&mut transcript);
        transcript.append(&server_fin()).unwrap();
        schedule.derive_master(&transcript).unwrap();
        assert!(matches!(
            schedule.take_resumption_master(),
            Err(Error::WrongStage)
        ));
        transcript.append(&client_fin()).unwrap();
        schedule.derive_resumption(&transcript).unwrap();
        let expected = schedule.resumption_psk(&[0, 0]).unwrap();
        let master = schedule.take_resumption_master().unwrap();
        assert_eq!(core::mem::size_of::<ResumptionMaster>(), HASH_LEN);
        assert_eq!(schedule.stage(), Stage::Discarded);
        assert!(schedule.resumption.is_none());
        assert!(schedule.client_handshake.is_none());
        assert!(schedule.server_handshake.is_none());
        assert!(schedule.client_application.is_none());
        assert!(schedule.server_application.is_none());
        assert!(schedule.exporter.is_none());
        assert!(schedule.secret.is_none());
        assert!(matches!(
            schedule.take_resumption_master(),
            Err(Error::Discarded)
        ));
        assert!(matches!(
            schedule.resumption_psk(&[0, 0]),
            Err(Error::Discarded)
        ));
        let mut output = [0; HASH_LEN];
        assert_eq!(
            schedule.export(b"export", b"context", &mut output),
            Err(Error::Discarded)
        );
        schedule.discard();
        drop(schedule);
        assert_eq!(
            master.derive(&[0, 0]).unwrap().as_bytes(),
            expected.as_bytes()
        );
        assert_eq!(
            master.derive(&[0, 0]).unwrap().as_bytes(),
            &hex::<32>("4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3")
        );
        assert_ne!(
            master.derive(&[0, 1]).unwrap().as_bytes(),
            expected.as_bytes()
        );
        assert!(master.derive(&[]).is_ok());
        assert!(master.derive(&[0; 255]).is_ok());
        assert!(matches!(
            master.derive(&[0; 256]),
            Err(Error::InvalidContext)
        ));
    }

    #[test]
    fn exporter_label_context_and_length_separate_outputs() {
        let (mut schedule, mut transcript) = schedule();
        append_server_authentication(&mut transcript);
        transcript.append(&server_fin()).unwrap();
        schedule.derive_master(&transcript).unwrap();
        let mut a = [0; 32];
        let mut b = [0; 32];
        let mut c = [0; 32];
        schedule
            .export(b"application", b"context A", &mut a)
            .unwrap();
        // Independent OpenSSL 3.5.7 HKDF EXPAND_ONLY cross-check from RFC8448 exporter master.
        assert_eq!(
            a,
            hex::<32>("07bdf88193be9345d14fea942d7ee27aae8cdd197f30319bebedc12e63e77f09")
        );
        schedule
            .export(b"application", b"context B", &mut b)
            .unwrap();
        schedule.export(b"other", b"context A", &mut c).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
        let mut short = [0; 16];
        schedule
            .export(b"application", b"context A", &mut short)
            .unwrap();
        assert_ne!(&a[..16], &short);
        let mut oversized = [0; MAX_HKDF_OUTPUT + 1];
        assert_eq!(
            schedule.export(b"application", b"context A", &mut oversized),
            Err(Error::OutputTooLong)
        );
    }
}
