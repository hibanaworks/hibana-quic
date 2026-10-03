//! Bounded authenticated tickets/cache with explicit optional early replay policy.
//!
//! This module performs no TLS transition or packet processing. The provider must
//! negotiate psk_dhe_ke, validate binder framing, enforce suite/hash continuity,
//! perform fresh ECDHE and verify Finished. Prepare a nonce, derive its PSK with
//! the existing TLS schedule, then consume both in seal; never retain the whole
//! handshake schedule merely to keep tickets. All clocks are injected trusted
//! milliseconds. Secret owners are non-Clone/non-Debug and wipe on retirement.
//!
//! Ciphertext uses RustCrypto ChaCha20Poly1305. Key generation requires injected
//! CryptoRng; there is no fixed-key or raw-key-import constructor. One key owner
//! issues unique counter nonces. Single-use replay state is borrowed, bounded,
//! scoped to that key and updated only after a valid binder. It must not be reset
//! independently while that key remains usable. Reusable tickets are explicitly
//! limited to 1-RTT. Early admission additionally requires the separately borrowed
//! early replay ledger, authenticated remembered limits and explicit freshness.
//!
//! Sources: RFC 9846 sections 4.2.11 and 4.6.1; RFC 9001 sections 4.5 and 4.6.

use crate::early_data::{
    self as early, EarlyFreshness, RememberedLimits, ReplayClaim, ReplayProtection, ReplayStorage,
};
use crate::tls_schedule::{self as schedule, KeySchedule, PskKind, Secret32};
use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{AeadInPlace, KeyInit},
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

pub const MAX_LIFETIME_SECONDS: u32 = 7 * 24 * 60 * 60;
pub const MAX_AGE_SKEW_MS: u32 = 5 * 60 * 1000;
pub const MAX_BINDING_PROFILE_BYTES: usize = 4096;
pub const TICKET_NONCE_BYTES: usize = 12;
const HEADER_BYTES: usize = 29; // format version, key identifier, AEAD nonce
const BODY_BYTES: usize = 83 + early::REMEMBERED_BYTES; // issued, lifetime, age_add, suite, PSK, binding, flags, remembered limits
pub const SEALED_TICKET_BYTES: usize = HEADER_BYTES + BODY_BYTES + 16;
const DOMAIN: &[u8] = b"hibana-quic ticket v2";
const MAX_ISSUED: u64 = 1 << 32;
const MAX_AUTH_FAILURES: u64 = 1 << 24;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Entropy,
    EarlyDataUnavailable,
    EarlyAgeMismatch,
    EarlyReplay(early::Error),
    InvalidBinding,
    VerificationContext,
    InvalidLifetime,
    InvalidSuite,
    InvalidAgeSkew,
    ClockRollback,
    ClockOverflow,
    Expired,
    AgeMismatch,
    BufferTooSmall,
    InvalidTicket,
    Authentication,
    Binder,
    KeyRetired,
    KeyExhausted,
    ForeignIssue,
    Replay,
    Capacity,
    DuplicateTicket,
    Schedule(schedule::Error),
}
impl From<schedule::Error> for Error {
    fn from(e: schedule::Error) -> Self {
        Self::Schedule(e)
    }
}

/// Hash of an authenticated origin and a caller-defined stable server transport
/// policy. The profile must canonically encode remembered limits/configuration;
/// do not hash connection-specific CIDs or treat a hash as actual 0-RTT limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Binding([u8; 32], [u8; 32]);
impl Binding {
    pub fn new(server_name: &str, alpn: &[u8], transport_profile: &[u8]) -> Result<Self, Error> {
        let name = rustls_pki_types::ServerName::try_from(server_name)
            .map_err(|_| Error::InvalidBinding)?;
        if !matches!(name, rustls_pki_types::ServerName::DnsName(_))
            || server_name.len() > 253
            || alpn.is_empty()
            || alpn.len() > 255
            || transport_profile.len() > MAX_BINDING_PROFILE_BYTES
        {
            return Err(Error::InvalidBinding);
        }
        let mut h = Sha256::new();
        h.update(b"hibana-quic resumption binding v1");
        h.update((server_name.len() as u16).to_be_bytes());
        for b in server_name.bytes() {
            h.update([b.to_ascii_lowercase()]);
        }
        h.update([alpn.len() as u8]);
        h.update(alpn);
        let origin = h.clone().finalize().into();
        h.update((transport_profile.len() as u32).to_be_bytes());
        h.update(transport_profile);
        Ok(Self(h.finalize().into(), origin))
    }
}

/// Digest of the concrete certificate trust configuration. Advancing wall clock
/// time is excluded; ticket expiry uses the injected monotonic clock. Root order
/// is significant, so equivalent reordered roots conservatively miss the cache.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerificationContext([u8; 32]);
impl VerificationContext {
    pub fn new(
        anchors: &[crate::tls_certificate::TrustAnchor<'_>],
        limits: crate::tls_certificate::Limits,
    ) -> Result<Self, Error> {
        if anchors.is_empty() || anchors.len() > crate::tls_certificate::MAX_TRUST_ANCHORS {
            return Err(Error::VerificationContext);
        }
        let mut h = Sha256::new();
        h.update(b"hibana-quic verify P256-RSA2048-3072-4096-SHA256 PSS-rsae-salt32 PKCS1-cert-only webpki-depth8 KU-EKU-DNS-NC v2");
        for value in [
            limits.max_certificate_bytes,
            limits.max_chain_bytes,
            limits.max_intermediates,
            limits.max_trust_anchors,
            anchors.len(),
        ] {
            h.update((value as u64).to_be_bytes());
        }
        for anchor in anchors {
            for value in [
                anchor.subject.as_ref(),
                anchor.subject_public_key_info.as_ref(),
            ] {
                if value.len() > crate::tls_certificate::MAX_CERTIFICATE_BYTES {
                    return Err(Error::VerificationContext);
                }
                h.update((value.len() as u64).to_be_bytes());
                h.update(value);
            }
            match &anchor.name_constraints {
                Some(value) => {
                    if value.as_ref().len() > crate::tls_certificate::MAX_CERTIFICATE_BYTES {
                        return Err(Error::VerificationContext);
                    }
                    h.update([1]);
                    h.update((value.as_ref().len() as u64).to_be_bytes());
                    h.update(value.as_ref());
                }
                None => h.update([0]),
            }
        }
        Ok(Self(h.finalize().into()))
    }
}

/// Injected trusted milliseconds, shared across sequential connections.
pub trait TicketClock {
    fn now_ms(&self) -> Result<u64, Error>;
}
/// Borrowed object-safe adapter. Storage and secret ownership stay with caller.
pub trait ServerTicketStore {
    fn supports_early(&self) -> bool {
        false
    }
    #[allow(clippy::too_many_arguments)]
    fn prepare_early(
        &mut self,
        _rng: &mut dyn rand_core::CryptoRngCore,
        _now_ms: u64,
        _lifetime_seconds: u32,
        _suite: u16,
        _binding: Binding,
        _limits: RememberedLimits,
    ) -> Result<IssueToken, Error> {
        Err(Error::EarlyDataUnavailable)
    }
    fn claim_early(
        &mut self,
        _accepted: &mut AcceptedTicket,
        _generation: u64,
        _now_ms: u64,
        _freshness: EarlyFreshness,
    ) -> Result<ReplayClaim, Error> {
        Err(Error::EarlyDataUnavailable)
    }
    fn prepare(
        &mut self,
        rng: &mut dyn rand_core::CryptoRngCore,
        now_ms: u64,
        lifetime_seconds: u32,
        suite: u16,
        binding: Binding,
    ) -> Result<IssueToken, Error>;
    fn seal(
        &mut self,
        token: IssueToken,
        psk: Secret32,
        out: &mut [u8],
    ) -> Result<IssuedTicket, Error>;
    fn accept(&mut self, ticket: &[u8], request: Acceptance<'_>) -> Result<AcceptedTicket, Error>;
    fn check(&mut self, ticket: &[u8], request: Acceptance<'_>) -> Result<AcceptedTicket, Error>;
}
impl ServerTicketStore for TicketKey<'_> {
    fn supports_early(&self) -> bool {
        self.early_replay.is_some()
    }
    fn prepare_early(
        &mut self,
        rng: &mut dyn rand_core::CryptoRngCore,
        now_ms: u64,
        lifetime_seconds: u32,
        suite: u16,
        binding: Binding,
        limits: RememberedLimits,
    ) -> Result<IssueToken, Error> {
        TicketKey::prepare_early(self, rng, now_ms, lifetime_seconds, suite, binding, limits)
    }
    fn claim_early(
        &mut self,
        accepted: &mut AcceptedTicket,
        generation: u64,
        now_ms: u64,
        freshness: EarlyFreshness,
    ) -> Result<ReplayClaim, Error> {
        TicketKey::claim_early(self, accepted, generation, now_ms, freshness)
    }
    fn prepare(
        &mut self,
        rng: &mut dyn rand_core::CryptoRngCore,
        now_ms: u64,
        lifetime_seconds: u32,
        suite: u16,
        binding: Binding,
    ) -> Result<IssueToken, Error> {
        TicketKey::prepare(self, rng, now_ms, lifetime_seconds, suite, binding)
    }
    fn seal(
        &mut self,
        token: IssueToken,
        psk: Secret32,
        out: &mut [u8],
    ) -> Result<IssuedTicket, Error> {
        TicketKey::seal(self, token, psk, out)
    }
    fn accept(&mut self, ticket: &[u8], request: Acceptance<'_>) -> Result<AcceptedTicket, Error> {
        TicketKey::accept(self, ticket, request)
    }
    fn check(&mut self, ticket: &[u8], request: Acceptance<'_>) -> Result<AcceptedTicket, Error> {
        TicketKey::check(self, ticket, request)
    }
}
pub trait ClientTicketStore {
    fn insert_verified_early(
        &mut self,
        now_ms: u64,
        received: ReceivedTicket<'_>,
        psk: Secret32,
        context: VerificationContext,
        _limits: RememberedLimits,
    ) -> Result<(), Error> {
        self.insert_verified(now_ms, received, psk, context)
    }
    fn insert_verified(
        &mut self,
        now_ms: u64,
        received: ReceivedTicket<'_>,
        psk: Secret32,
        context: VerificationContext,
    ) -> Result<(), Error>;
}
impl<const BYTES: usize> ClientTicketStore for ClientCache<'_, BYTES> {
    fn insert_verified_early(
        &mut self,
        now_ms: u64,
        received: ReceivedTicket<'_>,
        psk: Secret32,
        context: VerificationContext,
        limits: RememberedLimits,
    ) -> Result<(), Error> {
        ClientCache::insert_verified_early(self, now_ms, received, psk, context, limits)
    }
    fn insert_verified(
        &mut self,
        now_ms: u64,
        received: ReceivedTicket<'_>,
        psk: Secret32,
        context: VerificationContext,
    ) -> Result<(), Error> {
        ClientCache::insert_verified(self, now_ms, received, psk, context)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayPolicy {
    ReusableOneRtt,
    SingleUseOneRtt,
}
/// Caller-owned storage. It is exclusively borrowed for a ticket-key lifetime.
pub struct ReplaySlot {
    nonce: [u8; 12],
    expires_ms: u64,
    occupied: bool,
}
impl ReplaySlot {
    pub const fn empty() -> Self {
        Self {
            nonce: [0; 12],
            expires_ms: 0,
            occupied: false,
        }
    }
    fn clear(&mut self) {
        self.nonce.zeroize();
        self.expires_ms = 0;
        self.occupied = false;
    }
}

/// A unique issuance reservation, intentionally neither Clone nor Copy. A failed
/// or abandoned reservation burns its nonce. It contains no resumption secret.
pub struct IssueToken {
    key_id: [u8; 16],
    nonce: [u8; 12],
    issued_ms: u64,
    lifetime_seconds: u32,
    age_add: u32,
    suite: u16,
    binding: Binding,
    early: Option<RememberedLimits>,
}
impl IssueToken {
    pub fn ticket_nonce(&self) -> &[u8; 12] {
        &self.nonce
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IssuedTicket {
    pub len: usize,
    pub nonce: [u8; 12],
    pub lifetime_seconds: u32,
    pub age_add: u32,
}
/// Server acceptance parameters. The prefix hash must come from the existing
/// Transcript::binder_hash over the wire parser's exact binder truncation.
pub struct Acceptance<'a> {
    pub now_ms: u64,
    pub obfuscated_age: u32,
    pub max_age_skew_ms: u32,
    pub binding: &'a Binding,
    pub suite: u16,
    pub transcript_hash: &'a [u8; 32],
    pub binder: &'a [u8],
}
/// A binder-validated PSK schedule, still requiring fresh ECDHE and Finished.
pub struct AcceptedTicket {
    schedule: KeySchedule,
    suite: u16,
    early: Option<EarlyCandidate>,
}
struct EarlyCandidate {
    issuer: [u8; 16],
    nonce: [u8; 12],
    expires: u64,
    issued_ms: u64,
    reported_age_ms: u64,
    limits: RememberedLimits,
}
impl AcceptedTicket {
    pub fn early_limits(&self) -> Option<RememberedLimits> {
        self.early.as_ref().map(|candidate| candidate.limits)
    }
    pub fn suite(&self) -> u16 {
        self.suite
    }
    pub fn into_schedule(self) -> KeySchedule {
        self.schedule
    }
}

pub struct TicketKey<'a> {
    key: Zeroizing<[u8; 32]>,
    key_id: [u8; 16],
    next_nonce: u64,
    last_time: Option<u64>,
    auth_failures: u64,
    retired: bool,
    policy: ReplayPolicy,
    replay: &'a mut [ReplaySlot],
    early_replay: Option<&'a mut dyn ReplayProtection>,
}
impl<'a> TicketKey<'a> {
    pub fn generate<R: RngCore + CryptoRng>(
        rng: &mut R,
        policy: ReplayPolicy,
        replay: &'a mut [ReplaySlot],
    ) -> Result<Self, Error> {
        if policy == ReplayPolicy::SingleUseOneRtt && replay.is_empty() {
            return Err(Error::Capacity);
        }
        let mut key = Zeroizing::new([0; 32]);
        let mut key_id = [0; 16];
        rng.try_fill_bytes(&mut *key).map_err(|_| Error::Entropy)?;
        rng.try_fill_bytes(&mut key_id)
            .map_err(|_| Error::Entropy)?;
        for slot in replay.iter_mut() {
            slot.clear()
        }
        Ok(Self {
            key,
            key_id,
            next_nonce: 0,
            last_time: None,
            auth_failures: 0,
            retired: false,
            policy,
            replay,
            early_replay: None,
        })
    }
    /// The replay storage stays exclusively borrowed for this key's lifetime.
    /// Restart/rotation generates a fresh key+issuer; old tickets cannot decrypt.
    pub fn generate_with_early_replay<R: RngCore + CryptoRng, const N: usize>(
        rng: &mut R,
        policy: ReplayPolicy,
        replay: &'a mut [ReplaySlot],
        early_replay: &'a mut ReplayStorage<N>,
    ) -> Result<Self, Error> {
        let mut key = Self::generate(rng, policy, replay)?;
        early_replay
            .start_fresh_key_epoch(key.key_id)
            .map_err(Error::EarlyReplay)?;
        key.early_replay = Some(early_replay);
        Ok(key)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_early<R: RngCore + CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        now_ms: u64,
        lifetime_seconds: u32,
        suite: u16,
        binding: Binding,
        limits: RememberedLimits,
    ) -> Result<IssueToken, Error> {
        if self.early_replay.is_none() {
            return Err(Error::EarlyDataUnavailable);
        }
        let mut token = self.prepare(rng, now_ms, lifetime_seconds, suite, binding)?;
        token.early = Some(limits);
        Ok(token)
    }
    /// Consume the private candidate only after actual ticket/binder acceptance.
    /// A replay/full decision rejects early data but preserves the1RTT schedule.
    pub fn claim_early(
        &mut self,
        accepted: &mut AcceptedTicket,
        generation: u64,
        now_ms: u64,
        freshness: EarlyFreshness,
    ) -> Result<ReplayClaim, Error> {
        self.observe(now_ms)?;
        let candidate = accepted.early.take().ok_or(Error::EarlyDataUnavailable)?;
        if !bool::from(candidate.issuer.ct_eq(&self.key_id)) {
            return Err(Error::ForeignIssue);
        }
        let actual_age = now_ms
            .checked_sub(candidate.issued_ms)
            .ok_or(Error::ClockRollback)?;
        if !freshness.permits(actual_age, candidate.reported_age_ms) {
            return Err(Error::EarlyAgeMismatch);
        }
        self.early_replay
            .as_deref_mut()
            .ok_or(Error::EarlyDataUnavailable)?
            .claim_authenticated(
                candidate.issuer,
                candidate.nonce,
                candidate.expires,
                now_ms,
                generation,
            )
            .map_err(Error::EarlyReplay)
    }
    pub fn retire(&mut self) {
        self.key.zeroize();
        self.retired = true;
        for slot in self.replay.iter_mut() {
            slot.clear()
        }
    }
    pub fn is_retired(&self) -> bool {
        self.retired
    }
    fn observe(&mut self, now: u64) -> Result<(), Error> {
        if self.retired {
            return Err(Error::KeyRetired);
        }
        if self.last_time.is_some_and(|old| now < old) {
            return Err(Error::ClockRollback);
        }
        self.last_time = Some(now);
        Ok(())
    }
    pub fn prepare<R: RngCore + CryptoRng + ?Sized>(
        &mut self,
        rng: &mut R,
        now_ms: u64,
        lifetime_seconds: u32,
        suite: u16,
        binding: Binding,
    ) -> Result<IssueToken, Error> {
        lifetime_end(now_ms, lifetime_seconds)?;
        valid_suite(suite)?;
        self.observe(now_ms)?;
        if self.next_nonce >= MAX_ISSUED {
            return Err(Error::KeyExhausted);
        }
        let counter = self.next_nonce;
        self.next_nonce += 1;
        let mut random = [0; 4];
        rng.try_fill_bytes(&mut random)
            .map_err(|_| Error::Entropy)?;
        let mut nonce = [0; 12];
        nonce[..4].copy_from_slice(&self.key_id[..4]);
        nonce[4..].copy_from_slice(&counter.to_be_bytes());
        Ok(IssueToken {
            key_id: self.key_id,
            nonce,
            issued_ms: now_ms,
            lifetime_seconds,
            age_add: u32::from_be_bytes(random),
            suite,
            binding,
            early: None,
        })
    }
    /// Consumes a unique reservation and its schedule-derived PSK. Error paths
    /// wipe the PSK and never publish plaintext into the output buffer.
    pub fn seal(
        &mut self,
        token: IssueToken,
        psk: Secret32,
        out: &mut [u8],
    ) -> Result<IssuedTicket, Error> {
        if self.retired {
            return Err(Error::KeyRetired);
        }
        if !bool::from(token.key_id.ct_eq(&self.key_id)) {
            return Err(Error::ForeignIssue);
        }
        if out.len() < SEALED_TICKET_BYTES {
            return Err(Error::BufferTooSmall);
        }
        let mut header = [0; HEADER_BYTES];
        header[0] = 2;
        header[1..17].copy_from_slice(&self.key_id);
        header[17..].copy_from_slice(&token.nonce);
        let mut body = Zeroizing::new([0; BODY_BYTES]);
        body[..8].copy_from_slice(&token.issued_ms.to_be_bytes());
        body[8..12].copy_from_slice(&token.lifetime_seconds.to_be_bytes());
        body[12..16].copy_from_slice(&token.age_add.to_be_bytes());
        body[16..18].copy_from_slice(&token.suite.to_be_bytes());
        body[18..50].copy_from_slice(psk.as_bytes());
        body[50..82].copy_from_slice(&token.binding.0);
        body[82] = u8::from(token.early.is_some());
        if let Some(limits) = token.early {
            body[83..].copy_from_slice(&limits.encode());
        }
        let aad = aad(&header);
        let cipher =
            ChaCha20Poly1305::new_from_slice(&*self.key).map_err(|_| Error::Authentication)?;
        let tag = cipher
            .encrypt_in_place_detached((&token.nonce).into(), &aad, &mut *body)
            .map_err(|_| Error::Authentication)?;
        out[..HEADER_BYTES].copy_from_slice(&header);
        out[HEADER_BYTES..HEADER_BYTES + BODY_BYTES].copy_from_slice(&*body);
        out[HEADER_BYTES + BODY_BYTES..SEALED_TICKET_BYTES].copy_from_slice(&tag);
        Ok(IssuedTicket {
            len: SEALED_TICKET_BYTES,
            nonce: token.nonce,
            lifetime_seconds: token.lifetime_seconds,
            age_add: token.age_add,
        })
    }
    pub fn accept(
        &mut self,
        ticket: &[u8],
        request: Acceptance<'_>,
    ) -> Result<AcceptedTicket, Error> {
        self.accept_inner(ticket, request, true)
    }
    /// Validate CH1 before HRR without committing single-use replay state.
    /// The final ClientHello must call accept again with its fresh binder.
    pub fn check(
        &mut self,
        ticket: &[u8],
        request: Acceptance<'_>,
    ) -> Result<AcceptedTicket, Error> {
        self.accept_inner(ticket, request, false)
    }
    fn accept_inner(
        &mut self,
        ticket: &[u8],
        request: Acceptance<'_>,
        commit: bool,
    ) -> Result<AcceptedTicket, Error> {
        if request.max_age_skew_ms > MAX_AGE_SKEW_MS {
            return Err(Error::InvalidAgeSkew);
        }
        valid_suite(request.suite)?;
        self.observe(request.now_ms)?;
        if ticket.len() != SEALED_TICKET_BYTES || ticket[0] != 2 {
            return Err(Error::InvalidTicket);
        }
        if !bool::from(ticket[1..17].ct_eq(&self.key_id)) {
            return Err(Error::Authentication);
        }
        let mut nonce = [0; 12];
        nonce.copy_from_slice(&ticket[17..HEADER_BYTES]);
        let mut body = Zeroizing::new([0; BODY_BYTES]);
        body.copy_from_slice(&ticket[HEADER_BYTES..HEADER_BYTES + BODY_BYTES]);
        let mut header = [0; HEADER_BYTES];
        header.copy_from_slice(&ticket[..HEADER_BYTES]);
        let aad = aad(&header);
        let cipher =
            ChaCha20Poly1305::new_from_slice(&*self.key).map_err(|_| Error::Authentication)?;
        if cipher
            .decrypt_in_place_detached(
                (&nonce).into(),
                &aad,
                &mut *body,
                ticket[HEADER_BYTES + BODY_BYTES..].into(),
            )
            .is_err()
        {
            self.auth_failures += 1;
            if self.auth_failures >= MAX_AUTH_FAILURES {
                self.retire()
            }
            return Err(Error::Authentication);
        }
        let issued = u64::from_be_bytes(body[..8].try_into().map_err(|_| Error::InvalidTicket)?);
        let lifetime =
            u32::from_be_bytes(body[8..12].try_into().map_err(|_| Error::InvalidTicket)?);
        let expires = lifetime_end(issued, lifetime)?;
        let age = request
            .now_ms
            .checked_sub(issued)
            .ok_or(Error::ClockRollback)?;
        if request.now_ms >= expires {
            return Err(Error::Expired);
        }
        let age_add =
            u32::from_be_bytes(body[12..16].try_into().map_err(|_| Error::InvalidTicket)?);
        let reported = u64::from(request.obfuscated_age.wrapping_sub(age_add));
        if age.abs_diff(reported) > u64::from(request.max_age_skew_ms) {
            return Err(Error::AgeMismatch);
        }
        let suite = u16::from_be_bytes(body[16..18].try_into().map_err(|_| Error::InvalidTicket)?);
        if suite != request.suite
            || body[82] > 1
            || !bool::from(body[50..82].ct_eq(&request.binding.0))
        {
            return Err(Error::InvalidBinding);
        }
        let early = if body[82] == 1 {
            Some(EarlyCandidate {
                issuer: self.key_id,
                nonce,
                expires,
                issued_ms: issued,
                reported_age_ms: reported,
                limits: RememberedLimits::decode(&body[83..]).map_err(Error::EarlyReplay)?,
            })
        } else {
            if body[83..].iter().any(|b| *b != 0) {
                return Err(Error::InvalidTicket);
            }
            None
        };
        let schedule = KeySchedule::new(Some(&body[18..50]))?;
        let expected =
            Zeroizing::new(schedule.binder(PskKind::Resumption, request.transcript_hash)?);
        if !bool::from(expected.as_slice().ct_eq(request.binder)) {
            return Err(Error::Binder);
        }
        if self.policy == ReplayPolicy::SingleUseOneRtt {
            for slot in self.replay.iter_mut() {
                if slot.occupied && slot.expires_ms <= request.now_ms {
                    slot.clear()
                }
            }
            if self.replay.iter().any(|s| s.occupied && s.nonce == nonce) {
                return Err(Error::Replay);
            }
            let slot = self
                .replay
                .iter_mut()
                .find(|s| !s.occupied)
                .ok_or(Error::Capacity)?;
            if commit {
                *slot = ReplaySlot {
                    nonce,
                    expires_ms: expires,
                    occupied: true,
                };
            }
        }
        Ok(AcceptedTicket {
            schedule,
            suite,
            early,
        })
    }
}
impl Drop for TicketKey<'_> {
    fn drop(&mut self) {
        self.retire()
    }
}
fn valid_suite(suite: u16) -> Result<(), Error> {
    if matches!(suite, 0x1301 | 0x1303) {
        Ok(())
    } else {
        Err(Error::InvalidSuite)
    }
}
fn lifetime_end(start: u64, seconds: u32) -> Result<u64, Error> {
    if seconds == 0 || seconds > MAX_LIFETIME_SECONDS {
        return Err(Error::InvalidLifetime);
    }
    start
        .checked_add(u64::from(seconds) * 1000)
        .ok_or(Error::ClockOverflow)
}
fn aad(header: &[u8; HEADER_BYTES]) -> [u8; DOMAIN.len() + HEADER_BYTES] {
    let mut aad = [0; DOMAIN.len() + HEADER_BYTES];
    aad[..DOMAIN.len()].copy_from_slice(DOMAIN);
    aad[DOMAIN.len()..].copy_from_slice(header);
    aad
}

/// Caller-owned cache slot. Private fields prevent injecting populated entries.
pub struct ClientSlot<const BYTES: usize> {
    ticket: [u8; BYTES],
    len: usize,
    psk: Option<Secret32>,
    binding: Binding,
    suite: u16,
    received_ms: u64,
    lifetime_seconds: u32,
    age_add: u32,
    serial: u64,
    context: Option<VerificationContext>,
    early: Option<RememberedLimits>,
}
impl<const BYTES: usize> ClientSlot<BYTES> {
    pub const fn empty() -> Self {
        Self {
            ticket: [0; BYTES],
            len: 0,
            psk: None,
            binding: Binding([0; 32], [0; 32]),
            suite: 0,
            received_ms: 0,
            lifetime_seconds: 0,
            age_add: 0,
            serial: 0,
            context: None,
            early: None,
        }
    }
    fn clear(&mut self) {
        self.ticket.zeroize();
        self.len = 0;
        self.psk = None;
        self.serial = 0;
        self.context = None;
        self.early = None;
    }
}
impl<const BYTES: usize> Drop for ClientSlot<BYTES> {
    fn drop(&mut self) {
        self.clear()
    }
}
/// Received only over authenticated post-handshake TLS CRYPTO. The provider
/// derives the PSK from the ticket_nonce before handing its owner to insert.
pub struct ReceivedTicket<'a> {
    pub ticket: &'a [u8],
    pub lifetime_seconds: u32,
    pub age_add: u32,
    pub suite: u16,
    pub binding: Binding,
}
pub struct ClientCache<'a, const BYTES: usize> {
    slots: &'a mut [ClientSlot<BYTES>],
    last_time: Option<u64>,
    next_serial: u64,
}
impl<'a, const BYTES: usize> ClientCache<'a, BYTES> {
    pub fn new(slots: &'a mut [ClientSlot<BYTES>]) -> Self {
        for s in slots.iter_mut() {
            s.clear()
        }
        Self {
            slots,
            last_time: None,
            next_serial: 1,
        }
    }
    fn expire(&mut self, now: u64) -> Result<(), Error> {
        if self.last_time.is_some_and(|old| now < old) {
            return Err(Error::ClockRollback);
        }
        self.last_time = Some(now);
        for s in self.slots.iter_mut() {
            if s.psk.is_some() && now >= lifetime_end(s.received_ms, s.lifetime_seconds)? {
                s.clear()
            }
        }
        Ok(())
    }
    pub fn insert(
        &mut self,
        now_ms: u64,
        received: ReceivedTicket<'_>,
        psk: Secret32,
    ) -> Result<(), Error> {
        self.insert_inner(now_ms, received, psk, None, None)
    }
    pub fn insert_verified(
        &mut self,
        now_ms: u64,
        received: ReceivedTicket<'_>,
        psk: Secret32,
        context: VerificationContext,
    ) -> Result<(), Error> {
        self.insert_inner(now_ms, received, psk, Some(context), None)
    }
    pub fn insert_verified_early(
        &mut self,
        now_ms: u64,
        received: ReceivedTicket<'_>,
        psk: Secret32,
        context: VerificationContext,
        limits: RememberedLimits,
    ) -> Result<(), Error> {
        self.insert_inner(now_ms, received, psk, Some(context), Some(limits))
    }
    fn insert_inner(
        &mut self,
        now_ms: u64,
        received: ReceivedTicket<'_>,
        psk: Secret32,
        context: Option<VerificationContext>,
        early: Option<RememberedLimits>,
    ) -> Result<(), Error> {
        lifetime_end(now_ms, received.lifetime_seconds)?;
        valid_suite(received.suite)?;
        if received.ticket.is_empty() || received.ticket.len() > BYTES {
            return Err(Error::Capacity);
        }
        self.expire(now_ms)?;
        if self
            .slots
            .iter()
            .any(|s| s.psk.is_some() && s.ticket[..s.len] == *received.ticket)
        {
            return Err(Error::DuplicateTicket);
        }
        let next = self.next_serial.checked_add(1).ok_or(Error::Capacity)?;
        let slot = self
            .slots
            .iter_mut()
            .find(|s| s.psk.is_none())
            .ok_or(Error::Capacity)?;
        slot.ticket[..received.ticket.len()].copy_from_slice(received.ticket);
        slot.len = received.ticket.len();
        slot.psk = Some(psk);
        slot.binding = received.binding;
        slot.context = context;
        slot.early = early;
        slot.suite = received.suite;
        slot.received_ms = now_ms;
        slot.lifetime_seconds = received.lifetime_seconds;
        slot.age_add = received.age_add;
        slot.serial = self.next_serial;
        self.next_serial = next;
        Ok(())
    }
    /// Removes one matching ticket from the cache before exposing it. Dropping
    /// the returned offer burns it; retries within one handshake may recompute a
    /// binder, but a new connection cannot look up this cache entry again.
    pub fn take(
        &mut self,
        now_ms: u64,
        binding: &Binding,
        suite: u16,
    ) -> Result<Option<ClientOffer<BYTES>>, Error> {
        self.take_matching(now_ms, binding, suite, false, None)
    }
    /// Select using SNI+ALPN when the next server's transport profile is not yet
    /// known. The query binding's profile is ignored only for local selection;
    /// server accept still authenticates the complete current policy binding.
    /// The remembered profile digest does not authorize 0-RTT or replace actual
    /// remembered transport limits.
    pub fn take_for_origin(
        &mut self,
        now_ms: u64,
        origin: &Binding,
        suite: u16,
    ) -> Result<Option<ClientOffer<BYTES>>, Error> {
        self.take_matching(now_ms, origin, suite, true, None)
    }
    /// Consume only a ticket authenticated with this exact trust configuration.
    pub fn take_verified_for_origin(
        &mut self,
        now_ms: u64,
        origin: &Binding,
        suite: u16,
        context: VerificationContext,
    ) -> Result<Option<ClientOffer<BYTES>>, Error> {
        self.take_matching(now_ms, origin, suite, true, Some(context))
    }
    fn take_matching(
        &mut self,
        now_ms: u64,
        binding: &Binding,
        suite: u16,
        origin_only: bool,
        context: Option<VerificationContext>,
    ) -> Result<Option<ClientOffer<BYTES>>, Error> {
        valid_suite(suite)?;
        self.expire(now_ms)?;
        let index = self
            .slots
            .iter()
            .enumerate()
            .filter(|(_, s)| {
                s.psk.is_some()
                    && s.suite == suite
                    && context.is_none_or(|context| s.context == Some(context))
                    && if origin_only {
                        s.binding.1 == binding.1
                    } else {
                        s.binding == *binding
                    }
            })
            .min_by_key(|(_, s)| s.serial)
            .map(|(i, _)| i);
        Ok(index.map(|index| ClientOffer {
            slot: core::mem::replace(&mut self.slots[index], ClientSlot::empty()),
            last_time: now_ms,
        }))
    }
    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.psk.is_some()).count()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
impl<const BYTES: usize> Drop for ClientCache<'_, BYTES> {
    fn drop(&mut self) {
        for slot in self.slots.iter_mut() {
            slot.clear()
        }
    }
}
pub struct ClientOffer<const BYTES: usize> {
    slot: ClientSlot<BYTES>,
    last_time: u64,
}
impl<const BYTES: usize> ClientOffer<BYTES> {
    pub fn remembered_early_limits(&self) -> Option<RememberedLimits> {
        self.slot.early
    }
    pub fn verify_context(
        &self,
        context: VerificationContext,
        origin: &Binding,
    ) -> Result<(), Error> {
        if self.slot.context != Some(context) {
            return Err(Error::VerificationContext);
        }
        if self.slot.binding.1 != origin.1 {
            return Err(Error::InvalidBinding);
        }
        Ok(())
    }
    pub fn age_state(&self) -> OfferAge {
        OfferAge {
            received_ms: self.slot.received_ms,
            lifetime_seconds: self.slot.lifetime_seconds,
            age_add: self.slot.age_add,
            last_time: self.last_time,
        }
    }
    pub fn identity(&self) -> &[u8] {
        &self.slot.ticket[..self.slot.len]
    }
    pub fn suite(&self) -> u16 {
        self.slot.suite
    }
    pub fn obfuscated_age(&mut self, now_ms: u64) -> Result<u32, Error> {
        if now_ms < self.last_time {
            return Err(Error::ClockRollback);
        }
        self.last_time = now_ms;
        let age = now_ms
            .checked_sub(self.slot.received_ms)
            .ok_or(Error::ClockRollback)?;
        if now_ms >= lifetime_end(self.slot.received_ms, self.slot.lifetime_seconds)? {
            return Err(Error::Expired);
        }
        Ok((age as u32).wrapping_add(self.slot.age_add))
    }
    pub fn schedule(&self) -> Result<KeySchedule, Error> {
        Ok(KeySchedule::new(Some(
            self.slot
                .psk
                .as_ref()
                .ok_or(Error::InvalidTicket)?
                .as_bytes(),
        ))?)
    }
    pub fn binder(&self, transcript_hash: &[u8; 32]) -> Result<[u8; 32], Error> {
        Ok(self
            .schedule()?
            .binder(PskKind::Resumption, transcript_hash)?)
    }
}

/// Non-secret timing retained while a consumed offer participates in one HRR.
pub struct OfferAge {
    received_ms: u64,
    lifetime_seconds: u32,
    age_add: u32,
    last_time: u64,
}
impl OfferAge {
    pub fn obfuscated_age(&mut self, now_ms: u64) -> Result<u32, Error> {
        if now_ms < self.last_time {
            return Err(Error::ClockRollback);
        }
        self.last_time = now_ms;
        if now_ms >= lifetime_end(self.received_ms, self.lifetime_seconds)? {
            return Err(Error::Expired);
        }
        Ok(((now_ms - self.received_ms) as u32).wrapping_add(self.age_add))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls_schedule::{Side, Stage, Transcript};
    const HASH: [u8; 32] = [9; 32];
    // Deterministic RNG is test-only. Production APIs require caller CryptoRng.
    struct TestRng {
        value: u64,
        fail: bool,
    }
    impl TestRng {
        fn new(seed: u64) -> Self {
            Self {
                value: seed,
                fail: false,
            }
        }
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
            self.try_fill_bytes(out).unwrap()
        }
        fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
            if self.fail {
                return Err(rand_core::Error::from(
                    core::num::NonZeroU32::new(1).unwrap(),
                ));
            }
            for b in out {
                self.value = self
                    .value
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *b = (self.value >> 32) as u8;
            }
            Ok(())
        }
    }
    impl CryptoRng for TestRng {}
    fn binding() -> Binding {
        Binding::new("server.test", b"hq-interop", b"canonical limits v1").unwrap()
    }
    fn resumption() -> KeySchedule {
        // Synthetic framing is only a deterministic KDF fixture. Full provider
        // certificate/Finished authentication is tested separately.
        let mut t = Transcript::new();
        t.append(&[1, 0, 0, 0]).unwrap();
        t.append(&[2, 0, 0, 0]).unwrap();
        let mut s = KeySchedule::new(None).unwrap();
        s.derive_handshake(&[7; 32], &t).unwrap();
        t.append(&[20, 0, 0, 0]).unwrap();
        s.derive_master(&t).unwrap();
        t.append(&[20, 0, 0, 0]).unwrap();
        s.derive_resumption(&t).unwrap();
        s
    }
    fn issue(
        key: &mut TicketKey<'_>,
        rng: &mut TestRng,
        lifetime: u32,
    ) -> ([u8; SEALED_TICKET_BYTES], IssuedTicket, [u8; 32]) {
        let token = key.prepare(rng, 1000, lifetime, 0x1301, binding()).unwrap();
        let psk = resumption().resumption_psk(token.ticket_nonce()).unwrap();
        let binder = KeySchedule::new(Some(psk.as_bytes()))
            .unwrap()
            .binder(PskKind::Resumption, &HASH)
            .unwrap();
        let mut ticket = [0; SEALED_TICKET_BYTES];
        let issued = key.seal(token, psk, &mut ticket).unwrap();
        (ticket, issued, binder)
    }
    fn request<'a>(
        binding: &'a Binding,
        issued: &IssuedTicket,
        now: u64,
        binder: &'a [u8],
    ) -> Acceptance<'a> {
        Acceptance {
            now_ms: now,
            obfuscated_age: ((now - 1000) as u32).wrapping_add(issued.age_add),
            max_age_skew_ms: 100,
            binding,
            suite: 0x1301,
            transcript_hash: &HASH,
            binder,
        }
    }
    fn error<T>(result: Result<T, Error>) -> Error {
        match result {
            Err(e) => e,
            Ok(_) => panic!("unexpected acceptance"),
        }
    }

    fn early_limits() -> RememberedLimits {
        RememberedLimits::from_authenticated_server_parameters(&[
            0, 0, 15, 0, 4, 1, 16, 6, 1, 8, 7, 1, 8, 8, 1, 1, 9, 1, 1,
        ])
        .unwrap()
    }
    fn issue_early(
        key: &mut TicketKey<'_>,
        rng: &mut TestRng,
        lifetime: u32,
    ) -> ([u8; SEALED_TICKET_BYTES], IssuedTicket, [u8; 32]) {
        let token = key
            .prepare_early(rng, 1000, lifetime, 0x1301, binding(), early_limits())
            .unwrap();
        let psk = resumption().resumption_psk(token.ticket_nonce()).unwrap();
        let binder = KeySchedule::new(Some(psk.as_bytes()))
            .unwrap()
            .binder(PskKind::Resumption, &HASH)
            .unwrap();
        let mut bytes = [0; SEALED_TICKET_BYTES];
        let issued = key.seal(token, psk, &mut bytes).unwrap();
        (bytes, issued, binder)
    }
    #[test]
    fn early_ticket_real_aead_has_nonrefundable_single_use_and_retains_one_rtt_schedule() {
        let mut rng = TestRng::new(55);
        let mut ordinary = [];
        let mut early = ReplayStorage::<1>::new();
        let mut key = TicketKey::generate_with_early_replay(
            &mut rng,
            ReplayPolicy::ReusableOneRtt,
            &mut ordinary,
            &mut early,
        )
        .unwrap();
        let (bytes, issued, binder) = issue_early(&mut key, &mut rng, 60);
        let binding = binding();
        let mut accepted = key
            .accept(&bytes, request(&binding, &issued, 1000, &binder))
            .unwrap();
        assert_eq!(accepted.early_limits(), Some(early_limits()));
        let claim = key
            .claim_early(&mut accepted, 7, 1000, EarlyFreshness::new(100).unwrap())
            .unwrap();
        assert_eq!(claim.generation(), 7);
        assert_eq!(
            error(key.claim_early(&mut accepted, 7, 1000, EarlyFreshness::new(100).unwrap())),
            Error::EarlyDataUnavailable
        );
        assert_eq!(accepted.into_schedule().stage(), Stage::Early);
        let mut replayed = key
            .accept(&bytes, request(&binding, &issued, 1001, &binder))
            .unwrap();
        assert_eq!(
            error(key.claim_early(&mut replayed, 8, 1001, EarlyFreshness::new(100).unwrap())),
            Error::EarlyReplay(early::Error::Replay)
        );
        assert_eq!(replayed.into_schedule().stage(), Stage::Early);
    }
    #[test]
    fn early_ticket_bad_binder_never_claims_and_live_replay_capacity_never_evicts() {
        let mut rng = TestRng::new(56);
        let mut ordinary = [];
        let mut early = ReplayStorage::<1>::new();
        let mut key = TicketKey::generate_with_early_replay(
            &mut rng,
            ReplayPolicy::ReusableOneRtt,
            &mut ordinary,
            &mut early,
        )
        .unwrap();
        let (first, a, ab) = issue_early(&mut key, &mut rng, 1);
        let (second, b, bb) = issue_early(&mut key, &mut rng, 60);
        let binding = binding();
        let mut bad = ab;
        bad[0] ^= 1;
        assert_eq!(
            error(key.accept(&first, request(&binding, &a, 1000, &bad))),
            Error::Binder
        );
        let mut accepted = key
            .accept(&first, request(&binding, &a, 1000, &ab))
            .unwrap();
        let _claim = key
            .claim_early(&mut accepted, 1, 1000, EarlyFreshness::new(100).unwrap())
            .unwrap();
        let mut full = key
            .accept(&second, request(&binding, &b, 1000, &bb))
            .unwrap();
        assert_eq!(
            error(key.claim_early(&mut full, 2, 1000, EarlyFreshness::new(100).unwrap())),
            Error::EarlyReplay(early::Error::Capacity)
        );
        assert_eq!(full.into_schedule().stage(), Stage::Early);
        let mut after = key
            .accept(&second, request(&binding, &b, 2000, &bb))
            .unwrap();
        assert_eq!(
            key.claim_early(&mut after, 2, 2000, EarlyFreshness::new(100).unwrap())
                .unwrap()
                .generation(),
            2
        );
    }
    #[test]
    fn fresh_ticket_key_after_restart_invalidates_old_early_ticket() {
        let mut rng = TestRng::new(57);
        let mut ordinary = [];
        let mut early = ReplayStorage::<1>::new();
        let (bytes, issued, binder) = {
            let mut key = TicketKey::generate_with_early_replay(
                &mut rng,
                ReplayPolicy::ReusableOneRtt,
                &mut ordinary,
                &mut early,
            )
            .unwrap();
            issue_early(&mut key, &mut rng, 60)
        };
        let mut new_key = TicketKey::generate_with_early_replay(
            &mut rng,
            ReplayPolicy::ReusableOneRtt,
            &mut ordinary,
            &mut early,
        )
        .unwrap();
        let binding = binding();
        assert_eq!(
            error(new_key.accept(&bytes, request(&binding, &issued, 1000, &binder))),
            Error::Authentication
        );
    }
    #[test]
    fn early_age_tolerance_is_independent_exact_and_does_not_burn_on_failure() {
        for (delta, allowed) in [
            (999, true),
            (1000, true),
            (1001, false),
            (9999, false),
            (10000, false),
        ] {
            let mut rng = TestRng::new(900 + delta);
            let mut ordinary = [];
            let mut replay = ReplayStorage::<1>::new();
            let mut key = TicketKey::generate_with_early_replay(
                &mut rng,
                ReplayPolicy::ReusableOneRtt,
                &mut ordinary,
                &mut replay,
            )
            .unwrap();
            let (bytes, issued, binder) = issue_early(&mut key, &mut rng, 60);
            let binding = binding();
            let mut req = request(&binding, &issued, 2000, &binder);
            req.max_age_skew_ms = 10_000;
            req.obfuscated_age = req.obfuscated_age.wrapping_add(delta as u32);
            let mut accepted = key.accept(&bytes, req).unwrap();
            let result =
                key.claim_early(&mut accepted, 1, 2000, EarlyFreshness::new(1000).unwrap());
            assert_eq!(result.is_ok(), allowed);
            if !allowed {
                assert_eq!(error(result), Error::EarlyAgeMismatch);
                assert_eq!(accepted.into_schedule().stage(), Stage::Early);
                let mut correct = key
                    .accept(&bytes, request(&binding, &issued, 2000, &binder))
                    .unwrap();
                assert!(
                    key.claim_early(&mut correct, 2, 2000, EarlyFreshness::new(0).unwrap())
                        .is_ok()
                );
            }
        }
        assert_eq!(
            EarlyFreshness::new(EarlyFreshness::MAX_SKEW_MS + 1),
            Err(early::Error::InvalidFreshness)
        );
    }

    #[test]
    fn early_permission_requires_explicit_key_policy_and_cache_metadata() {
        let mut rng = TestRng::new(58);
        let mut ordinary = [];
        let mut key =
            TicketKey::generate(&mut rng, ReplayPolicy::ReusableOneRtt, &mut ordinary).unwrap();
        assert_eq!(
            error(key.prepare_early(&mut rng, 1000, 60, 0x1301, binding(), early_limits())),
            Error::EarlyDataUnavailable
        );
        let (bytes, issued, binder) = issue(&mut key, &mut rng, 60);
        let bind = binding();
        let mut accepted = key
            .accept(&bytes, request(&bind, &issued, 1000, &binder))
            .unwrap();
        assert_eq!(accepted.early_limits(), None);
        assert_eq!(
            error(key.claim_early(&mut accepted, 1, 1000, EarlyFreshness::new(100).unwrap())),
            Error::EarlyDataUnavailable
        );
        let context = VerificationContext([9; 32]);
        let mut slots = [ClientSlot::<256>::empty()];
        let mut cache = ClientCache::new(&mut slots);
        cache
            .insert_verified_early(1000, cached(b"opaque", 60), psk(), context, early_limits())
            .unwrap();
        let offer = cache
            .take_verified_for_origin(1000, &binding(), 0x1301, context)
            .unwrap()
            .unwrap();
        assert_eq!(offer.remembered_early_limits(), Some(early_limits()));
        offer.verify_context(context, &binding()).unwrap();
        assert_eq!(
            offer.verify_context(VerificationContext([8; 32]), &binding()),
            Err(Error::VerificationContext)
        );
    }

    #[test]
    fn real_aead_and_existing_binder_schedule_roundtrip() {
        let mut rng = TestRng::new(1);
        let mut ledger = [];
        let mut key =
            TicketKey::generate(&mut rng, ReplayPolicy::ReusableOneRtt, &mut ledger).unwrap();
        let token = key.prepare(&mut rng, 1000, 60, 0x1301, binding()).unwrap();
        let psk = resumption().resumption_psk(token.ticket_nonce()).unwrap();
        let original = *psk.as_bytes();
        let binder = KeySchedule::new(Some(psk.as_bytes()))
            .unwrap()
            .binder(PskKind::Resumption, &HASH)
            .unwrap();
        let mut ticket = [0; SEALED_TICKET_BYTES];
        let issued = key.seal(token, psk, &mut ticket).unwrap();
        assert_eq!(issued.len, SEALED_TICKET_BYTES);
        assert!(!ticket.windows(32).any(|w| w == original));
        let bind = binding();
        let accepted = key
            .accept(&ticket, request(&bind, &issued, 2000, &binder))
            .unwrap();
        assert_eq!(accepted.suite(), 0x1301);
        let mut server = accepted.into_schedule();
        assert_eq!(server.stage(), Stage::Early);
        let mut client = KeySchedule::new(Some(&original)).unwrap();
        let mut t = Transcript::new();
        t.append(&[1, 0, 0, 0]).unwrap();
        t.append(&[2, 0, 0, 0]).unwrap();
        client.derive_handshake(&[3; 32], &t).unwrap();
        server.derive_handshake(&[3; 32], &t).unwrap();
        assert_eq!(
            client.handshake_traffic(Side::Client).unwrap().as_bytes(),
            server.handshake_traffic(Side::Client).unwrap().as_bytes()
        );
        assert!(
            key.accept(&ticket, request(&bind, &issued, 2000, &binder))
                .is_ok(),
            "explicit reusable policy is 1RTT only"
        );
    }
    #[test]
    fn ciphertext_header_tag_and_every_truncation_are_authenticated() {
        let mut rng = TestRng::new(2);
        let mut ledger = [];
        let mut key =
            TicketKey::generate(&mut rng, ReplayPolicy::ReusableOneRtt, &mut ledger).unwrap();
        let (ticket, issued, binder) = issue(&mut key, &mut rng, 60);
        let bind = binding();
        for n in 0..ticket.len() {
            assert!(
                key.accept(&ticket[..n], request(&bind, &issued, 2000, &binder))
                    .is_err()
            )
        }
        for n in 0..ticket.len() {
            let mut bad = ticket;
            bad[n] ^= 1;
            assert!(
                key.accept(&bad, request(&bind, &issued, 2000, &binder))
                    .is_err(),
                "tamper at {n}"
            )
        }
        let mut trailing = [0; SEALED_TICKET_BYTES + 1];
        trailing[..ticket.len()].copy_from_slice(&ticket);
        assert_eq!(
            error(key.accept(&trailing, request(&bind, &issued, 2000, &binder))),
            Error::InvalidTicket
        );
        assert!(
            key.accept(&ticket, request(&bind, &issued, 2000, &binder))
                .is_ok()
        );
    }
    #[test]
    fn binding_domain_suite_and_binder_must_all_match() {
        let mut rng = TestRng::new(3);
        let mut ledger = [];
        let mut key =
            TicketKey::generate(&mut rng, ReplayPolicy::ReusableOneRtt, &mut ledger).unwrap();
        let (ticket, issued, binder) = issue(&mut key, &mut rng, 60);
        for bind in [
            Binding::new("different.test", b"hq-interop", b"canonical limits v1").unwrap(),
            Binding::new("server.test", b"h3", b"canonical limits v1").unwrap(),
            Binding::new("server.test", b"hq-interop", b"changed limits").unwrap(),
        ] {
            assert_eq!(
                error(key.accept(&ticket, request(&bind, &issued, 2000, &binder))),
                Error::InvalidBinding
            );
        }
        let bind = binding();
        let mut wrong = request(&bind, &issued, 2000, &binder);
        wrong.suite = 0x1303;
        assert_eq!(error(key.accept(&ticket, wrong)), Error::InvalidBinding);
        for bad in [&[0; 32][..], &binder[..31], &[]] {
            assert_eq!(
                error(key.accept(&ticket, request(&bind, &issued, 2000, bad))),
                Error::Binder
            )
        }
        let mut wrong = request(&bind, &issued, 2000, &binder);
        wrong.transcript_hash = &[8; 32];
        assert_eq!(error(key.accept(&ticket, wrong)), Error::Binder);
        let canonical = Binding::new("SERVER.TEST", b"hq-interop", b"canonical limits v1").unwrap();
        assert_eq!(canonical, bind);
        assert!(
            key.accept(&ticket, request(&canonical, &issued, 2000, &binder))
                .is_ok()
        );
    }
    #[test]
    fn expiry_age_skew_wrapping_and_clock_rollback_fail_closed() {
        let mut rng = TestRng::new(4);
        let mut ledger = [];
        let mut key =
            TicketKey::generate(&mut rng, ReplayPolicy::ReusableOneRtt, &mut ledger).unwrap();
        let mut token = key.prepare(&mut rng, 1000, 60, 0x1301, binding()).unwrap();
        token.age_add = u32::MAX - 5;
        let psk = resumption().resumption_psk(token.ticket_nonce()).unwrap();
        let binder = KeySchedule::new(Some(psk.as_bytes()))
            .unwrap()
            .binder(PskKind::Resumption, &HASH)
            .unwrap();
        let mut ticket = [0; SEALED_TICKET_BYTES];
        let issued = key.seal(token, psk, &mut ticket).unwrap();
        let bind = binding();
        let mut req = request(&bind, &issued, 2000, &binder);
        assert_eq!(req.obfuscated_age, 994);
        req.obfuscated_age = req.obfuscated_age.wrapping_add(101);
        assert_eq!(error(key.accept(&ticket, req)), Error::AgeMismatch);
        let mut req = request(&bind, &issued, 2000, &binder);
        req.max_age_skew_ms = MAX_AGE_SKEW_MS + 1;
        assert_eq!(error(key.accept(&ticket, req)), Error::InvalidAgeSkew);
        assert!(
            key.accept(&ticket, request(&bind, &issued, 2000, &binder))
                .is_ok()
        );
        assert_eq!(
            error(key.accept(&ticket, request(&bind, &issued, 1999, &binder))),
            Error::ClockRollback
        );
        assert_eq!(
            error(key.accept(&ticket, request(&bind, &issued, 61000, &binder))),
            Error::Expired
        );
    }
    #[test]
    fn one_time_replay_ledger_commits_only_after_valid_binder_and_never_evicts_live_entry() {
        let mut rng = TestRng::new(5);
        let mut ledger = [ReplaySlot::empty()];
        let mut key =
            TicketKey::generate(&mut rng, ReplayPolicy::SingleUseOneRtt, &mut ledger).unwrap();
        let (a, ai, ab) = issue(&mut key, &mut rng, 60);
        let (b, bi, bb) = issue(&mut key, &mut rng, 120);
        let bind = binding();
        assert_eq!(
            error(key.accept(&a, request(&bind, &ai, 2000, &[0; 32]))),
            Error::Binder
        );
        assert!(key.accept(&a, request(&bind, &ai, 2000, &ab)).is_ok());
        assert_eq!(
            error(key.accept(&a, request(&bind, &ai, 2000, &ab))),
            Error::Replay
        );
        assert_eq!(
            error(key.accept(&b, request(&bind, &bi, 2000, &bb))),
            Error::Capacity
        );
        assert!(key.accept(&b, request(&bind, &bi, 61000, &bb)).is_ok());
        assert_eq!(
            error(key.accept(&a, request(&bind, &ai, 61000, &ab))),
            Error::Expired
        );
    }
    #[test]
    fn hrr_check_preserves_single_use_until_final_binder_acceptance() {
        let mut rng = TestRng::new(42);
        let mut slots = [ReplaySlot::empty()];
        let mut key =
            TicketKey::generate(&mut rng, ReplayPolicy::SingleUseOneRtt, &mut slots).unwrap();
        let (ticket, issued, binder) = issue(&mut key, &mut rng, 60);
        let binding = binding();
        key.check(&ticket, request(&binding, &issued, 1000, &binder))
            .unwrap();
        key.check(&ticket, request(&binding, &issued, 1001, &binder))
            .unwrap();
        assert!(!key.replay[0].occupied);
        key.accept(&ticket, request(&binding, &issued, 1002, &binder))
            .unwrap();
        assert_eq!(
            error(key.check(&ticket, request(&binding, &issued, 1003, &binder))),
            Error::Replay
        );
    }

    #[test]
    fn verification_digest_binds_anchor_fields_limits_and_order() {
        use crate::tls_certificate::{Limits, TrustAnchor};
        let make = |subject: &'static [u8],
                    spki: &'static [u8],
                    constraints: Option<&'static [u8]>| TrustAnchor {
            subject: rustls_pki_types::Der::from(subject),
            subject_public_key_info: rustls_pki_types::Der::from(spki),
            name_constraints: constraints.map(rustls_pki_types::Der::from),
        };
        let anchors = [make(&b"subject"[..], &b"spki"[..], None::<&[u8]>)];
        let original = VerificationContext::new(&anchors, Limits::default()).unwrap();
        for changed in [
            make(&b"other"[..], &b"spki"[..], None),
            make(&b"subject"[..], &b"other"[..], None),
            make(&b"subject"[..], &b"spki"[..], Some(&b"constraints"[..])),
        ] {
            assert_ne!(
                original,
                VerificationContext::new(&[changed], Limits::default()).unwrap()
            );
        }
        let limits = Limits {
            max_chain_bytes: 32769,
            ..Limits::default()
        };
        assert_ne!(
            original,
            VerificationContext::new(&anchors, limits).unwrap()
        );
        let a = [
            make(&b"one"[..], &b"a"[..], None),
            make(&b"two"[..], &b"b"[..], None),
        ];
        let b = [
            make(&b"two"[..], &b"b"[..], None),
            make(&b"one"[..], &b"a"[..], None),
        ];
        assert_ne!(
            VerificationContext::new(&a, Limits::default()).unwrap(),
            VerificationContext::new(&b, Limits::default()).unwrap()
        );
    }

    #[test]
    fn nonce_reservations_are_unique_burned_on_failure_and_bounded() {
        let mut rng = TestRng::new(6);
        let mut ledger = [];
        let mut key =
            TicketKey::generate(&mut rng, ReplayPolicy::ReusableOneRtt, &mut ledger).unwrap();
        let a = key.prepare(&mut rng, 0, 1, 0x1301, binding()).unwrap();
        rng.fail = true;
        assert_eq!(
            error(key.prepare(&mut rng, 0, 1, 0x1301, binding())),
            Error::Entropy
        );
        rng.fail = false;
        let b = key.prepare(&mut rng, 0, 1, 0x1301, binding()).unwrap();
        assert_ne!(a.ticket_nonce(), b.ticket_nonce());
        assert_eq!(&a.nonce[4..], &0u64.to_be_bytes());
        assert_eq!(&b.nonce[4..], &2u64.to_be_bytes());
        key.next_nonce = MAX_ISSUED;
        assert_eq!(
            error(key.prepare(&mut rng, 0, 1, 0x1301, binding())),
            Error::KeyExhausted
        );
    }
    #[test]
    fn foreign_retired_and_undersized_issue_never_exposes_plaintext() {
        let mut rng = TestRng::new(7);
        let mut ledger = [];
        let mut foreign_ledger = [];
        let mut key =
            TicketKey::generate(&mut rng, ReplayPolicy::ReusableOneRtt, &mut ledger).unwrap();
        let mut foreign =
            TicketKey::generate(&mut rng, ReplayPolicy::ReusableOneRtt, &mut foreign_ledger)
                .unwrap();
        let a = key.prepare(&mut rng, 0, 1, 0x1301, binding()).unwrap();
        let psk = resumption().resumption_psk(a.ticket_nonce()).unwrap();
        let mut out = [0xcc; SEALED_TICKET_BYTES];
        assert_eq!(foreign.seal(a, psk, &mut out), Err(Error::ForeignIssue));
        assert_eq!(out, [0xcc; SEALED_TICKET_BYTES]);
        let a = key.prepare(&mut rng, 0, 1, 0x1301, binding()).unwrap();
        let psk = resumption().resumption_psk(a.ticket_nonce()).unwrap();
        assert_eq!(
            key.seal(a, psk, &mut out[..SEALED_TICKET_BYTES - 1]),
            Err(Error::BufferTooSmall)
        );
        assert_eq!(out, [0xcc; SEALED_TICKET_BYTES]);
        let a = key.prepare(&mut rng, 0, 1, 0x1301, binding()).unwrap();
        let psk = resumption().resumption_psk(a.ticket_nonce()).unwrap();
        key.retire();
        assert!(key.key.iter().all(|b| *b == 0));
        assert_eq!(key.seal(a, psk, &mut out), Err(Error::KeyRetired));
        assert_eq!(
            error(key.prepare(&mut rng, 0, 1, 0x1301, binding())),
            Error::KeyRetired
        );
    }
    #[test]
    fn failed_aead_budget_retires_and_wipes_owner() {
        let mut rng = TestRng::new(8);
        let mut ledger = [];
        let mut key =
            TicketKey::generate(&mut rng, ReplayPolicy::ReusableOneRtt, &mut ledger).unwrap();
        let (mut ticket, issued, binder) = issue(&mut key, &mut rng, 60);
        ticket[HEADER_BYTES] ^= 1;
        key.auth_failures = MAX_AUTH_FAILURES - 1;
        assert_eq!(
            error(key.accept(&ticket, request(&binding(), &issued, 2000, &binder))),
            Error::Authentication
        );
        assert!(key.is_retired() && key.key.iter().all(|b| *b == 0));
        assert_eq!(
            error(key.accept(&ticket, request(&binding(), &issued, 2000, &binder))),
            Error::KeyRetired
        );
    }
    #[test]
    fn invalid_entropy_limits_names_and_lifetimes_are_rejected() {
        let mut rng = TestRng::new(9);
        rng.fail = true;
        let mut ledger = [];
        assert_eq!(
            error(TicketKey::generate(
                &mut rng,
                ReplayPolicy::ReusableOneRtt,
                &mut ledger
            )),
            Error::Entropy
        );
        rng.fail = false;
        assert_eq!(
            error(TicketKey::generate(
                &mut rng,
                ReplayPolicy::SingleUseOneRtt,
                &mut ledger
            )),
            Error::Capacity
        );
        let mut key =
            TicketKey::generate(&mut rng, ReplayPolicy::ReusableOneRtt, &mut ledger).unwrap();
        for lifetime in [0, MAX_LIFETIME_SECONDS + 1] {
            assert_eq!(
                error(key.prepare(&mut rng, 0, lifetime, 0x1301, binding())),
                Error::InvalidLifetime
            )
        }
        assert_eq!(
            error(key.prepare(&mut rng, u64::MAX, 1, 0x1301, binding())),
            Error::ClockOverflow
        );
        assert_eq!(
            error(key.prepare(&mut rng, 0, 1, 0x1302, binding())),
            Error::InvalidSuite
        );
        for name in ["", "bad\0.test", "127.0.0.1"] {
            assert_eq!(
                Binding::new(name, b"hq-interop", &[]),
                Err(Error::InvalidBinding)
            )
        }
        assert_eq!(
            Binding::new("server.test", &[], &[]),
            Err(Error::InvalidBinding)
        );
        assert_eq!(
            Binding::new(
                "server.test",
                b"hq-interop",
                &[0; MAX_BINDING_PROFILE_BYTES + 1]
            ),
            Err(Error::InvalidBinding)
        );
    }
    fn cached<'a>(ticket: &'a [u8], lifetime: u32) -> ReceivedTicket<'a> {
        ReceivedTicket {
            ticket,
            lifetime_seconds: lifetime,
            age_add: u32::MAX - 5,
            suite: 0x1301,
            binding: binding(),
        }
    }
    fn psk() -> Secret32 {
        resumption().resumption_psk(b"client test nonce").unwrap()
    }
    #[test]
    fn issued_ticket_client_cache_and_server_binder_acceptance_compose() {
        let mut rng = TestRng::new(10);
        let mut replay = [ReplaySlot::empty()];
        let mut key =
            TicketKey::generate(&mut rng, ReplayPolicy::SingleUseOneRtt, &mut replay).unwrap();
        let master = resumption();
        let token = key.prepare(&mut rng, 1000, 60, 0x1301, binding()).unwrap();
        let server_psk = master.resumption_psk(token.ticket_nonce()).unwrap();
        let mut ticket = [0; SEALED_TICKET_BYTES];
        let issued = key.seal(token, server_psk, &mut ticket).unwrap();
        let client_psk = master.resumption_psk(&issued.nonce).unwrap();
        let mut slots = [ClientSlot::<SEALED_TICKET_BYTES>::empty()];
        let mut cache = ClientCache::new(&mut slots);
        cache
            .insert(
                1020,
                ReceivedTicket {
                    ticket: &ticket,
                    lifetime_seconds: issued.lifetime_seconds,
                    age_add: issued.age_add,
                    suite: 0x1301,
                    binding: binding(),
                },
                client_psk,
            )
            .unwrap();
        // Before reconnecting, only origin/ALPN are known; current server policy
        // is still checked on the server after authenticating the opaque ticket.
        let origin = Binding::new("SERVER.TEST", b"hq-interop", &[]).unwrap();
        assert!(cache.take(2000, &origin, 0x1301).unwrap().is_none());
        let mut offered = cache
            .take_for_origin(2000, &origin, 0x1301)
            .unwrap()
            .unwrap();
        let binder = offered.binder(&HASH).unwrap();
        let age = offered.obfuscated_age(2000).unwrap();
        let current = binding();
        let accepted = key
            .accept(
                offered.identity(),
                Acceptance {
                    now_ms: 2000,
                    obfuscated_age: age,
                    max_age_skew_ms: 100,
                    binding: &current,
                    suite: 0x1301,
                    transcript_hash: &HASH,
                    binder: &binder,
                },
            )
            .unwrap();
        assert_eq!(accepted.suite(), offered.suite());
        assert!(cache.is_empty());
        assert_eq!(offered.obfuscated_age(1999), Err(Error::ClockRollback));
        assert!(
            cache
                .take_for_origin(2000, &origin, 0x1301)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn client_cache_is_bounded_single_consumption_and_fifo() {
        let mut slots = [ClientSlot::<128>::empty(), ClientSlot::empty()];
        let mut cache = ClientCache::new(&mut slots);
        cache.insert(0, cached(b"first", 60), psk()).unwrap();
        cache.insert(0, cached(b"second", 60), psk()).unwrap();
        assert_eq!(
            cache.insert(0, cached(b"first", 60), psk()),
            Err(Error::DuplicateTicket)
        );
        assert_eq!(
            cache.insert(0, cached(b"third", 60), psk()),
            Err(Error::Capacity)
        );
        let wrong = Binding::new("other.test", b"hq-interop", b"canonical limits v1").unwrap();
        assert!(cache.take(0, &wrong, 0x1301).unwrap().is_none());
        let mut first = cache.take(1000, &binding(), 0x1301).unwrap().unwrap();
        assert_eq!(first.identity(), b"first");
        assert_eq!(first.obfuscated_age(1000), Ok(994));
        assert_eq!(
            first.binder(&HASH).unwrap(),
            KeySchedule::new(Some(psk().as_bytes()))
                .unwrap()
                .binder(PskKind::Resumption, &HASH)
                .unwrap()
        );
        cache.insert(1000, cached(b"third", 60), psk()).unwrap();
        assert_eq!(
            cache
                .take(1000, &binding(), 0x1301)
                .unwrap()
                .unwrap()
                .identity(),
            b"second"
        );
        assert_eq!(
            cache
                .take(1000, &binding(), 0x1301)
                .unwrap()
                .unwrap()
                .identity(),
            b"third"
        );
        assert!(cache.is_empty());
        assert!(cache.take(1000, &binding(), 0x1301).unwrap().is_none());
    }
    #[test]
    fn cache_expiry_bad_capacities_clock_and_drop_are_explicit() {
        let mut slots = [ClientSlot::<8>::empty()];
        {
            let mut cache = ClientCache::new(&mut slots);
            assert_eq!(cache.insert(0, cached(b"", 1), psk()), Err(Error::Capacity));
            assert_eq!(
                cache.insert(0, cached(b"too large", 1), psk()),
                Err(Error::Capacity)
            );
            cache.insert(0, cached(b"old", 1), psk()).unwrap();
            assert!(cache.take(1000, &binding(), 0x1301).unwrap().is_none());
            cache.insert(1000, cached(b"new", 1), psk()).unwrap();
            assert_eq!(
                error(cache.take(999, &binding(), 0x1301)),
                Error::ClockRollback
            );
            let mut offer = cache.take(1000, &binding(), 0x1301).unwrap().unwrap();
            assert_eq!(offer.obfuscated_age(999), Err(Error::ClockRollback));
            assert_eq!(offer.obfuscated_age(2000), Err(Error::Expired));
            cache.insert(1000, cached(b"wipe", 1), psk()).unwrap();
        }
        assert!(slots[0].psk.is_none());
        assert_eq!(slots[0].ticket, [0; 8]);
    }
}
