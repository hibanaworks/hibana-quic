//! Owned packet-key handoff from the bounded TLS transcript owner.
//!
//! Installations transfer cryptographic material only. The connection graph must
//! separately enforce Finished, handshake confirmation, authenticated ACK and
//! early replay/quarantine permissions. A fatal TLS result must retire keys in
//! the actual RX/TX owners; this source cannot revoke keys it no longer owns.
//!
//! Reconstructed from retained task tool-call bodies after executor replacement;
//! these recovered bytes have not been compiled or tested.
//! The later owned-level authentication receipt and fatal-poll distinction were
//! reimplemented from the recovery contract and likewise remain unverified.

#[cfg(test)]
#[path = "handoff_tests.rs"]
mod tests;

// Reimplemented from the later direct-wire recovery contract; not yet executed.
#[cfg(test)]
#[path = "owned_level_tests.rs"]
mod owned_level_tests;

use super::{BoundedTls, DirectionalKeys, Failure, State, map_crypto};
use crate::{
    crypto::{
        self, CipherSuite, IntegrityBudget, KeyKind, PacketKey,
        directional::{
            ApplicationKeyInstallation, ApplicationKeyScope, ApplicationReadKeys,
            ApplicationWriteKeys,
        },
    },
    early_data::{EarlyStatus, RememberedLimits, ReplayClaim},
    tls::{self, Level, Output, Provider},
    tls_schedule::Side,
};

/// The transcript/certificate/CRYPTO owner after exclusive packet-key handoff
/// was selected. It has no Provider implementation or packet-protection escape.
/// The immutable scope is bound before Handshake/application keys are created.
///
/// ```compile_fail
/// use hibana_quic::{bounded_tls::key_source::KeySource, tls::Provider};
/// fn combined(source: KeySource<'_, '_, '_>) {
///     let _: &dyn Provider = &source;
/// }
/// ```
pub struct KeySource<'scope, 'cfg, 'buf> {
    provider: BoundedTls<'cfg, 'buf>,
    scope: &'scope ApplicationKeyScope,
    application: Option<ApplicationKeyInstallation<'scope>>,
    integrity: Option<IntegrityBudget>,
}

impl<'cfg, 'buf> BoundedTls<'cfg, 'buf> {
    /// Select the owned-key path before processing the peer's first flight.
    /// Existing application/Handshake state, including legacy authorization,
    /// cannot be migrated. An existing client 0-RTT key moves with its complete
    /// nonce/confidentiality accounting; it grants no replay or delivery rights.
    /// The affine claim is consumed even if this transition is rejected.
    pub fn into_key_source<'scope>(
        mut self,
        installation: ApplicationKeyInstallation<'scope>,
    ) -> Result<KeySource<'scope, 'cfg, 'buf>, Failure> {
        if self.handshake_created
            || self.application_created
            || self.handshake_discarded
            || self.application_discarded
            || self.rx_used != 0
            || !self.pristine()
        {
            return Err(Failure::State);
        }
        self.key_handoff = true;
        let integrity = self.integrity.take_for_role();
        Ok(KeySource {
            provider: self,
            scope: installation.scope(),
            application: Some(installation),
            integrity: Some(integrity),
        })
    }
}

impl<'scope, 'cfg, 'buf> KeySource<'scope, 'cfg, 'buf> {
    pub(crate) fn material(&mut self) -> &mut BoundedTls<'cfg, 'buf> {
        &mut self.provider
    }
    pub const fn scope(&self) -> &'scope ApplicationKeyScope {
        self.scope
    }
    pub fn state(&self) -> State {
        self.provider.state()
    }
    /// The configured TLS role, obtained from the actual owning provider.
    pub fn side(&self) -> Side {
        self.provider.side()
    }
    pub fn last_failure(&self) -> Option<&Failure> {
        self.provider.last_failure()
    }
    pub fn is_handshaking(&self) -> bool {
        self.provider.is_handshaking()
    }
    pub fn is_resumed(&self) -> bool {
        self.provider.is_resumed()
    }
    pub fn negotiated_suite(&self) -> Option<CipherSuite> {
        self.provider.negotiated_suite()
    }
    pub fn negotiated_group(&self) -> Option<u16> {
        self.provider.negotiated_group()
    }
    pub fn negotiated_alpn(&self) -> Option<&'static [u8]> {
        self.provider.negotiated_alpn()
    }
    pub fn peer_transport_parameters(&self) -> Option<&[u8]> {
        self.provider.peer_transport_parameters()
    }
    pub fn observations(&self) -> tls::Observations {
        let mut observations = self.provider.observations();
        // Report only the actual budget still owned here, never the provider's
        // fail-closed sentinel or an invented post-transfer count.
        observations.failed_authentications =
            self.integrity.as_ref().map(IntegrityBudget::failed_packets);
        observations
    }
    pub fn write_failure_diagnostic(&self, out: &mut dyn core::fmt::Write) -> core::fmt::Result {
        self.provider.write_failure_diagnostic(out)
    }
    /// Input must already be packet-authenticated and CRYPTO-reassembled by RX.
    /// After Finished, OneRtt-only ticket input uses the same trusted boundary.
    pub fn receive(&mut self, level: Level, bytes: &[u8]) -> Result<(), tls::Error> {
        self.provider.receive(level, bytes)
    }
    pub fn transmit(&mut self, output: &mut [u8]) -> Result<Option<Output>, tls::Error> {
        self.provider.transmit(output)
    }
    pub fn resumed(&self) -> bool {
        self.provider.is_resumed()
    }
    pub fn early_status(&self) -> EarlyStatus {
        self.provider.early_status()
    }
    pub fn early_generation(&self) -> Option<u64> {
        self.provider.early_generation()
    }
    pub fn remembered_early_limits(&self) -> Option<RememberedLimits> {
        self.provider.remembered_early_limits()
    }
    /// Replay acceptance remains a separate, affine claim from key ownership.
    pub fn take_early_replay_claim(&mut self) -> Option<ReplayClaim> {
        self.provider.take_early_replay_claim()
    }
    /// Bind the actual burned replay claim and remembered limits to this source.
    pub fn take_early_admission(
        &mut self,
    ) -> Result<crate::early_data::owner::Admission<'scope>, tls::Error> {
        if self.provider.side() != Side::Server {
            return Err(tls::Error::InvalidInput);
        }
        let limits = self
            .provider
            .remembered_early_limits()
            .ok_or(tls::Error::KeysUnavailable)?;
        let claim = self
            .provider
            .take_early_replay_claim()
            .ok_or(tls::Error::KeysUnavailable)?;
        Ok(crate::early_data::owner::Admission::new(
            self.scope, limits, claim,
        ))
    }

    /// Emit the actual authenticated Finished transition exactly once. Client
    /// completion is not QUIC handshake confirmation; HANDSHAKE_DONE remains
    /// an independently authenticated receive transition.
    pub fn take_finished(&mut self) -> Result<FinishedAuthenticated<'scope>, tls::Error> {
        if self.provider.state == State::Failed {
            return Err(tls::Error::Handshake);
        }
        let verified = self
            .provider
            .verified_handshake
            .take()
            .ok_or(tls::Error::KeysUnavailable)?;
        let receipt = FinishedAuthenticated {
            scope: self.scope,
            side: verified.side,
            peer_parameters_digest: verified.peer_parameters_digest,
            early_status: verified.early_status,
            early_generation: verified.early_generation,
        };
        Ok(receipt)
    }
    /// Move the entire lifetime failed-authentication budget to RX, including
    /// failures accumulated by Initial/0-RTT before handoff. No replacement can
    /// be issued, and the source keeps only the existing fail-closed sentinel.
    pub fn take_integrity_budget(&mut self) -> Result<IntegrityBudget, tls::Error> {
        if self.provider.state == State::Failed {
            return Err(tls::Error::Handshake);
        }
        self.integrity.take().ok_or(tls::Error::KeysUnavailable)
    }
    /// Move both actual Handshake PacketKeys once. An unavailable early poll
    /// does not consume a future installation; dropping returned material does.
    pub fn take_handshake_keys(&mut self) -> Result<HandshakeKeyMaterial<'scope>, tls::Error> {
        if self.provider.state == State::Failed {
            return Err(tls::Error::Handshake);
        }
        let keys = self
            .provider
            .handshake
            .take()
            .ok_or(tls::Error::KeysUnavailable)?;
        Ok(HandshakeKeyMaterial {
            scope: self.scope,
            keys,
        })
    }
    /// The server can emit these keys before client Finished. Their existence
    /// is never a grant to deliver ordinary data, ACK it, or initiate an update.
    pub fn take_application_keys(&mut self) -> Result<ApplicationKeyMaterial<'scope>, tls::Error> {
        if self.provider.state == State::Failed {
            return Err(tls::Error::Handshake);
        }
        let keys = self
            .provider
            .application
            .take()
            .ok_or(tls::Error::KeysUnavailable)?;
        let installation = self.application.take().ok_or(tls::Error::KeysUnavailable)?;
        Ok(ApplicationKeyMaterial { installation, keys })
    }
    /// Move the sole early direction with unchanged packet usage. RX quarantine
    /// and TX replay policy are separate from this cryptographic capability.
    pub fn take_early_key(&mut self) -> Result<EarlyKeyMaterial<'scope>, tls::Error> {
        if self.provider.state == State::Failed {
            return Err(tls::Error::Handshake);
        }
        let key = self
            .provider
            .early_key
            .take()
            .ok_or(tls::Error::KeysUnavailable)?;
        Ok(match self.provider.side() {
            Side::Client => EarlyKeyMaterial::Transmit(TransmitPacketKey {
                scope: self.scope,
                key,
            }),
            Side::Server => EarlyKeyMaterial::Receive(ReceivePacketKey {
                scope: self.scope,
                key,
            }),
        })
    }
    /// Retire material still owned by TLS. The graph must separately retire
    /// already transferred owners before considering level retirement complete.
    pub fn discard_pending_keys(&mut self, level: Level) {
        self.provider.discard_keys(level);
    }
    pub fn discard_pending_early_key(&mut self) {
        self.provider.discard_early_keys();
    }
}

/// The actual peer Finished verification in one immutable connection domain.
/// Only KeySource can construct this affine receipt. Key installation and copied
/// observations cannot substitute for it in peer-parameter or early release
/// transitions. Its local side determines whether QUIC confirmation also exists.
/// ```compile_fail
/// use hibana_quic::bounded_tls::key_source::FinishedAuthenticated;
/// fn duplicate(done: FinishedAuthenticated<'_>) { let a = done; let b = done; }
/// ```
#[derive(Debug)]
#[must_use = "the connection graph must consume actual Finished authority"]
pub struct FinishedAuthenticated<'scope> {
    scope: &'scope ApplicationKeyScope,
    side: Side,
    peer_parameters_digest: [u8; 32],
    early_status: EarlyStatus,
    early_generation: Option<u64>,
}
impl<'scope> FinishedAuthenticated<'scope> {
    pub const fn scope(&self) -> &'scope ApplicationKeyScope {
        self.scope
    }
    pub const fn side(&self) -> Side {
        self.side
    }
    pub fn authenticates_peer_parameters(&self, parameters: &[u8]) -> bool {
        self.peer_parameters_digest == peer_parameters_digest(parameters)
    }
    pub const fn early_status(&self) -> EarlyStatus {
        self.early_status
    }
    pub const fn early_generation(&self) -> Option<u64> {
        self.early_generation
    }
}
pub(super) fn peer_parameters_digest(parameters: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(b"hibana-quic:verified-peer-parameters:v1\0");
    digest.update((parameters.len() as u64).to_be_bytes());
    digest.update(parameters);
    digest.finalize().into()
}

/// Affine Handshake installation. Neither direction can borrow the other's key.
/// ```compile_fail
/// use hibana_quic::bounded_tls::key_source::HandshakeKeyMaterial;
/// fn duplicate(keys: HandshakeKeyMaterial<'_>) { let a = keys; let b = keys; }
/// ```
#[must_use = "dropping key material permanently discards its installation"]
pub struct HandshakeKeyMaterial<'scope> {
    scope: &'scope ApplicationKeyScope,
    keys: DirectionalKeys,
}
impl<'scope> HandshakeKeyMaterial<'scope> {
    pub const fn scope(&self) -> &'scope ApplicationKeyScope {
        self.scope
    }
    pub fn install(self) -> (ReceivePacketKey<'scope>, TransmitPacketKey<'scope>) {
        (
            ReceivePacketKey {
                scope: self.scope,
                key: self.keys.remote,
            },
            TransmitPacketKey {
                scope: self.scope,
                key: self.keys.local,
            },
        )
    }
}

/// Fresh application material carrying the original pre-key installation claim.
/// No API exposes a combined legacy ApplicationKeys or accepts another scope.
/// ```compile_fail
/// use hibana_quic::bounded_tls::key_source::ApplicationKeyMaterial;
/// fn duplicate(keys: ApplicationKeyMaterial<'_>) { let a = keys; let b = keys; }
/// ```
#[must_use = "dropping key material permanently discards its installation"]
pub struct ApplicationKeyMaterial<'scope> {
    installation: ApplicationKeyInstallation<'scope>,
    keys: DirectionalKeys,
}
impl<'scope> ApplicationKeyMaterial<'scope> {
    pub const fn scope(&self) -> &'scope ApplicationKeyScope {
        self.installation.scope()
    }
    pub fn install(
        self,
    ) -> Result<(ApplicationReadKeys<'scope>, ApplicationWriteKeys<'scope>), tls::Error> {
        self.installation
            .install(self.keys.local, self.keys.remote)
            .map_err(map_crypto)
    }
}

#[must_use = "early keys carry no replay acceptance or delivery authority"]
pub enum EarlyKeyMaterial<'scope> {
    Receive(ReceivePacketKey<'scope>),
    Transmit(TransmitPacketKey<'scope>),
}

/// An actual successful Initial/Handshake authentication in one immutable scope.
/// Construction happens only after AEAD succeeds through its owning receive key.
/// The exact plaintext is bound with the existing length-prefixed digest. This
/// does not grant Finished, early delivery, or application-update authority.
///
/// ```compile_fail
/// use hibana_quic::bounded_tls::key_source::AuthenticatedLevelRead;
/// fn duplicate(receipt: AuthenticatedLevelRead<'_>) {
///     let first = receipt;
///     let second = receipt;
/// }
/// ```
/// ```compile_fail
/// use hibana_quic::{bounded_tls::key_source::AuthenticatedLevelRead,
///     crypto::{KeyKind, directional::ApplicationKeyScope}};
/// fn forge(scope: &ApplicationKeyScope) {
///     let _ = AuthenticatedLevelRead {
///         scope, kind: KeyKind::Handshake, packet_number: 0,
///         len: 1, plaintext_digest: [0; 32],
///     };
/// }
/// ```
#[derive(Debug)]
#[must_use = "consume the actual authentication in its scoped receive transition"]
pub struct AuthenticatedLevelRead<'scope> {
    scope: &'scope ApplicationKeyScope,
    kind: KeyKind,
    packet_number: u64,
    len: usize,
    plaintext_digest: [u8; 32],
}
impl<'scope> AuthenticatedLevelRead<'scope> {
    pub const fn scope(&self) -> &'scope ApplicationKeyScope {
        self.scope
    }
    pub const fn kind(&self) -> KeyKind {
        self.kind
    }
    pub const fn packet_number(&self) -> u64 {
        self.packet_number
    }
    pub const fn len(&self) -> usize {
        self.len
    }
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn authenticates_plaintext(&self, plaintext: &[u8]) -> bool {
        self.len == plaintext.len()
            && self.plaintext_digest == crate::crypto::plaintext_digest(plaintext)
    }
}

/// One inbound Initial, Handshake or 0-RTT key. Successful AEAD is only
/// cryptographic evidence; graph permissions decide which authenticated frames
/// may proceed. Only Initial and Handshake can emit AuthenticatedLevelRead.
pub struct ReceivePacketKey<'scope> {
    scope: &'scope ApplicationKeyScope,
    key: PacketKey,
}
impl<'scope> ReceivePacketKey<'scope> {
    /// Trusted direct RX attachment for an actual independently owned Initial
    /// key. Application and early keys cannot enter this constructor.
    pub(crate) fn from_initial(
        scope: &'scope ApplicationKeyScope,
        key: PacketKey,
    ) -> Result<Self, crypto::Error> {
        if key.kind() != KeyKind::Initial {
            return Err(crypto::Error::KeyDerivation);
        }
        key.ensure_active()?;
        Ok(Self { scope, key })
    }
    pub const fn scope(&self) -> &'scope ApplicationKeyScope {
        self.scope
    }
    pub const fn kind(&self) -> KeyKind {
        self.key.kind()
    }
    pub fn open(
        &self,
        pn: u64,
        header: &[u8],
        buffer: &mut [u8],
        budget: &mut IntegrityBudget,
    ) -> Result<usize, crypto::Error> {
        self.key.open(pn, header, buffer, budget)
    }
    /// Perform the actual AEAD and issue its affine, scope-bound evidence.
    /// 0-RTT requires replay/quarantine authority and 1-RTT requires directional
    /// epoch/ACK barriers, so both are rejected before touching the buffer/budget.
    /// Existing PacketKey handles nonce validation, limits and failure wiping.
    pub fn open_authenticated(
        &self,
        packet_number: u64,
        header: &[u8],
        buffer: &mut [u8],
        budget: &mut IntegrityBudget,
    ) -> Result<AuthenticatedLevelRead<'scope>, crypto::Error> {
        let kind = self.key.kind();
        if !matches!(kind, KeyKind::Initial | KeyKind::Handshake) {
            return Err(crypto::Error::KeyDerivation);
        }
        let len = self.key.open(packet_number, header, buffer, budget)?;
        Ok(AuthenticatedLevelRead {
            scope: self.scope,
            kind,
            packet_number,
            len,
            plaintext_digest: crate::crypto::plaintext_digest(&buffer[..len]),
        })
    }

    /// Actual 0-RTT authentication evidence, still without delivery authority.
    pub fn open_early_authenticated(
        &self,
        packet_number: u64,
        header: &[u8],
        buffer: &mut [u8],
        budget: &mut IntegrityBudget,
    ) -> Result<AuthenticatedEarlyRead<'scope>, crypto::Error> {
        if self.key.kind() != KeyKind::ZeroRtt {
            return Err(crypto::Error::KeyDerivation);
        }
        let len = self.key.open(packet_number, header, buffer, budget)?;
        Ok(AuthenticatedEarlyRead {
            scope: self.scope,
            packet_number,
            len,
            plaintext_digest: crate::crypto::plaintext_digest(&buffer[..len]),
        })
    }
    pub fn header_mask(&self, sample: &[u8; 16]) -> Result<[u8; 5], crypto::Error> {
        self.key.header_mask(sample)
    }
    pub fn unprotect_header(
        &self,
        packet: &mut [u8],
        pn_offset: usize,
    ) -> Result<usize, crypto::Error> {
        self.key.unprotect_header(packet, pn_offset)
    }
    pub fn discard(&mut self) {
        self.key.discard();
    }
}

/// One outbound Handshake or 0-RTT key retaining nonce/confidentiality accounting.
pub struct TransmitPacketKey<'scope> {
    scope: &'scope ApplicationKeyScope,
    key: PacketKey,
}
impl<'scope> TransmitPacketKey<'scope> {
    pub const fn scope(&self) -> &'scope ApplicationKeyScope {
        self.scope
    }
    pub const fn kind(&self) -> KeyKind {
        self.key.kind()
    }
    pub const fn sealed_packets(&self) -> u64 {
        self.key.sealed_packets()
    }
    pub const fn last_sealed_packet_number(&self) -> Option<u64> {
        self.key.last_sealed_packet_number()
    }
    pub fn seal(
        &mut self,
        pn: u64,
        header: &[u8],
        buffer: &mut [u8],
        plaintext_len: usize,
    ) -> Result<usize, crypto::Error> {
        self.key.seal(pn, header, buffer, plaintext_len)
    }
    pub fn header_mask(&self, sample: &[u8; 16]) -> Result<[u8; 5], crypto::Error> {
        self.key.header_mask(sample)
    }
    pub fn protect_header(&self, packet: &mut [u8], pn_offset: usize) -> Result<(), crypto::Error> {
        self.key.protect_header(packet, pn_offset)
    }
    pub fn discard(&mut self) {
        self.key.discard();
    }
}

/// Run the directly projected TLS client owner without exposing a Provider or
/// packet-key escape from the owned-key source. Input is the companion local
/// role in `bounded_tls::locals`, not a synchronous handshake dispatcher.
impl<'scope, 'cfg, 'buf> KeySource<'scope, 'cfg, 'buf> {
    pub async fn client_transcript_role(
        endpoint: &mut hibana::Endpoint<'_, { super::protocol::VERIFY }>,
        source: &core::cell::RefCell<Self>,
        message: &super::locals::MessageSlot<'_>,
    ) -> Result<(), super::locals::Error> {
        struct Access<'a, 'scope, 'cfg, 'buf>(
            &'a core::cell::RefCell<KeySource<'scope, 'cfg, 'buf>>,
        );
        impl super::locals::CryptoAccess for Access<'_, '_, '_, '_> {
            fn with_crypto<R>(&self, f: impl FnOnce(&mut BoundedTls<'_, '_>) -> R) -> R {
                f(&mut self.0.borrow_mut().provider)
            }
        }
        super::locals::client_owner(endpoint, &Access(source), message).await
    }
}

#[cfg(test)]
impl KeySource<'_, '_, '_> {
    pub(crate) fn test_handshake(client: &mut Self, server: &mut Self) {
        crate::bounded_tls::async_test_fixture::handshake(
            &mut client.provider,
            &mut server.provider,
        );
    }
}

// Unit-only receipt fixture for the isolated early-owner choreography. Real TLS
// production receipts still come exclusively from KeySource::take_finished.
#[cfg(test)]
pub(crate) fn synthetic_early_finished_for_owner_test(
    scope: &ApplicationKeyScope,
    generation: u64,
) -> FinishedAuthenticated<'_> {
    FinishedAuthenticated {
        scope,
        side: Side::Server,
        peer_parameters_digest: [0; 32],
        early_status: EarlyStatus::Accepted,
        early_generation: Some(generation),
    }
}

/// Affine evidence of actual 0-RTT AEAD, bound to scope, packet and plaintext.
#[derive(Debug)]
pub struct AuthenticatedEarlyRead<'scope> {
    scope: &'scope ApplicationKeyScope,
    packet_number: u64,
    len: usize,
    plaintext_digest: [u8; 32],
}
impl<'scope> AuthenticatedEarlyRead<'scope> {
    pub fn scope(&self) -> &'scope ApplicationKeyScope {
        self.scope
    }
    pub fn packet_number(&self) -> u64 {
        self.packet_number
    }
    pub fn authenticates_plaintext(&self, bytes: &[u8]) -> bool {
        self.len == bytes.len() && self.plaintext_digest == crate::crypto::plaintext_digest(bytes)
    }
}
