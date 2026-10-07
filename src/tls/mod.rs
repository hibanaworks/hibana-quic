//! Allocation-policy-neutral QUIC/TLS boundary. The core owns no TLS record I/O.
//! A provider must expose real authenticated TLS 1.3; a mock cannot qualify a gate.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Level {
    Initial,
    Handshake,
    OneRtt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Handshake,
    Alert(u8),
    KeysUnavailable,
    Authentication,
    Capacity,
    InvalidInput,
    ConfidentialityLimit,
    IntegrityLimit,
    PacketNumberReuse,
    ProtocolViolation,
    KeyUpdateError,
    KeyUpdateNotAllowed,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Output {
    pub level: Level,
    pub len: usize,
}

/// Copied provider observations. These values report state; they never grant
/// authentication, key-update, or delivery authority. None means unavailable.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Observations {
    pub resumed: Option<bool>,
    /// TLS/IANA wire identifier, including suites not implemented by core crypto.
    pub negotiated_suite: Option<u16>,
    /// Provider-reported count. This alone makes no connection-wide/Initial
    /// coverage claim for providers that do not expose a shared integrity budget.
    pub failed_authentications: Option<u64>,
}

pub const FAILURE_DIAGNOSTIC_BYTES: usize = 192;
/// Fixed, copied UTF-8 diagnostic text. It contains no Provider reference and
/// is informational only; actual command failures remain typed `Error` values.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct FailureDiagnostic {
    bytes: [u8; FAILURE_DIAGNOSTIC_BYTES],
    len: usize,
    truncated: bool,
    format_error: bool,
}
impl FailureDiagnostic {
    pub const fn empty() -> Self {
        Self {
            bytes: [0; FAILURE_DIAGNOSTIC_BYTES],
            len: 0,
            truncated: false,
            format_error: false,
        }
    }
    /// Render completely within the owning task, before any subsequent await.
    pub fn capture(provider: &(impl Provider + ?Sized)) -> Self {
        let mut result = Self::empty();
        if provider.write_failure_diagnostic(&mut result).is_err() {
            result.format_error = true;
        }
        result
    }
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.len]).expect("diagnostic writer preserves UTF-8")
    }
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub const fn truncated(&self) -> bool {
        self.truncated
    }
    pub const fn format_error(&self) -> bool {
        self.format_error
    }
}
impl Default for FailureDiagnostic {
    fn default() -> Self {
        Self::empty()
    }
}
impl core::fmt::Write for FailureDiagnostic {
    fn write_str(&mut self, value: &str) -> core::fmt::Result {
        if self.truncated {
            return Ok(());
        }
        let mut count = value.len().min(FAILURE_DIAGNOSTIC_BYTES - self.len);
        while !value.is_char_boundary(count) {
            count -= 1;
        }
        self.bytes[self.len..self.len + count].copy_from_slice(&value.as_bytes()[..count]);
        self.len += count;
        self.truncated = count != value.len();
        Ok(())
    }
}
impl core::fmt::Debug for FailureDiagnostic {
    fn fmt(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        out.debug_struct("FailureDiagnostic")
            .field("text", &self.as_str())
            .field("truncated", &self.truncated)
            .field("format_error", &self.format_error)
            .finish()
    }
}

/// Owned by one endpoint. Its allocation policy is part of the release identity:
/// implementing this trait does not establish no_alloc. The host reference backend
/// explicitly allocates. A release backend must use caller-owned bounded storage.
pub trait Provider {
    fn observations(&self) -> Observations {
        Observations::default()
    }
    /// Write diagnostic detail without allocation or retaining the sink. The
    /// owner copies this synchronously into FailureDiagnostic before awaiting.
    fn write_failure_diagnostic(&self, _out: &mut dyn core::fmt::Write) -> core::fmt::Result {
        Ok(())
    }

    /// Separate from CRYPTO levels: QUIC forbids CRYPTO frames in 0-RTT.
    fn early_status(&self) -> crate::early_data::EarlyStatus {
        crate::early_data::EarlyStatus::Disabled
    }
    fn early_generation(&self) -> Option<u64> {
        None
    }
    fn remembered_early_limits(&self) -> Option<crate::early_data::RememberedLimits> {
        None
    }
    /// Move the server's burned replay claim into its actual receive quarantine.
    fn take_early_replay_claim(&mut self) -> Option<crate::early_data::ReplayClaim> {
        None
    }
    fn has_early_keys(&self) -> bool {
        false
    }
    fn seal_early(
        &mut self,
        _pn: u64,
        _header: &[u8],
        _buffer: &mut [u8],
        _plaintext_len: usize,
    ) -> Result<usize, Error> {
        Err(Error::Unsupported)
    }
    fn open_early(&mut self, _pn: u64, _header: &[u8], _buffer: &mut [u8]) -> Result<usize, Error> {
        Err(Error::Unsupported)
    }
    fn early_header_mask(&self, _local: bool, _sample: &[u8; 16]) -> Result<[u8; 5], Error> {
        Err(Error::Unsupported)
    }
    fn discard_early_keys(&mut self) {}
    /// Input contains contiguous packet-authenticated CRYPTO data, not TLS records.
    fn receive(&mut self, level: Level, bytes: &[u8]) -> Result<(), Error>;
    /// Copy pending handshake bytes, preserving encryption level across fragments.
    fn transmit(&mut self, output: &mut [u8]) -> Result<Option<Output>, Error>;
    fn has_keys(&self, level: Level) -> bool;
    /// Irreversibly retire keys for this encryption level. Subsequent protection
    /// requests at that level must report KeysUnavailable (or equivalent).
    fn discard_keys(&mut self, level: Level);
    fn is_handshaking(&self) -> bool;
    fn peer_transport_parameters(&self) -> Option<&[u8]>;
    /// Provider must enforce its AEAD limits. Input has room for the appended tag.
    fn seal(
        &mut self,
        level: Level,
        pn: u64,
        header: &[u8],
        buffer: &mut [u8],
        plaintext_len: usize,
    ) -> Result<usize, Error>;
    /// Return plaintext length only after successful tag verification. On failure,
    /// no plaintext may be delivered; callers must discard the whole packet.
    fn open(
        &mut self,
        level: Level,
        pn: u64,
        header: &[u8],
        buffer: &mut [u8],
    ) -> Result<usize, Error>;
    /// First returned mask byte needs only low five bits; header form determines
    /// whether the caller applies four or five. Remaining bytes mask PN bytes.
    fn header_mask(&self, level: Level, local: bool, sample: &[u8; 16]) -> Result<[u8; 5], Error>;
    /// Backends without update support retain generation zero and reject phase changes.
    fn negotiated_group(&self) -> Option<u16> {
        None
    }
    fn key_phase(&self) -> bool {
        false
    }
    /// Bounded backends expose the same non-resettable integrity budget used by
    /// Handshake and every application generation, so Initial protection shares
    /// its connection-wide failed-authentication limit. Reference backends may
    /// return None and must not claim this bounded-backend property.
    fn integrity_budget(&mut self) -> Option<&mut crate::crypto::IntegrityBudget> {
        None
    }
    fn receive_key_generation(&self) -> u64 {
        0
    }
    fn key_generation(&self) -> u64 {
        0
    }
    fn confirm_handshake(&mut self) -> Result<(), Error> {
        Ok(())
    }
    fn maintain_keys(&mut self, _now: u64, _pto: u64) -> Result<(), Error> {
        Ok(())
    }
    fn initiate_key_update(&mut self, _now: u64, _pto: u64) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    /// Caller has already validated authenticated ACK ranges against actual sent history.
    fn acknowledge_one_rtt(
        &mut self,
        _sent_pn: u64,
        _received_generation: u64,
        _now: u64,
        _pto: u64,
    ) -> Result<(), Error> {
        Ok(())
    }
    fn open_one_rtt(
        &mut self,
        pn: u64,
        phase: bool,
        header: &[u8],
        buffer: &mut [u8],
        _now: u64,
        _pto: u64,
    ) -> Result<crate::crypto::Opened, Error> {
        if phase {
            return Err(Error::Authentication);
        }
        self.open(Level::OneRtt, pn, header, buffer)
            .map(|len| crate::crypto::Opened {
                len,
                generation: 0,
                key_updated: false,
            })
    }
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;
    use core::fmt::Write;
    #[test]
    fn bounded_utf8_diagnostic_never_splits_a_codepoint_and_stops_at_first_truncation() {
        let mut diagnostic = FailureDiagnostic::empty();
        for _ in 0..191 {
            diagnostic.write_str("a").unwrap();
        }
        diagnostic.write_str("é remaining").unwrap();
        diagnostic.write_str("x").unwrap();
        assert_eq!(diagnostic.as_str().len(), 191);
        assert!(diagnostic.truncated());
        assert!(!diagnostic.format_error());
    }
    #[test]
    fn exact_capacity_ascii_and_multibyte_diagnostics_remain_complete() {
        let mut diagnostic = FailureDiagnostic::empty();
        for _ in 0..64 {
            diagnostic.write_str("雪").unwrap();
        }
        assert_eq!(diagnostic.as_str().len(), FAILURE_DIAGNOSTIC_BYTES);
        assert!(!diagnostic.truncated());
        diagnostic.write_str("").unwrap();
        assert!(!diagnostic.truncated());
        diagnostic.write_str("x").unwrap();
        assert!(diagnostic.truncated());
    }
}

// Protocol roles and numerical/cryptographic mechanisms have separate modules.
pub mod certificate;
pub mod handshake;
pub mod rsa;
pub mod schedule;
pub mod ticket;
pub mod wire;
