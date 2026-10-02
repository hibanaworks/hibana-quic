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

/// Owned by one endpoint. Its allocation policy is part of the release identity:
/// implementing this trait does not establish no_alloc. The host reference backend
/// explicitly allocates. A release backend must use caller-owned bounded storage.
pub trait Provider {
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
