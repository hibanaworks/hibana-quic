//! Staged control for the whole TLS Provider owner.
//!
//! Each work scope has phase-specific request and result selectors. An actual
//! owner crypto operation emits its typed binary outcome. The client observes
//! that label and acknowledges OutcomeSeen without taking the output slot. The
//! owner then emits PhaseUnchanged or Prepared. ResultTaken transfers the output
//! slot, and the owner then emits a grant outside that rolled work scope. Grants
//! authorize
//! the next local async continuation; an observation of available keys does not.
//!
//! The owner must send ApplicationTrafficPrepared only when 1-RTT keys exist
//! AND TLS is no longer handshaking. A server can derive those keys before it
//! authenticates the client's Finished, so key availability alone is insufficient.
//!
//! The vendored elastic-roll continuations do not seal old reentry. Sequential role
//! continuations and consumed private capabilities enforce past-phase finality
//! in the production `tls_owner` locals. The Provider moves by value between
//! those capabilities, and the obsolete `protocol_tls` path re-exports this
//! graph; there is no independent flat or universal owner implementation. At a
//! boundary use the already-announced grant's direct recv, not offer at a roll
//! tail (which previews the old phase). No phase enum or generic event exists.
use hibana::{
    g,
    runtime::program::{RoleProgram, project},
};

pub const TLS_CLIENT: u8 = 24;
pub const TLS_OWNER: u8 = 25;

/// Selectors belonging only to the initial continuation.
pub mod initial {
    use hibana::g;
    pub const CRYPTO_INPUT: u8 = 0;
    pub type CryptoInput = g::Msg<{ CRYPTO_INPUT }, [u8; 16]>;
    pub const FLIGHT_REQUESTED: u8 = 1;
    pub type CryptoFlightRequested = g::Msg<{ FLIGHT_REQUESTED }, [u8; 16]>;
    pub const OPEN_EARLY: u8 = 2;
    pub type OpenEarly = g::Msg<{ OPEN_EARLY }, [u8; 16]>;
    pub const SEAL_EARLY: u8 = 3;
    pub type SealEarly = g::Msg<{ SEAL_EARLY }, [u8; 16]>;
    pub const EARLY_HEADER_MASK: u8 = 4;
    pub type EarlyHeaderMask = g::Msg<{ EARLY_HEADER_MASK }, [u8; 16]>;
    pub const TAKE_EARLY_REPLAY_CLAIM: u8 = 5;
    pub type TakeEarlyReplayClaim = g::Msg<{ TAKE_EARLY_REPLAY_CLAIM }, [u8; 16]>;
    pub const DISCARD_EARLY: u8 = 6;
    pub type DiscardEarly = g::Msg<{ DISCARD_EARLY }, [u8; 16]>;
    pub const MAINTAIN_KEYS: u8 = 15;
    pub type MaintainKeys = g::Msg<{ MAINTAIN_KEYS }, [u8; 16]>;
    pub const LOAN_INTEGRITY: u8 = 18;
    pub type LoanIntegrity = g::Msg<{ LOAN_INTEGRITY }, [u8; 16]>;
    pub const RETIRE_REQUESTED: u8 = 19;
    pub type RetireRequested = g::Msg<{ RETIRE_REQUESTED }, [u8; 16]>;
    pub const CRYPTO_ACCEPTED: u8 = 7;
    pub type CryptoAccepted = g::Msg<{ CRYPTO_ACCEPTED }, [u8; 16]>;
    pub const CRYPTO_REJECTED: u8 = 8;
    pub type CryptoRejected = g::Msg<{ CRYPTO_REJECTED }, [u8; 16]>;
    pub const FLIGHT_READY: u8 = 9;
    pub type FlightReady = g::Msg<{ FLIGHT_READY }, [u8; 16]>;
    pub const AWAIT_INPUT: u8 = 10;
    pub type AwaitInput = g::Msg<{ AWAIT_INPUT }, [u8; 16]>;
    pub const EARLY_OPENED: u8 = 11;
    pub type EarlyOpened = g::Msg<{ EARLY_OPENED }, [u8; 16]>;
    pub const EARLY_OPEN_REJECTED: u8 = 12;
    pub type EarlyOpenRejected = g::Msg<{ EARLY_OPEN_REJECTED }, [u8; 16]>;
    pub const EARLY_SEALED: u8 = 13;
    pub type EarlySealed = g::Msg<{ EARLY_SEALED }, [u8; 16]>;
    pub const EARLY_SEAL_REJECTED: u8 = 14;
    pub type EarlySealRejected = g::Msg<{ EARLY_SEAL_REJECTED }, [u8; 16]>;
    pub const HEADER_MASK_READY: u8 = 16;
    pub type HeaderMaskReady = g::Msg<{ HEADER_MASK_READY }, [u8; 16]>;
    pub const HEADER_MASK_REJECTED: u8 = 17;
    pub type HeaderMaskRejected = g::Msg<{ HEADER_MASK_REJECTED }, [u8; 16]>;
    pub const EARLY_REPLAY_CLAIM_READY: u8 = 20;
    pub type EarlyReplayClaimReady = g::Msg<{ EARLY_REPLAY_CLAIM_READY }, [u8; 16]>;
    pub const NO_EARLY_REPLAY_CLAIM: u8 = 21;
    pub type NoEarlyReplayClaim = g::Msg<{ NO_EARLY_REPLAY_CLAIM }, [u8; 16]>;
    pub const EARLY_DISCARDED: u8 = 22;
    pub type EarlyDiscarded = g::Msg<{ EARLY_DISCARDED }, [u8; 16]>;
    pub const KEYS_MAINTAINED: u8 = 23;
    pub type KeysMaintained = g::Msg<{ KEYS_MAINTAINED }, [u8; 16]>;
    pub const MAINTENANCE_REJECTED: u8 = 24;
    pub type MaintenanceRejected = g::Msg<{ MAINTENANCE_REJECTED }, [u8; 16]>;
    pub const INTEGRITY_GRANTED: u8 = 25;
    pub type IntegrityGranted = g::Msg<{ INTEGRITY_GRANTED }, [u8; 16]>;
    pub const LOAN_UNAVAILABLE: u8 = 26;
    pub type LoanUnavailable = g::Msg<{ LOAN_UNAVAILABLE }, [u8; 16]>;
    pub const INTEGRITY_RETURNED: u8 = 27;
    pub type IntegrityReturned = g::Msg<{ INTEGRITY_RETURNED }, [u8; 16]>;
    pub const INTEGRITY_RESTORED: u8 = 28;
    pub type IntegrityRestored = g::Msg<{ INTEGRITY_RESTORED }, [u8; 16]>;
    pub const RETIREMENT_PREPARED: u8 = 29;
    pub type RetirementPrepared = g::Msg<{ RETIREMENT_PREPARED }, [u8; 16]>;
    pub const RESULT_TAKEN: u8 = 30;
    pub type ResultTaken = g::Msg<{ RESULT_TAKEN }, [u8; 16]>;
    pub const RETIRED: u8 = 31;
    pub type Retired = g::Msg<{ RETIRED }, [u8; 16]>;
    pub const RETIREMENT_ACKNOWLEDGED: u8 = 160;
    pub type RetirementAcknowledged = g::Msg<{ RETIREMENT_ACKNOWLEDGED }, [u8; 16]>;
    pub const HANDSHAKE_KEYS_PREPARED: u8 = 161;
    pub type HandshakeKeysPrepared = g::Msg<{ HANDSHAKE_KEYS_PREPARED }, [u8; 16]>;
    pub const PHASE_UNCHANGED: u8 = 162;
    pub type PhaseUnchanged = g::Msg<{ PHASE_UNCHANGED }, [u8; 16]>;
    pub const OUTCOME_SEEN: u8 = 163;
    pub type OutcomeSeen = g::Msg<{ OUTCOME_SEEN }, [u8; 16]>;
}

/// Selectors belonging only to the handshake continuation.
pub mod handshake {
    use hibana::g;
    pub const CRYPTO_INPUT: u8 = 32;
    pub type CryptoInput = g::Msg<{ CRYPTO_INPUT }, [u8; 16]>;
    pub const FLIGHT_REQUESTED: u8 = 33;
    pub type CryptoFlightRequested = g::Msg<{ FLIGHT_REQUESTED }, [u8; 16]>;
    pub const OPEN_EARLY: u8 = 34;
    pub type OpenEarly = g::Msg<{ OPEN_EARLY }, [u8; 16]>;
    pub const SEAL_EARLY: u8 = 35;
    pub type SealEarly = g::Msg<{ SEAL_EARLY }, [u8; 16]>;
    pub const EARLY_HEADER_MASK: u8 = 36;
    pub type EarlyHeaderMask = g::Msg<{ EARLY_HEADER_MASK }, [u8; 16]>;
    pub const TAKE_EARLY_REPLAY_CLAIM: u8 = 37;
    pub type TakeEarlyReplayClaim = g::Msg<{ TAKE_EARLY_REPLAY_CLAIM }, [u8; 16]>;
    pub const DISCARD_EARLY: u8 = 38;
    pub type DiscardEarly = g::Msg<{ DISCARD_EARLY }, [u8; 16]>;
    pub const OPEN_HANDSHAKE: u8 = 39;
    pub type OpenHandshake = g::Msg<{ OPEN_HANDSHAKE }, [u8; 16]>;
    pub const SEAL_HANDSHAKE: u8 = 40;
    pub type SealHandshake = g::Msg<{ SEAL_HANDSHAKE }, [u8; 16]>;
    pub const HANDSHAKE_HEADER_MASK: u8 = 41;
    pub type HandshakeHeaderMask = g::Msg<{ HANDSHAKE_HEADER_MASK }, [u8; 16]>;
    pub const MAINTAIN_KEYS: u8 = 47;
    pub type MaintainKeys = g::Msg<{ MAINTAIN_KEYS }, [u8; 16]>;
    pub const LOAN_INTEGRITY: u8 = 50;
    pub type LoanIntegrity = g::Msg<{ LOAN_INTEGRITY }, [u8; 16]>;
    pub const RETIRE_REQUESTED: u8 = 51;
    pub type RetireRequested = g::Msg<{ RETIRE_REQUESTED }, [u8; 16]>;
    pub const CRYPTO_ACCEPTED: u8 = 42;
    pub type CryptoAccepted = g::Msg<{ CRYPTO_ACCEPTED }, [u8; 16]>;
    pub const CRYPTO_REJECTED: u8 = 43;
    pub type CryptoRejected = g::Msg<{ CRYPTO_REJECTED }, [u8; 16]>;
    pub const FLIGHT_READY: u8 = 44;
    pub type FlightReady = g::Msg<{ FLIGHT_READY }, [u8; 16]>;
    pub const AWAIT_INPUT: u8 = 45;
    pub type AwaitInput = g::Msg<{ AWAIT_INPUT }, [u8; 16]>;
    pub const EARLY_OPENED: u8 = 46;
    pub type EarlyOpened = g::Msg<{ EARLY_OPENED }, [u8; 16]>;
    pub const EARLY_OPEN_REJECTED: u8 = 48;
    pub type EarlyOpenRejected = g::Msg<{ EARLY_OPEN_REJECTED }, [u8; 16]>;
    pub const EARLY_SEALED: u8 = 49;
    pub type EarlySealed = g::Msg<{ EARLY_SEALED }, [u8; 16]>;
    pub const EARLY_SEAL_REJECTED: u8 = 52;
    pub type EarlySealRejected = g::Msg<{ EARLY_SEAL_REJECTED }, [u8; 16]>;
    pub const HEADER_MASK_READY: u8 = 53;
    pub type HeaderMaskReady = g::Msg<{ HEADER_MASK_READY }, [u8; 16]>;
    pub const HEADER_MASK_REJECTED: u8 = 54;
    pub type HeaderMaskRejected = g::Msg<{ HEADER_MASK_REJECTED }, [u8; 16]>;
    pub const EARLY_REPLAY_CLAIM_READY: u8 = 55;
    pub type EarlyReplayClaimReady = g::Msg<{ EARLY_REPLAY_CLAIM_READY }, [u8; 16]>;
    pub const NO_EARLY_REPLAY_CLAIM: u8 = 56;
    pub type NoEarlyReplayClaim = g::Msg<{ NO_EARLY_REPLAY_CLAIM }, [u8; 16]>;
    pub const EARLY_DISCARDED: u8 = 57;
    pub type EarlyDiscarded = g::Msg<{ EARLY_DISCARDED }, [u8; 16]>;
    pub const HANDSHAKE_OPENED: u8 = 58;
    pub type HandshakeOpened = g::Msg<{ HANDSHAKE_OPENED }, [u8; 16]>;
    pub const HANDSHAKE_OPEN_REJECTED: u8 = 59;
    pub type HandshakeOpenRejected = g::Msg<{ HANDSHAKE_OPEN_REJECTED }, [u8; 16]>;
    pub const HANDSHAKE_SEALED: u8 = 60;
    pub type HandshakeSealed = g::Msg<{ HANDSHAKE_SEALED }, [u8; 16]>;
    pub const HANDSHAKE_SEAL_REJECTED: u8 = 61;
    pub type HandshakeSealRejected = g::Msg<{ HANDSHAKE_SEAL_REJECTED }, [u8; 16]>;
    pub const KEYS_MAINTAINED: u8 = 62;
    pub type KeysMaintained = g::Msg<{ KEYS_MAINTAINED }, [u8; 16]>;
    pub const MAINTENANCE_REJECTED: u8 = 63;
    pub type MaintenanceRejected = g::Msg<{ MAINTENANCE_REJECTED }, [u8; 16]>;
    pub const INTEGRITY_GRANTED: u8 = 164;
    pub type IntegrityGranted = g::Msg<{ INTEGRITY_GRANTED }, [u8; 16]>;
    pub const LOAN_UNAVAILABLE: u8 = 165;
    pub type LoanUnavailable = g::Msg<{ LOAN_UNAVAILABLE }, [u8; 16]>;
    pub const INTEGRITY_RETURNED: u8 = 166;
    pub type IntegrityReturned = g::Msg<{ INTEGRITY_RETURNED }, [u8; 16]>;
    pub const INTEGRITY_RESTORED: u8 = 167;
    pub type IntegrityRestored = g::Msg<{ INTEGRITY_RESTORED }, [u8; 16]>;
    pub const RETIREMENT_PREPARED: u8 = 168;
    pub type RetirementPrepared = g::Msg<{ RETIREMENT_PREPARED }, [u8; 16]>;
    pub const RESULT_TAKEN: u8 = 169;
    pub type ResultTaken = g::Msg<{ RESULT_TAKEN }, [u8; 16]>;
    pub const RETIRED: u8 = 170;
    pub type Retired = g::Msg<{ RETIRED }, [u8; 16]>;
    pub const RETIREMENT_ACKNOWLEDGED: u8 = 171;
    pub type RetirementAcknowledged = g::Msg<{ RETIREMENT_ACKNOWLEDGED }, [u8; 16]>;
    pub const APPLICATION_TRAFFIC_PREPARED: u8 = 172;
    pub type ApplicationTrafficPrepared = g::Msg<{ APPLICATION_TRAFFIC_PREPARED }, [u8; 16]>;
    pub const PHASE_UNCHANGED: u8 = 173;
    pub type PhaseUnchanged = g::Msg<{ PHASE_UNCHANGED }, [u8; 16]>;
    pub const OUTCOME_SEEN: u8 = 174;
    pub type OutcomeSeen = g::Msg<{ OUTCOME_SEEN }, [u8; 16]>;
}

/// Selectors belonging only to the unconfirmed continuation.
pub mod unconfirmed {
    use hibana::g;
    pub const CRYPTO_INPUT: u8 = 64;
    pub type CryptoInput = g::Msg<{ CRYPTO_INPUT }, [u8; 16]>;
    pub const FLIGHT_REQUESTED: u8 = 65;
    pub type CryptoFlightRequested = g::Msg<{ FLIGHT_REQUESTED }, [u8; 16]>;
    pub const OPEN_EARLY: u8 = 66;
    pub type OpenEarly = g::Msg<{ OPEN_EARLY }, [u8; 16]>;
    pub const SEAL_EARLY: u8 = 67;
    pub type SealEarly = g::Msg<{ SEAL_EARLY }, [u8; 16]>;
    pub const EARLY_HEADER_MASK: u8 = 68;
    pub type EarlyHeaderMask = g::Msg<{ EARLY_HEADER_MASK }, [u8; 16]>;
    pub const TAKE_EARLY_REPLAY_CLAIM: u8 = 69;
    pub type TakeEarlyReplayClaim = g::Msg<{ TAKE_EARLY_REPLAY_CLAIM }, [u8; 16]>;
    pub const DISCARD_EARLY: u8 = 70;
    pub type DiscardEarly = g::Msg<{ DISCARD_EARLY }, [u8; 16]>;
    pub const OPEN_HANDSHAKE: u8 = 71;
    pub type OpenHandshake = g::Msg<{ OPEN_HANDSHAKE }, [u8; 16]>;
    pub const SEAL_HANDSHAKE: u8 = 72;
    pub type SealHandshake = g::Msg<{ SEAL_HANDSHAKE }, [u8; 16]>;
    pub const HANDSHAKE_HEADER_MASK: u8 = 73;
    pub type HandshakeHeaderMask = g::Msg<{ HANDSHAKE_HEADER_MASK }, [u8; 16]>;
    pub const OPEN_ONE_RTT: u8 = 74;
    pub type OpenOneRtt = g::Msg<{ OPEN_ONE_RTT }, [u8; 16]>;
    pub const SEAL_ONE_RTT: u8 = 75;
    pub type SealOneRtt = g::Msg<{ SEAL_ONE_RTT }, [u8; 16]>;
    pub const ONE_RTT_HEADER_MASK: u8 = 76;
    pub type OneRttHeaderMask = g::Msg<{ ONE_RTT_HEADER_MASK }, [u8; 16]>;
    pub const CONFIRM_HANDSHAKE: u8 = 77;
    pub type ConfirmHandshake = g::Msg<{ CONFIRM_HANDSHAKE }, [u8; 16]>;
    pub const VALIDATED_ACK: u8 = 78;
    pub type ValidatedAck = g::Msg<{ VALIDATED_ACK }, [u8; 16]>;
    pub const MAINTAIN_KEYS: u8 = 79;
    pub type MaintainKeys = g::Msg<{ MAINTAIN_KEYS }, [u8; 16]>;
    pub const LOAN_INTEGRITY: u8 = 82;
    pub type LoanIntegrity = g::Msg<{ LOAN_INTEGRITY }, [u8; 16]>;
    pub const RETIRE_REQUESTED: u8 = 83;
    pub type RetireRequested = g::Msg<{ RETIRE_REQUESTED }, [u8; 16]>;
    pub const CRYPTO_ACCEPTED: u8 = 80;
    pub type CryptoAccepted = g::Msg<{ CRYPTO_ACCEPTED }, [u8; 16]>;
    pub const CRYPTO_REJECTED: u8 = 81;
    pub type CryptoRejected = g::Msg<{ CRYPTO_REJECTED }, [u8; 16]>;
    pub const FLIGHT_READY: u8 = 84;
    pub type FlightReady = g::Msg<{ FLIGHT_READY }, [u8; 16]>;
    pub const AWAIT_INPUT: u8 = 85;
    pub type AwaitInput = g::Msg<{ AWAIT_INPUT }, [u8; 16]>;
    pub const EARLY_OPENED: u8 = 86;
    pub type EarlyOpened = g::Msg<{ EARLY_OPENED }, [u8; 16]>;
    pub const EARLY_OPEN_REJECTED: u8 = 87;
    pub type EarlyOpenRejected = g::Msg<{ EARLY_OPEN_REJECTED }, [u8; 16]>;
    pub const EARLY_SEALED: u8 = 88;
    pub type EarlySealed = g::Msg<{ EARLY_SEALED }, [u8; 16]>;
    pub const EARLY_SEAL_REJECTED: u8 = 89;
    pub type EarlySealRejected = g::Msg<{ EARLY_SEAL_REJECTED }, [u8; 16]>;
    pub const HEADER_MASK_READY: u8 = 90;
    pub type HeaderMaskReady = g::Msg<{ HEADER_MASK_READY }, [u8; 16]>;
    pub const HEADER_MASK_REJECTED: u8 = 91;
    pub type HeaderMaskRejected = g::Msg<{ HEADER_MASK_REJECTED }, [u8; 16]>;
    pub const EARLY_REPLAY_CLAIM_READY: u8 = 92;
    pub type EarlyReplayClaimReady = g::Msg<{ EARLY_REPLAY_CLAIM_READY }, [u8; 16]>;
    pub const NO_EARLY_REPLAY_CLAIM: u8 = 93;
    pub type NoEarlyReplayClaim = g::Msg<{ NO_EARLY_REPLAY_CLAIM }, [u8; 16]>;
    pub const EARLY_DISCARDED: u8 = 94;
    pub type EarlyDiscarded = g::Msg<{ EARLY_DISCARDED }, [u8; 16]>;
    pub const HANDSHAKE_OPENED: u8 = 95;
    pub type HandshakeOpened = g::Msg<{ HANDSHAKE_OPENED }, [u8; 16]>;
    pub const HANDSHAKE_OPEN_REJECTED: u8 = 175;
    pub type HandshakeOpenRejected = g::Msg<{ HANDSHAKE_OPEN_REJECTED }, [u8; 16]>;
    pub const HANDSHAKE_SEALED: u8 = 176;
    pub type HandshakeSealed = g::Msg<{ HANDSHAKE_SEALED }, [u8; 16]>;
    pub const HANDSHAKE_SEAL_REJECTED: u8 = 177;
    pub type HandshakeSealRejected = g::Msg<{ HANDSHAKE_SEAL_REJECTED }, [u8; 16]>;
    pub const ONE_RTT_OPENED: u8 = 178;
    pub type OneRttOpened = g::Msg<{ ONE_RTT_OPENED }, [u8; 16]>;
    pub const ONE_RTT_OPEN_REJECTED: u8 = 179;
    pub type OneRttOpenRejected = g::Msg<{ ONE_RTT_OPEN_REJECTED }, [u8; 16]>;
    pub const ONE_RTT_SEALED: u8 = 180;
    pub type OneRttSealed = g::Msg<{ ONE_RTT_SEALED }, [u8; 16]>;
    pub const ONE_RTT_SEAL_REJECTED: u8 = 181;
    pub type OneRttSealRejected = g::Msg<{ ONE_RTT_SEAL_REJECTED }, [u8; 16]>;
    pub const HANDSHAKE_CONFIRMED: u8 = 182;
    pub type HandshakeConfirmed = g::Msg<{ HANDSHAKE_CONFIRMED }, [u8; 16]>;
    pub const CONFIRMATION_REJECTED: u8 = 183;
    pub type ConfirmationRejected = g::Msg<{ CONFIRMATION_REJECTED }, [u8; 16]>;
    pub const ACK_APPLIED: u8 = 184;
    pub type AckApplied = g::Msg<{ ACK_APPLIED }, [u8; 16]>;
    pub const ACK_REJECTED: u8 = 185;
    pub type AckRejected = g::Msg<{ ACK_REJECTED }, [u8; 16]>;
    pub const KEYS_MAINTAINED: u8 = 186;
    pub type KeysMaintained = g::Msg<{ KEYS_MAINTAINED }, [u8; 16]>;
    pub const MAINTENANCE_REJECTED: u8 = 187;
    pub type MaintenanceRejected = g::Msg<{ MAINTENANCE_REJECTED }, [u8; 16]>;
    pub const INTEGRITY_GRANTED: u8 = 188;
    pub type IntegrityGranted = g::Msg<{ INTEGRITY_GRANTED }, [u8; 16]>;
    pub const LOAN_UNAVAILABLE: u8 = 189;
    pub type LoanUnavailable = g::Msg<{ LOAN_UNAVAILABLE }, [u8; 16]>;
    pub const INTEGRITY_RETURNED: u8 = 190;
    pub type IntegrityReturned = g::Msg<{ INTEGRITY_RETURNED }, [u8; 16]>;
    pub const INTEGRITY_RESTORED: u8 = 191;
    pub type IntegrityRestored = g::Msg<{ INTEGRITY_RESTORED }, [u8; 16]>;
    pub const RETIREMENT_PREPARED: u8 = 192;
    pub type RetirementPrepared = g::Msg<{ RETIREMENT_PREPARED }, [u8; 16]>;
    pub const RESULT_TAKEN: u8 = 193;
    pub type ResultTaken = g::Msg<{ RESULT_TAKEN }, [u8; 16]>;
    pub const RETIRED: u8 = 194;
    pub type Retired = g::Msg<{ RETIRED }, [u8; 16]>;
    pub const RETIREMENT_ACKNOWLEDGED: u8 = 195;
    pub type RetirementAcknowledged = g::Msg<{ RETIREMENT_ACKNOWLEDGED }, [u8; 16]>;
}

/// Selectors belonging only to the confirmed continuation.
pub mod confirmed {
    use hibana::g;
    pub const CRYPTO_INPUT: u8 = 96;
    pub type CryptoInput = g::Msg<{ CRYPTO_INPUT }, [u8; 16]>;
    pub const FLIGHT_REQUESTED: u8 = 97;
    pub type CryptoFlightRequested = g::Msg<{ FLIGHT_REQUESTED }, [u8; 16]>;
    pub const OPEN_EARLY: u8 = 98;
    pub type OpenEarly = g::Msg<{ OPEN_EARLY }, [u8; 16]>;
    pub const SEAL_EARLY: u8 = 99;
    pub type SealEarly = g::Msg<{ SEAL_EARLY }, [u8; 16]>;
    pub const EARLY_HEADER_MASK: u8 = 100;
    pub type EarlyHeaderMask = g::Msg<{ EARLY_HEADER_MASK }, [u8; 16]>;
    pub const TAKE_EARLY_REPLAY_CLAIM: u8 = 101;
    pub type TakeEarlyReplayClaim = g::Msg<{ TAKE_EARLY_REPLAY_CLAIM }, [u8; 16]>;
    pub const DISCARD_EARLY: u8 = 102;
    pub type DiscardEarly = g::Msg<{ DISCARD_EARLY }, [u8; 16]>;
    pub const OPEN_HANDSHAKE: u8 = 103;
    pub type OpenHandshake = g::Msg<{ OPEN_HANDSHAKE }, [u8; 16]>;
    pub const SEAL_HANDSHAKE: u8 = 104;
    pub type SealHandshake = g::Msg<{ SEAL_HANDSHAKE }, [u8; 16]>;
    pub const HANDSHAKE_HEADER_MASK: u8 = 105;
    pub type HandshakeHeaderMask = g::Msg<{ HANDSHAKE_HEADER_MASK }, [u8; 16]>;
    pub const OPEN_ONE_RTT: u8 = 106;
    pub type OpenOneRtt = g::Msg<{ OPEN_ONE_RTT }, [u8; 16]>;
    pub const SEAL_ONE_RTT: u8 = 107;
    pub type SealOneRtt = g::Msg<{ SEAL_ONE_RTT }, [u8; 16]>;
    pub const ONE_RTT_HEADER_MASK: u8 = 108;
    pub type OneRttHeaderMask = g::Msg<{ ONE_RTT_HEADER_MASK }, [u8; 16]>;
    pub const VALIDATED_ACK: u8 = 110;
    pub type ValidatedAck = g::Msg<{ VALIDATED_ACK }, [u8; 16]>;
    pub const MAINTAIN_KEYS: u8 = 111;
    pub type MaintainKeys = g::Msg<{ MAINTAIN_KEYS }, [u8; 16]>;
    pub const INITIATE_UPDATE: u8 = 112;
    pub type InitiateUpdate = g::Msg<{ INITIATE_UPDATE }, [u8; 16]>;
    pub const DISCARD_HANDSHAKE: u8 = 113;
    pub type DiscardHandshake = g::Msg<{ DISCARD_HANDSHAKE }, [u8; 16]>;
    pub const LOAN_INTEGRITY: u8 = 114;
    pub type LoanIntegrity = g::Msg<{ LOAN_INTEGRITY }, [u8; 16]>;
    pub const RETIRE_REQUESTED: u8 = 115;
    pub type RetireRequested = g::Msg<{ RETIRE_REQUESTED }, [u8; 16]>;
    pub const CRYPTO_ACCEPTED: u8 = 109;
    pub type CryptoAccepted = g::Msg<{ CRYPTO_ACCEPTED }, [u8; 16]>;
    pub const CRYPTO_REJECTED: u8 = 116;
    pub type CryptoRejected = g::Msg<{ CRYPTO_REJECTED }, [u8; 16]>;
    pub const FLIGHT_READY: u8 = 117;
    pub type FlightReady = g::Msg<{ FLIGHT_READY }, [u8; 16]>;
    pub const AWAIT_INPUT: u8 = 118;
    pub type AwaitInput = g::Msg<{ AWAIT_INPUT }, [u8; 16]>;
    pub const EARLY_OPENED: u8 = 119;
    pub type EarlyOpened = g::Msg<{ EARLY_OPENED }, [u8; 16]>;
    pub const EARLY_OPEN_REJECTED: u8 = 120;
    pub type EarlyOpenRejected = g::Msg<{ EARLY_OPEN_REJECTED }, [u8; 16]>;
    pub const EARLY_SEALED: u8 = 121;
    pub type EarlySealed = g::Msg<{ EARLY_SEALED }, [u8; 16]>;
    pub const EARLY_SEAL_REJECTED: u8 = 122;
    pub type EarlySealRejected = g::Msg<{ EARLY_SEAL_REJECTED }, [u8; 16]>;
    pub const HEADER_MASK_READY: u8 = 123;
    pub type HeaderMaskReady = g::Msg<{ HEADER_MASK_READY }, [u8; 16]>;
    pub const HEADER_MASK_REJECTED: u8 = 124;
    pub type HeaderMaskRejected = g::Msg<{ HEADER_MASK_REJECTED }, [u8; 16]>;
    pub const EARLY_REPLAY_CLAIM_READY: u8 = 125;
    pub type EarlyReplayClaimReady = g::Msg<{ EARLY_REPLAY_CLAIM_READY }, [u8; 16]>;
    pub const NO_EARLY_REPLAY_CLAIM: u8 = 126;
    pub type NoEarlyReplayClaim = g::Msg<{ NO_EARLY_REPLAY_CLAIM }, [u8; 16]>;
    pub const EARLY_DISCARDED: u8 = 127;
    pub type EarlyDiscarded = g::Msg<{ EARLY_DISCARDED }, [u8; 16]>;
    pub const HANDSHAKE_OPENED: u8 = 196;
    pub type HandshakeOpened = g::Msg<{ HANDSHAKE_OPENED }, [u8; 16]>;
    pub const HANDSHAKE_OPEN_REJECTED: u8 = 197;
    pub type HandshakeOpenRejected = g::Msg<{ HANDSHAKE_OPEN_REJECTED }, [u8; 16]>;
    pub const HANDSHAKE_SEALED: u8 = 198;
    pub type HandshakeSealed = g::Msg<{ HANDSHAKE_SEALED }, [u8; 16]>;
    pub const HANDSHAKE_SEAL_REJECTED: u8 = 199;
    pub type HandshakeSealRejected = g::Msg<{ HANDSHAKE_SEAL_REJECTED }, [u8; 16]>;
    pub const ONE_RTT_OPENED: u8 = 200;
    pub type OneRttOpened = g::Msg<{ ONE_RTT_OPENED }, [u8; 16]>;
    pub const ONE_RTT_OPEN_REJECTED: u8 = 201;
    pub type OneRttOpenRejected = g::Msg<{ ONE_RTT_OPEN_REJECTED }, [u8; 16]>;
    pub const ONE_RTT_SEALED: u8 = 202;
    pub type OneRttSealed = g::Msg<{ ONE_RTT_SEALED }, [u8; 16]>;
    pub const ONE_RTT_SEAL_REJECTED: u8 = 203;
    pub type OneRttSealRejected = g::Msg<{ ONE_RTT_SEAL_REJECTED }, [u8; 16]>;
    pub const ACK_APPLIED: u8 = 204;
    pub type AckApplied = g::Msg<{ ACK_APPLIED }, [u8; 16]>;
    pub const ACK_REJECTED: u8 = 205;
    pub type AckRejected = g::Msg<{ ACK_REJECTED }, [u8; 16]>;
    pub const KEYS_MAINTAINED: u8 = 206;
    pub type KeysMaintained = g::Msg<{ KEYS_MAINTAINED }, [u8; 16]>;
    pub const MAINTENANCE_REJECTED: u8 = 207;
    pub type MaintenanceRejected = g::Msg<{ MAINTENANCE_REJECTED }, [u8; 16]>;
    pub const KEY_UPDATED: u8 = 208;
    pub type KeyUpdated = g::Msg<{ KEY_UPDATED }, [u8; 16]>;
    pub const UPDATE_REJECTED: u8 = 209;
    pub type UpdateRejected = g::Msg<{ UPDATE_REJECTED }, [u8; 16]>;
    pub const HANDSHAKE_DISCARDED: u8 = 210;
    pub type HandshakeDiscarded = g::Msg<{ HANDSHAKE_DISCARDED }, [u8; 16]>;
    pub const INTEGRITY_GRANTED: u8 = 211;
    pub type IntegrityGranted = g::Msg<{ INTEGRITY_GRANTED }, [u8; 16]>;
    pub const LOAN_UNAVAILABLE: u8 = 212;
    pub type LoanUnavailable = g::Msg<{ LOAN_UNAVAILABLE }, [u8; 16]>;
    pub const INTEGRITY_RETURNED: u8 = 213;
    pub type IntegrityReturned = g::Msg<{ INTEGRITY_RETURNED }, [u8; 16]>;
    pub const INTEGRITY_RESTORED: u8 = 214;
    pub type IntegrityRestored = g::Msg<{ INTEGRITY_RESTORED }, [u8; 16]>;
    pub const RETIREMENT_PREPARED: u8 = 215;
    pub type RetirementPrepared = g::Msg<{ RETIREMENT_PREPARED }, [u8; 16]>;
    pub const RESULT_TAKEN: u8 = 216;
    pub type ResultTaken = g::Msg<{ RESULT_TAKEN }, [u8; 16]>;
    pub const RETIRED: u8 = 217;
    pub type Retired = g::Msg<{ RETIRED }, [u8; 16]>;
    pub const RETIREMENT_ACKNOWLEDGED: u8 = 218;
    pub type RetirementAcknowledged = g::Msg<{ RETIREMENT_ACKNOWLEDGED }, [u8; 16]>;
}

/// Selectors belonging only to the application continuation.
pub mod application {
    use hibana::g;
    pub const CRYPTO_INPUT: u8 = 128;
    pub type CryptoInput = g::Msg<{ CRYPTO_INPUT }, [u8; 16]>;
    pub const FLIGHT_REQUESTED: u8 = 129;
    pub type CryptoFlightRequested = g::Msg<{ FLIGHT_REQUESTED }, [u8; 16]>;
    pub const OPEN_ONE_RTT: u8 = 138;
    pub type OpenOneRtt = g::Msg<{ OPEN_ONE_RTT }, [u8; 16]>;
    pub const SEAL_ONE_RTT: u8 = 139;
    pub type SealOneRtt = g::Msg<{ SEAL_ONE_RTT }, [u8; 16]>;
    pub const ONE_RTT_HEADER_MASK: u8 = 140;
    pub type OneRttHeaderMask = g::Msg<{ ONE_RTT_HEADER_MASK }, [u8; 16]>;
    pub const VALIDATED_ACK: u8 = 142;
    pub type ValidatedAck = g::Msg<{ VALIDATED_ACK }, [u8; 16]>;
    pub const MAINTAIN_KEYS: u8 = 143;
    pub type MaintainKeys = g::Msg<{ MAINTAIN_KEYS }, [u8; 16]>;
    pub const INITIATE_UPDATE: u8 = 144;
    pub type InitiateUpdate = g::Msg<{ INITIATE_UPDATE }, [u8; 16]>;
    pub const LOAN_INTEGRITY: u8 = 146;
    pub type LoanIntegrity = g::Msg<{ LOAN_INTEGRITY }, [u8; 16]>;
    pub const RETIRE_REQUESTED: u8 = 147;
    pub type RetireRequested = g::Msg<{ RETIRE_REQUESTED }, [u8; 16]>;
    pub const CRYPTO_ACCEPTED: u8 = 130;
    pub type CryptoAccepted = g::Msg<{ CRYPTO_ACCEPTED }, [u8; 16]>;
    pub const CRYPTO_REJECTED: u8 = 131;
    pub type CryptoRejected = g::Msg<{ CRYPTO_REJECTED }, [u8; 16]>;
    pub const FLIGHT_READY: u8 = 132;
    pub type FlightReady = g::Msg<{ FLIGHT_READY }, [u8; 16]>;
    pub const AWAIT_INPUT: u8 = 133;
    pub type AwaitInput = g::Msg<{ AWAIT_INPUT }, [u8; 16]>;
    pub const ONE_RTT_OPENED: u8 = 134;
    pub type OneRttOpened = g::Msg<{ ONE_RTT_OPENED }, [u8; 16]>;
    pub const ONE_RTT_OPEN_REJECTED: u8 = 135;
    pub type OneRttOpenRejected = g::Msg<{ ONE_RTT_OPEN_REJECTED }, [u8; 16]>;
    pub const ONE_RTT_SEALED: u8 = 136;
    pub type OneRttSealed = g::Msg<{ ONE_RTT_SEALED }, [u8; 16]>;
    pub const ONE_RTT_SEAL_REJECTED: u8 = 137;
    pub type OneRttSealRejected = g::Msg<{ ONE_RTT_SEAL_REJECTED }, [u8; 16]>;
    pub const HEADER_MASK_READY: u8 = 141;
    pub type HeaderMaskReady = g::Msg<{ HEADER_MASK_READY }, [u8; 16]>;
    pub const HEADER_MASK_REJECTED: u8 = 145;
    pub type HeaderMaskRejected = g::Msg<{ HEADER_MASK_REJECTED }, [u8; 16]>;
    pub const ACK_APPLIED: u8 = 148;
    pub type AckApplied = g::Msg<{ ACK_APPLIED }, [u8; 16]>;
    pub const ACK_REJECTED: u8 = 149;
    pub type AckRejected = g::Msg<{ ACK_REJECTED }, [u8; 16]>;
    pub const KEYS_MAINTAINED: u8 = 150;
    pub type KeysMaintained = g::Msg<{ KEYS_MAINTAINED }, [u8; 16]>;
    pub const MAINTENANCE_REJECTED: u8 = 151;
    pub type MaintenanceRejected = g::Msg<{ MAINTENANCE_REJECTED }, [u8; 16]>;
    pub const KEY_UPDATED: u8 = 152;
    pub type KeyUpdated = g::Msg<{ KEY_UPDATED }, [u8; 16]>;
    pub const UPDATE_REJECTED: u8 = 153;
    pub type UpdateRejected = g::Msg<{ UPDATE_REJECTED }, [u8; 16]>;
    pub const INTEGRITY_GRANTED: u8 = 154;
    pub type IntegrityGranted = g::Msg<{ INTEGRITY_GRANTED }, [u8; 16]>;
    pub const LOAN_UNAVAILABLE: u8 = 155;
    pub type LoanUnavailable = g::Msg<{ LOAN_UNAVAILABLE }, [u8; 16]>;
    pub const INTEGRITY_RETURNED: u8 = 156;
    pub type IntegrityReturned = g::Msg<{ INTEGRITY_RETURNED }, [u8; 16]>;
    pub const INTEGRITY_RESTORED: u8 = 157;
    pub type IntegrityRestored = g::Msg<{ INTEGRITY_RESTORED }, [u8; 16]>;
    pub const RETIREMENT_PREPARED: u8 = 158;
    pub type RetirementPrepared = g::Msg<{ RETIREMENT_PREPARED }, [u8; 16]>;
    pub const RESULT_TAKEN: u8 = 159;
    pub type ResultTaken = g::Msg<{ RESULT_TAKEN }, [u8; 16]>;
    pub const RETIRED: u8 = 219;
    pub type Retired = g::Msg<{ RETIRED }, [u8; 16]>;
    pub const RETIREMENT_ACKNOWLEDGED: u8 = 220;
    pub type RetirementAcknowledged = g::Msg<{ RETIREMENT_ACKNOWLEDGED }, [u8; 16]>;
    // Server receive keys can outlive Handshake keys. These narrow residual
    // operations never admit Handshake use, early sending, or reconfirmation.
    pub const OPEN_EARLY: u8 = 227;
    pub type OpenEarly = g::Msg<{ OPEN_EARLY }, [u8; 16]>;
    pub const EARLY_HEADER_MASK: u8 = 228;
    pub type EarlyHeaderMask = g::Msg<{ EARLY_HEADER_MASK }, [u8; 16]>;
    pub const TAKE_EARLY_REPLAY_CLAIM: u8 = 229;
    pub type TakeEarlyReplayClaim = g::Msg<{ TAKE_EARLY_REPLAY_CLAIM }, [u8; 16]>;
    pub const DISCARD_EARLY: u8 = 230;
    pub type DiscardEarly = g::Msg<{ DISCARD_EARLY }, [u8; 16]>;
    pub const EARLY_OPENED: u8 = 231;
    pub type EarlyOpened = g::Msg<{ EARLY_OPENED }, [u8; 16]>;
    pub const EARLY_OPEN_REJECTED: u8 = 232;
    pub type EarlyOpenRejected = g::Msg<{ EARLY_OPEN_REJECTED }, [u8; 16]>;
    pub const EARLY_REPLAY_CLAIM_READY: u8 = 233;
    pub type EarlyReplayClaimReady = g::Msg<{ EARLY_REPLAY_CLAIM_READY }, [u8; 16]>;
    pub const NO_EARLY_REPLAY_CLAIM: u8 = 234;
    pub type NoEarlyReplayClaim = g::Msg<{ NO_EARLY_REPLAY_CLAIM }, [u8; 16]>;
    pub const EARLY_DISCARDED: u8 = 235;
    pub type EarlyDiscarded = g::Msg<{ EARLY_DISCARDED }, [u8; 16]>;
    pub const EARLY_HEADER_MASK_READY: u8 = 236;
    pub type EarlyHeaderMaskReady = g::Msg<{ EARLY_HEADER_MASK_READY }, [u8; 16]>;
    pub const EARLY_HEADER_MASK_REJECTED: u8 = 237;
    pub type EarlyHeaderMaskRejected = g::Msg<{ EARLY_HEADER_MASK_REJECTED }, [u8; 16]>;
}

pub const HANDSHAKE_KEY_GRANT: u8 = 221;
pub type HandshakeKeyGrant = g::Msg<{ HANDSHAKE_KEY_GRANT }, [u8; 16]>;
pub const APPLICATION_TRAFFIC_GRANT: u8 = 222;
pub type ApplicationTrafficGrant = g::Msg<{ APPLICATION_TRAFFIC_GRANT }, [u8; 16]>;
pub const CONFIRMED_GRANT: u8 = 223;
pub type ConfirmedGrant = g::Msg<{ CONFIRMED_GRANT }, [u8; 16]>;
pub const HANDSHAKE_RETIRED: u8 = 224;
pub type HandshakeRetired = g::Msg<{ HANDSHAKE_RETIRED }, [u8; 16]>;
pub const INSTALL: u8 = 225;
pub type Install = g::Msg<{ INSTALL }, [u8; 16]>;
pub const INSTALLED: u8 = 226;
pub type Installed = g::Msg<{ INSTALLED }, [u8; 16]>;

pub type BinaryFlow<const C: u8, const T: u8, const Q: u8, const S: u8, const F: u8, const A: u8> =
    g::Seq<
        g::Send<C, T, g::Msg<Q, [u8; 16]>>,
        g::Seq<
            g::Route<g::Send<T, C, g::Msg<S, [u8; 16]>>, g::Send<T, C, g::Msg<F, [u8; 16]>>>,
            g::Send<C, T, g::Msg<A, [u8; 16]>>,
        >,
    >;
pub type ProgressFlow<
    const C: u8,
    const T: u8,
    const Q: u8,
    const B: u8,
    const W: u8,
    const O: u8,
    const S: u8,
    const F: u8,
    const A: u8,
> = g::Seq<
    g::Send<C, T, g::Msg<Q, [u8; 16]>>,
    g::Seq<
        g::Route<g::Send<T, C, g::Msg<S, [u8; 16]>>, g::Send<T, C, g::Msg<F, [u8; 16]>>>,
        g::Seq<
            g::Send<C, T, g::Msg<O, [u8; 16]>>,
            g::Seq<
                g::Route<g::Send<T, C, g::Msg<B, [u8; 16]>>, g::Send<T, C, g::Msg<W, [u8; 16]>>>,
                g::Send<C, T, g::Msg<A, [u8; 16]>>,
            >,
        >,
    >,
>;
pub type UnaryFlow<const C: u8, const T: u8, const Q: u8, const S: u8, const A: u8> = g::Seq<
    g::Send<C, T, g::Msg<Q, [u8; 16]>>,
    g::Seq<g::Send<T, C, g::Msg<S, [u8; 16]>>, g::Send<C, T, g::Msg<A, [u8; 16]>>>,
>;
pub type LoanFlow<
    const C: u8,
    const T: u8,
    const Q: u8,
    const G: u8,
    const U: u8,
    const R: u8,
    const S: u8,
    const A: u8,
> = g::Seq<
    g::Send<C, T, g::Msg<Q, [u8; 16]>>,
    g::Route<
        g::Seq<
            g::Send<T, C, g::Msg<G, [u8; 16]>>,
            g::Seq<
                g::Send<C, T, g::Msg<A, [u8; 16]>>,
                g::Seq<
                    g::Send<C, T, g::Msg<R, [u8; 16]>>,
                    g::Seq<g::Send<T, C, g::Msg<S, [u8; 16]>>, g::Send<C, T, g::Msg<A, [u8; 16]>>>,
                >,
            >,
        >,
        g::Seq<g::Send<T, C, g::Msg<U, [u8; 16]>>, g::Send<C, T, g::Msg<A, [u8; 16]>>>,
    >,
>;
fn binary<const C: u8, const T: u8, const Q: u8, const S: u8, const F: u8, const A: u8>()
-> g::Program<BinaryFlow<C, T, Q, S, F, A>> {
    g::seq(
        g::send::<C, T, g::Msg<Q, [u8; 16]>>(),
        g::seq(
            g::route(
                g::send::<T, C, g::Msg<S, [u8; 16]>>(),
                g::send::<T, C, g::Msg<F, [u8; 16]>>(),
            ),
            g::send::<C, T, g::Msg<A, [u8; 16]>>(),
        ),
    )
}
fn progress<
    const C: u8,
    const T: u8,
    const Q: u8,
    const B: u8,
    const W: u8,
    const O: u8,
    const S: u8,
    const F: u8,
    const A: u8,
>() -> g::Program<ProgressFlow<C, T, Q, B, W, O, S, F, A>> {
    g::seq(
        g::send::<C, T, g::Msg<Q, [u8; 16]>>(),
        g::seq(
            g::route(
                g::send::<T, C, g::Msg<S, [u8; 16]>>(),
                g::send::<T, C, g::Msg<F, [u8; 16]>>(),
            ),
            g::seq(
                g::send::<C, T, g::Msg<O, [u8; 16]>>(),
                g::seq(
                    g::route(
                        g::send::<T, C, g::Msg<B, [u8; 16]>>(),
                        g::send::<T, C, g::Msg<W, [u8; 16]>>(),
                    ),
                    g::send::<C, T, g::Msg<A, [u8; 16]>>(),
                ),
            ),
        ),
    )
}
fn unary<const C: u8, const T: u8, const Q: u8, const S: u8, const A: u8>()
-> g::Program<UnaryFlow<C, T, Q, S, A>> {
    g::seq(
        g::send::<C, T, g::Msg<Q, [u8; 16]>>(),
        g::seq(
            g::send::<T, C, g::Msg<S, [u8; 16]>>(),
            g::send::<C, T, g::Msg<A, [u8; 16]>>(),
        ),
    )
}
fn loan<
    const C: u8,
    const T: u8,
    const Q: u8,
    const G: u8,
    const U: u8,
    const R: u8,
    const S: u8,
    const A: u8,
>() -> g::Program<LoanFlow<C, T, Q, G, U, R, S, A>> {
    g::seq(
        g::send::<C, T, g::Msg<Q, [u8; 16]>>(),
        g::route(
            g::seq(
                g::send::<T, C, g::Msg<G, [u8; 16]>>(),
                g::seq(
                    g::send::<C, T, g::Msg<A, [u8; 16]>>(),
                    g::seq(
                        g::send::<C, T, g::Msg<R, [u8; 16]>>(),
                        g::seq(
                            g::send::<T, C, g::Msg<S, [u8; 16]>>(),
                            g::send::<C, T, g::Msg<A, [u8; 16]>>(),
                        ),
                    ),
                ),
            ),
            g::seq(
                g::send::<T, C, g::Msg<U, [u8; 16]>>(),
                g::send::<C, T, g::Msg<A, [u8; 16]>>(),
            ),
        ),
    )
}

pub type InitialWork<const C: u8, const T: u8> = g::Roll<
    g::Route<
        g::Route<
            g::Route<
                ProgressFlow<
                    C,
                    T,
                    { initial::CRYPTO_INPUT },
                    { initial::HANDSHAKE_KEYS_PREPARED },
                    { initial::PHASE_UNCHANGED },
                    { initial::OUTCOME_SEEN },
                    { initial::CRYPTO_ACCEPTED },
                    { initial::CRYPTO_REJECTED },
                    { initial::RESULT_TAKEN },
                >,
                ProgressFlow<
                    C,
                    T,
                    { initial::FLIGHT_REQUESTED },
                    { initial::HANDSHAKE_KEYS_PREPARED },
                    { initial::PHASE_UNCHANGED },
                    { initial::OUTCOME_SEEN },
                    { initial::FLIGHT_READY },
                    { initial::AWAIT_INPUT },
                    { initial::RESULT_TAKEN },
                >,
            >,
            g::Route<
                BinaryFlow<
                    C,
                    T,
                    { initial::OPEN_EARLY },
                    { initial::EARLY_OPENED },
                    { initial::EARLY_OPEN_REJECTED },
                    { initial::RESULT_TAKEN },
                >,
                g::Route<
                    BinaryFlow<
                        C,
                        T,
                        { initial::SEAL_EARLY },
                        { initial::EARLY_SEALED },
                        { initial::EARLY_SEAL_REJECTED },
                        { initial::RESULT_TAKEN },
                    >,
                    BinaryFlow<
                        C,
                        T,
                        { initial::EARLY_HEADER_MASK },
                        { initial::HEADER_MASK_READY },
                        { initial::HEADER_MASK_REJECTED },
                        { initial::RESULT_TAKEN },
                    >,
                >,
            >,
        >,
        g::Route<
            g::Route<
                BinaryFlow<
                    C,
                    T,
                    { initial::TAKE_EARLY_REPLAY_CLAIM },
                    { initial::EARLY_REPLAY_CLAIM_READY },
                    { initial::NO_EARLY_REPLAY_CLAIM },
                    { initial::RESULT_TAKEN },
                >,
                UnaryFlow<
                    C,
                    T,
                    { initial::DISCARD_EARLY },
                    { initial::EARLY_DISCARDED },
                    { initial::RESULT_TAKEN },
                >,
            >,
            g::Route<
                BinaryFlow<
                    C,
                    T,
                    { initial::MAINTAIN_KEYS },
                    { initial::KEYS_MAINTAINED },
                    { initial::MAINTENANCE_REJECTED },
                    { initial::RESULT_TAKEN },
                >,
                g::Route<
                    LoanFlow<
                        C,
                        T,
                        { initial::LOAN_INTEGRITY },
                        { initial::INTEGRITY_GRANTED },
                        { initial::LOAN_UNAVAILABLE },
                        { initial::INTEGRITY_RETURNED },
                        { initial::INTEGRITY_RESTORED },
                        { initial::RESULT_TAKEN },
                    >,
                    UnaryFlow<
                        C,
                        T,
                        { initial::RETIRE_REQUESTED },
                        { initial::RETIREMENT_PREPARED },
                        { initial::RESULT_TAKEN },
                    >,
                >,
            >,
        >,
    >,
>;
pub fn initial_work<const C: u8, const T: u8>() -> g::Program<InitialWork<C, T>> {
    g::route(
        g::route(
            g::route(
                progress::<
                    C,
                    T,
                    { initial::CRYPTO_INPUT },
                    { initial::HANDSHAKE_KEYS_PREPARED },
                    { initial::PHASE_UNCHANGED },
                    { initial::OUTCOME_SEEN },
                    { initial::CRYPTO_ACCEPTED },
                    { initial::CRYPTO_REJECTED },
                    { initial::RESULT_TAKEN },
                >(),
                progress::<
                    C,
                    T,
                    { initial::FLIGHT_REQUESTED },
                    { initial::HANDSHAKE_KEYS_PREPARED },
                    { initial::PHASE_UNCHANGED },
                    { initial::OUTCOME_SEEN },
                    { initial::FLIGHT_READY },
                    { initial::AWAIT_INPUT },
                    { initial::RESULT_TAKEN },
                >(),
            ),
            g::route(
                binary::<
                    C,
                    T,
                    { initial::OPEN_EARLY },
                    { initial::EARLY_OPENED },
                    { initial::EARLY_OPEN_REJECTED },
                    { initial::RESULT_TAKEN },
                >(),
                g::route(
                    binary::<
                        C,
                        T,
                        { initial::SEAL_EARLY },
                        { initial::EARLY_SEALED },
                        { initial::EARLY_SEAL_REJECTED },
                        { initial::RESULT_TAKEN },
                    >(),
                    binary::<
                        C,
                        T,
                        { initial::EARLY_HEADER_MASK },
                        { initial::HEADER_MASK_READY },
                        { initial::HEADER_MASK_REJECTED },
                        { initial::RESULT_TAKEN },
                    >(),
                ),
            ),
        ),
        g::route(
            g::route(
                binary::<
                    C,
                    T,
                    { initial::TAKE_EARLY_REPLAY_CLAIM },
                    { initial::EARLY_REPLAY_CLAIM_READY },
                    { initial::NO_EARLY_REPLAY_CLAIM },
                    { initial::RESULT_TAKEN },
                >(),
                unary::<
                    C,
                    T,
                    { initial::DISCARD_EARLY },
                    { initial::EARLY_DISCARDED },
                    { initial::RESULT_TAKEN },
                >(),
            ),
            g::route(
                binary::<
                    C,
                    T,
                    { initial::MAINTAIN_KEYS },
                    { initial::KEYS_MAINTAINED },
                    { initial::MAINTENANCE_REJECTED },
                    { initial::RESULT_TAKEN },
                >(),
                g::route(
                    loan::<
                        C,
                        T,
                        { initial::LOAN_INTEGRITY },
                        { initial::INTEGRITY_GRANTED },
                        { initial::LOAN_UNAVAILABLE },
                        { initial::INTEGRITY_RETURNED },
                        { initial::INTEGRITY_RESTORED },
                        { initial::RESULT_TAKEN },
                    >(),
                    unary::<
                        C,
                        T,
                        { initial::RETIRE_REQUESTED },
                        { initial::RETIREMENT_PREPARED },
                        { initial::RESULT_TAKEN },
                    >(),
                ),
            ),
        ),
    )
    .roll()
}
pub type InitialRetirement<const C: u8, const T: u8> =
    g::Seq<g::Send<T, C, initial::Retired>, g::Send<C, T, initial::RetirementAcknowledged>>;
fn initial_retirement<const C: u8, const T: u8>() -> g::Program<InitialRetirement<C, T>> {
    g::seq(
        g::send::<T, C, initial::Retired>(),
        g::send::<C, T, initial::RetirementAcknowledged>(),
    )
}
pub type HandshakeWork<const C: u8, const T: u8> = g::Roll<
    g::Route<
        g::Route<
            g::Route<
                ProgressFlow<
                    C,
                    T,
                    { handshake::CRYPTO_INPUT },
                    { handshake::APPLICATION_TRAFFIC_PREPARED },
                    { handshake::PHASE_UNCHANGED },
                    { handshake::OUTCOME_SEEN },
                    { handshake::CRYPTO_ACCEPTED },
                    { handshake::CRYPTO_REJECTED },
                    { handshake::RESULT_TAKEN },
                >,
                g::Route<
                    ProgressFlow<
                        C,
                        T,
                        { handshake::FLIGHT_REQUESTED },
                        { handshake::APPLICATION_TRAFFIC_PREPARED },
                        { handshake::PHASE_UNCHANGED },
                        { handshake::OUTCOME_SEEN },
                        { handshake::FLIGHT_READY },
                        { handshake::AWAIT_INPUT },
                        { handshake::RESULT_TAKEN },
                    >,
                    BinaryFlow<
                        C,
                        T,
                        { handshake::OPEN_EARLY },
                        { handshake::EARLY_OPENED },
                        { handshake::EARLY_OPEN_REJECTED },
                        { handshake::RESULT_TAKEN },
                    >,
                >,
            >,
            g::Route<
                BinaryFlow<
                    C,
                    T,
                    { handshake::SEAL_EARLY },
                    { handshake::EARLY_SEALED },
                    { handshake::EARLY_SEAL_REJECTED },
                    { handshake::RESULT_TAKEN },
                >,
                g::Route<
                    BinaryFlow<
                        C,
                        T,
                        { handshake::EARLY_HEADER_MASK },
                        { handshake::HEADER_MASK_READY },
                        { handshake::HEADER_MASK_REJECTED },
                        { handshake::RESULT_TAKEN },
                    >,
                    BinaryFlow<
                        C,
                        T,
                        { handshake::TAKE_EARLY_REPLAY_CLAIM },
                        { handshake::EARLY_REPLAY_CLAIM_READY },
                        { handshake::NO_EARLY_REPLAY_CLAIM },
                        { handshake::RESULT_TAKEN },
                    >,
                >,
            >,
        >,
        g::Route<
            g::Route<
                UnaryFlow<
                    C,
                    T,
                    { handshake::DISCARD_EARLY },
                    { handshake::EARLY_DISCARDED },
                    { handshake::RESULT_TAKEN },
                >,
                g::Route<
                    BinaryFlow<
                        C,
                        T,
                        { handshake::OPEN_HANDSHAKE },
                        { handshake::HANDSHAKE_OPENED },
                        { handshake::HANDSHAKE_OPEN_REJECTED },
                        { handshake::RESULT_TAKEN },
                    >,
                    BinaryFlow<
                        C,
                        T,
                        { handshake::SEAL_HANDSHAKE },
                        { handshake::HANDSHAKE_SEALED },
                        { handshake::HANDSHAKE_SEAL_REJECTED },
                        { handshake::RESULT_TAKEN },
                    >,
                >,
            >,
            g::Route<
                g::Route<
                    BinaryFlow<
                        C,
                        T,
                        { handshake::HANDSHAKE_HEADER_MASK },
                        { handshake::HEADER_MASK_READY },
                        { handshake::HEADER_MASK_REJECTED },
                        { handshake::RESULT_TAKEN },
                    >,
                    BinaryFlow<
                        C,
                        T,
                        { handshake::MAINTAIN_KEYS },
                        { handshake::KEYS_MAINTAINED },
                        { handshake::MAINTENANCE_REJECTED },
                        { handshake::RESULT_TAKEN },
                    >,
                >,
                g::Route<
                    LoanFlow<
                        C,
                        T,
                        { handshake::LOAN_INTEGRITY },
                        { handshake::INTEGRITY_GRANTED },
                        { handshake::LOAN_UNAVAILABLE },
                        { handshake::INTEGRITY_RETURNED },
                        { handshake::INTEGRITY_RESTORED },
                        { handshake::RESULT_TAKEN },
                    >,
                    UnaryFlow<
                        C,
                        T,
                        { handshake::RETIRE_REQUESTED },
                        { handshake::RETIREMENT_PREPARED },
                        { handshake::RESULT_TAKEN },
                    >,
                >,
            >,
        >,
    >,
>;
pub fn handshake_work<const C: u8, const T: u8>() -> g::Program<HandshakeWork<C, T>> {
    g::route(
        g::route(
            g::route(
                progress::<
                    C,
                    T,
                    { handshake::CRYPTO_INPUT },
                    { handshake::APPLICATION_TRAFFIC_PREPARED },
                    { handshake::PHASE_UNCHANGED },
                    { handshake::OUTCOME_SEEN },
                    { handshake::CRYPTO_ACCEPTED },
                    { handshake::CRYPTO_REJECTED },
                    { handshake::RESULT_TAKEN },
                >(),
                g::route(
                    progress::<
                        C,
                        T,
                        { handshake::FLIGHT_REQUESTED },
                        { handshake::APPLICATION_TRAFFIC_PREPARED },
                        { handshake::PHASE_UNCHANGED },
                        { handshake::OUTCOME_SEEN },
                        { handshake::FLIGHT_READY },
                        { handshake::AWAIT_INPUT },
                        { handshake::RESULT_TAKEN },
                    >(),
                    binary::<
                        C,
                        T,
                        { handshake::OPEN_EARLY },
                        { handshake::EARLY_OPENED },
                        { handshake::EARLY_OPEN_REJECTED },
                        { handshake::RESULT_TAKEN },
                    >(),
                ),
            ),
            g::route(
                binary::<
                    C,
                    T,
                    { handshake::SEAL_EARLY },
                    { handshake::EARLY_SEALED },
                    { handshake::EARLY_SEAL_REJECTED },
                    { handshake::RESULT_TAKEN },
                >(),
                g::route(
                    binary::<
                        C,
                        T,
                        { handshake::EARLY_HEADER_MASK },
                        { handshake::HEADER_MASK_READY },
                        { handshake::HEADER_MASK_REJECTED },
                        { handshake::RESULT_TAKEN },
                    >(),
                    binary::<
                        C,
                        T,
                        { handshake::TAKE_EARLY_REPLAY_CLAIM },
                        { handshake::EARLY_REPLAY_CLAIM_READY },
                        { handshake::NO_EARLY_REPLAY_CLAIM },
                        { handshake::RESULT_TAKEN },
                    >(),
                ),
            ),
        ),
        g::route(
            g::route(
                unary::<
                    C,
                    T,
                    { handshake::DISCARD_EARLY },
                    { handshake::EARLY_DISCARDED },
                    { handshake::RESULT_TAKEN },
                >(),
                g::route(
                    binary::<
                        C,
                        T,
                        { handshake::OPEN_HANDSHAKE },
                        { handshake::HANDSHAKE_OPENED },
                        { handshake::HANDSHAKE_OPEN_REJECTED },
                        { handshake::RESULT_TAKEN },
                    >(),
                    binary::<
                        C,
                        T,
                        { handshake::SEAL_HANDSHAKE },
                        { handshake::HANDSHAKE_SEALED },
                        { handshake::HANDSHAKE_SEAL_REJECTED },
                        { handshake::RESULT_TAKEN },
                    >(),
                ),
            ),
            g::route(
                g::route(
                    binary::<
                        C,
                        T,
                        { handshake::HANDSHAKE_HEADER_MASK },
                        { handshake::HEADER_MASK_READY },
                        { handshake::HEADER_MASK_REJECTED },
                        { handshake::RESULT_TAKEN },
                    >(),
                    binary::<
                        C,
                        T,
                        { handshake::MAINTAIN_KEYS },
                        { handshake::KEYS_MAINTAINED },
                        { handshake::MAINTENANCE_REJECTED },
                        { handshake::RESULT_TAKEN },
                    >(),
                ),
                g::route(
                    loan::<
                        C,
                        T,
                        { handshake::LOAN_INTEGRITY },
                        { handshake::INTEGRITY_GRANTED },
                        { handshake::LOAN_UNAVAILABLE },
                        { handshake::INTEGRITY_RETURNED },
                        { handshake::INTEGRITY_RESTORED },
                        { handshake::RESULT_TAKEN },
                    >(),
                    unary::<
                        C,
                        T,
                        { handshake::RETIRE_REQUESTED },
                        { handshake::RETIREMENT_PREPARED },
                        { handshake::RESULT_TAKEN },
                    >(),
                ),
            ),
        ),
    )
    .roll()
}
pub type HandshakeRetirement<const C: u8, const T: u8> =
    g::Seq<g::Send<T, C, handshake::Retired>, g::Send<C, T, handshake::RetirementAcknowledged>>;
fn handshake_retirement<const C: u8, const T: u8>() -> g::Program<HandshakeRetirement<C, T>> {
    g::seq(
        g::send::<T, C, handshake::Retired>(),
        g::send::<C, T, handshake::RetirementAcknowledged>(),
    )
}
pub type UnconfirmedWork<const C: u8, const T: u8> = g::Roll<
    g::Route<
        g::Route<
            g::Route<
                g::Route<
                    BinaryFlow<
                        C,
                        T,
                        { unconfirmed::CRYPTO_INPUT },
                        { unconfirmed::CRYPTO_ACCEPTED },
                        { unconfirmed::CRYPTO_REJECTED },
                        { unconfirmed::RESULT_TAKEN },
                    >,
                    BinaryFlow<
                        C,
                        T,
                        { unconfirmed::FLIGHT_REQUESTED },
                        { unconfirmed::FLIGHT_READY },
                        { unconfirmed::AWAIT_INPUT },
                        { unconfirmed::RESULT_TAKEN },
                    >,
                >,
                g::Route<
                    BinaryFlow<
                        C,
                        T,
                        { unconfirmed::OPEN_EARLY },
                        { unconfirmed::EARLY_OPENED },
                        { unconfirmed::EARLY_OPEN_REJECTED },
                        { unconfirmed::RESULT_TAKEN },
                    >,
                    BinaryFlow<
                        C,
                        T,
                        { unconfirmed::SEAL_EARLY },
                        { unconfirmed::EARLY_SEALED },
                        { unconfirmed::EARLY_SEAL_REJECTED },
                        { unconfirmed::RESULT_TAKEN },
                    >,
                >,
            >,
            g::Route<
                g::Route<
                    BinaryFlow<
                        C,
                        T,
                        { unconfirmed::EARLY_HEADER_MASK },
                        { unconfirmed::HEADER_MASK_READY },
                        { unconfirmed::HEADER_MASK_REJECTED },
                        { unconfirmed::RESULT_TAKEN },
                    >,
                    BinaryFlow<
                        C,
                        T,
                        { unconfirmed::TAKE_EARLY_REPLAY_CLAIM },
                        { unconfirmed::EARLY_REPLAY_CLAIM_READY },
                        { unconfirmed::NO_EARLY_REPLAY_CLAIM },
                        { unconfirmed::RESULT_TAKEN },
                    >,
                >,
                g::Route<
                    UnaryFlow<
                        C,
                        T,
                        { unconfirmed::DISCARD_EARLY },
                        { unconfirmed::EARLY_DISCARDED },
                        { unconfirmed::RESULT_TAKEN },
                    >,
                    g::Route<
                        BinaryFlow<
                            C,
                            T,
                            { unconfirmed::OPEN_HANDSHAKE },
                            { unconfirmed::HANDSHAKE_OPENED },
                            { unconfirmed::HANDSHAKE_OPEN_REJECTED },
                            { unconfirmed::RESULT_TAKEN },
                        >,
                        BinaryFlow<
                            C,
                            T,
                            { unconfirmed::SEAL_HANDSHAKE },
                            { unconfirmed::HANDSHAKE_SEALED },
                            { unconfirmed::HANDSHAKE_SEAL_REJECTED },
                            { unconfirmed::RESULT_TAKEN },
                        >,
                    >,
                >,
            >,
        >,
        g::Route<
            g::Route<
                g::Route<
                    BinaryFlow<
                        C,
                        T,
                        { unconfirmed::HANDSHAKE_HEADER_MASK },
                        { unconfirmed::HEADER_MASK_READY },
                        { unconfirmed::HEADER_MASK_REJECTED },
                        { unconfirmed::RESULT_TAKEN },
                    >,
                    BinaryFlow<
                        C,
                        T,
                        { unconfirmed::OPEN_ONE_RTT },
                        { unconfirmed::ONE_RTT_OPENED },
                        { unconfirmed::ONE_RTT_OPEN_REJECTED },
                        { unconfirmed::RESULT_TAKEN },
                    >,
                >,
                g::Route<
                    BinaryFlow<
                        C,
                        T,
                        { unconfirmed::SEAL_ONE_RTT },
                        { unconfirmed::ONE_RTT_SEALED },
                        { unconfirmed::ONE_RTT_SEAL_REJECTED },
                        { unconfirmed::RESULT_TAKEN },
                    >,
                    BinaryFlow<
                        C,
                        T,
                        { unconfirmed::ONE_RTT_HEADER_MASK },
                        { unconfirmed::HEADER_MASK_READY },
                        { unconfirmed::HEADER_MASK_REJECTED },
                        { unconfirmed::RESULT_TAKEN },
                    >,
                >,
            >,
            g::Route<
                g::Route<
                    BinaryFlow<
                        C,
                        T,
                        { unconfirmed::CONFIRM_HANDSHAKE },
                        { unconfirmed::HANDSHAKE_CONFIRMED },
                        { unconfirmed::CONFIRMATION_REJECTED },
                        { unconfirmed::RESULT_TAKEN },
                    >,
                    BinaryFlow<
                        C,
                        T,
                        { unconfirmed::VALIDATED_ACK },
                        { unconfirmed::ACK_APPLIED },
                        { unconfirmed::ACK_REJECTED },
                        { unconfirmed::RESULT_TAKEN },
                    >,
                >,
                g::Route<
                    BinaryFlow<
                        C,
                        T,
                        { unconfirmed::MAINTAIN_KEYS },
                        { unconfirmed::KEYS_MAINTAINED },
                        { unconfirmed::MAINTENANCE_REJECTED },
                        { unconfirmed::RESULT_TAKEN },
                    >,
                    g::Route<
                        LoanFlow<
                            C,
                            T,
                            { unconfirmed::LOAN_INTEGRITY },
                            { unconfirmed::INTEGRITY_GRANTED },
                            { unconfirmed::LOAN_UNAVAILABLE },
                            { unconfirmed::INTEGRITY_RETURNED },
                            { unconfirmed::INTEGRITY_RESTORED },
                            { unconfirmed::RESULT_TAKEN },
                        >,
                        UnaryFlow<
                            C,
                            T,
                            { unconfirmed::RETIRE_REQUESTED },
                            { unconfirmed::RETIREMENT_PREPARED },
                            { unconfirmed::RESULT_TAKEN },
                        >,
                    >,
                >,
            >,
        >,
    >,
>;
pub fn unconfirmed_work<const C: u8, const T: u8>() -> g::Program<UnconfirmedWork<C, T>> {
    g::route(
        g::route(
            g::route(
                g::route(
                    binary::<
                        C,
                        T,
                        { unconfirmed::CRYPTO_INPUT },
                        { unconfirmed::CRYPTO_ACCEPTED },
                        { unconfirmed::CRYPTO_REJECTED },
                        { unconfirmed::RESULT_TAKEN },
                    >(),
                    binary::<
                        C,
                        T,
                        { unconfirmed::FLIGHT_REQUESTED },
                        { unconfirmed::FLIGHT_READY },
                        { unconfirmed::AWAIT_INPUT },
                        { unconfirmed::RESULT_TAKEN },
                    >(),
                ),
                g::route(
                    binary::<
                        C,
                        T,
                        { unconfirmed::OPEN_EARLY },
                        { unconfirmed::EARLY_OPENED },
                        { unconfirmed::EARLY_OPEN_REJECTED },
                        { unconfirmed::RESULT_TAKEN },
                    >(),
                    binary::<
                        C,
                        T,
                        { unconfirmed::SEAL_EARLY },
                        { unconfirmed::EARLY_SEALED },
                        { unconfirmed::EARLY_SEAL_REJECTED },
                        { unconfirmed::RESULT_TAKEN },
                    >(),
                ),
            ),
            g::route(
                g::route(
                    binary::<
                        C,
                        T,
                        { unconfirmed::EARLY_HEADER_MASK },
                        { unconfirmed::HEADER_MASK_READY },
                        { unconfirmed::HEADER_MASK_REJECTED },
                        { unconfirmed::RESULT_TAKEN },
                    >(),
                    binary::<
                        C,
                        T,
                        { unconfirmed::TAKE_EARLY_REPLAY_CLAIM },
                        { unconfirmed::EARLY_REPLAY_CLAIM_READY },
                        { unconfirmed::NO_EARLY_REPLAY_CLAIM },
                        { unconfirmed::RESULT_TAKEN },
                    >(),
                ),
                g::route(
                    unary::<
                        C,
                        T,
                        { unconfirmed::DISCARD_EARLY },
                        { unconfirmed::EARLY_DISCARDED },
                        { unconfirmed::RESULT_TAKEN },
                    >(),
                    g::route(
                        binary::<
                            C,
                            T,
                            { unconfirmed::OPEN_HANDSHAKE },
                            { unconfirmed::HANDSHAKE_OPENED },
                            { unconfirmed::HANDSHAKE_OPEN_REJECTED },
                            { unconfirmed::RESULT_TAKEN },
                        >(),
                        binary::<
                            C,
                            T,
                            { unconfirmed::SEAL_HANDSHAKE },
                            { unconfirmed::HANDSHAKE_SEALED },
                            { unconfirmed::HANDSHAKE_SEAL_REJECTED },
                            { unconfirmed::RESULT_TAKEN },
                        >(),
                    ),
                ),
            ),
        ),
        g::route(
            g::route(
                g::route(
                    binary::<
                        C,
                        T,
                        { unconfirmed::HANDSHAKE_HEADER_MASK },
                        { unconfirmed::HEADER_MASK_READY },
                        { unconfirmed::HEADER_MASK_REJECTED },
                        { unconfirmed::RESULT_TAKEN },
                    >(),
                    binary::<
                        C,
                        T,
                        { unconfirmed::OPEN_ONE_RTT },
                        { unconfirmed::ONE_RTT_OPENED },
                        { unconfirmed::ONE_RTT_OPEN_REJECTED },
                        { unconfirmed::RESULT_TAKEN },
                    >(),
                ),
                g::route(
                    binary::<
                        C,
                        T,
                        { unconfirmed::SEAL_ONE_RTT },
                        { unconfirmed::ONE_RTT_SEALED },
                        { unconfirmed::ONE_RTT_SEAL_REJECTED },
                        { unconfirmed::RESULT_TAKEN },
                    >(),
                    binary::<
                        C,
                        T,
                        { unconfirmed::ONE_RTT_HEADER_MASK },
                        { unconfirmed::HEADER_MASK_READY },
                        { unconfirmed::HEADER_MASK_REJECTED },
                        { unconfirmed::RESULT_TAKEN },
                    >(),
                ),
            ),
            g::route(
                g::route(
                    binary::<
                        C,
                        T,
                        { unconfirmed::CONFIRM_HANDSHAKE },
                        { unconfirmed::HANDSHAKE_CONFIRMED },
                        { unconfirmed::CONFIRMATION_REJECTED },
                        { unconfirmed::RESULT_TAKEN },
                    >(),
                    binary::<
                        C,
                        T,
                        { unconfirmed::VALIDATED_ACK },
                        { unconfirmed::ACK_APPLIED },
                        { unconfirmed::ACK_REJECTED },
                        { unconfirmed::RESULT_TAKEN },
                    >(),
                ),
                g::route(
                    binary::<
                        C,
                        T,
                        { unconfirmed::MAINTAIN_KEYS },
                        { unconfirmed::KEYS_MAINTAINED },
                        { unconfirmed::MAINTENANCE_REJECTED },
                        { unconfirmed::RESULT_TAKEN },
                    >(),
                    g::route(
                        loan::<
                            C,
                            T,
                            { unconfirmed::LOAN_INTEGRITY },
                            { unconfirmed::INTEGRITY_GRANTED },
                            { unconfirmed::LOAN_UNAVAILABLE },
                            { unconfirmed::INTEGRITY_RETURNED },
                            { unconfirmed::INTEGRITY_RESTORED },
                            { unconfirmed::RESULT_TAKEN },
                        >(),
                        unary::<
                            C,
                            T,
                            { unconfirmed::RETIRE_REQUESTED },
                            { unconfirmed::RETIREMENT_PREPARED },
                            { unconfirmed::RESULT_TAKEN },
                        >(),
                    ),
                ),
            ),
        ),
    )
    .roll()
}
pub type UnconfirmedRetirement<const C: u8, const T: u8> =
    g::Seq<g::Send<T, C, unconfirmed::Retired>, g::Send<C, T, unconfirmed::RetirementAcknowledged>>;
fn unconfirmed_retirement<const C: u8, const T: u8>() -> g::Program<UnconfirmedRetirement<C, T>> {
    g::seq(
        g::send::<T, C, unconfirmed::Retired>(),
        g::send::<C, T, unconfirmed::RetirementAcknowledged>(),
    )
}
pub type ConfirmedWork<const C: u8, const T: u8> = g::Roll<
    g::Route<
        g::Route<
            g::Route<
                g::Route<
                    BinaryFlow<
                        C,
                        T,
                        { confirmed::CRYPTO_INPUT },
                        { confirmed::CRYPTO_ACCEPTED },
                        { confirmed::CRYPTO_REJECTED },
                        { confirmed::RESULT_TAKEN },
                    >,
                    BinaryFlow<
                        C,
                        T,
                        { confirmed::FLIGHT_REQUESTED },
                        { confirmed::FLIGHT_READY },
                        { confirmed::AWAIT_INPUT },
                        { confirmed::RESULT_TAKEN },
                    >,
                >,
                g::Route<
                    BinaryFlow<
                        C,
                        T,
                        { confirmed::OPEN_EARLY },
                        { confirmed::EARLY_OPENED },
                        { confirmed::EARLY_OPEN_REJECTED },
                        { confirmed::RESULT_TAKEN },
                    >,
                    BinaryFlow<
                        C,
                        T,
                        { confirmed::SEAL_EARLY },
                        { confirmed::EARLY_SEALED },
                        { confirmed::EARLY_SEAL_REJECTED },
                        { confirmed::RESULT_TAKEN },
                    >,
                >,
            >,
            g::Route<
                g::Route<
                    BinaryFlow<
                        C,
                        T,
                        { confirmed::EARLY_HEADER_MASK },
                        { confirmed::HEADER_MASK_READY },
                        { confirmed::HEADER_MASK_REJECTED },
                        { confirmed::RESULT_TAKEN },
                    >,
                    BinaryFlow<
                        C,
                        T,
                        { confirmed::TAKE_EARLY_REPLAY_CLAIM },
                        { confirmed::EARLY_REPLAY_CLAIM_READY },
                        { confirmed::NO_EARLY_REPLAY_CLAIM },
                        { confirmed::RESULT_TAKEN },
                    >,
                >,
                g::Route<
                    UnaryFlow<
                        C,
                        T,
                        { confirmed::DISCARD_EARLY },
                        { confirmed::EARLY_DISCARDED },
                        { confirmed::RESULT_TAKEN },
                    >,
                    g::Route<
                        BinaryFlow<
                            C,
                            T,
                            { confirmed::OPEN_HANDSHAKE },
                            { confirmed::HANDSHAKE_OPENED },
                            { confirmed::HANDSHAKE_OPEN_REJECTED },
                            { confirmed::RESULT_TAKEN },
                        >,
                        BinaryFlow<
                            C,
                            T,
                            { confirmed::SEAL_HANDSHAKE },
                            { confirmed::HANDSHAKE_SEALED },
                            { confirmed::HANDSHAKE_SEAL_REJECTED },
                            { confirmed::RESULT_TAKEN },
                        >,
                    >,
                >,
            >,
        >,
        g::Route<
            g::Route<
                g::Route<
                    BinaryFlow<
                        C,
                        T,
                        { confirmed::HANDSHAKE_HEADER_MASK },
                        { confirmed::HEADER_MASK_READY },
                        { confirmed::HEADER_MASK_REJECTED },
                        { confirmed::RESULT_TAKEN },
                    >,
                    BinaryFlow<
                        C,
                        T,
                        { confirmed::OPEN_ONE_RTT },
                        { confirmed::ONE_RTT_OPENED },
                        { confirmed::ONE_RTT_OPEN_REJECTED },
                        { confirmed::RESULT_TAKEN },
                    >,
                >,
                g::Route<
                    BinaryFlow<
                        C,
                        T,
                        { confirmed::SEAL_ONE_RTT },
                        { confirmed::ONE_RTT_SEALED },
                        { confirmed::ONE_RTT_SEAL_REJECTED },
                        { confirmed::RESULT_TAKEN },
                    >,
                    g::Route<
                        BinaryFlow<
                            C,
                            T,
                            { confirmed::ONE_RTT_HEADER_MASK },
                            { confirmed::HEADER_MASK_READY },
                            { confirmed::HEADER_MASK_REJECTED },
                            { confirmed::RESULT_TAKEN },
                        >,
                        BinaryFlow<
                            C,
                            T,
                            { confirmed::VALIDATED_ACK },
                            { confirmed::ACK_APPLIED },
                            { confirmed::ACK_REJECTED },
                            { confirmed::RESULT_TAKEN },
                        >,
                    >,
                >,
            >,
            g::Route<
                g::Route<
                    BinaryFlow<
                        C,
                        T,
                        { confirmed::MAINTAIN_KEYS },
                        { confirmed::KEYS_MAINTAINED },
                        { confirmed::MAINTENANCE_REJECTED },
                        { confirmed::RESULT_TAKEN },
                    >,
                    BinaryFlow<
                        C,
                        T,
                        { confirmed::INITIATE_UPDATE },
                        { confirmed::KEY_UPDATED },
                        { confirmed::UPDATE_REJECTED },
                        { confirmed::RESULT_TAKEN },
                    >,
                >,
                g::Route<
                    UnaryFlow<
                        C,
                        T,
                        { confirmed::DISCARD_HANDSHAKE },
                        { confirmed::HANDSHAKE_DISCARDED },
                        { confirmed::RESULT_TAKEN },
                    >,
                    g::Route<
                        LoanFlow<
                            C,
                            T,
                            { confirmed::LOAN_INTEGRITY },
                            { confirmed::INTEGRITY_GRANTED },
                            { confirmed::LOAN_UNAVAILABLE },
                            { confirmed::INTEGRITY_RETURNED },
                            { confirmed::INTEGRITY_RESTORED },
                            { confirmed::RESULT_TAKEN },
                        >,
                        UnaryFlow<
                            C,
                            T,
                            { confirmed::RETIRE_REQUESTED },
                            { confirmed::RETIREMENT_PREPARED },
                            { confirmed::RESULT_TAKEN },
                        >,
                    >,
                >,
            >,
        >,
    >,
>;
pub fn confirmed_work<const C: u8, const T: u8>() -> g::Program<ConfirmedWork<C, T>> {
    g::route(
        g::route(
            g::route(
                g::route(
                    binary::<
                        C,
                        T,
                        { confirmed::CRYPTO_INPUT },
                        { confirmed::CRYPTO_ACCEPTED },
                        { confirmed::CRYPTO_REJECTED },
                        { confirmed::RESULT_TAKEN },
                    >(),
                    binary::<
                        C,
                        T,
                        { confirmed::FLIGHT_REQUESTED },
                        { confirmed::FLIGHT_READY },
                        { confirmed::AWAIT_INPUT },
                        { confirmed::RESULT_TAKEN },
                    >(),
                ),
                g::route(
                    binary::<
                        C,
                        T,
                        { confirmed::OPEN_EARLY },
                        { confirmed::EARLY_OPENED },
                        { confirmed::EARLY_OPEN_REJECTED },
                        { confirmed::RESULT_TAKEN },
                    >(),
                    binary::<
                        C,
                        T,
                        { confirmed::SEAL_EARLY },
                        { confirmed::EARLY_SEALED },
                        { confirmed::EARLY_SEAL_REJECTED },
                        { confirmed::RESULT_TAKEN },
                    >(),
                ),
            ),
            g::route(
                g::route(
                    binary::<
                        C,
                        T,
                        { confirmed::EARLY_HEADER_MASK },
                        { confirmed::HEADER_MASK_READY },
                        { confirmed::HEADER_MASK_REJECTED },
                        { confirmed::RESULT_TAKEN },
                    >(),
                    binary::<
                        C,
                        T,
                        { confirmed::TAKE_EARLY_REPLAY_CLAIM },
                        { confirmed::EARLY_REPLAY_CLAIM_READY },
                        { confirmed::NO_EARLY_REPLAY_CLAIM },
                        { confirmed::RESULT_TAKEN },
                    >(),
                ),
                g::route(
                    unary::<
                        C,
                        T,
                        { confirmed::DISCARD_EARLY },
                        { confirmed::EARLY_DISCARDED },
                        { confirmed::RESULT_TAKEN },
                    >(),
                    g::route(
                        binary::<
                            C,
                            T,
                            { confirmed::OPEN_HANDSHAKE },
                            { confirmed::HANDSHAKE_OPENED },
                            { confirmed::HANDSHAKE_OPEN_REJECTED },
                            { confirmed::RESULT_TAKEN },
                        >(),
                        binary::<
                            C,
                            T,
                            { confirmed::SEAL_HANDSHAKE },
                            { confirmed::HANDSHAKE_SEALED },
                            { confirmed::HANDSHAKE_SEAL_REJECTED },
                            { confirmed::RESULT_TAKEN },
                        >(),
                    ),
                ),
            ),
        ),
        g::route(
            g::route(
                g::route(
                    binary::<
                        C,
                        T,
                        { confirmed::HANDSHAKE_HEADER_MASK },
                        { confirmed::HEADER_MASK_READY },
                        { confirmed::HEADER_MASK_REJECTED },
                        { confirmed::RESULT_TAKEN },
                    >(),
                    binary::<
                        C,
                        T,
                        { confirmed::OPEN_ONE_RTT },
                        { confirmed::ONE_RTT_OPENED },
                        { confirmed::ONE_RTT_OPEN_REJECTED },
                        { confirmed::RESULT_TAKEN },
                    >(),
                ),
                g::route(
                    binary::<
                        C,
                        T,
                        { confirmed::SEAL_ONE_RTT },
                        { confirmed::ONE_RTT_SEALED },
                        { confirmed::ONE_RTT_SEAL_REJECTED },
                        { confirmed::RESULT_TAKEN },
                    >(),
                    g::route(
                        binary::<
                            C,
                            T,
                            { confirmed::ONE_RTT_HEADER_MASK },
                            { confirmed::HEADER_MASK_READY },
                            { confirmed::HEADER_MASK_REJECTED },
                            { confirmed::RESULT_TAKEN },
                        >(),
                        binary::<
                            C,
                            T,
                            { confirmed::VALIDATED_ACK },
                            { confirmed::ACK_APPLIED },
                            { confirmed::ACK_REJECTED },
                            { confirmed::RESULT_TAKEN },
                        >(),
                    ),
                ),
            ),
            g::route(
                g::route(
                    binary::<
                        C,
                        T,
                        { confirmed::MAINTAIN_KEYS },
                        { confirmed::KEYS_MAINTAINED },
                        { confirmed::MAINTENANCE_REJECTED },
                        { confirmed::RESULT_TAKEN },
                    >(),
                    binary::<
                        C,
                        T,
                        { confirmed::INITIATE_UPDATE },
                        { confirmed::KEY_UPDATED },
                        { confirmed::UPDATE_REJECTED },
                        { confirmed::RESULT_TAKEN },
                    >(),
                ),
                g::route(
                    unary::<
                        C,
                        T,
                        { confirmed::DISCARD_HANDSHAKE },
                        { confirmed::HANDSHAKE_DISCARDED },
                        { confirmed::RESULT_TAKEN },
                    >(),
                    g::route(
                        loan::<
                            C,
                            T,
                            { confirmed::LOAN_INTEGRITY },
                            { confirmed::INTEGRITY_GRANTED },
                            { confirmed::LOAN_UNAVAILABLE },
                            { confirmed::INTEGRITY_RETURNED },
                            { confirmed::INTEGRITY_RESTORED },
                            { confirmed::RESULT_TAKEN },
                        >(),
                        unary::<
                            C,
                            T,
                            { confirmed::RETIRE_REQUESTED },
                            { confirmed::RETIREMENT_PREPARED },
                            { confirmed::RESULT_TAKEN },
                        >(),
                    ),
                ),
            ),
        ),
    )
    .roll()
}
pub type ConfirmedRetirement<const C: u8, const T: u8> =
    g::Seq<g::Send<T, C, confirmed::Retired>, g::Send<C, T, confirmed::RetirementAcknowledged>>;
fn confirmed_retirement<const C: u8, const T: u8>() -> g::Program<ConfirmedRetirement<C, T>> {
    g::seq(
        g::send::<T, C, confirmed::Retired>(),
        g::send::<C, T, confirmed::RetirementAcknowledged>(),
    )
}
pub type ApplicationTrafficWork<const C: u8, const T: u8> = g::Route<
    g::Route<
        g::Route<
            BinaryFlow<
                C,
                T,
                { application::CRYPTO_INPUT },
                { application::CRYPTO_ACCEPTED },
                { application::CRYPTO_REJECTED },
                { application::RESULT_TAKEN },
            >,
            BinaryFlow<
                C,
                T,
                { application::FLIGHT_REQUESTED },
                { application::FLIGHT_READY },
                { application::AWAIT_INPUT },
                { application::RESULT_TAKEN },
            >,
        >,
        g::Route<
            BinaryFlow<
                C,
                T,
                { application::OPEN_ONE_RTT },
                { application::ONE_RTT_OPENED },
                { application::ONE_RTT_OPEN_REJECTED },
                { application::RESULT_TAKEN },
            >,
            g::Route<
                BinaryFlow<
                    C,
                    T,
                    { application::SEAL_ONE_RTT },
                    { application::ONE_RTT_SEALED },
                    { application::ONE_RTT_SEAL_REJECTED },
                    { application::RESULT_TAKEN },
                >,
                BinaryFlow<
                    C,
                    T,
                    { application::ONE_RTT_HEADER_MASK },
                    { application::HEADER_MASK_READY },
                    { application::HEADER_MASK_REJECTED },
                    { application::RESULT_TAKEN },
                >,
            >,
        >,
    >,
    g::Route<
        g::Route<
            BinaryFlow<
                C,
                T,
                { application::VALIDATED_ACK },
                { application::ACK_APPLIED },
                { application::ACK_REJECTED },
                { application::RESULT_TAKEN },
            >,
            BinaryFlow<
                C,
                T,
                { application::MAINTAIN_KEYS },
                { application::KEYS_MAINTAINED },
                { application::MAINTENANCE_REJECTED },
                { application::RESULT_TAKEN },
            >,
        >,
        g::Route<
            BinaryFlow<
                C,
                T,
                { application::INITIATE_UPDATE },
                { application::KEY_UPDATED },
                { application::UPDATE_REJECTED },
                { application::RESULT_TAKEN },
            >,
            g::Route<
                LoanFlow<
                    C,
                    T,
                    { application::LOAN_INTEGRITY },
                    { application::INTEGRITY_GRANTED },
                    { application::LOAN_UNAVAILABLE },
                    { application::INTEGRITY_RETURNED },
                    { application::INTEGRITY_RESTORED },
                    { application::RESULT_TAKEN },
                >,
                UnaryFlow<
                    C,
                    T,
                    { application::RETIRE_REQUESTED },
                    { application::RETIREMENT_PREPARED },
                    { application::RESULT_TAKEN },
                >,
            >,
        >,
    >,
>;
fn application_traffic_work<const C: u8, const T: u8>() -> g::Program<ApplicationTrafficWork<C, T>>
{
    g::route(
        g::route(
            g::route(
                binary::<
                    C,
                    T,
                    { application::CRYPTO_INPUT },
                    { application::CRYPTO_ACCEPTED },
                    { application::CRYPTO_REJECTED },
                    { application::RESULT_TAKEN },
                >(),
                binary::<
                    C,
                    T,
                    { application::FLIGHT_REQUESTED },
                    { application::FLIGHT_READY },
                    { application::AWAIT_INPUT },
                    { application::RESULT_TAKEN },
                >(),
            ),
            g::route(
                binary::<
                    C,
                    T,
                    { application::OPEN_ONE_RTT },
                    { application::ONE_RTT_OPENED },
                    { application::ONE_RTT_OPEN_REJECTED },
                    { application::RESULT_TAKEN },
                >(),
                g::route(
                    binary::<
                        C,
                        T,
                        { application::SEAL_ONE_RTT },
                        { application::ONE_RTT_SEALED },
                        { application::ONE_RTT_SEAL_REJECTED },
                        { application::RESULT_TAKEN },
                    >(),
                    binary::<
                        C,
                        T,
                        { application::ONE_RTT_HEADER_MASK },
                        { application::HEADER_MASK_READY },
                        { application::HEADER_MASK_REJECTED },
                        { application::RESULT_TAKEN },
                    >(),
                ),
            ),
        ),
        g::route(
            g::route(
                binary::<
                    C,
                    T,
                    { application::VALIDATED_ACK },
                    { application::ACK_APPLIED },
                    { application::ACK_REJECTED },
                    { application::RESULT_TAKEN },
                >(),
                binary::<
                    C,
                    T,
                    { application::MAINTAIN_KEYS },
                    { application::KEYS_MAINTAINED },
                    { application::MAINTENANCE_REJECTED },
                    { application::RESULT_TAKEN },
                >(),
            ),
            g::route(
                binary::<
                    C,
                    T,
                    { application::INITIATE_UPDATE },
                    { application::KEY_UPDATED },
                    { application::UPDATE_REJECTED },
                    { application::RESULT_TAKEN },
                >(),
                g::route(
                    loan::<
                        C,
                        T,
                        { application::LOAN_INTEGRITY },
                        { application::INTEGRITY_GRANTED },
                        { application::LOAN_UNAVAILABLE },
                        { application::INTEGRITY_RETURNED },
                        { application::INTEGRITY_RESTORED },
                        { application::RESULT_TAKEN },
                    >(),
                    unary::<
                        C,
                        T,
                        { application::RETIRE_REQUESTED },
                        { application::RETIREMENT_PREPARED },
                        { application::RESULT_TAKEN },
                    >(),
                ),
            ),
        ),
    )
}
/// Residual server early-receive/cleanup lifetime, independent of Handshake
/// key retirement. The graph admits these specific requests after that boundary;
/// the sole Provider owns and destroys actual early keys. Once discarded, opens
/// and header masks fail with KeysUnavailable; no copied presence flag grants use.
pub type RetainedEarlyReceiveWork<const C: u8, const T: u8> = g::Route<
    g::Route<
        BinaryFlow<
            C,
            T,
            { application::OPEN_EARLY },
            { application::EARLY_OPENED },
            { application::EARLY_OPEN_REJECTED },
            { application::RESULT_TAKEN },
        >,
        BinaryFlow<
            C,
            T,
            { application::EARLY_HEADER_MASK },
            { application::EARLY_HEADER_MASK_READY },
            { application::EARLY_HEADER_MASK_REJECTED },
            { application::RESULT_TAKEN },
        >,
    >,
    g::Route<
        BinaryFlow<
            C,
            T,
            { application::TAKE_EARLY_REPLAY_CLAIM },
            { application::EARLY_REPLAY_CLAIM_READY },
            { application::NO_EARLY_REPLAY_CLAIM },
            { application::RESULT_TAKEN },
        >,
        UnaryFlow<
            C,
            T,
            { application::DISCARD_EARLY },
            { application::EARLY_DISCARDED },
            { application::RESULT_TAKEN },
        >,
    >,
>;
fn retained_early_receive_work<const C: u8, const T: u8>()
-> g::Program<RetainedEarlyReceiveWork<C, T>> {
    g::route(
        g::route(
            binary::<
                C,
                T,
                { application::OPEN_EARLY },
                { application::EARLY_OPENED },
                { application::EARLY_OPEN_REJECTED },
                { application::RESULT_TAKEN },
            >(),
            binary::<
                C,
                T,
                { application::EARLY_HEADER_MASK },
                { application::EARLY_HEADER_MASK_READY },
                { application::EARLY_HEADER_MASK_REJECTED },
                { application::RESULT_TAKEN },
            >(),
        ),
        g::route(
            binary::<
                C,
                T,
                { application::TAKE_EARLY_REPLAY_CLAIM },
                { application::EARLY_REPLAY_CLAIM_READY },
                { application::NO_EARLY_REPLAY_CLAIM },
                { application::RESULT_TAKEN },
            >(),
            unary::<
                C,
                T,
                { application::DISCARD_EARLY },
                { application::EARLY_DISCARDED },
                { application::RESULT_TAKEN },
            >(),
        ),
    )
}
/// A single exclusive Provider local serializes both narrow operation groups.
/// Separate `par` futures must not share the Provider or Endpoint. Other owners
/// remain independently composed by the connection's outer `g::par`.
pub type ApplicationWork<const C: u8, const T: u8> =
    g::Roll<g::Route<ApplicationTrafficWork<C, T>, RetainedEarlyReceiveWork<C, T>>>;
pub fn application_work<const C: u8, const T: u8>() -> g::Program<ApplicationWork<C, T>> {
    g::route(
        application_traffic_work::<C, T>(),
        retained_early_receive_work::<C, T>(),
    )
    .roll()
}

pub type ApplicationRetirement<const C: u8, const T: u8> =
    g::Seq<g::Send<T, C, application::Retired>, g::Send<C, T, application::RetirementAcknowledged>>;
fn application_retirement<const C: u8, const T: u8>() -> g::Program<ApplicationRetirement<C, T>> {
    g::seq(
        g::send::<T, C, application::Retired>(),
        g::send::<C, T, application::RetirementAcknowledged>(),
    )
}
pub type TlsFlow<const C: u8, const T: u8> = g::Seq<
    g::Send<C, T, Install>,
    g::Seq<
        g::Send<T, C, Installed>,
        g::Seq<
            InitialWork<C, T>,
            g::Route<
                g::Seq<
                    g::Send<T, C, HandshakeKeyGrant>,
                    g::Seq<
                        HandshakeWork<C, T>,
                        g::Route<
                            g::Seq<
                                g::Send<T, C, ApplicationTrafficGrant>,
                                g::Seq<
                                    UnconfirmedWork<C, T>,
                                    g::Route<
                                        g::Seq<
                                            g::Send<T, C, ConfirmedGrant>,
                                            g::Seq<
                                                ConfirmedWork<C, T>,
                                                g::Route<
                                                    g::Seq<
                                                        g::Send<T, C, HandshakeRetired>,
                                                        g::Seq<
                                                            ApplicationWork<C, T>,
                                                            ApplicationRetirement<C, T>,
                                                        >,
                                                    >,
                                                    ConfirmedRetirement<C, T>,
                                                >,
                                            >,
                                        >,
                                        UnconfirmedRetirement<C, T>,
                                    >,
                                >,
                            >,
                            HandshakeRetirement<C, T>,
                        >,
                    >,
                >,
                InitialRetirement<C, T>,
            >,
        >,
    >,
>;
pub fn tls_choreography<const C: u8, const T: u8>() -> g::Program<TlsFlow<C, T>> {
    g::seq(
        g::send::<C, T, Install>(),
        g::seq(
            g::send::<T, C, Installed>(),
            g::seq(
                initial_work::<C, T>(),
                g::route(
                    g::seq(
                        g::send::<T, C, HandshakeKeyGrant>(),
                        g::seq(
                            handshake_work::<C, T>(),
                            g::route(
                                g::seq(
                                    g::send::<T, C, ApplicationTrafficGrant>(),
                                    g::seq(
                                        unconfirmed_work::<C, T>(),
                                        g::route(
                                            g::seq(
                                                g::send::<T, C, ConfirmedGrant>(),
                                                g::seq(
                                                    confirmed_work::<C, T>(),
                                                    g::route(
                                                        g::seq(
                                                            g::send::<T, C, HandshakeRetired>(),
                                                            g::seq(
                                                                application_work::<C, T>(),
                                                                application_retirement::<C, T>(),
                                                            ),
                                                        ),
                                                        confirmed_retirement::<C, T>(),
                                                    ),
                                                ),
                                            ),
                                            unconfirmed_retirement::<C, T>(),
                                        ),
                                    ),
                                ),
                                handshake_retirement::<C, T>(),
                            ),
                        ),
                    ),
                    initial_retirement::<C, T>(),
                ),
            ),
        ),
    )
}
pub fn tls_program<const R: u8>() -> RoleProgram<R> {
    project(&tls_choreography::<TLS_CLIENT, TLS_OWNER>())
}
pub fn tls_program_for<const R: u8, const C: u8, const T: u8>() -> RoleProgram<R> {
    project(&tls_choreography::<C, T>())
}
