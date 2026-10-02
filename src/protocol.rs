//! Internal service choreography executed by the single-owner QUIC driver.
//! The separate contract_program remains a diagnostic fixture.
//!
//! Independent services have their own guarded repeat scopes *inside* raw
//! `g::par`. No outer repeat/join forces a quiet UDP receive service to finish
//! before transmit or timer work can proceed. Recovery owns both Tx accounting
//! and timer decisions; one Endpoint is polled sequentially by that owner.

use hibana::{
    g,
    runtime::program::{RoleProgram, project},
};

pub const INGRESS: u8 = 0;
pub const PACKET: u8 = 1;
pub const APPLICATION: u8 = 2;
pub const RECOVERY: u8 = 3;
pub const ADAPTER: u8 = 4;
pub const TIMER: u8 = 5;

pub type RxDatagram = g::Msg<10, u32>;
pub type RxProcessed = g::Msg<11, u32>;
pub type TxRequest = g::Msg<20, u32>;
pub type TxReserved = g::Msg<21, u32>;
pub type TxResult = g::Msg<22, u32>;
pub type TxComplete = g::Msg<23, u32>;
pub type TimerExpired = g::Msg<30, u64>;
pub type TimerHandled = g::Msg<31, u64>;

pub type InitialKeyInstalled = g::Msg<70, u32>;
pub type InitialKeyUse = g::Msg<71, u32>;
pub type InitialKeyUsed = g::Msg<72, u32>;
pub type InitialKeyRetired = g::Msg<73, u32>;
pub type HandshakeKeyInstalled = g::Msg<80, u32>;
pub type HandshakeKeyUse = g::Msg<81, u32>;
pub type HandshakeKeyUsed = g::Msg<82, u32>;
pub type HandshakeKeyRetired = g::Msg<83, u32>;
pub type OneRttKeyInstalled = g::Msg<90, u32>;
pub type OneRttKeyUse = g::Msg<91, u32>;
pub type OneRttKeyUsed = g::Msg<92, u32>;
pub type OneRttKeyRetired = g::Msg<93, u32>;

pub type AckReleaseRequest = g::Msg<100, [u8; 8]>;
pub type AckReleaseCompleted = g::Msg<101, [u8; 8]>;
pub type DeliveryRequest = g::Msg<102, [u8; 16]>;
pub type DeliveryCompleted = g::Msg<103, [u8; 16]>;
pub type StreamRetiredRequest = g::Msg<104, [u8; 12]>;
pub type StreamRetiredAcknowledged = g::Msg<105, [u8; 12]>;

// Early data has a separate key and quarantine/release authority. It cannot
// pass an ordinary ReceiveTicket to ACK or stream-delivery services.
pub type EarlyKeyInstalled = g::Msg<110, u32>;
pub type EarlyKeyUse = g::Msg<111, u32>;
pub type EarlyKeyUsed = g::Msg<112, u32>;
pub type EarlyKeyRetired = g::Msg<113, u32>;
pub type EarlyAuthenticated = g::Msg<114, u32>;
pub type EarlyReceived = g::Msg<115, u32>;
pub type EarlyBufferRequest = g::Msg<116, [u8; 16]>;
pub type EarlyBufferCompleted = g::Msg<117, [u8; 16]>;
pub type VerifiedFinished = g::Msg<118, u32>;
pub type VerifiedFinishedAccepted = g::Msg<119, u32>;
pub type EarlyReleaseRequest = g::Msg<120, [u8; 12]>;
pub type EarlyReleaseCompleted = g::Msg<121, [u8; 12]>;

pub type PathEffectRequest = g::Msg<130, [u8; 16]>;
pub type PathEffectCompleted = g::Msg<131, [u8; 16]>;
pub type CidInstallRequest = g::Msg<132, [u8; 16]>;
pub type CidInstallCompleted = g::Msg<133, [u8; 16]>;
pub type CidRetirementRequest = g::Msg<134, [u8; 16]>;
pub type CidRetirementCompleted = g::Msg<135, [u8; 16]>;
pub type PathReserved = g::Msg<136, [u8; 16]>;
pub type PathAccepted = g::Msg<137, [u8; 16]>;
pub type PathCommitted = g::Msg<138, [u8; 16]>;
pub type PathRejected = g::Msg<139, [u8; 16]>;
pub type CidAdvertisementRequest = g::Msg<140, [u8; 16]>;
pub type CidAdvertisementCompleted = g::Msg<141, [u8; 16]>;

/// Tested fixed budget for the complete service profile. Public messages are
/// at most 16 bytes; all role attachments fit this many carrier ports.
pub const SERVICE_PORTS: usize = 48;
pub const SERVICE_MESSAGE_BYTES: usize = 16;
pub const SERVICE_SLAB_BYTES: usize = 32 * 1024;

/// Project the same raw-par service image for each internal role. Message
/// payloads are small internal descriptor IDs, never a QUIC wire envelope.
pub fn service_program<const ROLE: u8>() -> RoleProgram<ROLE> {
    let receive = g::seq(
        g::send::<INGRESS, PACKET, RxDatagram>(),
        g::seq(
            g::send::<PACKET, RECOVERY, AuthenticatedPacket>(),
            g::send::<PACKET, INGRESS, RxProcessed>(),
        ),
    )
    .roll();
    let transmit = g::seq(
        g::send::<APPLICATION, RECOVERY, TxRequest>(),
        g::seq(
            g::send::<RECOVERY, ADAPTER, TxReserved>(),
            g::seq(
                g::send::<ADAPTER, RECOVERY, TxResult>(),
                g::send::<RECOVERY, APPLICATION, TxComplete>(),
            ),
        ),
    )
    .roll();
    let timer = g::seq(
        g::send::<TIMER, RECOVERY, TimerExpired>(),
        g::send::<RECOVERY, TIMER, TimerHandled>(),
    )
    .roll();
    // The installed grant is an actual prerequisite at both participating
    // endpoints. A guarded route permits retirement even before the first use.
    // The driver ledger makes Retired terminal; the repeated wire route alone
    // does not establish the lifetime of a cryptographic key.
    macro_rules! key_service {
        ($installed:ty, $use:ty, $used:ty, $retired:ty) => {
            g::seq(
                g::send::<RECOVERY, PACKET, $installed>(),
                g::route(
                    g::seq(
                        g::send::<RECOVERY, PACKET, $use>(),
                        g::send::<PACKET, RECOVERY, $used>(),
                    ),
                    g::send::<RECOVERY, PACKET, $retired>(),
                )
                .roll(),
            )
        };
    }
    let initial = key_service!(
        InitialKeyInstalled,
        InitialKeyUse,
        InitialKeyUsed,
        InitialKeyRetired
    );
    let handshake = key_service!(
        HandshakeKeyInstalled,
        HandshakeKeyUse,
        HandshakeKeyUsed,
        HandshakeKeyRetired
    );
    let one_rtt = key_service!(
        OneRttKeyInstalled,
        OneRttKeyUse,
        OneRttKeyUsed,
        OneRttKeyRetired
    );
    let ack_release = g::seq(
        g::send::<PACKET, RECOVERY, AckReleaseRequest>(),
        g::send::<RECOVERY, PACKET, AckReleaseCompleted>(),
    )
    .roll();
    let delivery = g::seq(
        g::send::<PACKET, APPLICATION, DeliveryRequest>(),
        g::send::<APPLICATION, PACKET, DeliveryCompleted>(),
    )
    .roll();
    let stream_retirement = g::seq(
        g::send::<APPLICATION, RECOVERY, StreamRetiredRequest>(),
        g::send::<RECOVERY, APPLICATION, StreamRetiredAcknowledged>(),
    )
    .roll();
    let early_key = key_service!(
        EarlyKeyInstalled,
        EarlyKeyUse,
        EarlyKeyUsed,
        EarlyKeyRetired
    );
    let early_receive = g::seq(
        g::send::<INGRESS, PACKET, EarlyAuthenticated>(),
        g::send::<PACKET, INGRESS, EarlyReceived>(),
    )
    .roll();
    let early_buffer = g::seq(
        g::send::<PACKET, APPLICATION, EarlyBufferRequest>(),
        g::send::<APPLICATION, PACKET, EarlyBufferCompleted>(),
    )
    .roll();
    let early_release = g::seq(
        g::send::<PACKET, APPLICATION, VerifiedFinished>(),
        g::seq(
            g::send::<APPLICATION, PACKET, VerifiedFinishedAccepted>(),
            g::seq(
                g::send::<PACKET, APPLICATION, EarlyReleaseRequest>(),
                g::send::<APPLICATION, PACKET, EarlyReleaseCompleted>(),
            )
            .roll(),
        ),
    );
    // Receive authority crosses these independent services through checked
    // driver tickets; g::par alone does not establish packet authentication.
    let ordinary = g::par(
        g::par(receive, g::par(transmit, timer)),
        g::par(
            g::par(initial, g::par(handshake, one_rtt)),
            g::par(ack_release, g::par(delivery, stream_retirement)),
        ),
    );
    let path_effect = g::seq(
        g::send::<PACKET, RECOVERY, PathEffectRequest>(),
        g::send::<RECOVERY, PACKET, PathEffectCompleted>(),
    )
    .roll();
    let cid_install = g::seq(
        g::send::<PACKET, RECOVERY, CidInstallRequest>(),
        g::send::<RECOVERY, PACKET, CidInstallCompleted>(),
    )
    .roll();
    let cid_retirement = g::seq(
        g::send::<PACKET, RECOVERY, CidRetirementRequest>(),
        g::send::<RECOVERY, PACKET, CidRetirementCompleted>(),
    )
    .roll();
    let path_send = g::seq(
        g::send::<RECOVERY, ADAPTER, PathReserved>(),
        g::route(
            g::seq(
                g::send::<ADAPTER, RECOVERY, PathAccepted>(),
                g::send::<RECOVERY, ADAPTER, PathCommitted>(),
            ),
            g::send::<ADAPTER, RECOVERY, PathRejected>(),
        ),
    )
    .roll();
    let cid_advertisement = g::seq(
        g::send::<RECOVERY, PACKET, CidAdvertisementRequest>(),
        g::send::<PACKET, RECOVERY, CidAdvertisementCompleted>(),
    )
    .roll();
    let path_services = g::par(
        g::par(path_effect, g::par(cid_install, cid_retirement)),
        g::par(path_send, cid_advertisement),
    );
    let early_services = g::par(
        g::par(early_key, early_receive),
        g::par(early_buffer, early_release),
    );
    project(&g::par(ordinary, g::par(path_services, early_services)))
}

// Explicitly distinct protocol messages are used by the forbidden-transition
// tests. These establish local ordering; cryptographic authentication, lease
// ledger validation and accounting arithmetic remain separate obligations.
pub type InstallKey = g::Msg<40, u32>;
pub type AuthenticatedPacket = g::Msg<41, u32>;
pub type StreamDelivery = g::Msg<42, u32>;
pub type ValidatedAck = g::Msg<43, u32>;
pub type ReservationGranted = g::Msg<44, u32>;
pub type PublishPacket = g::Msg<45, u32>;
pub type AdapterResult = g::Msg<46, u32>;
pub type ReservationReleased = g::Msg<47, u32>;

/// One typed fixture covering key-before-authentication,
/// authentication-before-delivery/credit, reservation-before-publication, and
/// adapter-result-before-reservation-reuse. Roles: key authority 0, packet 1,
/// streams 2, Recovery 3, publisher 4, adapter 5, application 6.
pub fn contract_program<const ROLE: u8>() -> RoleProgram<ROLE> {
    let program = g::seq(
        g::send::<0, 1, InstallKey>(),
        g::seq(
            g::send::<1, 2, AuthenticatedPacket>(),
            g::seq(
                g::send::<2, 6, StreamDelivery>(),
                g::seq(
                    g::send::<2, 3, ValidatedAck>(),
                    g::seq(
                        g::send::<3, 4, ReservationGranted>(),
                        g::seq(
                            g::send::<4, 5, PublishPacket>(),
                            g::seq(
                                g::send::<5, 3, AdapterResult>(),
                                g::send::<3, 0, ReservationReleased>(),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    );
    project(&program)
}
