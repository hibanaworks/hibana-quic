//! Whole-Provider choreography. All keys and coupled 1-RTT state stay inside
//! one owner; distinct request messages express each operation and evidence.
//! Intrinsic result branches are selected by actual Provider operations.
use hibana::{
    g,
    runtime::program::{RoleProgram, project},
};
pub const TLS_CLIENT: u8 = 24;
pub const TLS_OWNER: u8 = 25;
pub const CRYPTO_INPUT: u8 = 100;
pub type CryptoInput = g::Msg<{ CRYPTO_INPUT }, [u8; 16]>;
pub const CRYPTO_ACCEPTED: u8 = 101;
pub type CryptoAccepted = g::Msg<{ CRYPTO_ACCEPTED }, [u8; 16]>;
pub const CRYPTO_REJECTED: u8 = 102;
pub type CryptoRejected = g::Msg<{ CRYPTO_REJECTED }, [u8; 16]>;
pub const CRYPTO_OUTPUT: u8 = 103;
pub type CryptoOutput = g::Msg<{ CRYPTO_OUTPUT }, [u8; 16]>;
pub const CRYPTO_OUTPUT_READY: u8 = 104;
pub type CryptoOutputReady = g::Msg<{ CRYPTO_OUTPUT_READY }, [u8; 16]>;
pub const NO_CRYPTO_OUTPUT: u8 = 105;
pub type NoCryptoOutput = g::Msg<{ NO_CRYPTO_OUTPUT }, [u8; 16]>;
pub const OPEN_HANDSHAKE: u8 = 106;
pub type OpenHandshake = g::Msg<{ OPEN_HANDSHAKE }, [u8; 16]>;
pub const HANDSHAKE_OPENED: u8 = 107;
pub type HandshakeOpened = g::Msg<{ HANDSHAKE_OPENED }, [u8; 16]>;
pub const HANDSHAKE_OPEN_REJECTED: u8 = 108;
pub type HandshakeOpenRejected = g::Msg<{ HANDSHAKE_OPEN_REJECTED }, [u8; 16]>;
pub const OPEN_ONE_RTT: u8 = 109;
pub type OpenOneRtt = g::Msg<{ OPEN_ONE_RTT }, [u8; 16]>;
pub const ONE_RTT_OPENED: u8 = 110;
pub type OneRttOpened = g::Msg<{ ONE_RTT_OPENED }, [u8; 16]>;
pub const ONE_RTT_OPEN_REJECTED: u8 = 111;
pub type OneRttOpenRejected = g::Msg<{ ONE_RTT_OPEN_REJECTED }, [u8; 16]>;
pub const SEAL_HANDSHAKE: u8 = 112;
pub type SealHandshake = g::Msg<{ SEAL_HANDSHAKE }, [u8; 16]>;
pub const HANDSHAKE_SEALED: u8 = 113;
pub type HandshakeSealed = g::Msg<{ HANDSHAKE_SEALED }, [u8; 16]>;
pub const HANDSHAKE_SEAL_REJECTED: u8 = 114;
pub type HandshakeSealRejected = g::Msg<{ HANDSHAKE_SEAL_REJECTED }, [u8; 16]>;
pub const SEAL_ONE_RTT: u8 = 115;
pub type SealOneRtt = g::Msg<{ SEAL_ONE_RTT }, [u8; 16]>;
pub const ONE_RTT_SEALED: u8 = 116;
pub type OneRttSealed = g::Msg<{ ONE_RTT_SEALED }, [u8; 16]>;
pub const ONE_RTT_SEAL_REJECTED: u8 = 117;
pub type OneRttSealRejected = g::Msg<{ ONE_RTT_SEAL_REJECTED }, [u8; 16]>;
pub const HEADER_MASK: u8 = 118;
pub type HeaderMask = g::Msg<{ HEADER_MASK }, [u8; 16]>;
pub const HEADER_MASK_READY: u8 = 119;
pub type HeaderMaskReady = g::Msg<{ HEADER_MASK_READY }, [u8; 16]>;
pub const HEADER_MASK_REJECTED: u8 = 120;
pub type HeaderMaskRejected = g::Msg<{ HEADER_MASK_REJECTED }, [u8; 16]>;
pub const CONFIRM_HANDSHAKE: u8 = 121;
pub type ConfirmHandshake = g::Msg<{ CONFIRM_HANDSHAKE }, [u8; 16]>;
pub const HANDSHAKE_CONFIRMED: u8 = 122;
pub type HandshakeConfirmed = g::Msg<{ HANDSHAKE_CONFIRMED }, [u8; 16]>;
pub const CONFIRMATION_REJECTED: u8 = 123;
pub type ConfirmationRejected = g::Msg<{ CONFIRMATION_REJECTED }, [u8; 16]>;
pub const VALIDATED_ACK: u8 = 124;
pub type ValidatedAck = g::Msg<{ VALIDATED_ACK }, [u8; 16]>;
pub const ACK_APPLIED: u8 = 125;
pub type AckApplied = g::Msg<{ ACK_APPLIED }, [u8; 16]>;
pub const ACK_REJECTED: u8 = 126;
pub type AckRejected = g::Msg<{ ACK_REJECTED }, [u8; 16]>;
pub const MAINTAIN_KEYS: u8 = 127;
pub type MaintainKeys = g::Msg<{ MAINTAIN_KEYS }, [u8; 16]>;
pub const KEYS_MAINTAINED: u8 = 128;
pub type KeysMaintained = g::Msg<{ KEYS_MAINTAINED }, [u8; 16]>;
pub const MAINTENANCE_REJECTED: u8 = 129;
pub type MaintenanceRejected = g::Msg<{ MAINTENANCE_REJECTED }, [u8; 16]>;
pub const INITIATE_UPDATE: u8 = 130;
pub type InitiateUpdate = g::Msg<{ INITIATE_UPDATE }, [u8; 16]>;
pub const KEY_UPDATED: u8 = 131;
pub type KeyUpdated = g::Msg<{ KEY_UPDATED }, [u8; 16]>;
pub const UPDATE_REJECTED: u8 = 132;
pub type UpdateRejected = g::Msg<{ UPDATE_REJECTED }, [u8; 16]>;
pub const DISCARD_HANDSHAKE: u8 = 133;
pub type DiscardHandshake = g::Msg<{ DISCARD_HANDSHAKE }, [u8; 16]>;
pub const HANDSHAKE_DISCARDED: u8 = 134;
pub type HandshakeDiscarded = g::Msg<{ HANDSHAKE_DISCARDED }, [u8; 16]>;
pub const LOAN_INTEGRITY: u8 = 135;
pub type LoanIntegrity = g::Msg<{ LOAN_INTEGRITY }, [u8; 16]>;
pub const INTEGRITY_GRANTED: u8 = 136;
pub type IntegrityGranted = g::Msg<{ INTEGRITY_GRANTED }, [u8; 16]>;
pub const LOAN_UNAVAILABLE: u8 = 137;
pub type LoanUnavailable = g::Msg<{ LOAN_UNAVAILABLE }, [u8; 16]>;
pub const INTEGRITY_RETURNED: u8 = 138;
pub type IntegrityReturned = g::Msg<{ INTEGRITY_RETURNED }, [u8; 16]>;
pub const INTEGRITY_RESTORED: u8 = 139;
pub type IntegrityRestored = g::Msg<{ INTEGRITY_RESTORED }, [u8; 16]>;
pub const RESULT_TAKEN: u8 = 140;
pub type ResultTaken = g::Msg<{ RESULT_TAKEN }, [u8; 16]>;
pub const RETIRE_REQUESTED: u8 = 141;
pub type RetireRequested = g::Msg<{ RETIRE_REQUESTED }, [u8; 16]>;
pub const RETIRED: u8 = 142;
pub type Retired = g::Msg<{ RETIRED }, [u8; 16]>;
pub const RETIREMENT_ACKNOWLEDGED: u8 = 143;
pub type RetirementAcknowledged = g::Msg<{ RETIREMENT_ACKNOWLEDGED }, [u8; 16]>;
pub const INSTALL: u8 = 144;
pub type Install = g::Msg<{ INSTALL }, [u8; 16]>;
pub const INSTALLED: u8 = 145;
pub type Installed = g::Msg<{ INSTALLED }, [u8; 16]>;
pub type CryptoInputFlow<const C: u8, const T: u8> = g::Seq<
    g::Send<C, T, CryptoInput>,
    g::Seq<
        g::Route<g::Send<T, C, CryptoAccepted>, g::Send<T, C, CryptoRejected>>,
        g::Send<C, T, ResultTaken>,
    >,
>;
pub type CryptoOutputFlow<const C: u8, const T: u8> = g::Seq<
    g::Send<C, T, CryptoOutput>,
    g::Seq<
        g::Route<g::Send<T, C, CryptoOutputReady>, g::Send<T, C, NoCryptoOutput>>,
        g::Send<C, T, ResultTaken>,
    >,
>;
pub type OpenHandshakeFlow<const C: u8, const T: u8> = g::Seq<
    g::Send<C, T, OpenHandshake>,
    g::Seq<
        g::Route<g::Send<T, C, HandshakeOpened>, g::Send<T, C, HandshakeOpenRejected>>,
        g::Send<C, T, ResultTaken>,
    >,
>;
pub type OpenOneRttFlow<const C: u8, const T: u8> = g::Seq<
    g::Send<C, T, OpenOneRtt>,
    g::Seq<
        g::Route<g::Send<T, C, OneRttOpened>, g::Send<T, C, OneRttOpenRejected>>,
        g::Send<C, T, ResultTaken>,
    >,
>;
pub type SealHandshakeFlow<const C: u8, const T: u8> = g::Seq<
    g::Send<C, T, SealHandshake>,
    g::Seq<
        g::Route<g::Send<T, C, HandshakeSealed>, g::Send<T, C, HandshakeSealRejected>>,
        g::Send<C, T, ResultTaken>,
    >,
>;
pub type SealOneRttFlow<const C: u8, const T: u8> = g::Seq<
    g::Send<C, T, SealOneRtt>,
    g::Seq<
        g::Route<g::Send<T, C, OneRttSealed>, g::Send<T, C, OneRttSealRejected>>,
        g::Send<C, T, ResultTaken>,
    >,
>;
pub type HeaderMaskFlow<const C: u8, const T: u8> = g::Seq<
    g::Send<C, T, HeaderMask>,
    g::Seq<
        g::Route<g::Send<T, C, HeaderMaskReady>, g::Send<T, C, HeaderMaskRejected>>,
        g::Send<C, T, ResultTaken>,
    >,
>;
pub type ConfirmHandshakeFlow<const C: u8, const T: u8> = g::Seq<
    g::Send<C, T, ConfirmHandshake>,
    g::Seq<
        g::Route<g::Send<T, C, HandshakeConfirmed>, g::Send<T, C, ConfirmationRejected>>,
        g::Send<C, T, ResultTaken>,
    >,
>;
pub type ValidatedAckFlow<const C: u8, const T: u8> = g::Seq<
    g::Send<C, T, ValidatedAck>,
    g::Seq<
        g::Route<g::Send<T, C, AckApplied>, g::Send<T, C, AckRejected>>,
        g::Send<C, T, ResultTaken>,
    >,
>;
pub type MaintainKeysFlow<const C: u8, const T: u8> = g::Seq<
    g::Send<C, T, MaintainKeys>,
    g::Seq<
        g::Route<g::Send<T, C, KeysMaintained>, g::Send<T, C, MaintenanceRejected>>,
        g::Send<C, T, ResultTaken>,
    >,
>;
pub type InitiateUpdateFlow<const C: u8, const T: u8> = g::Seq<
    g::Send<C, T, InitiateUpdate>,
    g::Seq<
        g::Route<g::Send<T, C, KeyUpdated>, g::Send<T, C, UpdateRejected>>,
        g::Send<C, T, ResultTaken>,
    >,
>;
pub type DiscardFlow<const C: u8, const T: u8> = g::Seq<
    g::Send<C, T, DiscardHandshake>,
    g::Seq<g::Send<T, C, HandshakeDiscarded>, g::Send<C, T, ResultTaken>>,
>;
pub type LoanFlow<const C: u8, const T: u8> = g::Seq<
    g::Send<C, T, LoanIntegrity>,
    g::Route<
        g::Seq<
            g::Send<T, C, IntegrityGranted>,
            g::Seq<
                g::Send<C, T, ResultTaken>,
                g::Seq<
                    g::Send<C, T, IntegrityReturned>,
                    g::Seq<g::Send<T, C, IntegrityRestored>, g::Send<C, T, ResultTaken>>,
                >,
            >,
        >,
        g::Seq<g::Send<T, C, LoanUnavailable>, g::Send<C, T, ResultTaken>>,
    >,
>;
pub const OPEN_EARLY: u8 = 146;
pub type OpenEarly = g::Msg<{ OPEN_EARLY }, [u8; 16]>;
pub const EARLY_OPENED: u8 = 147;
pub type EarlyOpened = g::Msg<{ EARLY_OPENED }, [u8; 16]>;
pub const EARLY_OPEN_REJECTED: u8 = 148;
pub type EarlyOpenRejected = g::Msg<{ EARLY_OPEN_REJECTED }, [u8; 16]>;
pub const SEAL_EARLY: u8 = 149;
pub type SealEarly = g::Msg<{ SEAL_EARLY }, [u8; 16]>;
pub const EARLY_SEALED: u8 = 150;
pub type EarlySealed = g::Msg<{ EARLY_SEALED }, [u8; 16]>;
pub const EARLY_SEAL_REJECTED: u8 = 151;
pub type EarlySealRejected = g::Msg<{ EARLY_SEAL_REJECTED }, [u8; 16]>;
pub const EARLY_HEADER_MASK: u8 = 152;
pub type EarlyHeaderMask = g::Msg<{ EARLY_HEADER_MASK }, [u8; 16]>;
pub const EARLY_HEADER_MASK_READY: u8 = 153;
pub type EarlyHeaderMaskReady = g::Msg<{ EARLY_HEADER_MASK_READY }, [u8; 16]>;
pub const EARLY_HEADER_MASK_REJECTED: u8 = 154;
pub type EarlyHeaderMaskRejected = g::Msg<{ EARLY_HEADER_MASK_REJECTED }, [u8; 16]>;
pub const TAKE_EARLY_REPLAY_CLAIM: u8 = 155;
pub type TakeEarlyReplayClaim = g::Msg<{ TAKE_EARLY_REPLAY_CLAIM }, [u8; 16]>;
pub const EARLY_REPLAY_CLAIM: u8 = 156;
pub type EarlyReplayClaim = g::Msg<{ EARLY_REPLAY_CLAIM }, [u8; 16]>;
pub const NO_EARLY_REPLAY_CLAIM: u8 = 157;
pub type NoEarlyReplayClaim = g::Msg<{ NO_EARLY_REPLAY_CLAIM }, [u8; 16]>;
pub const DISCARD_EARLY: u8 = 158;
pub type DiscardEarly = g::Msg<{ DISCARD_EARLY }, [u8; 16]>;
pub const EARLY_DISCARDED: u8 = 159;
pub type EarlyDiscarded = g::Msg<{ EARLY_DISCARDED }, [u8; 16]>;
pub type OpenEarlyFlow<const C: u8, const T: u8> = g::Seq<
    g::Send<C, T, OpenEarly>,
    g::Seq<
        g::Route<g::Send<T, C, EarlyOpened>, g::Send<T, C, EarlyOpenRejected>>,
        g::Send<C, T, ResultTaken>,
    >,
>;
pub type SealEarlyFlow<const C: u8, const T: u8> = g::Seq<
    g::Send<C, T, SealEarly>,
    g::Seq<
        g::Route<g::Send<T, C, EarlySealed>, g::Send<T, C, EarlySealRejected>>,
        g::Send<C, T, ResultTaken>,
    >,
>;
pub type EarlyHeaderMaskFlow<const C: u8, const T: u8> = g::Seq<
    g::Send<C, T, EarlyHeaderMask>,
    g::Seq<
        g::Route<g::Send<T, C, EarlyHeaderMaskReady>, g::Send<T, C, EarlyHeaderMaskRejected>>,
        g::Send<C, T, ResultTaken>,
    >,
>;
pub type TakeEarlyReplayClaimFlow<const C: u8, const T: u8> = g::Seq<
    g::Send<C, T, TakeEarlyReplayClaim>,
    g::Seq<
        g::Route<g::Send<T, C, EarlyReplayClaim>, g::Send<T, C, NoEarlyReplayClaim>>,
        g::Send<C, T, ResultTaken>,
    >,
>;
pub type DiscardEarlyFlow<const C: u8, const T: u8> = g::Seq<
    g::Send<C, T, DiscardEarly>,
    g::Seq<g::Send<T, C, EarlyDiscarded>, g::Send<C, T, ResultTaken>>,
>;
pub type EarlyFlow<const C: u8, const T: u8> = g::Route<
    g::Route<OpenEarlyFlow<C, T>, SealEarlyFlow<C, T>>,
    g::Route<
        EarlyHeaderMaskFlow<C, T>,
        g::Route<TakeEarlyReplayClaimFlow<C, T>, DiscardEarlyFlow<C, T>>,
    >,
>;
pub type TlsFlow<const C: u8, const T: u8> = g::Seq<
    g::Send<C, T, Install>,
    g::Seq<
        g::Send<T, C, Installed>,
        g::Seq<
            g::Roll<
                g::Route<
                    g::Route<
                        g::Route<
                            g::Route<
                                CryptoInputFlow<C, T>,
                                g::Route<CryptoOutputFlow<C, T>, OpenHandshakeFlow<C, T>>,
                            >,
                            g::Route<
                                g::Route<OpenOneRttFlow<C, T>, SealHandshakeFlow<C, T>>,
                                g::Route<SealOneRttFlow<C, T>, HeaderMaskFlow<C, T>>,
                            >,
                        >,
                        g::Route<
                            g::Route<
                                ConfirmHandshakeFlow<C, T>,
                                g::Route<ValidatedAckFlow<C, T>, MaintainKeysFlow<C, T>>,
                            >,
                            g::Route<
                                g::Route<InitiateUpdateFlow<C, T>, DiscardFlow<C, T>>,
                                g::Route<LoanFlow<C, T>, g::Send<C, T, RetireRequested>>,
                            >,
                        >,
                    >,
                    EarlyFlow<C, T>,
                >,
            >,
            g::Seq<g::Send<T, C, Retired>, g::Send<C, T, RetirementAcknowledged>>,
        >,
    >,
>;
pub fn tls_choreography<const C: u8, const T: u8>() -> g::Program<TlsFlow<C, T>> {
    let crypto_input = g::seq(
        g::send::<C, T, CryptoInput>(),
        g::seq(
            g::route(
                g::send::<T, C, CryptoAccepted>(),
                g::send::<T, C, CryptoRejected>(),
            ),
            g::send::<C, T, ResultTaken>(),
        ),
    );
    let crypto_output = g::seq(
        g::send::<C, T, CryptoOutput>(),
        g::seq(
            g::route(
                g::send::<T, C, CryptoOutputReady>(),
                g::send::<T, C, NoCryptoOutput>(),
            ),
            g::send::<C, T, ResultTaken>(),
        ),
    );
    let open_handshake = g::seq(
        g::send::<C, T, OpenHandshake>(),
        g::seq(
            g::route(
                g::send::<T, C, HandshakeOpened>(),
                g::send::<T, C, HandshakeOpenRejected>(),
            ),
            g::send::<C, T, ResultTaken>(),
        ),
    );
    let open_one_rtt = g::seq(
        g::send::<C, T, OpenOneRtt>(),
        g::seq(
            g::route(
                g::send::<T, C, OneRttOpened>(),
                g::send::<T, C, OneRttOpenRejected>(),
            ),
            g::send::<C, T, ResultTaken>(),
        ),
    );
    let seal_handshake = g::seq(
        g::send::<C, T, SealHandshake>(),
        g::seq(
            g::route(
                g::send::<T, C, HandshakeSealed>(),
                g::send::<T, C, HandshakeSealRejected>(),
            ),
            g::send::<C, T, ResultTaken>(),
        ),
    );
    let seal_one_rtt = g::seq(
        g::send::<C, T, SealOneRtt>(),
        g::seq(
            g::route(
                g::send::<T, C, OneRttSealed>(),
                g::send::<T, C, OneRttSealRejected>(),
            ),
            g::send::<C, T, ResultTaken>(),
        ),
    );
    let header_mask = g::seq(
        g::send::<C, T, HeaderMask>(),
        g::seq(
            g::route(
                g::send::<T, C, HeaderMaskReady>(),
                g::send::<T, C, HeaderMaskRejected>(),
            ),
            g::send::<C, T, ResultTaken>(),
        ),
    );
    let confirm_handshake = g::seq(
        g::send::<C, T, ConfirmHandshake>(),
        g::seq(
            g::route(
                g::send::<T, C, HandshakeConfirmed>(),
                g::send::<T, C, ConfirmationRejected>(),
            ),
            g::send::<C, T, ResultTaken>(),
        ),
    );
    let validated_ack = g::seq(
        g::send::<C, T, ValidatedAck>(),
        g::seq(
            g::route(
                g::send::<T, C, AckApplied>(),
                g::send::<T, C, AckRejected>(),
            ),
            g::send::<C, T, ResultTaken>(),
        ),
    );
    let maintain_keys = g::seq(
        g::send::<C, T, MaintainKeys>(),
        g::seq(
            g::route(
                g::send::<T, C, KeysMaintained>(),
                g::send::<T, C, MaintenanceRejected>(),
            ),
            g::send::<C, T, ResultTaken>(),
        ),
    );
    let initiate_update = g::seq(
        g::send::<C, T, InitiateUpdate>(),
        g::seq(
            g::route(
                g::send::<T, C, KeyUpdated>(),
                g::send::<T, C, UpdateRejected>(),
            ),
            g::send::<C, T, ResultTaken>(),
        ),
    );
    let discard = g::seq(
        g::send::<C, T, DiscardHandshake>(),
        g::seq(
            g::send::<T, C, HandshakeDiscarded>(),
            g::send::<C, T, ResultTaken>(),
        ),
    );
    let loan = g::seq(
        g::send::<C, T, LoanIntegrity>(),
        g::route(
            g::seq(
                g::send::<T, C, IntegrityGranted>(),
                g::seq(
                    g::send::<C, T, ResultTaken>(),
                    g::seq(
                        g::send::<C, T, IntegrityReturned>(),
                        g::seq(
                            g::send::<T, C, IntegrityRestored>(),
                            g::send::<C, T, ResultTaken>(),
                        ),
                    ),
                ),
            ),
            g::seq(
                g::send::<T, C, LoanUnavailable>(),
                g::send::<C, T, ResultTaken>(),
            ),
        ),
    );
    let ordinary = g::route(
        g::route(
            g::route(crypto_input, g::route(crypto_output, open_handshake)),
            g::route(
                g::route(open_one_rtt, seal_handshake),
                g::route(seal_one_rtt, header_mask),
            ),
        ),
        g::route(
            g::route(confirm_handshake, g::route(validated_ack, maintain_keys)),
            g::route(
                g::route(initiate_update, discard),
                g::route(loan, g::send::<C, T, RetireRequested>()),
            ),
        ),
    );
    let work = g::route(
        ordinary,
        g::route(
            g::route(
                g::seq(
                    g::send::<C, T, OpenEarly>(),
                    g::seq(
                        g::route(
                            g::send::<T, C, EarlyOpened>(),
                            g::send::<T, C, EarlyOpenRejected>(),
                        ),
                        g::send::<C, T, ResultTaken>(),
                    ),
                ),
                g::seq(
                    g::send::<C, T, SealEarly>(),
                    g::seq(
                        g::route(
                            g::send::<T, C, EarlySealed>(),
                            g::send::<T, C, EarlySealRejected>(),
                        ),
                        g::send::<C, T, ResultTaken>(),
                    ),
                ),
            ),
            g::route(
                g::seq(
                    g::send::<C, T, EarlyHeaderMask>(),
                    g::seq(
                        g::route(
                            g::send::<T, C, EarlyHeaderMaskReady>(),
                            g::send::<T, C, EarlyHeaderMaskRejected>(),
                        ),
                        g::send::<C, T, ResultTaken>(),
                    ),
                ),
                g::route(
                    g::seq(
                        g::send::<C, T, TakeEarlyReplayClaim>(),
                        g::seq(
                            g::route(
                                g::send::<T, C, EarlyReplayClaim>(),
                                g::send::<T, C, NoEarlyReplayClaim>(),
                            ),
                            g::send::<C, T, ResultTaken>(),
                        ),
                    ),
                    g::seq(
                        g::send::<C, T, DiscardEarly>(),
                        g::seq(
                            g::send::<T, C, EarlyDiscarded>(),
                            g::send::<C, T, ResultTaken>(),
                        ),
                    ),
                ),
            ),
        ),
    )
    .roll();
    g::seq(
        g::send::<C, T, Install>(),
        g::seq(
            g::send::<T, C, Installed>(),
            g::seq(
                work,
                g::seq(
                    g::send::<T, C, Retired>(),
                    g::send::<C, T, RetirementAcknowledged>(),
                ),
            ),
        ),
    )
}
pub fn tls_program<const R: u8>() -> RoleProgram<R> {
    project(&tls_choreography::<TLS_CLIENT, TLS_OWNER>())
}
