//! The packet-key service's actual global choreography.
//!
//! `roll` currently permits elastic reentry even after a following continuation.
//! Therefore Retired is NOT a graph-only sealing theorem. The implementation
//! consumes the live task and command receiver after that terminal exchange.
//! Dropped/cancelled tasks destroy the owned key and close command admission.

use hibana::{
    g,
    runtime::program::{RoleProgram, project},
};

pub const KEY_CLIENT: u8 = 16;
pub const KEY_CRYPTO: u8 = 17;
pub const INSTALL: u8 = 170;
pub type Install = g::Msg<INSTALL, u64>;
pub const INSTALLED: u8 = 171;
pub type Installed = g::Msg<INSTALLED, u64>;
pub const OPEN: u8 = 172;
pub type Open = g::Msg<OPEN, [u8; 16]>;
pub const OPENED: u8 = 173;
pub type Opened = g::Msg<OPENED, [u8; 16]>;
pub const OPEN_FAILED: u8 = 175;
pub type OpenFailed = g::Msg<OPEN_FAILED, [u8; 16]>;
pub const SEAL: u8 = 176;
pub type Seal = g::Msg<SEAL, [u8; 16]>;
pub const SEALED: u8 = 177;
pub type Sealed = g::Msg<SEALED, [u8; 16]>;
pub const SEAL_FAILED: u8 = 178;
pub type SealFailed = g::Msg<SEAL_FAILED, [u8; 16]>;
pub const HEADER_MASK: u8 = 179;
pub type HeaderMask = g::Msg<HEADER_MASK, [u8; 16]>;
pub const HEADER_MASK_READY: u8 = 180;
pub type HeaderMaskReady = g::Msg<HEADER_MASK_READY, [u8; 16]>;
pub const HEADER_MASK_FAILED: u8 = 181;
pub type HeaderMaskFailed = g::Msg<HEADER_MASK_FAILED, [u8; 16]>;
pub const RETIRE_REQUESTED: u8 = 182;
pub type RetireRequested = g::Msg<RETIRE_REQUESTED, [u8; 16]>;
pub const RETIRED: u8 = 183;
pub type Retired = g::Msg<RETIRED, [u8; 16]>;
pub const RETIREMENT_ACKNOWLEDGED: u8 = 184;
pub type RetirementAcknowledged = g::Msg<RETIREMENT_ACKNOWLEDGED, [u8; 16]>;
pub const RESULT_TAKEN: u8 = 185;
pub type ResultTaken = g::Msg<RESULT_TAKEN, [u8; 16]>;
pub const REKEY_INITIAL: u8 = 186;
pub type RekeyInitial = g::Msg<REKEY_INITIAL, [u8; 16]>;
pub const INITIAL_REKEYED: u8 = 187;
pub type InitialRekeyed = g::Msg<INITIAL_REKEYED, [u8; 16]>;
pub const INITIAL_REKEY_FAILED: u8 = 188;
pub type InitialRekeyFailed = g::Msg<INITIAL_REKEY_FAILED, [u8; 16]>;

pub type OpenFlow<const C: u8, const K: u8> = g::Seq<
    g::Send<C, K, Open>,
    g::Seq<g::Route<g::Send<K, C, Opened>, g::Send<K, C, OpenFailed>>, g::Send<C, K, ResultTaken>>,
>;
pub type SealFlow<const C: u8, const K: u8> = g::Seq<
    g::Send<C, K, Seal>,
    g::Seq<g::Route<g::Send<K, C, Sealed>, g::Send<K, C, SealFailed>>, g::Send<C, K, ResultTaken>>,
>;
pub type MaskFlow<const C: u8, const K: u8> = g::Seq<
    g::Send<C, K, HeaderMask>,
    g::Seq<
        g::Route<g::Send<K, C, HeaderMaskReady>, g::Send<K, C, HeaderMaskFailed>>,
        g::Send<C, K, ResultTaken>,
    >,
>;
pub type RekeyFlow<const C: u8, const K: u8> = g::Seq<
    g::Send<C, K, RekeyInitial>,
    g::Seq<
        g::Route<g::Send<K, C, InitialRekeyed>, g::Send<K, C, InitialRekeyFailed>>,
        g::Send<C, K, ResultTaken>,
    >,
>;
pub type KeyFlow<const C: u8, const K: u8> = g::Seq<
    g::Send<C, K, Install>,
    g::Seq<
        g::Send<K, C, Installed>,
        g::Seq<
            g::Roll<
                g::Route<
                    OpenFlow<C, K>,
                    g::Route<
                        SealFlow<C, K>,
                        g::Route<
                            MaskFlow<C, K>,
                            g::Route<RekeyFlow<C, K>, g::Send<C, K, RetireRequested>>,
                        >,
                    >,
                >,
            >,
            g::Seq<g::Send<K, C, Retired>, g::Send<C, K, RetirementAcknowledged>>,
        >,
    >,
>;

/// The concrete fragment can be composed under one `g::par` with distinct
/// role facets. This preserves the one-global-session guarantee boundary.
pub fn key_choreography<const CLIENT: u8, const CRYPTO: u8>() -> g::Program<KeyFlow<CLIENT, CRYPTO>>
{
    let open = g::seq(
        g::send::<CLIENT, CRYPTO, Open>(),
        g::seq(
            g::route(
                g::send::<CRYPTO, CLIENT, Opened>(),
                g::send::<CRYPTO, CLIENT, OpenFailed>(),
            ),
            g::send::<CLIENT, CRYPTO, ResultTaken>(),
        ),
    );
    let seal = g::seq(
        g::send::<CLIENT, CRYPTO, Seal>(),
        g::seq(
            g::route(
                g::send::<CRYPTO, CLIENT, Sealed>(),
                g::send::<CRYPTO, CLIENT, SealFailed>(),
            ),
            g::send::<CLIENT, CRYPTO, ResultTaken>(),
        ),
    );
    let mask = g::seq(
        g::send::<CLIENT, CRYPTO, HeaderMask>(),
        g::seq(
            g::route(
                g::send::<CRYPTO, CLIENT, HeaderMaskReady>(),
                g::send::<CRYPTO, CLIENT, HeaderMaskFailed>(),
            ),
            g::send::<CLIENT, CRYPTO, ResultTaken>(),
        ),
    );
    let work = g::route(
        open,
        g::route(
            seal,
            g::route(
                mask,
                g::route(
                    g::seq(
                        g::send::<CLIENT, CRYPTO, RekeyInitial>(),
                        g::seq(
                            g::route(
                                g::send::<CRYPTO, CLIENT, InitialRekeyed>(),
                                g::send::<CRYPTO, CLIENT, InitialRekeyFailed>(),
                            ),
                            g::send::<CLIENT, CRYPTO, ResultTaken>(),
                        ),
                    ),
                    g::send::<CLIENT, CRYPTO, RetireRequested>(),
                ),
            ),
        ),
    )
    .roll();
    g::seq(
        g::send::<CLIENT, CRYPTO, Install>(),
        g::seq(
            g::send::<CRYPTO, CLIENT, Installed>(),
            g::seq(
                work,
                g::seq(
                    g::send::<CRYPTO, CLIENT, Retired>(),
                    g::send::<CLIENT, CRYPTO, RetirementAcknowledged>(),
                ),
            ),
        ),
    )
}

/// Project the default standalone service (roles 16 and 17).
pub fn key_program<const ROLE: u8>() -> RoleProgram<ROLE> {
    project(&key_choreography::<KEY_CLIENT, KEY_CRYPTO>())
}
/// Project a standalone instance with explicit role facets.
pub fn key_program_for<const ROLE: u8, const CLIENT: u8, const CRYPTO: u8>() -> RoleProgram<ROLE> {
    project(&key_choreography::<CLIENT, CRYPTO>())
}
