//! Owned path/CID choreography. Frame admission, reservation, adapter completion,
//! and current-timer observations are different causal operations. The owner
//! selects the result route from the real kernels, before replying to its peer.
use hibana::{
    g,
    runtime::program::{RoleProgram, project},
};
pub const PATH_CLIENT: u8 = 30;
pub const PATH_OWNER: u8 = 31;
pub const INSTALL: u8 = 160;
pub type Install = g::Msg<INSTALL, [u8; 16]>;
pub const INSTALLED: u8 = 161;
pub type Installed = g::Msg<INSTALLED, [u8; 16]>;
pub const RESERVE: u8 = 162;
pub type Reserve = g::Msg<RESERVE, [u8; 16]>;
pub const RESERVE_CONTROL: u8 = 163;
pub type ReserveControl = g::Msg<RESERVE_CONTROL, [u8; 16]>;
pub const RESERVED: u8 = 164;
pub type Reserved = g::Msg<RESERVED, [u8; 16]>;
pub const ADAPTER_COMPLETE: u8 = 165;
pub type AdapterComplete = g::Msg<ADAPTER_COMPLETE, [u8; 16]>;
pub const LEARN_PEER_CID: u8 = 166;
pub type LearnPeerCid = g::Msg<LEARN_PEER_CID, [u8; 16]>;
pub const APPLY_RETRY: u8 = 167;
pub type ApplyRetry = g::Msg<APPLY_RETRY, [u8; 16]>;
pub const EARLY_PREFLIGHT: u8 = 168;
pub type EarlyPreflight = g::Msg<EARLY_PREFLIGHT, [u8; 16]>;
pub const EARLY_ADMISSION: u8 = 169;
pub type EarlyAdmission = g::Msg<EARLY_ADMISSION, [u8; 16]>;
pub const EARLY_RELEASE: u8 = 170;
pub type EarlyRelease = g::Msg<EARLY_RELEASE, [u8; 16]>;
pub const FRAME: u8 = 171;
pub type Frame = g::Msg<FRAME, [u8; 16]>;
pub const ACK: u8 = 172;
pub type Ack = g::Msg<ACK, [u8; 16]>;
pub const LOST: u8 = 173;
pub type Lost = g::Msg<LOST, [u8; 16]>;
pub const PTO: u8 = 174;
pub type Pto = g::Msg<PTO, [u8; 16]>;
pub const CHECK_RESET: u8 = 175;
pub type CheckReset = g::Msg<CHECK_RESET, [u8; 16]>;
pub const OBSERVE_TIMER: u8 = 176;
pub type ObserveTimer = g::Msg<OBSERVE_TIMER, [u8; 16]>;
pub const TIMEOUT: u8 = 177;
pub type Timeout = g::Msg<TIMEOUT, [u8; 16]>;
pub const ISSUE_CID: u8 = 178;
pub type IssueCid = g::Msg<ISSUE_CID, [u8; 16]>;
pub const HANDSHAKE: u8 = 179;
pub type Handshake = g::Msg<HANDSHAKE, [u8; 16]>;
pub const RETIRE_PATH: u8 = 180;
pub type RetirePath = g::Msg<RETIRE_PATH, [u8; 16]>;
pub const INSPECT: u8 = 181;
pub type Inspect = g::Msg<INSPECT, [u8; 16]>;
pub const APPLIED: u8 = 182;
pub type Applied = g::Msg<APPLIED, [u8; 16]>;
pub const REJECTED: u8 = 183;
pub type Rejected = g::Msg<REJECTED, [u8; 16]>;
pub const RESULT_TAKEN: u8 = 184;
pub type ResultTaken = g::Msg<RESULT_TAKEN, [u8; 16]>;
pub const RETIRE_REQUESTED: u8 = 185;
pub type RetireRequested = g::Msg<RETIRE_REQUESTED, [u8; 16]>;
pub const RETIRED: u8 = 186;
pub type Retired = g::Msg<RETIRED, [u8; 16]>;
pub const RETIREMENT_ACKNOWLEDGED: u8 = 187;
pub type RetirementAcknowledged = g::Msg<RETIREMENT_ACKNOWLEDGED, [u8; 16]>;
pub const ABANDONMENT_REQUIRED: u8 = 188;
pub type AbandonmentRequired = g::Msg<ABANDONMENT_REQUIRED, [u8; 16]>;
pub const ABANDON_COMPLETE: u8 = 189;
pub type AbandonComplete = g::Msg<ABANDON_COMPLETE, [u8; 16]>;
/// Lost deliveries must settle before Recovery can mint AbandonComplete. The
/// continuation cannot return to receive, transmit, or timer work prematurely.
pub type AbandonmentContinuation<const C: u8, const O: u8> = g::Seq<
    g::Send<C, O, ResultTaken>,
    g::Seq<
        g::Roll<g::Route<Operation<C, O, Lost>, g::Send<C, O, AbandonComplete>>>,
        g::Seq<g::Send<O, C, Applied>, g::Send<C, O, ResultTaken>>,
    >,
>;
pub type MayAbandon<const C: u8, const O: u8, M> = g::Seq<
    g::Send<C, O, M>,
    g::Route<
        g::Seq<g::Send<O, C, AbandonmentRequired>, AbandonmentContinuation<C, O>>,
        g::Seq<
            g::Route<g::Send<O, C, Applied>, g::Send<O, C, Rejected>>,
            g::Send<C, O, ResultTaken>,
        >,
    >,
>;
fn may_abandon<const C: u8, const O: u8, M: g::Message<Payload = [u8; 16]>>()
-> g::Program<MayAbandon<C, O, M>> {
    g::seq(
        g::send::<C, O, M>(),
        g::route(
            g::seq(
                g::send::<O, C, AbandonmentRequired>(),
                g::seq(
                    g::send::<C, O, ResultTaken>(),
                    g::seq(
                        g::route(
                            operation::<C, O, Lost>(),
                            g::send::<C, O, AbandonComplete>(),
                        )
                        .roll(),
                        g::seq(g::send::<O, C, Applied>(), g::send::<C, O, ResultTaken>()),
                    ),
                ),
            ),
            g::seq(
                g::route(g::send::<O, C, Applied>(), g::send::<O, C, Rejected>()),
                g::send::<C, O, ResultTaken>(),
            ),
        ),
    )
}
pub const PROBE_TIMEOUT: u8 = 191;
pub type ProbeTimeout = g::Msg<PROBE_TIMEOUT, [u8; 16]>;
pub const SERVER_RETRY: u8 = 190;
pub type ServerRetry = g::Msg<SERVER_RETRY, [u8; 16]>;
pub type Operation<const C: u8, const O: u8, M> = g::Seq<
    g::Send<C, O, M>,
    g::Seq<g::Route<g::Send<O, C, Applied>, g::Send<O, C, Rejected>>, g::Send<C, O, ResultTaken>>,
>;
pub type ReservationFlow<const C: u8, const O: u8, M> = g::Seq<
    g::Send<C, O, M>,
    g::Route<
        g::Seq<
            g::Send<O, C, Reserved>,
            g::Seq<g::Send<C, O, ResultTaken>, Operation<C, O, AdapterComplete>>,
        >,
        g::Seq<g::Send<O, C, Rejected>, g::Send<C, O, ResultTaken>>,
    >,
>;
pub type PathFlow<const C: u8, const O: u8> = g::Seq<
    g::Send<C, O, Install>,
    g::Seq<g::Send<O, C, Installed>, g::Seq<
        g::Roll<g::Route<
            Operation<C, O, ServerRetry>,
            g::Route<
                Operation<C, O, LearnPeerCid>,
                g::Route<
                    Operation<C, O, ApplyRetry>,
                    g::Route<
                        Operation<C, O, EarlyPreflight>,
                        g::Route<
                            Operation<C, O, EarlyAdmission>,
                            g::Route<
                                Operation<C, O, EarlyRelease>,
                                g::Route<
                                    MayAbandon<C, O, Frame>,
                                    g::Route<
                                        Operation<C, O, Ack>,
                                        g::Route<
                                            Operation<C, O, Lost>,
                                            g::Route<
                                                Operation<C, O, Pto>,
                                                g::Route<
                                                    Operation<C, O, ProbeTimeout>,
                                                    g::Route<
                                                        Operation<C, O, CheckReset>,
                                                        g::Route<
                                                            Operation<C, O, ObserveTimer>,
                                                            g::Route<
                                                                MayAbandon<C, O, Timeout>,
                                                                g::Route<
                                                                    Operation<C, O, IssueCid>,
                                                                    g::Route<
                                                                        Operation<C, O, Handshake>,
                                                                        g::Route<
                                                                            MayAbandon<C, O, RetirePath>,
                                                                            g::Route<
                                                                                Operation<C, O, Inspect>,
                                                                                g::Route<ReservationFlow<C, O, Reserve>, g::Route<ReservationFlow<C, O, ReserveControl>, g::Send<C, O, RetireRequested>>>,
                                                                            >,
                                                                        >,
                                                                    >,
                                                                >,
                                                            >,
                                                        >,
                                                    >,
                                                >,
                                            >,
                                        >,
                                    >,
                                >,
                            >,
                        >,
                    >,
                >,
            >,
        >>,
        g::Seq<g::Send<O, C, Retired>, g::Send<C, O, RetirementAcknowledged>>,
    >>,
>;
fn operation<const C: u8, const O: u8, M: g::Message<Payload = [u8; 16]>>()
-> g::Program<Operation<C, O, M>> {
    g::seq(
        g::send::<C, O, M>(),
        g::seq(
            g::route(g::send::<O, C, Applied>(), g::send::<O, C, Rejected>()),
            g::send::<C, O, ResultTaken>(),
        ),
    )
}
fn reservation<const C: u8, const O: u8, M: g::Message<Payload = [u8; 16]>>()
-> g::Program<ReservationFlow<C, O, M>> {
    g::seq(
        g::send::<C, O, M>(),
        g::route(
            g::seq(
                g::send::<O, C, Reserved>(),
                g::seq(
                    g::send::<C, O, ResultTaken>(),
                    operation::<C, O, AdapterComplete>(),
                ),
            ),
            g::seq(g::send::<O, C, Rejected>(), g::send::<C, O, ResultTaken>()),
        ),
    )
}
pub fn path_choreography<const C: u8, const O: u8>() -> g::Program<PathFlow<C, O>> {
    let work = g::route(
        operation::<C, O, ServerRetry>(),
        g::route(
            operation::<C, O, LearnPeerCid>(),
            g::route(
                operation::<C, O, ApplyRetry>(),
                g::route(
                    operation::<C, O, EarlyPreflight>(),
                    g::route(
                        operation::<C, O, EarlyAdmission>(),
                        g::route(
                            operation::<C, O, EarlyRelease>(),
                            g::route(
                                may_abandon::<C, O, Frame>(),
                                g::route(
                                    operation::<C, O, Ack>(),
                                    g::route(
                                        operation::<C, O, Lost>(),
                                        g::route(
                                            operation::<C, O, Pto>(),
                                            g::route(
                                                operation::<C, O, ProbeTimeout>(),
                                                g::route(
                                                    operation::<C, O, CheckReset>(),
                                                    g::route(
                                                        operation::<C, O, ObserveTimer>(),
                                                        g::route(
                                                            may_abandon::<C, O, Timeout>(),
                                                            g::route(
                                                                operation::<C, O, IssueCid>(),
                                                                g::route(
                                                                    operation::<C, O, Handshake>(),
                                                                    g::route(
                                                                        may_abandon::<C, O, RetirePath>(),
                                                                        g::route(
                                                                            operation::<C, O, Inspect>(),
                                                                            g::route(reservation::<C, O, Reserve>(), g::route(reservation::<C, O, ReserveControl>(), g::send::<C, O, RetireRequested>())),
                                                                        ),
                                                                    ),
                                                                ),
                                                            ),
                                                        ),
                                                    ),
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    ).roll();
    g::seq(
        g::send::<C, O, Install>(),
        g::seq(
            g::send::<O, C, Installed>(),
            g::seq(
                work,
                g::seq(
                    g::send::<O, C, Retired>(),
                    g::send::<C, O, RetirementAcknowledged>(),
                ),
            ),
        ),
    )
}
pub fn path_program<const ROLE: u8>() -> RoleProgram<ROLE> {
    project(&path_choreography::<PATH_CLIENT, PATH_OWNER>())
}
