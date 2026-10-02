//! Recovery's owned-resource choreography. Distinct client/owner facets compose
//! under the connection's `g::par`; neither facet offers across another domain.
//! Real arithmetic/admission chooses Applied versus Rejected. Final retirement
//! also consumes the running actors, rather than claiming elastic roll seals it.
use hibana::{
    g,
    runtime::program::{RoleProgram, project},
};

pub const RECOVERY_CLIENT: u8 = 26;
pub const RECOVERY_OWNER: u8 = 27;
pub const INSTALL: u8 = 200;
pub type Install = g::Msg<INSTALL, [u8; 16]>;
pub const INSTALLED: u8 = 201;
pub type Installed = g::Msg<INSTALLED, [u8; 16]>;
pub const RESERVE: u8 = 202;
pub type Reserve = g::Msg<RESERVE, [u8; 16]>;
pub const ADAPTER_COMPLETE: u8 = 203;
pub type AdapterComplete = g::Msg<ADAPTER_COMPLETE, [u8; 16]>;
pub const CANCEL: u8 = 204;
pub type Cancel = g::Msg<CANCEL, [u8; 16]>;
pub const ACK: u8 = 205;
pub type Ack = g::Msg<ACK, [u8; 16]>;
pub const DETECT_LOSS: u8 = 206;
pub type DetectLoss = g::Msg<DETECT_LOSS, [u8; 16]>;
pub const FLIGHT: u8 = 207;
pub type Flight = g::Msg<FLIGHT, [u8; 16]>;
pub const DISCARD_SPACE: u8 = 208;
pub type DiscardSpace = g::Msg<DISCARD_SPACE, [u8; 16]>;
pub const REQUEUE_SPACE: u8 = 209;
pub type RequeueSpace = g::Msg<REQUEUE_SPACE, [u8; 16]>;
pub const RECLAIM: u8 = 210;
pub type Reclaim = g::Msg<RECLAIM, [u8; 16]>;
pub const RESET_PATH: u8 = 211;
pub type ResetPath = g::Msg<RESET_PATH, [u8; 16]>;
pub const INSPECT: u8 = 212;
pub type Inspect = g::Msg<INSPECT, [u8; 16]>;
pub const TIMER: u8 = 219;
pub type Timer = g::Msg<TIMER, [u8; 16]>;
pub const KEY_PTO: u8 = 220;
pub type KeyPto = g::Msg<KEY_PTO, [u8; 16]>;
pub const ECN_MARKING: u8 = 221;
pub type EcnMarking = g::Msg<ECN_MARKING, [u8; 16]>;
pub const REJECT_ZERO_RTT: u8 = 222;
pub type RejectZeroRtt = g::Msg<REJECT_ZERO_RTT, [u8; 16]>;
pub const APPLIED: u8 = 213;
pub type Applied = g::Msg<APPLIED, [u8; 16]>;
pub const REJECTED: u8 = 214;
pub type Rejected = g::Msg<REJECTED, [u8; 16]>;
pub const RESULT_TAKEN: u8 = 215;
pub type ResultTaken = g::Msg<RESULT_TAKEN, [u8; 16]>;
pub const RETIRE_REQUESTED: u8 = 216;
pub type RetireRequested = g::Msg<RETIRE_REQUESTED, [u8; 16]>;
pub const RETIRED: u8 = 217;
pub type Retired = g::Msg<RETIRED, [u8; 16]>;
pub const RETIREMENT_ACKNOWLEDGED: u8 = 218;
pub type RetirementAcknowledged = g::Msg<RETIREMENT_ACKNOWLEDGED, [u8; 16]>;

pub type Operation<const C: u8, const O: u8, M> = g::Seq<
    g::Send<C, O, M>,
    g::Seq<g::Route<g::Send<O, C, Applied>, g::Send<O, C, Rejected>>, g::Send<C, O, ResultTaken>>,
>;
pub type RecoveryFlow<const C: u8, const O: u8> = g::Seq<
    g::Send<C, O, Install>,
    g::Seq<
        g::Send<O, C, Installed>,
        g::Seq<
            g::Roll<
                g::Route<
                    Operation<C, O, Reserve>,
                    g::Route<
                        Operation<C, O, AdapterComplete>,
                        g::Route<
                            Operation<C, O, Cancel>,
                            g::Route<
                                Operation<C, O, Ack>,
                                g::Route<
                                    Operation<C, O, DetectLoss>,
                                    g::Route<
                                        Operation<C, O, Flight>,
                                        g::Route<
                                            Operation<C, O, DiscardSpace>,
                                            g::Route<
                                                Operation<C, O, RequeueSpace>,
                                                g::Route<
                                                    Operation<C, O, Reclaim>,
                                                    g::Route<
                                                        Operation<C, O, ResetPath>,
                                                        g::Route<
                                                            Operation<C, O, Inspect>,
                                                            g::Route<
                                                                Operation<C, O, Timer>,
                                                                g::Route<
                                                                    Operation<C, O, KeyPto>,
                                                                    g::Route<
                                                                        Operation<C, O, EcnMarking>,
                                                                        g::Route<
                                                                            Operation<
                                                                                C,
                                                                                O,
                                                                                RejectZeroRtt,
                                                                            >,
                                                                            g::Send<
                                                                                C,
                                                                                O,
                                                                                RetireRequested,
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
            g::Seq<g::Send<O, C, Retired>, g::Send<C, O, RetirementAcknowledged>>,
        >,
    >,
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
pub fn recovery_choreography<const C: u8, const O: u8>() -> g::Program<RecoveryFlow<C, O>> {
    let work = g::route(
        operation::<C, O, Reserve>(),
        g::route(
            operation::<C, O, AdapterComplete>(),
            g::route(
                operation::<C, O, Cancel>(),
                g::route(
                    operation::<C, O, Ack>(),
                    g::route(
                        operation::<C, O, DetectLoss>(),
                        g::route(
                            operation::<C, O, Flight>(),
                            g::route(
                                operation::<C, O, DiscardSpace>(),
                                g::route(
                                    operation::<C, O, RequeueSpace>(),
                                    g::route(
                                        operation::<C, O, Reclaim>(),
                                        g::route(
                                            operation::<C, O, ResetPath>(),
                                            g::route(
                                                operation::<C, O, Inspect>(),
                                                g::route(
                                                    operation::<C, O, Timer>(),
                                                    g::route(
                                                        operation::<C, O, KeyPto>(),
                                                        g::route(
                                                            operation::<C, O, EcnMarking>(),
                                                            g::route(
                                                                operation::<C, O, RejectZeroRtt>(),
                                                                g::send::<C, O, RetireRequested>(),
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
    )
    .roll();
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
pub fn recovery_program<const ROLE: u8>() -> RoleProgram<ROLE> {
    project(&recovery_choreography::<RECOVERY_CLIENT, RECOVERY_OWNER>())
}
