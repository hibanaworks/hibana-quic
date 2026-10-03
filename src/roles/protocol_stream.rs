//! Stream ownership, authentication gates, and publication continuations.
//! Normal application operations occur only after AppReady. Early transmission
//! has its own owner-minted TLS gate and distinct PrepareEarly edge. A prepared
//! frame cannot escape reservation/cancellation and actual publication settlement.
//! Stage rolls contain their real exit requests; owner replies authorize the next stage.
use hibana::{
    g,
    runtime::program::{RoleProgram, project},
};
pub const STREAM_CLIENT: u8 = 28;
pub const STREAM_OWNER: u8 = 29;
pub const INSTALL: u8 = 40;
pub type Install = g::Msg<{ INSTALL }, [u8; 16]>;
pub const INSTALLED: u8 = 41;
pub type Installed = g::Msg<{ INSTALLED }, [u8; 16]>;
pub const PEER_READY: u8 = 42;
pub type PeerReady = g::Msg<{ PEER_READY }, [u8; 16]>;
pub const EARLY_READY: u8 = 43;
pub type EarlyReady = g::Msg<{ EARLY_READY }, [u8; 16]>;
pub const EARLY_SEND_READY: u8 = 44;
pub type EarlySendReady = g::Msg<{ EARLY_SEND_READY }, [u8; 16]>;
pub const EARLY_SEND_INSTALLED: u8 = 45;
pub type EarlySendInstalled = g::Msg<{ EARLY_SEND_INSTALLED }, [u8; 16]>;
pub const ACKNOWLEDGE: u8 = 46;
pub type Acknowledge = g::Msg<{ ACKNOWLEDGE }, [u8; 16]>;
pub const ACKNOWLEDGE_RESET: u8 = 47;
pub type AcknowledgeReset = g::Msg<{ ACKNOWLEDGE_RESET }, [u8; 16]>;
pub const CONSUME: u8 = 48;
pub type Consume = g::Msg<{ CONSUME }, [u8; 16]>;
pub const DELIVER: u8 = 49;
pub type Deliver = g::Msg<{ DELIVER }, [u8; 16]>;
pub const DELIVER_EARLY: u8 = 50;
pub type DeliverEarly = g::Msg<{ DELIVER_EARLY }, [u8; 16]>;
pub const ENQUEUE_EARLY: u8 = 51;
pub type EnqueueEarly = g::Msg<{ ENQUEUE_EARLY }, [u8; 16]>;
pub const INSPECT: u8 = 52;
pub type Inspect = g::Msg<{ INSPECT }, [u8; 16]>;
pub const INSPECT_EARLY: u8 = 53;
pub type InspectEarly = g::Msg<{ INSPECT_EARLY }, [u8; 16]>;
pub const LOST: u8 = 54;
pub type Lost = g::Msg<{ LOST }, [u8; 16]>;
pub const OPEN: u8 = 55;
pub type Open = g::Msg<{ OPEN }, [u8; 16]>;
pub const PROBE: u8 = 56;
pub type Probe = g::Msg<{ PROBE }, [u8; 16]>;
pub const READ: u8 = 57;
pub type Read = g::Msg<{ READ }, [u8; 16]>;
pub const RESET: u8 = 58;
pub type Reset = g::Msg<{ RESET }, [u8; 16]>;
pub const RETIRE_STREAM: u8 = 59;
pub type RetireStream = g::Msg<{ RETIRE_STREAM }, [u8; 16]>;
pub const SEND: u8 = 60;
pub type Send = g::Msg<{ SEND }, [u8; 16]>;
pub const STOP: u8 = 61;
pub type Stop = g::Msg<{ STOP }, [u8; 16]>;
pub const PREPARE: u8 = 62;
pub type Prepare = g::Msg<{ PREPARE }, [u8; 16]>;
pub const PREPARE_EARLY: u8 = 63;
pub type PrepareEarly = g::Msg<{ PREPARE_EARLY }, [u8; 16]>;
pub const RESERVE: u8 = 64;
pub type Reserve = g::Msg<{ RESERVE }, [u8; 16]>;
pub const CANCEL_PREPARED: u8 = 65;
pub type CancelPrepared = g::Msg<{ CANCEL_PREPARED }, [u8; 16]>;
pub const ADAPTER_ACCEPTED: u8 = 66;
pub type AdapterAccepted = g::Msg<{ ADAPTER_ACCEPTED }, [u8; 16]>;
pub const ADAPTER_REJECTED: u8 = 67;
pub type AdapterRejected = g::Msg<{ ADAPTER_REJECTED }, [u8; 16]>;
pub const CANCEL_TRANSMISSION: u8 = 68;
pub type CancelTransmission = g::Msg<{ CANCEL_TRANSMISSION }, [u8; 16]>;
pub const APPLIED: u8 = 69;
pub type Applied = g::Msg<{ APPLIED }, [u8; 16]>;
pub const REJECTED: u8 = 70;
pub type Rejected = g::Msg<{ REJECTED }, [u8; 16]>;
pub const RESULT_TAKEN: u8 = 71;
pub type ResultTaken = g::Msg<{ RESULT_TAKEN }, [u8; 16]>;
pub const RETIRE_REQUESTED: u8 = 72;
pub type RetireRequested = g::Msg<{ RETIRE_REQUESTED }, [u8; 16]>;
pub const RETIRED: u8 = 73;
pub type Retired = g::Msg<{ RETIRED }, [u8; 16]>;
pub const RETIREMENT_ACKNOWLEDGED: u8 = 74;
pub type RetirementAcknowledged = g::Msg<{ RETIREMENT_ACKNOWLEDGED }, [u8; 16]>;
pub const FRAME_PREPARED: u8 = 75;
pub type FramePrepared = g::Msg<{ FRAME_PREPARED }, [u8; 16]>;
pub const NO_FRAME: u8 = 76;
pub type NoFrame = g::Msg<{ NO_FRAME }, [u8; 16]>;
pub const RESERVED: u8 = 77;
pub type Reserved = g::Msg<{ RESERVED }, [u8; 16]>;
pub const READY: u8 = 78;
pub type Ready = g::Msg<{ READY }, [u8; 16]>;
pub const EARLY_REQUIRED: u8 = 79;
pub type EarlyRequired = g::Msg<{ EARLY_REQUIRED }, [u8; 16]>;
pub const EARLY_APPLIED: u8 = 80;
pub type EarlyApplied = g::Msg<{ EARLY_APPLIED }, [u8; 16]>;
pub const SELECTION_CANCELLED: u8 = 81;
pub type SelectionCancelled = g::Msg<{ SELECTION_CANCELLED }, [u8; 16]>;
pub const PUBLICATION_SETTLED: u8 = 82;
pub type PublicationSettled = g::Msg<{ PUBLICATION_SETTLED }, [u8; 16]>;
pub const RETRY: u8 = 83;
pub type Retry = g::Msg<{ RETRY }, [u8; 16]>;
pub type ReplyFlow<const C: u8, const O: u8, M> =
    g::Seq<g::Send<O, C, M>, g::Send<C, O, ResultTaken>>;
/// The owner chooses its outcome only after the concrete request arrives.
/// The client must acknowledge that result before this operation can reenter.
pub type OperationResult<const C: u8, const O: u8> =
    g::Seq<g::Route<g::Send<O, C, Applied>, g::Send<O, C, Rejected>>, g::Send<C, O, ResultTaken>>;
pub type Operation<const C: u8, const O: u8, M> = g::Seq<g::Send<C, O, M>, OperationResult<C, O>>;
pub type CompletionAttempts<const C: u8, const O: u8> = g::Route<
    Operation<C, O, AdapterAccepted>,
    g::Route<Operation<C, O, AdapterRejected>, Operation<C, O, CancelTransmission>>,
>;
pub type CompletionFlow<const C: u8, const O: u8> =
    g::Seq<g::Roll<CompletionAttempts<C, O>>, g::Send<O, C, PublicationSettled>>;
pub type ReservationAttempts<const C: u8, const O: u8> =
    g::Route<Operation<C, O, Reserve>, Operation<C, O, CancelPrepared>>;
pub type ReservationFlow<const C: u8, const O: u8> = g::Seq<
    g::Roll<ReservationAttempts<C, O>>,
    g::Route<
        g::Seq<g::Send<O, C, Reserved>, CompletionFlow<C, O>>,
        g::Send<O, C, SelectionCancelled>,
    >,
>;
pub type PrepareFlow<const C: u8, const O: u8, M> = g::Seq<
    g::Send<C, O, M>,
    g::Route<
        g::Seq<ReplyFlow<C, O, FramePrepared>, ReservationFlow<C, O>>,
        g::Route<ReplyFlow<C, O, NoFrame>, ReplyFlow<C, O, Rejected>>,
    >,
>;
pub type Retirement<const C: u8, const O: u8> = g::Seq<
    g::Send<C, O, RetireRequested>,
    g::Seq<g::Send<O, C, Retired>, g::Send<C, O, RetirementAcknowledged>>,
>;
/// Only these requests have the same result and return to the same active
/// roll. Preparation and retirement keep their own mandatory continuations.
pub type ActiveRequests<const C: u8, const O: u8> = g::Route<
    g::Route<
        g::Route<g::Send<C, O, Probe>, g::Send<C, O, Deliver>>,
        g::Route<g::Send<C, O, DeliverEarly>, g::Send<C, O, Acknowledge>>,
    >,
    g::Route<
        g::Route<
            g::Route<g::Send<C, O, Lost>, g::Send<C, O, Open>>,
            g::Route<g::Send<C, O, Send>, g::Send<C, O, Read>>,
        >,
        g::Route<
            g::Route<g::Send<C, O, Consume>, g::Send<C, O, AcknowledgeReset>>,
            g::Route<
                g::Route<g::Send<C, O, Reset>, g::Send<C, O, Stop>>,
                g::Route<g::Send<C, O, RetireStream>, g::Send<C, O, Inspect>>,
            >,
        >,
    >,
>;
pub type ActiveWork<const C: u8, const O: u8> = g::Route<
    g::Seq<ActiveRequests<C, O>, OperationResult<C, O>>,
    g::Route<PrepareFlow<C, O, Prepare>, g::Send<C, O, RetireRequested>>,
>;
/// Admission requests select a different continuation and are deliberately
/// outside the requests that share an ordinary result exchange.
pub type BootstrapRequests<const C: u8, const O: u8> = g::Route<
    g::Route<g::Send<C, O, Probe>, g::Send<C, O, Deliver>>,
    g::Route<
        g::Route<g::Send<C, O, Acknowledge>, g::Send<C, O, Lost>>,
        g::Route<g::Send<C, O, Retry>, g::Send<C, O, Inspect>>,
    >,
>;
pub type BootstrapWork<const C: u8, const O: u8> = g::Route<
    g::Seq<BootstrapRequests<C, O>, OperationResult<C, O>>,
    g::Route<
        g::Send<C, O, PeerReady>,
        g::Route<g::Send<C, O, EarlySendReady>, g::Send<C, O, RetireRequested>>,
    >,
>;
pub type EarlyWork<const C: u8, const O: u8> = g::Route<
    g::Route<
        g::Route<Operation<C, O, Probe>, Operation<C, O, Deliver>>,
        g::Route<
            Operation<C, O, Acknowledge>,
            g::Route<
                g::Route<Operation<C, O, Lost>, Operation<C, O, Retry>>,
                Operation<C, O, Inspect>,
            >,
        >,
    >,
    g::Route<
        g::Route<Operation<C, O, EnqueueEarly>, Operation<C, O, InspectEarly>>,
        g::Route<
            PrepareFlow<C, O, PrepareEarly>,
            g::Route<g::Send<C, O, PeerReady>, g::Send<C, O, RetireRequested>>,
        >,
    >,
>;
pub type RetirementSuffix<const C: u8, const O: u8> =
    g::Seq<g::Send<O, C, Retired>, g::Send<C, O, RetirementAcknowledged>>;
pub type Active<const C: u8, const O: u8> =
    g::Seq<g::Roll<ActiveWork<C, O>>, RetirementSuffix<C, O>>;
pub type EarlyAdmission<const C: u8, const O: u8> = g::Seq<
    ReplyFlow<C, O, EarlyRequired>,
    g::Seq<g::Send<C, O, EarlyReady>, ReplyFlow<C, O, EarlyApplied>>,
>;
pub type EarlyStage<const C: u8, const O: u8> = g::Seq<
    g::Roll<EarlyWork<C, O>>,
    g::Route<g::Seq<EarlyAdmission<C, O>, Active<C, O>>, RetirementSuffix<C, O>>,
>;
pub type BootstrapEnd<const C: u8, const O: u8> = g::Route<
    g::Seq<ReplyFlow<C, O, Ready>, Active<C, O>>,
    g::Route<g::Seq<ReplyFlow<C, O, EarlySendInstalled>, EarlyStage<C, O>>, RetirementSuffix<C, O>>,
>;
pub type StreamFlow<const C: u8, const O: u8> = g::Seq<
    g::Send<C, O, Install>,
    g::Seq<g::Send<O, C, Installed>, g::Seq<g::Roll<BootstrapWork<C, O>>, BootstrapEnd<C, O>>>,
>;
fn reply<const C: u8, const O: u8, M: g::Message<Payload = [u8; 16]>>()
-> g::Program<ReplyFlow<C, O, M>> {
    g::seq(g::send::<O, C, M>(), g::send::<C, O, ResultTaken>())
}
fn operation_result<const C: u8, const O: u8>() -> g::Program<OperationResult<C, O>> {
    g::seq(
        g::route(g::send::<O, C, Applied>(), g::send::<O, C, Rejected>()),
        g::send::<C, O, ResultTaken>(),
    )
}
fn operation<const C: u8, const O: u8, M: g::Message<Payload = [u8; 16]>>()
-> g::Program<Operation<C, O, M>> {
    g::seq(g::send::<C, O, M>(), operation_result::<C, O>())
}
fn retirement<const C: u8, const O: u8>() -> g::Program<Retirement<C, O>> {
    g::seq(
        g::send::<C, O, RetireRequested>(),
        g::seq(
            g::send::<O, C, Retired>(),
            g::send::<C, O, RetirementAcknowledged>(),
        ),
    )
}
pub(crate) fn prepare<const C: u8, const O: u8, M: g::Message<Payload = [u8; 16]>>()
-> g::Program<PrepareFlow<C, O, M>> {
    let attempts = g::route(
        operation::<C, O, AdapterAccepted>(),
        g::route(
            operation::<C, O, AdapterRejected>(),
            operation::<C, O, CancelTransmission>(),
        ),
    )
    .roll();
    let completion = g::seq(attempts, g::send::<O, C, PublicationSettled>());
    let reserve_attempts = g::route(
        operation::<C, O, Reserve>(),
        operation::<C, O, CancelPrepared>(),
    )
    .roll();
    let reserve = g::seq(
        reserve_attempts,
        g::route(
            g::seq(g::send::<O, C, Reserved>(), completion),
            g::send::<O, C, SelectionCancelled>(),
        ),
    );
    g::seq(
        g::send::<C, O, M>(),
        g::route(
            g::seq(reply::<C, O, FramePrepared>(), reserve),
            g::route(reply::<C, O, NoFrame>(), reply::<C, O, Rejected>()),
        ),
    )
}
pub fn stream_choreography<const C: u8, const O: u8>() -> g::Program<StreamFlow<C, O>> {
    let active = || {
        let requests = g::route(
            g::route(
                g::route(g::send::<C, O, Probe>(), g::send::<C, O, Deliver>()),
                g::route(
                    g::send::<C, O, DeliverEarly>(),
                    g::send::<C, O, Acknowledge>(),
                ),
            ),
            g::route(
                g::route(
                    g::route(g::send::<C, O, Lost>(), g::send::<C, O, Open>()),
                    g::route(g::send::<C, O, Send>(), g::send::<C, O, Read>()),
                ),
                g::route(
                    g::route(
                        g::send::<C, O, Consume>(),
                        g::send::<C, O, AcknowledgeReset>(),
                    ),
                    g::route(
                        g::route(g::send::<C, O, Reset>(), g::send::<C, O, Stop>()),
                        g::route(g::send::<C, O, RetireStream>(), g::send::<C, O, Inspect>()),
                    ),
                ),
            ),
        );
        g::seq(
            g::route(
                g::seq(requests, operation_result::<C, O>()),
                g::route(
                    prepare::<C, O, Prepare>(),
                    g::send::<C, O, RetireRequested>(),
                ),
            )
            .roll(),
            g::seq(
                g::send::<O, C, Retired>(),
                g::send::<C, O, RetirementAcknowledged>(),
            ),
        )
    };
    let bootstrap_requests = g::route(
        g::route(g::send::<C, O, Probe>(), g::send::<C, O, Deliver>()),
        g::route(
            g::route(g::send::<C, O, Acknowledge>(), g::send::<C, O, Lost>()),
            g::route(g::send::<C, O, Retry>(), g::send::<C, O, Inspect>()),
        ),
    );
    let bootstrap = g::route(
        g::seq(bootstrap_requests, operation_result::<C, O>()),
        g::route(
            g::send::<C, O, PeerReady>(),
            g::route(
                g::send::<C, O, EarlySendReady>(),
                g::send::<C, O, RetireRequested>(),
            ),
        ),
    )
    .roll();
    let early_work = g::route(
        g::route(
            g::route(operation::<C, O, Probe>(), operation::<C, O, Deliver>()),
            g::route(
                operation::<C, O, Acknowledge>(),
                g::route(
                    g::route(operation::<C, O, Lost>(), operation::<C, O, Retry>()),
                    operation::<C, O, Inspect>(),
                ),
            ),
        ),
        g::route(
            g::route(
                operation::<C, O, EnqueueEarly>(),
                operation::<C, O, InspectEarly>(),
            ),
            g::route(
                prepare::<C, O, PrepareEarly>(),
                g::route(
                    g::send::<C, O, PeerReady>(),
                    g::send::<C, O, RetireRequested>(),
                ),
            ),
        ),
    )
    .roll();
    let retirement = || {
        g::seq(
            g::send::<O, C, Retired>(),
            g::send::<C, O, RetirementAcknowledged>(),
        )
    };
    let early_admission = g::seq(
        reply::<C, O, EarlyRequired>(),
        g::seq(g::send::<C, O, EarlyReady>(), reply::<C, O, EarlyApplied>()),
    );
    let early_stage = g::seq(
        early_work,
        g::route(g::seq(early_admission, active()), retirement()),
    );
    let completion = g::route(
        g::seq(reply::<C, O, Ready>(), active()),
        g::route(
            g::seq(reply::<C, O, EarlySendInstalled>(), early_stage),
            retirement(),
        ),
    );
    g::seq(
        g::send::<C, O, Install>(),
        g::seq(g::send::<O, C, Installed>(), g::seq(bootstrap, completion)),
    )
}
pub fn stream_program<const ROLE: u8>() -> RoleProgram<ROLE> {
    project(&stream_choreography::<STREAM_CLIENT, STREAM_OWNER>())
}
