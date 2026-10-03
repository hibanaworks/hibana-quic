//! Explicit server early-data phases projected from one global.
//!
//! The first operation may be a real Receive, Inspect, Finish, or Retire request.
//! Holding work rolls include both exit requests; the actual owner's response
//! selects Finished acceptance, rejection, or retirement. Accepted Finished is
//! followed by the active roll, whose release branch mandates exact target
//! settlement before any next work. No dummy work message opens a phase.
//!
//! Trace: Install / Installed; (Receive / Check / Checked / Applied | Inspect /
//! Applied)*; Finish / Ready; (Release / Application-or-Path / Settle / Applied /
//! Settled | Receive / Check / Checked / Applied | Inspect / Applied)*;
//! RetireRequested / Retired / RetirementAcknowledged. Declined Finished instead
//! proceeds directly to retirement. Every result includes ResultTaken.
//!
//! The original after-one-Inspect post-roll retirement failure remains in
//! tests/support/early_original_choreography.rs. This design does not fix or
//! qualify that core behavior; it independently allows legitimate first exits.
use hibana::{
    g,
    runtime::program::{RoleProgram, project},
};
pub const EARLY_CLIENT: u8 = 32;
pub const EARLY_OWNER: u8 = 33;
pub const INSTALL: u8 = 80;
pub type Install = g::Msg<INSTALL, [u8; 16]>;
pub const INSTALLED: u8 = 81;
pub type Installed = g::Msg<INSTALLED, [u8; 16]>;
pub const RECEIVE: u8 = 82;
pub type Receive = g::Msg<RECEIVE, [u8; 16]>;
pub const CHECK: u8 = 83;
pub type Check = g::Msg<CHECK, [u8; 16]>;
pub const CHECKED: u8 = 84;
pub type Checked = g::Msg<CHECKED, [u8; 16]>;
pub const DROPPED: u8 = 85;
pub type Dropped = g::Msg<DROPPED, [u8; 16]>;
pub const FINISH: u8 = 86;
pub type Finish = g::Msg<FINISH, [u8; 16]>;
pub const READY: u8 = 87;
pub type Ready = g::Msg<READY, [u8; 16]>;
pub const DECLINED: u8 = 88;
pub type Declined = g::Msg<DECLINED, [u8; 16]>;
pub const RELEASE: u8 = 89;
pub type Release = g::Msg<RELEASE, [u8; 16]>;
pub const APPLICATION: u8 = 90;
pub type Application = g::Msg<APPLICATION, [u8; 16]>;
pub const PATH: u8 = 91;
pub type Path = g::Msg<PATH, [u8; 16]>;
pub const EMPTY: u8 = 92;
pub type Empty = g::Msg<EMPTY, [u8; 16]>;
pub const SETTLE: u8 = 93;
pub type Settle = g::Msg<SETTLE, [u8; 16]>;
pub const SETTLED: u8 = 94;
pub type Settled = g::Msg<SETTLED, [u8; 16]>;
pub const INSPECT: u8 = 95;
pub type Inspect = g::Msg<INSPECT, [u8; 16]>;
pub const APPLIED: u8 = 96;
pub type Applied = g::Msg<APPLIED, [u8; 16]>;
pub const REJECTED: u8 = 97;
pub type Rejected = g::Msg<REJECTED, [u8; 16]>;
pub const RESULT_TAKEN: u8 = 98;
pub type ResultTaken = g::Msg<RESULT_TAKEN, [u8; 16]>;
pub const RETIRE_REQUESTED: u8 = 99;
pub type RetireRequested = g::Msg<RETIRE_REQUESTED, [u8; 16]>;
pub const RETIRED: u8 = 100;
pub type Retired = g::Msg<RETIRED, [u8; 16]>;
pub const RETIREMENT_ACKNOWLEDGED: u8 = 101;
pub type RetirementAcknowledged = g::Msg<RETIREMENT_ACKNOWLEDGED, [u8; 16]>;
pub type Reply<const C: u8, const O: u8, M> = g::Seq<g::Send<O, C, M>, g::Send<C, O, ResultTaken>>;
pub type Operation<const C: u8, const O: u8, M> =
    g::Seq<g::Send<C, O, M>, g::Route<Reply<C, O, Applied>, Reply<C, O, Rejected>>>;
pub type Admission<const C: u8, const O: u8> = g::Seq<
    g::Send<C, O, Receive>,
    g::Route<
        g::Seq<Reply<C, O, Check>, Operation<C, O, Checked>>,
        g::Route<Reply<C, O, Dropped>, Reply<C, O, Rejected>>,
    >,
>;
pub type Settlement<const C: u8, const O: u8> =
    g::Seq<g::Roll<Operation<C, O, Settle>>, g::Send<O, C, Settled>>;
pub type ReleaseFlow<const C: u8, const O: u8> = g::Seq<
    g::Send<C, O, Release>,
    g::Route<
        g::Seq<g::Route<Reply<C, O, Application>, Reply<C, O, Path>>, Settlement<C, O>>,
        g::Route<Reply<C, O, Empty>, Reply<C, O, Rejected>>,
    >,
>;
pub type Retirement<const C: u8, const O: u8> = g::Seq<
    g::Send<C, O, RetireRequested>,
    g::Seq<g::Send<O, C, Retired>, g::Send<C, O, RetirementAcknowledged>>,
>;
pub type RetirementSuffix<const C: u8, const O: u8> =
    g::Seq<g::Send<O, C, Retired>, g::Send<C, O, RetirementAcknowledged>>;
pub type Active<const C: u8, const O: u8> = g::Seq<
    g::Roll<
        g::Route<
            Admission<C, O>,
            g::Route<
                Operation<C, O, Inspect>,
                g::Route<ReleaseFlow<C, O>, g::Send<C, O, RetireRequested>>,
            >,
        >,
    >,
    RetirementSuffix<C, O>,
>;
pub type FinishSuffix<const C: u8, const O: u8> = g::Route<
    g::Seq<Reply<C, O, Ready>, Active<C, O>>,
    g::Seq<Reply<C, O, Declined>, Retirement<C, O>>,
>;
pub type HoldingWork<const C: u8, const O: u8> = g::Route<
    Admission<C, O>,
    g::Route<
        Operation<C, O, Inspect>,
        g::Route<g::Send<C, O, Finish>, g::Send<C, O, RetireRequested>>,
    >,
>;
pub type EarlyFlow<const C: u8, const O: u8> = g::Seq<
    g::Send<C, O, Install>,
    g::Seq<
        g::Send<O, C, Installed>,
        g::Seq<g::Roll<HoldingWork<C, O>>, g::Route<FinishSuffix<C, O>, RetirementSuffix<C, O>>>,
    >,
>;

fn reply<const C: u8, const O: u8, M: g::Message<Payload = [u8; 16]>>() -> g::Program<Reply<C, O, M>>
{
    g::seq(g::send::<O, C, M>(), g::send::<C, O, ResultTaken>())
}
fn operation<const C: u8, const O: u8, M: g::Message<Payload = [u8; 16]>>()
-> g::Program<Operation<C, O, M>> {
    g::seq(
        g::send::<C, O, M>(),
        g::route(reply::<C, O, Applied>(), reply::<C, O, Rejected>()),
    )
}
fn admission<const C: u8, const O: u8>() -> g::Program<Admission<C, O>> {
    g::seq(
        g::send::<C, O, Receive>(),
        g::route(
            g::seq(reply::<C, O, Check>(), operation::<C, O, Checked>()),
            g::route(reply::<C, O, Dropped>(), reply::<C, O, Rejected>()),
        ),
    )
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
fn active<const C: u8, const O: u8>() -> g::Program<Active<C, O>> {
    let release = g::seq(
        g::send::<C, O, Release>(),
        g::route(
            g::seq(
                g::route(reply::<C, O, Application>(), reply::<C, O, Path>()),
                g::seq(
                    operation::<C, O, Settle>().roll(),
                    g::send::<O, C, Settled>(),
                ),
            ),
            g::route(reply::<C, O, Empty>(), reply::<C, O, Rejected>()),
        ),
    );
    g::seq(
        g::route(
            admission::<C, O>(),
            g::route(
                operation::<C, O, Inspect>(),
                g::route(release, g::send::<C, O, RetireRequested>()),
            ),
        )
        .roll(),
        retirement_suffix::<C, O>(),
    )
}
fn retirement_suffix<const C: u8, const O: u8>() -> g::Program<RetirementSuffix<C, O>> {
    g::seq(
        g::send::<O, C, Retired>(),
        g::send::<C, O, RetirementAcknowledged>(),
    )
}
pub fn early_choreography<const C: u8, const O: u8>() -> g::Program<EarlyFlow<C, O>> {
    // Roll is one-or-more. A phase exit is an actual request in that menu,
    // so Finished or retirement can also be the first legitimate operation.
    let holding = g::route(
        admission::<C, O>(),
        g::route(
            operation::<C, O, Inspect>(),
            g::route(
                g::send::<C, O, Finish>(),
                g::send::<C, O, RetireRequested>(),
            ),
        ),
    )
    .roll();
    let finish = g::route(
        g::seq(reply::<C, O, Ready>(), active::<C, O>()),
        g::seq(reply::<C, O, Declined>(), retirement::<C, O>()),
    );
    g::seq(
        g::send::<C, O, Install>(),
        g::seq(
            g::send::<O, C, Installed>(),
            g::seq(holding, g::route(finish, retirement_suffix::<C, O>())),
        ),
    )
}

pub fn early_program<const ROLE: u8>() -> RoleProgram<ROLE> {
    project(&early_choreography::<EARLY_CLIENT, EARLY_OWNER>())
}
