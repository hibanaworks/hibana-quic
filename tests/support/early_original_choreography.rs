//! Preserved original post-roll retirement reproduction on vendor3aef31ba.
//! One complete Inspect/Applied/ResultTaken iteration precedes the failing
//! RetireRequested99 send. This is intentionally separate from the production
//! first-request-capable exit-request design; it is not a core-fix claim.
//! Server early-data lifecycle projected from one global.
//!
//! Holding can authenticate/admit packets but cannot release bytes. The actual
//! Finished result selects active release or rejection. Admission requires the
//! path simulation result; release requires settlement before either work roll
//! resumes. This fragment composes under the connection global's `par`.
use hibana::runtime::program::Projectable;
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

fn reply<const C: u8, const O: u8, M: g::Message<Payload = [u8; 16]>>() -> impl Projectable
{
    g::seq(g::send::<O, C, M>(), g::send::<C, O, ResultTaken>())
}
fn operation<const C: u8, const O: u8, M: g::Message<Payload = [u8; 16]>>()
-> impl Projectable {
    g::seq(
        g::send::<C, O, M>(),
        g::route(reply::<C, O, Applied>(), reply::<C, O, Rejected>()),
    )
}
fn admission<const C: u8, const O: u8>() -> impl Projectable {
    g::seq(
        g::send::<C, O, Receive>(),
        g::route(
            g::seq(reply::<C, O, Check>(), operation::<C, O, Checked>()),
            g::route(reply::<C, O, Dropped>(), reply::<C, O, Rejected>()),
        ),
    )
}
fn retirement<const C: u8, const O: u8>() -> impl Projectable {
    g::seq(
        g::send::<C, O, RetireRequested>(),
        g::seq(
            g::send::<O, C, Retired>(),
            g::send::<C, O, RetirementAcknowledged>(),
        ),
    )
}
fn active<const C: u8, const O: u8>() -> impl Projectable {
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
            g::route(operation::<C, O, Inspect>(), release),
        )
        .roll(),
        retirement::<C, O>(),
    )
}
pub fn early_choreography<const C: u8, const O: u8>() -> impl Projectable {
    let finish = g::seq(
        g::send::<C, O, Finish>(),
        g::route(
            g::seq(reply::<C, O, Ready>(), active::<C, O>()),
            g::seq(reply::<C, O, Declined>(), retirement::<C, O>()),
        ),
    );
    g::seq(
        g::send::<C, O, Install>(),
        g::seq(
            g::send::<O, C, Installed>(),
            g::seq(
                g::route(admission::<C, O>(), operation::<C, O, Inspect>()).roll(),
                g::route(finish, retirement::<C, O>()),
            ),
        ),
    )
}

pub fn early_program<const ROLE: u8>() -> RoleProgram<ROLE> {
    project(&early_choreography::<EARLY_CLIENT, EARLY_OWNER>())
}
