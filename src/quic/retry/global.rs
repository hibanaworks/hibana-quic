//! Server Retry admission order. Native observations and token-validation
//! receipts remain separately owned data; unit messages cannot fabricate them.
//! The output role settles its actual send before another input is admitted.
use hibana::{
    g,
    runtime::program::{RoleProgram, project},
};

pub const INPUT: u8 = 0;
pub const OWNER: u8 = 1;
pub const OUTPUT: u8 = 2;
pub const SEND_RESULT: u16 = 1100;

pub type Observed = g::Msg<0, ()>;
pub type Datagram = g::Msg<1, ()>;
pub type Sent = g::Msg<2, ()>;
pub type Rejected = g::Msg<3, ()>;
pub type Settled = g::Msg<4, ()>;
pub type Ignored = g::Msg<5, ()>;
pub type Admitted = g::Msg<6, ()>;
pub type Stop = g::Msg<7, ()>;
pub type Stopped = g::Msg<8, ()>;
pub type NoSend = g::Msg<9, ()>;
pub type NoSendSeen = g::Msg<10, ()>;
pub type Joined = g::Msg<11, ()>;

type RetryRound = g::Seq<
    g::Send<OWNER, OUTPUT, Datagram>,
    g::Seq<
        g::Resolve<
            g::Route<g::Send<OUTPUT, OWNER, Sent>, g::Send<OUTPUT, OWNER, Rejected>>,
            SEND_RESULT,
        >,
        g::Seq<g::Send<OWNER, INPUT, Settled>, g::Send<INPUT, OWNER, Observed>>,
    >,
>;
type IgnoreRound = g::Seq<
    g::Send<OWNER, OUTPUT, NoSend>,
    g::Seq<
        g::Send<OUTPUT, OWNER, NoSendSeen>,
        g::Seq<g::Send<OWNER, INPUT, Ignored>, g::Send<INPUT, OWNER, Observed>>,
    >,
>;
type AdmitRound = g::Seq<
    g::Send<OWNER, INPUT, Admitted>,
    g::Seq<g::Send<OWNER, OUTPUT, Stop>, g::Send<OUTPUT, OWNER, Stopped>>,
>;
pub type Flow = g::Seq<
    g::Send<INPUT, OWNER, Observed>,
    g::Seq<
        g::Roll<g::Route<RetryRound, g::Route<IgnoreRound, AdmitRound>>>,
        g::Send<OWNER, INPUT, Joined>,
    >,
>;

pub fn choreography() -> g::Program<Flow> {
    g::seq(
        g::send::<INPUT, OWNER, Observed>(),
        g::seq(
            g::route(
                g::seq(
                    g::send::<OWNER, OUTPUT, Datagram>(),
                    g::seq(
                        g::route(
                            g::send::<OUTPUT, OWNER, Sent>(),
                            g::send::<OUTPUT, OWNER, Rejected>(),
                        )
                        .resolve::<SEND_RESULT>(),
                        g::seq(
                            g::send::<OWNER, INPUT, Settled>(),
                            g::send::<INPUT, OWNER, Observed>(),
                        ),
                    ),
                ),
                g::route(
                    g::seq(
                        g::send::<OWNER, OUTPUT, NoSend>(),
                        g::seq(
                            g::send::<OUTPUT, OWNER, NoSendSeen>(),
                            g::seq(
                                g::send::<OWNER, INPUT, Ignored>(),
                                g::send::<INPUT, OWNER, Observed>(),
                            ),
                        ),
                    ),
                    g::seq(
                        g::send::<OWNER, INPUT, Admitted>(),
                        g::seq(
                            g::send::<OWNER, OUTPUT, Stop>(),
                            g::send::<OUTPUT, OWNER, Stopped>(),
                        ),
                    ),
                ),
            )
            .roll(),
            g::send::<OWNER, INPUT, Joined>(),
        ),
    )
}

pub struct Programs {
    pub input: RoleProgram<INPUT>,
    pub owner: RoleProgram<OWNER>,
    pub output: RoleProgram<OUTPUT>,
}
pub fn programs() -> Programs {
    let global = choreography();
    Programs {
        input: project(&global),
        owner: project(&global),
        output: project(&global),
    }
}
