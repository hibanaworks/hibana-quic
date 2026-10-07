//! Path validation is a nested projected continuation. A Pending probe cannot
//! return to ordinary publication without a resolved or abandoned boundary.
use hibana::g;
// Role18 continues after its Initial-retirement prefix in this same session.
// Reuse the one endpoint; never enter the same role twice.
pub const OWNER: u8 = crate::connection::protocol::INITIAL_EVENT;
pub const TRANSMIT: u8 = 16;
pub type Request = g::Msg<221, ()>;
pub type Current = g::Msg<222, ()>;
pub type Settled = g::Msg<223, ()>;
pub type Begin = g::Msg<224, ()>;
pub type Probe = g::Msg<225, ()>;
pub type Hold = g::Msg<226, ()>;
pub type Resolved = g::Msg<227, ()>;
pub type Abandoned = g::Msg<228, ()>;
pub type End = g::Msg<229, ()>;
pub type Joined = g::Msg<230, ()>;
pub type Pause = g::Msg<231, ()>;
pub type Paused = g::Msg<232, ()>;
pub type ProbePause = g::Msg<233, ()>;
pub type ProbePaused = g::Msg<234, ()>;
pub type Expand = g::Msg<235, ()>;
pub type Reply = g::Msg<236, ()>;
pub type ProbeReply = g::Msg<237, ()>;
type ReplyRound = g::Seq<g::Send<OWNER, TRANSMIT, Reply>, Next>;
type ProbeReplyRound = g::Seq<g::Send<OWNER, TRANSMIT, ProbeReply>, Next>;
type ExpandRound = g::Seq<g::Send<OWNER, TRANSMIT, Expand>, Next>;
type Next = g::Seq<g::Send<TRANSMIT, OWNER, Settled>, g::Send<TRANSMIT, OWNER, Request>>;
type CurrentRound = g::Seq<g::Send<OWNER, TRANSMIT, Current>, Next>;
type ProbeRound = g::Seq<g::Send<OWNER, TRANSMIT, Probe>, Next>;
type HoldRound = g::Seq<g::Send<OWNER, TRANSMIT, Hold>, Next>;
type Boundary = g::Seq<
    g::Send<OWNER, TRANSMIT, Pause>,
    g::Seq<
        g::Send<TRANSMIT, OWNER, Paused>,
        g::Seq<g::Send<OWNER, TRANSMIT, End>, g::Send<TRANSMIT, OWNER, Joined>>,
    >,
>;
type ProbeBoundary = g::Seq<
    g::Send<OWNER, TRANSMIT, ProbePause>,
    g::Seq<
        g::Send<TRANSMIT, OWNER, ProbePaused>,
        g::Seq<
            g::Route<g::Send<OWNER, TRANSMIT, Resolved>, g::Send<OWNER, TRANSMIT, Abandoned>>,
            Next,
        >,
    >,
>;
type Cycle = g::Seq<
    g::Send<OWNER, TRANSMIT, Begin>,
    g::Seq<
        Next,
        g::Roll<
            g::Route<
                g::Route<g::Route<g::Route<ProbeRound, HoldRound>, ExpandRound>, ProbeReplyRound>,
                ProbeBoundary,
            >,
        >,
    >,
>;
pub type Flow = g::Seq<
    g::Send<TRANSMIT, OWNER, Request>,
    g::Roll<g::Route<g::Route<g::Route<CurrentRound, Cycle>, ReplyRound>, Boundary>>,
>;
pub fn choreography() -> g::Program<Flow> {
    let current = g::seq(
        g::send::<OWNER, TRANSMIT, Current>(),
        g::seq(
            g::send::<TRANSMIT, OWNER, Settled>(),
            g::send::<TRANSMIT, OWNER, Request>(),
        ),
    );
    let pending = g::route(
        g::route(
            g::route(
                g::route(
                    g::seq(
                        g::send::<OWNER, TRANSMIT, Probe>(),
                        g::seq(
                            g::send::<TRANSMIT, OWNER, Settled>(),
                            g::send::<TRANSMIT, OWNER, Request>(),
                        ),
                    ),
                    g::seq(
                        g::send::<OWNER, TRANSMIT, Hold>(),
                        g::seq(
                            g::send::<TRANSMIT, OWNER, Settled>(),
                            g::send::<TRANSMIT, OWNER, Request>(),
                        ),
                    ),
                ),
                g::seq(
                    g::send::<OWNER, TRANSMIT, Expand>(),
                    g::seq(
                        g::send::<TRANSMIT, OWNER, Settled>(),
                        g::send::<TRANSMIT, OWNER, Request>(),
                    ),
                ),
            ),
            g::seq(
                g::send::<OWNER, TRANSMIT, ProbeReply>(),
                g::seq(
                    g::send::<TRANSMIT, OWNER, Settled>(),
                    g::send::<TRANSMIT, OWNER, Request>(),
                ),
            ),
        ),
        g::seq(
            g::send::<OWNER, TRANSMIT, ProbePause>(),
            g::seq(
                g::send::<TRANSMIT, OWNER, ProbePaused>(),
                g::seq(
                    g::route(
                        g::send::<OWNER, TRANSMIT, Resolved>(),
                        g::send::<OWNER, TRANSMIT, Abandoned>(),
                    ),
                    g::seq(
                        g::send::<TRANSMIT, OWNER, Settled>(),
                        g::send::<TRANSMIT, OWNER, Request>(),
                    ),
                ),
            ),
        ),
    )
    .roll();
    let cycle = g::seq(
        g::send::<OWNER, TRANSMIT, Begin>(),
        g::seq(
            g::seq(
                g::send::<TRANSMIT, OWNER, Settled>(),
                g::send::<TRANSMIT, OWNER, Request>(),
            ),
            pending,
        ),
    );
    let end = g::seq(
        g::send::<OWNER, TRANSMIT, Pause>(),
        g::seq(
            g::send::<TRANSMIT, OWNER, Paused>(),
            g::seq(
                g::send::<OWNER, TRANSMIT, End>(),
                g::send::<TRANSMIT, OWNER, Joined>(),
            ),
        ),
    );
    g::seq(
        g::send::<TRANSMIT, OWNER, Request>(),
        g::route(
            g::route(
                g::route(current, cycle),
                g::seq(
                    g::send::<OWNER, TRANSMIT, Reply>(),
                    g::seq(
                        g::send::<TRANSMIT, OWNER, Settled>(),
                        g::send::<TRANSMIT, OWNER, Request>(),
                    ),
                ),
            ),
            end,
        )
        .roll(),
    )
}
