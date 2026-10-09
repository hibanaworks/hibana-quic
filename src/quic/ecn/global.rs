//! The fixed-path marking lifetime is a projected continuation, not a stored
//! phase discriminator. A request owns either one pending publication or the
//! actual end of publication. Every permit is settled before the next request.
//! Failure has no edge back to probing or validated marking.
use hibana::g;
use hibana::runtime::program::Projectable;

// A dedicated policy owner uses the existing spare role31. The publisher is
// the existing application adapter; their concurrent selectors are disjoint.
pub const OWNER: u8 = 31;
pub const PUBLISHER: u8 = 17;
pub type ProbePermit = g::Msg<100, u8>;
pub type Settled = g::Msg<101, ()>;
pub type Request = g::Msg<102, ()>;
pub type Validated = g::Msg<103, u8>;
pub type CapablePermit = g::Msg<106, u8>;
pub type ProbeFailed = g::Msg<107, ()>;
pub type ProbeFailedPermit = g::Msg<110, ()>;
pub type ProbeFailedEnd = g::Msg<111, ()>;
pub type ValidationFailed = g::Msg<112, ()>;
pub type FailedPermit = g::Msg<115, ()>;
pub type FailedEnd = g::Msg<116, ()>;
pub type ProbeEnd = g::Msg<117, ()>;
pub type CapableEnd = g::Msg<118, ()>;
pub type Joined = g::Msg<119, ()>;
pub type ProbePause = g::Msg<120, ()>;
pub type ProbePaused = g::Msg<121, ()>;
pub type CapablePause = g::Msg<122, ()>;
pub type CapablePaused = g::Msg<123, ()>;
pub type ProbeFailedPause = g::Msg<124, ()>;
pub type ProbeFailedPaused = g::Msg<125, ()>;
pub type FailedPause = g::Msg<126, ()>;
pub type FailedPaused = g::Msg<127, ()>;

pub fn choreography() -> impl Projectable {
    let probe = g::route(
        g::seq(
            g::send::<OWNER, PUBLISHER, ProbePermit>(),
            g::seq(
                g::send::<PUBLISHER, OWNER, Settled>(),
                g::send::<PUBLISHER, OWNER, Request>(),
            ),
        ),
        g::seq(
            g::send::<OWNER, PUBLISHER, ProbePause>(),
            g::send::<PUBLISHER, OWNER, ProbePaused>(),
        ),
    )
    .roll();
    let capable = g::route(
        g::seq(
            g::send::<OWNER, PUBLISHER, CapablePermit>(),
            g::seq(
                g::send::<PUBLISHER, OWNER, Settled>(),
                g::send::<PUBLISHER, OWNER, Request>(),
            ),
        ),
        g::seq(
            g::send::<OWNER, PUBLISHER, CapablePause>(),
            g::send::<PUBLISHER, OWNER, CapablePaused>(),
        ),
    )
    .roll();
    let failed_probe = g::route(
        g::seq(
            g::send::<OWNER, PUBLISHER, ProbeFailedPermit>(),
            g::seq(
                g::send::<PUBLISHER, OWNER, Settled>(),
                g::send::<PUBLISHER, OWNER, Request>(),
            ),
        ),
        g::seq(
            g::send::<OWNER, PUBLISHER, ProbeFailedPause>(),
            g::send::<PUBLISHER, OWNER, ProbeFailedPaused>(),
        ),
    )
    .roll();
    let failed = g::route(
        g::seq(
            g::send::<OWNER, PUBLISHER, FailedPermit>(),
            g::seq(
                g::send::<PUBLISHER, OWNER, Settled>(),
                g::send::<PUBLISHER, OWNER, Request>(),
            ),
        ),
        g::seq(
            g::send::<OWNER, PUBLISHER, FailedPause>(),
            g::send::<PUBLISHER, OWNER, FailedPaused>(),
        ),
    )
    .roll();
    g::seq(
        g::send::<PUBLISHER, OWNER, Request>(),
        g::seq(
            probe,
            g::seq(
                g::route(
                    g::seq(
                        g::send::<OWNER, PUBLISHER, Validated>(),
                        g::seq(
                            g::send::<PUBLISHER, OWNER, Settled>(),
                            g::seq(
                                g::send::<PUBLISHER, OWNER, Request>(),
                                g::seq(
                                    capable,
                                    g::route(
                                        g::seq(
                                            g::send::<OWNER, PUBLISHER, ValidationFailed>(),
                                            g::seq(
                                                g::send::<PUBLISHER, OWNER, Settled>(),
                                                g::seq(
                                                    g::send::<PUBLISHER, OWNER, Request>(),
                                                    g::seq(
                                                        failed,
                                                        g::send::<OWNER, PUBLISHER, FailedEnd>(),
                                                    ),
                                                ),
                                            ),
                                        ),
                                        g::send::<OWNER, PUBLISHER, CapableEnd>(),
                                    ),
                                ),
                            ),
                        ),
                    ),
                    g::route(
                        g::seq(
                            g::send::<OWNER, PUBLISHER, ProbeFailed>(),
                            g::seq(
                                g::send::<PUBLISHER, OWNER, Settled>(),
                                g::seq(
                                    g::send::<PUBLISHER, OWNER, Request>(),
                                    g::seq(
                                        failed_probe,
                                        g::send::<OWNER, PUBLISHER, ProbeFailedEnd>(),
                                    ),
                                ),
                            ),
                        ),
                        g::send::<OWNER, PUBLISHER, ProbeEnd>(),
                    ),
                ),
                g::send::<PUBLISHER, OWNER, Joined>(),
            ),
        ),
    )
}
