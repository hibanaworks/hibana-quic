//! Path validation is a nested projected continuation. A Pending probe cannot
//! return to ordinary publication without a resolved or abandoned boundary.
//!
//! OWNER executes the path-validation continuation in [`crate::quic::path::localside`].
//! TRANSMIT requests and settles each probe from the application transmit local.
//! Their endpoints belong to [`crate::quic::application::localside::Endpoints`];
//! [`crate::quic::application::localside::run`] polls both futures. Observed addresses,
//! probe receipts and bounded arithmetic live in the private `imp` storage.
use hibana::g;
use hibana::runtime::program::Projectable;
// The connected path owner has its own role in the application session.
// Endpoints::attach enters it once; the path localside owns its continuation.
pub const OWNER: u8 = 34;
pub const TRANSMIT: u8 = crate::quic::application::global::TRANSMIT;
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
pub fn choreography() -> impl Projectable {
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
