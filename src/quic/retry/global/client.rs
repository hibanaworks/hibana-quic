//! One-shot client Retry boundary. The Retry branch is outside both rolls:
//! the post-Retry continuation cannot select it a second time.
//!
//! This client prefix is composed into [`crate::quic::global`]. Its endpoints
//! are attached by [`crate::quic::localside::Endpoints`] and the real Retry local is
//! invoked by [`crate::quic::localside::run`] before continuing the same handshake.
use hibana::g;
use hibana::runtime::program::Projectable;
pub const OWNER: u8 = 3;
pub const IO: u8 = 4;
pub type Packet = g::Msg<0, ()>;
pub type Accepted = g::Msg<1, ()>;
pub type Rejected = g::Msg<2, ()>;
pub type Settled = g::Msg<3, ()>;
pub type Listen = g::Msg<4, ()>;
pub type Observed = g::Msg<5, ()>;
pub type Expired = g::Msg<6, ()>;
pub type Taken = g::Msg<7, ()>;
pub type Rekey = g::Msg<8, ()>;
pub type Rekeyed = g::Msg<9, ()>;
pub type Proceed = g::Msg<10, ()>;
pub type Joined = g::Msg<11, ()>;
pub type Bypass = g::Msg<12, ()>;
pub type Bypassed = g::Msg<13, ()>;
pub type Quiesce = g::Msg<14, ()>;
pub type Quiescent = g::Msg<15, ()>;
pub type RetriedPacket = g::Msg<20, ()>;
pub type RetriedAccepted = g::Msg<21, ()>;
pub type RetriedRejected = g::Msg<22, ()>;
pub type RetriedSettled = g::Msg<23, ()>;
pub type RetriedListen = g::Msg<24, ()>;
pub type RetriedObserved = g::Msg<25, ()>;
pub type RetriedExpired = g::Msg<26, ()>;
pub type RetriedTaken = g::Msg<27, ()>;
pub type RetriedQuiesce = g::Msg<28, ()>;
pub type RetriedQuiescent = g::Msg<29, ()>;
fn publish() -> impl Projectable {
    g::seq(
        g::send::<OWNER, IO, Packet>(),
        g::seq(
            g::route(
                g::send::<IO, OWNER, Accepted>(),
                g::send::<IO, OWNER, Rejected>(),
            ),
            g::send::<OWNER, IO, Settled>(),
        ),
    )
}
fn receive() -> impl Projectable {
    g::seq(
        g::send::<OWNER, IO, Listen>(),
        g::seq(
            g::route(
                g::send::<IO, OWNER, Observed>(),
                g::send::<IO, OWNER, Expired>(),
            ),
            g::send::<OWNER, IO, Taken>(),
        ),
    )
}
fn work() -> impl Projectable {
    g::route(
        publish(),
        g::route(
            receive(),
            g::seq(
                g::send::<OWNER, IO, Quiesce>(),
                g::send::<IO, OWNER, Quiescent>(),
            ),
        ),
    )
    .roll()
}
fn retried_publish() -> impl Projectable {
    g::seq(
        g::send::<OWNER, IO, RetriedPacket>(),
        g::seq(
            g::route(
                g::send::<IO, OWNER, RetriedAccepted>(),
                g::send::<IO, OWNER, RetriedRejected>(),
            ),
            g::send::<OWNER, IO, RetriedSettled>(),
        ),
    )
}
fn retried_receive() -> impl Projectable {
    g::seq(
        g::send::<OWNER, IO, RetriedListen>(),
        g::seq(
            g::route(
                g::send::<IO, OWNER, RetriedObserved>(),
                g::send::<IO, OWNER, RetriedExpired>(),
            ),
            g::send::<OWNER, IO, RetriedTaken>(),
        ),
    )
}
fn retried_work() -> impl Projectable {
    g::route(
        retried_publish(),
        g::route(
            retried_receive(),
            g::seq(
                g::send::<OWNER, IO, RetriedQuiesce>(),
                g::send::<IO, OWNER, RetriedQuiescent>(),
            ),
        ),
    )
    .roll()
}
fn finish() -> impl Projectable {
    g::seq(
        g::send::<OWNER, IO, Proceed>(),
        g::send::<IO, OWNER, Joined>(),
    )
}
pub fn choreography() -> impl Projectable {
    g::seq(
        publish(),
        g::seq(
            work(),
            g::seq(
                g::route(
                    g::seq(
                        g::send::<OWNER, IO, Rekey>(),
                        g::seq(g::send::<IO, OWNER, Rekeyed>(), retried_work()),
                    ),
                    g::seq(
                        g::send::<OWNER, IO, Bypass>(),
                        g::send::<IO, OWNER, Bypassed>(),
                    ),
                ),
                finish(),
            ),
        ),
    )
}
pub type Skip = g::Msg<30, ()>;
pub type Skipped = g::Msg<31, ()>;
pub fn prefix() -> impl Projectable {
    g::route(
        choreography(),
        g::seq(
            g::send::<OWNER, IO, Skip>(),
            g::send::<IO, OWNER, Skipped>(),
        ),
    )
}
