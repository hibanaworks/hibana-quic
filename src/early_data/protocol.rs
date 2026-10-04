//! The early-byte owner has finite holding, verified release, and discard paths.
use hibana::g;
pub const INPUT: u8 = 0;
pub const OWNER: u8 = 1;
pub const TLS: u8 = 2;
pub const APPLICATION: u8 = 3;
pub type Packet = g::Msg<0, u64>;
pub type PacketStored = g::Msg<1, u64>;
pub type PacketDropped = g::Msg<2, u64>;
pub type InputEnd = g::Msg<3, u64>;
pub type InputEnded = g::Msg<4, u64>;
pub type InputRetired = g::Msg<5, u64>;
pub type Verified = g::Msg<6, u64>;
pub type VerifiedTaken = g::Msg<7, u64>;
pub type Reject = g::Msg<8, u64>;
pub type Cancel = g::Msg<9, u64>;
pub type Range = g::Msg<10, u64>;
pub type RangeApplied = g::Msg<11, u64>;
pub type Released = g::Msg<12, u64>;
pub type ReleaseSeen = g::Msg<13, u64>;
pub type Discarded = g::Msg<14, u64>;
pub type DiscardSeen = g::Msg<15, u64>;
pub type Controls = g::Msg<17, u64>;
pub type ControlsApplied = g::Msg<18, u64>;
pub type Retired = g::Msg<16, u64>;

type PacketExchange = g::Seq<
    g::Send<INPUT, OWNER, Packet>,
    g::Route<g::Send<OWNER, INPUT, PacketStored>, g::Send<OWNER, INPUT, PacketDropped>>,
>;
type Holding = g::Seq<
    g::Roll<g::Route<PacketExchange, g::Send<INPUT, OWNER, InputEnd>>>,
    g::Seq<g::Send<OWNER, INPUT, InputEnded>, g::Send<INPUT, TLS, InputRetired>>,
>;
type Delivery = g::Seq<
    g::Roll<
        g::Route<
            g::Seq<g::Send<OWNER, APPLICATION, Range>, g::Send<APPLICATION, OWNER, RangeApplied>>,
            g::Route<
                g::Seq<
                    g::Send<OWNER, APPLICATION, Controls>,
                    g::Send<APPLICATION, OWNER, ControlsApplied>,
                >,
                g::Send<OWNER, APPLICATION, Released>,
            >,
        >,
    >,
    g::Send<APPLICATION, OWNER, ReleaseSeen>,
>;
type Accepted =
    g::Seq<g::Send<TLS, OWNER, Verified>, g::Seq<g::Send<OWNER, TLS, VerifiedTaken>, Delivery>>;
type Discard = g::Seq<
    g::Route<g::Send<TLS, OWNER, Reject>, g::Send<TLS, OWNER, Cancel>>,
    g::Seq<g::Send<OWNER, APPLICATION, Discarded>, g::Send<APPLICATION, OWNER, DiscardSeen>>,
>;
pub type Flow = g::Seq<Holding, g::Seq<g::Route<Accepted, Discard>, g::Send<OWNER, TLS, Retired>>>;

pub fn choreography() -> g::Program<Flow> {
    let holding = g::seq(
        g::route(
            g::seq(
                g::send::<INPUT, OWNER, Packet>(),
                g::route(
                    g::send::<OWNER, INPUT, PacketStored>(),
                    g::send::<OWNER, INPUT, PacketDropped>(),
                ),
            ),
            g::send::<INPUT, OWNER, InputEnd>(),
        )
        .roll(),
        g::seq(
            g::send::<OWNER, INPUT, InputEnded>(),
            g::send::<INPUT, TLS, InputRetired>(),
        ),
    );
    let deliver = g::seq(
        g::route(
            g::seq(
                g::send::<OWNER, APPLICATION, Range>(),
                g::send::<APPLICATION, OWNER, RangeApplied>(),
            ),
            g::route(
                g::seq(
                    g::send::<OWNER, APPLICATION, Controls>(),
                    g::send::<APPLICATION, OWNER, ControlsApplied>(),
                ),
                g::send::<OWNER, APPLICATION, Released>(),
            ),
        )
        .roll(),
        g::send::<APPLICATION, OWNER, ReleaseSeen>(),
    );
    let accepted = g::seq(
        g::send::<TLS, OWNER, Verified>(),
        g::seq(g::send::<OWNER, TLS, VerifiedTaken>(), deliver),
    );
    let discard = g::seq(
        g::route(
            g::send::<TLS, OWNER, Reject>(),
            g::send::<TLS, OWNER, Cancel>(),
        ),
        g::seq(
            g::send::<OWNER, APPLICATION, Discarded>(),
            g::send::<APPLICATION, OWNER, DiscardSeen>(),
        ),
    );
    g::seq(
        holding,
        g::seq(
            g::route(accepted, discard),
            g::send::<OWNER, TLS, Retired>(),
        ),
    )
}
