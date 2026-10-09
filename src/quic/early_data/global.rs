//! The early-byte owner has finite holding, verified release, and discard paths.
use hibana::g;
use hibana::runtime::program::Projectable;
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

pub fn choreography() -> impl Projectable {
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

// The finite optional bridge reuses the completed prefix's four endpoint roles.
// Every role observes the skip, so projection never guesses hidden knowledge.
pub type Skip = g::Msg<19, u64>;
pub type SkipOwner = g::Msg<20, u64>;
pub type SkipTls = g::Msg<21, u64>;
pub type SkipDone = g::Msg<22, u64>;
pub fn bridge() -> impl Projectable {
    g::route(
        choreography(),
        g::seq(
            g::send::<INPUT, OWNER, Skip>(),
            g::seq(
                g::send::<OWNER, TLS, SkipOwner>(),
                g::seq(
                    g::send::<TLS, APPLICATION, SkipTls>(),
                    g::send::<APPLICATION, INPUT, SkipDone>(),
                ),
            ),
        ),
    )
}
