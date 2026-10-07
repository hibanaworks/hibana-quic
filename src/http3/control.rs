//! HTTP/3 startup and peer control progression. The first SETTINGS boundary
//! and its single occurrence are protocol edges, never a stored phase flag.
use hibana::g;
pub const OWNER: u8 = crate::connection::protocol::INITIAL_OWNER;
pub const SOURCE: u8 = crate::connection::application::protocol::SOURCE;
pub const SINK: u8 = crate::connection::application::protocol::SINK;
pub type Plain = g::Msg<238, ()>;
pub type Http3 = g::Msg<239, ()>;
pub type PlainSink = g::Msg<240, ()>;
pub type Http3Sink = g::Msg<241, ()>;
pub type Ready = g::Msg<242, ()>;
pub type Aborted = g::Msg<243, ()>;
pub type Settings = g::Msg<244, ()>;
pub type Stored = g::Msg<245, ()>;
pub type Other = g::Msg<246, ()>;
pub type End = g::Msg<247, ()>;
pub type Closed = g::Msg<248, ()>;
type PlainFlow = g::Seq<
    g::Send<SOURCE, OWNER, Plain>,
    g::Seq<g::Send<OWNER, SINK, PlainSink>, g::Send<OWNER, SOURCE, Ready>>,
>;
type Exchange = g::Seq<g::Send<SINK, OWNER, Other>, g::Send<OWNER, SINK, Stored>>;
type SettingsFlow = g::Seq<
    g::Send<SINK, OWNER, Settings>,
    g::Seq<
        g::Send<OWNER, SINK, Stored>,
        g::Seq<
            g::Send<OWNER, SOURCE, Ready>,
            g::Roll<g::Route<Exchange, g::Send<SINK, OWNER, End>>>,
        >,
    >,
>;
type AbortedFlow = g::Seq<g::Send<SINK, OWNER, End>, g::Send<OWNER, SOURCE, Aborted>>;
type Http3Flow = g::Seq<
    g::Send<SOURCE, OWNER, Http3>,
    g::Seq<
        g::Send<OWNER, SINK, Http3Sink>,
        g::Seq<g::Route<SettingsFlow, AbortedFlow>, g::Send<OWNER, SINK, Closed>>,
    >,
>;
pub type Flow = g::Route<PlainFlow, Http3Flow>;
pub fn choreography() -> g::Program<Flow> {
    g::route(
        g::seq(
            g::send::<SOURCE, OWNER, Plain>(),
            g::seq(
                g::send::<OWNER, SINK, PlainSink>(),
                g::send::<OWNER, SOURCE, Ready>(),
            ),
        ),
        g::seq(
            g::send::<SOURCE, OWNER, Http3>(),
            g::seq(
                g::send::<OWNER, SINK, Http3Sink>(),
                g::seq(
                    g::route(
                        g::seq(
                            g::send::<SINK, OWNER, Settings>(),
                            g::seq(
                                g::send::<OWNER, SINK, Stored>(),
                                g::seq(
                                    g::send::<OWNER, SOURCE, Ready>(),
                                    g::route(
                                        g::seq(
                                            g::send::<SINK, OWNER, Other>(),
                                            g::send::<OWNER, SINK, Stored>(),
                                        ),
                                        g::send::<SINK, OWNER, End>(),
                                    )
                                    .roll(),
                                ),
                            ),
                        ),
                        g::seq(
                            g::send::<SINK, OWNER, End>(),
                            g::send::<OWNER, SOURCE, Aborted>(),
                        ),
                    ),
                    g::send::<OWNER, SINK, Closed>(),
                ),
            ),
        ),
    )
}
