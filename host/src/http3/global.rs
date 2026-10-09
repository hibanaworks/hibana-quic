//! FIN-complete file response: headers, body, trailers, completion.
use hibana::g;
pub(super) const READER: u8 = 0;
pub(super) const WRITER: u8 = 1;
pub(super) type Information = g::Msg<1, ()>;
pub(super) type Headers = g::Msg<2, ()>;
pub(super) type Stored = g::Msg<3, ()>;
pub(super) type Data = g::Msg<4, u64>;
pub(super) type BodyEnd = g::Msg<5, ()>;
pub(super) type Trailers = g::Msg<6, ()>;
pub(super) type NoTrailers = g::Msg<7, ()>;
pub(super) type End = g::Msg<8, ()>;
pub(super) type Done = g::Msg<9, ()>;
pub(super) type Head = g::Roll<
    g::Route<
        g::Seq<g::Send<READER, WRITER, Information>, g::Send<WRITER, READER, Stored>>,
        g::Seq<g::Send<READER, WRITER, Headers>, g::Send<WRITER, READER, Stored>>,
    >,
>;
pub(super) type Body = g::Roll<
    g::Route<
        g::Seq<g::Send<READER, WRITER, Data>, g::Send<WRITER, READER, Stored>>,
        g::Send<READER, WRITER, BodyEnd>,
    >,
>;
pub(super) type Tail = g::Route<
    g::Seq<g::Send<READER, WRITER, Trailers>, g::Send<WRITER, READER, Stored>>,
    g::Send<READER, WRITER, NoTrailers>,
>;
pub(super) type Flow = g::Seq<
    Head,
    g::Seq<Body, g::Seq<Tail, g::Seq<g::Send<READER, WRITER, End>, g::Send<WRITER, READER, Done>>>>,
>;
pub(super) fn choreography() -> g::Program<Flow> {
    g::seq(
        g::route(
            g::seq(
                g::send::<READER, WRITER, Information>(),
                g::send::<WRITER, READER, Stored>(),
            ),
            g::seq(
                g::send::<READER, WRITER, Headers>(),
                g::send::<WRITER, READER, Stored>(),
            ),
        )
        .roll(),
        g::seq(
            g::route(
                g::seq(
                    g::send::<READER, WRITER, Data>(),
                    g::send::<WRITER, READER, Stored>(),
                ),
                g::send::<READER, WRITER, BodyEnd>(),
            )
            .roll(),
            g::seq(
                g::route(
                    g::seq(
                        g::send::<READER, WRITER, Trailers>(),
                        g::send::<WRITER, READER, Stored>(),
                    ),
                    g::send::<READER, WRITER, NoTrailers>(),
                ),
                g::seq(
                    g::send::<READER, WRITER, End>(),
                    g::send::<WRITER, READER, Done>(),
                ),
            ),
        ),
    )
}
