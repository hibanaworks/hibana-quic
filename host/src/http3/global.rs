//! FIN-complete file response: headers, body, trailers, completion.
use hibana::g;
use hibana::runtime::program::Projectable;
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
pub(super) fn choreography() -> impl Projectable {
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
