//! FIN-complete file response: headers, body, trailers, completion.
//!
//! READER and WRITER execute [`crate::http3::message::local::read`] and
//! [`crate::http3::message::local::write`]. Their real endpoints are attached and
//! joined in [`crate::http3::message::local::run::decode_response`].
use hibana::g;
use hibana::runtime::program::Projectable;
pub const READER: u8 = 0;
pub const WRITER: u8 = 1;
pub type Information = g::Msg<1, ()>;
pub type Headers = g::Msg<2, ()>;
pub type Stored = g::Msg<3, ()>;
pub type Data = g::Msg<4, u64>;
pub type BodyEnd = g::Msg<5, ()>;
pub type Trailers = g::Msg<6, ()>;
pub type NoTrailers = g::Msg<7, ()>;
pub type End = g::Msg<8, ()>;
pub type Done = g::Msg<9, ()>;
pub fn choreography() -> impl Projectable {
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
