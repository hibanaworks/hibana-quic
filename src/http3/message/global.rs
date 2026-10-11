//! HTTP response consumption: headers, body, trailers, completion.
//!
//! READER and CONSUMER execute [`crate::http3::message::localside::reader::run`] and
//! [`crate::http3::message::localside::consumer::run`]. Their real endpoints are attached and
//! joined in [`crate::http3::message::localside::run::decode_response`].
use hibana::g;
use hibana::runtime::program::Projectable;
pub const READER: u8 = 0;
pub const CONSUMER: u8 = 1;
pub type Information = g::Msg<1, ()>;
pub type Headers = g::Msg<2, ()>;
pub type Stored = g::Msg<3, ()>;
pub type Data = g::Msg<4, u64>;
pub type BodyEnd = g::Msg<5, ()>;
pub type Trailers = g::Msg<6, ()>;
pub type NoTrailers = g::Msg<7, ()>;
pub type End = g::Msg<8, ()>;
pub type Done = g::Msg<9, ()>;
/// The reader's validated request-method classification, consumed by the
/// response writer before it can emit response bytes. This is local metadata,
/// not another HTTP field or a readiness notification.
pub type RequestMethod = g::Msg<10, u8>;
/// One server exchange with a genuine request-metadata handoff. The application
/// may interleave request consumption and response production on the same role;
/// only the reader supplies the method that governs response semantics.
pub fn server<const READ: u8, const APP: u8, const WRITE: u8>() -> impl Projectable {
    g::seq(
        g::send::<READ, WRITE, RequestMethod>(),
        g::par(request::<READ, APP>(), response::<APP, WRITE>()),
    )
}

/// Independent upload and download roles for one full-duplex client exchange.
/// The request writer transfers the actual method to the reader, which relays
/// it to the response consumer before publishing fields;
/// neither application role supplies a separate response-semantics flag.
pub fn client<const UPLOAD: u8, const WRITE: u8, const READ: u8, const DOWNLOAD: u8>()
-> impl Projectable {
    g::par(
        request::<UPLOAD, WRITE>(),
        g::seq(
            g::send::<WRITE, READ, RequestMethod>(),
            g::seq(
                g::send::<READ, DOWNLOAD, RequestMethod>(),
                response::<READ, DOWNLOAD>(),
            ),
        ),
    )
}
/// A response receive fragment with caller-selected local roles.
/// It can be composed with other choreography; the outer owner finishes
/// the endpoint only after every composed fragment has completed.
pub fn response<const INPUT: u8, const OUTPUT: u8>() -> impl Projectable {
    g::seq(
        g::route(
            g::seq(
                g::send::<INPUT, OUTPUT, Information>(),
                g::send::<OUTPUT, INPUT, Stored>(),
            ),
            g::seq(
                g::send::<INPUT, OUTPUT, Headers>(),
                g::send::<OUTPUT, INPUT, Stored>(),
            ),
        )
        .roll(),
        content::<INPUT, OUTPUT>(),
    )
}

/// An ordinary request has one initial field section and then the same
/// body/trailer storage-transfer order as a response.
pub fn request<const INPUT: u8, const OUTPUT: u8>() -> impl Projectable {
    g::seq(
        g::seq(
            g::send::<INPUT, OUTPUT, Headers>(),
            g::send::<OUTPUT, INPUT, Stored>(),
        ),
        content::<INPUT, OUTPUT>(),
    )
}

fn content<const INPUT: u8, const OUTPUT: u8>() -> impl Projectable {
    g::seq(
        g::route(
            g::seq(
                g::send::<INPUT, OUTPUT, Data>(),
                g::send::<OUTPUT, INPUT, Stored>(),
            ),
            g::send::<INPUT, OUTPUT, BodyEnd>(),
        )
        .roll(),
        g::seq(
            g::route(
                g::seq(
                    g::send::<INPUT, OUTPUT, Trailers>(),
                    g::send::<OUTPUT, INPUT, Stored>(),
                ),
                g::send::<INPUT, OUTPUT, NoTrailers>(),
            ),
            g::seq(
                g::send::<INPUT, OUTPUT, End>(),
                g::send::<OUTPUT, INPUT, Done>(),
            ),
        ),
    )
}
